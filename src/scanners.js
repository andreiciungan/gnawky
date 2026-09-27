import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makeFinding } from './finding.js';

export const IS_WIN = process.platform === 'win32';
// Tools installed as .cmd shims on Windows (need a shell there; only pass constant/validated args).
const SHELL_SHIMS = new Set(['npm', 'claude']);

/**
 * Run an external tool. Arguments are passed as an array (no shell), so
 * nothing from the scanned project can be interpreted as a command.
 * Exception: on Windows, npm and claude are .cmd shims that Node can only start
 * via a shell; callers must only pass constant or validated args to them.
 */
export function run(cmd, args, { cwd, timeoutMs = 10 * 60 * 1000 } = {}) {
  const viaShell = IS_WIN && SHELL_SHIMS.has(cmd);
  const res = spawnSync(viaShell ? `${cmd}.cmd` : cmd, args, {
    cwd,
    encoding: 'utf8',
    shell: viaShell,
    timeout: timeoutMs,
    maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '', error: res.error };
}

export function isAvailable(cmd) {
  const r = run(cmd, ['--version'], { timeoutMs: 15000 });
  return !r.error && r.status === 0;
}

// ---------------------------------------------------------------- npm audit

const NPM_SEVERITY = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'info' };

function npmFix(fixAvailable) {
  if (fixAvailable === true || (fixAvailable && !fixAvailable.isSemVerMajor)) {
    return { type: 'npm-audit-fix', detail: 'Non-breaking update available (npm audit fix).' };
  }
  if (fixAvailable && fixAvailable.isSemVerMajor) {
    return {
      type: 'npm-major-upgrade',
      package: fixAvailable.name,
      version: fixAvailable.version,
      detail: `Upgrade ${fixAvailable.name} to ${fixAvailable.version}. This is a semver-major change and may break your code; run your tests.`,
    };
  }
  return {
    type: 'manual',
    detail: 'No patched version published. Consider replacing the package, removing it, or mitigating how you use it.',
  };
}

export function scanNpmAudit(dir) {
  const hasLock = ['package-lock.json', 'npm-shrinkwrap.json'].some((f) => fs.existsSync(path.join(dir, f)));
  if (!hasLock) return { skipped: 'no package-lock.json (create one with: npm install --package-lock-only --ignore-scripts)' };

  const r = run('npm', ['audit', '--json'], { cwd: dir });
  let data;
  try {
    data = JSON.parse(r.stdout);
  } catch {
    return { error: `could not parse npm audit output: ${(r.stderr || String(r.error ?? '')).slice(0, 300)}` };
  }
  if (data.error) return { error: data.error.summary ?? 'npm audit failed' };

  const findings = [];
  for (const [pkg, v] of Object.entries(data.vulnerabilities ?? {})) {
    // Entries whose "via" only lists other package names are transitive:
    // the real advisory is already reported on the root vulnerable package.
    const advisories = (v.via ?? []).filter((x) => typeof x === 'object');
    for (const adv of advisories) {
      findings.push(
        makeFinding({
          tool: 'npm-audit',
          ruleId: String(adv.source ?? adv.url ?? adv.title),
          severity: NPM_SEVERITY[adv.severity ?? v.severity] ?? 'medium',
          title: `${pkg}: ${adv.title}`,
          package: pkg,
          file: 'package-lock.json',
          description: `Vulnerable versions: ${adv.range ?? 'unknown'}. Installed at: ${(v.nodes ?? []).slice(0, 3).join(', ') || 'n/a'}.`,
          cwe: adv.cwe ?? [],
          url: adv.url ?? null,
          fix: npmFix(v.fixAvailable),
        }),
      );
    }
  }
  return { findings };
}

// ----------------------------------------------------------------- gitleaks

export function scanGitleaks(dir) {
  if (!isAvailable('gitleaks')) return { skipped: 'gitleaks not installed' };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gnawky-'));
  const reportPath = path.join(tmpDir, 'gitleaks.json');
  const args = ['detect', '--source', dir, '--report-format', 'json', '--report-path', reportPath,
    '--redact', '--no-banner', '--exit-code', '0'];
  if (!fs.existsSync(path.join(dir, '.git'))) args.push('--no-git');

  try {
    const r = run('gitleaks', args);
    if (r.error || r.status !== 0) return { error: `gitleaks failed: ${r.stderr.slice(0, 300)}` };
    const items = JSON.parse(fs.readFileSync(reportPath, 'utf8') || '[]');
    // Deliberately never copy Secret/Match fields: the report must not leak secrets.
    const findings = items.map((it) =>
      makeFinding({
        tool: 'gitleaks',
        ruleId: it.RuleID,
        severity: 'high',
        title: `Possible secret: ${it.Description || it.RuleID}`,
        file: it.File,
        line: it.StartLine,
        description: it.Commit
          ? `Found in git history (commit ${it.Commit.slice(0, 8)}). Deleting the file is not enough; the value is still in history.`
          : 'Found in the working tree.',
        fix: {
          type: 'manual',
          detail: 'First rotate/revoke the credential. Then move it to an environment variable or secret manager and, if it was committed, purge it from git history.',
        },
      }),
    );
    return { findings };
  } catch (e) {
    return { error: `gitleaks output unreadable: ${e.message}` };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ------------------------------------------------------------------ semgrep

const SEMGREP_SEVERITY = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };

export function scanSemgrep(dir, configs = ['p/javascript', 'p/nodejsscan']) {
  if (!isAvailable('semgrep')) return { skipped: 'semgrep not installed' };

  const args = ['scan', '--json', '--quiet', '--metrics=off'];
  for (const c of configs) args.push('--config', c);
  args.push(dir);

  const r = run('semgrep', args);
  let data;
  try {
    data = JSON.parse(r.stdout);
  } catch {
    return { error: `could not parse semgrep output: ${r.stderr.slice(0, 300)}` };
  }

  // Code snippets (extra.lines) are left out on purpose: they can contain secrets.
  const findings = (data.results ?? []).map((res) => {
    const meta = res.extra?.metadata ?? {};
    return makeFinding({
      tool: 'semgrep',
      ruleId: res.check_id,
      severity: SEMGREP_SEVERITY[res.extra?.severity] ?? 'medium',
      title: res.check_id.split('.').pop().replace(/[-_]/g, ' '),
      file: path.relative(dir, res.path) || res.path,
      line: res.start?.line ?? null,
      description: (res.extra?.message ?? '').trim(),
      cwe: [].concat(meta.cwe ?? []),
      url: meta.source ?? (Array.isArray(meta.references) ? meta.references[0] : null),
      fix: res.extra?.fix
        ? { type: 'suggested-edit', detail: `Rule suggests replacing the code with: ${res.extra.fix}` }
        : { type: 'manual', detail: 'Review the flagged code; see the rule documentation for the safe pattern.' },
    });
  });
  return { findings };
}

// ---------------------------------------------------------------------- all

const isRemoteRule = (cfg) => /^(p|r|s)\//.test(cfg) || /^https?:/.test(cfg) || cfg === 'auto';

export function runAllScanners(dir, log = () => {}, opts = {}) {
  const enabled = opts.enabled ?? {};
  const offline = Boolean(opts.offline);
  const semgrepConfigs = opts.semgrepConfigs ?? ['p/javascript', 'p/nodejsscan'];

  const scanners = [
    ['npm-audit', () => (offline
      ? { skipped: 'offline mode (npm audit needs the npm registry)' }
      : scanNpmAudit(dir))],
    ['gitleaks', () => scanGitleaks(dir)],
    ['semgrep', () => {
      if (!offline) return scanSemgrep(dir, semgrepConfigs);
      const local = semgrepConfigs.filter((c) => !isRemoteRule(c));
      return local.length
        ? scanSemgrep(dir, local)
        : { skipped: 'offline mode (set a local rules file in Settings)' };
    }],
  ];

  const findings = [];
  const tools = [];
  for (const [name, fn] of scanners) {
    if (enabled[name] === false) {
      tools.push({ name, status: 'skipped', message: 'disabled in settings' });
      continue;
    }
    log(`  running ${name}…`);
    const res = fn();
    if (res.findings) {
      findings.push(...res.findings);
      tools.push({ name, status: 'ran', count: res.findings.length });
    } else {
      tools.push({ name, status: res.skipped ? 'skipped' : 'error', message: res.skipped ?? res.error });
    }
  }
  return { findings, tools };
}
