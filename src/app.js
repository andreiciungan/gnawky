import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { c, clear, ask, confirm, pause, select, sevTag } from './ui.js';
import { loadConfig, saveConfig, ensureOutDir, OUT_DIR, DEFAULT_CONFIG } from './config.js';
import { performScan, loadLastScan, writeReports, reportFile } from './scan.js';
import { SEVERITY_ORDER, loadIgnores, addIgnores, removeIgnore } from './finding.js';
import {
  isAutoFixable, emptyPlan, planSize, addFixToPlan, describePlan, preflight, applyPlan, hasDependencyChanges,
} from './fix.js';
import { run, isAvailable, IS_WIN } from './scanners.js';

// ------------------------------------------------------------------ helpers

const loc = (f) => (f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '');
const fmtDate = (iso) => new Date(iso).toLocaleString();

function safeIgnores(dir) {
  try { return loadIgnores(dir); } catch { return []; }
}

function readPkg(dir) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { return null; }
}

function summary(findings) {
  if (!findings.length) return c.green('no findings');
  const colors = { critical: c.red, high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
  return SEVERITY_ORDER
    .map((s) => [s, findings.filter((f) => f.severity === s).length])
    .filter(([, n]) => n)
    .map(([s, n]) => colors[s](`${n} ${s}`))
    .join(', ');
}

function header(s) {
  clear();
  const name = s.pkg?.name ?? path.basename(s.dir);
  console.log(`${c.bold(c.cyan('Gnawky'))}  ${c.bold(name)}  ${c.gray(s.dir)}`);
  const bits = [s.result ? `Last scan ${fmtDate(s.result.date)}: ${summary(s.result.findings)}` : c.gray('Not scanned yet')];
  if (s.cfg.offline) bits.push(c.yellow('offline mode'));
  if (s.stale && s.result) bits.push(c.yellow('results may be out of date, rescan'));
  if (!s.pkg) bits.push(c.yellow('no package.json here'));
  console.log(bits.join(c.gray('  ·  ')));
  console.log(c.gray('─'.repeat(Math.min(process.stdout.columns || 60, 72))));
  console.log();
}

function printFinding(f) {
  console.log(`${sevTag(f.severity)} ${c.bold(f.title)}\n`);
  const row = (k, v) => v && console.log(`  ${c.gray(k.padEnd(14))}${v}`);
  row('Location', loc(f));
  row('Found by', `${f.tool} (${f.ruleId})`);
  row('CWE', f.cwe?.join(', '));
  row('Details', f.description);
  row('Suggested fix', f.fix.detail);
  row('More info', f.url);
  row('ID', c.gray(f.fingerprint));
  console.log();
}

function dropFromResult(s, fingerprints) {
  const set = new Set(fingerprints);
  const before = s.result.findings.length;
  s.result.findings = s.result.findings.filter((f) => !set.has(f.fingerprint));
  s.result.ignoredCount += before - s.result.findings.length;
  writeReports(s.dir, s.result);
}

// ------------------------------------------------------------------ screens

async function scanScreen(s) {
  header(s);
  console.log(`${c.bold('Scanning')} ${c.gray('(read-only: nothing in your project is changed)')}\n`);
  s.result = performScan(s.dir, s.cfg, (m) => console.log(c.gray(m)));
  s.stale = false;

  console.log();
  for (const t of s.result.tools) {
    const icon = t.status === 'ran' ? c.green('✔') : t.status === 'skipped' ? c.yellow('–') : c.red('✖');
    const msg = t.status === 'ran' ? `${t.count} finding(s)` : c.gray(t.message);
    console.log(`  ${icon} ${t.name.padEnd(10)} ${msg}`);
  }
  if (s.result.tools.every((t) => t.status !== 'ran')) {
    console.log(c.yellow('\n  ⚠ No scanner ran, so "no findings" does NOT mean the project is safe.'));
    console.log(c.yellow('    Open "Check installed tools" from the menu to see what is missing.'));
  }
  console.log(`\n  ${c.bold('Result:')} ${summary(s.result.findings)}\n`);

  const n = s.result.findings.length;
  const next = await select('Next step', [
    { label: 'Review & fix findings one by one', value: 'review', disabled: !n },
    { label: 'Browse findings', value: 'view', disabled: !n },
    { label: 'Back to menu', value: null },
  ]);
  if (next) await SCREENS[next](s);
}

async function viewScreen(s) {
  for (;;) {
    header(s);
    const list = s.result.findings;
    if (!list.length) {
      console.log(c.green('No findings to show.'));
      await pause();
      return;
    }
    const pick = await select(`Findings (${list.length}). Choose one for details`, [
      ...list.map((f) => ({ label: `${sevTag(f.severity)} ${f.title}  ${c.gray(loc(f))}`, value: f })),
      { label: 'Back', value: null },
    ]);
    if (!pick) return;
    await detailScreen(s, pick);
  }
}

async function detailScreen(s, f) {
  header(s);
  printFinding(f);
  const auto = isAutoFixable(f);
  const action = await select('What do you want to do?', [
    { label: auto ? 'Fix it automatically' : 'Fix automatically (not available, see suggested fix)', value: 'fix', disabled: !auto },
    { label: 'Ask Claude to explain it and propose a fix', value: 'claude' },
    { label: 'Ignore it (needs a reason)', value: 'ignore' },
    { label: 'Back', value: null },
  ]);
  if (action === 'fix') {
    const plan = emptyPlan();
    addFixToPlan(plan, f);
    await confirmAndApply(s, plan);
  } else if (action === 'ignore') {
    const reason = await ask('Why is this safe to ignore? (leave empty to cancel) ');
    if (!reason) return;
    addIgnores(s.dir, [{ finding: f, reason }]);
    dropFromResult(s, [f.fingerprint]);
    console.log(c.green('✔ Ignored. You can restore it from "Ignored findings".'));
    await pause();
  } else if (action === 'claude') {
    await claudeScreen(s, f);
  }
}

async function reviewScreen(s) {
  const plan = emptyPlan();
  const list = [...s.result.findings];
  for (const [i, f] of list.entries()) {
    header(s);
    console.log(c.gray(`Finding ${i + 1} of ${list.length}   ·   planned so far: ${planSize(plan)} change(s)\n`));
    printFinding(f);
    const choice = await select('Your decision', [
      { label: 'Fix automatically', value: 'fix', disabled: !isAutoFixable(f) },
      { label: 'Skip for now', value: 'skip' },
      { label: 'Ignore (needs a reason)', value: 'ignore' },
      { label: 'Stop reviewing', value: 'stop' },
    ]);
    if (choice === null || choice === 'stop') break;
    if (choice === 'fix') addFixToPlan(plan, f);
    if (choice === 'ignore') {
      const reason = await ask('Why is this safe to ignore? (leave empty to skip) ');
      if (reason) plan.ignores.push({ finding: f, reason });
    }
  }
  if (!planSize(plan)) {
    header(s);
    console.log('No changes selected. Nothing was changed.');
    await pause();
    return;
  }
  await confirmAndApply(s, plan);
}

async function confirmAndApply(s, plan) {
  header(s);
  console.log(c.bold('Here is what will happen:\n'));
  for (const line of describePlan(plan)) console.log(`  • ${line}`);
  if (hasDependencyChanges(plan)) {
    const problem = preflight(s.dir);
    console.log(problem
      ? c.yellow(`\n  ⚠ Dependency fixes will be skipped: ${problem}`)
      : c.gray('\n  Dependency changes are made on a new git branch, with install scripts disabled.'));
  }
  console.log();
  if (!(await confirm('Apply this plan?'))) {
    console.log('Cancelled. Nothing was changed.');
    await pause();
    return;
  }
  console.log();
  const { branch } = applyPlan(s.dir, plan, (m) => console.log(m));
  if (plan.ignores.length) dropFromResult(s, plan.ignores.map((i) => i.finding.fingerprint));
  if (branch) s.stale = true;
  await pause();
}

function buildClaudePrompt(s, f) {
  const secretFiles = [...new Set(s.result.findings.filter((x) => x.tool === 'gitleaks').map((x) => x.file))];
  const focus = f
    ? `Focus only on the finding with fingerprint ${f.fingerprint} ("${f.title}").`
    : 'Go through the findings, most severe first.';
  return `# Security fix session (started by Gnawky)

Read \`${OUT_DIR}/findings.json\`: it contains the results of a security scan of this project.
${focus}

For each finding: explain in plain language what an attacker could do, check in the code whether it is a real issue or a false positive, then give 1 to 3 fix options with trade-offs (effort, risk of breaking things) and say which one you recommend. Then ask me what I want to do.

Rules. Follow them strictly:
- Do not open .env files, private keys (*.pem, *.key), or any credentials file.${secretFiles.length ? `\n- Do not open these files, a scanner flagged them as containing secrets: ${secretFiles.join(', ')}. Work from the file name and line number only.` : ''}
- Never print secret values.
- For leaked secrets, tell me to rotate the credential first; removing it from the code is not enough.
- Do not change any file until I approve that specific change. Show me the diff first.
- Never run \`npm audit fix --force\`, install scripts, this project's code or tests, \`git commit\`, or \`git push\` unless I ask.
`;
}

async function claudeScreen(s, f) {
  header(s);
  if (s.cfg.offline) {
    console.log(c.yellow('Offline mode is on. Asking Claude sends data to Anthropic, so it is turned off.'));
    console.log(c.gray('You can change this in Settings.'));
    await pause();
    return;
  }
  if (!isAvailable('claude')) {
    console.log('Claude Code is not installed.\n');
    console.log(`  Install it with:  ${c.cyan('npm install -g @anthropic-ai/claude-code')}`);
    console.log('  then choose this option again.');
    await pause();
    return;
  }
  console.log(c.bold('Before you continue: privacy\n'));
  console.log('  • This starts Claude Code in this folder.');
  console.log(`  • Claude will read ${OUT_DIR}/findings.json (secret values are already removed from it)`);
  console.log('    and may read the source files it needs. Anything Claude reads is sent to Anthropic.');
  console.log('  • Claude is told not to open .env files, keys, or files flagged as containing secrets.');
  console.log(c.gray('    That is an instruction, not a hard block. For a hard block, add deny rules'));
  console.log(c.gray('    in Claude Code\'s permission settings.'));
  console.log('  • Claude asks before changing any file.\n');
  if (!(await confirm('Continue?'))) return;

  ensureOutDir(s.dir);
  fs.writeFileSync(path.join(s.dir, OUT_DIR, 'claude-task.md'), buildClaudePrompt(s, f));
  // A constant prompt is passed, never scanner data, so it is safe even when Windows needs a shell.
  const prompt = `Read ${OUT_DIR}/claude-task.md and follow the instructions in it.`;
  clear();
  spawnSync(IS_WIN ? 'claude.cmd' : 'claude', [IS_WIN ? `"${prompt}"` : prompt], {
    cwd: s.dir, stdio: 'inherit', shell: IS_WIN,
  });
  s.stale = true; // Claude may have changed files
}

async function ignoredScreen(s) {
  for (;;) {
    header(s);
    const list = safeIgnores(s.dir);
    if (!list.length) {
      console.log('No ignored findings.');
      await pause();
      return;
    }
    const pick = await select(`Ignored findings (${list.length}). Choose one to restore it`, [
      ...list.map((i) => ({ label: `${i.title ?? i.fingerprint}  ${c.gray(`${i.date ?? ''}: ${i.reason}`)}`, value: i })),
      { label: 'Back', value: null },
    ]);
    if (!pick) return;
    if (await confirm(`Restore "${pick.title ?? pick.fingerprint}"? It will show up again on the next scan.`)) {
      removeIgnore(s.dir, pick.fingerprint);
      s.stale = true;
    }
  }
}

async function reportScreen(s) {
  header(s);
  const file = reportFile(s.dir);
  try {
    console.log(fs.readFileSync(file, 'utf8'));
  } catch {
    console.log('No report yet. Run a scan first.');
  }
  console.log(c.gray(`Saved at ${file} (also findings.json next to it).`));
  console.log(c.gray('It lists your weak spots: keep it private, don\'t upload it anywhere public.'));
  await pause();
}

async function settingsScreen(s) {
  const onoff = (v) => (v ? c.green('on') : c.gray('off'));
  for (;;) {
    header(s);
    const pick = await select(`Settings ${c.gray(`(saved in ${OUT_DIR}/config.json)`)}`, [
      { label: `Minimum severity to show: ${c.bold(s.cfg.minSeverity)}`, value: 'sev' },
      { label: `Offline mode: ${onoff(s.cfg.offline)}  ${c.gray('(nothing leaves this computer)')}`, value: 'offline' },
      { label: `Scanner npm audit: ${onoff(s.cfg.scanners['npm-audit'])}`, value: 'npm-audit' },
      { label: `Scanner gitleaks: ${onoff(s.cfg.scanners.gitleaks)}`, value: 'gitleaks' },
      { label: `Scanner semgrep: ${onoff(s.cfg.scanners.semgrep)}`, value: 'semgrep' },
      { label: `Semgrep rules: ${s.cfg.semgrepConfigs.join(', ')}`, value: 'rules' },
      { label: 'Reset to defaults', value: 'reset' },
      { label: 'Back', value: null },
    ]);
    if (!pick) return;
    if (pick === 'sev') {
      const v = await select('Show findings of at least this severity', SEVERITY_ORDER.map((x) => ({ label: x, value: x })));
      if (v) s.cfg.minSeverity = v;
    } else if (pick === 'offline') {
      s.cfg.offline = !s.cfg.offline;
    } else if (pick === 'rules') {
      console.log(c.gray('\nRegistry rulesets (like p/javascript) or local rule files (like ./rules.yml).'));
      console.log(c.gray('In offline mode only local files are used.'));
      const v = await ask('Comma-separated list (empty = keep current): ');
      if (v) s.cfg.semgrepConfigs = v.split(',').map((x) => x.trim()).filter(Boolean);
    } else if (pick === 'reset') {
      if (!(await confirm('Reset all settings?'))) continue;
      s.cfg = structuredClone(DEFAULT_CONFIG);
    } else {
      s.cfg.scanners[pick] = !s.cfg.scanners[pick];
    }
    saveConfig(s.dir, s.cfg);
    s.stale = true;
  }
}

const TOOLS = [
  { cmd: 'npm', why: 'checks dependencies', hint: 'comes with Node.js' },
  { cmd: 'git', why: 'safe fix branches', hint: 'https://git-scm.com' },
  { cmd: 'gitleaks', why: 'finds leaked secrets', hint: 'brew install gitleaks   (or https://github.com/gitleaks/gitleaks)' },
  { cmd: 'semgrep', why: 'finds risky code', hint: 'brew install semgrep   or   pipx install semgrep' },
  { cmd: 'claude', why: 'optional: Ask Claude', hint: 'npm install -g @anthropic-ai/claude-code' },
];

async function doctorScreen(s) {
  header(s);
  console.log(c.bold('Installed tools\n'));
  console.log(`  ${c.green('✔')} ${'node'.padEnd(9)} ${process.version}`);
  for (const t of TOOLS) {
    const r = run(t.cmd, ['--version'], { timeoutMs: 15000 });
    if (!r.error && r.status === 0) {
      const version = r.stdout.trim().split('\n')[0].slice(0, 40);
      console.log(`  ${c.green('✔')} ${t.cmd.padEnd(9)} ${version}  ${c.gray(t.why)}`);
    } else {
      console.log(`  ${c.red('✖')} ${t.cmd.padEnd(9)} ${c.gray(t.why)}`);
      console.log(`    ${c.gray('install:')} ${t.hint}`);
    }
  }
  const lock = ['package-lock.json', 'npm-shrinkwrap.json'].some((f) => fs.existsSync(path.join(s.dir, f)));
  if (!lock) console.log(c.yellow('\n  ⚠ No package-lock.json: npm audit needs one (npm install --package-lock-only --ignore-scripts).'));
  await pause();
}

const SCREENS = {
  scan: scanScreen, view: viewScreen, review: reviewScreen, claude: (s) => claudeScreen(s, null),
  ignored: ignoredScreen, report: reportScreen, settings: settingsScreen, doctor: doctorScreen,
};

// ------------------------------------------------------------------ main loop

export async function startApp(dir) {
  const s = { dir, cfg: loadConfig(dir), result: loadLastScan(dir), pkg: readPkg(dir), stale: false };
  try {
    if (!s.pkg) {
      header(s);
      console.log(c.yellow('There is no package.json in this folder.'));
      console.log('Gnawky is meant to be started inside the Node.js project you want to scan.\n');
      if (!(await confirm('Continue anyway?'))) return;
    }
    for (;;) {
      header(s);
      const n = s.result?.findings.length ?? 0;
      const ignored = safeIgnores(dir).length;
      const choice = await select('What would you like to do?', [
        { label: s.result ? 'Scan again' : 'Run security scan', value: 'scan' },
        { label: `Review & fix findings${n ? ` (${n})` : ''}`, value: 'review', disabled: !n },
        { label: 'Browse findings', value: 'view', disabled: !s.result },
        { label: 'Ask Claude for help', value: 'claude', disabled: !s.result },
        { label: `Ignored findings${ignored ? ` (${ignored})` : ''}`, value: 'ignored' },
        { label: 'View report', value: 'report', disabled: !s.result },
        { label: 'Settings', value: 'settings' },
        { label: 'Check installed tools', value: 'doctor' },
        { label: 'Quit', value: 'quit' },
      ]);
      if (choice === null || choice === 'quit') break;
      await SCREENS[choice](s);
    }
  } catch (e) {
    if (e.code !== 'ABORT_ERR') throw e;
  }
  clear();
  console.log('Gnawky closed. Reports are in .gnawky/');
}

