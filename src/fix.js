import fs from 'node:fs';
import path from 'node:path';
import { run } from './scanners.js';
import { addIgnores } from './finding.js';
import { PKG_NAME, PKG_VERSION, packageManager, runLabel } from './pm.js';
import { applyYarnStep } from './yarn.js';
import {
  hasNodeModules, installLocked, syncInstall, treeProblems, engineWarnings, runScripts,
} from './verify.js';

const EXACT_VERSION = /^\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]*)?$/;
const OWN_FILES = ['.gnawky/', '.gnawky-ignore.json'];
const DEP_FILES = ['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock'];
const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'];
// Fix types that change one package; the step kind decides how it is applied.
const STEP_KIND = {
  'npm-upgrade': 'upgrade',
  'npm-major-upgrade': 'upgrade',
  'yarn-upgrade': 'upgrade',
  'yarn-major-upgrade': 'upgrade',
  'yarn-refresh': 'refresh',
  'yarn-resolution': 'resolution',
  'yarn-major-resolution': 'resolution',
};

const git = (dir, args) => run('git', args, { cwd: dir });
const tail = (s, n = 8) => s.trim().split('\n').slice(-n).join('\n');

export const isAutoFixable = (f) => f.fix?.type === 'npm-audit-fix' || Boolean(STEP_KIND[f.fix?.type]);

export const emptyPlan = () => ({ auditFix: [], upgrades: [], ignores: [] });
export const planSize = (p) => p.auditFix.length + p.upgrades.length + p.ignores.length;
export const hasDependencyChanges = (p) => p.auditFix.length + p.upgrades.length > 0;

export function addFixToPlan(plan, f) {
  if (f.fix.type === 'npm-audit-fix') plan.auditFix.push(f);
  else if (STEP_KIND[f.fix.type]) plan.upgrades.push(f);
}

/** One step per package (plus one for npm audit fix), so each can be tested and undone on its own. */
export function planSteps(plan) {
  const steps = [];
  if (plan.auditFix.length) {
    steps.push({ kind: 'audit-fix', id: 'audit-fix', label: 'npm audit fix', findings: plan.auditFix });
  }
  const byPkg = new Map();
  for (const f of plan.upgrades) {
    const step = byPkg.get(f.fix.package) ?? {
      kind: STEP_KIND[f.fix.type],
      id: f.fix.package,
      package: f.fix.package,
      version: f.fix.version,
      fix: f.fix,
      major: f.fix.type.includes('major'),
      findings: [],
    };
    step.findings.push(f);
    byPkg.set(f.fix.package, step);
  }
  // Upgrades first: they often fix what a refresh or an override would otherwise force.
  const ORDER = { upgrade: 0, refresh: 1, resolution: 2 };
  const pkgSteps = [...byPkg.values()].sort((a, b) => ORDER[a.kind] - ORDER[b.kind]);
  for (const s of pkgSteps) steps.push({ ...s, label: stepLabel(s) });
  return steps;
}

function stepLabel(s) {
  if (s.kind === 'refresh') return `update ${s.package} within its allowed ranges (→ ${s.version} or later)`;
  if (s.kind === 'resolution') return `force ${s.package} → ^${s.version} (package.json "resolutions")`;
  return `upgrade ${s.package} → ${s.fix.spec ?? s.version}`;
}

export function describePlan(plan) {
  const lines = planSteps(plan).map((s) => (s.kind === 'audit-fix'
    ? `npm audit fix for ${s.findings.length} finding(s): non-breaking updates within your version ranges (may also update other packages)`
    : `${s.label}${s.major ? '  (major version: may break your code)' : ''}`));
  for (const { finding, reason } of plan.ignores) lines.push(`ignore "${finding.title}" (reason: ${reason})`);
  return lines;
}

/** Returns null if dependency fixes can safely run, otherwise the reason they can't. */
export function preflight(dir) {
  if (git(dir, ['rev-parse', '--is-inside-work-tree']).status !== 0) {
    return 'this folder is not a git repository, so changes could not be rolled back.';
  }
  const dirty = git(dir, ['status', '--porcelain']).stdout
    .split('\n')
    .filter((l) => l.trim() && !OWN_FILES.some((f) => l.slice(3).startsWith(f)));
  if (dirty.length) return 'you have uncommitted changes. Commit or stash them first so fixes stay isolated.';
  return null;
}

// ------------------------------------------------------------ helpers

function currentRef(dir) {
  const branch = git(dir, ['rev-parse', '--abbrev-ref', 'HEAD']).stdout.trim();
  return branch && branch !== 'HEAD' ? branch : git(dir, ['rev-parse', 'HEAD']).stdout.trim();
}

function isExactPin(dir, name) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    const spec = DEP_FIELDS.map((k) => pkg[k]?.[name]).find(Boolean);
    return EXACT_VERSION.test(spec ?? '');
  } catch {
    return false;
  }
}

const snapshotDepFiles = (dir) => Object.fromEntries(DEP_FILES.map((f) => {
  try { return [f, fs.readFileSync(path.join(dir, f), 'utf8')]; } catch { return [f, null]; }
}));

function restoreDepFiles(dir, snap) {
  for (const [f, content] of Object.entries(snap)) {
    const p = path.join(dir, f);
    if (content === null) fs.rmSync(p, { force: true });
    else fs.writeFileSync(p, content);
  }
}

// --ignore-scripts: third-party install scripts never run during a fix.
// --force is never used: it can silently install breaking major versions.
function applyStep(dir, step) {
  if (packageManager(dir) === 'yarn') return applyYarnStep(dir, step);
  let args;
  if (step.kind === 'audit-fix') {
    args = ['audit', 'fix', '--ignore-scripts', '--no-fund'];
  } else {
    if (!PKG_NAME.test(step.package) || !PKG_VERSION.test(step.version)) {
      return { ok: false, output: `Refused suspicious package spec: ${step.package}@${step.version}` };
    }
    args = ['install', `${step.package}@${step.version}`, '--ignore-scripts', '--no-audit', '--no-fund'];
    // Keep an exact pin exact instead of turning it into a ^range.
    if (isExactPin(dir, step.package)) args.push('--save-exact');
  }
  const r = run('npm', args, { cwd: dir });
  // npm audit fix exits with 1 when vulnerabilities remain; that is not a failure here.
  const ok = !r.error && (r.status === 0 || (step.kind === 'audit-fix' && r.status === 1));
  return { ok, output: `${r.stdout}\n${r.stderr}`, command: `npm ${args.join(' ')}` };
}

// ------------------------------------------------------------ apply

function applyDependencyFixes(dir, plan, log, report, opts) {
  const problem = preflight(dir);
  if (problem) {
    report.skipped = problem;
    log(`✖ Skipped dependency fixes: ${problem}`);
    return;
  }
  const base = currentRef(dir);
  const branch = `gnawky/fix-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}`;
  if (git(dir, ['checkout', '-b', branch]).status !== 0) {
    report.skipped = `could not create branch ${branch}.`;
    log(`✖ Could not create branch ${branch}.`);
    return;
  }
  Object.assign(report, { branch, base });
  log(`→ Created branch ${branch} (from ${base})`);

  const pm = packageManager(dir);
  const installCmd = pm === 'yarn' ? 'yarn install --frozen-lockfile' : 'npm ci';
  let scripts = [...opts.scripts];
  if (scripts.length && !hasNodeModules(dir)) {
    log(`→ ${installCmd} --ignore-scripts  (installs your current dependencies so your scripts can run)`);
    const r = installLocked(dir);
    if (r.status !== 0) {
      report.scriptsSkipped = `could not install the current dependencies (${installCmd} failed).`;
      log(`✖ ${report.scriptsSkipped}\n${tail(r.stderr)}`);
      scripts = [];
    }
  }
  report.scripts = scripts;
  const lsBefore = hasNodeModules(dir) ? treeProblems(dir) : null;

  if (scripts.length) {
    log('\nBefore the fix:');
    report.baseline = runScripts(dir, scripts, 'before', log);
  }
  // In one-at-a-time mode, each change is judged by the scripts that passed before it.
  const guard = opts.oneAtATime ? scripts.filter((n) => report.baseline[n].ok) : [];

  log('\nApplying fixes:');
  let npmOutput = '';
  for (const step of planSteps(plan)) {
    const snap = snapshotDepFiles(dir);
    log(`→ ${step.label}`);
    const r = applyStep(dir, step);
    npmOutput += r.output;
    const entry = { id: step.id, label: step.label, major: Boolean(step.major), findings: step.findings.length, status: 'applied' };
    report.steps.push(entry);
    if (!r.ok) {
      entry.status = 'failed';
      entry.error = tail(r.output);
      log(`  ✖ ${pm} failed:\n${entry.error.replace(/^/gm, '    ')}`);
      restoreDepFiles(dir, snap);
      continue;
    }
    if (r.skipped) {
      Object.assign(entry, { status: 'skipped', note: r.skipped });
      log(`  – Skipped: ${r.skipped}`);
      continue;
    }
    if (!guard.length) continue;
    const results = runScripts(dir, guard, `after-${step.id}`, log);
    const broken = guard.filter((n) => !results[n].ok);
    if (broken.length) {
      Object.assign(entry, { status: 'reverted', broke: broken, results });
      log(`  ↩ Undoing this change: it broke ${broken.map((n) => runLabel(pm, n)).join(', ')}`);
      restoreDepFiles(dir, snap);
      syncInstall(dir);
    }
  }

  if (scripts.length && !opts.oneAtATime) {
    log('\nAfter the fix:');
    report.after = runScripts(dir, scripts, 'after', log);
  }

  log('\nChecking dependency compatibility…');
  const lsAfter = treeProblems(dir) ?? [];
  report.lsPreexisting = lsBefore ? lsBefore.length : 0;
  report.lsNew = lsBefore ? lsAfter.filter((p) => !lsBefore.includes(p)) : lsAfter;
  report.engines = engineWarnings(npmOutput);
  report.diffStat = git(dir, ['diff', '--stat']).stdout.trim();
}

/**
 * Applies the plan. Dependency changes go on a new branch; if `scripts` are given,
 * they run before and after so a failure can be told apart from one that already existed.
 */
export function applyPlan(dir, plan, log = console.log, { scripts = [], oneAtATime = false } = {}) {
  const report = {
    branch: null, base: null, skipped: null, scriptsSkipped: null, oneAtATime,
    scripts: [], baseline: {}, after: {}, steps: [], lsNew: [], lsPreexisting: 0, engines: [], diffStat: '',
  };
  if (hasDependencyChanges(plan)) applyDependencyFixes(dir, plan, log, report, { scripts, oneAtATime });
  if (plan.ignores.length) log(`✔ Saved ${plan.ignores.length} ignore decision(s) to ${addIgnores(dir, plan.ignores)}`);
  return report;
}

/** Scripts that passed before the fix and fail after it. */
export function regressions(report) {
  if (report.oneAtATime) return [];
  return report.scripts.filter((n) => report.baseline[n]?.ok && report.after[n] && !report.after[n].ok);
}

/** Throws away the fix branch and returns to where the user was. */
export function undoFix(dir, report, log = console.log) {
  const tracked = git(dir, ['ls-files', '--', ...DEP_FILES]).stdout.split('\n').filter(Boolean);
  if (tracked.length) git(dir, ['checkout', '--', ...tracked]);
  if (git(dir, ['checkout', report.base]).status !== 0) {
    log(`✖ Could not switch back to ${report.base}. You are still on ${report.branch}.`);
    return false;
  }
  git(dir, ['branch', '-D', report.branch]);
  log(`✔ Back on ${report.base}; deleted ${report.branch}.`);
  if (hasNodeModules(dir)) {
    log(`→ ${packageManager(dir) === 'yarn' ? 'yarn' : 'npm'} install --ignore-scripts  (puts node_modules back in sync)`);
    syncInstall(dir);
  }
  return true;
}
