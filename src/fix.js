import fs from 'node:fs';
import path from 'node:path';
import { run } from './scanners.js';
import { addIgnores } from './finding.js';
import { PKG_NAME, PKG_VERSION, packageManager, runLabel, foreignAuditFindings, auditName } from './pm.js';
import { applyYarnStep } from './yarn.js';
import { applyNpmOverride, pinSpec } from './overrides.js';
import {
  hasNodeModules, installLocked, syncInstall, treeProblems, engineWarnings, runScripts,
} from './verify.js';
import { ensureOutDir } from './config.js';
import { compare as compareVersions, valid as validVersion } from './semver.js';

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
  'npm-override': 'override',
  'npm-major-override': 'override',
};

const git = (dir, args) => run('git', args, { cwd: dir });
const tail = (s, n = 8) => s.trim().split('\n').slice(-n).join('\n');

export const isAutoFixable = (f) => f.fix?.type === 'npm-audit-fix' || Boolean(STEP_KIND[f.fix?.type]);

// pins: package -> 'caret' | 'exact', how a forced version ("resolutions"/"overrides") is written.
export const emptyPlan = () => ({ auditFix: [], upgrades: [], ignores: [], pins: {} });

/** Fix kinds that force a version onto packages installed by other packages. */
export const isForced = (kind) => kind === 'resolution' || kind === 'override';
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
      pin: plan.pins?.[f.fix.package] ?? 'caret',
      findings: [],
    };
    step.findings.push(f);
    byPkg.set(f.fix.package, step);
  }
  // Upgrades first: they often fix what a refresh or an override would otherwise force.
  const ORDER = { upgrade: 0, refresh: 1, resolution: 2, override: 2 };
  const pkgSteps = [...byPkg.values()].sort((a, b) => ORDER[a.kind] - ORDER[b.kind]);
  for (const s of pkgSteps) steps.push({ ...s, label: stepLabel(s) });
  return steps;
}

function stepLabel(s) {
  if (s.kind === 'refresh') return `update ${s.package} within its allowed ranges (→ ${s.version} or later)`;
  if (s.kind === 'resolution') return `force ${s.package} → ${pinSpec(s.version, s.pin)} (package.json "resolutions")`;
  if (s.kind === 'override') return `force ${s.package} → ${pinSpec(s.version, s.pin)} (package.json "overrides")`;
  return `upgrade ${s.package} → ${s.fix.spec ?? s.version}`;
}

export function describePlan(plan) {
  const lines = planSteps(plan).map((s) => (s.kind === 'audit-fix'
    ? `npm audit fix for ${s.findings.length} finding(s): non-breaking updates within your version ranges (may also update other packages)`
    : `${s.label}${s.major ? '  (major version: may break your code)' : ''}`));
  // Advisories of one package ignored together (from a grouped review) get one line.
  const ignores = new Map();
  for (const { finding, reason } of plan.ignores) {
    const key = finding.package ? `${finding.package}\0${reason}` : finding.fingerprint;
    if (!ignores.has(key)) ignores.set(key, { finding, reason, n: 0 });
    ignores.get(key).n++;
  }
  for (const { finding, reason, n } of ignores.values()) {
    lines.push(n > 1
      ? `ignore ${n} advisories for ${finding.package} (reason: ${reason})`
      : `ignore "${finding.title}" (reason: ${reason})`);
  }
  return lines;
}

/** Returns null if dependency fixes can safely run, otherwise the reason they can't. */
export function preflight(dir) {
  if (git(dir, ['rev-parse', '--is-inside-work-tree']).status !== 0) {
    return 'this folder is not a git repository, so changes could not be rolled back.';
  }
  if (uncommittedFiles(dir).length) return DIRTY_PROBLEM;
  return null;
}

export const DIRTY_PROBLEM = 'you have uncommitted changes. Commit or stash them first so fixes stay isolated.';

/** `git status --porcelain` lines, without Gnawky's own files. */
export function uncommittedFiles(dir) {
  return git(dir, ['status', '--porcelain']).stdout
    .split('\n')
    .filter((l) => l.trim() && !OWN_FILES.some((f) => l.slice(3).startsWith(f)));
}

// ---- stashing your own changes for a fix, and giving them back

const STASH_PREFIX = 'gnawky: before fix on ';

/**
 * Stashes uncommitted changes (untracked files too, but not Gnawky's own) so the fix starts clean.
 * Returns { ok, error }.
 */
export function stashChanges(dir) {
  const branch = currentRef(dir);
  // Leave Gnawky's own files out, but only those git sees: an exclude for an ignored path
  // (.gnawky/ usually is) makes git stash fail halfway.
  const own = git(dir, ['status', '--porcelain']).stdout.split('\n')
    .map((l) => l.slice(3).replace(/\/$/, ''))
    .filter((f) => f && OWN_FILES.some((o) => f.startsWith(o.replace(/\/$/, ''))));
  const spec = own.length ? ['--', '.', ...own.map((f) => `:(exclude)${f}`)] : [];
  const r = git(dir, ['stash', 'push', '--include-untracked', '-m', `${STASH_PREFIX}${branch}`, ...spec]);
  return r.status === 0 ? { ok: true } : { ok: false, error: (r.stderr || r.stdout).trim() };
}

/** Gnawky's stash for this branch ({ ref: 'stash@{n}', branch }), or null. */
export function gnawkyStash(dir, branch = currentRef(dir)) {
  const lines = git(dir, ['stash', 'list', '--format=%gd%x09%s']).stdout.split('\n').filter(Boolean);
  for (const line of lines) {
    const [ref, subject] = line.split('\t');
    if (subject?.endsWith(`${STASH_PREFIX}${branch}`)) return { ref, branch };
  }
  return null;
}

/** Puts the stashed changes back (git stash pop). Returns { ok, error }. */
export function restoreStash(dir, stash) {
  const r = git(dir, ['stash', 'pop', stash.ref]);
  return r.status === 0 ? { ok: true } : { ok: false, error: (r.stderr || r.stdout).trim() };
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
  if (step.kind === 'override') return applyNpmOverride(dir, step);
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

const MAX_NAMED_PACKAGES = 3;
const MAX_BRANCH_LENGTH = 60;
// @scope/name → scope-name; anything git refuses or that reads badly becomes "-".
const refPart = (s) => s.replace(/^@/, '').replace(/[^\w.-]+/g, '-').replace(/\.{2,}/g, '.').replace(/^[-.]+|[-.]+$/g, '');

/** The base name for a fix branch, from what it changes: fix/upgrade-axios-1.7.4, fix/upgrade-5-packages… */
export function fixBranchBase(steps) {
  const pkgs = steps.filter((s) => s.package);
  const auditFix = steps.some((s) => s.kind === 'audit-fix');
  if (auditFix && !pkgs.length) return 'fix/npm-audit-fix';
  if (auditFix) return 'fix/upgrade-dependencies';
  if (pkgs.length === 1) return `fix/upgrade-${refPart(pkgs[0].package)}-${refPart(pkgs[0].version)}`;
  const named = `fix/upgrade-${pkgs.map((s) => refPart(s.package)).join('-')}`;
  return pkgs.length <= MAX_NAMED_PACKAGES && named.length <= MAX_BRANCH_LENGTH ? named : `fix/upgrade-${pkgs.length}-packages`;
}

/** A fix branch name that doesn't exist yet (adds -2, -3, … when it does). */
export function fixBranchName(dir, steps) {
  const base = fixBranchBase(steps);
  const taken = (name) => git(dir, ['rev-parse', '--verify', '--quiet', `refs/heads/${name}`]).status === 0;
  let name = base;
  for (let i = 2; taken(name); i += 1) name = `${base}-${i}`;
  return name;
}

// ------------------------------------------------------------ apply

/** Why a plan's dependency fixes can't run here, or null: fixes planned from the other package manager's audit. */
export function planMismatch(dir, plan) {
  const pm = packageManager(dir);
  const foreign = foreignAuditFindings(planSteps(plan).flatMap((st) => st.findings ?? []), pm);
  if (!foreign.length) return null;
  return `these fixes come from ${foreign[0].tool.replace('-', ' ')} results, but this project uses ${pm === 'yarn' ? 'yarn' : 'npm'} (${auditName(pm)}). Scan again, then fix.`;
}

async function applyDependencyFixes(dir, plan, log, report, opts) {
  const problem = planMismatch(dir, plan) ?? preflight(dir);
  if (problem) {
    report.skipped = problem;
    log(`✖ Skipped dependency fixes: ${problem}`);
    return;
  }
  const base = currentRef(dir);
  const branch = fixBranchName(dir, planSteps(plan));
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

  if (scripts.length && opts.baseline && scripts.every((n) => opts.baseline[n])) {
    // Already run on the starting branch, right before (the app does that, to offer fixing them first).
    report.baseline = opts.baseline;
  } else if (scripts.length) {
    log('\nBefore the fix:');
    report.baseline = runScripts(dir, scripts, 'before', log);
  }
  // In one-at-a-time mode, each change is judged by the scripts that passed before it.
  let guard = opts.oneAtATime ? scripts.filter((n) => report.baseline[n].ok) : [];

  log('\nApplying fixes:');
  let npmOutput = '';
  for (const step of planSteps(plan)) {
    const snap = snapshotDepFiles(dir);
    log(`→ ${step.label}`);
    const r = applyStep(dir, step);
    npmOutput += r.output;
    const entry = { id: step.id, kind: step.kind, package: step.package ?? null, version: step.version ?? null, label: step.label, major: Boolean(step.major), findings: step.findings.length, fingerprints: step.findings.map((f) => f.fingerprint), status: 'applied' };
    report.steps.push(entry);
    if (!r.ok) {
      entry.status = 'failed';
      entry.error = tail(r.output);
      entry.command = r.command ?? null;
      // The whole output, for the user and for Claude (the tail often misses the ERESOLVE details).
      entry.logFile = path.join(ensureOutDir(dir), `fix-failed-${String(step.package ?? step.kind).replace(/[^\w.-]+/g, '_')}.log`);
      fs.writeFileSync(entry.logFile, `$ ${entry.command ?? step.label}\n\n${r.output}`);
      log(`  ✖ ${pm} failed:\n${entry.error.replace(/^/gm, '    ')}`);
      restoreDepFiles(dir, snap);
      continue;
    }
    // npm audit fix can succeed without changing anything (nothing it may fix without --force).
    if (!r.skipped && step.kind === 'audit-fix' && JSON.stringify(snapshotDepFiles(dir)) === JSON.stringify(snap)) {
      r.skipped = 'changed nothing (the rest needs a breaking upgrade, or a step below)';
    }
    if (r.skipped) {
      Object.assign(entry, { status: 'skipped', note: r.skipped });
      log(`  – Skipped: ${r.skipped}`);
      continue;
    }
    if (!guard.length) continue;
    let results = runScripts(dir, guard, `after-${step.id}`, log);
    let broken = guard.filter((n) => !results[n].ok);
    // Ask what to do (the app: fix it with Claude, keep it, or undo it); without onBreak, undo it.
    let decision = 'revert';
    let fixedAfter = false;
    while (broken.length && opts.onBreak) {
      decision = await opts.onBreak({
        step: entry, broken, results, fixedAfter,
      });
      if (decision !== 'retry') break;
      fixedAfter = true;
      results = { ...results, ...runScripts(dir, broken, `after-${step.id}-retry`, log) };
      broken = broken.filter((n) => !results[n].ok);
    }
    if (!broken.length) {
      if (fixedAfter) {
        entry.note = 'the scripts it broke were fixed in the code';
        log('  ✔ The scripts pass again: keeping this change.');
      }
      continue;
    }
    if (decision === 'keep') {
      Object.assign(entry, { broke: broken, keptBroken: true, results });
      for (const n of broken) report.after[n] = results[n];
      log(`  ⚠ Keeping this change although it breaks ${broken.map((n) => runLabel(pm, n)).join(', ')}`);
      // Those scripts fail now, so they can't judge the next changes.
      guard = guard.filter((n) => !broken.includes(n));
      continue;
    }
    Object.assign(entry, { status: 'reverted', broke: broken, results });
    log(`  ↩ Undoing this change: it broke ${broken.map((n) => runLabel(pm, n)).join(', ')}`);
    restoreDepFiles(dir, snap);
    syncInstall(dir);
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
 * `baseline`: results of those scripts already run on the starting branch, to skip running them again.
 * `onBreak({ step, broken, results, fixedAfter })`: in one-at-a-time mode, called when a change breaks
 * scripts; resolves to 'retry' (the code was changed, run them again), 'keep' or 'revert' (the default).
 */
export async function applyPlan(dir, plan, log = console.log, { scripts = [], oneAtATime = false, baseline = null, onBreak = null } = {}) {
  const report = {
    branch: null, base: null, skipped: null, scriptsSkipped: null, oneAtATime,
    scripts: [], baseline: {}, after: {}, steps: [], lsNew: [], lsPreexisting: 0, engines: [], diffStat: '',
  };
  if (hasDependencyChanges(plan)) await applyDependencyFixes(dir, plan, log, report, { scripts, oneAtATime, baseline, onBreak });
  if (plan.ignores.length) log(`✔ Saved ${plan.ignores.length} ignore decision(s) to ${addIgnores(dir, plan.ignores)}`);
  return report;
}

/** Scripts that passed before the fix and fail after it. */
export function regressions(report) {
  // One at a time: only the scripts a change broke and the user chose to keep anyway.
  if (report.oneAtATime) return [...new Set(report.steps.filter((st) => st.keptBroken).flatMap((st) => st.broke))];
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

/** The version of `name` installed now (node_modules, else package-lock), or null. */
export function installedNow(dir, name) {
  const read = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };
  return read(path.join(dir, 'node_modules', name, 'package.json'))?.version
    ?? read(path.join(dir, 'package-lock.json'))?.packages?.[`node_modules/${name}`]?.version
    ?? null;
}

/** A failed upgrade step that is in place now (done by hand or with Claude): installed ≥ its version. */
export function upgradeNowInPlace(dir, step) {
  if (!step.package || !validVersion(step.version ?? '')) return false;
  const v = installedNow(dir, step.package);
  return Boolean(v && validVersion(v) && compareVersions(v, step.version) >= 0);
}

/** The line that says why npm failed ("ERESOLVE could not resolve", "notarget …"), or ''. */
export function npmErrorHeadline(output) {
  const lines = String(output ?? '').split('\n').map((l) => l.replace(/^npm (error|ERR!)\s*/, '').trim()).filter(Boolean);
  return lines.find((l) => /ERESOLVE|ETARGET|notarget|E404|EBADENGINE|peer dep|Could not resolve|conflicting/i.test(l))
    ?? lines.find((l) => !/^(A complete log|code |\$ )/.test(l)) ?? '';
}
