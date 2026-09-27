import { run } from './scanners.js';
import { addIgnores } from './finding.js';

const PKG_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const PKG_VERSION = /^[0-9A-Za-z.+-]+$/;
const OWN_FILES = ['.gnawky/', '.gnawky-ignore.json'];

const git = (dir, args) => run('git', args, { cwd: dir });

export const isAutoFixable = (f) => f.fix?.type === 'npm-audit-fix' || f.fix?.type === 'npm-major-upgrade';

export const emptyPlan = () => ({ auditFix: [], upgrades: [], ignores: [] });
export const planSize = (p) => p.auditFix.length + p.upgrades.length + p.ignores.length;
export const hasDependencyChanges = (p) => p.auditFix.length + p.upgrades.length > 0;

export function addFixToPlan(plan, f) {
  if (f.fix.type === 'npm-audit-fix') plan.auditFix.push(f);
  else if (f.fix.type === 'npm-major-upgrade') plan.upgrades.push(f);
}

export function describePlan(plan) {
  const lines = [];
  if (plan.auditFix.length) lines.push(`npm audit fix (non-breaking updates) for ${plan.auditFix.length} finding(s)`);
  const seen = new Set();
  for (const f of plan.upgrades) {
    if (seen.has(f.fix.package)) continue;
    seen.add(f.fix.package);
    lines.push(`upgrade ${f.fix.package} → ${f.fix.version}  (major version: may break your code)`);
  }
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

function applyDependencyFixes(dir, plan, log) {
  const problem = preflight(dir);
  if (problem) {
    log(`✖ Skipped dependency fixes: ${problem}`);
    return null;
  }
  const branch = `gnawky/fix-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}`;
  if (git(dir, ['checkout', '-b', branch]).status !== 0) {
    log(`✖ Could not create branch ${branch}.`);
    return null;
  }
  log(`→ Created branch ${branch}`);

  // --ignore-scripts: third-party install scripts never run during a fix.
  // --force is never used: it can silently install breaking major versions.
  if (plan.auditFix.length) {
    log('→ npm audit fix --ignore-scripts');
    const r = run('npm', ['audit', 'fix', '--ignore-scripts'], { cwd: dir });
    if (r.status !== 0 && r.status !== 1) log(r.stderr.slice(0, 500));
  }
  const seen = new Set();
  for (const f of plan.upgrades) {
    const { package: name, version } = f.fix;
    if (seen.has(name)) continue;
    seen.add(name);
    if (!PKG_NAME.test(name) || !PKG_VERSION.test(version)) {
      log(`✖ Refused suspicious package spec: ${name}@${version}`);
      continue;
    }
    log(`→ npm install ${name}@${version} --ignore-scripts`);
    const r = run('npm', ['install', `${name}@${version}`, '--ignore-scripts'], { cwd: dir });
    if (r.status !== 0) log(r.stderr.slice(0, 500));
  }

  log('\nChanged files:\n' + (git(dir, ['diff', '--stat']).stdout || '  (none)'));
  log('Next steps:');
  log('  1. Review the changes:  git diff');
  log('  2. If a package needs a build step:  npm rebuild');
  log('  3. Run your tests, then commit on this branch.');
  log(`  To throw it all away:  git restore package.json package-lock.json && git checkout - && git branch -D ${branch}`);
  return branch;
}

export function applyPlan(dir, plan, log = console.log) {
  let branch = null;
  if (hasDependencyChanges(plan)) branch = applyDependencyFixes(dir, plan, log);
  if (plan.ignores.length) log(`✔ Saved ${plan.ignores.length} ignore decision(s) to ${addIgnores(dir, plan.ignores)}`);
  return { branch };
}
