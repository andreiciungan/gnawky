// `gnawky pre-commit`: run by the git hook from githook.js. When a commit changes a lockfile,
// it audits the staged lockfile and the one in the last commit, and blocks the commit only for
// findings the commit introduces (high and critical by default, minus ignored findings).
// Old findings never block, so a project with known issues can still commit.
//
// It never blocks for its own problems: offline mode, no network, or an audit error print a
// note and let the commit through. `git commit --no-verify` skips the hook entirely.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { run, isAvailable, scanNpmAudit } from './scanners.js';
import { scanYarnAudit } from './yarn.js';
import { loadIgnores, rank } from './finding.js';
import { loadConfig } from './config.js';
import { c, ticker, sevTag } from './ui.js';

const err = process.stderr;
const say = (s = '') => err.write(`${s}\n`);
const tag = c.accent('gnawky');
const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock'];
const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const REGISTRY_FILES = ['.npmrc', '.yarnrc'];

const git = (args, cwd) => run('git', args, { cwd, timeoutMs: 30000 });

/** A file as it is in the index (':path') or in a commit ('HEAD:path'); null if it isn't there. */
function gitShow(root, spec) {
  const r = git(['show', spec], root);
  return r.status === 0 ? r.stdout : null;
}

const posix = (...parts) => path.posix.join(...parts.filter((p) => p && p !== '.'));

/** Writes package.json + lockfile from git into a temp folder, with the project's registry settings. */
function snapshot(root, rel, lock, rev) {
  const pkg = gitShow(root, `${rev}:${posix(rel, 'package.json')}`);
  const lockText = gitShow(root, `${rev}:${posix(rel, lock)}`);
  if (pkg === null || lockText === null) return null;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gnawky-commit-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), pkg);
  fs.writeFileSync(path.join(tmp, lock), lockText);
  for (const f of REGISTRY_FILES) {
    const src = path.join(root, rel, f);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(tmp, f));
  }
  return tmp;
}

const audit = (dir, lock) => (lock === 'yarn.lock' ? scanYarnAudit(dir) : scanNpmAudit(dir, { fixes: false }));

/** True if the dependency sections of package.json differ between the last commit and the index. */
function depsChanged(root, file) {
  const parse = (t) => { try { return JSON.parse(t); } catch { return {}; } };
  const before = parse(gitShow(root, `HEAD:${file}`) ?? '{}');
  const after = parse(gitShow(root, `:${file}`) ?? '{}');
  return DEP_FIELDS.some((k) => JSON.stringify(before[k] ?? {}) !== JSON.stringify(after[k] ?? {}));
}

/** Checks one staged lockfile. Returns the number of new findings that block the commit. */
async function checkLockfile(root, file, minSeverity) {
  const rel = path.posix.dirname(file);
  const lock = path.posix.basename(file);
  const dir = path.join(root, rel);
  const where = rel === '.' ? lock : file;

  if (loadConfig(dir).offline) {
    say(c.gray(`${tag}: ${where} changed, not checked (offline mode in this project)`));
    return 0;
  }
  if (lock === 'yarn.lock' && !isAvailable('yarn')) {
    say(c.gray(`${tag}: ${where} changed, not checked (yarn isn't installed)`));
    return 0;
  }

  const done = ticker(`${tag}: ${where} changed, checking new dependencies`, err);
  const staged = snapshot(root, rel, lock, '');
  const before = snapshot(root, rel, lock, 'HEAD');
  try {
    if (!staged) {
      done(`${where}: package.json isn't in the commit, not checked`, 'skip');
      return 0;
    }
    const [now, then] = await Promise.all([audit(staged, lock), before ? audit(before, lock) : { findings: [] }]);
    if (!now.findings) {
      done(`${where}: not checked (${now.error ?? now.skipped}). Committing anyway.`, 'skip');
      return 0;
    }
    if (!then.findings) {
      done(`${where}: couldn't audit the last commit to compare (${then.error ?? then.skipped}). Committing anyway.`, 'skip');
      return 0;
    }
    const old = new Set(then.findings.map((f) => f.fingerprint));
    const ignored = new Set(loadIgnores(dir).map((i) => i.fingerprint));
    const fresh = now.findings.filter((f) => !old.has(f.fingerprint) && !ignored.has(f.fingerprint));
    const blocking = fresh.filter((f) => rank(f.severity) <= rank(minSeverity));
    const others = fresh.length - blocking.length;
    const extra = others ? `, ${others} lower-severity` : '';
    if (!blocking.length) {
      done(`${where}: no new ${minSeverity === 'critical' ? 'critical' : `${minSeverity} or critical`} findings${extra}`, 'ok');
      return 0;
    }
    done(`${where}: ${blocking.length} new finding(s)${extra}`, 'fail');
    for (const f of blocking.sort((a, b) => rank(a.severity) - rank(b.severity))) {
      say(`  ${sevTag(f.severity)} ${f.title}${f.url ? c.gray(`  ${f.url}`) : ''}`);
      if (f.fix?.detail) say(c.gray(`           ${f.fix.detail}`));
    }
    return blocking.length;
  } finally {
    for (const t of [staged, before]) if (t) fs.rmSync(t, { recursive: true, force: true });
  }
}

export async function preCommit({ minSeverity = 'high' } = {}) {
  const top = git(['rev-parse', '--show-toplevel'], process.cwd());
  if (top.status !== 0) return 0;
  const root = top.stdout.trim();
  const list = git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'], root);
  if (list.status !== 0) return 0;
  const files = list.stdout.split('\0').filter(Boolean);
  const locks = files.filter((f) => LOCKFILES.includes(path.posix.basename(f)));

  // package.json dependencies changed without the lockfile: nothing resolved to check yet.
  const lockDirs = new Set(locks.map((f) => path.posix.dirname(f)));
  for (const f of files.filter((x) => path.posix.basename(x) === 'package.json')) {
    const d = path.posix.dirname(f);
    if (lockDirs.has(d) || !LOCKFILES.some((l) => fs.existsSync(path.join(root, d, l)))) continue;
    if (depsChanged(root, f)) say(c.yellow(`${tag}: ${f} changes dependencies but its lockfile isn't staged; run your install and stage the lockfile to have it checked`));
  }

  let blocked = 0;
  for (const f of locks) blocked += await checkLockfile(root, f, minSeverity);
  if (blocked) {
    say(`\n${c.bold(c.red('Commit blocked'))}: this commit adds ${blocked} ${minSeverity === 'critical' ? 'critical' : 'high/critical'} finding(s).`);
    say(c.gray('Fix them (gnawky → Findings), ignore them with a reason in gnawky, or commit anyway with git commit --no-verify.'));
  }
  return blocked ? 1 : 0;
}
