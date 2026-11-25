// `gnawky pre-push`: run by the git pre-push hook from githook.js. Lists the critical and high
// dependency advisories that ship to production (prod.js), old ones included, as a reminder
// before the code leaves this machine. It only warns: it always exits 0, so a push is never
// blocked. The pre-commit check (precommit.js) stays the gate for newly added findings.
//
// It audits on every push, so advisories published since the last scan show up. Each result is
// saved in .gnawky/cache/pre-push.json; when the audit fails (no network, registry down) the
// saved result for the same package.json + lockfile, or the last full scan, is shown instead,
// with its date.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { run, scanDependencies } from './scanners.js';
import { loadIgnores, rank } from './finding.js';
import { loadConfig, ensureOutDir, OUT_DIR } from './config.js';
import { loadLastScan } from './scan.js';
import { isDependencyFinding, isDepAudit, packageManager, lockfileName } from './pm.js';
import { classifyScope, isProdFirst } from './prod.js';
import { groupFindings, groupFixes } from './groups.js';
import { highestNeeds } from './coverage.js';
import { c, ticker, sevTag } from './ui.js';

const err = process.stderr;
const say = (s = '') => err.write(`${s}\n`);
const tag = c.accent('gnawky');
const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock'];

const git = (args, cwd) => run('git', args, { cwd, timeoutMs: 30000 });
const cacheFile = (dir) => path.join(dir, OUT_DIR, 'cache', 'pre-push.json');

/** Folders (relative to the repository root, '.' for the root) with a lockfile tracked by git. */
function projectDirs(root) {
  const r = git(['ls-files', '-z', '--', ...LOCKFILES.flatMap((l) => [l, `**/${l}`])], root);
  if (r.status !== 0) return [];
  const dirs = r.stdout.split('\0').filter(Boolean)
    .filter((f) => !f.split('/').includes('node_modules'))
    .map((f) => path.posix.dirname(f));
  return [...new Set(dirs)].sort();
}

/** Fingerprint of what the audit depends on: package.json + the lockfile in use. */
function depsHash(dir) {
  const h = crypto.createHash('sha256');
  for (const f of ['package.json', lockfileName(packageManager(dir))]) {
    try { h.update(f).update(fs.readFileSync(path.join(dir, f))); } catch { h.update(`${f}:missing`); }
  }
  return h.digest('hex');
}

const mtime = (file) => { try { return fs.statSync(file).mtimeMs; } catch { return Infinity; } };

/**
 * Dependency findings from the last full scan, when it is newer than package.json and the
 * lockfile, its audit ran, and it kept high findings (minimum severity).
 */
function fromLastScan(dir) {
  const scan = loadLastScan(dir);
  if (!scan?.date) return null;
  const at = new Date(scan.date).getTime();
  if (['package.json', lockfileName(packageManager(dir))].some((f) => mtime(path.join(dir, f)) > at)) return null;
  if (rank(scan.minSeverity ?? 'low') < rank('high')) return null;
  if (!scan.tools?.some((t) => isDepAudit({ tool: t.name }) && t.status === 'ran')) return null;
  return { findings: scan.findings.filter(isDependencyFinding), at };
}

function fromCache(dir, hash) {
  try {
    const c = JSON.parse(fs.readFileSync(cacheFile(dir), 'utf8'));
    if (c.hash !== hash) return null;
    return c;
  } catch {
    return null;
  }
}

function saveCache(dir, hash, findings) {
  try {
    ensureOutDir(dir);
    fs.mkdirSync(path.dirname(cacheFile(dir)), { recursive: true });
    fs.writeFileSync(cacheFile(dir), JSON.stringify({ hash, at: Date.now(), findings }) + '\n');
  } catch { /* without it, a failed audit later just has nothing to fall back on */ }
}

/**
 * One line on what fixes all of a group's critical/high advisories: "upgrade axios to 1.12.0",
 * "upgrade next to 15.5.7 (major)", "npm audit fix", "no fixed release yet" or "manual fix".
 */
function fixHint(g) {
  const fixes = groupFixes(g).map((x) => x.fix ?? {});
  if (fixes.some((f) => f.stillVulnerable && !f.needs)) return 'no fixed release yet';
  const major = fixes.some((f) => f.type === 'npm-major-upgrade' || f.upgrade === 'npm-major-upgrade') ? ' (major)' : '';
  // What each fix needs: a version to install, or (for advisories that version leaves open) a later one.
  const needs = fixes.map((f) => (f.stillVulnerable ? f.needs : f.version ? { version: f.version } : null));
  if (needs.every(Boolean)) {
    const top = highestNeeds(needs);
    return top.version ? `upgrade ${g.package} to ${top.version}${major}` : `needs a release of ${g.package} after ${top.after}`;
  }
  if (fixes.every((f) => f.type === 'npm-audit-fix')) return 'npm audit fix';
  return 'manual fix, see gnawky';
}

/** "direct dependency", or the production dependencies that bring it in. */
function viaText(g) {
  const via = g.lead.via ?? [];
  if (via.length === 1 && via[0] === g.package) return 'direct dependency';
  return g.lead.scopeNote ?? '';
}

/**
 * Audits one project. Returns { project, checked, error?, resultsFrom?, items }, where items are
 * the packages with critical/high advisories that ship to production, most severe first.
 * `onStart` gets called before the audit and returns the function that ends its progress line.
 */
async function checkProject(root, rel, onStart = () => () => {}) {
  const dir = path.join(root, rel);
  const project = rel === '.' ? path.basename(root) : rel;
  if (loadConfig(dir).offline) return { project, checked: false, error: 'offline mode in this project', items: [] };

  const hash = depsHash(dir);
  const done = onStart(project);
  const res = await scanDependencies(dir);
  let found;
  let error;
  if (res.findings) {
    classifyScope(dir, res.findings);
    saveCache(dir, hash, res.findings);
    found = { findings: res.findings };
  } else {
    error = res.error ?? res.skipped;
    // Older results for the same dependencies, newest first; better than nothing, marked as such.
    found = [fromCache(dir, hash), fromLastScan(dir)].filter(Boolean).sort((a, b) => b.at - a.at)[0];
    if (!found) return { project, checked: false, error, items: [], done };
  }

  const ignored = new Set(loadIgnores(dir).map((i) => i.fingerprint));
  const urgent = found.findings
    .filter((f) => !ignored.has(f.fingerprint) && isProdFirst(f))
    .sort((a, b) => rank(a.severity) - rank(b.severity));
  const items = groupFindings(urgent).map((g) => ({
    package: g.package,
    severity: g.severity,
    advisories: g.findings.length,
    vulnerablePackages: [...new Set(g.findings.map((f) => f.package))],
    fix: fixHint(g),
    via: viaText(g),
    ids: [...new Set(g.findings.flatMap((f) => [f.ghsa, ...(f.cves ?? [])]).filter(Boolean))],
  }));
  return {
    project,
    checked: true,
    ...(error ? { error, resultsFrom: new Date(found.at).toISOString() } : {}),
    items,
    done,
  };
}

/** Prints one project's result under its progress line. Returns how many packages it listed. */
function printProject(r) {
  const finish = r.done ?? ((text, kind) => say(`  ${{ ok: c.green('✔'), warn: c.yellow('!'), skip: c.yellow('–') }[kind]} ${text}`));
  if (!r.checked) {
    if (r.done) finish(`${r.project}: not checked (${r.error}). Pushing anyway.`, 'skip');
    else say(c.gray(`${tag}: ${r.project}: not checked (${r.error})`));
    return 0;
  }
  const n = r.items.length;
  const label = `${r.project}: ${n ? `${n} package(s) with critical/high advisories ship to production` : 'no critical/high advisories in production dependencies'}`;
  const note = r.resultsFrom ? c.yellow(` (audit failed: ${r.error}; showing results from ${new Date(r.resultsFrom).toLocaleString()}, newer advisories are missing)`) : '';
  finish(`${label}${note}`, n ? 'warn' : 'ok');
  const width = Math.min(30, Math.max(...r.items.map((i) => i.package.length), 0));
  for (const i of r.items) {
    say(`    ${sevTag(i.severity)} ${i.package.padEnd(width)}  ${i.advisories} advisor${i.advisories === 1 ? 'y' : 'ies'}: ${i.fix}${i.via ? c.gray(`  (${i.via})`) : ''}`);
  }
  return n;
}

/**
 * The hook's check. Prints a warning to stderr, or with `json` prints
 * { root, projects: [...] } to stdout (for Claude and scripts). Always returns 0.
 */
export async function prePush({ json = false } = {}) {
  const results = [];
  try {
    const top = git(['rev-parse', '--show-toplevel'], process.cwd());
    if (top.status !== 0) {
      if (json) process.stdout.write(JSON.stringify({ error: 'not a git repository', projects: [] }, null, 2) + '\n');
      return 0;
    }
    const root = top.stdout.trim();
    const onStart = json ? undefined : (project) => ticker(`${tag}: ${project}: checking production dependencies`, err);
    let total = 0;
    for (const rel of projectDirs(root)) {
      const r = await checkProject(root, rel, onStart);
      results.push(r);
      if (!json) total += printProject(r);
    }
    if (json) {
      process.stdout.write(JSON.stringify({ root, projects: results.map(({ done, ...r }) => r) }, null, 2) + '\n');
    } else if (total) {
      say(c.yellow(`\n${tag}: pushing anyway; this is a reminder, not a block.`));
      say(c.gray('Fix them in gnawky (Findings, or gnawky fix <package>), or ignore one with a reason: gnawky ignore <package> --reason "…"'));
    }
  } catch (e) {
    if (json) process.stdout.write(JSON.stringify({ error: e.message, projects: results.map(({ done, ...r }) => r) }, null, 2) + '\n');
    else say(c.gray(`${tag}: pre-push check failed (${e.message}). Pushing anyway.`));
  }
  return 0;
}
