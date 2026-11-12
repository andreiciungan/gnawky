// `gnawky guard npm|yarn <args>`: called by the shell functions from shellhook.js in place of
// `npm install <pkg>` / `yarn add <pkg>`. It checks the packages the command would add, asks
// when something looks wrong, and then runs the real command with the same arguments.
//
// The check never touches the project: the new packages are resolved in a temporary folder
// with `npm install --package-lock-only --ignore-scripts` (no tarballs, no install scripts),
// compared with the project's lockfile, and only the packages that are new are reported.
// Anything that keeps the check from working lets the command run as usual, with a note:
// the guard must never be the reason an install can't happen.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { runAsync, run } from './scanners.js';
import { parseLockfile } from './yarn.js';
import { PKG_NAME, packageManager } from './pm.js';
import { loadConfig } from './config.js';
import { c, ticker } from './ui.js';

const err = process.stderr;
const say = (s = '') => err.write(`${s}\n`);
const tag = c.accent('gnawky');

// npm's install command and all its aliases (npm help install).
const NPM_INSTALL = new Set(['install', 'i', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'isntall', 'add']);
// npm options that take a value as the next argument (--opt=value needs nothing special).
const NPM_VALUE_FLAGS = new Set(['--registry', '--tag', '--prefix', '-C', '--workspace', '-w', '--omit', '--include',
  '--cache', '--userconfig', '--save-prefix', '--install-strategy', '--loglevel', '--before']);
const SEVERITY = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'info' };
const BLOCKING = new Set(['critical', 'high']);
const NEW_VERSION_DAYS = 2;
const PUBLIC_REGISTRY = /^https:\/\/registry\.(npmjs\.org|yarnpkg\.com)\//;

/**
 * What the command adds: { packages: ['express@^4', ...], global } or null when it isn't
 * an "add packages" command (plain `npm install`, `npm run`, `yarn build`, ...).
 */
export function parseCommand(pm, args) {
  const words = [];
  let global = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '-g' || a === '--global' || a === '--location=global') global = true;
    if (a === '--') { words.push(...args.slice(i + 1)); break; }
    if (a.startsWith('-')) {
      if (pm === 'npm' && NPM_VALUE_FLAGS.has(a)) i++;
      continue;
    }
    words.push(a);
  }
  if (pm === 'npm') {
    if (!NPM_INSTALL.has(words[0])) return null;
    return words.length > 1 ? { packages: words.slice(1), global } : null;
  }
  if (pm === 'yarn') {
    // yarn add x · yarn workspace <name> add x · yarn global add x
    let w = words;
    if (w[0] === 'workspace') w = w.slice(2);
    if (w[0] === 'global') { global = true; w = w.slice(1); }
    if (w[0] !== 'add') return null;
    return w.length > 1 ? { packages: w.slice(1), global } : null;
  }
  return null;
}

/** "express@^4" -> { name: 'express', spec: '^4' }; null for git URLs, paths, tarballs, GitHub shorthands. */
export function parseSpec(arg) {
  const at = arg.indexOf('@', 1);
  const name = at === -1 ? arg : arg.slice(0, at);
  const spec = at === -1 ? 'latest' : arg.slice(at + 1);
  if (!PKG_NAME.test(name) || /^(file|link|git|git\+\w+|https?|github):/.test(spec)) return null;
  return { name, spec: spec || 'latest', implicit: at === -1 };
}

/** The folder npm/yarn will install into: the nearest one with a package.json. */
function projectDir(start) {
  for (let d = start; ; d = path.dirname(d)) {
    if (fs.existsSync(path.join(d, 'package.json'))) return d;
    if (path.dirname(d) === d) return null;
  }
}

/** The nearest lockfile at or above the project (a workspace root keeps it higher up). */
function findLockDir(dir) {
  for (let d = dir; ; d = path.dirname(d)) {
    if (packageManager(d)) return d;
    if (path.dirname(d) === d) return null;
  }
}

/** Names from a package-lock path like "node_modules/a/node_modules/@s/b" -> "@s/b". */
const nameFromLockPath = (p) => p.slice(p.lastIndexOf('node_modules/') + 'node_modules/'.length);

/** "name@version" of every package in the project's lockfile. */
export function installedPackages(lockDir) {
  const out = new Set();
  if (!lockDir) return out;
  const pm = packageManager(lockDir);
  if (pm === 'yarn') {
    for (const e of parseLockfile(fs.readFileSync(path.join(lockDir, 'yarn.lock'), 'utf8'))) {
      if (e.name && e.version) out.add(`${e.name}@${e.version}`);
    }
    return out;
  }
  if (pm !== 'npm') return out;
  const file = ['package-lock.json', 'npm-shrinkwrap.json'].map((f) => path.join(lockDir, f)).find((f) => fs.existsSync(f));
  const lock = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (lock.packages) {
    for (const [p, e] of Object.entries(lock.packages)) {
      if (p && e.version) out.add(`${e.name ?? nameFromLockPath(p)}@${e.version}`);
    }
  } else {
    const walk = (deps) => Object.entries(deps ?? {}).forEach(([n, e]) => { out.add(`${n}@${e.version}`); walk(e.dependencies); });
    walk(lock.dependencies);
  }
  return out;
}

/** Registry settings for the temporary folder: the project's .npmrc, and Yarn's registry if it isn't the default. */
function registrySetup(dir, lockDir, pm, tmp) {
  for (const d of [...new Set([dir, lockDir].filter(Boolean))]) {
    const rc = path.join(d, '.npmrc');
    if (fs.existsSync(rc)) { fs.copyFileSync(rc, path.join(tmp, '.npmrc')); break; }
  }
  if (pm !== 'yarn') return [];
  const r = run('yarn', ['config', 'get', 'registry'], { cwd: dir, timeoutMs: 15000 });
  const reg = r.status === 0 ? r.stdout.trim() : '';
  return reg && /^https?:\/\//.test(reg) && !/registry\.yarnpkg\.com/.test(reg) ? ['--registry', reg] : [];
}

/** Resolves the new packages in a temp folder: [{ name, version, resolved, installScript, direct }]. */
async function resolveNew(dir, lockDir, pm, specs) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gnawky-guard-'));
  try {
    const deps = Object.fromEntries(specs.map((s) => [s.name, s.spec]));
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'gnawky-check', private: true, dependencies: deps }));
    const reg = registrySetup(dir, lockDir, pm, tmp);
    const r = await runAsync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund',
      '--loglevel=error', ...reg], { cwd: tmp, timeoutMs: 3 * 60 * 1000 });
    if (r.status !== 0) {
      const why = (r.stderr || String(r.error ?? '')).split('\n').find((l) => /ERR!.*(404|E\d{3}|code|not found)/i.test(l)) ?? r.stderr.split('\n')[0];
      return { error: `could not resolve the packages (${(why ?? '').replace(/^npm (ERR!|error)\s*/, '').trim() || 'npm failed'})` };
    }
    const lock = JSON.parse(fs.readFileSync(path.join(tmp, 'package-lock.json'), 'utf8'));
    const have = installedPackages(lockDir);
    const seen = new Set();
    const pkgs = [];
    for (const [p, e] of Object.entries(lock.packages ?? {})) {
      if (!p || !e.version) continue;
      const name = e.name ?? nameFromLockPath(p);
      const key = `${name}@${e.version}`;
      if (have.has(key) || seen.has(key)) continue;
      seen.add(key);
      pkgs.push({ name, version: e.version, resolved: e.resolved ?? '', installScript: Boolean(e.hasInstallScript) });
    }
    const audit = pkgs.length ? await auditTree(tmp, reg) : { advisories: new Map() };
    return { pkgs, ...audit };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/** Advisories for the resolved tree, by package name. */
async function auditTree(tmp, reg) {
  const r = await runAsync('npm', ['audit', '--json', ...reg], { cwd: tmp, timeoutMs: 2 * 60 * 1000 });
  let data;
  try { data = JSON.parse(r.stdout); } catch { return { advisories: new Map(), auditError: 'npm audit gave no result' }; }
  if (data.error) return { advisories: new Map(), auditError: data.error.summary ?? 'npm audit failed' };
  const advisories = new Map();
  for (const [name, v] of Object.entries(data.vulnerabilities ?? {})) {
    const list = (v.via ?? []).filter((x) => typeof x === 'object')
      .map((a) => ({ title: a.title, url: a.url, range: a.range, severity: SEVERITY[a.severity] ?? 'medium' }));
    if (list.length) advisories.set(name, list);
  }
  return { advisories };
}

/** Publish dates from deps.dev, only for packages that came from the public registry (private names never leave). */
async function publishDates(pkgs) {
  const todo = pkgs.filter((p) => PUBLIC_REGISTRY.test(p.resolved)).slice(0, 60);
  const dates = new Map();
  let i = 0;
  const worker = async () => {
    while (i < todo.length) {
      const p = todo[i++];
      try {
        const url = `https://api.deps.dev/v3/systems/npm/packages/${encodeURIComponent(p.name)}/versions/${encodeURIComponent(p.version)}`;
        const res = await fetch(url, { signal: AbortSignal.timeout(10000), headers: { 'User-Agent': 'gnawky' } });
        if (res.ok) {
          const d = await res.json();
          if (d.publishedAt) dates.set(`${p.name}@${p.version}`, d.publishedAt);
        }
      } catch { /* the age is a hint; skip it on errors */ }
    }
  };
  await Promise.all(Array.from({ length: 8 }, worker));
  return { dates, privateCount: pkgs.length - todo.length };
}

const daysAgo = (iso) => (Date.now() - Date.parse(iso)) / 86400000;
const ago = (iso) => {
  const h = (Date.now() - Date.parse(iso)) / 3600000;
  return h < 48 ? `${Math.max(1, Math.round(h))} hour(s) ago` : `${Math.round(h / 24)} days ago`;
};

function askYesNo(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: err });
    rl.on('SIGINT', () => { rl.close(); resolve(false); });
    rl.question(question, (a) => { rl.close(); resolve(/^y(es)?$/i.test(a.trim())); });
  });
}

/** Runs the real npm/yarn with the original arguments and exits with its status. */
function runReal(pm, args) {
  const child = spawn(pm, args, { stdio: 'inherit' });
  child.on('error', (e) => { say(`${tag}: could not start ${pm}: ${e.message}`); process.exit(127); });
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    else process.exit(code ?? 1);
  });
}

/** Checks the packages; true means go ahead with the install. */
async function check(pm, args, cmd) {
  const dir = projectDir(process.cwd());
  if (!dir) return true;
  if (loadConfig(dir).offline) {
    say(c.gray(`${tag}: offline mode in this project, packages not checked`));
    return true;
  }
  const lockDir = findLockDir(dir);
  const lockPm = lockDir && packageManager(lockDir);
  if (lockPm === 'pnpm' || lockPm === 'yarn-berry') {
    say(c.gray(`${tag}: ${lockPm === 'pnpm' ? 'pnpm' : 'Yarn 2+'} projects aren't supported yet, packages not checked`));
    return true;
  }

  const specs = [];
  const unchecked = [];
  for (const a of cmd.packages) {
    const s = parseSpec(a);
    if (s) specs.push(s); else unchecked.push(a);
  }
  // `npm install x` without a version keeps the range package.json already has for x (yarn add takes latest).
  if (pm === 'npm') {
    let pkg = {};
    try { pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { /* none */ }
    const current = Object.assign({}, pkg.optionalDependencies, pkg.devDependencies, pkg.dependencies);
    for (const s of specs) if (s.implicit && current[s.name]) s.spec = current[s.name];
  }
  if (unchecked.length) say(c.yellow(`${tag}: can't check ${unchecked.join(', ')} (not a registry package)`));
  if (!specs.length) return true;

  const label = specs.map((s) => (s.implicit ? s.name : `${s.name}@${s.spec}`)).join(', ');
  const done = ticker(`${tag}: checking ${label} before installing`, err);
  const res = await resolveNew(dir, lockDir, pm, specs);
  if (res.error) {
    done(`${res.error}; running ${pm} without the check`, 'skip');
    return true;
  }
  const { dates, privateCount } = res.pkgs.length ? await publishDates(res.pkgs) : { dates: new Map(), privateCount: 0 };

  const problems = [];
  const notes = [];
  const young = [];
  const scripts = [];
  for (const p of res.pkgs) {
    const id = `${p.name}@${p.version}`;
    for (const a of res.advisories.get(p.name) ?? []) {
      const line = `${a.severity.toUpperCase()} ${id}: ${a.title}${a.url ? c.gray(` ${a.url}`) : ''}`;
      (BLOCKING.has(a.severity) ? problems : notes).push(line);
    }
    const published = dates.get(id);
    if (published && daysAgo(published) < NEW_VERSION_DAYS) young.push(`${id} (${ago(published)})`);
    if (p.installScript) scripts.push(id);
  }
  const list = (xs, max = 3) => xs.slice(0, max).join(', ') + (xs.length > max ? ` and ${xs.length - max} more` : '');
  if (young.length) {
    problems.push(`${young.length === 1 ? 'Published' : `${young.length} packages published`} in the last ${NEW_VERSION_DAYS} days: ${list(young)}. `
      + 'Malicious versions are usually caught within a day or two; consider waiting, or pinning an older version.');
  }
  if (scripts.length) notes.push(`Runs an install script: ${list(scripts, 5)}`);

  const count = `${res.pkgs.length} new package${res.pkgs.length === 1 ? '' : 's'}`;
  if (!res.pkgs.length) {
    done('nothing new to install', 'ok');
    return true;
  }
  done(`${count} checked${problems.length ? `, ${problems.length} problem(s)` : notes.length ? '' : ', nothing found'}`, problems.length ? 'fail' : 'ok');
  for (const p of problems) say(`  ${c.red('✖')} ${p}`);
  for (const n of notes) say(`  ${c.gray('•')} ${n}`);
  const hints = [
    res.auditError ? `advisories not checked: ${res.auditError}` : null,
    privateCount ? `publish date not checked for ${privateCount} package(s) from a private registry` : null,
  ].filter(Boolean);
  for (const h of hints) say(c.gray(`  ${h}`));
  if (!problems.length) return true;

  if (!process.stdin.isTTY) {
    say(c.yellow(`${tag}: not a terminal, so not asking; installing anyway`));
    return true;
  }
  const yes = await askYesNo(`${tag}: install anyway? ${c.gray('[y/N]')} `);
  if (!yes) say(`${tag}: not installed. Nothing was changed.`);
  return yes;
}

export async function guard(argv) {
  const [pm, ...args] = argv;
  if (pm !== 'npm' && pm !== 'yarn') {
    say(`usage: gnawky guard npm|yarn <arguments>`);
    process.exit(2);
  }
  const cmd = process.env.GNAWKY_SKIP ? null : parseCommand(pm, args);
  let go = true;
  if (cmd && !cmd.global) {
    try {
      go = await check(pm, args, cmd);
    } catch (e) {
      say(c.yellow(`${tag}: check failed (${e.message}); running ${pm} without it`));
    }
  }
  // Tells the shell function Gnawky started and decided; without it the function runs npm/yarn itself.
  if (process.env.GNAWKY_DECIDED) {
    try { fs.writeFileSync(process.env.GNAWKY_DECIDED, go ? 'install' : 'declined'); } catch { /* best effort */ }
  }
  if (go) runReal(pm, args);
  else process.exit(1);
}
