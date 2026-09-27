import fs from 'node:fs';
import path from 'node:path';
import { run } from './scanners.js';
import { ensureOutDir } from './config.js';

// Only these package.json scripts are ever offered, and only after the user
// confirms: they run the project's own code. The names are constants, so they
// are safe to pass to npm even where Windows needs a shell.
export const VERIFY_SCRIPTS = ['lint', 'typecheck', 'build', 'test'];
const SCRIPT_TIMEOUT_MS = 15 * 60 * 1000;
const NPM_QUIET = ['--no-audit', '--no-fund'];

const readJson = (file) => {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
};

export const hasNodeModules = (dir) => fs.existsSync(path.join(dir, 'node_modules'));

/** package.json scripts that can verify a fix, skipping npm's "no test specified" placeholder. */
export function detectScripts(dir) {
  const scripts = readJson(path.join(dir, 'package.json'))?.scripts ?? {};
  return VERIFY_SCRIPTS.filter((n) => typeof scripts[n] === 'string' && !/no test specified/.test(scripts[n]));
}

/** Runs `npm run <name>`; the full output goes to .gnawky/verify-<phase>-<name>.log. */
export function runScript(dir, name, phase) {
  if (!VERIFY_SCRIPTS.includes(name)) throw new Error(`not a verify script: ${name}`);
  const started = Date.now();
  const r = run('npm', ['run', name], { cwd: dir, timeoutMs: SCRIPT_TIMEOUT_MS, env: { CI: 'true' } });
  const output = `${r.stdout}\n${r.stderr}`.trim();
  const logFile = path.join(ensureOutDir(dir), `verify-${phase.replace(/[^A-Za-z0-9.-]/g, '_')}-${name}.log`);
  fs.writeFileSync(logFile, output + '\n');
  const timedOut = r.error?.code === 'ETIMEDOUT';
  return {
    name,
    ok: !r.error && r.status === 0,
    timedOut,
    seconds: Math.round((Date.now() - started) / 1000),
    tail: output.split('\n').slice(-25).join('\n'),
    logFile,
  };
}

export function runScripts(dir, names, phase, log = () => {}) {
  const results = {};
  for (const name of names) {
    log(`  running npm run ${name}…`);
    results[name] = runScript(dir, name, phase);
    log(`    ${describeResult(results[name])}`);
  }
  return results;
}

export const describeResult = (r) =>
  r.ok ? `✔ passed (${r.seconds}s)` : r.timedOut ? '✖ timed out' : `✖ failed (${r.seconds}s)`;

/** Installs the locked dependencies without running install scripts. */
export function installLocked(dir) {
  return run('npm', ['ci', '--ignore-scripts', ...NPM_QUIET], { cwd: dir });
}

/** Brings node_modules in line with package.json / the lockfile, without install scripts. */
export function syncInstall(dir) {
  return run('npm', ['install', '--ignore-scripts', ...NPM_QUIET], { cwd: dir });
}

/** Dependency tree problems reported by `npm ls` (missing, invalid, unmet peer), without "extraneous". */
export function npmLsProblems(dir) {
  const r = run('npm', ['ls', '--all', '--json'], { cwd: dir });
  let data;
  try { data = JSON.parse(r.stdout); } catch { return null; }
  return (data.problems ?? [])
    .filter((p) => !p.startsWith('extraneous'))
    .map((p) => p.split(dir + path.sep).join('').split(dir).join('.'));
}

/** Packages npm warned about because they don't support the current Node version. */
export function engineWarnings(npmOutput) {
  const found = new Map();
  const re = /EBADENGINE\s+package: '([^']+)',\s*\n.*EBADENGINE\s+required: (\{[^}]*\})/g;
  for (const m of npmOutput.matchAll(re)) found.set(m[1], m[2]);
  return [...found].map(([pkg, required]) => `${pkg} requires ${required.replace(/[{}]/g, '').trim()}`);
}

/** Installed packages that have install scripts (skipped by --ignore-scripts, so they may need `npm rebuild`). */
export function packagesWithInstallScripts(dir) {
  const lock = readJson(path.join(dir, 'package-lock.json')) ?? readJson(path.join(dir, 'npm-shrinkwrap.json'));
  return Object.entries(lock?.packages ?? {})
    .filter(([key, p]) => key && p.hasInstallScript)
    .map(([key]) => key.split('node_modules/').pop());
}

/** Runs every package's install scripts. Only after the user explicitly agrees. */
export function rebuild(dir) {
  return run('npm', ['rebuild'], { cwd: dir });
}

// After an upgrade the same vulnerability can come back under a different advisory
// ID (e.g. js-yaml 3.x vs 4.x), so dependency findings are matched by package and title.
const sameIssue = (f) => (f.package ? `${f.tool}|${f.title}` : f.fingerprint);

/** Compares findings before and after a fix. */
export function diffFindings(before, after) {
  const was = new Set(before.map(sameIssue));
  const now = new Set(after.map(sameIssue));
  return {
    fixed: before.filter((f) => !now.has(sameIssue(f))),
    remaining: after.filter((f) => was.has(sameIssue(f))),
    added: after.filter((f) => !was.has(sameIssue(f))),
  };
}
