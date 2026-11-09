// Forcing a version of a package installed by other packages: npm "overrides" and the
// shared pieces of yarn "resolutions" (how to pin the forced version, writing package.json).
import fs from 'node:fs';
import path from 'node:path';
import { run, runAsync } from './scanners.js';
import { PKG_NAME, PKG_VERSION } from './pm.js';
import {
  valid, parse, compare, satisfies, isBreaking,
} from './semver.js';

const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'];

const readJson = (file) => {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
};

/** Edits package.json in place, keeping its indentation and trailing newline. */
export function writePackageJson(dir, mutate) {
  const file = path.join(dir, 'package.json');
  const text = fs.readFileSync(file, 'utf8');
  const indent = /^[ \t]+(?=")/m.exec(text)?.[0] ?? '  ';
  const pkg = JSON.parse(text);
  mutate(pkg);
  fs.writeFileSync(file, JSON.stringify(pkg, null, indent) + (text.endsWith('\n') ? '\n' : ''));
}

// ------------------------------------------------------------ pin style

/** The version written for a forced package: "^1.2.3" (later minor/patch releases allowed) or "1.2.3" (exact). */
export const pinSpec = (version, pin) => (pin === 'exact' ? version : `^${version}`);

/** Entries in package.json "resolutions" (yarn) or "overrides" (npm) that force `name`. String values only. */
export function forcedEntries(pkg, name) {
  const yarn = Object.entries(pkg?.resolutions ?? {})
    .filter(([k, v]) => typeof v === 'string' && (k === name || k.endsWith(`/${name}`)));
  const npm = Object.entries(pkg?.overrides ?? {})
    .filter(([k, v]) => typeof v === 'string' && (k === name || k.startsWith(`${name}@`)));
  return [...yarn, ...npm];
}

/** True when the project saves new dependencies with exact versions by default. */
function savesExact(dir) {
  const read = (f) => { try { return fs.readFileSync(path.join(dir, f), 'utf8'); } catch { return ''; } };
  if (/^\s*save-exact\s*=\s*true\s*$/m.test(read('.npmrc'))) return true;
  if (/^\s*save-exact\s+true\s*$/m.test(read('.yarnrc')) || /^\s*save-prefix\s+["']{2}\s*$/m.test(read('.yarnrc'))) return true;
  const pkg = readJson(path.join(dir, 'package.json'));
  const specs = DEP_FIELDS.flatMap((k) => Object.values(pkg?.[k] ?? {}));
  return specs.length >= 3 && specs.every((s) => valid(s));
}

/**
 * Which pin style Gnawky recommends for forcing `name`, and why.
 * A range by default, so later releases (including security fixes) still arrive; exact when the
 * project already pins this package exactly, or pins its dependencies exactly in general.
 */
export function recommendPin(dir, name) {
  const pkg = readJson(path.join(dir, 'package.json'));
  const existing = forcedEntries(pkg, name);
  if (existing.length) {
    return existing.every(([, v]) => valid(v))
      ? { pin: 'exact', reason: `package.json already pins ${name} to an exact version.` }
      : { pin: 'caret', reason: `package.json already forces ${name} with a version range.` };
  }
  if (savesExact(dir)) return { pin: 'exact', reason: 'this project pins its dependencies to exact versions.' };
  return { pin: 'caret', reason: 'later patch and minor releases, including future security fixes, still arrive.' };
}

// ------------------------------------------------------------ npm overrides: planning

/** Installed copies of every package in package-lock.json: name -> [{ key, version }]. */
function lockCopies(lock) {
  const copies = new Map();
  for (const [key, p] of Object.entries(lock?.packages ?? {})) {
    const i = key.lastIndexOf('node_modules/');
    if (i === -1 || !p?.version || p.link) continue;
    const name = key.slice(i + 'node_modules/'.length);
    copies.set(name, [...(copies.get(name) ?? []), { key, version: p.version }]);
  }
  return copies;
}

/** Names of installed packages that depend on `name`. */
function dependents(lock, name) {
  const out = new Set();
  for (const [key, p] of Object.entries(lock?.packages ?? {})) {
    if (!key) continue;
    const deps = { ...p.dependencies, ...p.optionalDependencies, ...p.peerDependencies };
    if (deps[name]) out.add(key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length));
  }
  return [...out];
}

/** Published release versions of a package, from the registry the project uses. Null if unknown. */
async function publishedVersions(dir, name) {
  if (!PKG_NAME.test(name)) return null;
  const r = await runAsync('npm', ['view', name, 'versions', '--json'], { cwd: dir, timeoutMs: 60 * 1000 });
  if (r.error || r.status !== 0) return null;
  try {
    const v = JSON.parse(r.stdout);
    return [v].flat().filter((x) => typeof x === 'string' && parse(x) && !parse(x).pre.length).sort(compare);
  } catch {
    return null;
  }
}

/**
 * An npm "overrides" fix for a package that only other packages install, when a patched
 * version exists that npm audit fix can't reach. Returns null if there is none to offer.
 * `ranges` are the vulnerable ranges of every advisory for the package.
 */
function npmOverrideFix(name, ranges, versions, lock, pkg) {
  const copies = lockCopies(lock).get(name) ?? [];
  const isVulnerable = (v) => ranges.some((r) => satisfies(v, r));
  const hit = copies.filter((x) => isVulnerable(x.version));
  if (!hit.length || !versions?.length) return null;
  const targetFor = (v) => versions.find((c) => compare(c, v) >= 0 && !isVulnerable(c));
  const targets = hit.map((x) => targetFor(x.version));
  if (targets.some((t) => !t)) return null;
  const target = targets.sort(compare).at(-1);

  const via = dependents(lock, name).slice(0, 3);
  // An override applies to every copy, so it must not drag healthy copies to another major version.
  const dragged = copies.filter((x) => !isVulnerable(x.version) && isBreaking(x.version, target));
  const nested = Object.values(pkg?.overrides ?? {}).some((v) => typeof v === 'object');
  const existing = Object.entries(pkg?.overrides ?? {}).find(([k]) => k === name || k.startsWith(`${name}@`));
  if (dragged.length || nested || (existing && typeof existing[1] !== 'string')) {
    const parent = via[0];
    const example = parent ? ` such as "overrides": { "${parent}": { "${name}": "^${target}" } }` : '';
    return {
      type: 'manual',
      detail: `${name} ${hit.map((x) => x.version).join(', ')} needs ${target}, but `
        + (dragged.length
          ? `overriding every copy would also move ${name} ${dragged.map((x) => x.version).join(', ')} to another major version. `
          : 'package.json already has nested "overrides", which Gnawky does not edit. ')
        + `Update ${via.join(', ') || 'the packages that depend on it'}, or add a nested "overrides" entry${example}.`,
    };
  }

  const major = hit.some((x) => isBreaking(x.version, target));
  return {
    type: major ? 'npm-major-override' : 'npm-override',
    package: name,
    version: target,
    vulnerableRanges: ranges,
    detail: `Force ${name} to ${target} with an "overrides" entry in package.json (you choose ^${target} or exactly ${target}). `
      + `It is outside the range ${via.join(', ') || 'its dependents'} ask${via.length === 1 ? 's' : ''} for`
      + (major ? ', across a major version: this may break them; run your tests.' : '; run your tests.'),
  };
}

/**
 * Override fixes for vulnerable packages npm can't fix by itself: name -> fix.
 * `wanted` is name -> vulnerable ranges. Asks the registry for published versions (a few at a time).
 */
export async function npmOverrideFixes(dir, wanted) {
  const lock = readJson(path.join(dir, 'package-lock.json')) ?? readJson(path.join(dir, 'npm-shrinkwrap.json'));
  const pkg = readJson(path.join(dir, 'package.json'));
  const direct = new Set(DEP_FIELDS.flatMap((k) => Object.keys(pkg?.[k] ?? {})));
  const names = [...wanted.keys()].filter((n) => !direct.has(n));
  const fixes = new Map();
  for (let i = 0; i < names.length; i += 4) {
    const batch = names.slice(i, i + 4);
    const versions = await Promise.all(batch.map((n) => publishedVersions(dir, n)));
    batch.forEach((n, j) => {
      const fix = npmOverrideFix(n, wanted.get(n), versions[j], lock, pkg);
      if (fix) fixes.set(n, fix);
    });
  }
  return fixes;
}

// ------------------------------------------------------------ npm overrides: apply

/** Writes the override to package.json and runs npm install. Install scripts never run. */
export function applyNpmOverride(dir, step) {
  const { fix } = step;
  if (!PKG_NAME.test(fix.package) || !PKG_VERSION.test(fix.version)) {
    return { ok: false, output: `Refused suspicious package spec: ${fix.package}@${fix.version}` };
  }
  // An earlier step (usually upgrading the package that depends on this one) may have fixed it already.
  const lock = readJson(path.join(dir, 'package-lock.json')) ?? readJson(path.join(dir, 'npm-shrinkwrap.json'));
  const ranges = fix.vulnerableRanges ?? [];
  const copies = lockCopies(lock).get(fix.package) ?? [];
  if (ranges.length && !copies.some((x) => ranges.some((r) => satisfies(x.version, r)))) {
    return { ok: true, skipped: 'already fixed by an earlier change', output: '' };
  }
  const spec = pinSpec(fix.version, step.pin);
  writePackageJson(dir, (pkg) => {
    pkg.overrides ??= {};
    const keys = Object.keys(pkg.overrides).filter((k) => typeof pkg.overrides[k] === 'string'
      && (k === fix.package || k.startsWith(`${fix.package}@`)));
    for (const k of keys) pkg.overrides[k] = spec;
    if (!keys.includes(fix.package)) pkg.overrides[fix.package] = spec;
  });
  const args = ['install', '--ignore-scripts', '--no-audit', '--no-fund'];
  const r = run('npm', args, { cwd: dir });
  return { ok: !r.error && r.status === 0, output: `${r.stdout}\n${r.stderr}`, command: `npm ${args.join(' ')}` };
}
