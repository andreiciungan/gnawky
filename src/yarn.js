// Yarn 1 (Classic) support: `yarn audit`, and fixes through `yarn upgrade`,
// re-resolving yarn.lock entries, or a "resolutions" override in package.json.
import fs from 'node:fs';
import path from 'node:path';
import { run, runAsync } from './scanners.js';
import { makeFinding } from './finding.js';
import { PKG_NAME, PKG_VERSION } from './pm.js';
import { writePackageJson, pinSpec } from './overrides.js';
import {
  valid, compare, satisfies, parseRange, patchedCandidates, isBreaking,
} from './semver.js';

const SEVERITY = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'info' };
const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'];
const QUIET = ['--ignore-scripts', '--non-interactive', '--no-progress'];

const readJson = (file) => {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
};

// ------------------------------------------------------------ yarn.lock

function splitKey(key) {
  const at = key.indexOf('@', 1);
  return at === -1 ? { name: key, range: '' } : { name: key.slice(0, at), range: key.slice(at + 1) };
}

/** Entries of a Yarn 1 lockfile: { keys, name, ranges, version, start, end } (line numbers, end exclusive). */
export function parseLockfile(text) {
  const lines = text.split('\n');
  const entries = [];
  let cur = null;
  lines.forEach((line, i) => {
    if (/^[^\s#].*:$/.test(line)) {
      const keys = (line.slice(0, -1).match(/"(?:[^"\\]|\\.)*"|[^,\s]+/g) ?? []).map((k) => k.replace(/^"|"$/g, ''));
      const specs = keys.map(splitKey);
      cur = { keys, name: specs[0]?.name, ranges: specs.map((s) => s.range), version: null, start: i, end: i + 1 };
      entries.push(cur);
    } else if (cur && /^\s/.test(line) && line.trim()) {
      cur.end = i + 1;
      const m = /^ {2}version "?([^"\s]+)"?\s*$/.exec(line);
      if (m) cur.version = m[1];
    } else {
      cur = null;
    }
  });
  return entries;
}

const readLock = (dir) => {
  try { return fs.readFileSync(path.join(dir, 'yarn.lock'), 'utf8'); } catch { return ''; }
};

/** Removes lockfile entries so the next `yarn install` resolves them again (newest version in range). */
function removeLockEntries(dir, shouldRemove) {
  const text = readLock(dir);
  const lines = text.split('\n');
  const drop = new Set();
  for (const e of parseLockfile(text)) {
    if (!shouldRemove(e)) continue;
    for (let i = e.start; i < e.end; i++) drop.add(i);
    if (lines[e.end] === '') drop.add(e.end); // the blank line after the entry
  }
  if (drop.size) fs.writeFileSync(path.join(dir, 'yarn.lock'), lines.filter((_, i) => !drop.has(i)).join('\n'));
  return drop.size > 0;
}

// ------------------------------------------------------------ fixes

const isExact = (spec) => valid(spec);
const lockKey = (name, range) => `${name}@${range}`;

function resolutionKeys(pkg, name) {
  return Object.keys(pkg?.resolutions ?? {}).filter((k) => k === name || k.endsWith(`/${name}`));
}

/**
 * Works out one fix for every advisory of a package, so all its findings share the
 * same plan step. `advisories` are { vulnerable, patched, versions: Map(version -> paths) }.
 */
function yarnFix(name, advisories, entries, pkg, advised = new Set()) {
  const fixable = advisories.filter((a) => patchedCandidates(a.patched).length);
  if (!fixable.length) {
    return { type: 'manual', detail: 'No patched version published. Consider replacing the package, removing it, or mitigating how you use it.' };
  }
  const candidates = [...new Set(fixable.flatMap((a) => patchedCandidates(a.patched)))].sort(compare);
  // The lowest version at or above `v` that none of the advisories call vulnerable.
  const targetFor = (v) => candidates.find((c) => compare(c, v) >= 0 && fixable.every((a) => !satisfies(c, a.vulnerable)));
  const vulnerable = new Set(fixable.flatMap((a) => [...a.versions.keys()]));
  const hit = entries.filter((e) => vulnerable.has(e.version));
  if (!hit.length) {
    return { type: 'manual', detail: `Update ${name} to a patched version (${fixable[0].patched}).` };
  }
  const targets = hit.map((e) => ({ e, t: targetFor(e.version) }));
  if (targets.some((x) => !x.t)) {
    return { type: 'manual', detail: `No single patched version of ${name} fixes every advisory. Check ${fixable.map((a) => a.patched).join(', ')}.` };
  }
  const refreshable = (x) => x.e.ranges.every((r) => parseRange(r) && satisfies(x.t, r));
  const overridden = resolutionKeys(pkg, name).length > 0;

  // Direct dependency: upgrade it in package.json.
  const spec = DEP_FIELDS.map((k) => pkg?.[k]?.[name]).find(Boolean);
  const direct = spec && targets.find((x) => x.e.keys.includes(lockKey(name, spec)));
  if (direct && !overridden) {
    if (!parseRange(spec)) {
      return { type: 'manual', detail: `Update ${name} to ${direct.t} or later (package.json uses "${spec}", which Gnawky can't upgrade).` };
    }
    const newSpec = isExact(spec) ? direct.t : `${spec.trim().startsWith('~') ? '~' : '^'}${direct.t}`;
    const major = isBreaking(direct.e.version, direct.t);
    const nested = targets.filter((x) => x !== direct);
    const stuck = nested.filter((x) => !refreshable(x)).length;
    return {
      type: major ? 'yarn-major-upgrade' : 'yarn-upgrade',
      package: name,
      version: direct.t,
      spec: newSpec,
      vulnerableRanges: fixable.map((a) => a.vulnerable),
      refresh: nested.filter(refreshable).map((x) => x.e.version),
      detail: (major
        ? `Upgrade ${name} to ${newSpec}. This is a semver-major change and may break your code; run your tests.`
        : `Upgrade ${name} to ${newSpec} (same major version).`)
        + (stuck ? ` ${stuck} other copy/copies installed by other packages stay vulnerable.` : ''),
    };
  }

  const vulnerableRanges = fixable.map((a) => a.vulnerable);
  const paths = fixable.flatMap((a) => [...a.versions.values()].flat());
  const roots = [...new Set(paths.map((p) => p.split('>')[0]))].filter((r) => r !== name && DEP_FIELDS.some((k) => pkg?.[k]?.[r]));
  const upgradeHint = roots.length ? ` Upgrading ${roots.slice(0, 3).join(', ')} may also fix it.` : '';
  const fixedHere = roots.filter((r) => advised.has(r));
  const orderHint = upgradeHint + (fixedHere.length
    ? ` If you also fix ${fixedHere.slice(0, 3).join(', ')} here, that upgrade runs first and this step is skipped if it is no longer needed.`
    : '');

  // Only installed by other packages: re-resolve within their ranges if that is enough.
  const fresh = targets.filter(refreshable);
  if (!overridden && fresh.length === targets.length) {
    return {
      type: 'yarn-refresh',
      package: name,
      version: targets.map((x) => x.t).sort(compare).at(-1),
      vulnerableRanges,
      detail: `Update ${name} within the version ranges its dependents allow (yarn.lock only, like npm audit fix).`,
    };
  }

  // Otherwise force a patched version with "resolutions". It applies to every copy of the
  // package, so only when that doesn't move any other copy to a different major version.
  const stuck = overridden ? targets : targets.filter((x) => !refreshable(x));
  const target = stuck.map((x) => x.t).sort(compare).at(-1);
  const stuckEntries = new Set(stuck.map((x) => x.e));
  const dragged = entries.filter((e) => !stuckEntries.has(e) && valid(e.version) && isBreaking(e.version, target));
  const stuckPaths = [...new Set(stuck.flatMap((x) => fixable.flatMap((a) => a.versions.get(x.e.version) ?? [])))];
  const via = [...new Set(stuckPaths.map((p) => p.split('>').slice(-2, -1)[0]).filter(Boolean))].slice(0, 3);

  if (dragged.length) {
    const parent = via[0];
    const pathKey = parent ? `"**/${parent}/${name}": "^${target}"` : null;
    const manual = `${name} ${stuck.map((x) => x.e.version).join(', ')} (via ${via.join(', ') || 'other packages'}) needs ${target}, `
      + `but forcing every copy would also move ${name} ${dragged.map((e) => e.version).join(', ')} to another major version. `
      + `Update ${via.join(', ') || 'the packages that depend on it'}, or add a path-specific "resolutions" entry${pathKey ? ` such as ${pathKey}` : ''}.`;
    if (!overridden && fresh.length) {
      return {
        type: 'yarn-refresh',
        package: name,
        version: fresh.map((x) => x.t).sort(compare).at(-1),
        vulnerableRanges,
        detail: `Update ${name} within the version ranges its dependents allow: fixes ${fresh.length} of ${targets.length} vulnerable copies. ${manual}`,
      };
    }
    return { type: 'manual', detail: manual + upgradeHint };
  }

  const major = stuck.some((x) => isBreaking(x.e.version, target));
  return {
    type: major ? 'yarn-major-resolution' : 'yarn-resolution',
    package: name,
    version: target,
    vulnerableRanges,
    detail: `Force ${name} to ${target} with a "resolutions" entry in package.json (you choose ^${target} or exactly ${target}). `
      + `It is outside the range ${via.join(', ') || 'its dependents'} ask${via.length === 1 ? 's' : ''} for`
      + (major ? ', across a major version: this may break them; run your tests.' : '; run your tests.')
      + orderHint,
  };
}

// ------------------------------------------------------------ audit

export async function scanYarnAudit(dir) {
  const r = await runAsync('yarn', ['audit', '--json', '--non-interactive'], { cwd: dir });
  const lines = r.stdout.split('\n').filter((l) => l.trim()).map((l) => {
    try { return JSON.parse(l); } catch { return null; }
  }).filter(Boolean);
  if (!lines.some((l) => l.type === 'auditSummary')) {
    const err = lines.find((l) => l.type === 'error')?.data ?? r.stderr ?? String(r.error ?? '');
    return { error: `yarn audit failed: ${String(err).trim().slice(0, 300) || `exit code ${r.status}`}` };
  }

  // yarn prints the same advisory once per dependency path; merge them.
  const byId = new Map();
  for (const l of lines) {
    if (l.type !== 'auditAdvisory') continue;
    const adv = l.data.advisory;
    const a = byId.get(adv.id) ?? {
      adv, name: adv.module_name, vulnerable: adv.vulnerable_versions, patched: adv.patched_versions, versions: new Map(),
    };
    for (const f of adv.findings ?? []) {
      const paths = a.versions.get(f.version) ?? [];
      a.versions.set(f.version, [...new Set([...paths, ...(f.paths ?? [])])]);
    }
    byId.set(adv.id, a);
  }

  const pkg = readJson(path.join(dir, 'package.json'));
  const entries = parseLockfile(readLock(dir));
  const byName = new Map();
  for (const a of byId.values()) byName.set(a.name, [...(byName.get(a.name) ?? []), a]);

  const findings = [];
  for (const [name, advisories] of byName) {
    const fix = yarnFix(name, advisories, entries.filter((e) => e.name === name), pkg, new Set(byName.keys()));
    for (const a of advisories) {
      const unpatched = !patchedCandidates(a.patched).length;
      const installed = [...a.versions].slice(0, 3)
        .map(([v, paths]) => `${v} (via ${paths.slice(0, 2).map((p) => p.split('>').join(' > ')).join(', ')}${paths.length > 2 ? ', …' : ''})`);
      findings.push(makeFinding({
        tool: 'yarn-audit',
        ruleId: String(a.adv.id ?? a.adv.github_advisory_id ?? a.adv.url),
        severity: SEVERITY[a.adv.severity] ?? 'medium',
        title: `${name}: ${a.adv.title}`,
        package: name,
        file: 'yarn.lock',
        description: `Vulnerable versions: ${a.vulnerable ?? 'unknown'}. Installed: ${installed.join('; ') || 'n/a'}.`,
        cwe: [a.adv.cwe ?? []].flat(),
        url: a.adv.url ?? null,
        fix: unpatched
          ? { type: 'manual', detail: 'No patched version published. Consider replacing the package, removing it, or mitigating how you use it.' }
          : fix,
      }));
    }
  }
  return { findings };
}

// ------------------------------------------------------------ apply

/** Applies one plan step with yarn. Install scripts never run. */
export function applyYarnStep(dir, step) {
  const { fix } = step;
  if (!PKG_NAME.test(fix.package) || !PKG_VERSION.test(fix.version) || (fix.spec && !/^[\^~]?[0-9A-Za-z.+-]+$/.test(fix.spec))) {
    return { ok: false, output: `Refused suspicious package spec: ${fix.package}@${fix.spec ?? fix.version}` };
  }
  // Checked against the lockfile as it is now: an earlier step (usually upgrading the
  // package that depends on this one) may have fixed it already, or changed which copy is vulnerable.
  const ranges = fix.vulnerableRanges ?? [];
  const isVulnerable = (e) => e.name === fix.package && ranges.some((r) => satisfies(e.version, r));
  if (step.kind !== 'upgrade' && ranges.length && !parseLockfile(readLock(dir)).some(isVulnerable)) {
    return { ok: true, skipped: 'already fixed by an earlier change', output: '' };
  }

  if (step.kind === 'refresh') removeLockEntries(dir, isVulnerable);
  const refresh = new Set(fix.refresh ?? []);
  if (step.kind === 'upgrade') removeLockEntries(dir, (e) => e.name === fix.package && refresh.has(e.version));

  if (step.kind === 'upgrade') {
    // Edit the spec in place (yarn upgrade would re-sort package.json), then let yarn resolve it.
    let old = null;
    writePackageJson(dir, (pkg) => {
      const field = DEP_FIELDS.find((k) => pkg[k]?.[fix.package]);
      if (!field) return;
      old = pkg[field][fix.package];
      pkg[field][fix.package] = fix.spec;
    });
    if (old === null) return { ok: false, output: `${fix.package} is no longer in package.json` };
    removeLockEntries(dir, (e) => e.keys.includes(lockKey(fix.package, old)));
  } else if (step.kind === 'resolution') {
    writePackageJson(dir, (pkg) => {
      const spec = pinSpec(fix.version, step.pin);
      pkg.resolutions ??= {};
      const keys = resolutionKeys(pkg, fix.package);
      for (const k of keys) pkg.resolutions[k] = spec;
      if (!keys.some((k) => k === fix.package || k === `**/${fix.package}`)) pkg.resolutions[`**/${fix.package}`] = spec;
    });
  }
  const args = ['install', ...QUIET];
  const r = run('yarn', args, { cwd: dir });
  return { ok: !r.error && r.status === 0, output: `${r.stdout}\n${r.stderr}`, command: `yarn ${args.join(' ')}` };
}

// ------------------------------------------------------------ verify

export const yarnInstallLocked = (dir) => run('yarn', ['install', '--frozen-lockfile', ...QUIET], { cwd: dir });
export const yarnSyncInstall = (dir) => run('yarn', ['install', ...QUIET], { cwd: dir });

/**
 * Problems reported by `yarn check --verify-tree` (packages that don't match the ranges asked for),
 * leaving out packages pinned on purpose by package.json "resolutions".
 */
export function yarnTreeProblems(dir) {
  const r = run('yarn', ['check', '--verify-tree', '--non-interactive'], { cwd: dir });
  if (r.error) return null;
  const pkg = readJson(path.join(dir, 'package.json'));
  const forced = (line) => {
    const m = /^"(?:[^"]*#)?([^"#]+)" is wrong version/.exec(line);
    return m && resolutionKeys(pkg, m[1]).length > 0;
  };
  return `${r.stdout}\n${r.stderr}`.split('\n')
    .filter((l) => l.startsWith('error ') && !/^error Found \d+ errors?/.test(l))
    .map((l) => l.slice(6).trim())
    .filter((l) => !forced(l));
}

/** Installed packages with install scripts (skipped by --ignore-scripts). */
export function yarnPackagesWithInstallScripts(dir) {
  const root = path.join(dir, 'node_modules');
  const names = [];
  const list = (p) => { try { return fs.readdirSync(p); } catch { return []; } };
  for (const n of list(root)) {
    for (const name of n.startsWith('@') ? list(path.join(root, n)).map((s) => `${n}/${s}`) : [n]) {
      const pj = readJson(path.join(root, name, 'package.json'));
      const s = pj?.scripts ?? {};
      if (s.preinstall || s.install || s.postinstall || fs.existsSync(path.join(root, name, 'binding.gyp'))) names.push(name);
    }
  }
  return names;
}
