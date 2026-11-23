// Workspace mode: a folder that holds several projects (e.g. ~/dev/work/acme with an API, a
// shared utils library and two apps). You pick the projects that belong together; Gnawky maps
// which of them depend on each other and checks every project's dependencies in one go.
//
// Everything the workspace writes goes to <workspace>/.gnawky/, never into the projects:
// scanning them is read-only, so their git status stays clean.

import fs from 'node:fs';
import path from 'node:path';
import { OUT_DIR, ensureOutDir } from './config.js';
import { SEVERITY_ORDER, loadIgnores, rank } from './finding.js';
import { packageManager, auditName } from './pm.js';
import { scanDependencies } from './scanners.js';
import { usesNext, scanNextBundledReact } from './nextjs.js';
import { visibleFindings } from './scan.js';
import { satisfies, valid, parseRange } from './semver.js';
import { advisoryTitle } from './groups.js';
import { parseLockfile } from './yarn.js';
import { classifyScope, shipsToProd, isProdFirst } from './prod.js';

const DEP_FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
const SKIP_DIRS = new Set(['node_modules', OUT_DIR]);

const readJson = (file) => {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
};

// ------------------------------------------------------------ discovery

/**
 * Projects in the folders directly under `root` (one level deep): every folder with a
 * package.json. { rel, dir, name, version, pm, pkg }
 */
export function findProjects(root) {
  let entries = [];
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return []; }
  return entries
    .filter((e) => e.isDirectory() && !e.name.startsWith('.') && !SKIP_DIRS.has(e.name))
    .map((e) => {
      const dir = path.join(root, e.name);
      const pkg = readJson(path.join(dir, 'package.json'));
      if (!pkg) return null;
      return { rel: e.name, dir, name: pkg.name ?? e.name, version: pkg.version ?? null, pm: packageManager(dir), pkg };
    })
    .filter(Boolean)
    .sort((a, b) => a.rel.localeCompare(b.rel));
}

/** A folder without its own package.json that holds two or more projects. */
export function isWorkspaceRoot(dir) {
  return !fs.existsSync(path.join(dir, 'package.json')) && findProjects(dir).length >= 2;
}

// ------------------------------------------------------------ settings

const settingsFile = (root) => path.join(root, OUT_DIR, 'workspace.json');

export const workspaceExists = (root) => fs.existsSync(settingsFile(root));

/**
 * { projects: [folder names], offline, minSeverity, fixed: [folder names marked fixed in the
 * guided fix] }; projects is null before the first pick.
 */
export function loadWorkspace(root) {
  const w = readJson(settingsFile(root)) ?? {};
  return {
    projects: Array.isArray(w.projects) ? w.projects : null,
    offline: Boolean(w.offline),
    minSeverity: SEVERITY_ORDER.includes(w.minSeverity) ? w.minSeverity : 'low',
    fixed: Array.isArray(w.fixed) ? w.fixed : [],
  };
}

export function saveWorkspace(root, ws) {
  ensureOutDir(root);
  fs.writeFileSync(settingsFile(root), JSON.stringify(ws, null, 2) + '\n');
}

/** The picked projects that still exist, in folder order. */
export function selectedProjects(root, ws, all = findProjects(root)) {
  const picked = new Set(ws.projects ?? []);
  return all.filter((p) => picked.has(p.rel));
}

// ------------------------------------------------------------ links

/** The version of `name` the project's lockfile installs for `spec`, or null when it can't tell. */
export function installedVersion(p, name, spec) {
  if (p.pm === 'npm') {
    const lock = readJson(path.join(p.dir, 'package-lock.json'));
    return lock?.packages?.[`node_modules/${name}`]?.version ?? lock?.dependencies?.[name]?.version ?? null;
  }
  if (p.pm === 'yarn') {
    let text = '';
    try { text = fs.readFileSync(path.join(p.dir, 'yarn.lock'), 'utf8'); } catch { return null; }
    return parseLockfile(text).find((e) => e.name === name && e.ranges.includes(spec))?.version ?? null;
  }
  return null;
}

/** Things worth knowing before trusting a project's scan (e.g. two lockfiles). */
export function projectNotes(p) {
  const has = (f) => fs.existsSync(path.join(p.dir, f));
  const notes = [];
  if (has('package-lock.json') && has('yarn.lock')) {
    notes.push('has both package-lock.json and yarn.lock; npm audit checked package-lock.json, so if the project installs with yarn, delete the stale one');
  }
  if (!p.pm) notes.push('no lockfile, so its dependencies could not be checked');
  return notes;
}

/**
 * Which projects depend on which, from their package.json files: a dependency whose name is
 * another project's package name. Edge: { from, to, name, spec, field, installed, local, differs }
 *   installed: the version the project's lockfile installs (null if not in it)
 *   local: the version in the other project's package.json (what's in the folder now)
 *   differs: the spec doesn't include that version, e.g. the app installs 1.12.26 from the
 *     registry while the folder has 1.10.9 (an old checkout, or a version bumped at release)
 */
export function findLinks(projects) {
  const byName = new Map(projects.map((p) => [p.name, p]));
  const links = [];
  for (const p of projects) {
    const seen = new Set();
    for (const field of DEP_FIELDS) {
      for (const [name, spec] of Object.entries(p.pkg[field] ?? {})) {
        const q = byName.get(name);
        if (!q || q === p || seen.has(name)) continue;
        seen.add(name);
        const range = String(spec).replace(/^npm:[^@]+@/, '');
        // Only real semver ranges count: a git URL, a tag or file: says nothing about the version.
        const differs = Boolean(q.version && valid(q.version) && parseRange(range) && !satisfies(q.version, range));
        const installed = installedVersion(p, name, String(spec));
        links.push({ from: p.rel, to: q.rel, name, spec: String(spec), field, installed, local: q.version, differs: installed ? installed !== q.version : differs });
      }
    }
  }
  return links;
}

/**
 * For each picked project that others use: the versions they install (from their lockfiles,
 * or the version they ask for when the lockfile doesn't say).
 * [{ rel, name, local, specs: [{ spec, from: [rel, ...] }] }]; more than one spec means the
 * projects use different releases of it, so a fix released there doesn't reach all of them.
 */
export function sharedVersions(links) {
  const by = new Map();
  for (const l of links) {
    const e = by.get(l.to) ?? { rel: l.to, name: l.name, local: l.local, specs: new Map() };
    const v = l.installed ?? l.spec;
    e.specs.set(v, [...(e.specs.get(v) ?? []), l.from]);
    by.set(l.to, e);
  }
  return [...by.values()]
    .map((e) => ({ ...e, specs: [...e.specs].map(([spec, from]) => ({ spec, from: from.sort() })).sort((a, b) => b.from.length - a.from.length) }))
    .sort((a, b) => a.rel.localeCompare(b.rel));
}

/**
 * Layers for the map and the fix order: layer 0 depends on no other picked project, layer n
 * on something in layer n-1. Libraries come first, the apps that use them last.
 * Returns [[rel, ...], ...]. A dependency cycle is broken where it's found.
 */
export function layers(projects, links) {
  const deps = new Map(projects.map((p) => [p.rel, links.filter((l) => l.from === p.rel).map((l) => l.to)]));
  const level = new Map();
  const visiting = new Set();
  const depth = (rel) => {
    if (level.has(rel)) return level.get(rel);
    if (visiting.has(rel)) return 0;
    visiting.add(rel);
    const d = Math.max(-1, ...deps.get(rel).map(depth)) + 1;
    visiting.delete(rel);
    level.set(rel, d);
    return d;
  };
  projects.forEach((p) => depth(p.rel));
  const out = [];
  for (const p of projects) (out[level.get(p.rel)] ??= []).push(p.rel);
  return out.filter(Boolean);
}

/** Projects that use `rel`, directly or through another picked project. */
export function dependents(rel, links) {
  const out = new Set();
  const queue = [rel];
  while (queue.length) {
    const r = queue.shift();
    for (const l of links) if (l.to === r && !out.has(l.from)) { out.add(l.from); queue.push(l.from); }
  }
  return [...out].sort();
}

// ------------------------------------------------------------ scan

/**
 * Checks the dependencies of every picked project (npm/yarn audit, plus the Next.js bundled
 * React check in Next.js projects). Read-only: nothing is written into the projects; the caller
 * saves the result (writeWorkspaceReports).
 * onStep(label) → done(text, kind), like the app's ticker.
 */
export async function scanWorkspace(root, ws, projects, { onStep } = {}) {
  const step = onStep ?? (() => () => {});
  const cacheDir = path.join(ensureOutDir(root), 'cache');
  const results = [];
  for (const p of projects) {
    const tools = [];
    const findings = [];
    const run = async (name, label, fn) => {
      const done = step(`${p.rel}: ${label}`);
      const started = Date.now();
      const res = await fn();
      const seconds = Math.round((Date.now() - started) / 1000);
      const toolName = res.name ?? name;
      if (res.findings) {
        findings.push(...res.findings);
        tools.push({ name: toolName, status: 'ran', count: res.findings.length, seconds, ...(res.note ? { note: res.note } : {}) });
        done(`${p.rel}: ${toolName}, ${res.findings.length} finding(s)`, 'ok');
      } else {
        tools.push({ name: toolName, status: res.skipped ? 'skipped' : 'error', message: res.skipped ?? res.error, seconds });
        done(`${p.rel}: ${toolName} ${res.skipped ? 'skipped' : 'failed'} (${res.skipped ?? res.error})`, res.skipped ? 'skip' : 'fail');
      }
    };
    await run('npm-audit', `running ${auditName(p.pm)}`, () => (ws.offline
      ? { skipped: 'offline mode (the dependency audit needs the npm registry)' }
      : scanDependencies(p.dir)));
    if (usesNext(p.dir)) {
      await run('next-bundled-react', 'checking the React bundled in Next.js', () => (ws.offline
        ? { skipped: 'offline mode (the check needs the GitHub advisory API)' }
        : scanNextBundledReact(p.dir, { cacheDir })));
    }
    classifyScope(p.dir, findings);
    let ignored = new Set();
    try { ignored = new Set(loadIgnores(p.dir).map((i) => i.fingerprint)); } catch { /* invalid file: ignore nothing */ }
    const open = findings.filter((f) => !ignored.has(f.fingerprint));
    results.push({
      rel: p.rel, name: p.name, version: p.version, pm: p.pm, tools, notes: projectNotes(p),
      ignoredCount: findings.length - open.length,
      findings: visibleFindings(open, ws),
    });
  }
  const links = findLinks(projects);
  const result = {
    root,
    date: new Date().toISOString(),
    offline: ws.offline,
    minSeverity: ws.minSeverity,
    projects: results,
    links,
    layers: layers(projects, links),
  };
  return result;
}

const resultFile = (root) => path.join(root, OUT_DIR, 'workspace-findings.json');
export const workspaceReportFile = (root) => path.join(root, OUT_DIR, 'workspace-report.md');
export const workspaceHtmlFile = (root) => path.join(root, OUT_DIR, 'workspace-report.html');

export function writeWorkspaceResult(root, result) {
  ensureOutDir(root);
  fs.writeFileSync(resultFile(root), JSON.stringify(result, null, 2) + '\n');
}

export const loadWorkspaceResult = (root) => readJson(resultFile(root));

// ------------------------------------------------------------ across projects

// Package and advisory: one GHSA can cover several packages (lodash and lodash-es share them),
// and a project can have both installed, each with its own fix.
const advisoryKey = (f) => `${f.package}|${f.ghsa ?? advisoryTitle(f)}`;

/**
 * Dependency advisories merged across projects: the same advisory found in several projects is
 * one entry. { key, ghsa, package, title, severity, url, prod, prodFirst, projects: [{ rel, via, through, fix, prod }] }
 *   prod: it ships to production in at least one project; prodFirst: and it's critical/high
 *   via: the project's direct dependencies that bring the package in
 *   through: the picked projects among them (the advisory reaches this project through them)
 * Sorted: critical/high in production first, then by severity, then by how many projects have it.
 */
export function mergeAdvisories(result) {
  const internal = new Map(result.projects.map((p) => [p.name, p.rel]));
  const byKey = new Map();
  for (const p of result.projects) {
    for (const f of p.findings) {
      if (!f.package) continue;
      const key = advisoryKey(f);
      let a = byKey.get(key);
      if (!a) {
        a = { key, ghsa: f.ghsa ?? null, package: f.package, title: advisoryTitle(f), severity: f.severity, url: f.url, prod: false, prodFirst: false, projects: [] };
        byKey.set(key, a);
      }
      if (rank(f.severity) < rank(a.severity)) a.severity = f.severity;
      if (a.projects.some((x) => x.rel === p.rel)) continue;
      const via = f.via ?? [];
      a.prod ||= shipsToProd(f);
      a.prodFirst ||= isProdFirst(f);
      a.projects.push({ rel: p.rel, via, through: via.filter((v) => internal.has(v)).map((v) => internal.get(v)), fix: f.fix, prod: shipsToProd(f) });
    }
  }
  const tier = (a) => (a.prodFirst ? 0 : a.prod ? 1 : 2);
  return [...byKey.values()].sort((a, b) => tier(a) - tier(b) || rank(a.severity) - rank(b.severity) || b.projects.length - a.projects.length);
}

/**
 * Merged advisories grouped per vulnerable package, like the project view groups them, keeping
 * only packages found in more than one project:
 * { package, severity, prod, prodFirst, advisories: [merged advisory…],
 *   projects: [{ rel, through: [rel…], prod, fixes: [detail…], advisories: n }] }
 * Sorted like the findings: critical/high in production first, then severity, then reach.
 */
export function sharedPackages(merged) {
  const by = new Map();
  for (const a of merged) {
    const e = by.get(a.package) ?? { package: a.package, severity: a.severity, prod: false, prodFirst: false, advisories: [], projects: new Map() };
    e.advisories.push(a);
    if (rank(a.severity) < rank(e.severity)) e.severity = a.severity;
    e.prod ||= a.prod;
    e.prodFirst ||= a.prodFirst;
    for (const x of a.projects) {
      const p = e.projects.get(x.rel) ?? { rel: x.rel, through: new Set(), prod: false, fixes: new Set(), advisories: 0 };
      x.through.forEach((t) => p.through.add(t));
      p.prod ||= x.prod;
      if (x.fix?.detail) p.fixes.add(x.fix.detail);
      p.advisories++;
      e.projects.set(x.rel, p);
    }
    by.set(a.package, e);
  }
  const tier = (e) => (e.prodFirst ? 0 : e.prod ? 1 : 2);
  return [...by.values()]
    .filter((e) => e.projects.size > 1)
    .map((e) => ({
      ...e,
      advisories: [...e.advisories].sort((a, b) => rank(a.severity) - rank(b.severity) || b.projects.length - a.projects.length),
      projects: [...e.projects.values()]
        .map((p) => ({ ...p, through: [...p.through].sort(), fixes: [...p.fixes] }))
        .sort((a, b) => b.prod - a.prod || a.rel.localeCompare(b.rel)),
    }))
    .sort((a, b) => tier(a) - tier(b) || rank(a.severity) - rank(b.severity) || b.projects.length - a.projects.length || b.advisories.length - a.advisories.length);
}

/**
 * For each picked project that others use: the advisories it brings into them.
 * [{ rel, advisories: n, into: [rel, ...] }], most advisories first.
 */
export function throughProjects(merged) {
  const by = new Map();
  for (const a of merged) {
    for (const x of a.projects) {
      for (const t of x.through) {
        const e = by.get(t) ?? { rel: t, keys: new Set(), into: new Set() };
        e.keys.add(a.key);
        e.into.add(x.rel);
        by.set(t, e);
      }
    }
  }
  return [...by.values()]
    .map((e) => ({ rel: e.rel, advisories: e.keys.size, into: [...e.into].sort() }))
    .sort((a, b) => b.advisories - a.advisories);
}

/** "3 high, 9 medium" for a list of findings or advisories. */
export function countBySeverity(items) {
  return SEVERITY_ORDER
    .map((s) => [s, items.filter((f) => f.severity === s).length])
    .filter(([, n]) => n)
    .map(([s, n]) => `${n} ${s}`)
    .join(', ');
}
