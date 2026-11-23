// `gnawky workspace …`: the workspace mode without the menus (scripts, the Claude plugin).

import path from 'node:path';
import { SEVERITY_ORDER } from './finding.js';
import { ticker } from './ui.js';
import { UsageError } from './cli.js';
import {
  findProjects, loadWorkspace, saveWorkspace, selectedProjects, findLinks, sharedVersions, scanWorkspace,
  mergeAdvisories, throughProjects, countBySeverity, sharedPackages, workspaceReportFile, workspaceHtmlFile, loadWorkspaceResult,
} from './workspace.js';
import { writeWorkspaceReports } from './workspace-report.js';
import { prodFirstCount } from './prod.js';

export const WORKSPACE_HELP = `Workspace mode: a folder with several projects (run it in the folder that holds them).
  gnawky workspace [--projects a,b | --all]      list the projects and how they use each other
  gnawky workspace scan [--projects a,b | --all] [--offline] [--min-severity <level>] [--json]
                                                 check every picked project's dependencies, then write
                                                 .gnawky/workspace-report.md and .html in this folder
  gnawky workspace report                        show the last workspace scan
--projects / --all also saves the pick for next time. Without a saved pick, all projects are used.`;

function parse(argv) {
  const o = { sub: null, projects: null, all: false, offline: null, minSeverity: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--projects') o.projects = String(argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--all') o.all = true;
    else if (a === '--offline') o.offline = true;
    else if (a === '--online') o.offline = false;
    else if (a === '--json') o.json = true;
    else if (a === '--min-severity') o.minSeverity = argv[++i];
    else if (!a.startsWith('-') && !o.sub) o.sub = a;
    else throw new UsageError(`Unknown option: ${a}\n\n${WORKSPACE_HELP}`);
  }
  if (o.sub && !['scan', 'report'].includes(o.sub)) throw new UsageError(`Unknown workspace command: ${o.sub}\n\n${WORKSPACE_HELP}`);
  if (o.minSeverity && !SEVERITY_ORDER.includes(o.minSeverity)) throw new UsageError(`--min-severity must be one of: ${SEVERITY_ORDER.join(', ')}`);
  return o;
}

/** Applies --projects / --all / --offline / --min-severity and saves them; returns { ws, all, picked }. */
function resolve(root, o, { save = true } = {}) {
  const all = findProjects(root);
  if (all.length < 2) throw new UsageError(`No workspace here: ${root} needs at least two folders with a package.json.`);
  const ws = loadWorkspace(root);
  let changed = false;
  if (o.projects) {
    const known = new Set(all.map((p) => p.rel));
    const unknown = o.projects.filter((r) => !known.has(r));
    if (unknown.length) throw new UsageError(`Not a project in ${root}: ${unknown.join(', ')}. Projects: ${[...known].join(', ')}`);
    ws.projects = o.projects;
    changed = true;
  } else if (o.all) {
    ws.projects = all.map((p) => p.rel);
    changed = true;
  } else if (!ws.projects) {
    // Nothing picked yet: use all of them, but only save that when something is scanned.
    ws.projects = all.map((p) => p.rel);
    changed = save;
  }
  if (o.offline !== null) { ws.offline = o.offline; changed = true; }
  if (o.minSeverity) { ws.minSeverity = o.minSeverity; changed = true; }
  if (changed) saveWorkspace(root, ws);
  return { ws, all, picked: selectedProjects(root, ws, all) };
}

export function printLinks(picked, all, log = console.log) {
  const links = findLinks(picked);
  log(`Projects (${picked.length} of ${all.length} picked):`);
  const pickedSet = new Set(picked.map((p) => p.rel));
  for (const p of all) {
    const uses = links.filter((l) => l.from === p.rel).map((l) => `${l.name}@${l.installed ?? l.spec}`);
    log(`  ${pickedSet.has(p.rel) ? '[x]' : '[ ]'} ${p.rel.padEnd(24)} ${(p.pm ?? 'no lockfile').padEnd(11)} ${uses.length ? `uses ${uses.join(', ')}` : ''}`.trimEnd());
  }
  const versions = sharedVersions(links).filter((v) => v.specs.length > 1);
  if (versions.length) {
    log('\nDifferent versions in use:');
    for (const v of versions) log(`  ${v.name}: ${v.specs.map((s) => `${s.spec} (${s.from.join(', ')})`).join('; ')}`);
  }
}

export function printSummary(root, result, log = console.log) {
  log('');
  for (const p of result.projects) {
    const failed = p.tools.filter((t) => t.status !== 'ran').map((t) => `${t.name} ${t.status}`);
    const pf = prodFirstCount(p.findings);
    log(`  ${p.rel.padEnd(24)} ${pf ? `${pf} prod first · ` : ''}${countBySeverity(p.findings) || 'no findings'}${failed.length ? `  (${failed.join(', ')})` : ''}`);
    for (const n of p.notes ?? []) log(`  ${''.padEnd(24)} note: ${n}`);
  }
  const merged = mergeAdvisories(result);
  const shared = sharedPackages(merged);
  log(`\n${merged.length} distinct advisor${merged.length === 1 ? 'y' : 'ies'}; ${shared.length} vulnerable packages are in more than one project.`);
  log(`${prodFirstCount(result.projects.flatMap((p) => p.findings))} critical/high finding(s) ship to production: fix those first.`);
  for (const e of shared.slice(0, 10)) {
    const n = `${e.advisories.length} advisor${e.advisories.length === 1 ? 'y' : 'ies'}`;
    log(`  ${e.severity.toUpperCase().padEnd(8)} ${e.prodFirst ? '[prod first] ' : e.prod ? '' : '[dev only] '}${e.package}: ${n} (${e.projects.map((x) => x.rel + (x.prod ? '' : ' dev')).join(', ')})`);
  }
  if (shared.length > 10) log(`  … and ${shared.length - 10} more packages in the report (with the fix per project)`);
  const through = throughProjects(merged);
  if (through.length) {
    log('\nBrought in by your own projects:');
    for (const t of through) log(`  ${t.rel} brings ${t.advisories} advisor${t.advisories === 1 ? 'y' : 'ies'} into ${t.into.join(', ')}`);
  }
  log(`\nReport: ${workspaceReportFile(root)}`);
  log(`HTML report: ${workspaceHtmlFile(root)}`);
}

export async function workspaceCommand(cwd, argv) {
  const o = parse(argv);
  const root = path.resolve(cwd);
  if (o.sub === 'report') {
    const result = loadWorkspaceResult(root);
    if (!result) throw new UsageError('No workspace scan yet. Run: gnawky workspace scan');
    writeWorkspaceReports(root, result);
    if (o.json) process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    else printSummary(root, result);
    return;
  }
  const { ws, all, picked } = resolve(root, o, { save: o.sub === 'scan' });
  if (!o.sub) {
    printLinks(picked, all);
    return;
  }
  const log = (m) => console.error(m);
  log(`Checking the dependencies of ${picked.length} project(s) in ${root}`);
  const result = await scanWorkspace(root, ws, picked, { onStep: (label) => ticker(label, process.stderr) });
  writeWorkspaceReports(root, result);
  if (o.json) process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  else printSummary(root, result);
}
