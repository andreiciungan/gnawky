// The interactive app for a workspace (a folder holding several projects): pick the projects,
// see how they use each other, check all their dependencies, read the combined report.

import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { c, clear, pause, select, checklist, printLogo, wordmark, ticker, sevTag, truncate } from './ui.js';
import { SEVERITY_ORDER, rank } from './finding.js';
import { IS_WIN } from './scanners.js';
import {
  findProjects, loadWorkspace, saveWorkspace, selectedProjects, findLinks, sharedVersions, layers, dependents,
  scanWorkspace, loadWorkspaceResult, mergeAdvisories, throughProjects, sharedPackages, workspaceHtmlFile, workspaceReportFile,
} from './workspace.js';
import { writeWorkspaceReports } from './workspace-report.js';
import { prodFirstCount } from './prod.js';

const fmtDate = (iso) => new Date(iso).toLocaleString();
const rule = () => c.gray('─'.repeat(Math.min(process.stdout.columns || 60, 72)));

function summary(items) {
  if (!items.length) return c.green('no findings');
  const colors = { critical: c.red, high: c.red, medium: c.yellow, low: c.blue, info: c.gray };
  return SEVERITY_ORDER
    .map((s) => [s, items.filter((f) => f.severity === s).length])
    .filter(([, n]) => n)
    .map(([s, n]) => colors[s](`${n} ${s}`))
    .join(', ');
}

/** "58 prod first · 6 critical, 86 high…" for a project's findings. */
function projectSummary(findings) {
  const pf = prodFirstCount(findings);
  return `${pf ? `${c.bold(c.red(`${pf} prod first`))} ${c.gray('·')} ` : ''}${summary(findings)}`;
}

function header(s, { logo = false, below } = {}) {
  clear();
  const name = path.basename(s.root);
  if (logo) {
    printLogo(below === undefined ? undefined : { below: 4 + below });
    console.log(`${c.bold(name)} ${c.accent('workspace')}  ${c.gray(s.root)}`);
  } else {
    console.log(`${wordmark()}  ${c.bold(name)} ${c.accent('workspace')}  ${c.gray(s.root)}`);
  }
  const picked = selectedProjects(s.root, s.ws, s.all).length;
  const bits = [s.ws.projects ? `${picked} of ${s.all.length} projects` : `${s.all.length} projects found`];
  if (s.result) {
    const advisories = mergeAdvisories(s.result);
    bits.push(`Last scan ${fmtDate(s.result.date)}: ${advisories.length} advisories (${summary(advisories)})`);
    const pf = prodFirstCount(s.result.projects.flatMap((p) => p.findings));
    if (pf) bits.push(c.bold(c.red(`${pf} to fix for production first`)));
  } else bits.push(c.gray('Not scanned yet'));
  if (s.ws.offline) bits.push(c.yellow('offline mode'));
  if (s.stale && s.result) bits.push(c.yellow('results may be out of date, rescan'));
  console.log(bits.join(c.gray('  ·  ')));
  console.log(rule());
  console.log();
}

// ------------------------------------------------------------ pick projects

async function pickScreen(s) {
  const links = findLinks(s.all);
  const usedBy = (rel) => dependents(rel, links).length;
  const on = new Set(s.ws.projects ?? s.all.filter((p) => p.pm).map((p) => p.rel));
  const width = Math.max(...s.all.map((p) => p.rel.length));
  header(s);
  console.log('Pick the projects that belong together. Gnawky reads their package.json files to see');
  console.log('which ones use each other, and checks the dependencies of every picked project.');
  console.log(c.gray('Nothing is written into the projects: results go to .gnawky/ in this folder.\n'));
  const view = {
    title: () => `Projects in ${path.basename(s.root)} (${on.size} picked)`,
    items: () => s.all.map((p) => {
      const n = usedBy(p.rel);
      const uses = links.filter((l) => l.from === p.rel).length;
      const bits = [p.pm ?? c.yellow('no lockfile'), p.name !== p.rel ? p.name : null,
        n ? `used by ${n}` : null, uses ? `uses ${uses}` : null].filter(Boolean);
      return { label: `${p.rel.padEnd(width)}  ${c.gray(bits.join(' · '))}`, state: on.has(p.rel) ? 'on' : 'off' };
    }),
    toggle: (i) => {
      const rel = s.all[i].rel;
      if (on.has(rel)) on.delete(rel); else on.add(rel);
    },
  };
  for (;;) {
    const r = await checklist(view);
    if (r === null) return false;
    if (on.size) break;
    console.log(c.yellow('Pick at least one project.'));
  }
  s.ws.projects = s.all.filter((p) => on.has(p.rel)).map((p) => p.rel);
  saveWorkspace(s.root, s.ws);
  s.stale = true;
  return true;
}

async function networkScreen(s) {
  header(s);
  console.log('The dependency check sends each project\'s dependency list (names and versions) to the');
  console.log('npm registry, like npm install does. Your source code is never uploaded.\n');
  const pick = await select('How should Gnawky work in this workspace?', [
    { label: 'Online (recommended)', value: 'online' },
    { label: 'Offline (nothing leaves this computer, so the dependency check is skipped)', value: 'offline' },
  ], { initial: s.ws.offline ? 1 : 0 });
  if (pick === null) return false;
  s.ws.offline = pick === 'offline';
  saveWorkspace(s.root, s.ws);
  return true;
}

// ------------------------------------------------------------ links

function printLinks(s) {
  const picked = selectedProjects(s.root, s.ws, s.all);
  const links = findLinks(picked);
  if (!links.length) {
    console.log('None of the picked projects uses another one.');
    return;
  }
  console.log(c.bold('Who uses whom') + c.gray('  (versions from each project\'s lockfile)\n'));
  const linked = new Set(links.flatMap((l) => [l.from, l.to]));
  const width = Math.max(...picked.filter((p) => linked.has(p.rel)).map((p) => p.rel.length));
  for (const p of picked) {
    const uses = links.filter((l) => l.from === p.rel);
    if (uses.length) console.log(`  ${p.rel.padEnd(width)}  ${c.gray('uses')} ${uses.map((l) => `${l.name}${c.gray(`@${l.installed ?? l.spec}`)}`).join(', ')}`);
  }
  const loose = picked.filter((p) => !linked.has(p.rel)).map((p) => p.rel);
  if (loose.length) console.log(c.gray(`\n  Not linked to the others: ${loose.join(', ')}`));
  const versions = sharedVersions(links).filter((v) => v.specs.length > 1);
  if (versions.length) {
    console.log(`\n${c.yellow('Different versions in use')}: a fix released in one of these reaches only the projects that move to it.`);
    for (const v of versions) console.log(`  ${c.bold(v.name)}: ${v.specs.map((x) => `${x.spec} ${c.gray(`(${x.from.join(', ')})`)}`).join('; ')}`);
  }
  const order = layers(picked, links).map((l) => l.filter((r) => linked.has(r))).filter((l) => l.length);
  if (order.length > 1) {
    console.log(`\n${c.bold('Fix order')}: shared projects first, release them, then bump them where they're used.`);
    order.forEach((l, i) => console.log(`  ${i + 1}. ${l.join(', ')}`));
  }
  if (s.result) {
    const through = throughProjects(mergeAdvisories(s.result));
    if (through.length) {
      console.log(`\n${c.bold('Brought in by your own projects')} ${c.gray('(last scan)')}:`);
      for (const t of through) console.log(`  ${t.rel} brings ${t.advisories} advisor${t.advisories === 1 ? 'y' : 'ies'} into ${t.into.join(', ')}`);
    }
  }
}

async function linksScreen(s) {
  header(s);
  printLinks(s);
  await pause();
}

// ------------------------------------------------------------ scan

async function scanScreen(s) {
  header(s);
  const picked = selectedProjects(s.root, s.ws, s.all);
  console.log(`${c.bold('Checking dependencies')} of ${picked.length} project(s) ${c.gray('(read-only: nothing in the projects is changed)')}\n`);
  s.result = await scanWorkspace(s.root, s.ws, picked, { onStep: (label) => ticker(label) });
  writeWorkspaceReports(s.root, s.result);
  s.stale = false;
  console.log();
  printResults(s);
  const pick = await select('Next step', [
    { label: 'Open the HTML report in the browser', value: 'open' },
    { label: 'Back to menu', value: null },
  ]);
  if (pick === 'open' && !openInBrowser(workspaceHtmlFile(s.root))) await pause();
}

function printResults(s) {
  const width = Math.max(...s.result.projects.map((p) => p.rel.length));
  for (const p of s.result.projects) {
    const failed = p.tools.filter((t) => t.status !== 'ran');
    const icon = p.tools.some((t) => t.status === 'ran') ? c.green('✔') : c.yellow('–');
    const extra = failed.length ? c.gray(`  ·  ${failed.map((t) => `${t.name} ${t.status}`).join(', ')}`) : '';
    console.log(`  ${icon} ${p.rel.padEnd(width)}  ${projectSummary(p.findings)}${extra}`);
    for (const n of p.notes ?? []) console.log(`    ${' '.repeat(width)} ${c.yellow(`note: ${n}`)}`);
  }
  const merged = mergeAdvisories(s.result);
  const shared = merged.filter((a) => a.projects.length > 1);
  const pf = prodFirstCount(s.result.projects.flatMap((p) => p.findings));
  console.log(`\n  ${c.bold(`${merged.length} distinct advisories`)}, ${shared.length} in more than one project.`);
  console.log(`  ${c.bold(c.red(`${pf} critical/high findings ship to production`))}: fix those first ${c.gray('(dev-only ones come last)')}.\n`);
}

// ------------------------------------------------------------ findings across projects

async function sharedScreen(s) {
  const pkgs = sharedPackages(mergeAdvisories(s.result));
  header(s);
  if (!pkgs.length) {
    console.log('Every vulnerable package was found in one project only.');
    return pause();
  }
  const n = pkgs.reduce((k, e) => k + e.advisories.length, 0);
  console.log(`${c.bold('Packages in more than one project')}: ${pkgs.length} packages, ${n} advisories ${c.gray('(the report has the fix per project)')}\n`);
  const rows = Math.max(4, Math.floor(((process.stdout.rows || 24) - 14) / 2));
  const cols = (process.stdout.columns || 80) - 13;
  for (const e of pkgs.slice(0, rows)) {
    const n = e.advisories.length === 1 ? '1 advisory' : `${e.advisories.length} advisories`;
    const tag = e.prodFirst ? c.bold(c.red(' prod first')) : e.prod ? '' : c.gray(' [dev only]');
    console.log(`  ${sevTag(e.severity)} ${c.bold(e.package)}${tag} ${c.gray(`${n}, ${e.projects.length} projects`)}`);
    const who = e.projects.map((x) => `${x.rel}${x.through.length ? ` (via ${x.through.join(', ')})` : ''}${x.prod ? '' : ' (dev)'}`).join(', ');
    console.log(`           ${c.gray(truncate(who, cols))}`);
  }
  if (pkgs.length > rows) console.log(c.gray(`\n  … and ${pkgs.length - rows} more packages in the report.`));
  console.log();
  const pick = await select('', [
    { label: 'Open the HTML report in the browser', value: 'open' },
    { label: 'Back', value: null },
  ]);
  if (pick === 'open' && !openInBrowser(workspaceHtmlFile(s.root))) await pause();
}

/**
 * The picked projects in the recommended fix order: [{ step, label, rels }]. Projects others use
 * come first, then the ones that use them; projects with no links last, in any order.
 */
function fixSteps(s) {
  const picked = selectedProjects(s.root, s.ws, s.all);
  const links = findLinks(picked);
  const linked = new Set(links.flatMap((l) => [l.from, l.to]));
  const order = layers(picked, links).map((l) => l.filter((r) => linked.has(r))).filter((l) => l.length);
  const steps = order.map((rels, i) => ({
    step: i + 1,
    label: i === 0 ? 'fix first: used by the others' : i === order.length - 1 ? 'then the projects that use them' : 'uses the ones above, used by the ones below',
    rels,
  }));
  const loose = picked.map((p) => p.rel).filter((r) => !linked.has(r));
  if (loose.length) steps.push({ step: null, label: 'not linked to the others: any order', rels: loose });
  return { steps, links };
}

const doneSet = (s) => new Set(s.ws.fixed ?? []);

function markDone(s, rel, done) {
  const set = doneSet(s);
  if (done) set.add(rel); else set.delete(rel);
  s.ws.fixed = [...set];
  saveWorkspace(s.root, s.ws);
}

async function openProject(s, rel) {
  const { startApp } = await import('./app.js');
  await startApp(path.join(s.root, rel), { offline: s.ws.offline, fromWorkspace: true });
  // Fixes change the project's lockfile, so the workspace results may be out of date.
  s.stale = true;
}

/** What to do in a project before fixing it: bump the shared projects fixed in earlier steps. */
function printProjectBrief(s, rel, links) {
  const r = s.result?.projects.find((p) => p.rel === rel);
  console.log(`  Findings (last workspace scan): ${r ? projectSummary(r.findings) : c.gray('not scanned yet')}`);
  if (r && prodFirstCount(r.findings)) console.log(c.gray('  In the project, Review & fix starts with the ones that ship to production.'));
  const uses = links.filter((l) => l.from === rel);
  const usedBy = dependents(rel, links);
  if (uses.length) {
    const done = doneSet(s);
    console.log(`  Uses: ${uses.map((l) => `${l.name}@${l.installed ?? l.spec}${done.has(l.to) ? c.green(' (fixed)') : ''}`).join(', ')}`);
    if (uses.some((l) => done.has(l.to))) {
      console.log(c.yellow('  Once the fixed versions are released, upgrade them here first: that brings their fixes in,'));
      console.log(c.yellow('  and the scan here then shows only what is left.'));
    }
  }
  if (usedBy.length) {
    console.log(`  Used by: ${usedBy.join(', ')}`);
    const through = s.result ? throughProjects(mergeAdvisories(s.result)).find((t) => t.rel === rel) : null;
    if (through) console.log(`  Brings ${through.advisories} advisor${through.advisories === 1 ? 'y' : 'ies'} into ${through.into.join(', ')}.`);
    console.log(c.gray('  After fixing it, release a new version so the projects that use it can upgrade.'));
  }
}

/** Every picked project, listed in the fix order; opens the one you pick. */
async function openProjectScreen(s) {
  const { steps } = fixSteps(s);
  const done = doneSet(s);
  const byRel = new Map((s.result?.projects ?? []).map((p) => [p.rel, p]));
  const width = Math.max(...steps.flatMap((x) => x.rels).map((r) => r.length));
  header(s);
  console.log('Opens Gnawky inside the project, with everything it can do there: fixes, ignoring,');
  console.log('Claude triage, secrets and code checks. That saves its results in the project\'s .gnawky/');
  console.log(c.gray('folder, as when you start Gnawky there. Leave it to come back to the workspace.\n'));
  const options = [];
  for (const x of steps) {
    if (options.length) options.push({ static: '' });
    options.push({ static: c.bold(x.step ? `Step ${x.step}: ${x.label}` : `Other projects: ${x.label}`) });
    for (const rel of x.rels) {
      const r = byRel.get(rel);
      const mark = done.has(rel) ? c.green('✔ ') : '  ';
      const number = options.filter((o) => o.value).length + 1;
      options.push({ label: `${mark}${rel.padEnd(width)}  ${r ? projectSummary(r.findings) : c.gray('not scanned yet')}`, value: rel, number });
    }
  }
  const rel = await select('Which project? (listed in the recommended fix order)', options, { footer: [{ label: '← Back', value: null }] });
  if (rel) await openProject(s, rel);
}

/**
 * Walks the projects in the fix order, starting at the first one not marked fixed: for each, says
 * what to do there, opens it, and asks whether it's done (saved, so you can stop and come back
 * after releasing a shared project).
 */
async function guidedFixScreen(s) {
  const { steps, links } = fixSteps(s);
  const queue = steps.flatMap((x) => x.rels.map((rel) => ({ rel, step: x.step, total: steps.filter((y) => y.step).length })));
  for (;;) {
    const done = doneSet(s);
    const next = queue.find((q) => !done.has(q.rel));
    header(s);
    if (!next) {
      console.log(c.green('Every picked project is marked fixed.'));
      console.log('Scan the workspace again to see what is left.\n');
      const pick = await select('', [
        { label: 'Start over (clear the fixed marks)', value: 'reset' },
        { label: 'Back', value: null },
      ]);
      if (pick !== 'reset') return;
      s.ws.fixed = [];
      saveWorkspace(s.root, s.ws);
      continue;
    }
    const where = next.step ? `Step ${next.step} of ${next.total}` : 'Not linked to the others';
    const left = queue.filter((q) => !done.has(q.rel)).length;
    console.log(`${c.bold('Fix in the recommended order')}  ${c.gray(`${queue.length - left} of ${queue.length} done`)}\n`);
    console.log(`${c.accent(where)}: ${c.bold(next.rel)}\n`);
    printProjectBrief(s, next.rel, links);
    console.log();
    const pick = await select('', [
      { label: `Open ${next.rel}`, value: 'open' },
      { label: 'Mark it fixed and go to the next one', value: 'done' },
      { label: 'Back to the workspace (progress is saved)', value: null },
    ]);
    if (!pick) return;
    if (pick === 'done') { markDone(s, next.rel, true); continue; }
    await openProject(s, next.rel);
    header(s);
    console.log(`Back from ${c.bold(next.rel)}.\n`);
    const after = await select(`Is ${next.rel} done?`, [
      { label: 'Yes, mark it fixed and go to the next one', value: 'done' },
      { label: 'Not yet (it stays next)', value: 'later' },
      { label: 'Back to the workspace', value: null },
    ]);
    if (after === 'done') markDone(s, next.rel, true);
    if (!after) return;
  }
}

async function reportScreen(s) {
  writeWorkspaceReports(s.root, s.result);
  header(s);
  console.log(c.gray(`Saved at ${workspaceReportFile(s.root)} (and workspace-report.html next to it).`));
  console.log(c.gray('It lists your projects\' weak spots: keep it private.\n'));
  if (!openInBrowser(workspaceHtmlFile(s.root))) await pause();
}

function openInBrowser(file) {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [file]] : IS_WIN ? ['explorer', [file]] : ['xdg-open', [file]];
  const r = spawnSync(cmd, args, { stdio: 'ignore' });
  if (!r.error && (IS_WIN || !r.status)) return true;
  console.log(c.yellow(`Could not open a browser. Open this file yourself: ${file}`));
  return false;
}

// ------------------------------------------------------------ main loop

function fixedNote(s) {
  const picked = new Set(selectedProjects(s.root, s.ws, s.all).map((p) => p.rel));
  const n = (s.ws.fixed ?? []).filter((r) => picked.has(r)).length;
  return n ? ` (${n} of ${picked.size} done)` : '';
}

export async function startWorkspaceApp(root, { offline = false } = {}) {
  const s = { root, all: findProjects(root), ws: loadWorkspace(root), result: loadWorkspaceResult(root), stale: false };
  try {
    if (!s.ws.projects) {
      if (offline) s.ws.offline = true;
      if (!(await pickScreen(s))) return;
      if (!(await networkScreen(s))) return;
      header(s);
      printLinks(s);
      console.log();
      const go = await select('Check the dependencies of all picked projects now?', [
        { label: 'Yes, scan now', value: 'scan' },
        { label: 'Not now', value: null },
      ]);
      if (go) await scanScreen(s);
    }
    for (;;) {
      const picked = selectedProjects(s.root, s.ws, s.all).length;
      const options = [
        { label: s.result ? 'Scan again' : 'Scan all projects', value: 'scan', disabled: !picked },
        { label: 'How they are linked', value: 'links' },
        { label: 'Advisories across projects', value: 'shared', disabled: !s.result },
        { label: 'View report', value: 'report', disabled: !s.result },
        { label: `Fix in recommended order${fixedNote(s)}`, value: 'guided', disabled: !picked },
        { label: 'Open a project (to fix, ignore, triage…)', value: 'open', disabled: !picked },
        { label: `Pick projects (${picked} of ${s.all.length})`, value: 'pick' },
        { label: `Network: ${s.ws.offline ? 'offline' : 'online'}`, value: 'network' },
      ];
      header(s, { logo: true, below: options.length + 5 });
      const choice = await select('What would you like to do?', options, { footer: [{ label: 'Quit', value: 'quit' }] });
      if (choice === null || choice === 'quit') break;
      if (choice === 'scan') await scanScreen(s);
      else if (choice === 'links') await linksScreen(s);
      else if (choice === 'shared') await sharedScreen(s);
      else if (choice === 'report') await reportScreen(s);
      else if (choice === 'open') await openProjectScreen(s);
      else if (choice === 'guided') await guidedFixScreen(s);
      else if (choice === 'pick') await pickScreen(s);
      else if (choice === 'network') { if (await networkScreen(s)) s.stale = true; }
    }
  } catch (e) {
    if (e.code !== 'ABORT_ERR') throw e;
  }
  clear();
  console.log('Gnawky closed. Workspace reports are in .gnawky/');
}
