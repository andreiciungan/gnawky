// Headless subcommands (`gnawky findings | report | triage | ignore | fix`), used by the Claude
// Code plugin's gnawky skill and usable from scripts. Each works on the last scan in
// .gnawky/; `gnawky scan` (or `gnawky --no-ui`) makes a new one.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { SEVERITY_ORDER, addIgnores } from './finding.js';
import { loadConfig } from './config.js';
import { loadLastScan, filterFindings, writeReports, reportFile, htmlReportFile } from './scan.js';
import {
  loadTriage, runTriage, triageItems, batchCount, triageEstimate, findingSource, TRIAGE_SOURCES, MAX_PARALLEL,
  VERDICTS, URGENCIES,
} from './triage.js';
import { AUDIT_TOOL } from './audit.js';
import { isAvailable, IS_WIN } from './scanners.js';
import {
  groupFindings, isGroup, groupFixes, groupTitle, severityCounts, advisoryTitle, idsOf, alsoFixes, triageByPackage,
} from './groups.js';
import { lockfileName, packageManager, runLabel, auditName, isDepAudit, DEP_AUDIT_TOOLS } from './pm.js';
import { OUT_DIR } from './config.js';
import { visibleFindings } from './scan.js';
import {
  isAutoFixable, emptyPlan, addFixToPlan, planSteps, isForced, preflight, applyPlan, regressions, undoFix, fixBranchName,
} from './fix.js';
import { recommendPin } from './overrides.js';
import { detectScripts, diffFindings, VERIFY_SCRIPTS } from './verify.js';
import { scanDependencies } from './scanners.js';
import { saveFixRecord } from './fixlog.js';

export class UsageError extends Error {}

const out = (s = '') => process.stdout.write(`${s}\n`);
const err = (s = '') => process.stderr.write(`${s}\n`);

/** Splits argv into positional args and --flags (a flag takes the next arg unless it's a boolean flag). */
function parse(argv, booleans) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { o._.push(a); continue; }
    const key = a.slice(2);
    if (booleans.includes(key)) o[key] = true;
    else if (i + 1 < argv.length) o[key] = argv[++i];
    else throw new UsageError(`${a} needs a value`);
  }
  return o;
}

const list = (v, allowed, name) => {
  if (v === undefined) return null;
  const xs = String(v).split(',').map((x) => x.trim()).filter(Boolean);
  const bad = xs.filter((x) => !allowed.includes(x));
  if (bad.length || !xs.length) throw new UsageError(`--${name} takes a comma-separated list of: ${allowed.join(', ')}`);
  return xs;
};

/** The last scan with today's ignores applied, or a UsageError telling how to make one. */
function lastScan(dir, cfg) {
  const result = loadLastScan(dir);
  if (!result) throw new UsageError('No scan yet in this project. Run `gnawky scan` first.');
  const before = result.findings.length;
  result.findings = filterFindings(dir, cfg, result.findings);
  result.ignoredCount = (result.ignoredCount ?? 0) + before - result.findings.length;
  return result;
}

/** True when package.json or the lockfile changed after the scan, so the results may be out of date. */
function isStale(dir, result) {
  const scanned = new Date(result.date).getTime();
  return ['package.json', lockfileName(packageManager(dir))]
    .filter(Boolean)
    .some((f) => { try { return fs.statSync(path.join(dir, f)).mtimeMs > scanned; } catch { return false; } });
}

// ------------------------------------------------------------------ findings

const take = (t) => ({ verdict: t.verdict, urgency: t.verdict === 'false-positive' ? null : t.urgency, reason: t.reason });

/** The grouped view the app shows, as plain data. */
function groupedItems(findings, triage) {
  return groupFindings(findings).map((g) => {
    const takes = triageByPackage(g, triage);
    return {
      key: g.key,
      title: groupTitle(g),
      severity: g.severity,
      count: g.findings.length,
      severities: severityCounts(g.findings),
      package: g.package,
      alsoCovers: alsoFixes(g) || null,
      tool: [...new Set(g.findings.map((f) => f.tool))].join(', '),
      location: isGroup(g) ? null : g.lead.file ? `${g.lead.file}${g.lead.line ? `:${g.lead.line}` : ''}` : null,
      fixes: groupFixes(g).map((x) => ({ type: x.fix?.type, detail: x.fix?.detail, automatic: x.auto, findings: x.findings.length })),
      claude: takes.map(({ package: p, t }) => ({ package: p, ...take(t) })),
      findings: g.findings.map((f) => ({
        id: f.fingerprint,
        severity: f.severity,
        title: isGroup(g) ? advisoryTitle(f) : f.title,
        package: f.package,
        ids: idsOf(f),
        url: f.url,
        cwe: f.cwe?.length ? f.cwe : undefined,
        description: f.description,
        claude: triage.entries[f.fingerprint] ? take(triage.entries[f.fingerprint]) : undefined,
      })),
    };
  });
}

function summaryOf(dir, result) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, result.findings.filter((f) => f.severity === s).length]));
  return {
    target: dir,
    scanned: result.date,
    stale: isStale(dir, result),
    minSeverity: result.minSeverity,
    offline: result.offline,
    counts,
    total: result.findings.length,
    ignored: result.ignoredCount ?? 0,
    scanners: result.tools.map((t) => ({ name: t.name, status: t.status, findings: t.count, message: t.message ?? t.note })),
    reports: { markdown: reportFile(dir), html: htmlReportFile(dir) },
  };
}

function printFindings(dir, result, triage) {
  const sum = summaryOf(dir, result);
  const items = groupedItems(result.findings, triage);
  const counts = SEVERITY_ORDER.filter((s) => sum.counts[s]).map((s) => `${sum.counts[s]} ${s}`).join(', ');
  out(`Scan of ${dir} from ${new Date(result.date).toLocaleString()}${sum.stale ? ' (package.json or the lockfile changed since: rescan)' : ''}`);
  out(`${sum.total} finding(s)${counts ? `: ${counts}` : ''} in ${items.length} item(s)${sum.ignored ? `, ${sum.ignored} ignored` : ''}`);
  for (const t of result.tools) out(`  ${t.status === 'ran' ? '✔' : '–'} ${t.name}: ${t.status === 'ran' ? `${t.count} finding(s)` : `${t.status} (${t.message})`}`);
  if (result.tools.every((t) => t.status !== 'ran')) out('  No scanner ran, so "no findings" proves nothing.');
  for (const it of items) {
    out(`\n[${it.severity.toUpperCase()}] ${it.title}${it.count > 1 ? `  (${it.severities})` : ''}${it.location ? `  ${it.location}` : ''}`);
    if (it.alsoCovers) out(`  Also covers: ${it.alsoCovers} (installed by ${it.package}, fixed by the same change)`);
    for (const x of it.fixes) out(`  Fix${it.fixes.length > 1 ? ` (${x.findings})` : ''}: ${x.automatic ? '[automatic] ' : '[manual] '}${x.detail}`);
    for (const c of it.claude) {
      out(`  Claude${it.claude.length > 1 ? ` on ${c.package}` : ''}: ${VERDICTS[c.verdict]}${c.urgency ? `, ${URGENCIES[c.urgency]}` : ''}. ${c.reason}`);
    }
    if (it.count > 1) for (const f of it.findings) out(`    - ${f.severity.padEnd(8)} ${f.title}${f.ids.length ? `  ${f.ids.join(', ')}` : ''}  id ${f.id}`);
    else out(`  id ${it.findings[0].id}`);
  }
  out(`\nReports: ${sum.reports.markdown}\n         ${sum.reports.html}`);
}

/** `gnawky findings [--json] [--min-severity <level>]` */
export function findingsCommand(dir, argv) {
  const o = parse(argv, ['json']);
  const cfg = loadConfig(dir);
  if (o['min-severity']) {
    if (!SEVERITY_ORDER.includes(o['min-severity'])) throw new UsageError(`--min-severity must be one of: ${SEVERITY_ORDER.join(', ')}`);
    cfg.minSeverity = o['min-severity'];
  }
  const result = lastScan(dir, cfg);
  showFindings(dir, result, { json: o.json });
}

export function showFindings(dir, result, { json }) {
  const triage = loadTriage(dir);
  if (json) out(JSON.stringify({ ...summaryOf(dir, result), items: groupedItems(result.findings, triage) }, null, 2));
  else printFindings(dir, result, triage);
}

// ------------------------------------------------------------------ report

function openInBrowser(file) {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [file]] : IS_WIN ? ['explorer', [file]] : ['xdg-open', [file]];
  const r = spawnSync(cmd, args, { stdio: 'ignore' });
  return !r.error && (IS_WIN || !r.status);
}

/** `gnawky report [--open]`: rewrites both reports from the last scan (with the latest triage and ignores). */
export function reportCommand(dir, argv) {
  const o = parse(argv, ['open']);
  const result = lastScan(dir, loadConfig(dir));
  writeReports(dir, result);
  out(`Markdown report: ${reportFile(dir)}`);
  out(`HTML report:     ${htmlReportFile(dir)}`);
  out(`From the scan of ${new Date(result.date).toLocaleString()}${isStale(dir, result) ? ' (package.json or the lockfile changed since: run `gnawky scan` for current results)' : ''}.`);
  if (o.open) out(openInBrowser(htmlReportFile(dir)) ? 'Opened the HTML report in the browser.' : 'Could not open a browser; open the HTML file yourself.');
}

// ------------------------------------------------------------------ triage

const SEVERITIES_DESC = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * `gnawky triage [--severity a,b] [--sources a,b] [--all] [--parallel n] [--yes] [--json]`
 * Without --yes it only prints what would be sent and the estimate, so the caller can ask first.
 */
export async function triageCommand(dir, argv) {
  const o = parse(argv, ['all', 'yes', 'json']);
  const cfg = loadConfig(dir);
  const blocked = cfg.offline
    ? 'Offline mode is on in this project. Triage sends code to Anthropic, so it is off (turn offline mode off in Settings).'
    : !isAvailable('claude') ? 'Claude Code is not installed (npm install -g @anthropic-ai/claude-code).'
    : IS_WIN ? 'Claude triage is not supported on Windows yet.'
    : null;
  if (blocked) throw new UsageError(blocked);

  const result = lastScan(dir, cfg);
  let triage = loadTriage(dir);
  const all = result.findings.filter((f) => f.tool !== AUDIT_TOOL);
  const pool = o.all ? all : all.filter((f) => !triage.entries[f.fingerprint]);
  const last = cfg.triageFilter ?? {};
  const severities = list(o.severity, SEVERITIES_DESC, 'severity') ?? last.severities ?? ['critical', 'high'];
  const sources = list(o.sources, Object.keys(TRIAGE_SOURCES), 'sources') ?? last.sources ?? Object.keys(TRIAGE_SOURCES);
  const parallel = Math.max(1, Math.min(MAX_PARALLEL, Number(o.parallel ?? last.parallel ?? 1) || 1));
  const todo = pool.filter((f) => severities.includes(f.severity) && sources.includes(findingSource(f)));
  const items = triageItems(todo);
  const batches = batchCount(items);
  const plan = {
    findings: todo.length,
    items: items.length,
    runs: batches,
    parallel,
    estimate: triageEstimate(batches, parallel),
    severities,
    sources,
    alreadyTriaged: all.length - all.filter((f) => !triage.entries[f.fingerprint]).length,
    available: all.length,
  };

  if (!todo.length) {
    const why = pool.length ? `none match --severity ${severities.join(',')} --sources ${sources.join(',')}` : 'every finding already has a verdict (add --all to redo them)';
    if (o.json) out(JSON.stringify({ started: false, plan, reason: why }, null, 2));
    else out(`Nothing to triage: ${why}.`);
    return;
  }
  if (!o.yes) {
    if (o.json) { out(JSON.stringify({ started: false, plan }, null, 2)); return; }
    out(`Triage would check ${todo.length} finding(s) in ${items.length} item(s) (advisories grouped per package, secrets per file),`);
    out(`in ${batches} Claude run(s)${parallel > 1 ? `, ${parallel} at a time` : ''}: ${plan.estimate}. Severity: ${severities.join(', ')}. Sources: ${sources.join(', ')}.`);
    out(`${plan.alreadyTriaged} of ${all.length} finding(s) already have a verdict${o.all ? ' (redone with --all)' : ' (skipped; --all redoes them)'}.`);
    out('');
    out('Privacy and cost:');
    out('  - Claude gets the scan results (secret values removed) and reads the source files, package.json,');
    out('    the lockfile and node_modules it needs. All of it is sent to Anthropic.');
    out('  - Claude can only read and search files: it cannot edit files or run commands.');
    out('  - .env files, keys and .npmrc are blocked; files flagged for secrets are read as copies with the lines hidden.');
    out('  - It uses your Claude plan or API credits.');
    out('');
    out('Nothing was sent. Run again with --yes to start.');
    return;
  }

  cfg.triageFilter = { severities, sources, parallel };
  // Saved like the app does, so the app's triage screen starts from the same choice.
  const { saveConfig } = await import('./config.js');
  saveConfig(dir, cfg);

  const started = Date.now();
  err(`Claude is triaging ${todo.length} finding(s) in ${batches} run(s)…`);
  const r = await runTriage(dir, todo, all, {
    parallel,
    onProgress: (p) => err(`  ${p.done} of ${p.total} run(s) done${p.running ? `, ${p.running} running` : ''}`),
  });
  triage = r.triage;
  writeReports(dir, result);
  const seconds = Math.round((Date.now() - started) / 1000);
  const checked = groupedItems(todo, triage);
  if (o.json) {
    out(JSON.stringify({ started: true, plan, summary: { ...r.summary, seconds }, items: checked }, null, 2));
    return;
  }
  const s = r.summary;
  out(`Checked ${s.triaged} finding(s) in ${seconds}s${s.cost ? ` (≈ $${s.cost.toFixed(2)} at API prices)` : ''}.`);
  if (s.missing) out(`${s.missing} finding(s) got no verdict; run \`gnawky triage\` again for them.`);
  for (const e of s.errors) out(`Error: ${e}`);
  if (s.blocked) out(`${s.blocked} file(s) flagged for secrets stayed blocked, so findings in them may say "needs a human".`);
  for (const it of checked) {
    out(`\n[${it.severity.toUpperCase()}] ${it.title}`);
    for (const c of it.claude) out(`  ${it.claude.length > 1 ? `${c.package}: ` : ''}${VERDICTS[c.verdict]}${c.urgency ? `, ${URGENCIES[c.urgency]}` : ''}. ${c.reason}`);
    if (!it.claude.length) out('  no verdict');
  }
  out(`\nSaved in .gnawky/triage.json and added to the reports (${htmlReportFile(dir)}).`);
}

// ------------------------------------------------------------------ ignore

/**
 * `gnawky ignore <target>... --reason "…"`. A target is a finding id, a GHSA or CVE ID,
 * or a package name (every advisory in that package's grouped item).
 */
export function ignoreCommand(dir, argv) {
  const o = parse(argv, []);
  const reason = String(o.reason ?? '').trim();
  if (!o._.length) throw new UsageError('Usage: gnawky ignore <finding id | GHSA/CVE ID | package>... --reason "why it is safe"');
  if (!reason) throw new UsageError('--reason is required: say why it is safe to ignore (it is saved in .gnawky-ignore.json).');
  const cfg = loadConfig(dir);
  const result = lastScan(dir, cfg);
  const groups = groupFindings(result.findings);
  const picked = new Map();
  const unknown = [];
  for (const target of o._) {
    const t = target.toLowerCase();
    const hits = result.findings.filter((f) => f.fingerprint === t || idsOf(f).some((x) => x.toLowerCase() === t));
    const group = groups.find((g) => g.package && g.package.toLowerCase() === t);
    const all = [...hits, ...(group?.findings ?? [])];
    if (!all.length) unknown.push(target);
    for (const f of all) picked.set(f.fingerprint, f);
  }
  if (unknown.length) throw new UsageError(`Not in the last scan: ${unknown.join(', ')}. Nothing was ignored. (\`gnawky findings\` lists ids and packages.)`);
  const findings = [...picked.values()];
  addIgnores(dir, findings.map((finding) => ({ finding, reason })));
  result.findings = result.findings.filter((f) => !picked.has(f.fingerprint));
  result.ignoredCount += findings.length;
  writeReports(dir, result);
  out(`Ignored ${findings.length} finding(s) in .gnawky-ignore.json (reason: ${reason}):`);
  for (const f of findings) out(`  - [${f.severity}] ${f.title}`);
  out('Restore them from the app: Findings › Ignored findings. New advisories for the same packages will still show up.');
}

// ------------------------------------------------------------------ fix

const PENDING = 'pending-fix.json';
const pendingFile = (dir) => path.join(dir, OUT_DIR, PENDING);
const readPending = (dir) => { try { return JSON.parse(fs.readFileSync(pendingFile(dir), 'utf8')); } catch { return null; } };

/** The findings a fix target means: a package (its whole grouped item), a finding id, or a GHSA/CVE ID. */
function resolveTargets(findings, targets) {
  const groups = groupFindings(findings);
  const picked = new Map();
  const unknown = [];
  for (const target of targets) {
    const t = target.toLowerCase();
    const hits = [
      ...findings.filter((f) => f.fingerprint === t || idsOf(f).some((x) => x.toLowerCase() === t)),
      ...(groups.find((g) => g.package && g.package.toLowerCase() === t)?.findings ?? []),
    ];
    if (!hits.length) unknown.push(target);
    for (const f of hits) picked.set(f.fingerprint, f);
  }
  return { findings: [...picked.values()], unknown };
}

function stepView(dir, st) {
  const v = { kind: st.kind, label: st.label, package: st.package ?? null, version: st.version ?? null, major: Boolean(st.major), findings: st.findings.length };
  if (isForced(st.kind)) {
    const { pin, reason } = recommendPin(dir, st.package);
    Object.assign(v, { pin: st.pin, recommendedPin: pin, pinReason: reason });
  }
  return v;
}

/**
 * `gnawky fix <package|id|GHSA|CVE>... | --all [--scripts test,build|all] [--one-at-a-time]
 *  [--pin caret|exact] [--yes] [--json]`, then `gnawky fix --keep` or `gnawky fix --undo`.
 * Without --yes it only shows the plan. With --yes it applies it on a new branch (install
 * scripts off), runs the chosen package.json scripts before and after, audits again, and
 * leaves the branch for --keep or --undo, like the app's verify screen.
 */
export async function fixCommand(dir, argv) {
  const o = parse(argv, ['all', 'yes', 'json', 'keep', 'undo', 'one-at-a-time']);
  if (o.keep || o.undo) return finishFix(dir, o);
  const pending = readPending(dir);
  if (pending) {
    throw new UsageError(`A fix is waiting for a decision on branch ${pending.report.branch}: run \`gnawky fix --keep\` or \`gnawky fix --undo\` first.`);
  }
  if (!o.all && !o._.length) throw new UsageError('Usage: gnawky fix <package | finding id | GHSA/CVE ID>... (or --all) [--scripts test,build] [--yes]');

  const cfg = loadConfig(dir);
  const result = lastScan(dir, cfg);
  if (isStale(dir, result)) throw new UsageError('package.json or the lockfile changed since the last scan. Run `gnawky scan` first so the fixes match.');
  const { findings: wanted, unknown } = o.all ? { findings: result.findings, unknown: [] } : resolveTargets(result.findings, o._);
  if (unknown.length) throw new UsageError(`Not in the last scan: ${unknown.join(', ')}. Nothing was changed. (\`gnawky findings\` lists ids and packages.)`);

  const auto = wanted.filter(isAutoFixable);
  const manual = wanted.filter((f) => !isAutoFixable(f));
  const plan = emptyPlan();
  for (const f of auto) addFixToPlan(plan, f);
  const pinArg = o.pin;
  if (pinArg !== undefined && !['caret', 'exact'].includes(pinArg)) throw new UsageError('--pin must be caret or exact');
  for (const st of planSteps(plan).filter((x) => isForced(x.kind))) plan.pins[st.package] = pinArg ?? recommendPin(dir, st.package).pin;
  const steps = planSteps(plan);

  const available = detectScripts(dir);
  let scripts = [];
  if (o.scripts !== undefined) {
    scripts = o.scripts === 'all' ? available : list(o.scripts, VERIFY_SCRIPTS, 'scripts');
    const missing = scripts.filter((n) => !available.includes(n));
    if (missing.length) throw new UsageError(`package.json has no usable script: ${missing.join(', ')} (it has: ${available.join(', ') || 'none'})`);
  }
  const oneAtATime = Boolean(o['one-at-a-time']) && scripts.length > 0 && steps.length > 1;
  const problem = steps.length ? preflight(dir) : null;
  const manualItems = groupFindings(manual).map((g) => ({ title: groupTitle(g), fixes: groupFixes(g).map((x) => x.fix?.detail) }));
  const view = {
    steps: steps.map((st) => stepView(dir, st)),
    branch: steps.length ? fixBranchName(dir, steps) : null,
    findings: auto.length,
    notAutomatic: manualItems,
    blocked: problem,
    scripts,
    availableScripts: available,
    oneAtATime,
    pm: packageManager(dir),
  };

  if (!steps.length) {
    if (o.json) out(JSON.stringify({ applied: false, plan: view, reason: 'nothing can be fixed automatically' }, null, 2));
    else {
      out('Nothing here can be fixed automatically.');
      for (const m of manualItems) out(`  ${m.title}: ${m.fixes.join(' / ')}`);
    }
    return;
  }
  if (!o.yes || problem) {
    if (o.json) { out(JSON.stringify({ applied: false, plan: view }, null, 2)); return; }
    out(`Plan: ${auto.length} finding(s), ${steps.length} change(s), in this order:`);
    for (const [i, st] of view.steps.entries()) {
      out(`  ${i + 1}. ${st.label}${st.major ? '  (MAJOR version: may break your code)' : ''}  [${st.findings} finding(s)]`);
      if (st.recommendedPin) out(`     pinned ${st.pin === 'exact' ? 'exactly' : 'as a ^range'}${st.pin === st.recommendedPin ? ` (recommended: ${st.pinReason})` : ` (Gnawky recommends ${st.recommendedPin}: ${st.pinReason})`}`);
    }
    if (manualItems.length) {
      out('Not fixable automatically (left as they are):');
      for (const m of manualItems) out(`  ${m.title}: ${m.fixes.join(' / ')}`);
    }
    out(`\nThe changes go on a new branch, ${view.branch}, with install scripts disabled; you decide afterwards to keep or undo them.`);
    if (scripts.length) {
      out(`Verification: runs ${scripts.map((n) => runLabel(view.pm, n)).join(', ')} before and after${oneAtATime ? ' each change, undoing any change that breaks them' : ''}.`);
      out('  This runs the project\'s own code (tests may start servers or use the network). 15 minutes per script.');
    } else {
      out(`Verification: only dependency compatibility. ${available.length ? `Add --scripts ${available.join(',')} (or a subset) to run the project's scripts before and after; that runs the project's own code.` : 'package.json has no test, build, lint or typecheck script.'}`);
    }
    if (problem) out(`\nBlocked: ${problem}`);
    else out('\nNothing was changed. Run again with --yes to apply.');
    return;
  }

  const log = (m) => err(m);
  const report = applyPlan(dir, plan, log, { scripts, oneAtATime });
  if (!report.branch) throw new UsageError(`Nothing was changed: ${report.skipped ?? 'the fix could not start.'}`);

  let audit = null;
  let auditAll = null;
  if (!cfg.offline && cfg.scanners['npm-audit'] !== false) {
    err(`\nRunning ${auditName(view.pm)} again…`);
    const res = await scanDependencies(dir);
    if (res.findings) {
      auditAll = filterFindings(dir, cfg, res.findings);
      audit = diffFindings(result.findings.filter(isDepAudit), auditAll);
    }
  }
  fs.writeFileSync(pendingFile(dir), JSON.stringify({ report, audit, auditAll }, null, 2) + '\n');
  printFixReport(dir, report, audit, view.pm, o.json);
}

const brief = (f) => ({ severity: f.severity, title: f.title, ids: idsOf(f) });

function printFixReport(dir, report, audit, pm, json) {
  const broken = regressions(report);
  const data = {
    applied: true,
    branch: report.branch,
    base: report.base,
    steps: report.steps.map((st) => ({ label: st.label, major: st.major, findings: st.findings, status: st.status, note: st.note, broke: st.broke, error: st.error })),
    scripts: report.scripts.map((n) => ({
      script: runLabel(pm, n),
      before: report.baseline[n] ? (report.baseline[n].ok ? 'passed' : 'failed') : null,
      after: report.after[n] ? (report.after[n].ok ? 'passed' : report.after[n].timedOut ? 'timed out' : 'failed') : null,
      log: report.after[n]?.logFile ?? null,
    })),
    scriptsSkipped: report.scriptsSkipped,
    brokeScripts: broken.map((n) => runLabel(pm, n)),
    newDependencyProblems: report.lsNew,
    engineWarnings: report.engines,
    audit: audit ? { fixed: audit.fixed.length, stillOpen: audit.remaining.length, new: audit.added.map(brief) } : null,
    diffStat: report.diffStat,
    next: 'gnawky fix --keep (keep the branch, save the fixed advisories) or gnawky fix --undo (back to the base branch, delete this one)',
  };
  if (json) { out(JSON.stringify(data, null, 2)); return; }
  out(`Fix applied on branch ${report.branch} (from ${report.base}).`);
  for (const st of data.steps) out(`  ${{ applied: '✔', skipped: '–', reverted: '↩', failed: '✖' }[st.status] ?? '?'} ${st.label}${st.major ? ' (major)' : ''}  ${st.status}${st.note ? `: ${st.note}` : ''}${st.broke ? `: broke ${st.broke.join(', ')}` : ''}`);
  out(report.lsNew.length ? `New dependency problems: ${report.lsNew.slice(0, 8).join('; ')}` : 'No new dependency problems.');
  if (report.engines.length) out(`Packages that say they don't support Node ${process.version}: ${report.engines.slice(0, 8).join('; ')}`);
  if (audit) out(`Audit again: fixed ${audit.fixed.length}, still open ${audit.remaining.length}, new ${audit.added.length}.`);
  if (report.scriptsSkipped) out(`Scripts not run: ${report.scriptsSkipped}`);
  else if (!report.scripts.length) out('Scripts: not run, so the fix is not verified. Run the app and tests before committing.');
  for (const s of data.scripts) out(`  ${s.script}: ${s.before ?? '-'} before, ${s.after ?? (report.oneAtATime ? 'checked after each change' : '-')} after`);
  if (broken.length) out(`The fix broke: ${data.brokeScripts.join(', ')} (logs in .gnawky/verify-after-*.log).`);
  out(`\nNext: ${data.next}.`);
}

async function finishFix(dir, o) {
  const pending = readPending(dir);
  if (!pending) throw new UsageError('No fix is waiting for a decision.');
  const { report, audit, auditAll } = pending;
  if (o.undo) {
    const ok = undoFix(dir, report, (m) => err(m));
    if (!ok) throw new UsageError(`Could not switch back to ${report.base}. You are still on ${report.branch}; nothing was deleted.`);
    fs.rmSync(pendingFile(dir), { force: true });
    out(`Undone: back on ${report.base}, branch ${report.branch} deleted.`);
    return;
  }
  // Keep: save the fixed advisories, and update the results with the new audit.
  const cfg = loadConfig(dir);
  const result = lastScan(dir, cfg);
  const pm = packageManager(dir);
  const applied = report.steps.filter((st) => st.status === 'applied');
  let saved = null;
  if (applied.length) {
    const targeted = new Set(applied.flatMap((st) => st.fingerprints ?? []));
    const fixed = audit ? audit.fixed : result.findings.filter((f) => targeted.has(f.fingerprint));
    try {
      saved = await saveFixRecord(dir, {
        report, fixed, verified: Boolean(audit), pm, offline: cfg.offline,
        stillOpen: audit ? audit.remaining.length + audit.added.length : null,
      });
    } catch (e) {
      err(`Could not save the fixed advisories: ${e.message}`);
    }
  }
  if (auditAll) {
    const others = result.findings.filter((f) => !isDepAudit(f));
    result.findings = visibleFindings([...others, ...auditAll], cfg);
    const tool = result.tools.find((t) => DEP_AUDIT_TOOLS.includes(t.name));
    if (tool) tool.count = auditAll.length;
    result.date = new Date().toISOString();
    writeReports(dir, result);
  }
  fs.rmSync(pendingFile(dir), { force: true });
  const files = `package.json ${lockfileName(pm)}`;
  if (o.json) {
    out(JSON.stringify({
      kept: true, branch: report.branch, base: report.base, diffStat: report.diffStat,
      fixedLog: saved ? { markdown: saved.md, json: saved.json, fixed: saved.record.fixed.length, verified: saved.record.verified, note: saved.record.note ?? null } : null,
      rescanNeeded: !auditAll,
      commit: `git add ${files} && git commit -m "Fix vulnerable dependencies"`,
    }, null, 2));
    return;
  }
  out(`Kept on branch ${report.branch}.`);
  if (report.diffStat) out(report.diffStat);
  if (saved) out(`Fixed advisories (${saved.record.fixed.length}${saved.record.verified ? '' : ', not confirmed by a new audit'}) saved to ${path.relative(dir, saved.md)} for a PR or ticket.`);
  if (!auditAll) out('Run `gnawky scan` to refresh the results.');
  out(`Next: review with git diff, then commit on this branch: git add ${files} && git commit -m "Fix vulnerable dependencies"`);
}
