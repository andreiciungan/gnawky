// Headless subcommands (`gnawky findings | report | triage | ignore`), used by the Claude
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
import { lockfileName, packageManager } from './pm.js';

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
