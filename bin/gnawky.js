#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { SEVERITY_ORDER } from '../src/finding.js';
import { loadConfig } from '../src/config.js';
import { performScan, reportFile, htmlReportFile } from '../src/scan.js';

const HELP = `Gnawky - gnaws through your code, watches like a hawk.
Security scanner for Node.js projects.

Interactive app (recommended):
  cd your-project && gnawky

Headless mode (CI, scripts, the Claude plugin):
  gnawky [path] --no-ui          scan and write .gnawky/security-report.md and .html
  gnawky [path] --json           print findings as JSON on stdout
  gnawky [path] --ci             exit with code 1 if findings remain

Options for headless mode (override .gnawky/config.json):
  --min-severity <level>   critical | high | medium | low | info
  --offline                nothing leaves this computer
  --semgrep-config <cfg>   semgrep ruleset or local rules file (repeatable)
  -h, --help               show this help

Scanning is read-only. Changes only happen in the app, after you confirm.`;

function parseArgs(argv) {
  const o = { target: '.', json: false, ci: false, noUi: false, minSeverity: null, offline: false, semgrepConfigs: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (a === '--ci') o.ci = true;
    else if (a === '--no-ui') o.noUi = true;
    else if (a === '--offline') o.offline = true;
    else if (a === '--min-severity') o.minSeverity = argv[++i];
    else if (a === '--semgrep-config') o.semgrepConfigs.push(argv[++i]);
    else if (a === '-h' || a === '--help') { console.log(HELP); process.exit(0); }
    else if (!a.startsWith('-')) o.target = a;
    else { console.error(`Unknown option: ${a}\n\n${HELP}`); process.exit(2); }
  }
  if (o.minSeverity && !SEVERITY_ORDER.includes(o.minSeverity)) {
    console.error(`--min-severity must be one of: ${SEVERITY_ORDER.join(', ')}`);
    process.exit(2);
  }
  return o;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  const dir = path.resolve(o.target);
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    console.error(`Not a directory: ${dir}`);
    process.exit(2);
  }

  const interactive = process.stdin.isTTY && process.stdout.isTTY && !o.json && !o.ci && !o.noUi;
  if (interactive) {
    const { startApp } = await import('../src/app.js');
    await startApp(dir);
    return;
  }

  // Headless mode: progress on stderr so --json stdout stays clean.
  const cfg = loadConfig(dir);
  if (o.minSeverity) cfg.minSeverity = o.minSeverity;
  if (o.offline) cfg.offline = true;
  if (o.semgrepConfigs.length) cfg.semgrepConfigs = o.semgrepConfigs;

  const log = (m) => console.error(m);
  log(`Scanning ${dir}`);
  const result = performScan(dir, cfg, log);
  for (const t of result.tools) if (t.status !== 'ran') log(`  ${t.name}: ${t.status} (${t.message})`);

  if (o.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    const counts = SEVERITY_ORDER.map((s) => [s, result.findings.filter((f) => f.severity === s).length]).filter(([, n]) => n);
    console.log(`\n${result.findings.length} finding(s)` + (counts.length ? `: ${counts.map(([s, n]) => `${n} ${s}`).join(', ')}` : ''));
    console.log(`Report: ${reportFile(dir)}`);
    console.log(`HTML report: ${htmlReportFile(dir)}`);
  }
  if (o.ci && result.tools.every((t) => t.status !== 'ran')) {
    console.error('No scanner ran, so the result proves nothing. Failing the CI check.');
    process.exitCode = 2;
  } else if (o.ci && result.findings.length) {
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(`gnawky failed: ${e.message}`);
  process.exit(2);
});
