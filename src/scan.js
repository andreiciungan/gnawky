import fs from 'node:fs';
import path from 'node:path';
import { runAllScanners } from './scanners.js';
import { loadIgnores, rank } from './finding.js';
import { renderMarkdown } from './report.js';
import { renderHtml } from './html-report.js';
import { OUT_DIR, ensureOutDir } from './config.js';

export function performScan(dir, cfg, log = () => {}) {
  const { findings, tools } = runAllScanners(dir, log, {
    offline: cfg.offline,
    enabled: cfg.scanners,
    semgrepConfigs: cfg.semgrepConfigs,
  });
  const ignored = new Set(loadIgnores(dir).map((i) => i.fingerprint));
  const notIgnored = findings.filter((f) => !ignored.has(f.fingerprint));
  const result = {
    target: dir,
    date: new Date().toISOString(),
    minSeverity: cfg.minSeverity,
    offline: Boolean(cfg.offline),
    tools,
    ignoredCount: findings.length - notIgnored.length,
    findings: visibleFindings(notIgnored, cfg),
  };
  writeReports(dir, result);
  return result;
}

/** Findings at or above the minimum severity, most severe first. */
export function visibleFindings(findings, cfg) {
  return findings
    .filter((f) => rank(f.severity) <= rank(cfg.minSeverity))
    .sort((a, b) => rank(a.severity) - rank(b.severity));
}

/** Drops findings listed in .gnawky-ignore.json, then applies the severity filter. */
export function filterFindings(dir, cfg, findings) {
  const ignored = new Set(loadIgnores(dir).map((i) => i.fingerprint));
  return visibleFindings(findings.filter((f) => !ignored.has(f.fingerprint)), cfg);
}

export function writeReports(dir, result) {
  const out = ensureOutDir(dir);
  fs.writeFileSync(path.join(out, 'findings.json'), JSON.stringify(result, null, 2) + '\n');
  fs.writeFileSync(path.join(out, 'security-report.md'), renderMarkdown(result) + '\n');
  fs.writeFileSync(path.join(out, 'security-report.html'), renderHtml(result));
  return out;
}

export function loadLastScan(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, OUT_DIR, 'findings.json'), 'utf8'));
  } catch {
    return null;
  }
}

export const reportFile = (dir) => path.join(dir, OUT_DIR, 'security-report.md');
export const htmlReportFile = (dir) => path.join(dir, OUT_DIR, 'security-report.html');
