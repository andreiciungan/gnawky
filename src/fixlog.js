// A record of the advisories a kept dependency fix removed, with their GHSA and CVE IDs,
// saved in .gnawky/fixes/ (not committed) as JSON plus a Markdown list for a PR or ticket.

import fs from 'node:fs';
import path from 'node:path';
import { ensureOutDir } from './config.js';
import { ghsaFromUrl, rank } from './finding.js';
import { API, github, ApiError } from './github.js';

// Each lookup is one GitHub API request; without a token there are only 60 an hour.
const MAX_CVE_LOOKUPS = 40;

/** CVE IDs for advisories that came without them (npm audit), from the GitHub advisory API. */
async function lookUpCves(entries, offline) {
  const todo = [...new Set(entries.filter((e) => e.cves === null && e.ghsa).map((e) => e.ghsa))];
  const found = new Map();
  let note = null;
  if (offline) {
    note = 'CVE IDs not looked up (offline mode)';
  } else {
    for (const ghsa of todo.slice(0, MAX_CVE_LOOKUPS)) {
      try {
        const adv = await github(`${API}/advisories/${ghsa}`);
        found.set(ghsa, adv?.cve_id ? [adv.cve_id] : []);
      } catch (e) {
        note = `some CVE IDs could not be looked up: ${e instanceof ApiError ? e.message : e.message ?? e}`;
        break;
      }
    }
    if (!note && todo.length > MAX_CVE_LOOKUPS) note = `CVE IDs looked up for the first ${MAX_CVE_LOOKUPS} advisories only`;
  }
  for (const e of entries) {
    if (e.cves !== null) continue;
    e.cves = found.get(e.ghsa) ?? [];
    if (!found.has(e.ghsa)) e.cvesUnknown = true;
  }
  return note;
}

/** Which applied step most likely fixed a finding (null: a side effect of the other changes). */
function fixedBy(f, steps) {
  const applied = steps.filter((s) => s.status === 'applied');
  const step = (f.fix?.type === 'npm-audit-fix' && applied.find((s) => s.kind === 'audit-fix'))
    || applied.find((s) => s.package && (s.package === f.fix?.package || s.package === f.package));
  return step ? step.label : null;
}

function toEntry(f, steps) {
  const ghsa = f.ghsa ?? ghsaFromUrl(f.url) ?? ghsaFromUrl(f.ruleId);
  return {
    package: f.package,
    severity: f.severity,
    title: f.title.startsWith(`${f.package}: `) ? f.title.slice(f.package.length + 2) : f.title,
    ghsa,
    // null = not known yet (npm audit doesn't report CVEs); [] = the advisory has none.
    cves: Array.isArray(f.cves) ? f.cves : null,
    url: f.url ?? (ghsa ? `https://github.com/advisories/${ghsa}` : null),
    fixedBy: fixedBy(f, steps),
  };
}

/** One line per advisory: the same advisory can be reported for several dependency paths. */
function dedupe(entries) {
  const seen = new Map();
  for (const e of entries) {
    const key = `${e.package}|${e.ghsa ?? e.title}`;
    if (!seen.has(key)) seen.set(key, e);
  }
  return [...seen.values()].sort((a, b) => rank(a.severity) - rank(b.severity) || a.package.localeCompare(b.package));
}

const ids = (e) => [...e.cves, e.ghsa].filter(Boolean).join(', ') || 'no ID';

export function renderFixMarkdown(rec) {
  const out = [`# Vulnerabilities fixed (${rec.date.slice(0, 10)})`, ''];
  out.push(`Branch \`${rec.branch}\` (from \`${rec.base}\`), ${rec.packageManager}.`, '');
  if (!rec.verified) {
    out.push(`> Not confirmed by a new ${rec.packageManager} audit: these are the advisories the applied changes target.`, '');
  }
  out.push('| Severity | Package | Advisory | IDs |', '|---|---|---|---|');
  for (const e of rec.fixed) {
    const link = e.url ? `[${ids(e)}](${e.url})` : ids(e);
    out.push(`| ${e.severity} | ${e.package} | ${e.title.replace(/\|/g, '\\|')} | ${link} |`);
  }
  if (!rec.fixed.length) out.push('| | | none | |');
  out.push('');
  const changes = rec.changes.map((c) => `- ${c}`);
  if (changes.length) out.push('Changes:', '', ...changes, '');
  if (rec.stillOpen) out.push(`Still open after the fix: ${rec.stillOpen} advisory finding(s).`, '');
  if (rec.note) out.push(`_${rec.note}._`, '');
  return out.join('\n');
}

/**
 * Saves the record of a kept fix. `fixed` are the findings the re-audit no longer reports
 * (verified), or, without a re-audit, the findings of the changes that were applied.
 * Returns { json, md, record }.
 */
export async function saveFixRecord(dir, { report, fixed, stillOpen, verified, pm, offline }) {
  const entries = dedupe(fixed.map((f) => toEntry(f, report.steps)));
  const note = await lookUpCves(entries, offline);
  const date = new Date().toISOString();
  const record = {
    date,
    branch: report.branch,
    base: report.base,
    packageManager: pm,
    verified,
    changes: report.steps.filter((s) => s.status === 'applied').map((s) => s.label),
    fixed: entries,
    stillOpen,
    note,
  };
  const out = path.join(ensureOutDir(dir), 'fixes');
  fs.mkdirSync(out, { recursive: true });
  const base = path.join(out, date.slice(0, 19).replace(/[:T]/g, '-'));
  fs.writeFileSync(`${base}.json`, JSON.stringify(record, null, 2) + '\n');
  fs.writeFileSync(`${base}.md`, renderFixMarkdown(record));
  return { json: `${base}.json`, md: `${base}.md`, record };
}

export { ids as advisoryIds };
