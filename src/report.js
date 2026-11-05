import { SEVERITY_ORDER } from './finding.js';
import { VERDICTS, URGENCIES } from './triage.js';

const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function renderMarkdown({ target, date, findings, tools, ignoredCount }, triage = { entries: {} }) {
  const out = [];
  out.push('# Security scan report', '');
  out.push(`- **Target:** \`${target}\``, `- **Date:** ${date}`, `- **Suppressed by .gnawky-ignore.json:** ${ignoredCount}`, '');

  out.push('## Summary', '', '| Severity | Count |', '|---|---|');
  for (const sev of SEVERITY_ORDER) {
    const n = findings.filter((f) => f.severity === sev).length;
    if (n) out.push(`| ${sev} | ${n} |`);
  }
  if (!findings.length) out.push('| none | 0 |');
  out.push('');

  out.push('## Scanners', '');
  for (const t of tools) {
    out.push(t.status === 'ran' ? `- **${t.name}:** ran, ${t.count} finding(s)` : `- **${t.name}:** ${t.status} (${cell(t.message)})`);
  }
  out.push('');

  if (tools.every((t) => t.status !== 'ran')) {
    out.push('> **Warning:** no scanner ran successfully, so an empty result does not mean the project is safe.', '');
  }

  out.push('## Findings', '');
  if (!findings.length) out.push('No findings at or above the selected severity.');
  for (const f of findings) {
    const loc = f.file ? `\`${f.file}${f.line ? `:${f.line}` : ''}\`` : 'n/a';
    out.push(`### [${f.severity.toUpperCase()}] ${f.title}`, '');
    out.push(`- **Tool / rule:** ${f.tool} / \`${f.ruleId}\``);
    out.push(`- **Location:** ${loc}`);
    if (f.cwe?.length) out.push(`- **CWE:** ${f.cwe.join(', ')}`);
    if (f.description) out.push(`- **Details:** ${f.description}`);
    out.push(`- **Suggested fix (${f.fix.type}):** ${f.fix.detail}`);
    const t = triage.entries[f.fingerprint];
    if (t) out.push(`- **Claude's take (suggestion):** ${VERDICTS[t.verdict]}, ${URGENCIES[t.urgency]}. ${t.reason}`);
    if (f.url) out.push(`- **Reference:** ${f.url}`);
    out.push(`- **ID:** \`${f.fingerprint}\``, '');
  }
  return out.join('\n');
}
