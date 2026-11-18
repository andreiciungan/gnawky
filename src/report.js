import { SEVERITY_ORDER } from './finding.js';
import { VERDICTS, URGENCIES } from './triage.js';
import { groupFindings, isGroup, groupFixes, groupTitle, groupTriage, severityCounts, advisoryTitle, idsOf, alsoFixes } from './groups.js';

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
    out.push(t.status === 'ran' ? `- **${t.name}:** ran, ${t.count} finding(s)${t.note ? ` (${t.note})` : ''}` : `- **${t.name}:** ${t.status} (${cell(t.message)})`);
  }
  out.push('');

  if (tools.every((t) => t.status !== 'ran')) {
    out.push('> **Warning:** no scanner ran successfully, so an empty result does not mean the project is safe.', '');
  }

  out.push('## Findings', '');
  if (!findings.length) out.push('No findings at or above the selected severity.');
  const groups = groupFindings(findings);
  if (groups.length < findings.length) out.push('_Advisories fixed by changing the same package are grouped: one upgrade fixes them all._', '');
  for (const g of groups) {
    if (isGroup(g)) pushGroup(out, g, triage);
    else pushFinding(out, g.lead, triage);
  }
  return out.join('\n');
}

function pushFinding(out, f, triage) {
  const loc = f.file ? `\`${f.file}${f.line ? `:${f.line}` : ''}\`` : 'n/a';
  out.push(`### [${f.severity.toUpperCase()}] ${f.title}`, '');
  out.push(`- **Tool / rule:** ${f.tool} / \`${f.ruleId}\``);
  out.push(`- **Location:** ${loc}`);
  if (f.cwe?.length) out.push(`- **CWE:** ${f.cwe.join(', ')}`);
  if (f.description) out.push(`- **Details:** ${f.description}`);
  out.push(`- **Suggested fix (${f.fix.type}):** ${f.fix.detail}`);
  if (f.audit) {
    out.push(`- **Full audit:** verified${f.audit.confidence ? `, ${f.audit.confidence} confidence` : ''}. Details: \`${f.audit.runDir}\``);
    if (f.audit.trace.length) out.push(`- **Trace:** ${f.audit.trace.map((x) => `${x.kind} \`${x.file}:${x.line}\``).join(' → ')}`);
  }
  const t = triage.entries[f.fingerprint];
  if (t) out.push(`- **Claude's take (suggestion):** ${VERDICTS[t.verdict]}, ${URGENCIES[t.urgency]}. ${t.reason}`);
  if (f.url) out.push(`- **Reference:** ${f.url}`);
  out.push(`- **ID:** \`${f.fingerprint}\``, '');
}

/** One package's advisories: the shared fix once, then a table with a row per advisory. */
function pushGroup(out, g, triage) {
  out.push(`### [${g.severity.toUpperCase()}] ${groupTitle(g)} (${severityCounts(g.findings)})`, '');
  out.push(`- **Package:** \`${g.package}\``);
  if (alsoFixes(g)) out.push(`- **Also covers:** ${alsoFixes(g)}, installed by \`${g.package}\` and fixed by the same change`);
  out.push(`- **Location:** ${[...new Set(g.findings.map((f) => `\`${f.file}\``))].join(', ')}`);
  const fixes = groupFixes(g);
  if (fixes.length === 1) {
    out.push(`- **Suggested fix (${fixes[0].fix.type}, all ${g.findings.length}):** ${fixes[0].fix.detail}`);
  } else {
    out.push('- **Suggested fixes:**');
    for (const x of fixes) out.push(`  - (${x.fix.type}, ${x.findings.length} advisor${x.findings.length === 1 ? 'y' : 'ies'}) ${x.fix.detail}`);
  }
  const t = groupTriage(g, triage);
  if (t) out.push(`- **Claude's take (suggestion):** ${VERDICTS[t.verdict]}, ${URGENCIES[t.urgency]}. ${t.reason}`);
  out.push('');
  const multiFix = fixes.length > 1;
  out.push(`| Severity | Advisory | IDs | Details |${multiFix ? ' Fix |' : ''} ID |`, `|---|---|---|---|${multiFix ? '---|' : ''}---|`);
  for (const f of g.findings) {
    const title = f.url ? `[${cell(advisoryTitle(f))}](${f.url})` : cell(advisoryTitle(f));
    const fix = multiFix ? ` ${cell(f.fix.type)} |` : '';
    out.push(`| ${f.severity} | ${title} | ${cell(idsOf(f).join(', '))} | ${cell(f.description)} |${fix} \`${f.fingerprint}\` |`);
  }
  out.push('');
}
