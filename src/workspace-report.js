import fs from 'node:fs';
import { SEVERITY_ORDER, rank } from './finding.js';
import { isGroup, groupFixes, groupTitle, severityCounts, idsOf } from './groups.js';
import {
  mergeAdvisories, throughProjects, sharedVersions, countBySeverity, sharedPackages, writeWorkspaceResult, workspaceReportFile, workspaceHtmlFile,
  attachTriage, triageCounts,
} from './workspace.js';
import { reviewGroups, VERDICTS, URGENCIES } from './triage.js';

const URG_RANK = { now: 0, soon: 1, low: 2 };
const VERDICT_RANK = { real: 0, 'needs-review': 1, 'false-positive': 2 };
/** A project's verdicts in the shape triage.js uses. */
const triageOf = (p) => ({ entries: p.triage ?? {} });
/**
 * Claude's verdict for a group of findings in one project: the most serious one (a real issue
 * before "needs a human" before a likely false positive, then the most urgent), or null.
 */
function groupVerdict(g, p) {
  const ts = g.findings.map((f) => p.triage?.[f.fingerprint]).filter(Boolean);
  if (!ts.length) return null;
  return [...ts].sort((a, b) => (VERDICT_RANK[a.verdict] ?? 1) - (VERDICT_RANK[b.verdict] ?? 1) || (URG_RANK[a.urgency] ?? 2) - (URG_RANK[b.urgency] ?? 2))[0];
}
/** Groups in report order: Claude's order once triaged (likely false positives last). */
const projectGroups = (p) => reviewGroups(p.findings, triageOf(p));
const triageLine = (projects) => {
  const n = triageCounts(projects);
  return n.real + n.falsePositive + n.unsure
    ? `Claude triage: ${n.real} real, ${n.falsePositive} likely false positive${n.falsePositive === 1 ? '' : 's'}, ${n.unsure} unsure, ${n.none} not triaged.`
    : null;
};
import { REPORT_CSS, esc, safeUrl, FAVICON, BRAND, triageBadges, SPARK } from './html-report.js';
import { prodFirstCount, shipsToProd, priorityTier } from './prod.js';

const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

/** Everything both reports show, worked out once. */
function digest(result) {
  const merged = mergeAdvisories(result);
  const linked = new Set(result.links.flatMap((l) => [l.from, l.to]));
  const worst = (p) => p.findings.reduce((w, f) => (rank(f.severity) < rank(w) ? f.severity : w), 'none');
  const audit = (p) => p.tools.find((t) => /audit/.test(t.name));
  return {
    merged,
    shared: sharedPackages(merged),
    through: throughProjects(merged),
    versions: sharedVersions(result.links).filter((v) => v.specs.length > 1),
    differs: result.links.filter((l) => l.differs),
    linked,
    worst,
    audit,
    total: result.projects.reduce((n, p) => n + p.findings.length, 0),
    // Fix order only matters for projects that others use, and the ones that use them.
    order: result.layers.map((l) => l.filter((r) => linked.has(r))).filter((l) => l.length),
    fixOrder: fixOrder(result, worst),
  };
}

/**
 * Projects in the order to fix them: a shared project before the projects that use it (its
 * fix has to be released before they can pick it up), then the most urgent first: most
 * critical/high findings in production, worst severity, most findings. Projects with nothing
 * to fix come last.
 */
function fixOrder(result, worst) {
  const layer = new Map(result.layers.flatMap((l, i) => l.map((r) => [r, i])));
  const key = (p) => [p.findings.length ? 0 : 1, layer.get(p.rel) ?? 0, -prodFirstCount(p.findings), rank(worst(p)), -p.findings.length];
  return [...result.projects].sort((a, b) => {
    const x = key(a);
    const y = key(b);
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i];
    return 0;
  });
}

const usesOf = (result, rel) => result.links.filter((l) => l.from === rel);

// ------------------------------------------------------------ Markdown

export function renderWorkspaceMarkdown(result) {
  const d = digest(result);
  const out = [];
  out.push('# Workspace security report', '');
  out.push(`- **Folder:** \`${result.root}\``, `- **Date:** ${result.date}`, `- **Projects:** ${result.projects.length}`);
  if (result.offline) out.push('- **Offline mode:** the dependency audit was skipped');
  out.push(`- **Checked:** dependencies only (npm/yarn audit, and the React bundled in Next.js). Open a project in Gnawky for secrets and code checks.`, '');

  const first = prodFirstCount(result.projects.flatMap((p) => p.findings));
  out.push(`**Fix for production first:** ${first} critical/high finding(s) ship to production across the projects (column "Prod first"). Findings that only devDependencies bring in are listed last.`, '');
  const tl = triageLine(result.projects);
  if (tl) out.push(`**${tl}** Likely false positives are listed last in each project. Verdicts are suggestions.`, '');
  out.push('## How they are linked', '');
  if (!result.links.length) out.push('None of the picked projects depends on another one.', '');
  else {
    for (const p of result.projects) {
      const uses = usesOf(result, p.rel);
      if (uses.length) out.push(`- **${p.rel}** uses ${uses.map((l) => `\`${l.name}@${l.installed ?? l.spec}\`${l.field === 'dependencies' ? '' : ` (${l.field})`}`).join(', ')}`);
    }
    out.push('');
    if (d.versions.length) {
      out.push('**Different versions in use.** A fix released in one of these reaches only the projects that move to it:', '');
      for (const v of d.versions) out.push(`- \`${v.name}\`: ${v.specs.map((s) => `${s.spec} (${s.from.join(', ')})`).join('; ')}`);
      out.push('');
    }
    if (d.differs.length) {
      const libs = [...new Set(d.differs.map((l) => l.to))];
      out.push(`**Folder version differs** from what the others install for ${libs.map((r) => `\`${r}\``).join(', ')} (old checkout, or the version is bumped at release). Its own scan checks the folder's lockfile; what the apps install is checked in their own scans.`, '');
    }
    if (d.order.length > 1) {
      out.push('**Fix order:** shared projects first, release them, then bump them in the projects that use them:', '');
      d.order.forEach((l, i) => out.push(`${i + 1}. ${l.join(', ')}`));
      out.push('');
    }
  }

  if (d.through.length) {
    out.push('## Brought in by your own projects', '');
    out.push('Advisories that reach a project through another picked project (from each project\'s lockfile):', '');
    for (const t of d.through) out.push(`- **${t.rel}** brings ${plural(t.advisories, 'advisory', 'advisories')} into ${t.into.join(', ')}`);
    out.push('');
  }

  out.push('## Findings per project', '', 'In the order to fix them: shared projects before the projects that use them, then the most urgent first.', '');
  for (const p of d.fixOrder) {
    out.push(`### ${d.fixOrder.indexOf(p) + 1}. ${p.rel} (${countBySeverity(p.findings) || 'no findings'}${prodFirstCount(p.findings) ? `; ${prodFirstCount(p.findings)} to fix for production first` : ''})`, '');
    for (const n of p.notes ?? []) out.push(`- _Note: ${cell(n)}_`);
    for (const t of p.tools) if (t.status !== 'ran') out.push(`- _${t.name} ${t.status}: ${cell(t.message)}_`);
    for (const g of projectGroups(p)) {
      const fixes = groupFixes(g);
      const fix = fixes.length === 1 ? fixes[0].fix.detail : `${fixes.length} different fixes`;
      const via = (g.lead.via ?? []).filter((v) => v !== g.package);
      const tag = ['fix first, production', 'production', 'dev only'][Math.min(...g.findings.map(priorityTier))];
      const t = groupVerdict(g, p);
      const claude = t ? ` Claude: ${VERDICTS[t.verdict] ?? t.verdict}${t.verdict === 'false-positive' ? '' : `, ${URGENCIES[t.urgency] ?? t.urgency}`}${t.reason ? ` (${cell(t.reason)})` : ''}.` : '';
      out.push(`- **[${g.severity.toUpperCase()}] ${cell(groupTitle(g))}**${isGroup(g) ? ` (${severityCounts(g.findings)})` : ''} _${tag}_${via.length ? `, via ${via.join(', ')}` : ''}. ${cell(fix)}.${claude}`);
    }
    if (!p.findings.length && p.tools.some((t) => t.status === 'ran')) out.push('No findings at or above the selected severity.');
    out.push('');
  }

  out.push('## Projects', '', '| Project | Package manager | Dependency audit | Prod first | Findings | Uses |', '|---|---|---|---|---|---|');
  for (const p of result.projects) {
    const a = d.audit(p);
    const status = !a ? 'n/a' : a.status === 'ran' ? 'ran' : `${a.status}: ${a.message}`;
    const uses = usesOf(result, p.rel).map((l) => `${l.to} ${l.installed ?? l.spec}`).join(', ');
    out.push(`| ${cell(p.rel)} | ${cell(p.pm ?? 'no lockfile')} | ${cell(status)} | ${prodFirstCount(p.findings)} | ${cell(countBySeverity(p.findings) || 'none')} | ${cell(uses)} |`);
  }
  out.push('');

  const sharedAdvisories = d.shared.reduce((n, e) => n + e.advisories.length, 0);
  out.push(`## Packages in more than one project (${d.shared.length})`, '');
  if (!d.shared.length) out.push('None: every vulnerable package was found in one project only.', '');
  else {
    out.push(`${sharedAdvisories} advisories in ${d.shared.length} packages, grouped per package like in each project. The fix can differ per project (it depends on what installs the package there).`, '');
    for (const e of d.shared) {
      const tag = e.prodFirst ? ', fix first (production)' : e.prod ? '' : ', dev only everywhere';
      out.push(`### [${e.severity.toUpperCase()}] ${e.package}: ${e.advisories.length} advisor${e.advisories.length === 1 ? 'y' : 'ies'} in ${e.projects.length} projects${tag}`, '');
      out.push('| Project | Production | Advisories | Fix |', '|---|---|---|---|');
      for (const x of e.projects) {
        out.push(`| ${cell(x.rel)}${x.through.length ? ` (via ${cell(x.through.join(', '))})` : ''} | ${x.prod ? 'yes' : 'dev only'} | ${x.advisories} | ${cell(x.fixes.join(' / '))} |`);
      }
      out.push('');
      for (const a of e.advisories) {
        const title = a.url ? `[${cell(a.title)}](${a.url})` : cell(a.title);
        out.push(`- ${a.severity}: ${title}${a.ghsa ? ` (${a.ghsa})` : ''}, in ${a.projects.length} project${a.projects.length === 1 ? '' : 's'}`);
      }
      out.push('');
    }
  }
  return out.join('\n');
}

// ------------------------------------------------------------ HTML

/**
 * The link map: an inline SVG with projects that others use at the bottom, the projects that
 * use them above and an arrow for each "uses". Projects with no link are a row of boxes below
 * it, then the legend.
 */
function mapSvg(result, d) {
  const W = 168;
  const H = 52;
  const GX = 24;
  const GY = 64;
  const rows = [...d.order].reverse(); // apps on top, libraries at the bottom
  const loose = result.projects.map((p) => p.rel).filter((r) => !d.linked.has(r));
  const cols = Math.max(...rows.map((r) => r.length));
  const width = cols * W + (cols - 1) * GX;
  const height = rows.length * H + (rows.length - 1) * GY;
  const pos = new Map();
  rows.forEach((row, y) => {
    const offset = (width - (row.length * W + (row.length - 1) * GX)) / 2;
    row.forEach((rel, x) => pos.set(rel, { x: offset + x * (W + GX), y: y * (H + GY) }));
  });
  const byRel = new Map(result.projects.map((p) => [p.rel, p]));
  const versions = new Map(d.versions.map((v) => [v.rel, v]));
  const edges = result.links.map((l) => {
    const a = pos.get(l.from);
    const b = pos.get(l.to);
    const x1 = a.x + W / 2;
    const y1 = a.y + H;
    const x2 = b.x + W / 2;
    const y2 = b.y;
    const odd = versions.has(l.to) && versions.get(l.to).specs[0].spec !== (l.installed ?? l.spec);
    const my = (y1 + y2) / 2;
    return `<path class="edge${odd ? ' odd' : ''}" d="M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2 - 4}" marker-end="url(#arr)"><title>${esc(`${l.from} uses ${l.name}@${l.installed ?? l.spec}`)}</title></path>`;
  }).join('');
  const info = (rel) => {
    const p = byRel.get(rel);
    const pf = prodFirstCount(p.findings);
    const sub = p.findings.length ? `${pf ? `${pf} prod first · ` : ''}${p.findings.length} finding${p.findings.length === 1 ? '' : 's'}` : d.audit(p)?.status === 'ran' ? 'no findings' : 'not checked';
    return { p, w: d.worst(p), sub, label: rel.length > 22 ? `${rel.slice(0, 21)}…` : rel, tip: `${rel}: ${countBySeverity(p.findings) || sub}` };
  };
  const nodes = [...pos].map(([rel, { x, y }]) => {
    const n = info(rel);
    return `<g class="node sev-${n.w}" transform="translate(${x},${y})"><title>${esc(n.tip)}</title><rect width="${W}" height="${H}" rx="8"/><text x="${W / 2}" y="21" class="n">${esc(n.label)}</text><text x="${W / 2}" y="39" class="s">${esc(n.sub)}</text></g>`;
  }).join('');
  const looseRow = loose.length ? `<div class="loose"><div class="loose-h">Not linked to the others</div><div class="loose-row">${loose.map((rel) => {
    const n = info(rel);
    return `<a class="pnode sev-${n.w}" href="#p-${esc(rel)}" title="${esc(n.tip)}"><b>${esc(n.label)}</b><span>${esc(n.sub)}</span></a>`;
  }).join('')}</div></div>` : '';
  const swatches = [['critical', 'critical'], ['high', 'high'], ['medium', 'medium'], ['low', 'low'], ['none', 'no findings']]
    .map(([s, l]) => `<span><i class="sw sev-${s}"></i>${l}</span>`).join('');
  return `<div class="mapbox"><svg class="map" width="${width + 4}" viewBox="-2 -2 ${width + 4} ${height + 4}" role="img" aria-label="Which projects use which">
<defs><marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="arrow"/></marker></defs>
${edges}${nodes}</svg>
${looseRow}
<div class="legend"><span><svg width="26" height="10" viewBox="0 0 26 10" aria-hidden="true"><path d="M0,5 H20" class="edge"/><path d="M18,1 L25,5 L18,9 z" class="arrow"/></svg>uses</span>${d.versions.length ? '<span><i class="dash"></i>different version than most</span>' : ''}<span class="legend-sep">Border: worst finding</span>${swatches}</div></div>`;
}

const sevBadge = (s) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;

export function renderWorkspaceHtml(result) {
  const d = digest(result);
  const dateText = new Date(result.date).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
  const allFindings = result.projects.flatMap((p) => p.findings);
  const tiles = SEVERITY_ORDER.map((s) => {
    const n = allFindings.filter((f) => f.severity === s).length;
    return `<div class="tile sev-tile-${s}${n ? '' : ' empty'}" style="cursor:default"><span class="n">${n}</span><span class="l">${s}</span></div>`;
  }).join('');

  const prodFirstTotal = prodFirstCount(allFindings);
  const devTotal = allFindings.filter((f) => !shipsToProd(f)).length;
  const projectRows = result.projects.map((p) => {
    const a = d.audit(p);
    const status = !a ? '<span class="muted">n/a</span>' : a.status === 'ran' ? esc(a.name) : `<span class="muted">${esc(a.status)}: ${esc(a.message)}</span>`;
    const uses = usesOf(result, p.rel).map((l) => `<code>${esc(l.name)}@${esc(l.installed ?? l.spec)}</code>`).join(' ');
    const pf = prodFirstCount(p.findings);
    return `<tr><td><a href="#p-${esc(p.rel)}"><b>${esc(p.rel)}</b></a></td><td>${esc(p.pm ?? 'no lockfile')}</td><td>${status}</td><td>${pf ? `<b class="pf">${pf}</b>` : '0'}</td><td>${esc(countBySeverity(p.findings) || 'none')}</td><td>${uses}</td></tr>`;
  }).join('');

  const versionNotes = d.versions.map((v) => `<li><code>${esc(v.name)}</code>: ${v.specs.map((s) => `<b>${esc(s.spec)}</b> <span class="muted">(${esc(s.from.join(', '))})</span>`).join(' · ')}</li>`).join('');
  const differLibs = [...new Set(d.differs.map((l) => l.to))];
  const linksSection = result.links.length ? `
${mapSvg(result, d)}
${versionNotes ? `<div class="note"><b>Different versions in use.</b> A fix released in one of these reaches only the projects that move to it.<ul>${versionNotes}</ul></div>` : ''}
${differLibs.length ? `<p class="muted">The folder version of ${differLibs.map((r) => `<code>${esc(r)}</code>`).join(', ')} differs from what the others install (old checkout, or the version is bumped at release). Its own scan checks the folder's lockfile; what the apps install is checked in their own scans.</p>` : ''}
${d.order.length > 1 ? `<p><b>Fix order:</b> shared projects first, release them, then bump them where they're used.</p><ol class="order">${d.order.map((l) => `<li>${l.map((r) => `<code>${esc(r)}</code>`).join(' ')}</li>`).join('')}</ol>` : ''}`
    : '<div class="empty-state">None of the picked projects depends on another one.</div>';

  const sharedCards = d.shared.map((e, i) => {
    const badge = e.prodFirst ? '<span class="tri prod-first">prod first</span>' : e.prod ? '' : '<span class="tri">dev only</span>';
    const rows = e.projects.map((x) => `<tr><td><b>${esc(x.rel)}</b>${x.through.length ? ` <span class="muted">(via ${esc(x.through.join(', '))})</span>` : ''}</td><td>${x.prod ? 'yes' : '<span class="muted">dev only</span>'}</td><td>${x.advisories}</td><td>${x.fixes.map(esc).join('<br>')}</td></tr>`).join('');
    const advs = e.advisories.map((a) => {
      const url = safeUrl(a.url);
      const title = url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(a.title)}</a>` : esc(a.title);
      return `<li>${sevBadge(a.severity)} ${title} <span class="muted">${esc([a.ghsa, `${a.projects.length} project${a.projects.length === 1 ? '' : 's'}`].filter(Boolean).join(' · '))}</span></li>`;
    }).join('');
    return `<details class="finding sev-${esc(e.severity)}" data-tier="${e.prodFirst ? 0 : e.prod ? 1 : 2}"${i < 3 ? ' open' : ''}><summary><span class="sev sev-${esc(e.severity)}">${esc(e.severity)}</span><span class="title">${esc(e.package)}: ${e.advisories.length} advisor${e.advisories.length === 1 ? 'y' : 'ies'}</span>${badge}<span class="meta">${esc(countBySeverity(e.advisories))} · ${e.projects.length} projects</span></summary>
<div class="advs"><div class="scroll"><table><thead><tr><th>Project</th><th>Production</th><th>Advisories</th><th>Fix there</th></tr></thead><tbody>${rows}</tbody></table></div>
<div class="advs-h" style="margin-top:12px">Advisories</div><ul class="advlist">${advs}</ul></div></details>`;
  }).join('\n');

  const throughList = d.through.map((t) => `<li><b>${esc(t.rel)}</b> brings ${esc(plural(t.advisories, 'advisory', 'advisories'))} into ${esc(t.into.join(', '))}</li>`).join('');

  const perProject = d.fixOrder.map((p, step) => {
    const notes = (p.notes ?? []).map((n) => `<li class="note-line">Note: ${esc(n)}</li>`).join('');
    const skipped = notes + p.tools.filter((t) => t.status !== 'ran').map((t) => `<li class="muted">${esc(t.name)} ${esc(t.status)}: ${esc(t.message)}</li>`).join('');
    const items = projectGroups(p).map((g) => {
      const fixes = groupFixes(g);
      const via = (g.lead.via ?? []).filter((v) => v !== g.package);
      const ids = isGroup(g) ? '' : idsOf(g.lead).join(', ');
      const tier = Math.min(...g.findings.map(priorityTier));
      const badge = tier === 0 ? ' <span class="tri prod-first">prod first</span>' : tier === 2 ? ' <span class="tri">dev only</span>' : '';
      const t = groupVerdict(g, p);
      const why = t?.reason ? `<div class="take take-sm take-${esc(t.verdict)}"><div class="take-h">${SPARK}<b>Claude</b></div><p>${esc(t.reason)}</p></div>` : '';
      return `<li class="sev-${esc(g.severity)}${t?.verdict === 'false-positive' ? ' fp' : ''}" data-tier="${tier}">${sevBadge(g.severity)}${badge}${t ? triageBadges(t) : ''} <b>${esc(groupTitle(g))}</b>${isGroup(g) ? ` <span class="muted">(${esc(severityCounts(g.findings))})</span>` : ''}${ids ? ` <span class="muted">${esc(ids)}</span>` : ''}${via.length ? ` <span class="muted">via ${esc(via.join(', '))}</span>` : ''}<div class="fixline">${fixes.map((x) => esc(x.fix.detail)).join('<br>')}</div>${why}</li>`;
    }).join('');
    const none = !p.findings.length && p.tools.some((t) => t.status === 'ran') ? '<li class="muted">No findings at or above the selected severity.</li>' : '';
    return `<details class="proj" id="p-${esc(p.rel)}"><summary><span class="step" title="Fix order">${step + 1}</span><b>${esc(p.rel)}</b> <span class="muted">${esc(p.name !== p.rel ? p.name : '')}</span><span class="cnt">${prodFirstCount(p.findings) ? `<b class="pf">${prodFirstCount(p.findings)} prod first</b> · ` : ''}${esc(countBySeverity(p.findings) || 'no findings')}${triageCounts([p]).falsePositive ? ` · ${triageCounts([p]).falsePositive} likely false positive` : ''}</span></summary><ul>${skipped}${items}${none}</ul></details>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Gnawky workspace report</title>
${FAVICON}
<style>
${REPORT_CSS}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-top:1px solid var(--border);vertical-align:top}th{color:var(--muted);font-weight:600;border-top:0}
td a{color:var(--accent)}.scroll{overflow-x:auto}
.mapbox{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px;overflow:hidden;box-shadow:var(--shadow)}
.map{display:block;max-width:100%;height:auto;margin:0 auto}
.legend{display:flex;flex-wrap:wrap;justify-content:center;align-items:center;gap:8px 18px;margin:16px -16px -16px;padding:12px 16px;border-top:1px solid var(--border);color:var(--muted);font-size:13px}
.legend span{display:inline-flex;align-items:center;gap:6px}.legend .legend-sep{color:var(--text);font-weight:600}
.legend .dash{display:inline-block;width:24px;border-top:2px dashed var(--medium)}
.legend .edge{fill:none;stroke:var(--muted);stroke-width:1.5}.legend .arrow{fill:var(--muted)}
.legend .sw{display:inline-block;width:14px;height:14px;border-radius:4px;border:2px solid var(--c)}.sw.sev-none{--c:var(--ok)}
.loose{margin-top:20px;padding-top:16px;border-top:1px dashed var(--border);text-align:center}
.loose-h{color:var(--muted);font-size:13px;margin-bottom:10px}
.loose-row{display:flex;flex-wrap:wrap;justify-content:center;gap:12px 24px}
.pnode{display:flex;flex-direction:column;justify-content:center;width:168px;height:52px;border:2px solid var(--c,var(--border));border-radius:8px;background:var(--panel);color:var(--text);text-decoration:none;font-size:13px;line-height:1.35}
.pnode.sev-none{--c:var(--ok)}.pnode span{color:var(--muted);font-size:12px}.pnode:hover{background:var(--panel-2)}
.step{display:inline-grid;place-items:center;min-width:24px;height:24px;padding:0 6px;border-radius:999px;background:var(--accent-soft);color:var(--accent);font-size:12.5px;font-weight:700;align-self:center}
.map .node rect{fill:var(--panel);stroke:var(--c,var(--border));stroke-width:2}
.map .node.sev-none rect{stroke:var(--ok)}
.map text{fill:var(--text);text-anchor:middle;font:13px -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.map text.n{font-weight:600}.map text.s{fill:var(--muted);font-size:12px}.map text.cap{text-anchor:start;fill:var(--muted);font-size:12px}
.map .edge{fill:none;stroke:var(--muted);stroke-width:1.5}.map .edge.odd{stroke:var(--medium);stroke-dasharray:5 4}.map .arrow{fill:var(--muted)}
.note{margin:12px 0;padding:10px 14px;border:1px solid var(--medium);border-radius:8px}.note ul{margin:6px 0 0;padding-left:18px}
ol.order{margin:0;padding-left:22px}ol.order li{margin-bottom:4px}
.proj{background:var(--panel);border:1px solid var(--border);border-radius:8px;margin-bottom:8px}
.proj summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.proj .cnt{margin-left:auto;color:var(--muted);font-size:13px}
.proj ul{list-style:none;margin:0;padding:4px 14px 12px;border-top:1px solid var(--border)}
.proj li{padding:8px 0;border-top:1px solid var(--border)}.proj li:first-child{border-top:0}
.note-line{color:var(--medium)}
.advlist{list-style:none;margin:0;padding:0}.advlist li{padding:4px 0}
.fixline{color:var(--muted);font-size:13px;margin-top:2px}
.sev-none{--c:var(--ok)}.pf{color:var(--critical)}
.proj li.fp{opacity:.7}
.proj li>.sev,.proj li>.tri{margin-right:4px}
.take-sm{margin:8px 0 2px;padding:8px 12px 10px}.take-sm p{font-size:14.5px;margin-top:4px}
.proj{box-shadow:var(--shadow);border-radius:12px}
[hidden]{display:none!important}
</style>
</head>
<body>
<main>
${BRAND}
<h1>Workspace report</h1>
<div class="facts"><span><code>${esc(result.root)}</code></span><span>${esc(dateText)}</span><span>${esc(plural(result.projects.length, 'project'))}</span><span>Minimum severity: ${esc(result.minSeverity)}</span>${result.offline ? '<span>Offline mode</span>' : ''}</div>
<p class="muted">Dependencies only (npm/yarn audit, and the React bundled in Next.js). Open a project in Gnawky for secrets and code checks.</p>
<div class="tiles">${tiles}</div>
<div class="claude"><div class="tile prod-tile" style="cursor:default"><span class="n">${prodFirstTotal}</span><span class="l">Fix for production first</span></div>
<p>Critical and high findings that ship to production. ${devTotal ? `${devTotal} ${devTotal === 1 ? "comes" : "come"} only from devDependencies (build, test and lint tools) and are listed last in each project.` : ''} Worked out from package.json; in Next.js projects, devDependencies that aren't test or lint tools count as production, since they can be bundled.</p></div>
${triageLine(result.projects) ? `<div class="claude claude-ai"><div><div class="take-h">${SPARK}<b>${esc(triageLine(result.projects))}</b></div><p>Likely false positives are listed last in each project. Verdicts are suggestions from Claude, made with each project's code: check the reason before you rely on one.</p></div></div>` : ''}


<h2>How they are linked</h2>
${linksSection}

${throughList ? `<h2>Brought in by your own projects</h2><p class="muted">Advisories that reach a project through another picked project, from each project's lockfile.</p><ul>${throughList}</ul>` : ''}
<h2>Findings per project <span class="muted">(${d.total})</span></h2>
<p class="muted">In the order to fix them: shared projects before the projects that use them (release the fix, then bump it), then the most urgent first.</p>
${allFindings.some((f) => f.scope) ? `<div class="controls"><select id="scope" aria-label="Filter by production"><option value="">All (${allFindings.length})</option><option value="prod"${allFindings.length - devTotal ? '' : ' disabled'}>Production only (${allFindings.length - devTotal})</option><option value="dev"${devTotal ? '' : ' disabled'}>Dev only (${devTotal})</option></select></div>` : ''}
${perProject}


<h2>Projects</h2>
<div class="scroll"><table><thead><tr><th>Project</th><th>Package manager</th><th>Dependency audit</th><th>Prod first</th><th>Findings</th><th>Uses</th></tr></thead><tbody>${projectRows}</tbody></table></div>

<h2>Packages in more than one project <span class="muted">(${d.shared.length})</span></h2>
${d.shared.length ? `<p class="muted">${d.shared.reduce((n, e) => n + e.advisories.length, 0)} advisories in ${d.shared.length} packages, grouped per package like in each project. The fix can differ per project: it depends on what installs the package there.</p>${sharedCards}` : '<div class="empty-state">Every vulnerable package was found in one project only.</div>'}

<script>
(function(){
  var scope=document.getElementById('scope');if(!scope)return;
  var items=[].slice.call(document.querySelectorAll('[data-tier]'));
  scope.addEventListener('change',function(){
    var v=scope.value;
    items.forEach(function(el){var t=el.dataset.tier;el.hidden=v==='prod'?t==='2':v==='dev'?t!=='2':false;});
    // A project or package list with nothing left in this filter says so instead of looking empty.
    [].slice.call(document.querySelectorAll('.proj')).forEach(function(p){
      var left=p.querySelectorAll('li[data-tier]:not([hidden])').length,all=p.querySelectorAll('li[data-tier]').length;
      var n=p.querySelector('.none-in-filter');
      if(all&&!left&&!n){n=document.createElement('li');n.className='none-in-filter muted';n.textContent='Nothing in this filter.';p.querySelector('ul').appendChild(n);}
      if(n)n.hidden=!(all&&!left);
    });
  });
})();
</script>
<footer>Generated by Gnawky. This report lists your projects' weak spots: keep it private.</footer>
</main>
</body>
</html>
`;
}

/** Saves the result and both reports in <workspace>/.gnawky/. */
export function writeWorkspaceReports(root, result) {
  attachTriage(root, result);
  writeWorkspaceResult(root, result);
  fs.writeFileSync(workspaceReportFile(root), renderWorkspaceMarkdown(result) + '\n');
  fs.writeFileSync(workspaceHtmlFile(root), renderWorkspaceHtml(result));
}
