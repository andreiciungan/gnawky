import fs from 'node:fs';
import { SEVERITY_ORDER, rank } from './finding.js';
import { groupFindings, isGroup, groupFixes, groupTitle, severityCounts, idsOf } from './groups.js';
import {
  mergeAdvisories, throughProjects, sharedVersions, countBySeverity, sharedPackages, writeWorkspaceResult, workspaceReportFile, workspaceHtmlFile,
} from './workspace.js';
import { REPORT_CSS, esc, safeUrl, FAVICON, BRAND } from './html-report.js';
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
  };
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
  out.push('## Projects', '', '| Project | Package manager | Dependency audit | Prod first | Findings | Uses |', '|---|---|---|---|---|---|');
  for (const p of result.projects) {
    const a = d.audit(p);
    const status = !a ? 'n/a' : a.status === 'ran' ? 'ran' : `${a.status}: ${a.message}`;
    const uses = usesOf(result, p.rel).map((l) => `${l.to} ${l.installed ?? l.spec}`).join(', ');
    out.push(`| ${cell(p.rel)} | ${cell(p.pm ?? 'no lockfile')} | ${cell(status)} | ${prodFirstCount(p.findings)} | ${cell(countBySeverity(p.findings) || 'none')} | ${cell(uses)} |`);
  }
  out.push('');

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

  if (d.through.length) {
    out.push('## Brought in by your own projects', '');
    out.push('Advisories that reach a project through another picked project (from each project\'s lockfile):', '');
    for (const t of d.through) out.push(`- **${t.rel}** brings ${plural(t.advisories, 'advisory', 'advisories')} into ${t.into.join(', ')}`);
    out.push('');
  }

  out.push('## Findings per project', '');
  for (const p of result.projects) {
    out.push(`### ${p.rel} (${countBySeverity(p.findings) || 'no findings'}${prodFirstCount(p.findings) ? `; ${prodFirstCount(p.findings)} to fix for production first` : ''})`, '');
    for (const n of p.notes ?? []) out.push(`- _Note: ${cell(n)}_`);
    for (const t of p.tools) if (t.status !== 'ran') out.push(`- _${t.name} ${t.status}: ${cell(t.message)}_`);
    for (const g of groupFindings(p.findings)) {
      const fixes = groupFixes(g);
      const fix = fixes.length === 1 ? fixes[0].fix.detail : `${fixes.length} different fixes`;
      const via = (g.lead.via ?? []).filter((v) => v !== g.package);
      const tag = ['fix first, production', 'production', 'dev only'][Math.min(...g.findings.map(priorityTier))];
      out.push(`- **[${g.severity.toUpperCase()}] ${cell(groupTitle(g))}**${isGroup(g) ? ` (${severityCounts(g.findings)})` : ''} _${tag}_${via.length ? `, via ${via.join(', ')}` : ''}. ${cell(fix)}`);
    }
    if (!p.findings.length && p.tools.some((t) => t.status === 'ran')) out.push('No findings at or above the selected severity.');
    out.push('');
  }
  return out.join('\n');
}

// ------------------------------------------------------------ HTML

/**
 * The link map as inline SVG: projects that others use at the bottom, the projects that use
 * them above, an arrow for each "uses". Projects with no link sit in a row of their own.
 */
function mapSvg(result, d) {
  const W = 168;
  const H = 52;
  const GX = 24;
  const GY = 64;
  const rows = [...d.order].reverse(); // apps on top, libraries at the bottom
  const loose = result.projects.map((p) => p.rel).filter((r) => !d.linked.has(r));
  if (loose.length) rows.push(loose);
  const cols = Math.max(...rows.map((r) => r.length));
  const width = cols * W + (cols - 1) * GX;
  const height = rows.length * H + (rows.length - 1) * GY + (loose.length ? 24 : 0);
  const pos = new Map();
  rows.forEach((row, y) => {
    const offset = (width - (row.length * W + (row.length - 1) * GX)) / 2;
    const extra = loose.length && y === rows.length - 1 ? 24 : 0;
    row.forEach((rel, x) => pos.set(rel, { x: offset + x * (W + GX), y: y * (H + GY) + extra }));
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
  const nodes = [...pos].map(([rel, { x, y }]) => {
    const p = byRel.get(rel);
    const w = d.worst(p);
    const label = rel.length > 22 ? `${rel.slice(0, 21)}…` : rel;
    const pf = prodFirstCount(p.findings);
    const sub = p.findings.length ? `${pf ? `${pf} prod first · ` : ''}${p.findings.length} finding${p.findings.length === 1 ? '' : 's'}` : d.audit(p)?.status === 'ran' ? 'no findings' : 'not checked';
    return `<g class="node sev-${w}" transform="translate(${x},${y})"><title>${esc(`${rel}: ${countBySeverity(p.findings) || sub}`)}</title><rect width="${W}" height="${H}" rx="8"/><text x="${W / 2}" y="21" class="n">${esc(label)}</text><text x="${W / 2}" y="39" class="s">${esc(sub)}</text></g>`;
  }).join('');
  const looseLabel = loose.length ? `<text x="0" y="${pos.get(loose[0]).y - 10}" class="cap">Not linked to the others</text>` : '';
  return `<div class="mapbox"><svg class="map" width="${width + 4}" viewBox="-2 -2 ${width + 4} ${height + 4}" role="img" aria-label="Which projects use which">
<defs><marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="arrow"/></marker></defs>
${edges}${nodes}${looseLabel}</svg>
<p class="legend">An arrow means "uses". Border color: the project's worst finding.${d.versions.length ? ' <span class="dash"></span> uses a different version than most.' : ''}</p></div>`;
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
    return `<details class="finding sev-${esc(e.severity)}"${i < 3 ? ' open' : ''}><summary><span class="sev sev-${esc(e.severity)}">${esc(e.severity)}</span><span class="title">${esc(e.package)}: ${e.advisories.length} advisor${e.advisories.length === 1 ? 'y' : 'ies'}</span>${badge}<span class="meta">${esc(countBySeverity(e.advisories))} · ${e.projects.length} projects</span></summary>
<div class="advs"><div class="scroll"><table><thead><tr><th>Project</th><th>Production</th><th>Advisories</th><th>Fix there</th></tr></thead><tbody>${rows}</tbody></table></div>
<div class="advs-h" style="margin-top:12px">Advisories</div><ul class="advlist">${advs}</ul></div></details>`;
  }).join('\n');

  const throughList = d.through.map((t) => `<li><b>${esc(t.rel)}</b> brings ${esc(plural(t.advisories, 'advisory', 'advisories'))} into ${esc(t.into.join(', '))}</li>`).join('');

  const perProject = result.projects.map((p) => {
    const notes = (p.notes ?? []).map((n) => `<li class="note-line">Note: ${esc(n)}</li>`).join('');
    const skipped = notes + p.tools.filter((t) => t.status !== 'ran').map((t) => `<li class="muted">${esc(t.name)} ${esc(t.status)}: ${esc(t.message)}</li>`).join('');
    const items = groupFindings(p.findings).map((g) => {
      const fixes = groupFixes(g);
      const via = (g.lead.via ?? []).filter((v) => v !== g.package);
      const ids = isGroup(g) ? '' : idsOf(g.lead).join(', ');
      const tier = Math.min(...g.findings.map(priorityTier));
      const badge = tier === 0 ? ' <span class="tri prod-first">prod first</span>' : tier === 2 ? ' <span class="tri">dev only</span>' : '';
      return `<li class="sev-${esc(g.severity)}">${sevBadge(g.severity)}${badge} <b>${esc(groupTitle(g))}</b>${isGroup(g) ? ` <span class="muted">(${esc(severityCounts(g.findings))})</span>` : ''}${ids ? ` <span class="muted">${esc(ids)}</span>` : ''}${via.length ? ` <span class="muted">via ${esc(via.join(', '))}</span>` : ''}<div class="fixline">${fixes.map((x) => esc(x.fix.detail)).join('<br>')}</div></li>`;
    }).join('');
    const none = !p.findings.length && p.tools.some((t) => t.status === 'ran') ? '<li class="muted">No findings at or above the selected severity.</li>' : '';
    return `<details class="proj" id="p-${esc(p.rel)}"><summary><b>${esc(p.rel)}</b> <span class="muted">${esc(p.name !== p.rel ? p.name : '')}</span><span class="cnt">${prodFirstCount(p.findings) ? `<b class="pf">${prodFirstCount(p.findings)} prod first</b> · ` : ''}${esc(countBySeverity(p.findings) || 'no findings')}</span></summary><ul>${skipped}${items}${none}</ul></details>`;
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
.mapbox{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px}
.map{display:block;max-width:100%;height:auto;margin:0 auto}
.legend{margin:10px 0 0;color:var(--muted);font-size:13px;text-align:center}
.legend .dash{display:inline-block;width:28px;border-top:2px dashed var(--medium);vertical-align:middle;margin:0 4px 0 8px}
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
<p>Critical and high findings that ship to production. ${devTotal ? `${devTotal} come only from devDependencies (build, test and lint tools) and are listed last in each project.` : ''} Worked out from package.json; in Next.js projects, devDependencies that aren't test or lint tools count as production, since they can be bundled.</p></div>

<h2>How they are linked</h2>
${linksSection}

<h2>Projects</h2>
<div class="scroll"><table><thead><tr><th>Project</th><th>Package manager</th><th>Dependency audit</th><th>Prod first</th><th>Findings</th><th>Uses</th></tr></thead><tbody>${projectRows}</tbody></table></div>

<h2>Packages in more than one project <span class="muted">(${d.shared.length})</span></h2>
${d.shared.length ? `<p class="muted">${d.shared.reduce((n, e) => n + e.advisories.length, 0)} advisories in ${d.shared.length} packages, grouped per package like in each project. The fix can differ per project: it depends on what installs the package there.</p>${sharedCards}` : '<div class="empty-state">Every vulnerable package was found in one project only.</div>'}
${throughList ? `<h2>Brought in by your own projects</h2><p class="muted">Advisories that reach a project through another picked project, from each project's lockfile.</p><ul>${throughList}</ul>` : ''}

<h2>Findings per project <span class="muted">(${d.total})</span></h2>
${perProject}

<footer>Generated by Gnawky. This report lists your projects' weak spots: keep it private.</footer>
</main>
</body>
</html>
`;
}

/** Saves the result and both reports in <workspace>/.gnawky/. */
export function writeWorkspaceReports(root, result) {
  writeWorkspaceResult(root, result);
  fs.writeFileSync(workspaceReportFile(root), renderWorkspaceMarkdown(result) + '\n');
  fs.writeFileSync(workspaceHtmlFile(root), renderWorkspaceHtml(result));
}
