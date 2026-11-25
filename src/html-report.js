import fs from 'node:fs';
import { SEVERITY_ORDER } from './finding.js';
import { VERDICTS, URGENCIES, reviewGroups } from './triage.js';
import { scopeText, groupScopeText, shipsToProd, isProdFirst, prodFirstCount, priorityTier } from './prod.js';
import { groupFindings, isGroup, groupFixes, groupTitle, groupTriage, advisoryTitle, idsOf, alsoFixes, triageByPackage } from './groups.js';

// Self-contained HTML report: no external CSS, JS, fonts or images, so it opens
// offline and viewing it never sends anything anywhere. Every value comes from
// scanner output (package names, advisory text, file paths), so all of it is escaped.

// The logo is embedded (header banner and tab icon) so the report stays one self-contained file.
// The banner files are 720px copies of assets/logo-{light,dark}.png, small enough to inline.
const asset = (name, enc) => {
  try { return fs.readFileSync(new URL(`../assets/${name}`, import.meta.url), enc); } catch { return null; }
};
// The same tab icon as gnawky.dev: the mascot on a purple tile.
const ICON = asset('favicon.png', 'base64');
export const FAVICON = ICON ? `<link rel="icon" type="image/png" href="data:image/png;base64,${ICON}">` : '';
const BANNER = { light: asset('report-logo-light.png', 'base64'), dark: asset('report-logo-dark.png', 'base64') };
const ALT = 'Gnawky: gnaws through your code, watches like a hawk';
export const BRAND = BANNER.light && BANNER.dark
  ? `<img class="logo logo-light" src="data:image/png;base64,${BANNER.light}" alt="${ALT}" width="360" height="102"><img class="logo logo-dark" src="data:image/png;base64,${BANNER.dark}" alt="${ALT}" width="360" height="102">`
  : '<div class="brand">gnawky</div>';

export const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);

// Only plain web links become clickable; anything else (javascript:, data:) is shown as text.
export const safeUrl = (u) => (typeof u === 'string' && /^https?:\/\//i.test(u) ? u : null);

const FIX_LABELS = {
  'npm-audit-fix': ['automatic', 'npm audit fix'],
  'npm-upgrade': ['automatic', 'upgrade'],
  'npm-major-upgrade': ['breaking', 'major upgrade'],
  'yarn-upgrade': ['automatic', 'upgrade'],
  'yarn-major-upgrade': ['breaking', 'major upgrade'],
  'yarn-refresh': ['automatic', 'lockfile refresh'],
  'yarn-resolution': ['risky', 'resolution override'],
  'yarn-major-resolution': ['breaking', 'major resolution override'],
  'npm-override': ['risky', 'override'],
  'npm-major-override': ['breaking', 'major override'],
  'suggested-edit': ['manual', 'suggested edit'],
  manual: ['manual', 'manual'],
};

export function fixBadge(type) {
  const [kind, label] = FIX_LABELS[type] ?? ['manual', type ?? 'manual'];
  return `<span class="fix fix-${kind}">${esc(label)}</span>`;
}

export function triageBadges(t) {
  const v = VERDICTS[t.verdict] ? t.verdict : 'needs-review';
  const u = URGENCIES[t.urgency] ? t.urgency : 'low';
  return `<span class="tri tri-v tri-${v}">${esc(VERDICTS[v])}</span>${v === 'false-positive' ? '' : `<span class="tri urg-${u}">${esc(URGENCIES[u])}</span>`}`;
}

function searchText(f, t) {
  return [f.title, f.tool, f.ruleId, f.file, f.package, f.description, f.fix?.detail, t?.reason, f.ghsa, ...(f.cves ?? []), ...(f.cwe ?? [])].join(' ').toLowerCase();
}

const reference = (f) => {
  const url = safeUrl(f.url);
  return url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a>` : f.url ? esc(f.url) : null;
};

function findingRows(f, t, { inGroup = false } = {}) {
  const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : null;
  return [
    ['Tool / rule', `${esc(f.tool)} / <code>${esc(f.ruleId)}</code>`],
    !inGroup && f.package && ['Package', `<code>${esc(f.package)}</code>`],
    ['Location', loc ? `<code>${esc(loc)}</code>` : 'n/a'],
    !inGroup && scopeText(f) && ['Production', scopeHtml([f])],
    inGroup && idsOf(f).length && ['IDs', idsOf(f).map((x) => `<code>${esc(x)}</code>`).join(' ')],
    f.cwe?.length && ['CWE', f.cwe.map(esc).join(', ')],
    f.description && ['Details', esc(f.description)],
    inGroup && ['Suggested fix', `${fixBadge(f.fix?.type)} ${esc(f.fix?.detail)}`],
    f.audit && ['Full audit', `<span class="tri tri-real">verified</span>${f.audit.confidence ? ` ${esc(f.audit.confidence)} confidence` : ''}${f.audit.likelihood ? `, likelihood ${esc(f.audit.likelihood)}, impact ${esc(f.audit.impact)}` : ''}${f.audit.confidenceReason ? `. ${esc(f.audit.confidenceReason)}` : ''}`],
    f.audit?.attacker && ['Attacker', esc(f.audit.attacker)],
    f.audit?.conditions.length && ['Conditions', `<ul>${f.audit.conditions.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`],
    f.audit?.trace.length && ['Trace', `<ol class="trace">${f.audit.trace.map((x) => `<li><b>${esc(x.kind)}</b> <code>${esc(x.file)}:${esc(x.line)}</code> ${esc(x.description)}</li>`).join('')}</ol>`],
    f.audit && ['Full report', `<code>${esc(f.audit.runDir)}</code>`],
    ['Reference', reference(f)],
    ['ID', `<code>${esc(f.fingerprint)}</code>`],
  ].filter((r) => r && r[1]);
}

/** "ships to production (via axios)" with a "fix first" badge for critical/high. */
function scopeHtml(findings) {
  const text = groupScopeText(findings);
  if (!text) return null;
  const first = findings.some(isProdFirst) ? ' <span class="fix fix-breaking">fix first</span>' : '';
  return `${findings.some(shipsToProd) ? esc(text) : `<span class="muted">${esc(text)}</span>`}${first}`;
}

/** Badge in a card's summary line: "prod first" or "dev only". */
function scopeBadge(findings) {
  if (findings.some(isProdFirst)) return '<span class="tri prod-first">prod first</span>';
  if (findings.some((f) => f.scope) && !findings.some(shipsToProd)) return '<span class="tri">dev only</span>';
  return '';
}

const dl = (rows) => `<dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;

/** The filter and sort attributes every card carries (a group matches a severity or tool if any of its findings does). */
function cardAttrs(sev, list, t, search, open) {
  const sevs = [...new Set(list.map((f) => f.severity))].join(' ');
  const tools = [...new Set(list.map((f) => f.tool))].join(' ');
  const tier = Math.min(...list.map(priorityTier));
  return `class="finding sev-${esc(sev)}${t?.verdict === 'false-positive' ? ' fp' : ''}" data-tier="${tier}" data-sev="${esc(sev)}" data-sevs="${esc(sevs)}" data-tools="${esc(tools)}" data-verdict="${t ? esc(t.verdict) : 'none'}" data-urgency="${t ? esc(t.urgency) : 'none'}" data-search="${esc(search)}"${open ? ' open' : ''}`;
}

/** "4 critical", "18 high"… as colored chips. */
export const sevChips = (findings) => SEVERITY_ORDER
  .map((s) => [s, findings.filter((f) => f.severity === s).length])
  .filter(([, n]) => n)
  .map(([s, n]) => `<span class="chip sev-${s}">${n} ${s}</span>`).join('');

/** A title with the package name first and larger: "next" + "7 advisories". */
export function titleHtml(pkg, title) {
  if (pkg && title.startsWith(`${pkg}: `)) return `<b class="pkg">${esc(pkg)}</b><span>${esc(title.slice(pkg.length + 2))}</span>`;
  return `<b class="pkg">${esc(title)}</b>`;
}

/** The fix lines of an item, each with its kind; how many advisories each covers when there are several. */
export function fixesHtml(fixes) {
  const many = fixes.length > 1;
  return `<ul class="fixes">${fixes.map((x) => `<li>${fixBadge(x.fix?.type)}<span>${esc(x.fix?.detail)}${many ? ` <span class="muted">(${x.findings.length} ${x.findings.length === 1 ? 'advisory' : 'advisories'})</span>` : ''}</span></li>`).join('')}</ul>`;
}

const fixBox = (fixes) => `<div class="fixbox"><div class="fixbox-h">Suggested fix</div>${fixesHtml(fixes)}</div>`;

function findingCard(f, i, triage) {
  const t = triage.entries[f.fingerprint];
  const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : null;
  return `<details ${cardAttrs(f.severity, [f], t, searchText(f, t), i < 3)}>
<summary><div class="item-t">${titleHtml(f.package, f.title)}</div><div class="item-meta"><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>${scopeBadge([f])}${t ? triageBadges(t) : ''}<span class="meta">${esc(f.tool)}${loc ? ` · ${esc(loc)}` : ''}</span></div></summary>
${t ? takeBlock([{ package: null, t }], t) : ''}
${fixBox([{ fix: f.fix, findings: [f] }])}
${dl(findingRows(f, t))}
</details>`;
}

export const SPARK = '<svg class="spark" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2l2.2 6.6L21 11l-6.8 2.4L12 20l-2.2-6.6L3 11l6.8-2.4z"/></svg>';
const verdictOf = (t) => (VERDICTS[t?.verdict] ? t.verdict : 'needs-review');
const takeDate = (t) => esc(String(t.date ?? '').slice(0, 10));

/**
 * Claude's take as a highlighted block at the top of a card, so the verdict and the reason
 * are the first thing you read. `takes` is [{ package, t }]; package is null for a single finding.
 */
function takeBlock(takes, lead) {
  if (!takes.length) return '';
  const one = takes.length === 1;
  const body = one
    ? `<p>${esc(takes[0].t.reason)}</p>`
    : `<ul>${takes.map(({ package: p, t }) => `<li><div class="take-pkg"><code>${esc(p)}</code>${triageBadges(t)}</div><p>${esc(t.reason)}</p></li>`).join('')}</ul>`;
  return `<div class="take take-${verdictOf(lead)}">
<div class="take-h">${SPARK}<b>Claude's take</b>${one ? triageBadges(takes[0].t) : ''}<span class="take-note">suggestion, ${takeDate(takes[0].t)}</span></div>
${body}
</div>`;
}

/** One card per package: the shared fix once, then each advisory as its own expandable row. */
function groupCard(g, i, triage) {
  const t = groupTriage(g, triage);
  const takes = triageByPackage(g, triage);
  const fixes = groupFixes(g);
  const rows = [
    ['Package', `<code>${esc(g.package)}</code>`],
    ['Production', scopeHtml(g.findings)],
    alsoFixes(g) && ['Also covers', `${esc(alsoFixes(g))} <span class="muted">(installed by ${esc(g.package)}; npm expects this upgrade to fix them, not checked)</span>`],
    ['Location', [...new Set(g.findings.map((f) => f.file).filter(Boolean))].map((x) => `<code>${esc(x)}</code>`).join(' ') || 'n/a'],
  ].filter((r) => r && r[1]);
  const mixed = new Set(g.findings.map(shipsToProd)).size > 1;
  const advisories = g.findings.map((f) => `<details class="adv sev-${esc(f.severity)}">
<summary><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span><span class="title">${esc(advisoryTitle(f))}</span><span class="meta">${idsOf(f).map(esc).join(' · ')}</span></summary>
${dl([...(mixed ? [['Production', scopeHtml([f])]] : []), ...findingRows(f, null, { inGroup: true })])}
</details>`).join('\n');
  const search = g.findings.map((f) => searchText(f, triage.entries[f.fingerprint])).join(' ');
  const tools = [...new Set(g.findings.map((f) => f.tool))].join(', ');
  return `<details ${cardAttrs(g.severity, g.findings, t, search, i < 3)}>
<summary><div class="item-t">${titleHtml(g.package, groupTitle(g))}</div><div class="item-meta"><span class="sev sev-${esc(g.severity)}">${esc(g.severity)}</span>${scopeBadge(g.findings)}${t ? triageBadges(t) : ''}${sevChips(g.findings)}<span class="meta">${esc(tools)}</span></div></summary>
${takeBlock(takes, t ?? takes[0]?.t)}
${fixBox(fixes)}
${dl(rows)}
<div class="advs"><div class="advs-h">Advisories</div>${advisories}</div>
</details>`;
}

/** The report's styles, shared with the workspace report. */
export const REPORT_CSS = `:root{color-scheme:light;--bg:#f6f5fa;--panel:#fff;--panel-2:#faf9fd;--text:#1b1830;--muted:#625d78;--border:#e4e1ee;--code:#efedf6;--accent:#6d28d9;--accent-soft:#ede7fb;
--critical:#c4261d;--high:#c9520f;--medium:#a57400;--low:#2d6fb3;--info:#6b6680;--ok:#23854a;--shadow:0 1px 2px rgba(27,24,48,.06),0 4px 14px rgba(27,24,48,.05);}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#0b0914;--panel:#15111f;--panel-2:#1a1528;--text:#f3f0fa;--muted:#a9a2c2;--border:#2c2547;--code:#221c36;--accent:#a78bfa;--accent-soft:#251b47;
--critical:#f2665c;--high:#f08a4b;--medium:#e0b23a;--low:#6aa8e8;--info:#9a94b3;--ok:#5cc184;--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 20px rgba(0,0,0,.25);}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:1040px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:26px;letter-spacing:-.01em;margin:0 0 6px}h2{font-size:17px;margin:36px 0 12px;display:flex;align-items:baseline;gap:6px}
.muted{color:var(--muted)}code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);padding:1px 6px;border-radius:5px;word-break:break-all}
.brand{font-weight:800;font-size:18px;color:var(--accent);margin-bottom:6px}
.logo{display:block;width:300px;max-width:100%;height:auto;margin:0 0 18px -6px}
.logo-dark{display:none}
@media (prefers-color-scheme:dark){.logo-light{display:none}.logo-dark{display:block}}
.facts{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:8px;color:var(--muted);font-size:14px}
.warn{margin:20px 0;padding:12px 16px;border:1px solid var(--critical);background:color-mix(in srgb,var(--critical) 8%,var(--panel));border-radius:10px;color:var(--critical)}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:26px}
.tile{font:inherit;color:inherit;background:color-mix(in srgb,var(--c,var(--accent)) 6%,var(--panel));border:1px solid var(--border);border-radius:12px;padding:14px 16px;text-align:left;cursor:pointer;border-top:4px solid var(--c);box-shadow:var(--shadow);transition:transform .15s,border-color .15s}
.tile:hover{transform:translateY(-1px);border-color:color-mix(in srgb,var(--c) 45%,var(--border))}
.tile .n{display:block;font-size:30px;font-weight:750;line-height:1.1;color:var(--c)}.tile .l{color:var(--muted);text-transform:capitalize;font-size:14px}
.tile.empty{opacity:.5}.tile.empty .n{color:var(--muted)}.tile[aria-pressed=true]{outline:2px solid var(--c);outline-offset:-1px}
${SEVERITY_ORDER.map((s) => `.sev-tile-${s},.sev-${s}{--c:var(--${s})}`).join('')}
ul.scanners{list-style:none;padding:0;margin:0;background:var(--panel);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow)}
ul.scanners li{padding:10px 16px;border-top:1px solid var(--border)}ul.scanners li:first-child{border-top:0}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;vertical-align:middle}.dot.ok{background:var(--ok)}.dot.off{background:var(--muted)}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.controls input,.controls select{font:inherit;color:inherit;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:8px 12px}
.controls input{flex:1;min-width:200px}.controls input:focus,.controls select:focus{outline:2px solid var(--accent);outline-offset:0}
.finding{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--c);border-radius:12px;margin-bottom:10px;box-shadow:var(--shadow);overflow:hidden}
.finding>summary{cursor:pointer;padding:14px 44px 14px 16px;display:block;list-style:none;position:relative}
.finding>summary:hover{background:var(--panel-2)}
.finding summary::-webkit-details-marker{display:none}
.finding>summary::after{content:"";position:absolute;right:18px;top:19px;width:8px;height:8px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(45deg);transition:transform .15s}
.finding[open]>summary::after{transform:rotate(-135deg);top:22px}
.finding>summary .meta{color:var(--muted);font-size:13px;word-break:break-all}
.finding.fp>summary{opacity:.7}.finding.fp>summary .pkg{text-decoration:line-through;text-decoration-color:color-mix(in srgb,var(--muted) 60%,transparent)}
.chip{display:inline-flex;align-items:center;font-size:12px;font-weight:650;line-height:1.5;border-radius:999px;padding:1px 9px;white-space:nowrap;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent);border:1px solid color-mix(in srgb,var(--c) 40%,transparent)}
.chip-none{--c:var(--ok)}
.item-t{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 10px;font-size:15px}
.item-t .pkg{font-size:17px;font-weight:700;letter-spacing:-.005em}.item-t span{color:var(--muted)}
.item-meta{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:8px;font-size:13px}.item-meta .sev,.item-meta .tri{margin:0}
.fixes{list-style:none;margin:0;padding:4px 14px;background:var(--panel-2);border:1px solid var(--border);border-radius:10px;font-size:14px;line-height:1.55}
.fixes li{display:flex;gap:10px;align-items:baseline;padding:8px 0;border-top:1px dashed var(--border)}.fixes li:first-child{border-top:0}
.fixes .fix{flex:none;margin:0}
.fixbox{margin:0 16px 14px}.fixbox-h{color:var(--muted);font-size:13px;font-weight:650;text-transform:uppercase;letter-spacing:.06em;margin:0 0 6px}
.sev{font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.06em;color:var(--c);background:color-mix(in srgb,var(--c) 12%,transparent);border:1px solid color-mix(in srgb,var(--c) 55%,transparent);border-radius:6px;padding:1px 7px}
.finding dl{display:grid;grid-template-columns:130px 1fr;gap:6px 16px;margin:0;padding:6px 16px 16px;border-top:1px solid var(--border)}
.finding dt{color:var(--muted);padding-top:8px;font-size:14px}.finding dd{margin:0;padding-top:8px;overflow-wrap:anywhere}
.finding a{color:var(--accent)}
.fix{font-size:12px;font-weight:650;border-radius:999px;padding:1px 9px;margin-right:6px;white-space:nowrap}
.fix-automatic{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
.fix-risky{background:color-mix(in srgb,var(--medium) 18%,transparent);color:var(--medium)}
.fix-breaking{background:color-mix(in srgb,var(--critical) 15%,transparent);color:var(--critical)}
.fix-manual{background:var(--code);color:var(--muted)}
.tri{display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:650;line-height:1.5;border-radius:999px;padding:1px 9px;white-space:nowrap;background:var(--code);color:var(--muted);border:1px solid transparent}
.tri-v::before{content:"";width:10px;height:10px;flex:none;background:currentColor;-webkit-mask:var(--spark) center/contain no-repeat;mask:var(--spark) center/contain no-repeat}
:root{--spark:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M12 2l2.2 6.6L21 11l-6.8 2.4L12 20l-2.2-6.6L3 11l6.8-2.4z'/%3E%3C/svg%3E")}
.tri-real{background:color-mix(in srgb,var(--high) 15%,transparent);color:var(--high);border-color:color-mix(in srgb,var(--high) 35%,transparent)}
.tri-false-positive{background:color-mix(in srgb,var(--ok) 14%,transparent);color:var(--ok);border-color:color-mix(in srgb,var(--ok) 35%,transparent)}
.tri-needs-review{background:color-mix(in srgb,var(--medium) 15%,transparent);color:var(--medium);border-color:color-mix(in srgb,var(--medium) 35%,transparent)}
.urg-now{background:var(--critical);color:#fff}
.urg-soon{background:color-mix(in srgb,var(--medium) 18%,transparent);color:var(--medium)}
.urg-low{background:var(--code);color:var(--muted)}
.prod-first{background:color-mix(in srgb,var(--critical) 14%,transparent);color:var(--critical);border-color:color-mix(in srgb,var(--critical) 35%,transparent)}
.spark{width:16px;height:16px;flex:none;fill:var(--accent)}
.take{--v:var(--accent);margin:0 16px 14px;padding:12px 16px 14px;border-radius:10px;border:1px solid color-mix(in srgb,var(--accent) 35%,var(--border));border-left:4px solid var(--v);background:linear-gradient(135deg,var(--accent-soft),color-mix(in srgb,var(--accent-soft) 40%,var(--panel)))}
.take-real{--v:var(--high)}.take-false-positive{--v:var(--ok)}.take-needs-review{--v:var(--medium)}
.take-h{display:flex;flex-wrap:wrap;align-items:center;gap:6px 8px}.take-h b{color:var(--accent);font-size:14px;margin-right:2px}
.take-note{margin-left:auto;color:var(--muted);font-size:12px}
.take p{margin:8px 0 0;font-size:15.5px;line-height:1.55}
.take ul{list-style:none;margin:6px 0 0;padding:0}.take li{padding:8px 0 0}.take li+li{border-top:1px solid color-mix(in srgb,var(--accent) 20%,transparent);margin-top:8px}
.take-pkg{display:flex;flex-wrap:wrap;align-items:center;gap:6px}.take li p{margin-top:4px}
.claude{display:flex;gap:16px;align-items:center;margin-top:12px;padding:14px;background:var(--panel);border:1px solid var(--border);border-radius:14px;box-shadow:var(--shadow)}.claude p{margin:0;color:var(--muted);font-size:14px}
.claude-ai{background:linear-gradient(135deg,var(--accent-soft),var(--panel) 70%);border-color:color-mix(in srgb,var(--accent) 35%,var(--border))}
.claude-ai p{margin-top:8px}.stats{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.prod-tile{--c:var(--critical);flex:0 0 200px}.prod-tile .l,.now-tile .l{text-transform:none}
.now-tile{--c:var(--critical);flex:0 0 200px}
.finding dd ul,.finding dd ol{margin:0;padding-left:18px}
.advs{padding:0 16px 16px}.advs-h{color:var(--muted);margin:6px 0 8px;font-size:13px;font-weight:650;text-transform:uppercase;letter-spacing:.06em}
.adv{border:1px solid var(--border);border-left:3px solid var(--c);border-radius:8px;margin-bottom:6px;background:var(--panel-2)}
.adv summary{cursor:pointer;padding:8px 12px;display:flex;flex-wrap:wrap;align-items:center;gap:4px 10px;list-style:none}
.adv summary::-webkit-details-marker{display:none}
.adv .title{flex:1;min-width:200px;font-weight:550}.adv .meta{color:var(--muted);font-size:13px}
.adv dl{display:grid;grid-template-columns:118px 1fr;gap:6px 14px;margin:0;padding:4px 12px 12px;border-top:1px solid var(--border)}
.adv dt{color:var(--muted);padding-top:6px;font-size:14px}.adv dd{margin:0;padding-top:6px;overflow-wrap:anywhere}.adv a{color:var(--accent)}.trace li{margin-bottom:4px}
.empty-state{padding:24px;text-align:center;color:var(--muted);background:var(--panel);border:1px dashed var(--border);border-radius:12px}
footer{margin-top:40px;font-size:13px;color:var(--muted)}
@media (max-width:640px){.tiles{grid-template-columns:repeat(3,1fr)}.claude{flex-direction:column;align-items:stretch}.now-tile,.prod-tile{flex:none}.finding dl{grid-template-columns:1fr}.finding dt{padding-top:10px}.finding dd{padding-top:0}.take{margin:0 12px 12px}.take-note{margin-left:0;flex-basis:100%}}
@media (prefers-reduced-motion:reduce){.tile,.finding>summary::after{transition:none}.tile:hover{transform:none}}
@media print{.adv{break-inside:avoid}.adv:not([open]) dl{display:block}.logo-light{display:block!important}.logo-dark{display:none!important}body{background:#fff;color:#000}.controls{display:none}.finding{break-inside:avoid;box-shadow:none}.finding:not([open]) dl{display:block}.finding>summary::after{display:none}}`;

export function renderHtml({ target, date, findings, tools, ignoredCount, minSeverity, offline }, triage = { entries: {} }) {
  const project = target.split(/[\\/]/).filter(Boolean).pop() ?? target;
  const when = new Date(date);
  const dateText = isNaN(when) ? String(date) : when.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]);
  const toolNames = [...new Set(findings.map((f) => f.tool))];
  const groups = reviewGroups(findings, triage);
  const noneRan = tools.every((t) => t.status !== 'ran');
  const tri = findings.map((f) => triage.entries[f.fingerprint]).filter(Boolean);
  const fixNow = tri.filter((t) => t.verdict !== 'false-positive' && t.urgency === 'now').length;
  const falsePos = tri.filter((t) => t.verdict === 'false-positive').length;
  const realN = tri.filter((t) => t.verdict === 'real').length;
  const reviewN = tri.length - realN - falsePos;
  const prodFirst = prodFirstCount(findings);
  const devOnly = findings.filter((f) => !shipsToProd(f)).length;

  const tiles = counts
    .map(([s, n]) => `<button class="tile sev-tile-${s}${n ? '' : ' empty'}" data-sev="${s}" aria-pressed="false"><span class="n">${n}</span><span class="l">${s}</span></button>`)
    .join('');
  const scanners = tools
    .map((t) => `<li><span class="dot ${t.status === 'ran' ? 'ok' : 'off'}"></span><b>${esc(t.name)}</b> ${t.status === 'ran' ? `ran, ${t.count} finding(s)${t.note ? ` <span class="muted">(${esc(t.note)})</span>` : ''}` : `${esc(t.status)}${t.message ? ` <span class="muted">(${esc(t.message)})</span>` : ''}`}</li>`)
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Gnawky report: ${esc(project)}</title>
${FAVICON}
<style>
${REPORT_CSS}
</style>
</head>
<body>
<main>
${BRAND}
<h1>Security report: ${esc(project)}</h1>
<div class="facts"><span><code>${esc(target)}</code></span><span>${esc(dateText)}</span><span>Minimum severity: ${esc(minSeverity ?? 'n/a')}</span>${offline ? '<span>Offline mode</span>' : ''}<span>Ignored via .gnawky-ignore.json: ${ignoredCount ?? 0}</span></div>
${noneRan ? '<div class="warn"><b>Warning:</b> no scanner ran successfully, so an empty result does not mean the project is safe.</div>' : ''}
<div class="tiles">${tiles}</div>
${prodFirst || devOnly ? `<div class="claude"><button class="tile prod-tile" id="prodfirst" aria-pressed="false"><span class="n">${prodFirst}</span><span class="l">Fix for production first</span></button>
<p>Critical and high findings that ship to production${tri.length ? '. The list follows Claude\'s order (fix now first, likely false positives last); the Sort menu switches to production first' : ', listed first'}. ${devOnly ? `${devOnly} finding(s) come only from devDependencies (build, test and lint tools) and are listed last.` : ''} Worked out from package.json${findings.some((f) => /Next\.js/.test(f.scopeNote ?? '')) ? '; in Next.js, devDependencies that aren\'t test or lint tools count as production, since they can be bundled' : ''}.</p></div>` : ''}
${tri.length ? `<div class="claude claude-ai"><button class="tile now-tile" id="fixnow" aria-pressed="false"><span class="n">${fixNow}</span><span class="l">Fix now, says Claude</span></button>
<div><div class="take-h">${SPARK}<b>Claude reviewed ${tri.length} of ${findings.length} findings against your code</b></div>
<div class="stats"><span class="tri urg-now">${fixNow} fix now</span><span class="tri tri-real">${realN} real</span><span class="tri tri-needs-review">${reviewN} need a human</span><span class="tri tri-false-positive">${falsePos} likely false positive</span></div>
<p>These are suggestions, not facts: check the reason on each finding before you rely on it. Click the number to show only what Claude says to fix now.</p></div></div>` : ''}

<h2>Scanners</h2>
<ul class="scanners">${scanners}</ul>

<h2>Findings <span class="muted" id="shown">(${groups.length})</span></h2>
${groups.length < findings.length ? `<p class="muted">${findings.length} findings in ${groups.length} items: advisories whose fix changes the same package are grouped, and each item says how many its upgrade really fixes.</p>` : ''}
${findings.length ? `<div class="controls">
<input id="q" type="search" placeholder="Search title, package, file, rule, CWE…" aria-label="Search findings">
${findings.some((f) => f.scope) ? `<select id="scope" aria-label="Filter by production"><option value="">All (${findings.length})</option><option value="prod"${findings.length - devOnly ? '' : ' disabled'}>Production only (${findings.length - devOnly})</option><option value="dev"${devOnly ? '' : ' disabled'}>Dev only (${devOnly})</option></select>\n` : ''}<select id="tool" aria-label="Filter by tool"><option value="">All tools</option>${toolNames.map((t) => `<option>${esc(t)}</option>`).join('')}</select>
${tri.length ? `<select id="verdict" aria-label="Filter by Claude's verdict"><option value="">Any verdict</option>${Object.entries(VERDICTS).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join('')}<option value="none">not triaged</option></select>
<select id="order" aria-label="Sort"><option value="claude">Sort: Claude's order</option><option value="sev">Sort: production first, then severity</option></select>` : ''}
<select id="toggle" aria-label="Expand or collapse"><option value="">Expand…</option><option value="open">Expand all</option><option value="close">Collapse all</option></select>
</div>
<div id="list">${groups.map((g, i) => (isGroup(g) ? groupCard(g, i, triage) : findingCard(g.lead, i, triage))).join('\n')}</div>
<div class="empty-state" id="nomatch" hidden>No findings match the filters.</div>` : '<div class="empty-state">No findings at or above the selected severity.</div>'}

<footer>Generated by Gnawky. This report lists your project's weak spots: keep it private. Secrets are redacted and code snippets are never included.</footer>
</main>
<script>
(function(){
  var cards=[].slice.call(document.querySelectorAll('.finding'));
  function has(list,v){return (' '+list+' ').indexOf(' '+v+' ')!==-1;}
  function anySev(c){var r=false;sevs.forEach(function(s){if(has(c.dataset.sevs,s))r=true;});return r;}if(!cards.length)return;
  var q=document.getElementById('q'),tool=document.getElementById('tool'),verdict=document.getElementById('verdict'),order=document.getElementById('order'),now=document.getElementById('fixnow'),pf=document.getElementById('prodfirst'),scope=document.getElementById('scope'),list=document.getElementById('list'),sevs=new Set(),onlyNow=false,onlyPf=false;
  function apply(){
    var text=q.value.trim().toLowerCase(),t=tool.value,v=verdict?verdict.value:'',n=0;
    cards.forEach(function(c){
      var sc=scope?scope.value:'';
      var show=(!onlyPf||c.dataset.tier==='0')&&(!sc||(sc==='dev'?c.dataset.tier==='2':c.dataset.tier!=='2'))&&(!sevs.size||anySev(c))&&(!t||has(c.dataset.tools,t))&&(!v||c.dataset.verdict===v)&&(!onlyNow||(c.dataset.urgency==='now'&&c.dataset.verdict!=='false-positive'))&&(!text||c.dataset.search.indexOf(text)!==-1);
      c.hidden=!show;if(show)n++;
    });
    document.getElementById('shown').textContent='('+n+(n===cards.length?'':' of '+cards.length)+')';
    document.getElementById('nomatch').hidden=n>0;
  }
  [].forEach.call(document.querySelectorAll('.tile[data-sev]'),function(b){b.addEventListener('click',function(){
    var s=b.dataset.sev;if(sevs.has(s))sevs.delete(s);else sevs.add(s);b.setAttribute('aria-pressed',sevs.has(s));apply();
  });});
  q.addEventListener('input',apply);tool.addEventListener('change',apply);
  if(verdict)verdict.addEventListener('change',apply);
  if(now)now.addEventListener('click',function(){onlyNow=!onlyNow;now.setAttribute('aria-pressed',onlyNow);apply();});
  if(pf)pf.addEventListener('click',function(){onlyPf=!onlyPf;pf.setAttribute('aria-pressed',onlyPf);apply();});
  if(scope)scope.addEventListener('change',apply);
  var rankS={critical:0,high:1,medium:2,low:3,info:4};
  // The page comes in Claude's order (fix now, soon, low, not triaged, likely false positives last).
  if(order)order.addEventListener('change',function(){
    cards.slice().sort(function(a,b){return order.value==='claude'?(+a.dataset.i)-(+b.dataset.i):(+a.dataset.tier)-(+b.dataset.tier)||(rankS[a.dataset.sev]-rankS[b.dataset.sev])||(+a.dataset.i)-(+b.dataset.i);})
      .forEach(function(c){list.appendChild(c);});
  });
  cards.forEach(function(c,i){c.dataset.i=i;});
  document.getElementById('toggle').addEventListener('change',function(e){
    var open=e.target.value==='open';if(e.target.value)cards.forEach(function(c){if(!c.hidden)c.open=open;});e.target.value='';
  });
})();
</script>
</body>
</html>
`;
}
