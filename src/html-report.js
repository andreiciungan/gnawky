import { SEVERITY_ORDER } from './finding.js';

// Self-contained HTML report: no external CSS, JS, fonts or images, so it opens
// offline and viewing it never sends anything anywhere. Every value comes from
// scanner output (package names, advisory text, file paths), so all of it is escaped.

const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);

// Only plain web links become clickable; anything else (javascript:, data:) is shown as text.
const safeUrl = (u) => (typeof u === 'string' && /^https?:\/\//i.test(u) ? u : null);

const FIX_LABELS = {
  'npm-audit-fix': ['automatic', 'npm audit fix'],
  'npm-upgrade': ['automatic', 'upgrade'],
  'npm-major-upgrade': ['breaking', 'major upgrade'],
  'yarn-upgrade': ['automatic', 'upgrade'],
  'yarn-major-upgrade': ['breaking', 'major upgrade'],
  'yarn-refresh': ['automatic', 'lockfile refresh'],
  'yarn-resolution': ['risky', 'resolution override'],
  'yarn-major-resolution': ['breaking', 'major resolution override'],
  'suggested-edit': ['manual', 'suggested edit'],
  manual: ['manual', 'manual'],
};

function fixBadge(type) {
  const [kind, label] = FIX_LABELS[type] ?? ['manual', type ?? 'manual'];
  return `<span class="fix fix-${kind}">${esc(label)}</span>`;
}

function findingCard(f, i) {
  const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : null;
  const url = safeUrl(f.url);
  const search = [f.title, f.tool, f.ruleId, f.file, f.package, f.description, f.fix?.detail, ...(f.cwe ?? [])].join(' ').toLowerCase();
  const rows = [
    ['Tool / rule', `${esc(f.tool)} / <code>${esc(f.ruleId)}</code>`],
    f.package && ['Package', `<code>${esc(f.package)}</code>`],
    ['Location', loc ? `<code>${esc(loc)}</code>` : 'n/a'],
    f.cwe?.length && ['CWE', f.cwe.map(esc).join(', ')],
    f.description && ['Details', esc(f.description)],
    ['Suggested fix', `${fixBadge(f.fix?.type)} ${esc(f.fix?.detail)}`],
    ['Reference', url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a>` : f.url ? esc(f.url) : null],
    ['ID', `<code>${esc(f.fingerprint)}</code>`],
  ].filter((r) => r && r[1]);
  return `<details class="finding" data-sev="${esc(f.severity)}" data-tool="${esc(f.tool)}" data-search="${esc(search)}"${i < 3 ? ' open' : ''}>
<summary><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span><span class="title">${esc(f.title)}</span><span class="meta">${esc(f.tool)}${loc ? ` · ${esc(loc)}` : ''}</span></summary>
<dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>
</details>`;
}

export function renderHtml({ target, date, findings, tools, ignoredCount, minSeverity, offline }) {
  const project = target.split(/[\\/]/).filter(Boolean).pop() ?? target;
  const when = new Date(date);
  const dateText = isNaN(when) ? String(date) : when.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]);
  const toolNames = [...new Set(findings.map((f) => f.tool))];
  const noneRan = tools.every((t) => t.status !== 'ran');

  const tiles = counts
    .map(([s, n]) => `<button class="tile sev-tile-${s}${n ? '' : ' empty'}" data-sev="${s}" aria-pressed="false"><span class="n">${n}</span><span class="l">${s}</span></button>`)
    .join('');
  const scanners = tools
    .map((t) => `<li><span class="dot ${t.status === 'ran' ? 'ok' : 'off'}"></span><b>${esc(t.name)}</b> ${t.status === 'ran' ? `ran, ${t.count} finding(s)` : `${esc(t.status)}${t.message ? ` <span class="muted">(${esc(t.message)})</span>` : ''}`}</li>`)
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Gnawky report: ${esc(project)}</title>
<style>
:root{--bg:#f7f7f5;--panel:#fff;--text:#1d1d1b;--muted:#6b6b66;--border:#e3e2dd;--code:#f0efea;--accent:#2f6f4f;
--critical:#b3261e;--high:#d0541b;--medium:#b58100;--low:#2d6fb3;--info:#6b6b66;--ok:#2f8f4f;}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--panel:#1f1f1c;--text:#ecebe6;--muted:#9a9990;--border:#34332f;--code:#2a2a26;--accent:#6fbf8f;
--critical:#f2665c;--high:#f08a4b;--medium:#e0b23a;--low:#6aa8e8;--info:#9a9990;--ok:#5cc184;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 12px}
.muted{color:var(--muted)}code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
.brand{font-weight:700;color:var(--accent);letter-spacing:.02em}
.facts{display:flex;flex-wrap:wrap;gap:4px 20px;margin-top:8px;color:var(--muted);font-size:14px}
.warn{margin:20px 0;padding:12px 14px;border:1px solid var(--critical);border-radius:8px;color:var(--critical)}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-top:24px}
.tile{font:inherit;color:inherit;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px;text-align:left;cursor:pointer;border-top:4px solid var(--c)}
.tile .n{display:block;font-size:26px;font-weight:700}.tile .l{color:var(--muted);text-transform:capitalize}
.tile.empty{opacity:.5}.tile[aria-pressed=true]{outline:2px solid var(--c);outline-offset:-1px}
${SEVERITY_ORDER.map((s) => `.sev-tile-${s},.sev-${s}{--c:var(--${s})}`).join('')}
ul.scanners{list-style:none;padding:0;margin:0;background:var(--panel);border:1px solid var(--border);border-radius:10px}
ul.scanners li{padding:8px 14px;border-top:1px solid var(--border)}ul.scanners li:first-child{border-top:0}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;vertical-align:middle}.dot.ok{background:var(--ok)}.dot.off{background:var(--muted)}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.controls input,.controls select{font:inherit;color:inherit;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:7px 10px}
.controls input{flex:1;min-width:180px}
.finding{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--c);border-radius:8px;margin-bottom:8px}
.finding summary{cursor:pointer;padding:10px 14px;display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 10px;list-style:none}
.finding summary::-webkit-details-marker{display:none}
.finding .title{font-weight:600;flex:1;min-width:200px}.finding .meta{color:var(--muted);font-size:13px;word-break:break-all}
.sev{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--c);border:1px solid var(--c);border-radius:4px;padding:0 5px}
.finding dl{display:grid;grid-template-columns:130px 1fr;gap:6px 14px;margin:0;padding:4px 14px 14px;border-top:1px solid var(--border)}
.finding dt{color:var(--muted);padding-top:8px}.finding dd{margin:0;padding-top:8px;overflow-wrap:anywhere}
.finding a{color:var(--accent)}
.fix{font-size:12px;font-weight:600;border-radius:4px;padding:1px 6px;margin-right:4px;white-space:nowrap}
.fix-automatic{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
.fix-risky{background:color-mix(in srgb,var(--medium) 20%,transparent);color:var(--medium)}
.fix-breaking{background:color-mix(in srgb,var(--critical) 18%,transparent);color:var(--critical)}
.fix-manual{background:var(--code);color:var(--muted)}
.empty-state{padding:24px;text-align:center;color:var(--muted);background:var(--panel);border:1px dashed var(--border);border-radius:10px}
footer{margin-top:40px;font-size:13px;color:var(--muted)}
@media (max-width:640px){.tiles{grid-template-columns:repeat(3,1fr)}.finding dl{grid-template-columns:1fr}.finding dt{padding-top:10px}.finding dd{padding-top:0}}
@media print{body{background:#fff;color:#000}.controls{display:none}.finding{break-inside:avoid}.finding:not([open]) dl{display:block}}
</style>
</head>
<body>
<main>
<div class="brand">gnawky</div>
<h1>Security report: ${esc(project)}</h1>
<div class="facts"><span><code>${esc(target)}</code></span><span>${esc(dateText)}</span><span>Minimum severity: ${esc(minSeverity ?? 'n/a')}</span>${offline ? '<span>Offline mode</span>' : ''}<span>Ignored via .gnawky-ignore.json: ${ignoredCount ?? 0}</span></div>
${noneRan ? '<div class="warn"><b>Warning:</b> no scanner ran successfully, so an empty result does not mean the project is safe.</div>' : ''}
<div class="tiles">${tiles}</div>

<h2>Scanners</h2>
<ul class="scanners">${scanners}</ul>

<h2>Findings <span class="muted" id="shown">(${findings.length})</span></h2>
${findings.length ? `<div class="controls">
<input id="q" type="search" placeholder="Search title, package, file, rule, CWE…" aria-label="Search findings">
<select id="tool" aria-label="Filter by tool"><option value="">All tools</option>${toolNames.map((t) => `<option>${esc(t)}</option>`).join('')}</select>
<select id="toggle" aria-label="Expand or collapse"><option value="">Expand…</option><option value="open">Expand all</option><option value="close">Collapse all</option></select>
</div>
<div id="list">${findings.map(findingCard).join('\n')}</div>
<div class="empty-state" id="nomatch" hidden>No findings match the filters.</div>` : '<div class="empty-state">No findings at or above the selected severity.</div>'}

<footer>Generated by Gnawky. This report lists your project's weak spots: keep it private. Secrets are redacted and code snippets are never included.</footer>
</main>
<script>
(function(){
  var cards=[].slice.call(document.querySelectorAll('.finding'));if(!cards.length)return;
  var q=document.getElementById('q'),tool=document.getElementById('tool'),sevs=new Set();
  function apply(){
    var text=q.value.trim().toLowerCase(),t=tool.value,n=0;
    cards.forEach(function(c){
      var show=(!sevs.size||sevs.has(c.dataset.sev))&&(!t||c.dataset.tool===t)&&(!text||c.dataset.search.indexOf(text)!==-1);
      c.hidden=!show;if(show)n++;
    });
    document.getElementById('shown').textContent='('+n+(n===cards.length?'':' of '+cards.length)+')';
    document.getElementById('nomatch').hidden=n>0;
  }
  [].forEach.call(document.querySelectorAll('.tile'),function(b){b.addEventListener('click',function(){
    var s=b.dataset.sev;if(sevs.has(s))sevs.delete(s);else sevs.add(s);b.setAttribute('aria-pressed',sevs.has(s));apply();
  });});
  q.addEventListener('input',apply);tool.addEventListener('change',apply);
  document.getElementById('toggle').addEventListener('change',function(e){
    var open=e.target.value==='open';if(e.target.value)cards.forEach(function(c){if(!c.hidden)c.open=open;});e.target.value='';
  });
})();
</script>
</body>
</html>
`;
}
