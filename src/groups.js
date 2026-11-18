import { rank, SEVERITY_ORDER } from './finding.js';
import { isDependencyFinding } from './pm.js';
import { isAutoFixable } from './fix.js';

/**
 * Groups findings for display: dependency advisories fixed by changing the same package
 * become one group (the package the fix upgrades, e.g. next for a postcss advisory that
 * upgrading next fixes; otherwise the vulnerable package itself). Everything else stays a
 * group of one.
 * Keeps the order of `findings`: a group sits where its first finding was, so callers
 * sort first (by severity, or in Claude's order) and the most important advisory leads.
 *
 * Group: { key, package, findings, lead, severity }
 */
export function groupFindings(findings) {
  const groups = [];
  const byPkg = new Map();
  for (const f of findings) {
    if (isDependencyFinding(f) && f.package) {
      const pkg = f.fix?.package ?? f.package;
      const key = `pkg:${pkg}`;
      let g = byPkg.get(key);
      if (!g) {
        g = { key, package: pkg, findings: [] };
        byPkg.set(key, g);
        groups.push(g);
      }
      g.findings.push(f);
    } else {
      groups.push({ key: f.fingerprint, package: null, findings: [f] });
    }
  }
  for (const g of groups) {
    g.findings.sort((a, b) => rank(a.severity) - rank(b.severity));
    g.lead = g.findings[0];
    g.severity = g.lead.severity;
  }
  return groups;
}

export const isGroup = (g) => g.findings.length > 1;

/** Other vulnerable packages a group's fix covers, e.g. "postcss (4)" in the next group, or ''. */
export function alsoFixes(g) {
  const counts = new Map();
  for (const f of g.findings) if (f.package !== g.package) counts.set(f.package, (counts.get(f.package) ?? 0) + 1);
  return [...counts].map(([p, n]) => `${p} (${n})`).join(', ');
}

/** "3 high, 9 medium" for the findings of a group. */
export function severityCounts(findings) {
  return SEVERITY_ORDER
    .map((s) => [s, findings.filter((f) => f.severity === s).length])
    .filter(([, n]) => n)
    .map(([s, n]) => `${n} ${s}`)
    .join(', ');
}

/**
 * The fixes of a group, each with the findings it covers: auto-fixable ones first,
 * then manual ones. Most groups have a single fix.
 */
export function groupFixes(g) {
  const fixes = new Map();
  for (const f of g.findings) {
    const key = `${f.fix?.type}|${f.fix?.detail}`;
    if (!fixes.has(key)) fixes.set(key, { fix: f.fix, auto: isAutoFixable(f), findings: [] });
    fixes.get(key).findings.push(f);
  }
  return [...fixes.values()].sort((a, b) => b.auto - a.auto);
}

/** Title for a group: the finding's own title, or "<package>: N advisories". */
export function groupTitle(g) {
  return isGroup(g) ? `${g.package}: ${g.findings.length} advisories` : g.lead.title;
}

/** The advisory title without the "package: " prefix the scanners add. */
export function advisoryTitle(f) {
  return f.package && f.title.startsWith(`${f.package}: `) ? f.title.slice(f.package.length + 2) : f.title;
}

/** The advisory's GHSA and CVE IDs, for listing them next to the title. */
export const idsOf = (f) => [f.ghsa, ...(f.cves ?? [])].filter(Boolean);

const URGENCY_RANK = { now: 0, soon: 1, low: 2 };
const triageKey = (t) => (t.verdict === 'false-positive' ? 3 : URGENCY_RANK[t.urgency] ?? 2);
const mostUrgent = (findings, triage) => findings
  .map((f) => triage.entries[f.fingerprint])
  .filter(Boolean)
  .sort((a, b) => triageKey(a) - triageKey(b))[0] ?? null;

/** The most urgent triage entry among a group's findings (false positives count last). */
export const groupTriage = (g, triage) => mostUrgent(g.findings, triage);

/**
 * Claude's take per vulnerable package in a group ({ package, t }), the group's own package
 * first. Triage runs per vulnerable package, so a group that also covers other packages
 * (postcss in the next group) can have a different verdict for each.
 */
export function triageByPackage(g, triage) {
  const pkgs = [...new Set(g.findings.map((f) => f.package))]
    .sort((a, b) => (b === g.package) - (a === g.package));
  return pkgs
    .map((p) => ({ package: p, t: mostUrgent(g.findings.filter((f) => f.package === p), triage) }))
    .filter((x) => x.t);
}
