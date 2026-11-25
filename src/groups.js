import { rank, SEVERITY_ORDER } from './finding.js';
import { isDependencyFinding, NEXT_REACT_TOOL } from './pm.js';
import { isAutoFixable } from './fix.js';
import { highestNeeds, needsText } from './coverage.js';

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

/**
 * Other vulnerable packages whose fix is this group's upgrade, e.g. "postcss (4)" in the next
 * group, or ''. That is npm's expectation; whether the new next brings a fixed postcss can't be
 * checked without the registry, and the audit after the fix shows it.
 */
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
const BUNDLED_DATE = /release from after (\d{4}-\d{2}-\d{2})/;

export function groupFixes(g) {
  const fixes = new Map();
  for (const f of g.findings) {
    // Advisories the same upgrade leaves open share one line, with the highest version they need.
    // The React that Next.js bundles: one line for all of them (a release after the latest date covers the rest).
    const bundled = f.tool === NEXT_REACT_TOOL && f.fix?.type === 'manual';
    const key = bundled ? 'bundled-react' : f.fix?.stillVulnerable ? `still|${f.fix.package}|${f.fix.after}` : `${f.fix?.type}|${f.fix?.detail}`;
    if (!fixes.has(key)) fixes.set(key, { fix: f.fix, auto: isAutoFixable(f), findings: [] });
    fixes.get(key).findings.push(f);
  }
  const react = fixes.get('bundled-react');
  if (react?.findings.length > 1) {
    const dates = react.findings.map((f) => f.fix.disclosed ?? BUNDLED_DATE.exec(f.fix.detail ?? '')?.[1]).filter(Boolean).sort();
    if (dates.length) {
      react.fix = {
        ...react.fix,
        disclosed: dates.at(-1),
        detail: `Upgrade next to a release from after ${dates.at(-1)} that includes the fixes for these ${react.findings.length} advisories in the React it bundles `
          + '(see the Next.js releases or the Next.js advisories). Upgrading react or react-dom alone does not help: '
          + 'the App Router uses the copy bundled in next.',
      };
    }
  }
  for (const x of fixes.values()) {
    if (!x.fix?.stillVulnerable || x.findings.length < 2) continue;
    const { package: pkg, after, upgrade } = x.fix;
    const needs = highestNeeds(x.findings.map((f) => f.fix.needs));
    const verb = /override|resolution/.test(upgrade) ? 'Forcing' : 'Upgrading';
    x.fix = {
      ...x.fix,
      needs,
      detail: `${verb} ${pkg} to ${after} doesn't fix these ${x.findings.length}. Fixing all of them needs ${needsText(pkg, needs)}.`,
    };
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
