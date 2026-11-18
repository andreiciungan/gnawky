// npm audit names one "fix" version per package (fixAvailable), and every advisory of that
// package gets it, even the ones it doesn't fix: for next@14.0.0 it suggests 14.2.35, which
// fixes 13 of its 40 advisories, while the rest need 15.5.x. Here each advisory's vulnerable
// range is checked against the version its fix installs, and the ones still vulnerable at
// that version get a manual fix that says what they actually need.

import { satisfies, firstOutside, compare } from './semver.js';

// Fix types that install one known version of the vulnerable package itself.
const VERSIONED = new Set([
  'npm-upgrade', 'npm-major-upgrade', 'yarn-upgrade', 'yarn-major-upgrade',
  'npm-override', 'npm-major-override', 'yarn-resolution', 'yarn-major-resolution',
]);

const verb = (type) => (/override|resolution/.test(type) ? 'Forcing' : 'Upgrading');

/** What an advisory still vulnerable at `after` needs, as text: "next 15.5.21 or later". */
export function needsText(pkg, needs) {
  if (!needs) return `a fixed release of ${pkg} (none is known for this advisory)`;
  return needs.version ? `${pkg} ${needs.version} or later` : `a release of ${pkg} after ${needs.after}`;
}

/**
 * Replaces the fix of every advisory that its fix's version would leave vulnerable with a
 * manual fix: { type: 'manual', stillVulnerable: true, package, after, needs, upgrade, detail }.
 * Only checks fixes that install the advisory's own package (the version of a package
 * installed by another one can't be known without the registry). Returns the findings.
 */
export function markUnfixed(findings) {
  for (const f of findings) {
    const fix = f.fix;
    if (!fix || !VERSIONED.has(fix.type) || fix.package !== f.package || !fix.version || !f.vulnerable) continue;
    if (!satisfies(fix.version, f.vulnerable)) continue;
    const needs = firstOutside(fix.version, f.vulnerable);
    f.fix = {
      type: 'manual',
      stillVulnerable: true,
      package: f.package,
      after: fix.version,
      needs,
      upgrade: fix.type,
      detail: `${verb(fix.type)} ${f.package} to ${fix.version} doesn't fix this one (vulnerable: ${f.vulnerable}). It needs ${needsText(f.package, needs)}.`,
    };
  }
  return findings;
}

/** The highest of several `needs` (null, meaning no known fix, wins). */
export function highestNeeds(list) {
  if (list.some((n) => !n)) return null;
  return list.reduce((best, n) => {
    const v = n.version ?? n.after;
    const b = best.version ?? best.after;
    const c = compare(v, b);
    // At the same version, "after X" asks for more than "X or later".
    return c > 0 || (c === 0 && n.after) ? n : best;
  });
}
