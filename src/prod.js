// Does a finding ship to production? Worked out without Claude, from package.json: a vulnerable
// package matters in production when one of the project's `dependencies` brings it in, and much
// less when only `devDependencies` do (build tools, tests, linters).
//
// Next.js (and other bundled apps) can import runtime code from devDependencies and ship it in
// the bundle, so in a Next.js project a devDependency counts as production unless it is plainly
// tooling (test runners, linters, type packages…).
//
// Claude triage goes further (is the vulnerable code actually used?); this is the cheap first cut.

import fs from 'node:fs';
import path from 'node:path';
import { rank } from './finding.js';
import { isDependencyFinding, NEXT_REACT_TOOL } from './pm.js';
import { usesNext } from './nextjs.js';

/**
 * f.scope:
 *   'prod'    a production dependency brings it in (or code / secrets: they're in the project itself)
 *   'dev'     only devDependencies bring it in
 *   'unknown' the path to it couldn't be worked out; treated as production
 * f.scopeNote: why, e.g. "via jest, eslint" or "Next.js bundles devDependencies (via swr)".
 */
export const SCOPE_LABELS = { prod: 'ships to production', dev: 'dev only', unknown: 'not sure, treated as production' };

// Test runners, linters, type packages…: they never end up in an app bundle or run in production.
const TOOLING = /^(@types\/|typescript$|ts-node$|tsx$|eslint|@eslint\/|@typescript-eslint\/|prettier|stylelint|jest|@jest\/|ts-jest$|babel-jest$|vitest$|@vitest\/|mocha$|chai$|sinon$|nyc$|c8$|@testing-library\/|happy-dom$|cypress|@cypress\/|playwright$|@playwright\/|storybook$|@storybook\/|husky$|lint-staged$|@commitlint\/|commitizen$|nodemon$|msw$|nock$|supertest$|@swc\/jest$|webpack-bundle-analyzer$|@next\/bundle-analyzer$|@next\/eslint|eslint-config-next$)/;

export const isTooling = (name) => TOOLING.test(name);

const readPkg = (dir) => {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch { return {}; }
};

/** Sets scope / scopeNote on the project's dependency findings (in place) and returns them. */
export function classifyScope(dir, findings) {
  const pkg = readPkg(dir);
  const prod = new Set(['dependencies', 'optionalDependencies', 'peerDependencies'].flatMap((k) => Object.keys(pkg[k] ?? {})));
  const dev = new Set(Object.keys(pkg.devDependencies ?? {}));
  const bundlesDev = usesNext(dir);
  for (const f of findings) {
    if (!isDependencyFinding(f)) continue;
    if (f.tool === NEXT_REACT_TOOL) { f.scope = 'prod'; continue; }
    const via = f.via ?? [];
    // A test runner or linter doesn't run in production, even when it's listed under dependencies.
    if (f.package && isTooling(f.package)) {
      f.scope = 'dev';
      f.scopeNote = prod.has(f.package)
        ? `${f.package} is a test/lint tool; it's listed under dependencies, move it to devDependencies`
        : `${f.package} is a test/lint tool`;
      continue;
    }
    const list = (names) => names.slice(0, 3).join(', ') + (names.length > 3 ? ', …' : '');
    const prodVia = via.filter((v) => prod.has(v));
    if (prodVia.length) {
      f.scope = 'prod';
      f.scopeNote = `via ${list(prodVia)}`;
    } else if (via.length && via.every((v) => dev.has(v))) {
      const bundled = bundlesDev ? via.filter((v) => !isTooling(v)) : [];
      if (bundled.length) {
        f.scope = 'prod';
        f.scopeNote = `via ${list(bundled)}, a devDependency that Next.js can bundle`;
      } else {
        f.scope = 'dev';
        f.scopeNote = `via ${list(via)}`;
      }
    } else {
      f.scope = 'unknown';
      f.scopeNote = via.length ? `via ${list(via)}` : 'no dependency path found in the lockfile';
    }
  }
  return findings;
}

/** Everything but dev-only dependencies: code, secrets and unknown paths count as production. */
export const shipsToProd = (f) => f.scope !== 'dev';

/** Critical or high, and it ships: fix these first. */
export const isProdFirst = (f) => shipsToProd(f) && rank(f.severity) <= rank('high');

/** 0: fix for prod first, 1: other production findings, 2: dev only. */
export const priorityTier = (f) => (isProdFirst(f) ? 0 : shipsToProd(f) ? 1 : 2);

/** "ships to production (via next)" for one finding. */
export function scopeText(f) {
  if (!f.scope) return null;
  return `${SCOPE_LABELS[f.scope]}${f.scopeNote ? ` (${f.scopeNote})` : ''}`;
}

/** For a group of advisories: "ships to production (via axios)", or a split like "9 ship to production, 3 dev only". */
export function groupScopeText(findings) {
  const deps = findings.filter((f) => f.scope);
  if (!deps.length) return null;
  const prodN = deps.filter(shipsToProd).length;
  if (prodN === deps.length || prodN === 0) return scopeText(deps.find(shipsToProd) ?? deps[0]);
  return `${prodN} ship to production, ${deps.length - prodN} dev only`;
}

export const prodFirstCount = (findings) => findings.filter(isProdFirst).length;
