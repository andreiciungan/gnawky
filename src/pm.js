import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export const PKG_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
export const PKG_VERSION = /^[0-9A-Za-z.+-]+$/;

export const LOCKFILES = { npm: 'package-lock.json', yarn: 'yarn.lock' };

/**
 * Which package manager the project's lockfile belongs to:
 * 'npm', 'yarn' (Yarn 1 / Classic), 'yarn-berry' (Yarn 2+), 'pnpm', or null (no lockfile).
 */
export function packageManager(dir) {
  return detectPackageManager(dir).pm;
}

const yarnKind = (dir) => {
  let head = '';
  try { head = fs.readFileSync(path.join(dir, 'yarn.lock'), 'utf8').slice(0, 300); } catch { /* unreadable */ }
  return /yarn lockfile v1/.test(head) ? 'yarn' : 'yarn-berry';
};

const gitSays = (dir, args) => spawnSync('git', args, { cwd: dir, encoding: 'utf8' }).status === 0;

/**
 * { pm, why }: why is set when several lockfiles exist and one had to be picked, e.g.
 * "package-lock.json is ignored by git". A stale lockfile next to the real one (often a
 * git-ignored package-lock.json in a yarn project) must not make Gnawky run npm.
 * Order: package.json "packageManager", then the lockfile git tracks, then the one git doesn't
 * ignore, then the newest.
 */
export function detectPackageManager(dir) {
  const exists = (f) => fs.existsSync(path.join(dir, f));
  const npmLock = ['package-lock.json', 'npm-shrinkwrap.json'].find(exists);
  const found = [
    ...(npmLock ? [{ pm: 'npm', file: npmLock }] : []),
    ...(exists('yarn.lock') ? [{ pm: yarnKind(dir), file: 'yarn.lock' }] : []),
    ...(exists('pnpm-lock.yaml') ? [{ pm: 'pnpm', file: 'pnpm-lock.yaml' }] : []),
  ];
  if (found.length <= 1) return { pm: found[0]?.pm ?? null, why: null, others: [] };
  const others = (pick) => found.filter((x) => x !== pick).map((x) => x.file);

  let declared = '';
  try { declared = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).packageManager ?? ''; } catch { /* none */ }
  const byField = found.find((x) => declared.startsWith(x.pm === 'yarn-berry' ? 'yarn' : x.pm));
  if (byField) return { pm: byField.pm, why: `package.json says "packageManager": "${declared}"`, others: others(byField) };

  const tracked = found.filter((x) => gitSays(dir, ['ls-files', '--error-unmatch', '--', x.file]));
  if (tracked.length === 1) return { pm: tracked[0].pm, why: `only ${tracked[0].file} is committed to git`, others: others(tracked[0]) };

  const ignored = found.filter((x) => gitSays(dir, ['check-ignore', '-q', '--', x.file]));
  const kept = found.filter((x) => !ignored.includes(x));
  if (kept.length === 1) return { pm: kept[0].pm, why: `${ignored.map((x) => x.file).join(', ')} ${ignored.length === 1 ? 'is' : 'are'} ignored by git`, others: others(kept[0]) };

  const mtime = (f) => { try { return fs.statSync(path.join(dir, f)).mtimeMs; } catch { return 0; } };
  const newest = [...found].sort((a, b) => mtime(b.file) - mtime(a.file))[0];
  return { pm: newest.pm, why: `${newest.file} is the most recently changed lockfile`, others: others(newest) };
}

/** The lockfile Gnawky works with, for messages like "git add package.json yarn.lock". */
export const lockfileName = (pm) => LOCKFILES[pm] ?? 'package-lock.json';

/** How a package.json script is run, for display: "npm run test" or "yarn run test". */
export const runLabel = (pm, name) => `${pm === 'yarn' ? 'yarn' : 'npm'} run ${name}`;

/** Name of the dependency audit scanner for this package manager. */
export const auditName = (pm) => (pm === 'yarn' ? 'yarn audit' : 'npm audit');

export const DEP_AUDIT_TOOLS = ['npm-audit', 'yarn-audit'];
export const isDepAudit = (f) => DEP_AUDIT_TOOLS.includes(f.tool);

/** The audit tool that matches a package manager: 'yarn-audit' for yarn, else 'npm-audit'. */
export const auditToolFor = (pm) => (pm === 'yarn' ? 'yarn-audit' : 'npm-audit');

/**
 * Dependency findings from the other package manager's audit (e.g. npm audit results in a project
 * that Gnawky now runs with yarn): their fixes don't fit, so the project needs a new scan.
 */
export const foreignAuditFindings = (findings, pm) => (findings ?? []).filter((f) => isDepAudit(f) && f.tool !== auditToolFor(pm));

/** The check for React advisories in the copy of React that Next.js bundles (src/nextjs.js). */
export const NEXT_REACT_TOOL = 'next-bundled-react';
/** Any finding about a dependency, including ones npm/yarn audit can't fix or re-check. */
export const isDependencyFinding = (f) => isDepAudit(f) || f.tool === NEXT_REACT_TOOL;
