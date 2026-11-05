import fs from 'node:fs';
import path from 'node:path';

export const PKG_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
export const PKG_VERSION = /^[0-9A-Za-z.+-]+$/;

export const LOCKFILES = { npm: 'package-lock.json', yarn: 'yarn.lock' };

/**
 * Which package manager the project's lockfile belongs to:
 * 'npm', 'yarn' (Yarn 1 / Classic), 'yarn-berry' (Yarn 2+), 'pnpm', or null (no lockfile).
 */
export function packageManager(dir) {
  const exists = (f) => fs.existsSync(path.join(dir, f));
  if (exists('package-lock.json') || exists('npm-shrinkwrap.json')) return 'npm';
  if (exists('yarn.lock')) {
    let head = '';
    try { head = fs.readFileSync(path.join(dir, 'yarn.lock'), 'utf8').slice(0, 300); } catch { /* unreadable */ }
    return /yarn lockfile v1/.test(head) ? 'yarn' : 'yarn-berry';
  }
  if (exists('pnpm-lock.yaml')) return 'pnpm';
  return null;
}

/** The lockfile Gnawky works with, for messages like "git add package.json yarn.lock". */
export const lockfileName = (pm) => LOCKFILES[pm] ?? 'package-lock.json';

/** How a package.json script is run, for display: "npm run test" or "yarn run test". */
export const runLabel = (pm, name) => `${pm === 'yarn' ? 'yarn' : 'npm'} run ${name}`;

/** Name of the dependency audit scanner for this package manager. */
export const auditName = (pm) => (pm === 'yarn' ? 'yarn audit' : 'npm audit');

export const DEP_AUDIT_TOOLS = ['npm-audit', 'yarn-audit'];
export const isDepAudit = (f) => DEP_AUDIT_TOOLS.includes(f.tool);
