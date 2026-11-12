// Adds or removes the git pre-commit hook that runs `gnawky pre-commit` (src/precommit.js),
// as a marked block in the project's pre-commit script:
// - husky (core.hooksPath .husky/_): .husky/pre-commit, committed, so the whole team gets it
// - another core.hooksPath (like .githooks): <that folder>/pre-commit, shared if committed
// - otherwise .git/hooks/pre-commit: this clone only
// lefthook rewrites the scripts it manages, so for lefthook the user gets a snippet instead.

import fs from 'node:fs';
import path from 'node:path';
import { run } from './scanners.js';

const START = '# >>> gnawky dependency check >>>';
const END = '# <<< gnawky dependency check <<<';

// Teammates without gnawky (or a GUI git client without it on PATH) commit as before.
export const BLOCK = `${START}
# Blocks commits that add dependencies with new high or critical advisories. Skip once: git commit --no-verify
if command -v gnawky >/dev/null 2>&1; then gnawky pre-commit || exit 1; fi
${END}`;

export const LEFTHOOK_SNIPPET = `pre-commit:
  commands:
    gnawky:
      glob: "{package.json,package-lock.json,npm-shrinkwrap.json,yarn.lock}"
      run: command -v gnawky >/dev/null 2>&1 && gnawky pre-commit || true`;

const LEFTHOOK_FILES = ['lefthook.yml', '.lefthook.yml', 'lefthook.yaml', '.lefthook.yaml', 'lefthook.toml', 'lefthook.json'];
const git = (args, cwd) => run('git', args, { cwd, timeoutMs: 15000 });

/**
 * Where the hook goes: { kind: 'husky' | 'custom' | 'local' | 'lefthook', file, shared, root },
 * or null outside a git repository.
 */
export function hookTarget(dir) {
  const top = git(['rev-parse', '--show-toplevel'], dir);
  if (top.status !== 0) return null;
  const root = top.stdout.trim();
  if (LEFTHOOK_FILES.some((f) => fs.existsSync(path.join(root, f)))) return { kind: 'lefthook', file: null, shared: true, root };
  const hooksPath = git(['config', '--get', 'core.hooksPath'], root).stdout.trim();
  if (/^\.husky(\/_)?\/?$/.test(hooksPath)) return { kind: 'husky', file: path.join(root, '.husky', 'pre-commit'), shared: true, root };
  if (hooksPath) {
    const abs = path.resolve(root, hooksPath);
    return { kind: 'custom', file: path.join(abs, 'pre-commit'), shared: abs.startsWith(root + path.sep) && !abs.includes(`${path.sep}.git${path.sep}`), root };
  }
  const hooks = git(['rev-parse', '--git-path', 'hooks'], root).stdout.trim();
  return { kind: 'local', file: path.join(path.resolve(root, hooks), 'pre-commit'), shared: false, root };
}

const read = (file) => {
  try { return fs.readFileSync(file, 'utf8'); } catch { return null; }
};

const blockPattern = () => new RegExp(`${START.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[\\s\\S]*?${END.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n?`);

export const isHookInstalled = (t) => Boolean(t?.file) && (read(t.file) ?? '').includes(START);

/**
 * Adds the block near the top of the script (after a shebang), so an earlier `exit` in an
 * existing hook can't skip it. Creates the script if there is none.
 */
export function installHook(t) {
  if (!t?.file) throw new Error('no pre-commit script to write to');
  const existing = read(t.file);
  let text;
  if (existing === null) {
    // husky 9 scripts are plain commands; git's own hooks need a shebang.
    text = t.kind === 'husky' ? `${BLOCK}\n` : `#!/bin/sh\n${BLOCK}\n`;
  } else {
    const clean = existing.replace(blockPattern(), '');
    const nl = clean.indexOf('\n');
    text = clean.startsWith('#!')
      ? `${clean.slice(0, nl + 1)}${BLOCK}\n${clean.slice(nl + 1)}`
      : `${BLOCK}\n${clean}`;
  }
  fs.mkdirSync(path.dirname(t.file), { recursive: true });
  fs.writeFileSync(t.file, text);
  fs.chmodSync(t.file, 0o755);
  return t.file;
}

/** Removes the block; deletes the script when nothing else is left in it. */
export function uninstallHook(t) {
  const existing = t?.file ? read(t.file) : null;
  if (existing === null || !existing.includes(START)) return false;
  const rest = existing.replace(blockPattern(), '');
  if (!rest.replace(/^#!.*\n?/, '').trim()) fs.rmSync(t.file);
  else fs.writeFileSync(t.file, rest);
  return true;
}
