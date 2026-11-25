// Adds or removes Gnawky's git hooks, each as a marked block in the project's hook script:
// - pre-commit runs `gnawky pre-commit` (src/precommit.js): blocks commits adding new high/critical findings
// - pre-push runs `gnawky pre-push` (src/prepush.js): warns about critical/high findings that ship to production
// Where the script lives:
// - husky (core.hooksPath .husky/_): .husky/<hook>, committed, so the whole team gets it
// - another core.hooksPath (like .githooks): <that folder>/<hook>, shared if committed
// - otherwise .git/hooks/<hook>: this clone only
// lefthook rewrites the scripts it manages, so for lefthook the user gets a snippet instead.

import fs from 'node:fs';
import path from 'node:path';
import { run } from './scanners.js';

// Teammates without gnawky (or a GUI git client without it on PATH) commit and push as before.
// pre-push gets </dev/null: git passes the pushed refs on stdin, and a later part of the
// script (git-lfs, for one) may need to read them.
const HOOKS = {
  'pre-commit': {
    start: '# >>> gnawky dependency check >>>',
    end: '# <<< gnawky dependency check <<<',
    body: `# Blocks commits that add dependencies with new high or critical advisories. Skip once: git commit --no-verify
if command -v gnawky >/dev/null 2>&1; then gnawky pre-commit || exit 1; fi`,
    lefthook: `pre-commit:
  commands:
    gnawky:
      glob: "{package.json,package-lock.json,npm-shrinkwrap.json,yarn.lock}"
      run: command -v gnawky >/dev/null 2>&1 && gnawky pre-commit || true`,
  },
  'pre-push': {
    start: '# >>> gnawky production check >>>',
    end: '# <<< gnawky production check <<<',
    body: `# Warns about critical/high advisories in dependencies that ship to production. Never blocks the push.
if command -v gnawky >/dev/null 2>&1; then gnawky pre-push </dev/null || true; fi`,
    lefthook: `pre-push:
  commands:
    gnawky:
      run: command -v gnawky >/dev/null 2>&1 && gnawky pre-push </dev/null || true`,
  },
};

export const HOOK_NAMES = Object.keys(HOOKS);
export const blockFor = (hook) => `${HOOKS[hook].start}\n${HOOKS[hook].body}\n${HOOKS[hook].end}`;
export const lefthookSnippet = (hook) => HOOKS[hook].lefthook;
// Kept for existing callers: the pre-commit versions.
export const BLOCK = blockFor('pre-commit');
export const LEFTHOOK_SNIPPET = lefthookSnippet('pre-commit');

const LEFTHOOK_FILES = ['lefthook.yml', '.lefthook.yml', 'lefthook.yaml', '.lefthook.yaml', 'lefthook.toml', 'lefthook.json'];
const git = (args, cwd) => run('git', args, { cwd, timeoutMs: 15000 });

/**
 * Where the hook goes: { hook, kind: 'husky' | 'custom' | 'local' | 'lefthook', file, shared, root },
 * or null outside a git repository.
 */
export function hookTarget(dir, hook = 'pre-commit') {
  const top = git(['rev-parse', '--show-toplevel'], dir);
  if (top.status !== 0) return null;
  const root = top.stdout.trim();
  if (LEFTHOOK_FILES.some((f) => fs.existsSync(path.join(root, f)))) return { hook, kind: 'lefthook', file: null, shared: true, root };
  const hooksPath = git(['config', '--get', 'core.hooksPath'], root).stdout.trim();
  if (/^\.husky(\/_)?\/?$/.test(hooksPath)) return { hook, kind: 'husky', file: path.join(root, '.husky', hook), shared: true, root };
  if (hooksPath) {
    const abs = path.resolve(root, hooksPath);
    return { hook, kind: 'custom', file: path.join(abs, hook), shared: abs.startsWith(root + path.sep) && !abs.includes(`${path.sep}.git${path.sep}`), root };
  }
  const hooks = git(['rev-parse', '--git-path', 'hooks'], root).stdout.trim();
  return { hook, kind: 'local', file: path.join(path.resolve(root, hooks), hook), shared: false, root };
}

const read = (file) => {
  try { return fs.readFileSync(file, 'utf8'); } catch { return null; }
};

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const blockPattern = (hook) => new RegExp(`${esc(HOOKS[hook].start)}[\\s\\S]*?${esc(HOOKS[hook].end)}\\n?`);
const hookOf = (t) => t?.hook ?? 'pre-commit';

export const isHookInstalled = (t) => Boolean(t?.file) && (read(t.file) ?? '').includes(HOOKS[hookOf(t)].start);

/**
 * Adds the block near the top of the script (after a shebang), so an earlier `exit` in an
 * existing hook can't skip it. Creates the script if there is none.
 */
export function installHook(t) {
  if (!t?.file) throw new Error(`no ${hookOf(t)} script to write to`);
  const block = blockFor(hookOf(t));
  const existing = read(t.file);
  let text;
  if (existing === null) {
    // husky 9 scripts are plain commands; git's own hooks need a shebang.
    text = t.kind === 'husky' ? `${block}\n` : `#!/bin/sh\n${block}\n`;
  } else {
    const clean = existing.replace(blockPattern(hookOf(t)), '');
    const nl = clean.indexOf('\n');
    text = clean.startsWith('#!')
      ? `${clean.slice(0, nl + 1)}${block}\n${clean.slice(nl + 1)}`
      : `${block}\n${clean}`;
  }
  fs.mkdirSync(path.dirname(t.file), { recursive: true });
  fs.writeFileSync(t.file, text);
  fs.chmodSync(t.file, 0o755);
  return t.file;
}

/** Removes the block; deletes the script when nothing else is left in it. */
export function uninstallHook(t) {
  const existing = t?.file ? read(t.file) : null;
  if (existing === null || !existing.includes(HOOKS[hookOf(t)].start)) return false;
  const rest = existing.replace(blockPattern(hookOf(t)), '');
  if (!rest.replace(/^#!.*\n?/, '').trim()) fs.rmSync(t.file);
  else fs.writeFileSync(t.file, rest);
  return true;
}
