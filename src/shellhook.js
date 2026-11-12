// Adds or removes the shell functions that send `npm install <pkg>` and `yarn add <pkg>`
// through `gnawky guard` (src/guard.js), so pasted commands are checked too.
// The functions live in a marked block in the user's shell startup file.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const START = '# >>> gnawky package check >>>';
const END = '# <<< gnawky package check <<<';

// Plain sh syntax that works in zsh and bash. `function name {` instead of `name() {` so a
// user's alias with the same name can't break it in zsh. Only commands that may add packages
// start Node; gnawky guard then parses them exactly and runs everything else unchanged.
export const BLOCK = `${START}
# Checks new packages with Gnawky before \`npm install <pkg>\` and \`yarn add <pkg>\`.
# Turn it off in gnawky Settings, or delete this block. Skip once: GNAWKY_SKIP=1 npm install <pkg>
__gnawky_check() {
  local pm="$1" a
  shift
  if [ -z "$GNAWKY_SKIP" ] && command -v gnawky >/dev/null 2>&1; then
    for a in "$@"; do
      case "$pm:$a" in
        npm:install|npm:i|npm:in|npm:ins|npm:inst|npm:insta|npm:instal|npm:isnt|npm:isnta|npm:isntal|npm:isntall|npm:add|yarn:add)
          command gnawky guard "$pm" "$@"
          return ;;
      esac
    done
  fi
  command "$pm" "$@"
}
function npm { __gnawky_check npm "$@"; }
function yarn { __gnawky_check yarn "$@"; }
${END}`;

/** The startup file for the user's shell, or null for shells this doesn't support (fish, ...). */
export function rcFile(env = process.env) {
  const shell = path.basename(env.SHELL ?? '');
  if (shell === 'zsh') return path.join(env.ZDOTDIR || os.homedir(), '.zshrc');
  if (shell === 'bash') return path.join(os.homedir(), '.bashrc');
  return null;
}

const read = (file) => {
  try { return fs.readFileSync(file, 'utf8'); } catch { return ''; }
};

const blockPattern = () => new RegExp(`\\n?${START.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[\\s\\S]*?${END.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n?`);

export const isInstalled = (file = rcFile()) => Boolean(file) && read(file).includes(START);

/** Adds the block (or refreshes an older copy of it). Returns the file it wrote. */
export function install(file = rcFile()) {
  if (!file) throw new Error(`unsupported shell (${process.env.SHELL || 'unknown'}); zsh and bash are supported`);
  const text = read(file).replace(blockPattern(), '');
  const sep = text && !text.endsWith('\n') ? '\n' : '';
  fs.writeFileSync(file, `${text}${sep}\n${BLOCK}\n`);
  return file;
}

/** Removes the block. Returns true if there was one. */
export function uninstall(file = rcFile()) {
  if (!file) return false;
  const text = read(file);
  if (!text.includes(START)) return false;
  fs.writeFileSync(file, text.replace(blockPattern(), '').replace(/\n{3,}$/, '\n'));
  return true;
}
