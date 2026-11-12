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
//
// Setups it has to survive:
// - npm/yarn already being shell functions, like nvm lazy loading (the function loads nvm on
//   first use): they are kept as __gnawky_prev_npm/yarn and called to load Node and to run
//   the real command while the binary isn't on PATH yet.
// - gnawky missing in the current Node version (nvm use): a one-time note, then npm runs.
// - gnawky failing to start: it writes $GNAWKY_DECIDED once it has decided, so an empty file
//   means it never got that far, and the command runs without the check. Ctrl+C still stops.
export const BLOCK = `${START}
# Checks new packages with Gnawky before \`npm install <pkg>\` and \`yarn add <pkg>\`.
# Turn it off in gnawky Settings, or delete this block. Skip once: GNAWKY_SKIP=1 npm install <pkg>
__gnawky_bin() { if [ -n "$ZSH_VERSION" ]; then whence -p "$1" >/dev/null 2>&1; else type -P "$1" >/dev/null 2>&1; fi; }
__gnawky_real() {
  local pm="$1"
  shift
  if ! __gnawky_bin "$pm" && typeset -f "__gnawky_prev_$pm" >/dev/null 2>&1; then
    "__gnawky_prev_$pm" "$@"
  else
    command "$pm" "$@"
  fi
}
__gnawky_check() {
  local pm="$1" a f rc
  shift
  if ! __gnawky_bin "$pm" && typeset -f "__gnawky_prev_$pm" >/dev/null 2>&1; then
    "__gnawky_prev_$pm" --version >/dev/null 2>&1
    __gnawky_define
  fi
  if [ -z "$GNAWKY_SKIP" ]; then
    for a in "$@"; do
      case "$pm:$a" in
        npm:install|npm:i|npm:in|npm:ins|npm:inst|npm:insta|npm:instal|npm:isnt|npm:isnta|npm:isntal|npm:isntall|npm:add|yarn:add)
          if ! __gnawky_bin gnawky; then
            [ -n "$__GNAWKY_WARNED" ] || echo "gnawky: not installed for this Node version ($(command node --version 2>/dev/null)), packages not checked. Install it with: npm install -g gnawky" >&2
            __GNAWKY_WARNED=1
            break
          fi
          f="$(mktemp "\${TMPDIR:-/tmp}/gnawky.XXXXXX")" || break
          GNAWKY_DECIDED="$f" command gnawky guard "$pm" "$@"
          rc=$?
          if [ -s "$f" ] || [ "$rc" -ge 128 ]; then rm -f "$f"; return "$rc"; fi
          rm -f "$f"
          echo "gnawky: the package check could not start, running $pm without it" >&2
          break ;;
      esac
    done
  fi
  __gnawky_real "$pm" "$@"
}
__gnawky_define() {
  local pm
  for pm in npm yarn; do
    if typeset -f "$pm" >/dev/null 2>&1 && ! typeset -f "$pm" | grep -q __gnawky_check; then
      eval "$(typeset -f "$pm" | sed "1s/^$pm/__gnawky_prev_$pm/")"
    fi
  done
  function npm { __gnawky_check npm "$@"; }
  function yarn { __gnawky_check yarn "$@"; }
}
__gnawky_define
${END}`;

/** The startup file for the user's shell, or null for shells this doesn't support (fish, ...). */
export function rcFile(env = process.env) {
  const shell = path.basename(env.SHELL ?? '');
  if (shell === 'zsh') return path.join(env.ZDOTDIR || os.homedir(), '.zshrc');
  // macOS terminals start bash as a login shell, which reads ~/.bash_profile, not ~/.bashrc.
  if (shell === 'bash') return path.join(os.homedir(), process.platform === 'darwin' ? '.bash_profile' : '.bashrc');
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

/**
 * Replaces an older copy of the block with the current one, in the same place (it has to stay
 * after anything that defines npm or yarn, like nvm). Returns true if it changed the file.
 */
export function refresh(file = rcFile()) {
  if (!file) return false;
  const text = read(file);
  if (!text.includes(START) || text.includes(BLOCK)) return false;
  fs.writeFileSync(file, text.replace(blockPattern(), `\n${BLOCK}\n`));
  return true;
}

/** Removes the block. Returns true if there was one. */
export function uninstall(file = rcFile()) {
  if (!file) return false;
  const text = read(file);
  if (!text.includes(START)) return false;
  fs.writeFileSync(file, text.replace(blockPattern(), '').replace(/\n{3,}$/, '\n'));
  return true;
}
