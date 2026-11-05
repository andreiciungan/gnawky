import { spawnSync } from 'node:child_process';
import { run, isAvailable, IS_WIN, VERSION_ARGS } from './scanners.js';

/**
 * External tools Gnawky uses. `brew` / `pipx` name the package to install when
 * that package manager is available; otherwise only the manual hint is shown.
 */
export const TOOLS = [
  { cmd: 'npm', why: 'checks dependencies', hint: 'comes with Node.js' },
  { cmd: 'yarn', why: 'checks dependencies (yarn projects)', brew: 'yarn', hint: 'npm install -g yarn', onlyFor: 'yarn' },
  { cmd: 'git', why: 'safe fix branches', brew: 'git', hint: 'https://git-scm.com' },
  { cmd: 'gitleaks', why: 'finds leaked secrets', brew: 'gitleaks', hint: 'https://github.com/gitleaks/gitleaks#installing' },
  { cmd: 'semgrep', why: 'finds risky code', brew: 'semgrep', pipx: 'semgrep', hint: 'pipx install semgrep   (https://semgrep.dev/docs/getting-started)' },
  { cmd: 'claude', why: 'optional: Ask Claude', hint: 'https://docs.claude.com/en/docs/claude-code/setup' },
];

export const tool = (cmd) => TOOLS.find((t) => t.cmd === cmd);

/** First line of `<tool> --version`, or null if the tool is not installed. */
export function toolVersion(cmd) {
  const r = run(cmd, VERSION_ARGS[cmd] ?? ['--version'], { timeoutMs: 15000 });
  if (r.error || r.status !== 0) return null;
  return r.stdout.trim().split('\n')[0].slice(0, 40) || 'installed';
}

/** [command, args] that installs the tool here, or null if we can't do it automatically. */
export function installCommand(t) {
  if (IS_WIN) return null;
  if (t.brew && isAvailable('brew')) return ['brew', ['install', t.brew]];
  if (t.pipx && isAvailable('pipx')) return ['pipx', ['install', t.pipx]];
  return null;
}

/** Runs the installer with its output shown live. Returns true if the tool works afterwards. */
export function installTool(t) {
  const cmd = installCommand(t);
  if (!cmd) return false;
  spawnSync(cmd[0], cmd[1], { stdio: 'inherit' });
  return toolVersion(t.cmd) !== null;
}
