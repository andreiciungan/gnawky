# Gnawky

*Gnaws through your code, watches like a hawk.*

Gnawky is a local security scanner for Node.js projects. It combines proven open-source scanners, writes one report, and lets you choose per finding: **fix**, **ignore (with a reason)**, or **skip**. It also ships as a Claude Code plugin that explains findings and proposes fixes.

## What it checks

| Scanner | Finds | Required? |
|---|---|---|
| `npm audit` | Known-vulnerable dependencies | Yes (comes with npm) |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secrets in files and git history | Optional, recommended |
| [semgrep](https://semgrep.dev) | Risky code (injection, XSS, unsafe `eval`, etc.) | Optional, recommended |

Missing optional scanners are reported as "skipped", never silently ignored.

```bash
brew install gitleaks semgrep        # macOS
pipx install semgrep                 # alternative for semgrep
```

## Usage

Install once (inside this folder):

```bash
npm link
```

Then start it **inside the project you want to scan**:

```bash
cd ~/code/my-app
gnawky
```

You get an interactive menu (arrow keys + Enter, or number keys; `q`/Esc goes back):

```
gnawky  my-app  /Users/you/code/my-app
Last scan 27/09/2026 10:14: 1 high, 2 medium
──────────────────────────────────────────
What would you like to do?
❯ 1. Scan again
  2. Review & fix findings (3)
  3. Browse findings
  4. Ask Claude for help
  5. Ignored findings
  6. View report
  7. Settings
  8. Check installed tools
  9. Quit
```

- **Review & fix**: go through findings one by one and choose fix, skip, or ignore. Nothing happens until you confirm the final plan.
- **Browse findings**: open any finding for details and act on just that one.
- **Ask Claude for help**: starts Claude Code with the scan results, after a privacy notice (needs Claude Code; disabled in offline mode).
- **Ignored findings**: see every ignore decision with its reason, and restore any of them.
- **Settings**: minimum severity, offline mode, scanners on/off, semgrep rules. Saved per project in `.gnawky/config.json`.
- **Check installed tools**: shows which scanners are missing and how to install them.

Headless mode for CI and scripts:

```bash
gnawky --no-ui                      # scan and write the report
gnawky --ci --min-severity high     # exit 1 if findings remain, 2 if no scanner could run
gnawky --json                       # machine-readable output (used by the Claude plugin)
gnawky --offline                    # nothing leaves this computer
```

Requires Node 18+ and a `package-lock.json`.

## Safety model

- **The scan is read-only.** Nothing changes unless you choose a fix in the app and confirm the plan.
- **Fixes happen on a new git branch**, and only if your working tree is clean, so you can review with `git diff` and throw everything away in one command.
- **No install scripts run during fixes** (`--ignore-scripts`), and `npm audit fix --force` is never used. Semver-major upgrades are labeled as breaking and need their own approval.
- **Secrets are never written to reports.** gitleaks runs with `--redact`, and code snippets are excluded.
- **No shell.** External tools are launched with argument arrays, so file names or package data can't inject commands. Package specs are validated before `npm install`.
- **Offline mode** (Settings, or `--offline`): npm audit is skipped (it sends your dependency list to the npm registry), semgrep only uses local rule files, and "Ask Claude" is disabled. Outside offline mode your source code is still never uploaded: only the dependency list goes to the registry, and semgrep downloads its rulesets with metrics turned off.
- **"Ask Claude" shows a privacy notice first**: anything Claude reads is sent to Anthropic. Claude is told not to open `.env` files, keys, or files flagged as containing secrets; for a hard block, add deny rules in Claude Code's permission settings.
- **Reports stay out of git**: `.gnawky/` ignores itself. `.gnawky-ignore.json` *is* meant to be committed so your team shares ignore decisions and their reasons.

## Claude Code plugin

The repo is also a plugin (`.claude-plugin/plugin.json`) with:

- `/security-scan`: runs the scanner, explains each finding, recommends fixes, and asks before changing anything
- `security-reviewer` agent: read-only triage of true vs. false positives, drafts minimal fix diffs

Install it locally through the included `marketplace.json`:

```
/plugin marketplace add /path/to/gnawky
/plugin install gnawky@gnawky-marketplace
```

Check the current Claude Code plugin docs if the commands differ in your version: https://docs.claude.com/en/docs/claude-code/overview

## Roadmap ideas

- Built-in Node-specific checks (e.g. `helmet` missing in Express, `cookie` without `httpOnly`/`secure`)
- Apply semgrep autofixes with per-edit approval
- HTML report and SARIF output for GitHub code scanning
- Support for yarn and pnpm lockfiles
