---
description: Scan this Node.js project for security issues and walk through fixes
argument-hint: "[path] [--min-severity high]"
allowed-tools: Bash(node:*), Read, Grep, Glob
---

Run the scanner in read-only mode:

`node "${CLAUDE_PLUGIN_ROOT}/bin/gnawky.js" $ARGUMENTS --json`

(If `CLAUDE_PLUGIN_ROOT` is not set, use `gnawky $ARGUMENTS --json` instead.)

Then, using the JSON output:

1. Give a short summary: counts by severity, and which scanners were skipped and why. If every scanner was skipped, say clearly that the result proves nothing.
2. List the findings, most severe first. For each one, explain in plain language what an attacker could do, then give 1 to 3 fix options with trade-offs (effort, breaking-change risk) and say which one you recommend. Use the `security-reviewer` agent to check whether a code finding is a real issue or a false positive when that is unclear.
3. Ask the user which findings to fix, ignore (with a reason), or skip.

Safety rules. Follow them strictly:
- Never print secret values, even if you read the file containing one. Refer to them by file and line only.
- For leaked secrets, always say the credential must be rotated first; removing it from the code is not enough.
- Never edit a file until the user has approved that specific change. Show the diff first.
- Never run `npm audit fix --force`, install scripts, the project's own code or tests, `git commit`, or `git push` unless the user explicitly asks.
- For dependency fixes, recommend the user run `gnawky` in their terminal and choose "Review & fix findings" (it works on a separate git branch), or propose the exact command and wait for approval.
