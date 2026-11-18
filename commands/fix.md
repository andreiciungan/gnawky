---
description: Fix vulnerable dependencies with Gnawky on a new branch (shows the plan and asks before changing anything)
argument-hint: "<package | finding id | GHSA/CVE ID>... | --all"
---

Use the gnawky skill to fix these findings: $ARGUMENTS. Show the plan from `gnawky fix … --json`, agree the order and verification with the user, apply it with `--yes` only after they confirm, then let them choose `gnawky fix --keep` or `gnawky fix --undo`.
