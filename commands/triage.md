---
description: Have Claude triage Gnawky's findings against the code (shows the plan and asks before sending anything)
argument-hint: "[--severity critical,high] [--sources dependencies,code,secrets] [--all]"
---

Use the gnawky skill to triage the findings with `gnawky triage $ARGUMENTS`: show the plan from the run without `--yes`, ask the user before starting, then run it with `--yes` and summarize the verdicts.
