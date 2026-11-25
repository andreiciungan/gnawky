---
description: Quick check with a fresh audit - which packages with critical/high advisories ship to production (no full scan)
---

Use the gnawky skill to run the quick production check: run `gnawky pre-push --json`, then summarize it as the skill describes and offer `gnawky fix` for the packages that have an upgrade.
