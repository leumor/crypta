---
name: gh-fix-ci
description: Diagnose and fix failing GitHub Actions checks for a PR using gh and captured job logs.
metadata:
  short-description: Fix failing GitHub Actions checks
---

# Fix GitHub Actions checks

Use [Git policy](../cryptad-git-workflow/SKILL.md) for identity and authorization.
Default to the current branch's PR unless the user selects another.

Run the bundled inspector from the repository root:

```bash
python3 .agents/skills/gh-fix-ci/scripts/inspect_pr_checks.py --repo . --json
```

Add `--pr <number-or-url>` when needed. The script selects `leumor` explicitly and returns
nonzero when failing checks remain; inspect its JSON/log evidence before treating that as a
tool failure. Missing logs are an evidence gap, not proof of success.

Identify the failed job, source SHA, error, and relevant code. For an authorized fix request,
explain the approach briefly, implement it, and run relevant local checks. A diagnosis-only request
ends with findings. No separate plan approval is required for fixes already requested.

Load build/tooling or certification guidance for the affected job. Do not weaken required checks,
permissions, protected environments, or evidence authentication to make CI green.
For external-provider checks, report URLs and access limitations unless the user requests
investigation with an available integration.

Recheck PR status with explicit `leumor` credentials after an authorized push. Distinguish
local validation from hosted checks for the new SHA. Report cause, change, checks, and blockers.
