---
name: create-pr
description: Review and prepare branch changes, then open a GitHub PR into develop or a selected base.
---

# Create a pull request

Load [Git policy](../cryptad-git-workflow/SKILL.md).
A request to create/open a PR authorizes creation; do not ask again.
For preparation-only work, finish the reviewable diff and PR text before asking about publication.

Default to `develop`, honoring an explicit base. Fetch with verified `leumor` credentials,
then resolve the base from the repository root:

```bash
bash .agents/skills/create-pr/scripts/resolve_base_branch.sh
# For an explicitly selected base:
bash .agents/skills/create-pr/scripts/resolve_base_branch.sh <base>
```

The helper falls back to `main` only when no base was specified and `origin/develop` is absent.
Never commit on primary branches or the chosen base; use
[start-work-branch](../cryptad-start-work-branch/SKILL.md) when needed.

Review commits and the complete diff against `origin/<base>`, plus local changes belonging to the
PR. Preserve unrelated work. Follow [commit/push](../git-commit-push/SKILL.md) for pending changes;
format applicable files and reuse valid checks. Check for an existing head/base PR before creating.

Use a Conventional Commit title with a capitalized imperative summary and no trailing period.
Follow the repository PR template if present. Describe the final problem, resulting behavior,
validation, and material limitations. Honor a requested draft; otherwise use ready-for-review when
verification is complete, or a draft with explicit outstanding checks.

Prefer GitHub MCP after verifying its authenticated user is `leumor`; otherwise use explicitly
authenticated `gh`. Supply the body as a structured field or UTF-8 file via `--body-file`.
Verify author, base, head, and draft state. Return the PR URL and actual validation.
