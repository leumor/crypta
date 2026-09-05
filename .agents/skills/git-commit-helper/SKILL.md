---
name: git-commit-helper
description: Write a Conventional Commit message from staged or explicitly selected changes.
---

# Write a commit message

Read the staged or user-selected diff. Use status to distinguish staged, unstaged, and untracked
work; describe only the proposed commit.

Use `<type>(<scope>): <summary>`, omitting scope when unnecessary. Select the type from the actual
change. Write a concise imperative summary without a trailing period. Add a body for rationale,
behavior, or compatibility a future maintainer needs. Mark only actual breaking changes.

A message request does not authorize staging, committing, amending, or pushing.
When those actions are requested, follow [Git policy](../cryptad-git-workflow/SKILL.md) and
[commit/push](../git-commit-push/SKILL.md). Preserve unrelated staged work and do not rewrite history
without explicit authorization.
