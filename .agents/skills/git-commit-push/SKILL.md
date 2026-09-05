---
name: git-commit-push
description: Review, format as needed, commit, and push requested changes on a safe work branch.
---

# Commit and push

Load [Git policy](../cryptad-git-workflow/SKILL.md).
A commit/push request authorizes those actions and routine local preparation, without a second
approval. It does not authorize a PR, merge, release, or history rewrite.

Inspect staged, unstaged, and relevant untracked changes. Preserve unrelated edits and staged work.
Never commit directly to `main`, `develop`, or the selected PR base. Use
[start-work-branch](../cryptad-start-work-branch/SKILL.md) if needed; reserve integer hotfix branches
for the explicit production-hotfix workflow.

For files owned by Spotless, use [build tooling](../cryptad-build-tooling/SKILL.md), run the
appropriate formatter, and review its diff. Prose-only or skill-metadata edits do not require Gradle.
Make routine corrections necessary for the commit unless the user requested review-only/no-edit
work; avoid unrelated cleanup. Reuse verification not invalidated by subsequent changes.

Use [commit-message guidance](../git-commit-helper/SKILL.md), stage intended paths, inspect the
staged diff, and perform the Git identity check. Commit and push to the intended remote branch
with verified `leumor` credentials. A bare `git push` does not necessarily use a prefixed
`gh` command's account.

Report branch, commit, pushed remote, included changes, and actual verification.
