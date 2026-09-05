---
name: cryptad-start-work-branch
description: Start feature or bugfix work from develop while preserving existing local changes.
---

# Start a work branch

Use [Git policy](../cryptad-git-workflow/SKILL.md).
Choose `feature/<short-name>` for enhancements/refactoring and `bugfix/<short-name>` for ordinary
fixes, inferring a name from the request. Reserve `hotfix/<build-number>` for production hotfixes.

Inspect branch, status, and refs. Preserve an existing suitable work branch.
Base new work on `develop`; fetch with verified `leumor` credentials when freshness matters.
Update clean develop with `git pull --ff-only` when appropriate. Local-only work can use available
local develop; report when it was not refreshed.

Preserve dirty work: do not auto-stash unrelated edits, reset branches, or switch across incompatible
bases. Use an isolated worktree when useful. If work already exists on a primary branch, preserve
it on a work branch and inspect its relationship to develop before preparing a PR.

Create the branch and complete requested work. Branch creation alone does not request committing,
pushing, or opening a PR. When requested, use Conventional Commits and target develop by default.
Feature/bugfix PRs require green CI and at least one approval; squash-and-merge is encouraged.
