---
name: cryptad-hotfix-workflow
description: Prepare integer-build hotfixes from main and execute authorized ordinary or Stable security releases.
---

# Cryptad hotfix workflow

Load [Git policy](../cryptad-git-workflow/SKILL.md).
Use `hotfix/<build-number>` from `main`; bump the integer build when shipped bytes change.
Merge the published candidate independently into `main` and `develop` with `--no-ff`, without
squash/rebase. Do not infer publication or merge authorization from a preparation request.

Select ordinary or Stable security mode before running commands. Stable security hotfixes require
`stable-backport` and `stable-maintenance`; the protected workflow creates/verifies the annotated
tag. Do not manually tag them or waive non-waivable gates. Keep incident material private.

## Read for the current task

- [Rules; Procedure; Checklist](references/ordinary-hotfix.md).
- [Stable 1.0 security hotfix path](references/stable-security.md).
