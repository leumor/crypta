---
name: cryptad-release-workflow
description: Prepare integer-build release branches and execute authorized ordinary or protected Stable releases.
---

# Cryptad release workflow

Load [Git policy](../cryptad-git-workflow/SKILL.md) before Git mutations.
Release branches start from `develop` as `release/<build-number>`; tags use `v<build-number>`.
Stable 1.0 is a product/API milestone, not a semantic project version. Release merges preserve
history with `--no-ff`, without squash/rebase, into `main` and independently into `develop`.

Select ordinary, Stable RC/GA, or post-GA maintenance mode before running commands.
A preparation request ends with validated candidate material; it does not authorize publishing or
merging. Honor existing authorization, but retain protected environment approvals and receipts.
For Stable publication, freeze/build once and publish only the authorized exact bytes through the
protected workflow. Never run ordinary manual tagging commands for Stable GA/maintenance.

## Read for the current task

- [Rules](references/release-rules.md).
- [Procedure; Checklist](references/preparation-and-promotion.md).
- [Stable 1.0 maintenance releases after GA](references/maintenance.md).
- [Stable 1.0 protected execution](references/protected-execution.md).
