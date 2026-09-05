---
name: cryptad-git-workflow
description: "Apply Cryptad branch, commit, PR, merge, versioning, and GitHub identity policy."
metadata:
  area: git
  domain: cryptad
---

## When to use
Use this skill whenever you:
- Need the canonical branch/release policy reference.
- Create branches, commits, tags, releases, or hotfixes.
- Resolve merge conflicts or integrate changes between branches.
- Prepare a pull request (even if you won’t open it yet).

## Workflow reference
### Goals
- Keep `main` always releasable and matching the latest production build.
- Use a single integer build number for shipped versions.
- Keep feature work parallel while preserving auditable release/hotfix history.

### Versioning and tags
- The build number is a single integer in `build.gradle.kts` (example: `version = 2`).
- Release/hotfix tags must use `v<build-number>` (example: `v2`).
- If a release/hotfix changes the shipped build, bump `version` to the intended build number.
- Stable 1.0 is a product/API milestone within this integer model. Do not create a `1.0.0` project
  version, semantic-version tag, replacement branch model, or a second build with the same integer
  version but different product bytes.

### Branching model (GitFlow-inspired)
- Primary branches:
  - `main`: production-ready; every commit is release-quality.
  - `develop`: integration branch for the next release.
- Supporting branches:
  - `feature/<name>`: new features/refactors targeting `develop`.
  - `bugfix/<name>`: non-production fixes targeting `develop`.
  - `release/<build-number>`: stabilization branch from `develop`.
  - `hotfix/<build-number>`: emergency production fix branch from `main`.

## Merge and PR policy
- Commit format: Conventional Commits.
- `feature/*` and `bugfix/*` PRs: squash-and-merge is encouraged.
- `release/*` and `hotfix/*` merges:
  - Do not squash or rebase these merges.
  - Merge into `main` with `--no-ff`.
  - Back-merge into `develop` with `--no-ff`.
- Before Stable RC/GA, maintenance, security-hotfix, or release-train work, read
  [protected release policy](references/protected-releases.md). Ordinary local changes and PR
  preparation do not require that operational checklist.
- PR policy: require green CI and at least one approval.
- Create a PR when the user requests or has already authorized it. A preparation/review request alone does not authorize creation; finish the diff and PR text before asking about publication.

## Git identity policy (must follow)
### GitHub operation identity
- All GitHub operations for this repository must use the `leumor` account, including PR creation,
  review comments, issue comments, review-thread resolution, release edits, CI inspection, and
  branch pushes.
- Do not rely on the active/default `gh` account. Prefix every manual `gh` command with:
  `GH_TOKEN="$(gh auth token --user leumor)" gh ...`.
- Verify an MCP/plugin authenticated user before a write; use explicitly authenticated `gh` if
  the tool cannot establish `leumor`. Verify the resulting author. If an unexpected account wrote
  an artifact, stop further writes and report it; do not compound the error with automatic deletion
  or recreation.
- For Git transport, verify the remote and its credential identity separately; a `GH_TOKEN`
  prefix on `gh` does not configure bare `git` or SSH. Use an account-specific SSH identity or a
  command-scoped HTTPS credential helper authenticated as `leumor`, without printing tokens.
- If `gh auth token --user leumor` fails, stop and ask the user to authenticate `leumor`; do not
  fall back to another GitHub account.

### Never override authorship/committer identity
- Do not pass `--author` or `--reset-author` to `git commit`.
- Do not set `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, or `GIT_COMMITTER_EMAIL` in commit flows.
- Do not run `git config user.name` / `git config user.email` inside this repository during commit flows.
- Use the existing project/default identity configured for the environment.

### Pre-commit identity check (required)
Before any `git commit` **or** history rewrite, verify identity is configured:
```bash
git config --get user.name
git config --get user.email
```

If either is missing/empty:
1. STOP. Do not proceed with the commit or rewrite.
2. Warn the user and ask them to set identity themselves (agents must not set it).
   Example:
   ```bash
   git config --global user.name "<Your Name>" && git config --global user.email "<you@example.com>"
   ```
3. Recheck identity and resume when it is configured; do not require another confirmation.

### History rewrites
Only rewrite authorship/committer history when explicitly requested by a maintainer.
- Use a deterministic non-interactive rewrite plan unless the user requests an interactive session.
- Push with `--force-with-lease`.
- Document rewritten SHAs in the PR.
