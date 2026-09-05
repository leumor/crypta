# Standard Git Branching and Release Workflow for Cryptad

Last validated: 2025-09-18

This document captures the Cryptad team’s standard Git branching and release workflow, validated against the project wiki and aligned with repository policies found in `AGENTS.md`.

## Goals

- Keep `main` always releasable and matching the latest production build.
- Use a simple, predictable versioning model driven by a single integer build number.
- Allow parallel feature development while keeping release and hotfix flows safe and auditable.

## Versioning System

- Single integer build number set in `build.gradle.kts` (e.g., `version = 2`).
- Tags use `v<build-number>` (e.g., `v2`).
- Generated artifacts and installers use this integer where a numeric version is required (e.g., jpackage `--app-version`).
- Compatibility: The build number is used in Cryptad/Fred version strings and for update compatibility checks.

Rationale: Using a single, monotonically increasing integer keeps updater compatibility straightforward (USK subscriptions, minimum build checks) and avoids semantic-version drift.

Stable 1.0 is a product and Platform API compatibility milestone, not a semantic version in the Git
model. A Stable 1.0 release candidate still belongs to the intended integer build and, if later
published, follows the normal `release/<build-number>` and `v<build-number>` workflow. The
[Stable RC release-freeze command](stable-1.0-rc-execution-and-release-freeze.md) prepares evidence
for review only; it does not create a branch or tag, merge code, publish a GitHub Release, or
declare GA. The subsequent
[Stable GA validation and promotion process](stable-1.0-rc-validation-and-ga-promotion.md) preserves
the same integer model and promotes the exact frozen RC bytes.

For Stable 1.0 GA, validation, authorization, and publication are separate. The side-effect-free
`stable-ga` command does not create Git state. The protected publication operation verifies the
expected `release/<build-number>` branch and authorized commit, then creates or verifies an
annotated `v<build-number>` tag through the required `leumor` GitHub identity. It never creates a
`v1.0.0` tag and never merges the release branch automatically. Complete the normal no-squash
`--no-ff` merge into `main` and back-merge into `develop` as explicit maintainer operations.

## Branching Model (GitFlow‑inspired)

- Primary branches
  - `main`: latest production-ready code; every commit on `main` must be release-quality.
  - `develop`: integration branch for upcoming work that will land in the next release.

- Supporting branches
  - `feature/<name>`: new features or refactors targeting the next release.
  - `bugfix/<name>`: fixes for work on `develop` before a release branch is cut.
  - `release/<build-number>`: release stabilization for the numbered build; only critical changes.
  - `hotfix/<build-number>`: emergency fix for production; based on `main`.

Notes
- Use Conventional Commits in messages (e.g., `feat:`, `fix:`, `docs:`). Squash & merge for feature/bugfix PRs is encouraged. Do not squash `release/*` or `hotfix/*` merges.
- PR creation requires maintainer/requester authorization; an explicit request to open a PR
  provides that authorization without a second confirmation. A review/preparation-only request
  does not. Merging still requires at least one approval and green CI.

## Common Workflows

### 1) Feature Development

1. Branch from `develop`:
   - `git checkout develop && git pull`
   - `git checkout -b feature/<name>`
2. Commit with Conventional Commit messages.
3. Open PR to `develop`. Enable “squash and merge”.
4. After merge, delete the feature branch.

### 2) Bugfix on Develop (pre‑release)

1. Branch from `develop`:
   - `git checkout -b bugfix/<name>`
2. Open PR to `develop` (squash & merge).

### 3) Release Workflow (stabilization)

The manual tag commands below apply to ordinary releases. For Stable RC/GA or post-GA maintenance,
use the protected publication sequence described above and in the maintenance runbook; do not
create its tag manually. Run publication and merge steps only within their authorized scope.

1. Prepare the build number in `build.gradle.kts` (e.g., bump to `version = 2`).
2. Create release branch:
   - `git checkout develop && git pull`
   - `git checkout -b release/2`
3. Stabilize: only fixes, docs, and release tasks. Avoid large refactors.
4. Tag the release on `release/2`:
   - `git tag v2`
5. Merge forward to `main` (no squash), then back‑merge to `develop`:
   - `git checkout main && git merge --no-ff release/2`
   - `git checkout develop && git merge --no-ff release/2`
6. Push branches and tags:
   - `git push origin main develop release/2`
   - `git push origin v2`

Outcome: `main` now reflects release `v2`. `develop` includes the same changes so future work starts from the released state.

### 4) Hotfix Workflow (production)

The manual tag command below applies to an ordinary hotfix. Stable security hotfixes use the
protected maintenance workflow for tag creation and exact-byte publication.

1. Branch from `main`:
   - `git checkout main && git pull`
   - `git checkout -b hotfix/3`
2. Fix the issue. Update the build number to the next integer if the hotfix changes the shipped build (e.g., `version = 3`).
3. Tag the hotfix on `hotfix/3`:
   - `git tag v3`
4. Merge to `main` and back‑merge to `develop` (no squash):
   - `git checkout main && git merge --no-ff hotfix/3`
   - `git checkout develop && git merge --no-ff hotfix/3`
5. Push branches and tags:
   - `git push origin main develop hotfix/3`
   - `git push origin v3`

Outcome: Production receives `v3`; `develop` is updated to include the hotfix.

## Do/Don’t

- Do
  - Keep `main` releasable; use `develop` for integration.
  - Use squash merges for `feature/*` and `bugfix/*` to keep history clean.
  - Use `--no-ff` merges for `release/*` and `hotfix/*` to preserve branch context.
  - Tag every release/hotfix with `v<build-number>`.
  - After releasing or hotfixing, always back‑merge to `develop`.

- Don’t
  - Don’t rebase or squash `release/*` and `hotfix/*` branches when merging into `main`/`develop`.
  - Don’t skip bumping the build number when a release/hotfix changes the shipped build.
  - Don’t open PRs without maintainer/requester approval.

## Release/Hotfix Checklist

- [ ] `build.gradle.kts` has the intended numeric `version` (build number).
- [ ] CI is green on the release/hotfix branch.
- [ ] Tag created: `v<build-number>`.
- [ ] Merged to `main` (no squash), then back‑merged to `develop`.
- [ ] Pushed tags and branches.
- [ ] Release notes updated (if applicable).

For a Stable 1.0 GA publication, also confirm:

- [ ] The latest successful frozen RC completed exact-byte post-freeze validation.
- [ ] Explicit GA authorization binds the final immutable validation identity and publication scope.
- [ ] The protected publication receipt verifies the annotated tag, GitHub Release assets, notes,
      and exact stable catalog bytes at the primary, mirrors, and authorized rollback location.
- [ ] Publication state is `publication-complete`, not merely `validated` or
      `publication-authorized`.

## Notes on Updater Compatibility

- The integer build number participates in network compatibility checks and update gating.
- Update-over-Mandatory (UOM) for the core JAR is disabled in favor of the package‑based CoreUpdater. Tags and build numbers still identify releases for packaging and distribution.

## Stable 1.0 maintenance and security hotfix branches

Stable 1.0 maintenance keeps the same branch model: `release/<build-number>` starts from
`develop`, while an urgent `hotfix/<build-number>` starts from the currently published `main` state.
Before transferring a fix, record its classification, disposition, state, source commit, intended
candidate, evidence, and provenance through `stable-backport`. Routine maintenance accepts only
the `routine-maintenance` lane; a critical incident uses the existing `security-hotfix` lane.

Cryptad publishes one Stable 1.0 successor chain. A historical supported or deprecated build may
be an upgrade-test or advisory-coverage source, but it never gets a mutable patch branch. Do not
create `release/<old-build>-patch`, a parallel LTS branch, or another latest pointer.

An accepted fix may reach the candidate as an authenticated inherited commit, a reviewed clean
cherry-pick with supporting patch identity, or a reviewed manual conflict resolution. Patch-id
equality does not authorize a release, and no mode of `stable-backport` performs the transfer.

The protected maintenance workflow validates the immutable ref and creates the annotated
`v<build-number>` tag only when exact-byte publication is authorized. It never merges either branch.
Release and hotfix merge-backs remain explicit, no-squash, `--no-ff` operations.

After publication and the manual merges, run `stable-backport` in
`verify-release-completion` mode. Missing main/develop reconciliation and incomplete hotfix
merge-back remain carried blockers for the next train. The release/hotfix candidate is the merged
tip in both independent no-ff merge records; the later `main` merge commit is not the tip merged
into `develop`.

See the [Stable 1.0 maintenance release and security hotfix
path](stable-1.0-maintenance-release-and-hotfix-path.md) for the complete lineage, authorization,
publication, and recovery rules. See the [Stable 1.0 backport and release-train
runbook](stable-1.0-backport-and-release-train-governance.md) for intake, change accounting,
candidate handoff, and reconciliation.
