# Rules reference

Read for Rules. Commands and unlinked source paths are relative to the repository root.

## Rules
- Release branches are `release/<build-number>` and must be based on `develop`.
- The build number is a single integer in `build.gradle.kts` (e.g., `version = 2`).
- Tag the release as `v<build-number>` on the release branch.
- Merge `release/*` into `main` and back-merge into `develop` using **no squash** and `--no-ff`.
- Stabilization only: allow critical fixes/docs/release tasks; avoid large refactors.
- Do not rebase/squash release merges.
- Stable 1.0 is a product/API milestone, not a semantic project version. Keep the integer build and
  `v<build-number>` tag model; never introduce `1.0.0`.
- For Stable 1.0, freeze with `stable-rc` and promote that exact product with `stable-ga`. Do not
  rebuild, re-sign, rewrite the catalog, or create the GA tag/Release outside the explicitly
  protected publication operation.
- Treat Stable catalog ceremony and network-primary publication as a separate PR-293 protected
  authority layered on the exact RC/GA bytes. Keep catalog, first-party app, reviewer, and recovery
  keys distinct; keep the offline recovery key out of routine signing; and retain Stable GA's HTTPS
  observations when adding the public Crypta USK primary and independent mirror. Restrict the
  mutation job to the dedicated protected `cryptad-stable-catalog-publication` self-hosted runner;
  its managed localhost daemon, shared filesystem identity, and matching form-password secret are
  provisioning prerequisites. Require credential-free daemon and Platform API contract checks
  before secrets enter the job, and do not build, start, restart, or stop the daemon from the
  release workflow. Follow
  `docs/stable-1.0-catalog-publication-and-key-ceremony.md`.
- After Stable 1.0 GA, use `stable-maintenance` for both routine maintenance and security hotfix
  candidates. It builds and freezes one new integer-build candidate; the protected maintenance
  workflow publishes only those authorized bytes and never merges the branch.
- Before either Stable maintenance lane reaches `stable-maintenance`, use `stable-backport`.
  Authenticate the latest single-chain predecessor, classify every fix, bind inherited,
  clean-cherry-pick, or reviewed manual-conflict provenance, carry prior obligations, and require
  complete zero-unaccounted candidate coverage. The release-train authorization approves candidate
  composition only; it never authorizes publication.
- Use `docs/cryptad-release-workflow-and-runbook.md` as the detailed release-readiness source of
  truth. Current release gates include the release certification report, first-party app
  staging/signing/verification, first-party beta catalog and trusted app-review receipt smoke,
  app-review governance/reviewer-key/transparency-log evidence, app-owned UI design-system/lint
  smoke, Platform API 1.0 stable baseline, target-stability, and stable breaking-change evidence,
  app-vault capability evidence, generated-document insert evidence, content-fetch evidence,
  durable content-subscription evidence, shared app-network budget and network-scale soak evidence,
  durable app-data and app-data backup/restore evidence, app-service
  registry/grant/dependency/grant-bundle evidence, Trust Graph Local RC evidence, Site
  Publisher/Profile Publisher/Social Inbox RC/Feed Reader/Trust Graph Local RC reference-app
  evidence, app platform beta docs/program evidence, third-party developer beta evidence,
  multi-node beta soak and upgrade drill evidence, live USK catalog publication evidence,
  catalog operations and mirrors evidence, production beta artifact redaction evidence, production
  beta go/no-go dashboard evidence, waiver validation, and
  `production-security.response-runbook` when app artifacts ship, app-update
  lifecycle/scheduler/rollback and app-data migration contract evidence, `crypta-app` developer
  beta toolkit smoke, operator RC
  recovery/support evidence, legacy plugin freeze evidence, legacy-admin retirement/removal Wave
  1-5 and final-surface evidence, Hyphanet interop smoke/soak evidence, and the packaged-node
  performance smoke.

---
