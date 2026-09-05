# Release certification gate reference

Read for Release certification gate. Commands and unlinked source paths are relative to the repository root.

## Release certification gate

- `stable-legacy-plugin-migration` validates the narrow Sharesite pilot's closed sanitized local
  observations. Local claims remain unverified; its runtime/closeout modes fail closed while a
  protected migration producer is unavailable. Keep the PR-296 subject-projection prerequisite
  separate from successful offline conversion or local data commit. Synthetic upstream-writer
  vectors and executable tests cannot claim real-user migration or network publication. Never
  upload private snapshots, conversion packages, plans, backups, labels, old read URIs, or raw
  private comparison hashes. See `docs/real-legacy-plugin-migration-pilot.md`.

- `tools/release-certification/certify.py release-certification` aggregates interop, performance,
  app-platform, network-scale soak, multi-node beta soak, catalog, app-owned UI, operator beta
  recovery, optional live-network beta certification, legacy-admin retirement, and CI metadata into:

```text
build/release-certification/<release-id>/release-certification/summary.json
build/release-certification/<release-id>/release-certification/report.md
build/release-certification/<release-id>/release-certification/redaction-report.json
build/release-certification/<release-id>/release-certification/artifacts/
build/release-certification/<release-id>/network-scale-soak/summary.json
build/release-certification/<release-id>/multi-node-beta/run/summary.json
build/release-certification/<release-id>/live-network-beta/summary.json
build/release-certification/<release-id>/security-response/
```

- `tools/release-certification/certify.py production-beta` is the top-level production beta
  app-ecosystem release pipeline. It orchestrates Gradle build/install tasks, first-party app
  staging/signing/verification, signed catalog and review receipt generation, app-platform smoke,
  live-network beta smoke when required, network-scale soak, multi-node beta soak and upgrade
  evidence, ecosystem RC certification, final artifact redaction, the production beta go/no-go
  dashboard, and public archive creation below
  `<out-root>/<release-id>/production-beta/artifacts/legacy/`.
  `developer-dry-run` is CI-safe and non-release; `release-candidate` is strict but may use
  non-production signing labels; `production-beta` requires production signing, a complete
  in-pipeline Gradle build/stage/sign run, a public HTTPS artifact base URI, live-network evidence
  unless the explicit emergency skip is used, passing multi-node beta evidence, and a clean
  workspace before `promotionReady` can become true. Emergency build skips must leave
  `nonRelease=true` and fail the build-complete promotion gate.
- `tools/release-certification/certify.py go-no-go` is the final release-manager
  dashboard generator for production beta launch candidates. It consumes sanitized production beta,
  release-certification, ecosystem matrix, app-platform, live-network, network-scale, multi-node,
  security-response, and waiver inputs; emits JSON, Markdown, and a dashboard redaction report; and
  decides only `go`, `no-go`, or `go-with-waivers`. Production-beta mode fails closed for
  mandatory launch evidence, invalid or expired waivers, unsafe artifact hygiene, fixture/test
  signing, non-release summaries, dirty workspaces, and redaction findings.
- `tools/release-certification/certify.py stable-readiness` is the Stable 1.0 readiness gate. It
  consumes production beta outputs, go/no-go output, release certification, app-platform evidence,
  multi-node and network-scale soak, security drill summaries, public beta known issues, policy,
  known limitations, and Stable-scoped waivers. Required consumers must reject malformed summaries,
  mismatched `releaseId`, missing `stable-1.0.*` evidence rows, failed redaction, stale security or
  soak evidence, and non-release production beta inputs.
- `tools/release-certification/certify.py stable-rc` is the only canonical Stable 1.0 RC execution
  and freeze command. It reuses the `stable-review` profile, executes the required production and
  readiness stages, freezes the candidate, emits the deterministic product and outer RC archives,
  records checksums/provenance/limitations/API/content-profile/catalog/app identities, and verifies
  post-package drift. Do not create a second RC format or promote any result with
  `promotionReady=false`, `nonRelease=true`, incomplete freeze, drift other than `no-drift`, or a
  decision outside `go` and policy-compliant `go-with-waivers`.
- `tools/release-certification/certify.py stable-ga` is side-effect-free. It authenticates the
  selected RC summary, freeze/sidecar, product/archive/checksums/provenance, latest successful
  protected freeze/refreeze lineage, and frozen catalog/app/API/profile identities. It requires
  production post-freeze evidence and an explicit protected authorization bound to the exact
  digests, emits deterministic promotion/publication/maintenance records, and verifies a supplied
  publication receipt. It never creates a tag, GitHub Release, branch, catalog update, or network
  insert. Any payload change must return to `stable-rc` refreeze.
- `tools/release-certification/certify.py app-platform` produces the app-platform summary consumed by
  the aggregator. It keeps `--self-test` offline and Python-only, including source/test evidence
  for the Platform API contract, Platform API 1.0 stable baseline, compatibility-window metadata,
  previous contract snapshot policy, stable descriptor deprecation/removal windows,
  experimental-graduation policy, manifest/catalog target stability, first-party stability
  declarations, stable reference docs, app-vault capability docs,
  signed catalogs, first-party maintenance metadata, app-store submission package and pre-review
  evidence, catalog security advisory/denylist evidence, catalog operations and mirrors evidence,
  trusted app-review receipt/revocation evidence, unified user-consent snapshot/digest/audit
  evidence, app-owned UI origin behavior, app UI design-system/lint evidence, live USK catalog
  publication, Site Publisher
  reference-content coverage, Profile Publisher identity-profile coverage, Feed Reader
  content-fetch, subscription, app-data, and app-data migration coverage, Social Inbox RC
  multi-source/threading/read-state/local-filter/export/trust-grant coverage, Trust Graph Local RC
  durable exchange, import-preview, duplicate-issuer/conflict, anchor-lifecycle, bounded-score, and
  app-data migration coverage, app-data backup/restore portability evidence, app-service
  registry/grant/dependency/grant-bundle/redaction coverage, generated document insert/content-fetch
  and trust redaction coverage, app-network budget source evidence, third-party developer beta
  docs, template, sample-flow, checklist, compatibility, feedback, plugin-migration, and redaction
  evidence, legacy plugin freeze evidence, app-review governance/reviewer-key/transparency-log
  evidence, public-beta security hardening
  evidence, operator beta dashboard/recovery/support-bundle evidence, legacy-admin
  retirement/removal Wave 1-5 and final-surface evidence, production security response runbook
  evidence, sandbox provider selection, and app-update lifecycle/scheduler/rollback.
- `tools/release-certification/certify.py network-scale-soak` produces the deterministic simulated
  network-scale soak summary consumed by the aggregator. Normal PR and CI runs must use simulated
  time instead of a literal 24-hour test. Release-candidate runs may attach an external
  `simulated-rc-soak` or `live-rc-soak` summary with the same redacted schema.
- `tools/release-certification/certify.py multi-node-beta` produces deterministic multi-node beta
  soak and upgrade/rollback/backup drill evidence consumed by the aggregator and production beta
  pipeline. Normal PR and CI runs use the checked-in simulated topology. Release-manager runs may
  attach an external `simulated`, `hybrid`, or `live` summary with the same redacted schema.
- `tools/release-certification/certify.py live-network-beta` is the explicit release-manager live
  network collector. Its self-test is offline and deterministic, but normal runs may call only a
  validated localhost node and use env/protected-file fixtures for form passwords, catalog expected
  key ids, content/feed/profile/trust URIs, and private insert material. Required mode must fail
  closed for missing fixtures, failed required evidence, stale app principals, cleanup failures, or
  redaction findings.
- `tools/release-certification/certify.py app-platform-docs` produces deterministic app-platform
  beta docs evidence for the developer portal, tutorials, beta program, third-party developer beta
  docs, issue templates, relative Markdown links, and docs redaction checks.
- With `execution.collectEvidence=true`, the unified command runs candidate-scoped app-platform,
  network-scale, multi-node, and security-drill collectors before aggregation. Set the matching
  `inputs` path to attach external evidence instead. `requirements.liveNetwork=true` or
  `execution.collectLiveNetwork=true` also runs the candidate-scoped live collector.
  Internally collected component directories are rebuilt on every invocation, including runs with
  `output.reset=false`; only explicit manifest inputs are reusable. Strict release-candidate and
  production-beta app-platform collection normally runs the first-party Gradle sign/verify tasks.
  PR-mode collection automatically skips those tasks; other modes may use an explicit
  `execution.skipGradle=true`. Strict runs with that explicit skip remain non-promotable or
  emergency evidence as enforced by production policy. Reused run workspaces must reject
  symlinked component or artifact directories and any resolved path outside the marked run root.
  Apply the same confinement checks to nested engine output directories such as
  `artifacts/legacy`. Before recollecting evidence, reject an already completed aggregate so a
  failed rerun cannot leave old aggregate output beside newly rebuilt component evidence.
  Manifests must remain non-secret in both field names and scalar values, published input paths
  must be reduced to `<repo>/...` or `<external-input>`, and a nonzero component process exit must
  always produce and require failed evidence.
  Legacy outputs without explicit redaction metadata require a complete safe payload scan; false
  direct or nested guarantees fail closed. Validate every component path segment before cleanup so
  intermediate symlinks are never followed, and preserve production `goNoGo.decision` in the
  common envelope result.
  Inputs mapped to unified components must require candidate-bound v2 envelopes of their assigned
  kind, profile-compatible policy, component identity, and declared candidate version. Strict
  profiles must reject PR, nightly, and developer-dry-run evidence even when the kind and release ID
  match. Stable review may consume production-beta evidence, and release or production aggregation
  may consume an explicit Stable-review summary; do not add other cross-profile transitions.
  Explicit external or non-envelope interop, performance, ecosystem-matrix, and third-party intake
  inputs retain their native JSON contracts. Policy command modes must match the mode derived from
  `release.profile` so command configuration cannot weaken or mislabel strict evidence. An
  explicitly attached optional live-network summary enables the live gate without making it
  required. Reject argparse abbreviations of every adapter-controlled option before forwarding
  command escape-hatch arguments. Normalize known negative live redaction facts such as
  `rawBodiesStored: false` into true positive v2 guarantees without accepting unsafe true values.
  Migration and fallback scans must recursively reject payload-bearing sensitive JSON field names
  and all local POSIX, Windows drive, and UNC absolute path forms outside public API route shapes.
  They must accept complete canonical `<repo>/relative/path` placeholders produced by existing
  release summaries without accepting traversal, malformed separators, or mixed absolute paths.
  Workflow dispatches that attach candidate-bound multi-node, security-drill, history, or Stable
  v2 summaries must require the matching explicit candidate release ID before generating a manifest.
  Generate workflow manifest `release.version` from the checked-out build with
  `./gradlew -q printVersion`; require attached v2 evidence to carry that same candidate version.
  Reject attached v2 inputs for strict hand-authored manifests when `release.version` is null;
  never treat an absent strict candidate version as a wildcard.
  Required-but-missing evidence remains an engine gate: for example,
  `requirements.history=true` without `inputs.releaseHistory` must load successfully and produce a
  failed release-candidate certification aggregate and report.
  Before extracting an attached v2 input, scan its legacy payload independently of the claimed
  outer redaction result. Scan and digest-check every referenced security-drill sidecar, copying
  sidecars from the effective verification input directory. Preserve the validated envelope
  identity when unwrapping multi-node evidence, and use configured live-network and network-scale
  input paths when producing downstream production extracts.
  If a legacy engine exits early, returns nonzero, or emits unsafe fallback content, remove unsafe
  raw copies from the publishable workspace and emit only sanitized failed evidence with
  `promotionReady=false`. Shared output writers and extracted-input directories must reject
  symlinks and paths outside the marked workspace. Completed component and migration summaries are
  immutable unless the manifest explicitly requests a safe reset.
  Keep `certify.py` as a thin entry point and split engine modules before they exceed 5,000 lines;
  `self-test core` enforces the source-size boundary.
- Normal local commands:

```bash
python3 tools/release-certification/certify.py self-test all
cp tools/release-certification/manifests/release-candidate.example.json \
  build/release-candidate.json
# Replace every placeholder before running candidate-bound commands.
python3 tools/release-certification/certify.py security-response verify --manifest build/release-candidate.json
python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
cp tools/release-certification/manifests/production-beta.example.json \
  build/production-beta.json
# Replace every placeholder before running the protected pipeline.
python3 tools/release-certification/certify.py production-beta --manifest build/production-beta.json
cp tools/release-certification/manifests/stable-1.0-rc.example.json \
  build/stable-1.0-rc.json
# Replace every placeholder and use protected production inputs.
python3 tools/release-certification/certify.py stable-rc \
  --manifest build/stable-1.0-rc.json
cp tools/release-certification/manifests/stable-1.0-ga.example.json \
  build/stable-1.0-ga.json
# Bind the selected exact RC, post-freeze evidence, and protected authorization.
python3 tools/release-certification/certify.py stable-ga \
  --manifest build/stable-1.0-ga.json
```

- Release-candidate mode fails when required evidence is missing, skipped, malformed, wrong-mode,
  or failing unless a release-manager waiver is recorded. Required app-platform evidence now
  includes `app-platform.first-party`, `app-platform.devtools-cli`,
  `app-platform.developer-beta-toolkit`, `app-platform.docs-portal`,
  `app-platform.beta-program`, `app-platform.beta-tutorials`,
  `app-platform.docs-redaction`, `app-platform.signed-bundles`,
  `third-party-developer.beta-program`, `third-party-developer.docs`,
  `third-party-developer.template`, `third-party-developer.sample-app-flow`,
  `third-party-developer.submission-checklist`, `third-party-developer.compatibility-window`,
  `third-party-developer.feedback-workflow`, `third-party-developer.plugin-author-migration`,
  `third-party-developer.redaction`, `catalog.smoke`,
  `app-catalog.first-party-beta`, `catalog.production-channels`,
  `catalog.operations-and-mirrors`, `app-catalog.first-party-maintenance-policy`,
  `catalog.security-advisories`,
  `catalog.version-denylist`, `app-review.receipt-revocation`,
  `app-review.reviewer-key-compromise-flow`, `app-update.security-denylist-gates`,
  `web-shell.security-advisory-trust-warnings`,
  `ecosystem-security.advisory-revocation-redaction`, `production-security.response-runbook`,
  `platform-api.contract`,
  `platform-api.stable-baseline`, `platform-api.stable-breaking-change-check`,
  `platform-api.compatibility-window`, `platform-api.previous-contract-snapshot`,
  `platform-api.deprecation-window-policy`, `platform-api.experimental-graduation-policy`,
  `platform-api.manifest-target-stability`,
  `platform-api.first-party-stability-declarations`, `platform-api.stable-reference-docs`,
  `app-vault.capabilities`,
  `app-platform.identity-profile-publish`, `app-platform.generated-document-insert`,
  `app-platform.content-fetch`, `app-platform.content-subscriptions`,
  `network-content.subscription-scheduler`, `app-platform.durable-app-data-store`,
  `app-data.backup-restore-portability`, `app-platform.trust-graph-preview`,
  `app-platform.trust-graph-rc-scope-and-safety`, `app-platform.trust-graph-durable-store`,
  `app-platform.trust-graph-exchange`, `app-platform.trust-statement-signing`,
  `app-platform.social-message-signing`, `app-services.registry`, `app-services.grants`,
  `app-services.dependency-graph`, `app-services.grant-bundles`,
  `app-services.grant-expiry-renewal`, `app-services.provider-revalidation`,
  `app-services.trust-score-provider`, `app-services.web-shell`, `app-services.redaction`,
  `app-services.dependency-redaction`,
  `app-ui.design-system`, `app-ui.lint`, `app-ui.first-party-adoption`, `app-ui.smoke`,
  `reference-apps.content`, `reference-app.profile-publisher`,
  `reference-app.profile-publisher-app-data`, `reference-app.feed-reader`,
  `reference-app.feed-reader-subscriptions`, `reference-app.feed-reader-app-data`,
  `reference-app.social-inbox`, `reference-app.social-inbox-signed-message`,
  `reference-app.social-inbox-subscriptions`, `reference-app.social-inbox-app-data`,
  `reference-app.social-inbox-trust-annotations`, `reference-app.social-inbox-service-grant`,
  `reference-app.social-inbox-rc-threading`, `reference-app.social-inbox-service-dependency`,
  `migration.social-mail-preview`, `reference-app.trust-graph`,
  `reference-app.trust-graph-durable-exchange`, `reference-app.trust-graph-app-data-preview`,
  `legacy-plugin.freeze-policy`,
  `legacy.retirement`, `legacy-admin.removal-wave-1`, `legacy-admin.removal-wave-2`,
  `legacy-admin.removal-wave-3`, `legacy-admin.removal-wave-4`,
  `legacy-admin.removal-wave-5`, `legacy-admin.final-admin-surface`,
  `legacy-admin.browse-retained`, `legacy-admin.emergency-fallback-retained`,
  `apphost.sandbox-provider`,
  `app-update.lifecycle`,
  `app-update.scheduler`, `app-update.rollback`, `app-update.live-catalog-refresh`,
  `app-update.data-migration-contract`,
  `public-beta-security.*`, `operator-beta.*`, `operator-rc.*`, `app-review.trusted-receipts`,
  `app-review.policy`, `app-review.governance`, `app-review.reviewer-key-lifecycle`,
  `app-review.transparency-log`, `app-review.review-history-api`,
  `app-review.first-party-catalog`, `app-review.first-party-review-chain`, and
  `network-scale.app-network-budget`, `network-scale.content-fetch-budget`,
  `network-scale.subscription-budget`, `network-scale.queue-pressure-backoff`,
  `network-scale.trust-graph-import-budget`, `network-scale.social-inbox-multi-source-soak`,
  `network-scale.redaction`, `network-scale.rc-soak-summary`, `multi-node-beta.soak`,
  `multi-node-beta.upgrade-drill`, `multi-node-beta.catalog-channel-update`,
  `multi-node-beta.app-install-update-rollback`, `multi-node-beta.app-data-migration`,
  `multi-node-beta.backup-restore`, `multi-node-beta.subscription-pressure`,
  `multi-node-beta.trust-graph-import`, `multi-node-beta.social-inbox-multi-source`,
  `multi-node-beta.support-bundle-drill`, `multi-node-beta.redaction`, and
  `release-certification.ecosystem-matrix`, `production-beta.go-no-go-dashboard`,
  `production-beta.go-no-go-decision`, `production-beta.waiver-validation`,
  `production-beta.dashboard-redaction`, and `production-beta.launch-artifact-hygiene`.
- Platform API stable-history checks compare the stable baseline name/counts/lists, stable endpoint
  required-capability sets, stable endpoint action labels, stable endpoint app-process/app-browser
  access flags, and compatibility-window metadata. App-platform smoke evidence must also inspect
  `stableDescriptorDeprecations` and fail `platform-api.deprecation-window-policy` when a stable
  descriptor is deprecated or scheduled for removal without valid metadata, has a future
  `deprecatedSinceContractVersion`, or publishes a too-short `removalContractVersion` window. In
  production history mode, missing previous baseline, compatibility-window, or endpoint metadata is
  a blocker; developer dry runs may warn when no production history is available.
- `catalog.operations-and-mirrors` is deterministic source-level evidence. It must verify the
  primary-plus-mirrors model, mirror fallback with signed verification, stale/downgrade
  prevention, bounded verified revision history, explicit rollback re-verification, key-rotation
  status visibility, emergency advisory refresh support, Platform API/Web Shell wiring, docs
  coverage, and redaction without requiring live mirror infrastructure or production signing keys.
- Network-scale release-candidate evidence must be generated fresh by the wrapper or attached
  explicitly. Do not let the aggregator reuse stale default `network-scale-soak/summary.json`
  files across release workspaces.
- Multi-node beta release-candidate evidence must be generated fresh by the wrapper or attached
  explicitly. Do not use the checked-in self-test topology as production promotion evidence, and do
  not let the aggregator reuse stale default `multi-node-beta-soak/summary.json` files across
  release workspaces.
  For developer and release-candidate production-pipeline runs, `runMultiNodeSoak=true` without an
  explicit topology config invokes `multi-node-beta run` without `--config`, which selects the
  checked-in PR-safe default topology. When `inputs.multiNodeSoakConfig` is set, unified
  multi-node `plan` and `run` actions must pass that exact path as `--config`; command escape-hatch
  arguments cannot replace the structured topology. Multi-node and security-response passthrough
  output flags are likewise reserved: manifests cannot override `--out`, `--out-dir`, `--report`,
  `--summary-out`, or `--release-notes-out`, and generated files must remain candidate-scoped.
  A required multi-node run whose effective configured or overridden mode is `live` must propagate
  `--require-live`; deterministic fallback evidence with zero reachable localhost nodes cannot be
  promotion-ready.
  Protected `production-beta` promotion still requires a production topology config or attached
  summary.
- Stable readiness generated by the production beta wrapper must use
  `evidence/stable-readiness-multi-node-beta-soak.json` and
  `evidence/stable-readiness-network-scale-soak.json`, not the compact generic soak extracts. Those
  Stable-specific files preserve freshness metadata for the readiness gate. Generated multi-node
  Stable extracts must also carry the selected manifest `release.id`; do not derive candidate
  identity from `currentCandidate.version` when an explicit release ID exists.
- Stable readiness redaction is non-waivable. Keep dashboard redaction status separate from release
  artifact redaction status, and gate archive/upload decisions on both plus Stable readiness
  redaction when Stable artifacts are generated. Do not forward production beta go/no-go waiver
  files into Stable validation unless the waiver file is explicitly Stable-scoped.
- `live-network-beta.*` evidence is release-blocking only when manifest
  `requirements.liveNetwork=true`. When live-network beta is disabled, the
  aggregator must ignore stale live summaries and must not copy stale live artifacts into the
  release record.
- Live-network beta runs must use only `http://127.0.0.1:<port>`,
  `http://localhost:<port>`, or `http://[::1]:<port>` node URLs without credentials, query
  strings, fragments, redirects, or proxy forwarding. Form passwords, app browser sessions,
  private insert URIs, and app-service grants must not leak into artifacts, shell history, or
  proxy traffic.
- Do not publish private signing keys, form passwords, app tokens, browser-session tokens, raw
  reviewer keys, raw trusted reviewer public key bytes, raw request bodies, raw feed bodies, raw
  trust documents from real users, raw social message bodies, raw fetched social documents, raw
  incident artifacts, raw app-service subject URIs, provider app data, raw app-data values, raw
  update/rollback command output, command lines containing secrets, CI secret values, queue HTML,
  budget-store file paths, private insert URIs, non-localhost endpoint metadata, catalog scratch
  paths, staged bundle paths, rollback backup paths, multi-node node profile paths, previous
  candidate archive paths, UI lint report paths, or other unsanitized local paths. The aggregator
  filters `artifacts/private-insert-uris.json` even when interop summaries reference it.
- Treat docs redaction findings as non-waivable blockers. Link-only or presence-only docs gaps can
  be waived by a release manager when policy allows, but raw secret/path findings must keep the
  evidence and matrix row failing.
