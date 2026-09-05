# CI and release notes reference

Read for CI and release notes. Commands and unlinked source paths are relative to the repository root.

## CI and release notes

- `.github/workflows/ci.yml` runs `interop-smoke` on push/PR, `interop-extended` on schedule/manual,
  interop self-tests on the multi-OS matrix, performance self-tests on the multi-OS matrix,
  release-certification self-tests on the multi-OS matrix, and `performance-smoke` on
  schedule/manual. Certification self-tests allow 30 minutes on Ubuntu and macOS and 60 minutes on
  Windows; keep workspace paths canonical before comparing absolute paths across those runners.
- PR-294 external-pilot evidence is a separate later operational class:
  `third-party-pilot.external-developer`, `third-party-pilot.bundle-signature`,
  `third-party-pilot.reviewed-install`, `third-party-pilot.rejected-resubmission`,
  `third-party-pilot.caution-consent`, `third-party-pilot.catalog-publication`,
  `third-party-pilot.update-rollback`, `third-party-pilot.transparency`, and
  `third-party-pilot.redaction`. Do not make historical Stable GA depend retroactively on these
  rows, and do not map sample, fixture, workflow-definition, intake install-smoke, partial
  publication, or incomplete cleanup evidence to operational completion. Use
  `docs/stable-1.0-external-third-party-app-pilot.md` and the `stable-third-party-pilot` command.
  Authenticate the runtime's exact normal Stable, canonical PR-293 catalog, and dedicated pilot
  registry digests independently. Expired, revoked, or cleaned-up pilot trust may block external
  subjects only; it must not block ordinary Stable app or catalog verification.
  At pilot closeout, derive PR-293's expected catalog subject from the mutually bound PR-291
  selected RC, PR-292 subject inventory, and exact selected-RC freeze. Never learn revision,
  edition, catalog/signature digest, or signer expectations from the PR-293 result being verified.
- PR-295 federated-catalog evidence is another prospective operational class. Use
  `docs/stable-1.0-federated-catalog-discovery-and-trust.md` and the single
  `stable-federated-catalog` command. Keep descriptor/endorsement verification, local trust,
  conflicts, protected runtime observation, and closeout as distinct stages. Endorsements remain
  non-transitive hints; they cannot create trust or reputation. Operational closeout must
  authenticate the exact original PR-291, PR-292, PR-293, and PR-294 coordinates and one signed,
  fresh, non-partial runtime observation. Fixture, sample, self-test, checked-in manifest,
  workflow source, reupload, upload success, digest-only binding, or partial cleanup cannot produce
  operational federation completion. A protected node-side runtime producer must select its
  adapter digest and observer identity from its protected environment, authenticate the exact
  confined source attempt, and publish distinct immutable observation and signed-receipt artifacts.
  The evidence producer must authenticate that runtime producer's exact attempt, protected job and
  environment deployment, artifact names and digests, and independently bound observer identity
  before upload. The coordinator may import only the canonical artifact from the allowlisted
  `stable-1.0-federated-catalog-evidence.yml` producer: authenticate its exact attempt, protected ref
  and commit, dispatch actors, successful producer job, protected environment deployment, artifact
  ID/name, and archive digest before extraction. Do not make historical Stable GA or earlier
  PR-293/PR-294 evidence depend retroactively on PR-295.
- PR-296 Platform API 1.x compatibility operations use the single side-effect-free
  `stable-platform-api-1x` command and
  `.github/workflows/stable-1.0-platform-api-1x-compatibility.yml`. Its only evidence source is the
  fixed protected `.github/workflows/stable-1.0-platform-api-1x-evidence.yml` producer; authenticate
  the producer run, exact successful job, protected environment deployment, actors, source, and
  artifact ownership/name/digest/time bounds before extraction. The static execution template must
  leave runtime evidence and authority null. The allowlisted
  `.github/workflows/stable-1.0-platform-api-1x-runtime-observation.yml` producer must first verify
  the exact static matrix and then use only the digest-pinned adapter and daemon access selected by
  its protected managed-node environment. The evidence producer independently authenticates that
  exact runtime run, successful job, protected deployment, source, artifact ownership, and
  observation bytes, then constructs the runtime authority binding locally. The evidence producer
  must also authenticate every bound PR-291 through PR-295 and previous Platform API run attempt,
  exact job, protected deployment, artifact, and summary bytes; copying local summaries is not
  authentication.
  Preserve the exact Platform API 1.0 freeze while verifying a digest-chained per-release contract
  ledger, conditionally required proposal and graduation evidence, history-bound monotonic
  deprecation clocks, static app matrix, and bounded runtime observation. Derive proposal
  membership, graduation semantics, and matrix verdicts from the accepted registry and exact
  history snapshots rather than producer labels. Resolve the
  oldest-supported matrix role through the ledger's authenticated support projection rather than
  assuming the genesis release remains supported. Authenticate the independently re-fetched Stable
  lifecycle receipt and exact descriptor bytes, then derive the minimum `current-stable` or
  `supported-maintenance` build; the ledger's own oldest-supported field is not authority. New
  deprecation rows must match their first authenticated history notice and cannot begin removed or
  backdated. This authority version rejects operational lifecycle states for future baselines until
  a separately reviewed protected activation receipt exists. A production runtime pass likewise
  requires an allowlisted protected runtime producer run/job/deployment/artifact binding; a
  self-digested observation is not evidence. Treat checked-in
  manifests, repository history files, fixtures, and self-tests as non-operational. Only exact
  authenticated PR-291 through PR-295 roots may complete closeout. Do not claim a Platform API 1.1
  activation or the PR-300 long-duration cross-version soak.
  A nonterminal future definition requires its exact singular version-1 proposal and app-matrix
  binding; pure `1.0` history may omit a proposal, while multiple simultaneous future definitions
  require a later schema. Reject member descriptors introduced after a definition's claimed
  first-complete contract and graduation observations later than the execution evaluation time.
  Authenticate current authorities against the current execution source ref and previous-history
  authority against its accepted ledger head's source ref.
  Treat the app matrix as a derived report, not an app inventory: require a separate closed
  authority-root-bound subject inventory, compare every identity, digest, target, range, and
  capability field before computing a verdict, and derive required coverage from that inventory
  plus the policy-fixed first-party IDs. A PR-292/294/295 summary that omits those fields cannot
  authenticate them by implication.
- `.github/workflows/release-certification.yml` runs scheduled/manual/release-ref certification,
  uploads sanitized certification artifacts, and uses `release-candidate` mode for `release/**`
  branches and `v*` tags. When the manual extended gate produces
  `build/interop-extended/summary.json`, the generated manifest must bind it as
  `inputs.interopExtended`. Interop smoke, extended interop, and performance inputs must be omitted
  when their tolerated producer step did not write a summary so aggregation can record the missing
  gate instead of failing during manifest input loading.
- `.github/workflows/production-beta-release.yml` runs the production beta pipeline in
  `developer-dry-run` for PR-safe checks, `release-candidate` for release refs/manual dispatch, and
  protected `production-beta` only when release secrets, live-node inputs, and a real artifact base
  URI are available. Protected production dispatches must also require and materialize
  `third_party_intake_summary`, bind it as `inputs.thirdPartyIntake`, and set
  `requirements.thirdPartyIntake=true`; the non-release sample flow cannot satisfy this gate.
  Artifact uploads and job-summary dashboard publication must stay gated on the
  production-beta redaction summary, `go-no-go-redaction-report.json`, and any generated Stable
  readiness redaction status passing. PR and developer-dry-run manifests must omit interop and
  performance input paths when those producer steps did not run. Release-candidate history is
  required only when a history artifact is supplied or policy explicitly requires it; protected
  production-beta runs continue to require candidate-bound history.
- `.github/workflows/stable-1.0-rc-release.yml` is the protected RC producer. It authenticates
  candidate-bound inputs, runs `stable-rc`, uploads only the passing public component, and performs
  no GA tag/Release/catalog publication. Its concurrency key is shared with Stable GA for the same
  release/build so a refreeze cannot race publication.
- `.github/workflows/stable-1.0-ga-promotion.yml` separates a read-only validation job from an
  explicitly dispatched protected publication job. Treat external validation and authorization
  evidence as protected producer artifacts with attested digests. Reauthenticate the latest RC
  lineage, release branch, evidence freshness, authorization expiry, artifact base, and catalog
  targets immediately before mutation boundaries. Conflict and recovery paths must inspect and
  record public state without creating or repairing it. Matching existing tag/Release/assets are
  idempotent only after the same checks pass; mismatches produce a verified failure receipt.
- Release notes should mention interop, performance, or certification gate changes only when they
  affect release readiness, operator confidence, app/platform behavior, or packager workflows.
