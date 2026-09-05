# Release certification smoke reference

Read for Release certification smoke. Commands and unlinked source paths are relative to the repository root.

## Release certification smoke

- `tools/release-certification/certify.py app-platform` is the app-platform evidence collector for
  release certification. It validates first-party staged bundles, static UI/SDK coherence,
  design-system adoption, strict UI lint JSON evidence, `crypta-app init/validate/pack/dev/test`,
  Platform API contract snapshots, Platform API 1.0 stable-baseline and target-stability evidence,
  app-vault capability evidence, generated document insert
  evidence, bounded content-fetch/subscription evidence, durable app-data and app-data
  backup/restore evidence, app-network budget and network-scale soak evidence, signed bundle
  evidence, signed catalog/live USK publication evidence,
  first-party beta catalog metadata, app-store submission/pre-review evidence, third-party
  developer beta docs, template, sample flow, checklist, compatibility, feedback,
  plugin-migration, and redaction evidence, trusted app-review
  receipt evidence, sandbox-provider evidence, app-update lifecycle/scheduler/rollback and
  app-data migration contract evidence, Site Publisher/Profile Publisher/Social Inbox RC/Feed
  Reader/Trust Graph Local RC reference-app evidence, unified consent evidence, app-service
  registry/grant/dependency/grant-bundle/redaction evidence, legacy plugin freeze
  evidence, app-review governance and local transparency-log evidence, public-beta security
  hardening evidence, catalog operations and mirrors evidence, operator beta
  dashboard/recovery/support-bundle evidence, operator RC recovery/support workflow evidence,
  production security response runbook evidence,
  legacy-admin retirement Wave 1-5/final-surface state, and optional localhost-only live AppHost
  lifecycle evidence.
- `tools/release-certification/certify.py live-network-beta` is the explicit release-manager
  live-network beta evidence collector. It validates a prepared localhost node, live catalog
  source/key metadata, app-principal browser-session workflows, content/feed/profile/trust
  fixtures, optional app-service scoring, timing metadata, cleanup, and redaction without leaking
  secrets or becoming a normal CI dependency.
- `tools/release-certification/certify.py stable-third-party-pilot` is the side-effect-free
  external-pilot authenticator. Keep its `third-party-pilot.*` operational evidence separate from
  sample-oriented `third-party-intake.*` rows. A fixture can reach only
  `fixture-verification-complete`; operational completion requires signed external handoff,
  PR-293 reviewer/catalog receipts, the bounded pilot publisher approval, the existing
  live-network collector receipt, exact rollback/cleanup, and PR-291/292/293 roots.
- External pilot trust uses a dedicated or ephemeral app registry and
  `PilotPublisherVerificationPolicy`. Bind the exact normal Stable, canonical PR-293 catalog, and
  pilot registry byte digests; keep all three roles disjoint by key id and public key. Pilot cleanup,
  expiry, or revocation must disable only the approved external publisher, not ordinary Stable app
  or catalog verification. Never add the publisher key silently to the normal Stable registry,
  authorize another app/version/sidecar, or let intake `install-smoke` substitute for a live AppHost
  drill.
- External-pilot closeout must derive the expected PR-293 catalog subject from the authenticated
  PR-291 selected RC, exact selected-RC freeze, and PR-292 subject inventory. Never use PR-293's own
  closeout subject as its expected revision, edition, catalog/signature digest, or signer.
- `tools/release-certification/certify.py stable-federated-catalog` is the side-effect-free PR-295
  verifier. Signed discovery and endorsement records are public hints only; they must not install
  keys, add sources, create trust, disclose subscriptions, or authorize publishers/reviewers.
  Runtime evidence must preserve catalog/app/reviewer/recovery role separation, classify hard
  conflicts without lexical trust decisions, keep updates pinned to installed origin, require
  explicit source/publisher-switch consent, restore origin with rollback, and isolate one
  catalog's suspension/revocation. Operational closeout requires exact authenticated PR-291,
  PR-292, PR-293, and PR-294 coordinates plus a signed non-partial protected runtime observation.
  Compose catalog/app-scoped publisher verification with any existing PR-294 pilot approval; do
  not replace the exact pilot app/version/sidecar boundary. Lifecycle source switching must carry
  an explicit target catalog and its exact preview digest through retained-plan verification before
  any migration dry run.
  Capture the authenticated catalog-origin subject in the retained install plan and reverify it
  before mutation. A legacy plan may carry non-federation-scoped context for that retained-plan
  check, but default nodes must not persist it as installed origin, pin updates, apply federation
  conflicts, or require source-switch consent. Commit federation-scoped catalog origin through
  AppHost together with bundle install/update so migration or health rollback always sees matching
  current/rollback slots; provenance write failure must leave or restore the prior bundle state.
  Before committing or restoring a catalog bundle, AppHost must compare the copied bundle's actual
  signing-key ID, canonical signing-key fingerprint, and signed content commitment with the stored
  origin; a broadly trusted signature plus matching manifest metadata is insufficient.
  AppHost interface defaults must reject catalog install/update and standalone origin persistence
  before bundle mutation. Dispatch rollback from the retained rollback slot: catalog provenance
  requires the authorized overload, while an untracked legacy slot retains the original
  `rollback(String)` compatibility path.
  Resource-consuming source-switch previews are host/operator-only form-password-guarded `POST`
  routes; never expose catalog download, extraction, or verification preparation through `GET`.
  Suspension blocks routine work but may authorize explicit rollback of exact retained bytes when
  the stable binding identity and current signer, catalog, channel, and historical lifecycle policy
  still match; revocation, removal, and pending state remain blocked. Fixtures and self-tests can
  reach only
  `fixture-verification-complete`.
- `tools/release-certification/certify.py stable-platform-api-1x` is the side-effect-free PR-296
  operations authority. Keep URL API `v1`, integer contract versions, daemon releases, and named
  stable baselines distinct. Its append-only history, proposal/graduation records, monotonic
  deprecation ledger, static app matrix, and bounded runtime observation never activate a future
  baseline or grant permissions. Fixture/self-test evidence can reach only
  `fixture-verification-complete`; operational closeout requires exact authenticated PR-291 through
  PR-295 roots. Platform API 1.0 membership and semantics remain immutable, and PR-300 owns the
  long-duration cross-version network soak.
  Before admitting a stable app, validate the selected `active` or `deprecated` baseline as a
  complete exact projection of the target contract, including the first-complete contract version
  and every endpoint authorization semantic. No member descriptor may have an introduction version
  later than the definition's claimed first-complete version; checking only the app's requested
  capabilities is not sufficient. Keep custom baseline-registry JSON closed at every registry,
  definition, endpoint, and lineage object so ignored or duplicate evidence fields cannot survive
  inspection.
  Bind current and predecessor deprecation ledgers to their exact history heads, derive removal
  blockers from the accepted baseline registry and app matrix, and select the oldest-supported
  matrix snapshot through an authenticated Stable lifecycle receipt and descriptor rather than
  ledger position or a caller-selected ledger field. Anchor every newly introduced deprecation row
  to its first authenticated history snapshot. The version-1 authority must reject future baseline
  activation until a dedicated protected activation receipt exists. Production runtime status must
  come from `.github/workflows/stable-1.0-platform-api-1x-runtime-observation.yml`, whose protected
  environment selects a digest-pinned managed-node adapter; the evidence producer must
  independently authenticate that run and construct its authority binding rather than accepting a
  self-sealed observation. Require the exact proposal and app-matrix binding whenever the registry
  carries a nonterminal future definition, and reject graduation observations later than the
  execution evaluation time.
  Never derive required app coverage from the matrix itself. Require a separate closed,
  authority-root-bound app-subject inventory, compare every matrix compatibility input against it,
  and derive required IDs from that inventory plus the policy-fixed first-party set. Existing
  PR-292/294/295 summaries that omit a complete compatibility projection are not substitutes for
  fresh authenticated subject evidence.
  Catalog install, update, staged apply, and source-switch preview must admit the exact signed
  staged manifest, never only advisory catalog compatibility metadata. If a catalog explicitly
  names a target baseline, its baseline/stability declaration must match the signed manifest;
  wholly undeclared legacy catalogs remain readable and the manifest remains authoritative.
  Explicit catalog target-baseline metadata requires the cumulative signed-catalog v7 format;
  preserve the closed v1-v6 formats without interpreting that field in older schema versions.
- `tools/release-certification/certify.py app-platform-docs` is the deterministic docs evidence
  collector for the app ecosystem beta portal, tutorials, beta program, issue templates, internal
  Markdown links, and docs redaction checks.
- `pr` mode must stay fast and offline-safe. It must not require a live node, signing keys, Hyphanet
  downloads, or production credentials.
- `release-candidate` mode treats missing required signed bundle/catalog/app-platform evidence as
  failing unless a release-manager waiver is recorded by the aggregator.
- Stable 1.0 readiness is a stricter promotion layer over production beta evidence. App-platform
  changes that affect Platform API stability, first-party app maturity, third-party intake,
  security response, legacy migration, public beta support, diagnostics redaction, or app-data
  migration/backup evidence must keep the corresponding `stable-1.0.*` readiness rows complete and
  redaction-safe.
- Stable RC freezes the selected signed catalog/app set, maintenance metadata, API contract/diff,
  content profiles, limitations, product archive, and provenance. Stable GA consumes those exact
  identities plus protected post-freeze install/upgrade/rollback/migration/backup/live/security/
  support evidence. It must prove `rcProductDigest == gaProductDigest`; it cannot regenerate app or
  catalog payloads.
- `stable-1.0-maintenance-baseline.json` is the post-publication comparison anchor for the Platform
  API 1.0 surface, stable catalog revision/key, app versions/bundles/reviews/data schemas,
  content-profile canonicalization, limitations, advisory/denylist/reviewer state, support, and
  legacy boundaries. Future maintenance or hotfix work compares against it rather than mutating it.
- Stable API release evidence must include stable capability names, stable endpoint identities,
  stable endpoint required-capability sets, stable endpoint action labels, and stable endpoint
  app-process/app-browser access flags, compatibility-window metadata, and descriptor-level stable
  deprecation/removal metadata.
  `platform-api.contract` details should include `stableDescriptorDeprecations`, and
  `platform-api.deprecation-window-policy` should expose descriptor-level errors/warnings for
  missing `deprecatedSinceContractVersion`, future deprecation starts, invalid
  `removalContractVersion`, and too-short removal windows. Production history checks fail closed on
  stable removals, required-capability changes, access regressions, missing current metadata,
  malformed stable descriptor deprecation metadata, or missing previous metadata when history is
  required.
- Keep app smoke self-tests Python-only and deterministic. Use fixtures or fake CLI helpers instead
  of network or Java dependencies for regression coverage where possible.
