# Ownership map reference

Read for Ownership map. Commands and unlinked source paths are relative to the repository root.

## Ownership map

- `:platform-api` owns the transport-neutral Platform API v1 router, route families,
  deterministic compatibility contract, Platform API 1.0 stable baseline metadata, app-token
  authorization decisions, browser-session
  authorization decisions, capabilities, app-vault route handlers, generated app-document queue
  staging, bounded content fetch routing, shared app-network budget service/store, durable content
  subscriptions, durable app data, app-data backup/restore planning and commit routes, unified
  consent previews/decisions/audit stores, internal update snapshots, local Trust Graph Local RC
  route handlers, local app-service discovery/dependency/grant-bundle routes and adapters, bounded
  app audit logs, and the local app-update lifecycle service plus scheduler above AppHost, catalog,
  vault, app-data, content, trust, and runtime primitives, plus host/operator-only catalog
  operation routes for mirror management, source health, revision history, rollback, key-rotation
  status, and emergency advisory refresh; the host/operator-only beta dashboard, subscription
  recovery wrappers, typed operator RC recovery action planning/execution, safe network-budget
  snapshots, support-bundle preview metadata, redacted support-bundle assembly, and the
  host/operator-only Stable 1.0 lifecycle snapshot route.
- `:platform-apphost` owns installed app layout, manifest parsing, app process lifecycle,
  per-launch `CRYPTAD_APP_TOKEN`, runtime status, process-log capture/redaction, and restart
  attempts, durable previous-bundle rollback records, plus sandbox policy/status reporting,
  Linux bubblewrap provider selection, and positive data/cache quota enforcement.
- `:platform-app-ui` owns static route/path/content-type/header helpers for `/apps/{appId}/` and
  isolated per-app loopback origin metadata, launch-proof bootstrap, and short-lived browser
  session issuance/verification for static app Platform API calls.
- `:platform-sdk-js` owns `crypta-platform.js`, the dependency-free browser helper staged into
  first-party static app bundles, including queue/content/feed/vault/trust/app-data/app-service
  helpers.
- `:platform-design-system` owns canonical local app UI CSS/JS assets and safe asset metadata/copy
  helpers used by scaffolds, first-party staging, UI lint, and release evidence.
- `:platform-appvault` owns app secret and identity vault storage records, metadata/grant value
  types, local wrapping-key provider, bounded profile/trust statement signing helpers,
  audit/redaction helpers, and deterministic vault tests.
- `:platform-appdist` owns local signed bundle digests, signatures, trusted-key verification,
  deterministic bundle packaging, manifest sandbox/quota/app-data schema migration fields, API
  target-stability metadata, and first-party signing/verification tooling.
- `:platform-appcatalog` owns signed catalog parsing, catalog writing, catalog source/artifact
  verification, `crypta:` catalog-source URI handling, safe ZIP extraction, and verified staging
  into AppHost install/update flows, plus optional review/API compatibility target-stability
  metadata, first-party maintenance metadata, catalog security advisory lifecycle/version
  denylists, production security response drill metadata, submission package
  writing/verification/pre-review/redaction, independent app-review receipts, trusted reviewer-key
  loading, review policy modes, and review trust decisions used by app update review,
  reviewer-key lifecycle parsing, local review transparency logging, governance snapshots,
  review-history API support, primary-plus-mirror source metadata, mirror fallback refresh,
  bounded verified revision history, explicit rollback re-verification, catalog key-rotation
  status, and emergency advisory refresh metadata.
- `:platform-trustgraph` owns the Trust Graph Local RC statement model, strict JSON parser,
  canonical payload and signature helpers, process-local anchor/store abstractions, lifecycle
  status records, and deterministic direct-anchor scoring. It is a local RC library, not a
  peer protocol or full Web of Trust implementation.
- `:platform-devtools` owns the standalone `crypta-app` CLI for scaffolding, validating, signing,
  packaging, verifying, catalog-authoring, app-store submission package/pre-review/candidate
  commands, API contract snapshotting, compatibility verification, stable-only `hello-stable`
  third-party templates and review-note scaffolds, mock dev serving with deterministic Platform API
  contract fixtures, offline app tests, developer key generation, and dry-run publication planning
  or explicit live USK publication for developer-owned staged bundles, including `crypta-app ui
  lint` and review receipt sign/verify helpers.
- `:platform-web-shell` owns `/app/node/` browser shell assets, bootstrap, app/catalog/update/review
  operator views, catalog source/mirror health and guarded catalog operations, the operator beta
  dashboard/support-bundle panel, the Operator RC Recovery surface, subscription recovery
  controls, app-data backup/restore controls, app-service dependency/grant-bundle review UI,
  security response and Stable 1.0 lifecycle status rendering, and explicit legacy
  security/diagnostic fallback actions.
- `:adapter-http-legacy-admin` hosts the current `/api/v1/`, `/app/node/`, `/apps/{appId}/`
  compatibility bridge, isolated app-UI loopback origin server, Platform API form-password guard,
  mutating catalog-operation form-password guard, operator recovery/subscription form-password
  guards, legacy admin retirement notices, Wave 5 final-surface policy, replacement/fallback
  routing, and diagnostics counters.
- `:apps:queue-manager` stages the first-party queue-control static UI bundle.
- `:apps:publisher` stages the legacy-publisher replacement static UI bundle.
- `:apps:site-publisher` stages the first-party content reference static UI bundle.
  Its selected Sharesite pastebin pilot uses `sharesite-drafts` schema 1 and one bounded dataset
  record. Read `docs/real-legacy-plugin-migration-pilot.md` before changing the offline converter,
  private package, draft UI, or guarded writes. Require the `sharesiteWriteGuard` status marker
  before preview requests; older daemons ignore unknown record fields. Preserve signed installed
  bundle verification, generation/consent/quota fencing, literal text fidelity, independent bundle
  rollback and data undo, and explicit new-CHK publication. Private payloads and comparison hashes
  must never become support or release evidence. The plugin runtime remains removed.
- `:apps:profile-publisher` stages the first-party identity-profile reference static UI bundle.
- `:apps:social-inbox` stages the first-party Social Inbox RC static UI bundle for beta
  social/mail-like threading, multi-source subscriptions, local read/filter/export state, and
  operator-approved Trust Graph score annotations through app-service grants.
- `:apps:feed-reader` stages the first-party feed reader/subscription reference static UI bundle.
- `:apps:trust-graph` stages the first-party Trust Graph Local RC static UI bundle, including local
  anchor lifecycle controls, import previews, recovery/export/import affordances, and the local
  `trust.score` app-service provider.
