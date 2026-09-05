# Guardrails reference

Read for Guardrails. Commands and unlinked source paths are relative to the repository root.

## Guardrails

- Never expose `CRYPTAD_APP_TOKEN` through browser bootstrap JSON, Web Shell bootstrap, app
  summaries, runtime/log/audit API responses, diagnostics, `toString()`, or error text.
- Browser static UI prefers isolated per-app loopback origins, with `/apps/{appId}/` retained as a
  same-origin compatibility fallback. Browser origin isolation is not a process sandbox or
  app-token authority; server-side Platform API permission checks remain authoritative.
- Static app browser session tokens are local browser credentials for installed static UI calls.
  They are not AppHost launch tokens, must not expose `CRYPTAD_APP_TOKEN`, and should stay out of
  persistent browser storage.
- App-originated Platform API requests must authenticate with a live app process token or app
  browser session and pass the central capability matrix. Deny app principals by default.
- Material install, update, app-data migration, backup-before-update, app-service grant, and Trust
  Graph import-preview decisions must use unified consent snapshots when required. Approval is
  bound to the exact snapshot digest, stale approvals must fail closed, and consent audit evidence
  must stay path-free and token-free.
- Platform API 1.0 is the stable app-facing baseline named `stableBaseline.name=1.0`, frozen at
  contract version 19 and distinct from the current integer contract version. Later contract bumps
  must not expand or shrink that baseline unless the change deliberately defines a new baseline.
- Stable baseline membership is bounded to app-facing stable descriptors introduced no later than
  contract version 19 and backed by the baseline capability set. Do not silently promote app-vault,
  app-service, Trust Graph Local RC, internal, or operator-only routes into the 1.0 stable surface.
- App manifests and catalog descriptors use `api.targetStability=stable|experimental`. Stable
  targets may use only Platform API 1.0 baseline capabilities; experimental app-facing use still
  requires `api.experimentalCapabilitiesAccepted=true`; internal and operator-only capabilities
  are rejected for third-party app compatibility even with experimental acceptance.
- `vault.identities.manage` is host/operator-only identity management. Keep it out of
  requestable third-party app capability guidance, scaffolds, manifests, and stable baseline
  examples.
- Contract JSON parsing must remain backward compatible for pre-freeze version 19 snapshots that
  omit `stableBaseline`. Contract versions after 19 must include stable-baseline metadata, and the
  parsed metadata must match descriptor membership instead of being silently recomputed.
- App-facing `POST /api/v1/content/fetch` is bounded foreground content retrieval only. It must
  require `content.fetch`, cap bytes and timeouts, allow only Crypta/Freenet content-key forms, and
  reject `file:`, arbitrary HTTP(S), loopback/LAN URLs, and absolute local paths before calling the
  runtime fetch port.
- Shared app-network budgets are required for app-initiated network work: foreground content
  fetch, subscription manual refresh, subscription scheduler poll, Trust Graph direct import, and
  Trust Graph import-by-URI. Use `AppNetworkBudgetService` with reserved internal scopes for
  global and host/operator counters; do not add per-feature counters that bypass the shared global
  content-fetch budget. Full runtime should fail closed when durable budget state is unavailable.
- Durable content subscriptions are bounded USK follow metadata plus scheduled refresh requests.
  Manual refresh and scheduler polls consume shared app-network budget after queue-pressure checks.
  They must not become a crawler, arbitrary HTTP client, queue-HTML parser, raw content archive, or
  source of private insert URIs.
- Durable app data is app-owned state only. It must remain scoped to the authenticated caller app,
  enforce bounded namespaces/keys/values/imports, and keep raw values, request bodies, store roots,
  app data directories, private insert URIs, tokens, and local paths out of public JSON, audit,
  docs, and release evidence.
- App-data backup/restore is host/operator-only and is not an app-facing contract bump by itself.
  Restore previews and support evidence must stay metadata-only: no raw backup payloads, raw app
  data values, form passwords, private insert URIs, tokens, store roots, or absolute local paths.
- App-generated document insert routes accept generated document bytes, not local source paths.
  Keep raw generated documents, raw feed/profile/trust bodies, private insert URIs, raw
  signatures, and request bodies out of audit entries, logs, and release evidence.
- Trust Graph Local RC is local RC scoring and bounded statement import/sign/publish support.
  Direct import and pasted import preview consume Trust Graph import budget; import-by-URI and URI
  preview consume both Trust Graph import budget and the shared content-fetch budget. URI previews
  must fetch one root `crypta.trust.statement.v1` document so `import-preview-uri` and `import-uri`
  agree. Pasted previews may summarize arrays or `{ "statements": [...] }` wrappers, but commits
  must send one direct statement document. Do not claim full Web of Trust compatibility, old plugin
  compatibility, global moderation, background crawling, daemon-core identity sharing, or
  protocol/network behavior changes. Trust evidence must stay bounded and redacted; do not record
  raw trust documents from real users.
- App-service discovery and grants are local Platform API mediation only. Do not add generic RPC,
  arbitrary localhost proxying, bearer tokens apps can pass around, remote discovery, daemon-core
  plugin ABIs, cross-app app-data access, or provider run/cache/store path exposure. Invocation must
  check the authenticated app principal, declared capabilities, current provider descriptor, active
  grant, scope, and context at call time.
- App-service dependency graphs and grant bundles must remain bounded operator-mediated metadata.
  Revalidate signed consumer manifests and current provider descriptors before approval, renewal,
  or invocation. Evidence and Web Shell summaries must not include raw service request bodies, raw
  subject URIs, raw Trust Graph data, provider app data, tokens, private keys, private insert URIs,
  raw signatures, backup payloads, or local paths.
- Social Inbox RC is a first-party beta reference app for social/mail-like local workflows. It may
  manage multiple bounded USK sources, local read/unread state, local mute/block filters, redacted
  exports, author profile summaries, and Trust Graph score annotations only through app-service
  grants. Do not present it as encrypted mail transport, Freetalk/Sone/Freemail compatibility, full
  WoT, network moderation, or a daemon-core message protocol.
- The legacy in-process plugin system is frozen and removed. Do not add
  `network.crypta.pluginmanager`, plugin toadlets, old plugin ABIs, old
  WebOfTrust/Freetalk/Sone/Freemail shims, or FCP plugin command execution. Legacy plugin FCP
  command names may only map to deterministic unsupported responses through the existing
  unsupported-command handler.
- Audit entries are bounded and process-local. Do not add query strings, request bodies, form
  passwords, tokens, absolute filesystem paths, or large payloads.
- Static UI routes must serve only immutable installed-bundle files. Reject traversal, encoded path
  separators, symlink/reparse escapes, reserved sidecars, and host-dependent MIME inference.
- Static app UI design-system assets must stay local to the bundle. Do not add CDN dependencies or
  remote CSS/JS allowances; use `crypta-app ui lint` for offline CSP, SDK/bootstrap, accessibility,
  permission-disclosure, and design-system checks.
- Signed catalogs and bundles must verify before install/update. Unsigned live-node installs require
  the explicit development-only escape hatch.
- Keep Stable catalog, first-party app, reviewer, and offline recovery keys role-distinct. Catalog
  verification uses the catalog-specific registry when configured; AppHost keeps the app-bundle
  registry, and review keeps `TrustedReviewerKeys`. The legacy AppHost-registry fallback is allowed
  only when catalog-specific configuration is absent, must warn, and cannot satisfy Stable
  production certification. When catalog-specific trust is present, reject cross-registry overlap
  by stable key ID or SHA-256 X.509 public-key fingerprint across every lifecycle state. Within
  each catalog or app-bundle registry, reject one public-key fingerprint under multiple IDs so an
  unsigned sidecar ID cannot select active policy for revoked key material. Retain every
  non-staged catalog/app identity in its role registry, mapping revoked, suspected, or compromised
  material to `revoked`. Authenticate the preceding signed transparency artifact for every
  non-genesis ceremony and keep key identity membership append-only so a later transition cannot
  prune and reassign an old ID or fingerprint across roles. Reverify an installed
  bundle with historical lifecycle policy before every explicit launch and automatic
  restart; retiring and retired keys are bounded by their support windows, while revoked,
  compromised, and out-of-window keys fail closed. Never auto-trust a key because a catalog or
  mirror lists it. Derived reviewer registries must retain revoked, suspected, and compromised
  reviewer identities as `revoked`; omitting them downgrades a force-blocking known revocation to
  an unknown-reviewer result. Omit only staged reviewers, and preserve retired/uncompromised
  historical reviewed-at semantics.
- At a release boundary, verify the exact detached catalog sidecar and the independently frozen
  signer id. `crypta-app catalog verify --catalog-signature-file <path> --expected-key-id <id>`
  prevents another key in a broad trusted registry from satisfying that binding. Do not replace
  this with a digest-only check or infer signer identity from the registry.
- Trusted app-review receipts are independent reviewer evidence. Do not treat publisher advisory
  `review.status`, app signing keys, or catalog signing keys as reviewer trust.
- App-store submission packages are review inputs, not install approvals. Keep package bodies,
  rationale documents, maintainer/source metadata, pre-review findings, transparency events, and
  catalog candidates deterministic and redacted; consent previews may summarize review metadata but
  must not include raw package bodies, local paths, keys, or tokens.
- Third-party developer beta artifacts are non-production unless explicitly promoted through the
  normal signed bundle, review, catalog, consent, and compatibility gates. The checked-in
  `hello-stable` sample and generated `review/*.md` files must stay stable-only by default,
  use only non-production reviewer material in tests, write generated ZIPs/reports outside the
  bundle root, and avoid private insert URIs, private keys, bearer/session tokens, raw fetched
  content, raw app data, raw rationale bodies, local absolute paths, and production signing or
  reviewer material.
- Reviewer governance is local trusted-key configuration plus a local tamper-evident transparency
  log. Do not present catalog-listed reviewer keys as automatically trusted, and do not describe
  the local transparency log as a global public log.
- `crypta:` catalog sources still require signed catalog verification. They do not make catalog
  artifacts trusted, and catalog entry bundle artifacts remain limited to the schemes documented in
  `docs/app-catalogs.md`.
- Catalog mirrors are transport fallbacks only. Every primary or mirror refresh must preserve safe
  source URI validation, signed catalog verification, catalog-id matching, trusted-key policy,
  parser/security-advisory checks, digest/revision calculation, and stale/downgrade prevention.
  Mirror refresh must not silently roll back to older bytes; only an explicit operator rollback to
  a previously verified revision may move backward.
- Stable GA must publish or confirm the exact frozen signed stable catalog, signature, revision,
  artifact URLs, first-party app bundles, trusted review receipts, signing identities, maintenance
  policy, Platform API snapshot, and content-format profile registry. Do not rewrite, re-sign,
  relabel, or substitute any of those bytes after RC freeze. A required change returns to the
  authorized RC exception/refreeze path and restarts post-freeze validation.
- Stable catalog publication targets must be canonical, public HTTPS locations with a distinct
  primary and mirrors. Resolve and pin public addresses at the protected fetch boundary; verify the
  current and rollback signed catalog bytes before any public release mutation and again afterward.
  A mirror is never a trust authority. Never serialize private insert URIs or publication
  credentials in the plan, maintenance baseline, or receipt.
- PR-293 adds a public Crypta USK network primary; it does not remove the Stable GA HTTPS checks.
  Bind the exact frozen catalog and detached signature, revision and USK edition, signer ID and
  fingerprint, PR-291 release root, PR-292 catalog subject, independently operated mirror, and
  eligible rollback subject. Only the protected mutation job may materialize insert capability.
  Run that job on the dedicated protected Stable catalog-publication runner with a managed
  localhost daemon and matching form-password secret. Its bounded greeting and Platform API
  contract preflight must pass before secrets enter the job; daemon lifecycle remains a protected
  runner-provisioning responsibility, not a release-workflow action.
  Local engines, fixtures, docs, or workflow definitions never prove ceremony, publication,
  observation, rotation, or rollback completion.
- Catalog operation routes under `/api/v1/app-catalogs/{catalogId}/mirrors` and
  `/api/v1/app-catalogs/{catalogId}/operations/*` are host/operator-only local-management routes.
  They must deny app-process and app-browser principals, and mutating bridge requests must pass the
  form-password guard. Support/API/Web Shell output must remain redacted: no private insert URIs,
  private keys, app/session/process tokens, form passwords, raw catalog bytes, raw signature bytes,
  raw fetched content, raw app data, scratch paths, staged paths, rollback paths, or absolute local
  paths.
- Production security response is catalog/app/reviewer governance only. Keep emergency advisories,
  exact-version denylists, reviewer-key/receipt revocations, catalog signing-key rotation evidence,
  replacement guidance, and safe uninstall/update labels compact and operator-facing. Do not expose
  raw incident artifacts, raw catalog bytes, private insert URIs, tokens, private keys, raw fetched
  content, raw app data, command lines containing secrets, CI secret values, or local absolute paths
  through API responses, Web Shell text, support bundles, release notes, or certification evidence.
- App-update lifecycle state, including app-data migration summaries, must stay path-free and
  token-free. Do not expose catalog scratch directories, staged bundle paths, migration command
  paths, rollback directories, launch tokens, browser sessions, form passwords, private signing
  keys, private insert URIs, raw migration logs, or raw app-data values through API responses, Web
  Shell text, logs, audit entries, or certification output.
- The default app-update policy is `manual`. Do not introduce silent third-party auto-update; policy
  `stage` may stage eligible verified candidates, and `apply_when_stopped` may apply only when the
  app is already stopped and all review/compatibility gates pass.
- App-update routes under `/api/v1/apps/{appId}/updates` are mutating local-management routes when
  they check, stage, apply, rollback, or update policy. Browser/host requests must pass the
  form-password guard. App principals need the published app/catalog capabilities; do not let
  `apps.manage` alone trigger catalog refresh or artifact staging.
- Rollback normally restores only the immutable installed bundle. It must preserve AppHost-managed
  data/cache/run ownership boundaries and must not claim broad mutable app-data rollback. The
  narrow exception is the app-update migration path, where `AppUpdateService` may create and
  restore an internal, app-scoped, short-lived durable app-data snapshot; do not expose it as
  user-facing backup/restore or cross-app portability.
- Operator routes under `/api/v1/operator` are host/operator-only local management and support
  routes. They are not part of the app-facing Platform API compatibility contract, must deny app
  principals, and should not bump the integer contract version. Support bundles and dashboard
  summaries must exclude raw bodies, private insert URIs, app/session/process tokens, form
  passwords, local paths, command lines, and app-private values.
- `GET /api/v1/updates/support-lifecycle` is likewise host/operator-only and
  `OPERATOR_ONLY` in the compatibility contract. Keep the app-readable
  `GET /api/v1/updates/core` response limited to updater availability and download readiness; do
  not expose lifecycle state through it as a shortcut around the direct-route principal check.
  Web Shell must treat failure of the lifecycle request as an unknown best-effort diagnostic while
  preserving a successful core response and its independently authorized controls.
- Operator RC recovery routes must stay typed and allowlisted. Clients request an
  `OperatorRecoveryPlan` for a known `OperatorRecoveryActionId`, then execute that exact action
  with the matching one-time `planToken`; destructive actions require explicit confirmation. Do
  not add generic route proxying, arbitrary method/path execution, broad shell commands,
  token-persistent dashboards, or support bundles that include plan tokens, raw backup payloads,
  raw Trust Graph statements, private insert URIs, raw app data, command lines, or local paths.
- Positive AppHost data/cache quotas must block launch or restart when usage is over limit or an
  enforced area cannot be measured completely. Quotas and current sandbox providers are operational
  controls, not hard OS isolation.
- Bubblewrap sandbox status is public only as provider/support-level metadata. Do not expose the
  configured `bwrap` executable path, generated wrapper command line, bind mount source paths, app
  tokens, or host private configuration.
- Legacy admin retirement changes must update both the code map
  (`LegacyAdminRetirementRegistry`) and `docs/legacy-retirement-plan.md`.
- Legacy admin Wave 5 is the production-beta final admin surface. It adds no new removed-by-default
  route ids, keeps Wave 1-4 removals stable, marks legacy admin maintenance-only, and retains FProxy
  browse/content rendering, content filter, startup/recovery, support, and exact emergency fallback
  surfaces. Do not add new daily legacy-admin surfaces; route new operator workflows through Web
  Shell, Platform API, or first-party apps.
- Release-certification evidence must not expose private signing keys, app process tokens,
  browser-session tokens, form passwords, raw request bodies, raw feed bodies, raw trust documents,
  raw diagnostic exports, raw app-data backup payloads, private insert URIs, non-localhost endpoint
  metadata, or unsanitized local paths. Optional live AppHost smoke reads the form password from
  `CRYPTAD_CERT_FORM_PASSWORD`; do not pass it as a command-line argument. Dedicated live-network
  beta certification must stay localhost-only, env/protected-file driven for secrets, and disabled
  for normal PR/nightly/offline release-candidate runs unless explicitly requested.
- Unified app-platform, live-network, multi-node, security, production, dashboard, Stable, and
  release-certification inputs are candidate-bound v2 envelopes. Do not bypass kind, release-ID,
  exit-code, or common-redaction validation through legacy aliases, fixture switches, or command
  passthrough arguments. Attached legacy payloads are scanned again before extraction, and
  security-drill sidecars are scanned and digest-checked before copying.
- Release artifacts live under `<out-root>/<release-id>/<component>/`. Common v2 files are at the
  component root, engine-native output is under `artifacts/legacy/`, and validated attached inputs
  are under `artifacts/inputs/`. All writers must remain symlink-safe and confined to the marked
  workspace. If engine output fails the fallback scan, remove the unsafe raw copies and emit only a
  sanitized failed envelope with `promotionReady=false`.
