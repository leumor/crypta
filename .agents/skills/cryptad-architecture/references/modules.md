# Build/module layout (current) reference

Read for Build/module layout (current). Commands and unlinked source paths are relative to the repository root.

## Build/module layout (current)
- Cryptad now uses a partial multi-project Gradle build.
- The root project `:cryptad` remains the daemon/application project.
- The root project still owns `buildJar`, `run`, `runLauncher`, distribution/jpackage tasks, the
  strongly coupled core packages, and most broad tests.
- Leaf subprojects:
  - `:foundation-support` → the current stable generic subset of `network.crypta.support`,
    `network.crypta.support.api`, `network.crypta.support.io`,
    `network.crypta.support.compress`, `network.crypta.support.math`,
    `network.crypta.support.transport.ip`, and `network.crypta.support.http`, plus
    `network.crypta.io.AddressIdentifier`, `network.crypta.io.WritableToDataOutputStream`,
    `network.crypta.node.FSParseException`, `network.crypta.node.FastRunnable`,
    `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`,
    `network.crypta.support.IllegalValueException`, `network.crypta.support.JVMVersion`, the
    generic `HTTPRequest` / `HTTPUploadedFile` / `MultiValueTable` / `SizeUtil` support surface,
    generic helpers such as `URIPreEncoder`, `IOUtils`, and `LegacyFileSupport`, and the
    cycle-safe file-backed support I/O slice
  - `:foundation-store-contracts` → neutral `network.crypta.store` contracts
    `BlockMetadata`, `GetPubkey`, `StorableBlock`, plus the `network.crypta.store.alerts` seam
    (`StoreAlertSink`, `StoreMaintenanceAlertKind`, `StoreMaintenanceAlertSource`)
  - `:foundation-crypto-keys` → `network.crypta.crypt`, `network.crypta.keys`, plus
    `network.crypta.support.io.BucketTools`, `network.crypta.support.io.NoFreeBucket`, and
    `network.crypta.support.io.PrependLengthOutputStream`
  - `:foundation-store` → reusable `network.crypta.store` implementations plus
    `network.crypta.store.caching` and `network.crypta.store.saltedhash`
  - `:interop-wire` → the leaf-safe wire/message/schema/version/probe nucleus:
    selected `network.crypta.io.comm` types, `network.crypta.node.Version`,
    `network.crypta.node.probe.Error`, `network.crypta.node.probe.Type`, and
    `network.crypta.support.Serializer`
  - `:foundation-config` → `network.crypta.config`, `network.crypta.l10n`, the main l10n
    resources, and shared setup helpers such as `DatastoreSizingSupport`; public config APIs
    re-export `:foundation-support` and `:foundation-fs` where they expose shared types
  - `:foundation-fs` → `network.crypta.fs`
  - `:foundation-compat` → `network.crypta.compat`, including
    `network.crypta.compat.bandwidth`
  - `:kernel-content` → the compile-neutral phase-1 content slice across selected
    `network.crypta.client`, `network.crypta.client.events`,
    `network.crypta.client.filter`, `network.crypta.client.async.alerts`,
    `network.crypta.client.async.persistence`, selected filter policy/helper types such as
    `HTMLFilterPolicy`, concrete media/CSS/HTML parser/filter helpers, selected event/helper
    types such as `SplitfileCompatibilityMode*`, and `network.crypta.support.MediaType`
  - `:kernel-transport` → the compile-neutral phase-1 transport slice across selected
    `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` helpers such as
    address matchers, allow-list parsing, listener abstractions, `SSLNetworkInterface`,
    I/O statistics collection, throttling, and partially received block assembly
  - `:kernel-routing` → the compile-neutral phase-1 routing/helper slice across selected
    `network.crypta.node` value, exception, callback, and request-item helper types such as
    `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`, `RequestClient`,
    `PeerStatusCounts`, `RecentlyFailedReturn`, `RequestPriorityClasses`, and
    `SendableRequestItem*`
  - `:runtime-spi` → `network.crypta.runtime.spi` (JDK-only runtime/config boundary)
  - `:platform-api` → `network.crypta.platform.api` (transport-neutral Platform API v1,
    compatibility contract, Platform API 1.0 stable-baseline metadata, app capabilities/audit,
    app-vault routes, app-generated document inserts, bounded content fetch, shared app-network
    budget service/store, durable content
    subscriptions, durable app data and internal update snapshots, app-data backup/restore routes,
    unified consent preview/decision/audit routes, local app-service discovery/dependency
    graph/grant-bundle routes, app-update lifecycle/scheduler, and host/operator-only beta
    dashboard/support-bundle, typed operator RC recovery, safe network-budget snapshots, and the
    host/operator-only Stable 1.0 support-lifecycle snapshot route)
  - `:platform-apphost` → `network.crypta.platform.apphost` (transport-neutral out-of-process
    AppHost core, sandbox status, durable rollback records, and AppHost-managed quota enforcement)
  - `:platform-app-ui` → `network.crypta.platform.appui` (app-owned static UI route and asset
    resolution helpers, isolated origin metadata, and browser-session helpers)
  - `:platform-appvault` → `network.crypta.platform.appvault` (app secret and identity vault
    records, grants, local wrapping-key provider, and audit/redaction value types)
  - `:platform-design-system` → `network.crypta.platform.designsystem` (canonical local app UI
    CSS/JS resources plus asset metadata and safe bundle-copy helpers)
  - `:platform-sdk-js` → browser SDK resource for app-owned static UI bootstrap, Platform API
    transport helpers, mutation form handling, queue/content/vault/feed/app-data/app-service
    helpers, error parsing, and conservative fragment sanitization
  - `:platform-appdist` → `network.crypta.platform.appdist` (signed local app bundle digest,
    signature, manifest API target-stability and app-data schema/migration metadata, verifier,
    trusted-key,
    deterministic packager, and distribution tooling)
  - `:platform-appcatalog` → `network.crypta.platform.appcatalog` (signed catalog sources,
    catalog writer/descriptors, Crypta catalog source handling, app-store/API compatibility
    target-stability metadata, first-party maintenance metadata, submission package
    verification/pre-review/candidate metadata, independent app-review receipts, catalog security
    advisory lifecycle/denylist policy, production security response metadata, primary-plus-mirror
    catalog source operations, mirror fallback refresh, bounded verified revision history,
    explicit rollback re-verification, catalog signing-key rotation status, emergency advisory
    refresh metadata, artifact verification, safe ZIP extraction, and verified staging)
  - `:platform-trustgraph` → `network.crypta.platform.trustgraph` (Trust Graph Local RC statement
    parsing, canonicalization, verification, process-local store/anchor behavior, import-preview
    summaries, duplicate-issuer/conflict handling, lifecycle/status records, and bounded
    deterministic direct-anchor scoring explanations)
  - `:platform-devtools` → `network.crypta.platform.devtools` (standalone `crypta-app` developer
    CLI for staged-bundle, UI lint, mock dev server, offline tests, catalog-authoring, app-store
    submission package/pre-review/candidate workflows, developer keys, publication plans, explicit
    live USK catalog publication, API snapshot, and compatibility verification workflows)
  - `:platform-web-shell` → `network.crypta.platform.webshell` (browser-facing Web Shell v1,
    including Apps, catalog, update, review, unified consent review, operator beta
    dashboard/support-bundle, catalog source/mirror health and guarded catalog operation controls,
    security response and Stable 1.0 lifecycle status rendering, Operator RC Recovery,
    subscription recovery, app-data backup/restore, app-service dependency/grant-bundle review,
    and explicit legacy security/diagnostic fallback surfaces)
  - `:runtime-alerts` → the extracted leaf-safe `network.crypta.runtime.alerts` feed/model subset
    plus the detached `UserAlertSurface`
  - `:runtime-node` → extracted daemon runtime body across the remaining cyclic/high-level
    `network.crypta.client` body, the remaining peer/request/routing-engine and transport-heavy
    `network.crypta.node` / `network.crypta.runtime.*` slices, the retained node-coupled
    transport/message execution code in `network.crypta.io*`, the package updater and Stable 1.0
    support-lifecycle subscriber/parser/store/state integration, and the remaining daemon-coupled
    `network.crypta.support` / `network.crypta.support.io` / `network.crypta.support.api` subset
  - `:adapter-fcp` → the detached protocol-side `network.crypta.clients.fcp` package tree
  - `:bridge-fcp-runtime` → the concrete runtime-binding FCP bridge package
    `network.crypta.clients.fcp.bridge`
  - `:adapter-http-legacy-admin` → the detached shared legacy `network.crypta.clients.http`
    shell, admin toadlets, `/api/v1/` and `/app/node/` bridge entrypoints, the app-UI loopback
    origin server, and matching `network/crypta/clients/http/**` main resources
  - `:adapter-http-legacy-browse` → the concrete legacy browse/FProxy routes, toadlets, helper
    models, and browse-only packages under `network.crypta.clients.http`
  - `:bridge-http-runtime` → the concrete runtime-binding HTTP bridge implementations under
    `network.crypta.clients.http.bridge` plus the legacy HTTP GeoIP helper package
    `network.crypta.clients.http.geoip`
  - `:thirdparty-onion` → `com.onionnetworks` plus `lib/fec.properties`
  - `:thirdparty-legacy` → `org.bitpedia`, `org.sevenzip`, `org.spaceroots`
  - `:launcher-desktop` → `network.crypta.launcher`, `com.jthemedetecor`, `oshi`, launcher
    resources
- First-party app bundle subprojects:
  - `:apps:queue-manager` → staged Queue Manager AppHost bundle with a static UI under
    an isolated app origin when available, with `/apps/queue-manager/static/` as fallback
  - `:apps:publisher` → staged Publisher AppHost bundle with a static UI under
    an isolated app origin when available, with `/apps/publisher/static/` as fallback
  - `:apps:site-publisher` → staged Site Publisher content reference AppHost bundle with a static
    UI under an isolated app origin when available, with `/apps/site-publisher/static/` as fallback
  - `:apps:profile-publisher` → staged Profile Publisher identity-profile reference AppHost bundle
    with a static UI under an isolated app origin when available, using app-vault profile-document
    creation and app-generated document insertion
  - `:apps:social-inbox` → staged Social Inbox RC beta social/message reference AppHost bundle
    with a static UI under an isolated app origin when available, using bounded AppVault
    social-message signing, generated outbox insertion, multi-source durable content
    subscriptions, durable app data for read state and local filters, redacted exports, and
    operator-approved Trust Graph score app-service grants
  - `:apps:feed-reader` → staged Feed Reader content-fetch and subscription reference AppHost bundle
    with a static UI under an isolated app origin when available, using bounded Crypta content
    fetch, budgeted durable USK content subscriptions, durable app data, and app-generated feed
    document insertion
  - `:apps:trust-graph` → staged Trust Graph Local RC trust-service reference AppHost bundle with a
    static UI under an isolated app origin when available, using `trust.read`, `trust.write`,
    durable trust graph storage/exchange, budgeted import previews, local anchor lifecycle
    actions, budgeted content fetch/subscriptions, AppVault trust-statement signing,
    app-generated trust statement insertion, and the `trust.score` app-service provider
- The runtime boundary is split intentionally:
  - `:runtime-spi` exposes small JDK-only ports plus immutable config, alert, queue, peer, wizard,
    updater, and shell DTOs.
  - `:runtime-node` now implements the daemon-backed ports across
    `network.crypta.runtime.core` and `network.crypta.runtime.admin`. The runtime nucleus lives in
    `network.crypta.runtime.core.LegacyRuntimePorts` plus core adapters such as
    `LegacyConfigPort`, `LegacyConnectivityPort`, `LegacyNodeInfoPort`, `LegacyPeerPort`,
    `LegacyRequestQueuePort`, `LegacySecurityLevelsPort`, and `LegacyCoreUpdateActionPort`.
    Page-oriented adapters such as `LegacyConnectionsPagePort`,
    `LegacyConnectionsSupportPort`, `LegacyDarknetConnectionsPort`,
    `LegacyDarknetMessagingPort`, `LegacyQueuePagePort`, `LegacyQueueMutationPort`,
    `LegacyQueueSupportPort`, `LegacyPageChromePort`, `LegacyDiagnosticPort`,
    `LegacyStatisticsPort`, `LegacyFirstTimeWizardPort`, `LegacyToadletSymlinkPort`,
    `LegacyWelcomePagePort`, and `LegacyWelcomeActionPort` now live in
    `network.crypta.runtime.admin`, supported by queue helper seams under
    `network.crypta.runtime.admin.queue` and `network.crypta.runtime.admin.queue.page`.
    Queue completion/download/insert bridges plus the remaining concrete FCP bridge
    implementations now live under `network.crypta.clients.fcp.bridge`.
  - The root project keeps application composition, packaging/runtime tasks, most broad tests,
    tools, and root-local bridge selection in
    `network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories`.
- The daemon runtime and app-platform build now span extracted leaves plus a thin root composition
  layer:
  `:kernel-content` owns the compile-neutral phase-1 client/content slice,
  `:kernel-transport` owns the compile-neutral phase-1 transport helper slice,
  `:kernel-routing` owns the compile-neutral phase-1 routing/helper slice,
  `:platform-api` owns the transport-neutral Platform API surface including app-vault route
  handlers, social-message signing, app-generated document inserts, bounded content fetch,
  shared app-network budget service/store, durable content subscriptions, durable app data and
  internal app-update snapshots, unified consent previews/decisions/audit, local app-service
  discovery/grants, app-update scheduling, and host/operator-only beta dashboard/support-bundle,
  typed operator RC recovery, and network-budget snapshot routes,
  `:platform-apphost` owns the transport-neutral AppHost core, `:platform-app-ui` owns
  app-owned static UI route helpers,
  `:platform-appvault` owns app secret and identity vault records/grants,
  `:platform-design-system` owns canonical local app UI assets, `:platform-sdk-js` owns the
  browser SDK resource, `:platform-appdist` owns signed local bundle distribution,
  `:platform-appcatalog` owns signed catalog sources, source/mirror operations, verified revision
  history, rollback, key-rotation status, emergency advisory refresh, submission
  pre-review/candidate metadata, trusted app-review receipts, and verified staging,
  `:platform-trustgraph` owns local trust
  statement parsing, import-preview/conflict summaries, lifecycle records, and deterministic
  bounded-score explanations, `:platform-devtools` owns the standalone app developer CLI, app-store
  submission workflows, and offline UI linter, `:platform-web-shell` owns the browser-facing
  node-management shell, unified consent review, catalog source/mirror operations, app-data
  backup/restore controls, app-service dependency/grant-bundle review, operator beta dashboard, and
  Operator RC Recovery,
  `:runtime-alerts` owns the extracted alert/feed model subset,
  `:runtime-node` owns the
  remaining runtime/node/client/support body, `:adapter-fcp` owns the FCP adapter tree,
  `:bridge-fcp-runtime` owns the concrete FCP bridge implementations,
  `:adapter-http-legacy-admin` owns the shared legacy HTTP shell/admin layer,
  `:adapter-http-legacy-browse` owns the concrete browse/FProxy layer,
  `:bridge-http-runtime` owns the concrete HTTP runtime bridge, and the root project keeps tests,
  packaging, tool entrypoints, and remaining composition glue.
- The wire split is intentionally narrow:
  `:interop-wire` owns the message/schema nucleus, `:kernel-transport` owns the compile-neutral
  transport helper slice (`AllowedHosts`, `NetworkInterface`, `IOStatisticCollector`,
  `SSLNetworkInterface`, `SocketHandler`, `PacketThrottle`, `PartiallyReceivedBlock`, etc.),
  while `:runtime-node` keeps `MessageCore`, `MessageFilter`, `AsyncMessageFilterCallback`,
  `SlowAsyncMessageFilterCallback`, `PeerContext`, incoming-packet filters, active socket
  handlers, and transfer send/receive code.
  `network.crypta.io.comm.Message` now depends on the minimal `MessageSource` seam instead of
  directly on `PeerContext`.
- For the detached adapter/runtime boundary details, prefer the maintenance docs in
  `docs/fcp-boundary.md` and `docs/legacy-http-boundary.md` over older migration narratives.
- `:foundation-config` is the current home for all main `network.crypta.config` and
  `network.crypta.l10n` sources. Their unit tests still live in the root test tree and are run by
  the root project.
- Every extracted internal leaf relies on leaf-owned aggregated-output metadata at
  `<leaf>/gradle/owned-output-patterns.txt`. This is required even for structurally separate
  package/resource moves, because stale non-owner aggregated outputs from earlier builds or branch
  switches can still shadow leaf outputs while `buildJar` packages aggregated main outputs first.
- Update that metadata whenever a leaf starts owning additional main classes/resources that root
  used to compile/package. This applies to existing leaves such as `:foundation-support` and
  `:foundation-store-contracts` just as much as any future extraction.
- Focused leaf-local boundary tests now freeze the extracted layout. In particular,
  `RuntimeNodeKernelSplitPrepBoundaryTest`, `KernelContentBoundaryTest`,
  `KernelTransportBoundaryTest`, `KernelRoutingBoundaryTest`, `PlatformApiBoundaryTest`,
  `AdapterFcpBoundaryTest`, `BridgeFcpRuntimeBoundaryTest`, `AppHostBoundaryTest`,
  `CryptaPlatformSdkBoundaryTest`, `WebShellBoundaryTest`, `HttpLegacyAdminBoundaryTest`,
  `LegacyHttpBrowseBoundaryTest`, and `BridgeHttpRuntimeBoundaryTest` guard leaf
  ownership/import rules. The runtime, kernel,
  platform, FCP, and HTTP boundary suites also require `package-info.java` in the production
  packages they own.
