# Architecture overview (by package) reference

Read for Architecture overview (by package). Commands and unlinked source paths are relative to the repository root.

## Architecture overview (by package)
### Core network layer (`network.crypta.node`)
- Node coordination: `Node.java`
- Peer management: `PeerNode`, `PeerManager`
- Network transport: `PacketSender`, `FNPPacketMangler`
- Request orchestration: `RequestStarter`, `RequestScheduler`
- `:kernel-routing` now owns the compile-neutral phase-1 helper/value slice inside
  `network.crypta.node`, including request client metadata, low-level routing exceptions,
  lightweight peer-status summaries, and sendable-request item helper interfaces.
- Updates now bootstrap through `network.crypta.runtime.updater.NodeUpdateManager`

### Runtime orchestration packages (`network.crypta.runtime.*`)
- Startup/CLI/config bootstrap: `network.crypta.runtime.bootstrap`
  (`NodeStarter`, `NodeBootstrap`, `NodeCli`, `NodeConfigManager`, `LoggingConfigHandler`)
- Runtime SPI nucleus and daemon-backed core adapters: `network.crypta.runtime.core`
- Page-oriented admin/runtime adapters: `network.crypta.runtime.admin`
- Operator-facing alerts and alert-feed seams: `network.crypta.runtime.alerts`
- Endpoint bootstrap glue for FCP/HTTP/TMCI: `network.crypta.runtime.endpoints`
- Service coordination: `network.crypta.runtime.services`
- Core update subsystem: `network.crypta.runtime.updater`

### Content storage (`network.crypta.store`)
- Storage abstractions: `FreenetStore`
- CHK/SSK stores: `CHKStore`, `SSKStore`
- Caching: `SlashdotStore`
- `:foundation-store` now owns the reusable store implementations, cache layer, and salted-hash
  store code.
- Neutral contracts `BlockMetadata`, `GetPubkey`, and `StorableBlock` live in
  `:foundation-store-contracts`, along with the store-maintenance alert seam in
  `network.crypta.store.alerts`.
- Root-owned runtime/UI integration now lives in `network.crypta.runtime.alerts`, for example
  `UserAlertManagerStoreAlertSink`.

### Cryptography (`network.crypta.crypt`)
- Encryption: block cipher / AES streams
- Signatures: DSA/ECDSA
- Hashing: SHA-256 and others
- RNG: `RandomSource` / Yarrow
- This package now lives in `:foundation-crypto-keys`.

### Key management (`network.crypta.keys`)
- Client keys: `ClientCHK`, `ClientSSK`
- URIs: `FreenetURI`
- Updatable keys: USK
- This package now lives in `:foundation-crypto-keys`.

### Wire/message nucleus (`network.crypta.io.comm`, `network.crypta.node.Version`)
- `:interop-wire` owns the leaf-safe message/schema/address subset such as `Message`,
  `MessageType`, `Peer`, `FreenetInetAddress`, and related exceptions.
- `:interop-wire` also owns `network.crypta.node.Version`,
  `network.crypta.node.VersionParseException`, `network.crypta.node.probe.Error`,
  `network.crypta.node.probe.Type`, and `network.crypta.support.Serializer`.
- `:kernel-transport` owns the compile-neutral transport helper slice across selected
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` classes such as
  `AllowedHosts`, `NetworkInterface`, `IOStatisticCollector`, `SocketHandler`,
  `PortForwardSensitiveSocketHandler`, `PacketThrottle`, and `PartiallyReceivedBlock`.
- `:kernel-routing` owns the compile-neutral phase-1 `network.crypta.node` helper/value slice,
  including `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`,
  `RequestClient`, `PeerStatusCounts`, `RecentlyFailedReturn`, and `SendableRequestItem*`.
- `:runtime-node` keeps the node-coupled transport-facing code such as `PeerContext`,
  `MessageCore`, packet filters, active socket handlers, transfer send/receive code, and the
  remaining peer/request/routing-engine side of `network.crypta.node`, plus runtime helpers like
  `network.crypta.runtime.core.SSL`.

### Client APIs
- High-level client: `network.crypta.client`
  - `:kernel-content` now owns the compile-neutral phase-1 content slice: selected
    archive/value/helper classes, immutable event values, the full
    `network.crypta.client.async.alerts` seam, client-local seams under
    `network.crypta.client.async.persistence`, a conservative subset of filter helper/parser
    types plus policy holders such as `HTMLFilterPolicy`, concrete media/CSS/HTML parser/filter
    helpers, event/helper types such as `ClientEventProducer` and `SplitfileCompatibilityMode*`,
    utility/value types such as `ClientGetterOptions` and `ClientPutterOptions`, `InsertUriChecks`,
    and
    `network.crypta.support.MediaType`.
  - `:runtime-node` still owns the cyclic async scheduler/request engine, high-level client APIs,
    and the remaining filter/archive surfaces that still depend on request scheduling or node
    internals.
  - The async client layer also retains client-local seams under
    `network.crypta.client.async.persistence` so runtime/FCP bridges can recover durable requests
    without owning those contracts.
- FCP: `network.crypta.clients.fcp`
  - This package now lives in `:adapter-fcp`.
  - Runtime-facing execution, randomness, lifecycle, transfer-policy, and config access now come
    through `RuntimePorts`.
  - `FcpRuntimeAdapters` preserves legacy FCP-local shapes such as `PriorityAwareExecutor` and
    `RandomSource` on top of the SPI.
  - Detached peer-management operations such as `ModifyPeer` now go through `RuntimePorts#peer()`.
  - Server bootstrap now flows through `FcpServerDependencies` and
    `CoreFcpServerDependenciesFactory`.
  - Package-local seams split the remaining daemon-backed work by concern:
    `FcpServerRuntimeSupport`, `FcpMessageRuntimeSupport`, `FcpFetchRuntimeSupport`, and
    `FcpInsertRuntimeSupport`.
  - FCP insert request options and mutable insert-context handles stay adapter-owned through
    `FcpInsertOptions`, `FcpInsertBehaviorOptions`, and `FcpInsertContextHandle`; bridge code
    adapts those seams to runtime insert contexts.
  - Runtime-owned FCP seam types now live under `network.crypta.runtime.fcp` and
    `network.crypta.runtime.endpoints.fcp`, while concrete persistent-request services, queue
    adapters, alert-feed adapters, and endpoint-handle wrappers now live under
    `network.crypta.clients.fcp.bridge`.
- HTTP interface: `network.crypta.clients.http`
  - The package family is now split physically:
    `:adapter-http-legacy-admin` owns the shared shell/admin routes and the matching
    `network/crypta/clients/http/**` main resources such as `staticfiles/**` and `templates/**`;
    `:adapter-http-legacy-browse` owns the concrete browse/FProxy routes, toadlets, and helper
    models; `:bridge-http-runtime` owns the concrete runtime-binding bridge implementations under
    `network.crypta.clients.http.bridge` plus the legacy HTTP GeoIP helper package.
  - The migrated management and shell slices no longer depend directly on live daemon peers or
    node-info exports for their core data flow.
  - `ConfigToadlet` now takes detached configuration export/update capabilities from
    `ConfigPort` through `ConfigToadletRuntimePorts` and classifies directory-browser fields
    through the detached `network.crypta.config.DirectorySelectionCallback` marker instead of
    importing `ProgramDirectory`.
  - `ConnectionsToadlet`, `DarknetConnectionsToadlet`, `OpennetConnectionsToadlet`, and
    `DarknetAddRefToadlet` use detached ports such as `ConnectionsPagePort`,
    `ConnectionsSupportPort`, `PeerPort`, and `NodeInfoPort`.
  - `QueueToadlet` now acts as an HTTP adapter over `QueuePagePort`, `QueueDownloadPort`,
    `QueueInsertPort`, `QueueMutationPort`, `QueueSupportPort`, `QueueCompletionPort`,
    `TransferAccessPort`, `DarknetConnectionsPort`, and `DarknetMessagingPort`.
  - `SecurityLevelsToadlet` uses `SecurityLevelsPort` for detached page state, warning HTML, and
    master-password mutation flows.
  - `PageMaker` reads shared shell status through `PageChromePort`.
  - `LegacyAdminRetirementRegistry` maps replaced legacy admin surfaces, and
    `LegacyAdminUsageRecorder` feeds process-local legacy-page counters into Platform API
    diagnostics without storing query strings, form bodies, tokens, or remote addresses.
  - Current legacy admin removal waves cover selected queue/publisher/peer/connectivity routes,
    selected alert/config/core-update/statistics/queue helper routes, the security-levels safe-read
    route with exact `legacyFallback=security-levels` support fallback, and the diagnostic safe-read
    route with exact `legacyFallback=diagnostic-export` plaintext export fallback. Wave 5 adds the
    machine-checkable final admin surface without promoting new removals: legacy admin is
    maintenance-only, FProxy browse/content rendering and the content filter remain retained, and
    startup/recovery/support plus chat, translation, help, and node-to-node message routes remain
    retained or pending.
  - `network.crypta.clients.http.updater.CoreActionToadlet` reaches updater availability,
    download triggers, and installer-path validation through `CoreUpdateActionPort`.
  - `FirstTimeWizardToadlet` and `FirstTimeWizardNewToadlet` use `FirstTimeWizardPort` for
    detached snapshot export, validation bounds, bandwidth/security suggestions, current-bandwidth
    rows, and submission handling.
  - `SymlinkerToadlet` persists aliases through `ToadletSymlinkPort`.
  - `WelcomeToadlet` splits detached GET state and POST actions across `WelcomePagePort` and
    `WelcomeActionPort`, bundled in `WelcomeToadletRuntimePorts`.
  - FProxy and shell bootstrap now have local package-private seams:
    `BookmarkRuntimeSupport`, `BrowseContentClient`, `FProxyRuntimeSupport`,
    `HttpShellRuntimeSupport`,
    `HttpShellFProxyBootstrap`, and `FProxyRegistrarDependencies`.
  - HTTP/admin alert rendering now crosses the detached
    `network.crypta.runtime.alerts.UserAlertSurface` instead of importing
    `UserAlertManager` directly.
  - Concrete HTTP shell, bookmark, GeoIP, and security-page bridge implementations now live under
    `network.crypta.clients.http.bridge` in `:bridge-http-runtime`.
  - `BookmarkEditorToadletRuntimePorts` and `FileInsertWizardToadletRuntimePorts` are small
    page-specific records used to keep constructor surfaces explicit during HTTP wiring.
  - `N2NTMToadlet` uses `DarknetConnectionsPort` and `DarknetMessagingPort` for selected-peer
    lookup, transfer confirmations, and compose/send actions.

### Platform control/UI modules
- `:platform-api` owns the transport-neutral Platform API v1 under `network.crypta.platform.api`.
  It exposes node/config/peer/connectivity/security, queue, updates, wizard, alerts, diagnostics,
  apps, app updates, app-catalog control-plane families, app-vault route handlers, generated
  app-document inserts, bounded content fetch, shared app-network budget service/store, durable
  content subscriptions, durable app data and update migration snapshots, app-data backup/restore
  routes, local app-service
  discovery/dependency graph/grant-bundle routes, the host/operator-only Stable 1.0
  support-lifecycle snapshot route, and the deterministic Platform API compatibility contract plus
  the frozen Platform API 1.0 stable-baseline metadata,
  and is currently mounted at `/api/v1/` by the legacy HTTP adapter. It also owns app-token and
  browser-session authorization decisions, bounded process-local app audit logs, and local
  app-update lifecycle/scheduler coordination above AppHost, signed catalog, vault, app-data,
  content-fetch, content-subscription, trust graph, and app-service primitives.
- `:platform-apphost` owns the transport-neutral out-of-process AppHost v1 under
  `network.crypta.platform.apphost`. It validates staged local app bundles, owns the immutable
  installed-bundle layout plus mutable data/cache/run directories, and provides local
  install/list/describe/start/stop/update/uninstall operations, per-launch app tokens, minimal
  launch environments, token-redacted process-log snapshots, durable previous-bundle rollback
  records, sandbox policy/status reporting, Linux bubblewrap provider selection for enforced
  restricted-process launches, AppHost-managed data/cache quota enforcement, bounded process logs,
  and in-session restart attempts for manifests that opt in.
- `:platform-app-ui` owns `network.crypta.platform.appui`, the transport-neutral app-owned static
  UI path and origin layer. It maps installed static UI manifests to isolated per-app loopback
  origins with `/apps/{appId}/` retained as a compatibility fallback, preserves nested entry base
  URLs, resolves bundle assets, rejects traversal/symlink/reparse escapes, and supplies
  deterministic content-type, security-header, launch-proof bootstrap, and browser-session helpers
  for HTTP adapters.
- `:platform-appvault` owns `network.crypta.platform.appvault`, the local app secret and identity
  vault model. It provides encrypted record envelopes, local wrapping-key lookup, app-owned and
  shared identity metadata, grant records, identity-use result types, and audit/redaction values
  used by Platform API app, profile-document, trust-statement, and social-message workflows without
  exporting raw private material.
- `:platform-sdk-js` owns the dependency-free browser SDK resource staged into first-party static
  app bundles. It wraps route bootstrap, same-origin Platform API reads, app-browser form
  mutations, queue/content/app-vault/feed/app-data/app-service helpers, error parsing, and
  conservative legacy HTML fragment sanitization; it is not an authority or isolation boundary.
- `:platform-appdist` owns `network.crypta.platform.appdist`, the signed local bundle
  distribution layer. It parses normalized app manifests, writes deterministic SHA-256 digest
  sidecars, verifies Ed25519 signatures, rejects reserved sidecars as executable/UI entries,
  carries sandbox/quota/API compatibility and app-data schema/migration manifest fields, and
  exposes the packager/distribution tool used by first-party app Gradle tasks and developer
  tooling.
- `:platform-appcatalog` owns `network.crypta.platform.appcatalog`, the signed catalog source and
  artifact staging layer. It writes catalogs from descriptors, verifies catalog signatures,
  enforces source/URI policy including `crypta:` catalog sources, parses optional review/API
  compatibility metadata, verifies submission packages and pre-review/candidate metadata, verifies
  independent app-review receipts against trusted reviewer keys and local review policy, enforces
  catalog security advisory and exact-version denylist decisions, stores primary-plus-mirror source
  metadata, performs signed primary-then-mirror fallback refresh, retains bounded verified revision
  history, re-verifies explicit rollback candidates, reports catalog signing-key rotation status
  without key material, records emergency advisory refresh metadata, validates artifact size and
  SHA-256, safely extracts ZIP bundles, and delegates verified staged bundles to AppHost
  install/update flows.
- `:platform-trustgraph` owns `network.crypta.platform.trustgraph`, the local Trust Graph Local RC
  model and scoring layer. It parses bounded trust statement documents, canonicalizes and verifies
  statement payloads, builds redacted import previews, summarizes duplicate issuer conflicts,
  stores process-local anchors/statements, records local lifecycle status, and computes bounded
  deterministic direct trust scores without changing peer protocols or claiming full Web of Trust
  behavior.
- `:platform-devtools` owns `network.crypta.platform.devtools`, the standalone `crypta-app` CLI. It
  wires app template scaffolding, bundle validation, signing, packaging, verification, permission
  linting, offline UI linting, mock dev serving, offline app tests, developer key generation,
  app-store submission package/pre-review/candidate commands, publication plan dry-runs, explicit
  live USK catalog publication, API contract snapshot/compatibility verification, review receipt
  signing/verification, and catalog create/sign/verify commands around the platform distribution,
  API, design-system, and catalog libraries.
- `:platform-web-shell` owns the first browser-facing Web Shell v1 under
  `network.crypta.platform.webshell`. It provides the current node-management shell route
  constants, bootstrap payload, renderer, and static browser assets mounted at `/app/node/`; it
  opens app-owned `uiUrl` values when installed app summaries expose them and surfaces app catalog
  review, catalog source/mirror health, fallback warnings, rollback candidates, key-rotation
  status, emergency advisory refresh controls, unified consent previews, update candidate, staged
  update, policy, health-gate, rollback, app-data backup/restore controls, advertised app-service
  dependencies, grant-bundle approval/renewal state, Stable 1.0 lifecycle status/recovery guidance,
  and explicit legacy security/diagnostic fallback actions for operators.

### Runtime SPI (`network.crypta.runtime.spi`)
- Aggregate boundary: `RuntimePorts`
- Small ports include: `ExecutionPort`, `RandomnessPort`, `TransferAccessPort`, `LifecyclePort`,
  `ConfigPort`, `ConnectivityPort`, `ConnectionsPagePort`, `ConnectionsSupportPort`,
  `DarknetConnectionsPort`, `DarknetMessagingPort`, `DiagnosticPort`, `QueueSupportPort`,
  `QueueCompletionPort`, `QueuePagePort`, `QueueDownloadPort`, `QueueInsertPort`,
  `QueueMutationPort`, `StatisticsPort`, `SecurityLevelsPort`, `PageChromePort`,
  `CoreUpdateActionPort`, `FirstTimeWizardPort`, `ToadletSymlinkPort`, `WelcomePagePort`,
  `WelcomeActionPort`, `AlertFeedPort`, `AlertMutationPort`, `LegacyAdminUsagePort`,
  `RequestQueuePort`, `NodeInfoPort`, `PeerPort`, and `ContentFetchPort`
- Detached DTOs include config, connectivity, peer, darknet-friends, node-reference, queue,
  security-level, shared shell, first-time-wizard, symlinker, welcome-page, alert, and
  statistics/report snapshot types such as
  `ConfigSnapshot`, `ConfigFieldSet`, `ConfigSection`, `PeerSnapshot`,
  `DarknetConnectionPeerSnapshot`, `DarknetUploadedFile`, `NodeReferenceSnapshot`,
  `BoundedContentFetchRequest`, `BoundedContentFetchResult`, `ContentFetchException`,
  `QueuePageSnapshot`, `QueuePersistenceStatusSnapshot`, `QueueInsertOutcome`,
  `SecurityLevelsSnapshot`, `PageChromeSnapshot`, `FirstTimeWizardSnapshot`,
  `FirstTimeWizardCurrentBandwidthLimits`, `ToadletSymlinkEntry`, `WelcomePageSnapshot`,
  `AlertListSnapshot`, `AlertSnapshot`, `AlertSeverity`, `LegacyAdminUsageSnapshot`,
  `LegacyAdminSurfaceUsage`, `CoreSupportLifecycleSnapshot`, and
  `CoreSupportLifecycleStatus`
- Daemon-backed adapters in `network.crypta.runtime.core` (currently in `:runtime-node`):
  `LegacyRuntimePorts`, `LegacyConfigPort`,
  `LegacyConnectivityPort`, `LegacyNodeInfoPort`, `LegacyPeerPort`, `LegacyRequestQueuePort`,
  `LegacySecurityLevelsPort`, and `LegacyCoreUpdateActionPort`
- Daemon-backed adapters in `network.crypta.runtime.admin` (currently in `:runtime-node`):
  `LegacyConnectionsPagePort`,
  `LegacyConnectionsSupportPort`, `LegacyDarknetConnectionsPort`,
  `LegacyDarknetMessagingPort`, `LegacyDiagnosticPort`, `LegacyStatisticsPort`,
  `LegacyPageChromePort`, `LegacyQueuePagePort`, `LegacyQueueMutationPort`,
  `LegacyQueueSupportPort`, `LegacyFirstTimeWizardPort`, `LegacyToadletSymlinkPort`,
  `LegacyWelcomePagePort`, and `LegacyWelcomeActionPort`, plus queue helper seams under
  `network.crypta.runtime.admin.queue` and `network.crypta.runtime.admin.queue.page`
- Adapter-owned concrete FCP bridges in `network.crypta.clients.fcp.bridge`:
  `LegacyQueueCompletionPort`, `LegacyQueueDownloadPort`, `LegacyQueueInsertPort`,
  `CoreFcpPersistentRequestCatalog`, `FcpPersistentRequestRecoveryCodec`,
  `FcpQueueAdminBackend`, `FcpQueuePageBackend`, `FcpUserAlertFeedSubscriber`,
  `FcpUserAlertFeedMessageFactory`, `FcpPersistentRequestServices`, and endpoint-handle wrappers

### Plugin system
- The legacy in-process plugin runtime is frozen and removed from the node.
- Do not add `network.crypta.pluginmanager`, plugin toadlets, old plugin ABI compatibility, or old
  WebOfTrust/Freetalk/Sone/Freemail shims. Legacy FCP plugin command names should continue to
  fail deterministically through the unsupported-command handler, not execute plugin code.
- Plugin-like functionality should use out-of-process apps, signed catalogs, Platform API,
  AppVault, durable app data, budgeted content subscriptions, Trust Graph Local RC, and
  operator-approved app-service grants.

### Configuration (`network.crypta.config`)
- Main sources live in `:foundation-config`.
- Type-safe configuration with persistence
- Main localization sources and `crypta.l10n.en.properties` also live in `:foundation-config`
  under `network.crypta.l10n`.
- Shared setup helpers such as `DatastoreSizingSupport` also live in `:foundation-config`.
- Narrow callback-level UI markers such as
  `network.crypta.config.DirectorySelectionCallback` also live in `:foundation-config`, so HTTP
  admin code can classify directory-selection fields without importing concrete runtime-owned
  callback implementations.
- Higher layers should prefer the narrow `RuntimePorts` sub-port that already covers the needed
  operation (`config()`, `peer()`, `nodeInfo()`, `connectionsPage()`, `connectionsSupport()`,
  `darknetConnections()`, `darknetMessaging()`, `queuePage()`, `queueDownload()`,
  `queueInsert()`, `queueMutation()`, `queueSupport()`, `queueCompletion()`,
  `securityLevels()`, `pageChrome()`, `coreUpdateAction()`, `firstTimeWizard()`,
  `toadletSymlinks()`, `welcomePage()`, `welcomeAction()`, etc.) instead of traversing daemon
  internals directly
- File-system-based l10n tests still run from the root project and resolve main resources through
  `foundation-config/src/main/resources/network/crypta/l10n/`.

### Supporting infrastructure (`network.crypta.support`)
- Logging, data structures, threading, helpers
- `:foundation-support` now owns the stable generic support subset across `network.crypta.support`,
  `network.crypta.support.api`, `network.crypta.support.io`,
  `network.crypta.support.compress`, `network.crypta.support.math`,
  `network.crypta.support.transport.ip`, and `network.crypta.support.http`.
- `:foundation-support` also owns `network.crypta.io.AddressIdentifier`,
  `network.crypta.io.WritableToDataOutputStream`, `network.crypta.node.FastRunnable`,
  `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`,
  `network.crypta.support.IllegalValueException`, `network.crypta.support.JVMVersion`, the
  generic HTTP request/upload and multimap/size-formatting surface, generic helpers such as
  `URIPreEncoder`, `IOUtils`, and `LegacyFileSupport`, the cycle-safe file-backed support I/O
  slice, and `network.crypta.support.SerializationLimits`.
- The root project still owns daemon-coupled support code and higher-level wiring that is not yet
  stable enough to extract cleanly.

### Launcher/Desktop leaf module (`:launcher-desktop`)
- Swing launcher: `network.crypta.launcher`
- Desktop theme detection: `com.jthemedetecor`
- Vendored OSHI annotations and launcher resources

### Foundation leaf modules
- `:foundation-support`: stable generic `network.crypta.support*` subset plus
  `network.crypta.io.AddressIdentifier`, `network.crypta.io.WritableToDataOutputStream`,
  `network.crypta.node.FSParseException`, `network.crypta.node.FastRunnable`,
  `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`,
  `network.crypta.support.http`, `network.crypta.support.IllegalValueException`,
  `network.crypta.support.JVMVersion`, the generic `HTTPRequest` / `HTTPUploadedFile` /
  `MultiValueTable` / `SizeUtil` surface, generic helpers such as `URIPreEncoder`, `IOUtils`,
  `LegacyFileSupport`, and `HTMLDecoder`, and the cycle-safe file-backed support I/O slice
- `:foundation-store-contracts`: neutral `network.crypta.store` contracts plus
  `network.crypta.store.alerts`
- `:foundation-crypto-keys`: `network.crypta.crypt`, `network.crypta.keys`, plus adjacent
  support-IO helpers such as `BucketTools`, `NoFreeBucket`, and
  `PrependLengthOutputStream`
- `:foundation-store`: reusable `network.crypta.store` implementations
- `:interop-wire`: wire/message/schema/version/probe nucleus
- `:foundation-config`: `network.crypta.config`, `network.crypta.l10n`,
  `DatastoreSizingSupport`
- `:foundation-fs`: `network.crypta.fs`
- `:foundation-compat`: `network.crypta.compat`, `network.crypta.compat.bandwidth`
- `:kernel-content`: compile-neutral phase-1 content slice across selected `network.crypta.client*`
  classes, `network.crypta.client.async.persistence`, event/helper types such as
  `SplitfileCompatibilityMode*`, filter policy/helper types such as `HTMLFilterPolicy`, concrete
  media/CSS/HTML parser/filter helpers, `InsertUriChecks`, and `network.crypta.support.MediaType`
- `:kernel-transport`: compile-neutral phase-1 transport slice across selected
  `network.crypta.io*` helpers including `SSLNetworkInterface`
- `:kernel-routing`: compile-neutral phase-1 routing/helper slice across selected
  `network.crypta.node` helper/value types
- `:runtime-spi`: `network.crypta.runtime.spi`
- `:platform-api`: `network.crypta.platform.api`
- `:platform-apphost`: `network.crypta.platform.apphost`
- `:platform-app-ui`: `network.crypta.platform.appui`
- `:platform-appvault`: `network.crypta.platform.appvault`
- `:platform-sdk-js`: browser SDK resource under `network/crypta/platform/sdk/js`
- `:platform-appdist`: `network.crypta.platform.appdist`
- `:platform-appcatalog`: `network.crypta.platform.appcatalog`
- `:platform-trustgraph`: `network.crypta.platform.trustgraph`
- `:platform-devtools`: `network.crypta.platform.devtools`
- `:platform-web-shell`: `network.crypta.platform.webshell`
- `:runtime-alerts`: `network.crypta.runtime.alerts`, including the detached
  `UserAlertSurface`
- `:runtime-node`: extracted daemon runtime body across the remaining cyclic/high-level
  `network.crypta.client` body, the remaining peer/request/routing-engine
  `network.crypta.node` / `network.crypta.runtime.*` slices, the retained node-coupled
  transport/message execution code, and the remaining daemon-coupled support helpers
- `:adapter-fcp`: `network.crypta.clients.fcp`
- `:bridge-fcp-runtime`: `network.crypta.clients.fcp.bridge`
- `:adapter-http-legacy-admin`: shared legacy HTTP shell/admin layer plus matching resources
- `:adapter-http-legacy-browse`: concrete legacy browse/FProxy layer
- `:bridge-http-runtime`: `network.crypta.clients.http.bridge` and
  `network.crypta.clients.http.geoip`

### Vendored library leaf modules
- `:thirdparty-onion`: `com.onionnetworks`
- `:thirdparty-legacy`: `org.bitpedia`, `org.sevenzip`, `org.spaceroots`

### UID trace logging
- UID lifecycle tracing logs routing/timeout/finish events to `crypta-uidtrace-latest.log` to debug
  stuck requests/inserts.
- Disabled by default in `src/main/resources/logback.xml` (logger `network.crypta.uidtrace`).
- Enable by setting `logger.priorityDetail=network.crypta.uidtrace:INFO` (or `DEBUG`) and
  restarting. The log file is written under `logger.dirname` (falls back to `crypta.log.dir`).
