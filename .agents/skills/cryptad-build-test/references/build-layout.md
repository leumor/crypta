# Build layout reference

Read for Build layout. Commands and unlinked source paths are relative to the repository root.

## Build layout
- Cryptad now uses a partial multi-project Gradle build.
- Use root-project tasks by default; the root project remains the daemon/application target.
- Current leaf projects are `:foundation-support`, `:foundation-store`,
  `:foundation-store-contracts`, `:foundation-crypto-keys`, `:interop-wire`,
  `:foundation-config`, `:foundation-fs`, `:foundation-compat`, `:kernel-content`,
  `:kernel-transport`, `:kernel-routing`, `:runtime-spi`, `:platform-api`,
  `:platform-apphost`, `:platform-app-ui`, `:platform-appvault`, `:platform-appdist`,
  `:platform-appcatalog`, `:platform-trustgraph`, `:platform-design-system`,
  `:platform-devtools`, `:platform-sdk-js`, `:platform-web-shell`, `:runtime-alerts`,
  `:runtime-node`, `:adapter-fcp`,
  `:bridge-fcp-runtime`, `:bridge-http-runtime`,
  `:adapter-http-legacy-admin`, `:adapter-http-legacy-browse`, `:thirdparty-onion`,
  `:thirdparty-legacy`, and `:launcher-desktop`.
- First-party app bundle projects live under `:apps:queue-manager`, `:apps:publisher`,
  `:apps:site-publisher`, `:apps:profile-publisher`, `:apps:social-inbox`,
  `:apps:feed-reader`, and `:apps:trust-graph`.
- The extracted leaf projects compile separately, but `buildJar`, `run`, `runLauncher`,
  `assembleCryptadDist`, and jpackage tasks are still rooted at `:cryptad`.
- `:foundation-support` owns the current stable generic support subset under
  `network.crypta.support*`, `network.crypta.support.transport.ip`,
  `network.crypta.support.http`, `network.crypta.io.AddressIdentifier`,
  `network.crypta.io.WritableToDataOutputStream`, `network.crypta.node.FSParseException`,
  `network.crypta.node.FastRunnable`, `network.crypta.node.PrioRunnable`,
  `network.crypta.node.SemiOrderedShutdownHook`, `network.crypta.support.IllegalValueException`,
  `network.crypta.support.JVMVersion`, the generic `HTTPRequest` / `HTTPUploadedFile` /
  `MultiValueTable` / `SizeUtil` surface, generic helpers such as `URIPreEncoder`, `IOUtils`,
  `LegacyFileSupport`, and `HTMLDecoder`, plus the cycle-safe file-backed support I/O slice.
- `:foundation-store-contracts` owns the neutral `network.crypta.store` contracts
  `BlockMetadata`, `GetPubkey`, and `StorableBlock`, plus the `network.crypta.store.alerts`
  seam.
- `:foundation-crypto-keys` owns `network.crypta.crypt`, `network.crypta.keys`, and the adjacent
  `BucketTools` / `NoFreeBucket` / `PrependLengthOutputStream` helpers.
- `:foundation-store` owns reusable `network.crypta.store` implementations plus
  `network.crypta.store.caching` and `network.crypta.store.saltedhash`.
- `:interop-wire` owns the narrow wire/message/schema/version/probe nucleus:
  leaf-safe `network.crypta.io.comm` message/schema classes, `network.crypta.node.Version`,
  `network.crypta.node.probe.Error` and `Type`, and `network.crypta.support.Serializer`.
- `:foundation-config` owns the main `network.crypta.config` and `network.crypta.l10n` sources,
  plus shared setup helpers such as `DatastoreSizingSupport`. Its public APIs now re-export
  `:foundation-support` and `:foundation-fs` where needed.
- `:foundation-compat` owns extracted compatibility helpers under `network.crypta.compat`,
  including the wizard-neutral bandwidth support moved to
  `network.crypta.compat.bandwidth`.
- `:kernel-content` owns the compile-neutral phase-1 content slice across selected
  `network.crypta.client`, `network.crypta.client.events`, `network.crypta.client.filter`,
  `network.crypta.client.async.alerts`, `network.crypta.client.async.persistence`,
  event/helper types such as `SplitfileCompatibilityMode*`, filter policy/helper types such as
  `HTMLFilterPolicy`, concrete media/CSS/HTML parser/filter helpers, `InsertUriChecks`, and
  `network.crypta.support.MediaType`.
- `:kernel-transport` owns the compile-neutral phase-1 transport slice across selected
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` helpers such as
  allow-list parsing, listener abstraction, `SSLNetworkInterface`, I/O statistics collection,
  throttling, and partially received block assembly.
- `:kernel-routing` owns the compile-neutral phase-1 routing/helper slice across selected
  `network.crypta.node` value, exception, callback, and request-item helper types such as
  `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`, `RequestClient`,
  `PeerStatusCounts`, `RecentlyFailedReturn`, `RequestPriorityClasses`, and
  `SendableRequestItem*`.
- Every extracted internal leaf must keep leaf-owned aggregated-output metadata in sync at
  `<leaf>/gradle/owned-output-patterns.txt`, even for structurally separate package/resource
  moves. Non-clean builds and branch switches can leave stale non-owner aggregated outputs behind,
  and `buildJar` still packages aggregated main outputs before leaf outputs.
- When moving additional main classes/resources from root into any extracted leaf, update that
  leaf's `owned-output-patterns.txt` and validate with
  `./gradlew verifySelectiveLeafOwnershipMetadata buildJar`.
- Focused leaf-local boundary tests now freeze the current extracted layout.
  `RuntimeNodeKernelSplitPrepBoundaryTest`, `KernelContentBoundaryTest`,
  `KernelTransportBoundaryTest`, `KernelRoutingBoundaryTest`, `PlatformApiBoundaryTest`,
  `AdapterFcpBoundaryTest`, `BridgeFcpRuntimeBoundaryTest`, `AppHostBoundaryTest`,
  `CryptaPlatformSdkBoundaryTest`, `WebShellBoundaryTest`, `HttpLegacyAdminBoundaryTest`,
  `LegacyHttpBrowseBoundaryTest`, and `BridgeHttpRuntimeBoundaryTest` are the focused regression
  checks for leaf ownership/import boundaries. The runtime, kernel, platform, FCP, and HTTP
  boundary suites also enforce
  `package-info.java` coverage for the production packages they own.
- `:runtime-spi` is the JDK-only runtime/config API leaf. Leaf-owned focused tests, including the
  support-lifecycle snapshot contract, live under `runtime-spi/src/test/java`; remaining broad
  runtime/bootstrap SPI tests still run through the root build.
- `:platform-api` owns the transport-neutral Platform API v1, deterministic compatibility contract,
  Platform API 1.0 stable-baseline metadata, app capability/audit decisions, app-vault route
  handlers, content/app-data/subscription/service routes, app-data backup/restore planning and
  commit routes, app-service dependency graph and grant-bundle routes, shared app-network budget
  service/store, app-update lifecycle service, app-data migration planning/execution and internal
  update snapshots, host/operator-only catalog operation routes, and host/operator-only beta
  dashboard/support-bundle, typed operator RC recovery, network-budget snapshots, and the
  host/operator-only Stable 1.0 support-lifecycle snapshot route. Its
  focused leaf tests now live under
  `platform-api/src/test/java`.
- `:platform-apphost` owns the transport-neutral out-of-process AppHost core, sandbox
  policy/status reporting, Linux bubblewrap provider selection, durable rollback records,
  data/cache quota enforcement, and focused leaf tests under `platform-apphost/src/test/java`.
- `:platform-app-ui` owns app-owned static UI route, isolated origin metadata, path, content-type,
  header, asset resolver, launch-proof bootstrap, and browser-session helpers plus focused tests
  under `platform-app-ui/src/test/java`.
- `:platform-appvault` owns the app secret and identity vault records, local key provider, grant
  metadata, redaction/audit value types, and focused tests under
  `platform-appvault/src/test/java`.
- `:platform-appdist` owns signed local app bundle digest, signature, verifier, manifest,
  app-data schema/migration metadata parsing, deterministic packager, and distribution-tool code
  plus focused tests under `platform-appdist/src/test/java`.
- `:platform-appcatalog` owns signed catalog source parsing, catalog writer/descriptor support,
  verification, `crypta:` catalog source fetching, app-store/API compatibility metadata,
  submission package/pre-review/candidate metadata, independent app-review receipt trust metadata,
  primary-plus-mirror source operations, mirror fallback refresh, verified revision history,
  explicit rollback re-verification, catalog signing-key rotation status, emergency advisory
  refresh metadata, artifact download, safe ZIP extraction, and verified staging code plus focused
  tests under `platform-appcatalog/src/test/java`.
- `:platform-trustgraph` owns Trust Graph Local RC statement parsing, canonicalization,
  verification, process-local store/anchor behavior, import-preview summaries,
  duplicate-issuer/conflict handling, lifecycle/status records, and bounded deterministic scoring
  explanations plus focused tests under `platform-trustgraph/src/test/java`.
- `:platform-design-system` owns the canonical local app UI CSS/JS resources plus safe
  asset-listing, hashing, and bundle-copy helpers. Its focused tests live under
  `platform-design-system/src/test/java`.
- `:platform-devtools` owns the standalone `crypta-app` developer CLI, including API snapshot and
  compatibility verification commands and offline app UI linting, plus focused CLI/linter tests
  under `platform-devtools/src/test/java`.
- `:platform-sdk-js` owns the dependency-free browser SDK resource and focused resource/boundary
  tests under `platform-sdk-js/src/test/java`.
- `:platform-web-shell` owns the browser-facing Web Shell leaf, including app/catalog/update/review
  views, catalog source/mirror health and guarded catalog operation controls, app-service
  dependency/grant-bundle review, operator beta dashboard, Operator RC Recovery, app-data
  backup/restore controls, Stable 1.0 lifecycle status and recovery guidance, legacy explicit
  fallback actions, and focused leaf tests under
  `platform-web-shell/src/test/java`.
- `:runtime-alerts` owns the extracted leaf-safe `network.crypta.runtime.alerts` feed/model
  subset plus the detached `UserAlertSurface` used by legacy HTTP/admin code.
- `:runtime-node` is the extracted daemon runtime leaf. It now owns the remaining cyclic/high-level
  `network.crypta.client` body, the remaining peer/request/routing-engine side of
  `network.crypta.node`, the retained node-coupled transport/message execution code in
  `network.crypta.io*`, `network.crypta.runtime.*`, the package updater and Stable 1.0
  support-lifecycle subscriber/parser/store/state integration, and the remaining daemon-coupled
  support helpers.
- `:adapter-fcp` owns the detached protocol-side `network.crypta.clients.fcp` tree.
- `:bridge-fcp-runtime` owns the concrete runtime-binding
  `network.crypta.clients.fcp.bridge` implementations, remains the only FCP leaf with the direct
  `:runtime-node` binding, and keeps its focused leaf tests under
  `bridge-fcp-runtime/src/test/java`.
- `:bridge-http-runtime` owns the concrete `network.crypta.clients.http.bridge` runtime-binding
  implementations plus the legacy HTTP `network.crypta.clients.http.geoip` helper package, with
  focused leaf tests under `bridge-http-runtime/src/test/java`.
- `:adapter-http-legacy-admin` owns the detached shared legacy `network.crypta.clients.http`
  shell, admin toadlets, `/api/v1/` and `/app/node/` bridge entrypoints, Platform API
  form-password guards for mutating host/operator routes such as catalog operations, and the
  matching `network/crypta/clients/http/**` main resources.
- `:adapter-http-legacy-browse` owns the concrete browse/FProxy routes, toadlets, and helper
  models under `network.crypta.clients.http`, with focused leaf tests under
  `adapter-http-legacy-browse/src/test/java`.
- On the root test/runtime classpath, admin-owned HTTP resources often resolve from the leaf JAR,
  so tests must treat them as classpath resources rather than assume a plain filesystem `Path`.
- Most tests still live in the root project and compile against the leaf subprojects through the
  root build, but the extracted boundary suites now live with their owning leaves under each
  module's `src/test/java` tree.
- File-system-based l10n tests still run from the root project and use
  `foundation-config/src/main/resources/network/crypta/l10n/` as the main resource path.
