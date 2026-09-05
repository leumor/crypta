# Ownership in the partial multi-project build reference

Read for Ownership in the partial multi-project build, Distributions and Windows wrapper sources. Commands and unlinked source paths are relative to the repository root.

## Ownership in the partial multi-project build
- Packaging remains root-owned.
- The root project `:cryptad` still owns `buildJar`, `assembleCryptadDist`, `dist*`, `run`,
  `runLauncher`, and jpackage tasks.
- Current contributing leaf modules are `:foundation-support`, `:foundation-store`,
  `:foundation-store-contracts`, `:foundation-crypto-keys`, `:interop-wire`,
  `:foundation-config`, `:foundation-fs`, `:foundation-compat`, `:kernel-content`,
  `:kernel-transport`, `:kernel-routing`, `:runtime-spi`, `:platform-api`,
  `:platform-apphost`, `:platform-app-ui`, `:platform-appvault`, `:platform-appdist`,
  `:platform-appcatalog`, `:platform-trustgraph`, `:platform-design-system`,
  `:platform-devtools`, `:platform-sdk-js`, `:platform-web-shell`, `:runtime-alerts`,
  `:runtime-node`, `:adapter-fcp`,
  `:bridge-fcp-runtime`, `:bridge-http-runtime`, `:adapter-http-legacy-admin`,
  `:adapter-http-legacy-browse`, `:thirdparty-onion`,
  `:thirdparty-legacy`, and `:launcher-desktop`.
- Extracted leaf modules contribute jars and resources through the root runtime classpath.
- `:foundation-support` and `:foundation-store-contracts` contribute shared runtime classes via
  their leaf JARs like the other extracted modules.
- `:foundation-crypto-keys` and `:foundation-store` contribute the extracted crypto/key/store
  runtime classes through their leaf JARs.
- `:interop-wire` contributes the extracted message/schema/version/probe nucleus and serializer
  classes through its leaf JAR.
- `:foundation-config` contributes the config/l10n code and main l10n resources via its leaf JAR
  and re-exports `:foundation-support` and `:foundation-fs` where public APIs expose those types.
- The `:runtime-spi` JAR is packaged like the other leaf artifacts; packaging still produces one
  daemon distribution rooted at `:cryptad`.
- The `:platform-api` JAR contributes the transport-neutral Platform API v1 surface, compatibility
  contract, app-vault route handlers, generated app-document inserts, bounded content fetch,
  shared app-network budget service/store, durable content subscriptions, durable app data,
  app-data backup/restore routes, app-service dependency graph/grant-bundle routes, Trust Graph
  Local RC route handlers, and app-update lifecycle/scheduler coordination, and the
  `:platform-apphost` JAR contributes the transport-neutral local AppHost core, sandbox-provider
  selection, and durable bundle rollback used by that API.
- The `:platform-app-ui` JAR contributes app-owned static UI route/origin helpers used by the
  legacy HTTP admin adapter to serve isolated per-app loopback origins and the `/apps/{appId}/`
  compatibility fallback.
- The `:platform-appvault` JAR contributes app secret and identity vault records, local wrapping-key
  provider, grant metadata, and audit/redaction value types used by Platform API app/vault routes.
- The `:platform-appdist` JAR contributes signed local app bundle digest, signature, verifier,
  trusted-key, packager, and distribution-tool classes used by first-party app tasks, developer
  tooling, and AppHost validation.
- The `:platform-appcatalog` JAR contributes signed catalog source parsing, catalog writing,
  verification, Crypta catalog source fetching, app-store/API compatibility metadata parsing,
  independent app-review receipt trust metadata, catalog security advisory/denylist policy,
  artifact download, safe ZIP extraction, and verified staging support.
- The `:platform-trustgraph` JAR contributes local Trust Graph Local RC statement parsing,
  canonicalization, verification, process-local store/anchor behavior, lifecycle/status records,
  and deterministic scoring used by Platform API trust routes.
- The `:platform-design-system` JAR contributes canonical local static app UI assets and helper
  APIs used by first-party app staging and the standalone developer CLI. It is packaged as a normal
  leaf artifact but the CSS/JS bytes are copied into app bundles, not loaded from a daemon-hosted
  CDN.
- The `:platform-devtools` application builds the standalone `crypta-app` developer CLI
  distribution with its own `installDist` output, including scaffold, validation, signing,
  packaging, mock dev server, offline test, catalog, review, developer-key, and publication-plan
  helpers. It is developer tooling, not a daemon entrypoint inside `build/cryptad-dist`.
- The `:platform-sdk-js` JAR contributes the browser SDK resource staged into first-party static
  app bundles and loaded by app-owned UIs on isolated loopback origins or the `/apps/{appId}/`
  fallback.
- The `:platform-web-shell` JAR contributes the browser-facing node-management shell HTML, CSS,
  JavaScript, and bootstrap resources that the legacy HTTP adapter mounts at `/app/node/`,
  including app-service dependency/grant-bundle review, operator app-data backup/restore controls,
  and explicit legacy security/diagnostic fallback actions.
- The `:runtime-alerts` JAR contributes the detached alert/feed model subset, including the
  `UserAlertSurface` consumed by the legacy HTTP/admin shell.
- The `:runtime-node` JAR now carries a large extracted daemon runtime/node/client/support subset
  and participates in the root runtime classpath and packaged distribution like the other leaf
  artifacts.
- The `:adapter-fcp` JAR carries the extracted FCP adapter code, including the deterministic
  unsupported-command handler for old plugin FCP command names. It must not package a restored
  plugin runtime.
- The `:bridge-fcp-runtime` JAR carries the concrete runtime-binding
  `network.crypta.clients.fcp.bridge` implementations.
- The `:adapter-http-legacy-admin` JAR carries the shared legacy HTTP shell/admin classes plus the
  matching `network/crypta/clients/http/**` resources. Static files and templates now ship from
  that leaf JAR on the runtime classpath, so packaged/runtime code must treat them as classpath
  resources rather than plain files. This leaf also hosts the current `/api/v1/` bridge for
  `:platform-api`, the `/app/node/` bridge for `:platform-web-shell`, and the per-app loopback
  origin server used by isolated static app UIs, plus legacy-admin retirement policy, Wave 5
  final-surface metadata, and explicit retained emergency fallback routes.
- The `:adapter-http-legacy-browse` JAR carries the concrete legacy browse/FProxy classes.
- The `:bridge-http-runtime` JAR carries the concrete `network.crypta.clients.http.bridge`
  runtime-binding implementations plus the legacy HTTP `network.crypta.clients.http.geoip`
  helper package.
- Packaging does not have separate entrypoints per leaf project; it still assembles a single daemon
  artifact and distribution layout from the root build.
- First-party app projects such as `:apps:queue-manager`, `:apps:publisher`,
  `:apps:site-publisher`, `:apps:profile-publisher`, `:apps:social-inbox`,
  `:apps:feed-reader`, and `:apps:trust-graph` provide staged app bundles through their
  `stageApp`, `signApp`, and `verifyApp` tasks. Those bundles are release artifacts and AppHost
  install inputs; they are not daemon entrypoints inside `build/cryptad-dist`.
  Their static UI staging copies the current `:platform-sdk-js` browser resource and canonical
  `:platform-design-system` assets into each bundle's `static/` assets.

## Distributions and Windows wrapper sources
- `assembleCryptadDist` creates a portable layout under `build/cryptad-dist` with `bin/`, `lib/`, and `conf/`.
  - Non-Windows wrapper files come from the upstream Tanuki delta pack.
  - Windows x86_64/arm64 wrapper exe/DLL are fetched from the newest GitHub release of `crypta-network/wrapper-windows-build`.

### Override points (optional)
- `-PwrapperWinApiUrl=<api-url>` to pin a specific release API.
- `-PwrapperWinAmd64Url=<asset-url>` / `-PwrapperWinArm64Url=<asset-url>` to force asset URLs.

### Archives
- `distZipCryptad` / `distTarCryptad` → `build/distributions/cryptad-v<version>.(zip|tar.gz)`
- `distJlinkCryptad` → `build/distributions/cryptad-jlink-v<version>.(zip|tar.gz)`
- Both include Windows launchers and binaries.
- These general Gradle archive tasks normalize member order, timestamps, ownership, modes, and
  gzip/ZIP metadata inside the Java 25 Gradle build. They do not require Python; the Python release
  certification command independently verifies the resulting archive bytes.
- Archive modes come only from deterministic member-path roles, never host execute-access checks:
  ordinary files are `0644`, directories are `0755`, and only Unix/JRE launchers, jlink helper
  executables, and the shipped wrapper native libraries receive `0755`.
- The Python maintenance archive rewriter and independent hygiene gate must apply that same
  member-path policy. They must not preserve a source archive's execute bits or accept both `0644`
  and `0755` indiscriminately for regular files.
- Treat canonical member names as extraction identities. Reject raw `.` or empty components,
  trailing-slash file/directory aliases, duplicate canonical paths at every nested level, POSIX,
  drive-qualified, and UNC absolute paths, escaping symlink targets, and special files. Require
  closed gzip headers, only necessary canonical PAX extensions, empty ZIP archive/member comments
  and extra fields, and explicit Unix type/mode metadata for every ZIP member. Bound a nested
  member before reading or decompressing its bytes.
