# Core build commands reference

Read for Core build commands, Testing, Compile-only / quick checks. Commands and unlinked source paths are relative to the repository root.

## Core build commands
- Build the node JAR:
  - `./gradlew buildJar`
- Clean build:
  - `./gradlew clean buildJar`
- The build prints the SHA-256 of `build/libs/cryptad.jar`.

## Testing
Always give enough running time (more than 15 minutes) for Gradle to complete tests.
Use a pollable process with a total execution allowance longer than 15 minutes for a full suite.

- Run all tests:
  - `./gradlew test`
- Run one root-owned test class (use `:<module>:test` for a leaf):
  - `./gradlew :test --tests '*TestClassName'`
- Run one root-owned test method:
  - `./gradlew :test --tests '*TestClassName.methodName'`
- Run the focused leaf-local boundary suites:
  - `./gradlew :platform-api:test`
  - `./gradlew :platform-apphost:test`
  - `./gradlew :platform-app-ui:test`
  - `./gradlew :platform-appvault:test`
  - `./gradlew :platform-appdist:test`
  - `./gradlew :platform-appcatalog:test`
  - `./gradlew :platform-trustgraph:test`
  - `./gradlew :platform-design-system:test`
  - `./gradlew :platform-devtools:test`
  - `./gradlew :platform-sdk-js:test`
  - `./gradlew :platform-web-shell:test`
  - `./gradlew :kernel-content:test`
  - `./gradlew :kernel-transport:test`
  - `./gradlew :kernel-routing:test`
  - `./gradlew :runtime-node:test`
  - `./gradlew :adapter-fcp:test`
  - `./gradlew :bridge-fcp-runtime:test`
  - `./gradlew :bridge-http-runtime:test`
  - `./gradlew :adapter-http-legacy-admin:test`
  - `./gradlew :adapter-http-legacy-browse:test`
- Run the remaining root-owned Platform API/bootstrap slice explicitly against the root project:
  - `./gradlew :test --tests '*DefaultNodeRuntimeBridgeFactoriesTest' --tests '*PlatformApiRouterTest' --tests '*PlatformApiAppsIntegrationTest'`
- Run the focused Stable 1.0 lifecycle runtime and operator surface together:
  - `./gradlew :runtime-spi:test :runtime-node:test :platform-api:test :platform-web-shell:test`
- When changing lifecycle parsing, persistence, activation ordering, or revocation projection, run:
  - `./gradlew :runtime-node:test --tests '*CoreSupportLifecycleParserTest' --tests '*CoreSupportLifecycleStateTest' --tests '*CoreSupportLifecycleStoreTest' --tests '*CoreSupportLifecycleTransitionTest'`
- When changing subscriber scheduling, URI-scope fencing, package-action authorization, or
  update-key compromise handling, run the root-owned updater integration tests:
  - `./gradlew :test --tests '*CoreSupportLifecycleUpdaterTest' --tests '*CoreUpdaterTest' --tests '*NodeUpdateManagerTest' --tests '*NodeUpdaterTest' --tests '*RevocationCheckerTest' --tests '*UpdateOverMandatoryManagerTest'`
- When changing installer/store handoff or the detached updater SPI, also run:
  - `./gradlew :runtime-spi:test :adapter-http-legacy-admin:test`
  - `./gradlew :test --tests '*LegacyCoreUpdateActionPortTest' --tests '*CoreActionToadletTest'`

## Compile-only / quick checks
- Compile only:
  - `./gradlew compileJava`
- Compile the support leaf when you touched extracted generic support classes:
  - `./gradlew :foundation-support:classes`
  - Representative moved types: `URIPreEncoder`, `IOUtils`, `LegacyFileSupport`, `HTMLDecoder`,
    file-backed buckets, generic HTTP request/upload helpers.
- Compile the crypto/keys leaf when you touched `network.crypta.crypt`, `network.crypta.keys`,
  or the moved bucket/length helpers:
  - `./gradlew :foundation-crypto-keys:classes`
  - Representative moved types: `NoFreeBucket`, `BucketTools`,
    `PrependLengthOutputStream`.
- Compile the reusable store leaf when you touched extracted `network.crypta.store`,
  `network.crypta.store.caching`, or `network.crypta.store.saltedhash` code:
  - `./gradlew :foundation-store:compileJava`
- Compile the neutral store-contracts leaf when you touched `BlockMetadata`, `GetPubkey`, or
  `StorableBlock`, or the store-maintenance alert seam:
  - `./gradlew :foundation-store-contracts:compileJava`
- Compile the wire/version leaf when you touched moved message/schema/address/version/probe code:
  - `./gradlew :interop-wire:compileJava`
- Compile the config/l10n leaf when you touched extracted config or l10n sources:
  - `./gradlew :foundation-config:classes`
- Compile the compat leaf when you touched extracted compatibility helpers such as
  `network.crypta.compat.bandwidth`:
  - `./gradlew :foundation-compat:classes`
- Compile the phase-1 kernel-content leaf when you touched extracted compile-neutral client/content
  classes:
  - `./gradlew :kernel-content:compileJava`
  - Representative moved types: `ClientEventProducer`, `SplitfileCompatibilityMode*`,
    `HTMLFilterPolicy`, concrete media/CSS/HTML parser/filter helpers, `InsertUriChecks`,
    `PersistentRequestCoordinatorContext`, `ClientGetterOptions`.
- Compile the phase-1 kernel-transport leaf when you touched extracted compile-neutral transport
  helpers:
  - `./gradlew :kernel-transport:compileJava`
  - Representative moved types: `SSLNetworkInterface`, `NetworkInterface`,
    `AllowedHosts`, `SocketHandler`.
- Compile the phase-1 kernel-routing leaf when you touched extracted compile-neutral routing/helper
  classes:
  - `./gradlew :kernel-routing:compileJava`
  - Representative moved types: `RequestPriorityClasses`, `RequestClient`, `SendableRequestItem*`.
- Compile only the runtime SPI leaf when you touched just that JDK-only API surface:
  - `./gradlew :runtime-spi:compileJava`
- Compile the Platform API leaf when you touched `network.crypta.platform.api`:
  - `./gradlew :platform-api:compileJava`
- Compile the AppHost leaf when you touched `network.crypta.platform.apphost`:
  - `./gradlew :platform-apphost:compileJava`
- Compile the app-owned static UI leaf when you touched `network.crypta.platform.appui`:
  - `./gradlew :platform-app-ui:compileJava`
- Compile the app vault leaf when you touched `network.crypta.platform.appvault`:
  - `./gradlew :platform-appvault:compileJava`
- Compile the app distribution leaf when you touched `network.crypta.platform.appdist`:
  - `./gradlew :platform-appdist:compileJava`
- Compile the app catalog leaf when you touched `network.crypta.platform.appcatalog`:
  - `./gradlew :platform-appcatalog:compileJava`
- Compile the Trust Graph Local RC leaf when you touched `network.crypta.platform.trustgraph`:
  - `./gradlew :platform-trustgraph:compileJava`
- Compile the developer app CLI leaf when you touched `network.crypta.platform.devtools`:
  - `./gradlew :platform-devtools:compileJava`
- Process and test the Platform SDK resource leaf when you touched
  `platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js`:
  - `./gradlew :platform-sdk-js:processResources :platform-sdk-js:test`
- Compile the Web Shell leaf when you touched `network.crypta.platform.webshell`:
  - `./gradlew :platform-web-shell:compileJava`
- Compile the extracted runtime-alerts leaf when you touched `network.crypta.runtime.alerts`:
  - `./gradlew :runtime-alerts:compileJava`
- Compile the extracted runtime-node leaf when you touched daemon runtime, node, client, xfer, or
  remaining support code that now lives there:
  - `./gradlew :runtime-node:compileJava`
- Compile the FCP adapter leaf when you touched `network.crypta.clients.fcp`:
  - `./gradlew :adapter-fcp:compileJava`
- Compile the concrete FCP bridge leaf when you touched `network.crypta.clients.fcp.bridge`:
  - `./gradlew :bridge-fcp-runtime:compileJava`
- Compile the shared legacy HTTP admin leaf when you touched shared shell/admin
  `network.crypta.clients.http` sources or admin-owned resources:
  - `./gradlew :adapter-http-legacy-admin:compileJava :adapter-http-legacy-admin:processResources`
- Compile the concrete legacy HTTP browse leaf when you touched browse/FProxy classes:
  - `./gradlew :adapter-http-legacy-browse:compileJava`
- Compile the concrete legacy HTTP runtime bridge leaf when you touched
  `network.crypta.clients.http.bridge` or `network.crypta.clients.http.geoip`:
  - `./gradlew :bridge-http-runtime:compileJava`
- Compile the root project and its unchanged test tree against the leaf-module layout:
  - `./gradlew compileJava compileTestJava`
