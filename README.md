<p align="center"><img src="docs/images/crypta_logo.png" alt="Crypta Logo" width="160"></p>
<h1 align="center" style="padding-top: 0; margin-top: 0;"><strong>Crypta</strong></h1>
<p align="center"><em><strong>Crypta</strong> is a privacy‑first, decentralized datastore and app platform — a modern fork of Hyphanet/Freenet.</em></p>

<p align="center">
  <a href="https://github.com/crypta-network/cryptad/actions/workflows/ci.yml">
    <img alt="CI" src="https://github.com/crypta-network/cryptad/actions/workflows/ci.yml/badge.svg?branch=main" />
  </a>
  <a href="https://www.gnu.org/licenses/gpl-3.0">
    <img alt="License: GPLv3" src="https://img.shields.io/badge/license-GPLv3-blue.svg" />
  </a>
  <img alt="Java 25+" src="https://img.shields.io/badge/Java-25%2B-007396?logo=openjdk" />
  <img alt="Gradle" src="https://img.shields.io/badge/Build-Gradle-02303A?logo=gradle" />
</p>

## Overview

**Crypta** is a platform for censorship‑resistant communication and publishing. It is a fork of Hyphanet (formerly Freenet)
that builds on its core ideas while modernizing usability, performance, and developer experience. **Crypta** provides a
peer‑to‑peer, distributed, encrypted, and decentralized datastore on top of which applications such as forums, chat,
micro‑blogs, and websites can run without central servers.

Why fork? Hyphanet/Freenet pioneered privacy‑preserving routing and content‑addressed storage, but several long‑standing
frictions hold it back:

- Usability and onboarding: confusing opennet/darknet concepts, painful first‑run setup, and limited, dated UIs make it
  hard for new users to join and stay.
- Performance for cold content: the anonymity model and multi‑hop routing can lead to slower retrievals, especially for
  infrequently accessed data; bootstrap and NAT traversal further compound early‑session latency.
- Observability without compromising privacy: network‑wide performance and health are hard to measure, making tuning and
  evolution slow and error‑prone.

**Crypta**’s vision is to keep the privacy and resilience, while making it pleasant, fast, and sustainable to use and build
on:

- User experience first: a modern web UI, sensible defaults, and a one‑click guided onboarding that hides complexity
  (smart opennet bootstrap, optional darknet linking later).
- Faster routing and retrieval: adaptive, locality‑aware routing; popularity‑sensitive caching; opportunistic prefetch;
  and transport updates (e.g., QUIC/HTTP‑3, improved congestion control, and better NAT traversal) for lower tail
  latency.
- Safe observability: privacy‑preserving telemetry and reproducible benchmarking harnesses to inform tuning without
  leaking user data.
- A better platform: typed configuration and testable interfaces to make extending the network
  straightforward.

This repository contains the reference node (the “**Crypta** reference daemon”) that participates in the network, stores
data, and serves applications.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/screenshot_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/screenshot_light.png">
  <img alt="Fallback image description" src="docs/images/screenshot_dark.png">
</picture>

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Building](#building)
- [Signed App Bundles](#signed-app-bundles)
- [App Platform Beta](#app-platform-beta)
- [Developer App CLI](#developer-app-cli)
- [Platform Closeout & API Surface](#platform-closeout--api-surface)
- [Trust Graph Preview](#trust-graph-preview)
- [Hyphanet Interop Gate](#hyphanet-interop-gate)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Running Your Build](#running-your-build)
- [Development Guidelines](#development-guidelines)
- [Dependencies](#dependencies)
- [Spotless + Dependency Verification](#spotless--dependency-verification)
- [Versioning](#versioning)
- [Branching & Releases](#branching--releases)
- [Update System](#update-system)
- [Architecture Overview](#architecture-overview)
- [License](#license)

## Quick Start

Choose one of the following options.

### A) Install via Packages (recommended)

- Windows
  - This repository does not build Windows installers. Use the portable distribution or the
    jpackage app image below. If a Windows installer is published on the project’s Releases page,
    you can install it by double‑clicking; if SmartScreen warns, click “More info” → “Run anyway”.

- macOS (.dmg)
  - Download the DMG from the Releases page and open it.
  - Drag “Crypta.app” to Applications. If Gatekeeper blocks it, right‑click → Open (or allow in Settings → Privacy & Security).
  - Launch “Crypta” from Applications/Launchpad.

- Debian/Ubuntu (.deb)
  - Install from a local .deb:
    ```bash
    sudo apt install ./Crypta-<version>_amd64.deb   # adjust arch/version
    ```

- Fedora/RHEL/openSUSE (.rpm)
  - Install from a local .rpm:
    ```bash
    sudo dnf install ./Crypta-<version>.x86_64.rpm  # or: sudo zypper install ./...
    ```

- Snap (.snap)
  - Local snap install (not from store):
    ```bash
    sudo snap install --dangerous ./crypta-<version>.snap
    ```

- Flatpak (.flatpak or .flatpakref)
  - Local Flatpak bundle:
    ```bash
    flatpak install --user ./crypta-<version>-amd64.flatpak
    flatpak run network.crypta.cryptad//v1
    ```

Linux servers (no desktop environment)
- On systems without a desktop environment, the installer (deb/rpm) creates a systemd unit `cryptad.service` and enables it, but does not start it automatically. You must start it manually after installation:
  ```bash
  sudo systemctl start cryptad
  ```

After installation, start Crypta from your OS application launcher (on desktops). The app starts the daemon, opens the UI in your browser on the first successful start, and manages start/stop for you.

### B) Portable Distribution (for developers)

Build the portable distribution and run the Swing launcher without installing system packages:

```bash
./gradlew assembleCryptadDist
build/cryptad-dist/bin/cryptad-launcher    # Windows: cryptad-launcher.bat
```

The launcher starts the daemon, streams live logs, waits for a structured readiness file under the
resolved runtime directory (currently `<runDir>/platform-ui.properties`), and opens
`http://localhost:<port>/` on the first successful start. If the readiness file cannot be used,
the launcher can still fall back to the legacy `Starting FProxy on ...:<port>` log line.

Shortcuts (global):
- ↑/↓ one row; PgUp/PgDn one page.
- ←/→ move focus among the three buttons (wrap‑around).
- Enter/Space click the focused button; s start/stop; q quit.

Notes
- Live output combines the wrapper’s console with tailing of the wrapper log file when configured, so JVM logs appear while the wrapper is running.
- On Unix/macOS the launcher uses a pseudo‑tty (via `script`) when available to reduce buffering.

## Building

We use the [Gradle Wrapper](https://docs.gradle.org/9.7.1/userguide/gradle_wrapper.html). If you trust the committed
wrapper, you can build immediately.

See the [dependency baseline](docs/dependency-upgrade-9.7.1.md) for the reviewed library,
build-tool, CI, and Docker versions and the compatibility checks for this upgrade.

Prerequisites:

- Java 25 or newer
- A POSIX shell or Windows terminal

Build the node JAR (prints SHA‑256 of the output):

```bash
./gradlew buildJar
```

Clean build:

```bash
./gradlew clean buildJar
```

### Project Layout

Cryptad now uses a partial multi-project Gradle build.

- The root project remains the daemon/application project. It still owns the daemon JAR, tests,
  `run`, `runLauncher`, `assembleCryptadDist`, and jpackage task graph.
- `:foundation-support` owns the current stable generic support subset under
  `network.crypta.support`, `network.crypta.support.api`, `network.crypta.support.io`,
  `network.crypta.support.compress`, `network.crypta.support.math`,
  `network.crypta.support.transport.ip`, and `network.crypta.support.http`, plus
  `network.crypta.io.AddressIdentifier`, `network.crypta.io.WritableToDataOutputStream`,
  `network.crypta.node.FSParseException`, `network.crypta.node.FastRunnable`,
  `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`,
  `network.crypta.support.IllegalValueException`, `network.crypta.support.JVMVersion`, the generic
  `HTTPRequest` / `HTTPUploadedFile` / `MultiValueTable` / `SizeUtil` support surface, and the
  generic utility/file-helper surface around `URIPreEncoder`, `IOUtils`, `LegacyFileSupport`, and
  `HTMLDecoder`, plus the cycle-safe file-backed support I/O slice (`BaseFileBucket`,
  `FileBucket`, `FileRandomAccessBuffer`, `PersistentTempFileBucket`,
  `PooledFileRandomAccessBuffer`, `TempFileBucket`, and their related
  exceptions/factories).
- `:foundation-store-contracts` owns the neutral `network.crypta.store` contracts
  `BlockMetadata`, `GetPubkey`, and `StorableBlock`, plus the store-maintenance alert seam under
  `network.crypta.store.alerts`.
- `:foundation-crypto-keys` owns `network.crypta.crypt`, `network.crypta.keys`, and the
  crypto-adjacent `network.crypta.support.io.BucketTools`,
  `network.crypta.support.io.NoFreeBucket`, and
  `network.crypta.support.io.PrependLengthOutputStream` helpers.
- `:foundation-store` owns the reusable `network.crypta.store` implementations plus
  `network.crypta.store.caching` and `network.crypta.store.saltedhash`.
- `:interop-wire` owns the narrow wire/message/schema/version/probe nucleus: leaf-safe
  `network.crypta.io.comm` message/schema classes, `network.crypta.node.Version`,
  `network.crypta.node.probe.Error` and `Type`, and `network.crypta.support.Serializer`.
- `:foundation-config` owns `network.crypta.config`, `network.crypta.l10n`, and the main
  `network/crypta/l10n/crypta.l10n.en.properties` resource plus shared config helpers such as
  `DatastoreSizingSupport`. Its public APIs now export `:foundation-support` and `:foundation-fs`
  where config types expose `SimpleFieldSet` or filesystem-facing value types.
- `:foundation-fs` owns `network.crypta.fs`.
- `:foundation-compat` owns `network.crypta.compat`, including compatibility helpers such as the
  extracted bandwidth-detection support under `network.crypta.compat.bandwidth`, plus the shared
  `network.crypta.runtime.core.SSL` helper.
- `:kernel-content` owns the compile-neutral phase-1 content slice across selected
  `network.crypta.client`, `network.crypta.client.events`, `network.crypta.client.filter`,
  `network.crypta.client.async.alerts`, `network.crypta.client.async.persistence`, the leaf-safe
  `network.crypta.client.events` contract/helper subset (`ClientEventListener`,
  `ClientEventProducer`, `SimpleEventProducer`, `EventLogger`, `EventDumper`,
  `SplitfileProgressEvent`, `SplitfileCompatibilityModeEvent`, `SplitfileCompatibilityMode`), the
  leaf-safe `network.crypta.client.async` utility/value subset (`BlockSet`, `BinaryBlob`,
  `BinaryBlobFormatException`, `BinaryBlobWriter`, `CacheFetchResult`, `ClientGetterOptions`,
  `ClientPutterOptions`, `PersistenceDisabledException`, `TooManyFilesInsertException`), the
  client failure/filter exception subset, selected filter policy/helper types such as
  `HTMLFilterPolicy`, concrete media/CSS/HTML parser and filter helpers, the MIME helper
  `network.crypta.support.MediaType`, and the small manifest/model helper subset under
  `network.crypta.support.*` (`ManifestElement`, `ContainerSizeEstimator`) plus
  `InsertUriChecks` that stay free of `:runtime-node`, adapter, and root-composition
  dependencies.
- `:kernel-transport` owns the compile-neutral phase-1 transport slice across selected
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` helpers such as
  address matching, allowlist parsing, listener abstraction, `SSLNetworkInterface`,
  I/O statistics collection, transfer throttling, and partially received block assembly that stay
  free of `:runtime-node`, adapters, and root-composition dependencies.
- `:kernel-routing` owns the compile-neutral phase-1 routing/helper slice across selected
  `network.crypta.node` value, exception, callback, and request-item helper types such as
  `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`, `RequestClient`,
  `PeerStatusCounts`, `RequestPriorityClasses`, and `SendableRequestItem*` that stay free of
  `:runtime-node`, adapters, and root-composition dependencies.
- `:runtime-spi` owns `network.crypta.runtime.spi` and the JDK-only runtime/config boundary used
  by higher layers, including the admin-HTTP config, connectivity, connections, queue,
  security-levels, shared page-chrome, core-update action, first-time-wizard, symlinker, and
  welcome-page slices plus shared path constants such as `ConnectivityPagePaths` and
  `UpdaterPaths`.
- `:platform-api` owns the transport-neutral Platform API v1 under
  `network.crypta.platform.api`. It sits above `:runtime-spi`, exposes detached runtime snapshots
  and local AppHost control operations as JSON-oriented responses, and is currently mounted at
  `/api/v1/` through a thin legacy HTTP bridge in `:adapter-http-legacy-admin`. The current surface
  covers node, connectivity, queue, peers, config, security levels, updates, wizard/welcome, alerts,
  diagnostics, apps, app catalogs, app vault routes, app data and backup/restore, content
  fetch/subscriptions, Trust Graph Local RC routes, app-service dependencies/grant bundles, operator
  beta support routes, and the deterministic `/api/v1/platform/contract` compatibility snapshot;
  `GET /api/v1/config` defaults to the effective `CURRENT` section when `sections=` is omitted.
- `:platform-apphost` owns the transport-neutral out-of-process AppHost v1 core under
  `network.crypta.platform.apphost`. It defines the local manifest, installed-app layout, process
  lifecycle, per-start launch-token plumbing, sandbox status reporting, data/cache quota checks,
  and bounded process-log handling for local apps.
- `:platform-app-ui` owns app-owned static UI route helpers under
  `network.crypta.platform.appui`. It maps static app UI metadata to isolated per-app loopback
  origins with `/apps/{appId}/` as a compatibility fallback, resolves installed-bundle assets,
  issues origin-bound short-lived browser sessions for static app API calls, and enforces
  traversal, symlink, and content-type boundaries before the HTTP adapter streams files.
- `:platform-appvault` owns app secret and identity vault records under
  `network.crypta.platform.appvault`. It provides local vault storage models, wrapping-key lookup,
  app-owned/shared identity grants, and audit/redaction value types without exposing raw secret
  values or private identity material to browser UI.
- `:platform-design-system` owns the canonical local app UI design-system resources under
  `network.crypta.platform.designsystem`, including CSS tokens, base `cr-*` classes, optional
  progressive-enhancement JavaScript, and safe asset metadata/copy helpers for staged static app
  bundles.
- `:platform-sdk-js` owns the dependency-free browser SDK resource used by app-owned static UI
  bundles. First-party app staging copies this SDK into staged `static/` assets so pages can use
  the same bootstrap, Platform API, mutation, error, and fragment-sanitization helpers.
- `:platform-appdist` owns the local app distribution tooling used to digest, sign, package, and
  verify staged AppHost bundles, including optional manifest API compatibility metadata.
- `:platform-appcatalog` owns signed app catalog parsing, catalog writing, signature verification,
  remote/local/Crypta catalog fetching, app-store metadata parsing, artifact digest checks, safe
  ZIP extraction, reviewer-key lifecycle governance, local review transparency logging, and
  verified staging for AppHost install/update flows.
- `:platform-trustgraph` owns the local Trust Graph Local RC statement model, strict JSON parsing,
  canonicalization, verification, process-local anchor/store behavior, lifecycle/status records,
  and deterministic direct scoring. It is a local preview service, not the old Web of Trust plugin
  or a network protocol change.
- `:platform-devtools` owns the standalone `crypta-app` developer CLI for scaffolding, validating,
  UI linting, signing, packaging, verifying, catalog-authoring, API contract snapshotting, and
  compatibility verification for standalone staged bundles.
- `:platform-web-shell` owns the first browser-facing Web Shell v1 under
  `network.crypta.platform.webshell`. It keeps the node-management shell's route constants,
  bootstrap payload, HTML renderer, and plain browser assets self-owned while staying separate
  from runtime, adapter, Platform API, and AppHost implementation code. It also owns the operator
  panels for app-service dependency/grant-bundle review, app-data backup/restore, and explicit
  legacy security/diagnostic fallbacks. That shell is mounted at `/app/node/` through a thin legacy
  HTTP bridge in `:adapter-http-legacy-admin`.
- `:runtime-alerts` owns the extracted leaf-safe alert/feed subset under
  `network.crypta.runtime.alerts`, including the full `feed` package plus the reusable alert
  model/base types that no longer need direct daemon state, along with the detached
  consumer-facing `UserAlertSurface` used by the legacy HTTP/admin shell.
- `:runtime-node` owns the remaining daemon runtime body across the still-cyclic
  `network.crypta.client` async/request engine and high-level client APIs, large slices of
  `network.crypta.node` after the phase-1 routing/helper move, the retained runtime-owned client
  context and metadata implementation, and the retained node-coupled transport/message execution
  code in
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer`, the remaining
  daemon-bound `network.crypta.runtime.*` implementation slices, and the remaining daemon-coupled
  `network.crypta.support` / `network.crypta.support.io` / `network.crypta.support.api` subset
  after the generic HTTP, multimap, size-formatting, and file-backed bucket slice moved into
  `:foundation-support` and the manifest/model helper subset moved into `:kernel-content`.
- `:adapter-fcp` owns the detached protocol-side `network.crypta.clients.fcp` package tree and
  its protocol-side persistent-bucket/filter seams. It does not depend directly on
  `:runtime-node`. See [docs/fcp-boundary.md](docs/fcp-boundary.md) for the explicit maintenance
  boundary.
- `:bridge-fcp-runtime` owns the concrete runtime-binding bridge package
  `network.crypta.clients.fcp.bridge`, including the live persistent-bucket and content-filter
  bindings, and remains the only FCP leaf that depends directly on `:runtime-node`.
- `:adapter-http-legacy-admin` owns the shared legacy `network.crypta.clients.http` shell, the
  admin toadlets, the `/api/v1/` and `/app/node/` bridge entrypoints, and the matching
  `network/crypta/clients/http/**` main resources such as `staticfiles/**` and `templates/**`.
  It is detached from `:runtime-node`, keeps the browse-neutral shell and seam types, and no
  longer owns the concrete browse/FProxy implementations. See
  [docs/legacy-http-boundary.md](docs/legacy-http-boundary.md) for the explicit maintenance
  boundary.
- `:adapter-http-legacy-browse` owns the concrete legacy browse/FProxy routes, toadlets, helper
  models, and browse-only packages under `network.crypta.clients.http`.
- `:bridge-http-runtime` owns the concrete `network.crypta.clients.http.bridge` runtime-binding
  leaf plus the legacy HTTP `network.crypta.clients.http.geoip` helper package. It depends on the
  browse leaf for concrete browse construction while keeping the admin-owned shell seams intact.
- `:thirdparty-onion` owns `com.onionnetworks` and `lib/fec.properties`.
- `:thirdparty-legacy` owns `org.bitpedia`, `org.sevenzip`, and `org.spaceroots`.
- `:launcher-desktop` owns `network.crypta.launcher`, `com.jthemedetecor`, `oshi`, and launcher
  resources.
- The daemon runtime body now spans extracted leaves plus a thin root composition layer. The root
  project still owns the daemon/application build, packaging/runtime tasks, most broad
  functional/unit/integration tests, `network.crypta.tools`, and root-local composition code such
  as `network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories`. The extracted leaves now
  keep their own focused boundary suites alongside the code they protect.
- Every extracted leaf keeps its aggregated-output ownership metadata in
  `<leaf>/gradle/owned-output-patterns.txt`. When you move main classes or resources between root
  and a leaf, or between leaves, update that metadata and validate it with
  `./gradlew verifySelectiveLeafOwnershipMetadata buildJar` so stale non-owner outputs do not leak
  back into aggregated builds.
- Higher-level infrastructure now crosses a narrower boundary through
  `network.crypta.runtime.spi.RuntimePorts`, the minimal wire-side `MessageSource` seam used by
  leaf-owned messages, the new phase-1 `:kernel-content` content slice, the phase-1
  `:kernel-transport` helper slice, the phase-1 `:kernel-routing` helper slice, client-owned seams
  such as `network.crypta.client.async.alerts`,
  `network.crypta.client.async.persistence`, and the leaf-safe
  `network.crypta.client.async` utility/value subset, and runtime-owned seams such as
  `network.crypta.runtime.alerts.feed`, `network.crypta.runtime.fcp`,
  `network.crypta.runtime.http`, `network.crypta.runtime.http.security`,
  `network.crypta.runtime.peers.reference`, and `network.crypta.runtime.persistence`.
- Default production bridge selection now starts in
  `network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories`. Concrete adapter
  implementations stay in `network.crypta.clients.fcp.bridge` under
  `:bridge-fcp-runtime`, `network.crypta.clients.http.bridge` under `:bridge-http-runtime`, and
  `network.crypta.clients.http.updater` under `:adapter-http-legacy-admin`, while higher-level
  runtime code depends on runtime-owned seam types such as
  `network.crypta.runtime.endpoints.fcp.FcpEndpointHandle`,
  `network.crypta.runtime.http.HttpShellContainer`, and
  `network.crypta.runtime.http.security.PasswordFormPageRenderer`. For HTTP, this bootstrap
  factory remains the production binding site that imports the concrete bridge classes from the
  extracted bridge leaf.

The wrapper validates the distribution URL (`validateDistributionUrl=true` in
`gradle/wrapper/gradle-wrapper.properties`). To also verify the download by checksum, add
`distributionSha256Sum=<sha256>` for the chosen Gradle distribution.

## Signed App Bundles

Local AppHost app bundles keep `stageApp` unsigned by default and use separate signing and
verification tasks for first-party bundles.

Common commands:

```bash
./gradlew stageFirstPartyApps
./gradlew signFirstPartyApps \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPrivateKeyFile=/abs/path/to/dev-app-signing-private.pem
./gradlew verifyFirstPartyApps \
  -PcryptadAppSigningKeyId=dev-local \
  -PcryptadAppSigningPublicKeyFile=/abs/path/to/dev-app-signing-public.pem
```

Signed staged bundles add `cryptad-app.digests` and `cryptad-app.signature` at the bundle root. The digest uses deterministic SHA-256 file entries, and the signature uses Ed25519 over the exact digest sidecar bytes.

Signed app catalogs add a verified source layer above signed bundles. See
[`docs/app-catalogs.md`](docs/app-catalogs.md) for the `cryptad-app-catalog.properties` format,
catalog signatures, trusted-key configuration, optional app-store/API compatibility metadata,
independent app review receipts, reviewer-key configuration, review policy modes, and
`/api/v1/app-catalogs` install/update flow. See
[`docs/app-review-governance.md`](docs/app-review-governance.md) for reviewer-key v2 lifecycle
metadata, policy-version constraints, the local tamper-evident review transparency log, governance
API routes, Web Shell review-history surfaces, and `crypta-app review` inspection commands. Catalog
signatures authenticate catalog bytes and publisher metadata, artifact digests bind entries to ZIP
bytes, bundle signatures authenticate app bundles, and review receipt signatures independently
authenticate reviewer evidence. Legacy catalog `review.status` and `review.note` metadata remains
publisher-advisory only.

Installed apps can also declare browser UI ownership with `app.ui.mode` and `app.ui.entry`.
Static UI bundles prefer isolated loopback origins per app; `/apps/{appId}/` remains a
compatibility fallback, and shell-panel bundles keep existing local links such as
`/app/node/#queue`. See [`docs/app-owned-ui.md`](docs/app-owned-ui.md) for the route contract,
origin-bound bootstrap JSON, restricted Platform API CORS behavior, security headers, and static
asset boundary. The repo-owned Queue Manager, legacy Publisher, Site Publisher, Profile Publisher,
Social Inbox Preview, Feed Reader, and Trust Graph Preview bundles now stage static UIs that open
through the isolated app UI path when available, including the browser SDK described in
[`docs/platform-sdk-js.md`](docs/platform-sdk-js.md) and the canonical UI design-system assets
described in [`docs/app-ui-design-system.md`](docs/app-ui-design-system.md). Site Publisher is the
content reference app for publishing workflows. Profile Publisher is the identity-profile reference
app: it creates an app-owned identity, asks Cryptad to produce a profile document, and queues the
generated app document without exporting private keys or recording raw signatures in release
evidence. Feed Reader is the content-fetch and subscription reference app: it uses bounded content
fetch, durable USK content subscriptions, durable app data, and generated feed-document publication
without recording raw feed bodies, request bodies, private insert URIs, tokens, form passwords, or
local paths. Social Inbox Preview is the social/mail-like migration reference app: it composes
bounded social-message signing, generated outbox inserts, durable subscriptions, durable app data,
and operator-approved Trust Graph service annotations outside daemon core. Legacy Publisher remains
the compatibility replacement for old insert admin pages. Trust Graph Preview is the local
trust-service reference app: it uses direct Trust Graph routes, bounded AppVault trust-statement
signing, content fetch/subscriptions, durable app data for UI-local state, and the v12
`trust.score` app-service provider to demonstrate direct/imported trust statements and local anchors
without claiming full WoT, old plugin compatibility, moderation, or daemon-core trust behavior.

Production-facing installs reject unsigned bundles by default. To install signed bundles through a
live node, configure a trusted public key with `CRYPTAD_APPHOST_TRUSTED_KEY_ID` plus
`CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_BASE64` or `CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_FILE`, or use
`CRYPTAD_APPHOST_TRUSTED_KEYS_FILE`. `CRYPTAD_APPHOST_ALLOW_UNSIGNED=true` is an explicit
development-only escape hatch for unsigned local testing.

Do not commit production private signing keys to this repository. Keep local development keys
outside the repo and pass them through Gradle properties or environment variables. Catalog-backed
install/update endpoints are available now; catalog-backed candidate detection and explicit
apply-when-stopped updates are implemented, and the background scheduler refreshes signed catalogs
and checks installed apps through the same lifecycle service. Silent auto-update is not the
default: manual remains the default policy, and automatic staging or apply requires an explicit
operator-selected policy. Review policy defaults to advisory display, with stricter modes
available for explicit acknowledgement or trusted-positive receipt requirements. See
[docs/app-update-lifecycle.md](docs/app-update-lifecycle.md) for scheduler state, manual apply,
review gates, and rollback scope.
Apps that request local vault access use `vault.secrets.*` and `vault.identities.*` capabilities.
Those grants distinguish app-owned identities from operator-shared identities and carry separate
process/browser, lifecycle, audit, and redaction rules. Profile publishing uses
`POST /api/v1/app-vault/identities`,
`POST /api/v1/app-vault/identities/{identityId}/profile-document`, and
`POST /api/v1/queue/inserts/app-document`; see
[docs/app-secret-and-identity-vault.md](docs/app-secret-and-identity-vault.md).
See [docs/app-distribution.md](docs/app-distribution.md) for the full workflow and exact signing
inputs.

## App Platform Beta

Public-beta onboarding starts at
[docs/public-beta/README.md](docs/public-beta/README.md). It links role-based paths for beta
users/operators, installers, first-party app users, developers, former plugin authors, security
reporters, reviewers, and release managers.

The app ecosystem beta is documented through
[docs/app-platform-developer-portal.md](docs/app-platform-developer-portal.md). Start there for
the current Platform API contract version, first-party app map, offline beta tutorials, known
limitations, beta feedback and app submission workflow, and release-manager closeout path.

The beta is offline-first for developer tests and dry-run publication planning. Release operators
can publish a signed first-party catalog with `crypta-app publish-usk --live` when a localhost node,
form password, trusted public catalog key, and private insert URI are supplied through secure
configuration. That live workflow publishes `cryptad-app-catalog.properties` and the sibling
`cryptad-app-catalog.signature` at the same USK edition and writes sanitized evidence. It does not
create a public production app store, does not auto-install recommended catalog apps, does not
require public Crypta network access for tests, and does not change FNP, FCP, Hyphanet/Freenet
compatibility behavior, or retained FProxy browse behavior.

## Developer App CLI

Standalone app authors can use `crypta-app` for staged bundle scaffolding, validation, signing,
packing, and catalog generation. The command is delivered by the `:platform-devtools` application
plugin:

```bash
./gradlew :platform-devtools:installDist
platform-devtools/build/install/crypta-app/bin/crypta-app --help
```

The common flow is:

```bash
crypta-app init \
  --dir build/dev-apps/hello-queue \
  --app-id hello-queue \
  --name "Hello Queue" \
  --version 0.1.0 \
  --ui-mode static \
  --permission queue.read
crypta-app ui lint --bundle-dir build/dev-apps/hello-queue --strict
crypta-app validate --bundle-dir build/dev-apps/hello-queue --strict
crypta-app sign \
  --bundle-dir build/dev-apps/hello-queue \
  --key-id dev-local \
  --private-key-file /abs/path/to/dev-app-signing-private.pem
crypta-app pack \
  --bundle-dir build/dev-apps/hello-queue \
  --output dist/apps/hello-queue-0.1.0.zip \
  --overwrite
crypta-app verify \
  --bundle-dir build/dev-apps/hello-queue \
  --trusted-key-id dev-local \
  --trusted-public-key-file /abs/path/to/dev-app-signing-public.pem
crypta-app api snapshot --output build/platform-api-contract.json
crypta-app compat verify \
  --bundle-dir build/dev-apps/hello-queue \
  --contract build/platform-api-contract.json
```

`crypta-app init` writes a standalone staged bundle directory, not a new Gradle subproject. Static
scaffolds copy or vendor the browser SDK as `static/crypta-platform.js` when available and copy the
canonical app UI design-system assets into `static/crypta-ui/`. The CLI is local developer
tooling; it does not add hot reload or a daemon-side install command. Third-party scaffolds and
submission checks reject internal and host/operator-only capabilities. `vault.identities.manage`
is operator-only; app authors should use the documented app-facing vault capabilities only when
their workflow needs them.

`crypta-app catalog create` descriptors can author optional store metadata such as homepage,
source, license, categories, advisory review status/note, permission rationales, screenshot URL
metadata, changelog metadata, and advisory minimum Cryptad version. Descriptors without those
fields and without API compatibility metadata generate minimal `catalog.version=1` catalogs;
descriptors or artifacts with store/API compatibility metadata generate at least
`catalog.version=2`. An explicit `api.targetBaseline` requires `catalog.version=7`, so older strict
consumers reject the new compatibility subject instead of ignoring it. See
[docs/app-dev-cli.md](docs/app-dev-cli.md) for descriptor fields.

`crypta-app review sign` and `crypta-app review verify` create and check independent review
receipt properties files offline. `crypta-app catalog create --review-receipt` embeds a receipt
into the generated catalog entry so Platform API responses can expose `reviewTrust` alongside the
legacy advisory `review` object.

First-party apps can keep using `:apps:queue-manager`, `:apps:publisher`,
`:apps:site-publisher`, `:apps:profile-publisher`, `:apps:social-inbox`,
`:apps:feed-reader`, and `:apps:trust-graph` `stageApp`, `signApp`, and `verifyApp` tasks. See
[docs/app-platform-developer-portal.md](docs/app-platform-developer-portal.md) for the beta
developer portal, [docs/app-platform-beta-tutorials.md](docs/app-platform-beta-tutorials.md) for
copyable offline flows, [docs/app-dev-cli.md](docs/app-dev-cli.md) for the standalone CLI flow,
and [docs/app-catalogs.md](docs/app-catalogs.md) for catalog entry descriptors and verification.
The developer beta toolkit walkthrough is in
[docs/developer-beta-toolkit.md](docs/developer-beta-toolkit.md). External app authors should use
[docs/third-party-developer-beta-program.md](docs/third-party-developer-beta-program.md),
[docs/third-party-app-submission-checklist.md](docs/third-party-app-submission-checklist.md), and
[docs/platform-api-compatibility-support-window.md](docs/platform-api-compatibility-support-window.md)
before generating a submission package.

## Platform Closeout & API Surface

Phase 3 Platform Primacy makes `:platform-api`, `:platform-web-shell`, and `:platform-apphost` the
primary local platform path for operator workflows and first-party apps. Legacy HTTP remains the
bridge for `/api/v1/`, `/app/node/`, `/apps/{appId}/`, retained FProxy browse, and pending legacy
tools; FCP remains a separate compatibility protocol. The first legacy-admin removal wave now
returns replacement responses for selected already-replaced admin pages instead of rendering them
as normal fallback surfaces.

Phase 5 app-platform work added signed catalog sources, Crypta catalog transport, app-owned static
UI routes, browser sessions for static app API calls, richer catalog review metadata, AppHost
sandbox/quota visibility, the `crypta-app` developer CLI, and the first independent first-party app
UIs. Later reference-app work adds Queue Manager, Publisher, Site Publisher, Profile Publisher,
Social Inbox Preview, Feed Reader, and Trust Graph Preview as the current repo-owned app set. Phase
6 adds isolated per-app loopback origins for static app UIs while
retaining `/apps/{appId}/` as a compatibility fallback, and adds the first enforced Linux AppHost
process sandbox provider through bubblewrap for supported `restricted-process` launches. Installed
apps can be launched through `/app/node/` shell-panel links or through isolated app UI URLs when the
signed bundle declares `app.ui.mode=static`. Phase 6 also adds a canonical local app UI design
system and offline UI linting so first-party and third-party static UIs can check CSP-compatible
resources, SDK/bootstrap ordering, permission disclosure, accessibility basics, and platform
consistency before signing. The deterministic Platform API compatibility contract lets app
manifests, signed catalogs, developer tooling, and release certification compare API contract
versions without changing endpoint behavior. The Web Shell Apps section uses
`/api/v1/app-catalogs` metadata to show source, license, category, review, permission-rationale,
version-difference, API compatibility, and changelog details before install or update.
PR-221 adds Site Publisher as the first content reference app without changing peer protocol
behavior or wiring it into the legacy insert-page retirement map. PR-226 adds Profile Publisher as
the first identity-profile reference app, plus the profile-document and app-document insert routes
needed for browser-safe profile publishing. PR-227 adds Feed Reader as the content-fetch reference
app, with Platform API v6 `POST /api/v1/content/fetch`, the `content.fetch` permission, and SDK
feed helpers. PR-228 adds Trust Graph Preview as the local trust-service reference app, with
Platform API v7 trust routes, `trust.read`, `trust.write`, SDK trust helpers, and the bounded
AppVault trust-statement signing route. Phase 8 expands the app platform with explicit live USK
catalog publication, durable USK content subscriptions, durable app-owned data, a file-backed Trust
Graph store with exchange/import support, Social Inbox Preview, and contract v12 app-service
discovery/grants for local platform-mediated app-to-app calls.
Later RC work adds app-data backup/restore portability, app-data schema migrations, Trust Graph
Local RC lifecycle evidence, Social Inbox RC threading and trust annotations, and contract v16
app-service dependency graphs plus grant bundles.
Phase 6 PR-8, tracked as `legacy-admin.removal-wave-1`, removes `/downloads/`, `/uploads/`,
`/insertfile/`, `/insert-browse/`, `/friends/`, `/addfriend/`, `/strangers/`, and
`/connectivity/` by default when their replacements are reachable: safe reads redirect to Queue
Manager, Publisher, or Web Shell, while mutating requests are blocked before old handlers run.
Configurations without the replacement static app UI, without FProxy JavaScript, or without Web
Shell as the advertised primary UI keep rendering the legacy fallback and count that usage in
diagnostics. FProxy browse, retained browse-adjacent tools, and pending routes remain reachable.
Phase 7 PR-230, tracked as `legacy-admin.removal-wave-2`, extends removal-by-default to safe reads
for alerts, config, core-update status, statistics, and reviewed queue helper routes when their Web
Shell or Queue Manager replacements are reachable. Config POST mutations are blocked through the
replacement gate, while mutating legacy alert bulk actions, core-update installer and package-store
actions, diagnostic export, content filter, FProxy browse, wizard, node-to-node messages,
translation, help, chat, Platform API, Web Shell, and app-owned UI routes remain reachable.
Phase 8 PR-244, tracked as `legacy-admin.removal-wave-3`, redirects safe reads for the
security-levels route to Web Shell security when that replacement is reachable. The exact
`legacyFallback=security-levels` marker remains the explicit same-origin fallback for legacy
password, recovery, and high-physical-security flows.
Phase 9 PR-254, tracked as `legacy-admin.removal-wave-4`, makes Web Shell diagnostics the default
destination for `/diagnostic/` safe reads when the shell is reachable. The legacy plaintext export
is available only through the exact support fallback marker
`legacyFallback=diagnostic-export`; arbitrary diagnostic query strings, mutating requests, and
subpaths do not bypass the removal policy. FProxy browse/content rendering, content filter,
startup wizard/recovery flows, security recovery fallback, chat, translation, help, and
node-to-node messages remain outside Wave 4.
Phase 10 moves the app ecosystem from prototype to production beta readiness. It adds first-party
maintenance policy metadata, freezes the Platform API 1.0 stable baseline, adds deterministic
third-party submission/review/catalog-candidate tooling, unifies user-consent upgrade UX, hardens
Trust Graph Local RC and Social Inbox RC, finalizes the retained legacy admin surface, adds the
production security response runbook, records multi-node beta soak and upgrade/rollback/backup
drills, documents the external third-party developer beta program with the stable-only
`hello-stable` sample, and adds the production beta go/no-go dashboard as the final launch
decision artifact. These gates do not create a hosted public app store or introduce production
signing material into local tests.

Stable 1.0 release work keeps readiness, RC freezing, GA authorization, and publication separate.
The canonical `stable-rc` command builds and freezes one reviewable candidate with deterministic
product and evidence archives. The side-effect-free `stable-ga` command then authenticates that
exact freeze, requires post-freeze production evidence and an explicit protected authorization,
and proves that the GA product digest is identical to the RC product digest. Only the explicitly
dispatched protected workflow may create or verify `v<build-number>` and the GitHub Release, and it
must verify the public catalog state; neither command merges the release branch or publishes during
local tests.

After GA, `stable-maintenance` authenticates the immutable GA root and complete no-fork successor
history before it freezes or authorizes one later integer-build maintenance or security-hotfix
candidate. Support-state changes use the separate `stable-lifecycle` component and protected
`support-lifecycle` update-key document. They do not rewrite published `core-info.json`, GA
artifacts, maintenance receipts, or successor baselines. Nodes consume that descriptor locally and
retain a last-known-good support snapshot without centralized telemetry.

Key docs:

- [Phase 3 Platform Primacy closeout](docs/phase-3-platform-primacy-closeout.md)
- [Platform API and Web Shell surface](docs/platform-api-surface.md)
- [Platform API compatibility contract](docs/platform-api-contract.md)
- [App platform developer portal](docs/app-platform-developer-portal.md)
- [App platform beta tutorials](docs/app-platform-beta-tutorials.md)
- [App platform beta program](docs/app-platform-beta-program.md)
- [Developer app CLI](docs/app-dev-cli.md)
- [Developer beta toolkit](docs/developer-beta-toolkit.md)
- [Third-party developer beta program](docs/third-party-developer-beta-program.md)
- [Third-party app submission checklist](docs/third-party-app-submission-checklist.md)
- [Platform API compatibility support window](docs/platform-api-compatibility-support-window.md)
- [Third-party Hello Stable SDK example](docs/examples/third-party-hello-stable.md)
- [Signed App Distribution](docs/app-distribution.md)
- [Signed app catalogs](docs/app-catalogs.md)
- [First-party beta app catalog](docs/first-party-beta-catalog.md)
- [Production beta release pipeline](docs/production-beta-release-pipeline.md)
- [Production beta go/no-go dashboard](docs/production-beta-go-no-go-dashboard.md)
- [Stable 1.0 readiness gate](docs/stable-1.0-readiness-gate.md)
- [Stable 1.0 RC execution and release freeze](docs/stable-1.0-rc-execution-and-release-freeze.md)
- [Stable 1.0 RC validation and GA promotion](docs/stable-1.0-rc-validation-and-ga-promotion.md)
- [Stable 1.0 maintenance release and security hotfix path](docs/stable-1.0-maintenance-release-and-hotfix-path.md)
- [Stable 1.0 support lifecycle and deprecation governance](docs/stable-1.0-support-lifecycle-and-deprecation-governance.md)
- [Multi-node beta soak and upgrade drill](docs/multi-node-beta-soak-and-upgrade-drill.md)
- [App-owned static UI](docs/app-owned-ui.md)
- [App UI design system](docs/app-ui-design-system.md)
- [Platform JavaScript SDK](docs/platform-sdk-js.md)
- [Durable app data store](docs/app-data-store.md)
- [App-data backup, restore, and portability](docs/app-data-backup-restore-portability.md)
- [Feed Reader reference app](docs/feed-reader-reference-app.md)
- [Social Inbox Preview reference app](docs/social-inbox-reference-app.md)
- [App-service discovery and grants](docs/app-service-discovery-and-grants.md)
- [Trust Graph Preview](docs/trust-graph-preview.md)
- [AppHost runtime hardening](docs/apphost-runtime-hardening.md)
- [App permissions and audit](docs/app-permissions-and-audit.md)
- [App secret and identity vault](docs/app-secret-and-identity-vault.md)
- [App review governance](docs/app-review-governance.md)
- [App update lifecycle](docs/app-update-lifecycle.md)
- [App platform beta known limitations](docs/app-platform-beta-known-limitations.md)
- [Legacy admin retirement plan](docs/legacy-retirement-plan.md)
- [Legacy plugin freeze policy](docs/legacy-plugin-freeze-policy.md)
- [Legacy plugin migration guide](docs/legacy-plugin-migration-guide.md)
- [Production security response runbook](docs/production-security-response-runbook.md)
- [Release certification](docs/release-certification.md)

## Hyphanet Interop Gate

The packaged-node Hyphanet interop smoke gate lives under `tools/interop/` and is wired into CI as
the `interop-smoke` job. Local usage, baseline configuration, diagnostics, and follow-ups are
documented in [tools/interop/README.md](tools/interop/README.md).

Fast parser/client self-test:

```bash
python3 tools/interop/interop_smoke.py --self-test
```

Full gate when the local environment is prepared:

```bash
tools/interop/run-hyphanet-interop-smoke.sh
```

## Performance Regression Gate

The lightweight packaged-node performance regression gate lives under `tools/perf/`. Local usage,
metrics, baseline policy, CI behavior, and interpretation guidance are documented in
[tools/perf/README.md](tools/perf/README.md).

Fast self-test with Python 3.12 or newer:

```bash
python3 tools/perf/perf_smoke.py --self-test
```

Smoke run when the local environment is prepared:

```bash
tools/perf/run-performance-smoke.sh
```

## Release Certification

Release-candidate evidence is aggregated by the release certification tooling under
`tools/release-certification/`. It consumes the interop, performance, app-platform, catalog,
Platform API contract, app-owned UI, trusted app-review receipt, app-data backup/restore,
app-service dependency/grant-bundle, network-scale soak, multi-node beta soak, third-party
developer beta, production security response, legacy plugin freeze, legacy-admin retirement and
final-surface evidence, and CI summaries. It writes a redacted report plus a stable JSON
companion. The report also includes historical comparison output and ecosystem gates when a
previous certified summary is provided. `legacy-admin.removal-wave-1` through
`legacy-admin.removal-wave-5`, `legacy-admin.final-admin-surface`,
`legacy-plugin.freeze-policy`, `multi-node-beta.*`, `third-party-developer.*`, and
`app-data.backup-restore-portability` are release-candidate-blocking deterministic evidence and do
not require a live node.

Run the complete offline certification suite:

```bash
python3 tools/release-certification/certify.py self-test all
```

Focused self-tests are also available:

```bash
python3 tools/release-certification/certify.py app-platform-docs --self-test
python3 tools/release-certification/certify.py release-certification --self-test
python3 tools/release-certification/certify.py app-platform --self-test
python3 tools/release-certification/certify.py network-scale-soak --self-test
python3 tools/release-certification/certify.py multi-node-beta --self-test
python3 tools/release-certification/certify.py go-no-go --self-test
python3 tools/release-certification/certify.py production-beta --self-test
python3 tools/release-certification/certify.py stable-rc --self-test
python3 tools/release-certification/certify.py stable-ga --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py stable-lifecycle --self-test
```

Generate a local report:

```bash
python3 tools/release-certification/certify.py release-certification \
  --manifest tools/release-certification/manifests/developer-dry-run.json
```

Generate release-candidate evidence:

```bash
cp tools/release-certification/manifests/release-candidate.example.json \
  build/release-candidate.json
# Replace every REPLACE_ME value and select the candidate release ID before running.
python3 tools/release-certification/certify.py release-certification --manifest build/release-candidate.json
```

Set `inputs.previousCandidate` and `inputs.releaseHistory` in the manifest when the previous
release's candidate-bound v2 summaries have been restored locally or in CI. Use `migrate-v1` for
the first v2 candidate; normal component inputs reject legacy summaries. The command writes the
common evidence envelope, report, redaction report, and supporting artifacts below
`<out-root>/<release-id>/release-certification/`.

Stable 1.0 uses four additional candidate-bound components under the same release workspace:

- `stable-rc` executes the protected production stages, freezes the candidate, verifies
  post-package drift, and emits deterministic product/archive checksums and provenance.
- `stable-ga` selects and authenticates the latest successful freeze, validates exact-RC-bound
  post-freeze evidence and authorization, and emits a promotion plan and maintenance baseline
  without creating a tag, Release, branch, catalog update, or network insert.
- `stable-maintenance` authenticates GA and the immediate published predecessor, freezes one
  built-once maintenance or security-hotfix candidate, and prepares protected publication and
  successor-baseline artifacts without publishing during ordinary validation.
- `stable-lifecycle` derives the published Stable 1.0 inventory from authenticated receipts and
  baselines, evaluates monotonic support-state transitions, and prepares a separately versioned
  lifecycle descriptor without mutating historical release artifacts.

Use the checked-in example manifests only as templates. Copy them below `build/`, replace every
placeholder, and follow the protected workflow instructions in the linked RC and GA runbooks.

See [docs/release-certification.md](docs/release-certification.md) for required evidence,
including `app-review.trusted-receipts`, `app-review.policy`,
`app-review.first-party-catalog`, `app-update.live-catalog-refresh`,
`app-platform.content-subscriptions`, `network-content.subscription-scheduler`,
`app-platform.durable-app-data-store`, `reference-app.profile-publisher`,
`reference-app.feed-reader`, `reference-app.social-inbox`, `reference-app.trust-graph`,
`app-services.registry`, `app-services.grants`, `app-services.trust-score-provider`,
`app-services.web-shell`, `app-services.redaction`, `network-scale.*`, `multi-node-beta.*`,
`third-party-developer.*`, app-vault capability/redaction evidence, historical comparison,
ecosystem gates, structured waivers, optional live-node evidence, production beta promotion
summaries, the go/no-go dashboard, and redaction rules.

## Trust Graph Preview

Trust Graph Preview is a reference app and local preview API for direct trust statements, local
anchors, and deterministic local scoring. It stores trust data in a durable local preview store,
signs bounded trust statements through AppVault without exporting private identity material, imports
selected trust statements through bounded content fetch or durable content subscriptions, and
advertises a local `trust.score` app-service provider. Other apps, including Social Inbox Preview,
can invoke that service only through Platform API mediation after an operator-approved grant.

The preview is intentionally not a full Web of Trust implementation. It does not implement the old
WebOfTrust plugin, PluginTalker/FCP plugin compatibility, global moderation, automatic content
blocking, background crawling, daemon-core identity sharing, wire-protocol changes, routing
changes, datastore changes, peer-management changes, or FProxy browse removal. See
[docs/trust-graph-preview.md](docs/trust-graph-preview.md).

## Testing

- Run all tests:

```bash
./gradlew test
```

- Run a specific test class:

```bash
./gradlew test --tests *TestClassName
```

- Run a specific test method:

```bash
./gradlew test --tests *TestClassName.methodName
```

For extraction and boundary work, run the focused leaf-local boundary suites that freeze current
leaf ownership and import rules:

```bash
./gradlew :platform-api:test
./gradlew :platform-apphost:test
./gradlew :platform-app-ui:test
./gradlew :platform-appvault:test
./gradlew :platform-design-system:test
./gradlew :platform-appdist:test
./gradlew :platform-appcatalog:test
./gradlew :platform-devtools:test
./gradlew :platform-sdk-js:test
./gradlew :platform-trustgraph:test
./gradlew :platform-web-shell:test
./gradlew :kernel-content:test
./gradlew :kernel-transport:test
./gradlew :kernel-routing:test
./gradlew :runtime-node:test
./gradlew :adapter-fcp:test
./gradlew :bridge-fcp-runtime:test
./gradlew :bridge-http-runtime:test
./gradlew :adapter-http-legacy-admin:test
./gradlew :adapter-http-legacy-browse:test
```

Those boundary suites also enforce the current extracted-leaf documentation convention that the
production packages they own keep the required `package-info.java`.

Run the remaining root-owned composition and router slice against the root project explicitly:

```bash
./gradlew :test --tests *DefaultNodeRuntimeBridgeFactoriesTest --tests *PlatformApiRouterTest --tests *PlatformApiAppsIntegrationTest
```

Additional root and mixed verification slices remain available:

```bash
./gradlew :adapter-http-legacy-admin:test
./gradlew :test --tests *PlatformApiRouterTest --tests *PlatformApiAppsIntegrationTest
```

Platform checks now live in `:platform-api`, `:platform-apphost`, `:platform-app-ui`,
`:platform-appvault`, `:platform-design-system`, `:platform-appdist`, `:platform-appcatalog`,
`:platform-devtools`, `:platform-sdk-js`, `:platform-trustgraph`, and `:platform-web-shell`.

## Code Quality

- Compile only:

```bash
./gradlew compileJava
```

- Formatting via Spotless is configured; see the Spotless and Dependency Verification section if verification blocks resolution.
- Gradle daemon is enabled by default; avoid passing `--no-daemon`.

## Running Your Build

To try your local build of **Crypta**:

1. Build it with `./gradlew buildJar`.
2. Stop your running node.
3. Replace the existing node JAR with `build/libs/cryptad.jar` produced by the build.
4. Start your node again.

If you want to test the launcher without the real daemon, build with a dummy script that simulates
output (including the FProxy line):

```
./gradlew -PuseDummyCryptad=true assembleCryptadDist
build/cryptad-dist/bin/cryptad-launcher
```

Distribution (Java Service Wrapper):

- Build a portable distribution (downloads the Tanuki wrapper and assembles bin/conf/lib):

```
./gradlew assembleCryptadDist
```

- Package it as a tar.gz:

```
./gradlew distTarCryptad
```

The resulting tree at `build/cryptad-dist` contains:
- `bin/cryptad` and wrapper binaries
- `bin/cryptad-launcher` (and `cryptad-launcher.bat` on Windows)
- `conf/wrapper.conf` configured to use `lib/*.jar`
- `lib/cryptad.jar`, runtime dependencies, and `lib/wrapper.jar`

The launcher defers config path resolution to the runtime via `AppEnv` (no hard‑coded
`cryptad.ini`), adapting to system services or per‑user environments.

Use the repo’s Gradle defaults for daemon, parallelism, and JVM settings. Avoid `--no-daemon`,
`--parallel`, and ad-hoc CLI JVM tuning when running local builds.

### JLink Runtime Distribution

Build a minimal JRE image that embeds the Cryptad distribution using direct jlink/jdeps tasks (no external runtime plugin):

```bash
# 1) Build the wrapper-based dist the jlink step consumes
./gradlew assembleCryptadDist

# 2) Create the jlink image and zip/tar.gz archives
./gradlew distJlinkCryptad

# Result:
#  - build/cryptad-jlink-image/           (runnable image)
#  - build/distributions/cryptad-jlink-v<version>.zip
#  - build/distributions/cryptad-jlink-v<version>.tar.gz

# Launch using the embedded runtime (no system JRE required):
build/cryptad-jlink-image/bin/cryptad-launcher    # Windows: cryptad-launcher.bat
```

Notes
- The jlink image includes `bin/cryptad-launcher` which prefers the embedded `bin/java` and uses `lib/*` for classpath.
- We explicitly include key modules (e.g., `jdk.crypto.ec`, `jdk.httpserver`, `java.net.http`, `jdk.unsupported`, `java.desktop`) and call `jlink` directly.
- This does not alter the existing wrapper-based distribution; it is an additional, self-contained runtime option.
- `bin/cryptad-launcher` and `cryptad-launcher.bat` now auto-detect the embedded runtime: when run from the jlink image they prefer `image/bin/java`; outside the image they fall back to `$JAVA_HOME/bin/java` or `java` on `PATH`.

### Installers (jpackage)

Build a desktop app image and (on macOS/Linux) native installers with `jpackage`. The image embeds a minimal runtime and
bundles the portable distribution under `app/cryptad-dist/` so the GUI can invoke the wrapper reliably.

Commands

```bash
# Build includes the jpackage app image.
# On Linux and macOS, it also builds native installers when tooling is present
# (Linux: DEB/RPM via `dpkg-deb`/`rpmbuild`; macOS: DMG). On Windows, installers
# are not built by `build`.
./gradlew build

# App image only
./gradlew jpackageImageCryptad

# Native installer (macOS: .dmg; Linux: .deb or .rpm)
# - Auto-picks type on Linux (prefers rpm when available)
./gradlew jpackageInstallerCryptad

# Force a specific Linux package type
./gradlew jpackageInstallerRpm     # requires rpmbuild
./gradlew jpackageInstallerDeb     # requires dpkg-deb

# Or override the auto-detected Linux type
./gradlew -PlinuxInstaller=rpm jpackageInstallerCryptad
```

Outputs (macOS example)

- App image: `build/jpackage/Crypta.app`
- Installer: `build/jpackage/Crypta-<numeric>.dmg`

Details

- App metadata: Name `Crypta`, Vendor `crypta.network`, App ID `network.crypta.cryptad`.
- Main entry: `network.crypta.launcher.Launcher`.
- Icons: `src/jpackage/macos/cryptad.icns`, `src/jpackage/windows/cryptad.ico`, `src/jpackage/linux/cryptad.png`.
- Included docs: `LICENSE.txt`, `EULA.txt` (from `LICENSE`), `README.txt` (from `README.md`).
- App layout: the launcher config (`Crypta.cfg`) sets classpath to `app/cryptad-dist/lib/*.jar`; jars are not duplicated in `app/`.
- Versioning note: jpackage enforces numeric `--app-version` (e.g., `1`). Installer filenames follow jpackage defaults (e.g., `Crypta-<version>.<ext>`).
Note: Windows installers are not built; Windows builds produce only the app image.

Linux notes

- RPM builds require `rpmbuild` to be installed and on PATH.
- When both `dpkg-deb` and `rpmbuild` are installed, the default task prefers RPM. You can force DEB/RPM using the
  tasks above or `-PlinuxInstaller=<deb|rpm>`.
- The `build` task on Linux now depends on building all available Linux installers (DEB/RPM) and will skip any
  installer type whose tool is missing.

macOS notes

- The `build` task on macOS now also builds a `.dmg` via `jpackage`.
- Unsigned DMGs are fine for local testing; macOS may require right‑click → Open
  or removing quarantine to run the app the first time.

Linux behavior and service

- Install location: the app image installs under `/opt/cryptad/Crypta` and the launcher/scripts expect `/opt/cryptad`.
- Server vs. desktop detection:
  - Considered a “desktop” only when a display manager (`display-manager.service`) exists and is enabled or active.
  - As a fallback, presence of session files (`/usr/share/xsessions/*.desktop` or `/usr/share/wayland-sessions/*.desktop`) also counts as desktop.
  - This avoids mislabeling headless servers that happen to default to `graphical.target`.
- Install‑time actions:
  - Server (no desktop): install a systemd unit at `/etc/systemd/system/cryptad.service`, then `systemctl daemon-reload` and `enable` it. The service is NOT auto‑started; start it manually when ready.
  - Desktop: install a `.desktop` entry at `/usr/share/applications/crypta.desktop` and refresh caches when tools are present (`update-desktop-database`, `gtk-update-icon-cache`).
- Accounts and data:
  - Creates an explicit system group `cryptad`, then a system user `cryptad` with primary group `cryptad` (home `/var/lib/cryptad`, shell `nologin`).
  - Ensures `/var/lib/cryptad` exists and is owned by `cryptad:cryptad` (0750). Application state/log/cache directories defined in the systemd unit (e.g., `StateDirectory=cryptad`) are managed by systemd on first start.
- Removal and cleanup:
  - DEB `postrm`/RPM `%preun` disable and stop the unit only when it is enabled or active (race‑free check), remove the unit file, and run `daemon-reload`.
  - Desktop caches are refreshed; `.desktop` is removed when present. Scripts tolerate missing desktop tooling.
  - The `cryptad` user/group and data directory are preserved to avoid data loss. Remove them manually if desired.

Manual service control (Linux)

Service management (Linux):

```bash
sudo systemctl status cryptad
sudo systemctl start cryptad   # start explicitly after installation
sudo systemctl stop cryptad
sudo systemctl disable --now cryptad
```

Package removal behavior (Linux)

- DEB removal: disables/stops the service if enabled/active, removes `/etc/systemd/system/cryptad.service`, reloads systemd, and removes the desktop entry if present. The `cryptad` user/group and `/var/lib/cryptad` remain.
- RPM removal: `%preun` performs the same service cleanup; the user/group and data remain.

To remove the account and data explicitly (optional):

```bash
sudo systemctl disable --now cryptad || true
sudo rm -f /etc/systemd/system/cryptad.service && sudo systemctl daemon-reload
sudo rm -rf /var/lib/cryptad
sudo userdel cryptad 2>/dev/null || true
sudo groupdel cryptad 2>/dev/null || true
```

Troubleshooting (macOS)

- Unsigned app first‑run: right‑click → Open, or clear quarantine:

```bash
xattr -dr com.apple.quarantine "build/jpackage/Crypta.app"
```

- See launcher logs by running the Mach‑O launcher in Terminal:

```bash
build/jpackage/Crypta.app/Contents/MacOS/Crypta 2>&1 | tee build/crypta-run.log
```

- Run the embedded JRE directly to isolate classpath issues:

```bash
cd build/jpackage/Crypta.app/Contents
./runtime/bin/java -cp "app/cryptad-dist/lib/*" network.crypta.launcher.Launcher
```

## Launcher Details

### Windows shutdown behavior

- The Windows batch launcher (`bin/cryptad.bat`) passes a per‑user anchor location to the wrapper: `"wrapper.anchorfile=%LOCALAPPDATA%\Cryptad.anchor"`.
- The Swing launcher requests a graceful stop by deleting that file; the Java Service Wrapper notices and shuts down the JVM cleanly (running shutdown hooks, flushing logs, etc.).
- If the process tree is still alive after ~25 seconds, the launcher escalates to `taskkill` (first without `/F`, then with `/F`).
- Advanced: To change the anchor path, customize the batch file, or pass a different property on the command line; a value in `wrapper.conf` is overridden by the batch property.

### Launcher script resolution

- Env override: set `CRYPTAD_PATH` to an absolute path or a path relative to your current working directory to force a specific wrapper script, e.g. `export CRYPTAD_PATH=bin/cryptad`.
- Default resolution order (first match wins):
  - From the running `cryptad.jar` directory: `<jarDir>/cryptad`.
  - From the assembled distribution layout: `<jarDir>/../bin/cryptad`.
  - Fallbacks from `user.dir`: `./bin/cryptad`, then `./cryptad`.

## Development Guidelines

- Primary language: Java
- Code style:
  - Java: https://google.github.io/styleguide/javaguide.html
- Tests: JUnit; target 80%+ coverage
- Documentation: Add or update Javadoc when editing Java files

## Dependencies

- Runtime: Java 25+
- Tooling: Gradle Wrapper (provided in this repo)
- External libraries are managed via Gradle.
- Dependency verification is enabled. When adding or updating libraries:
  - Declare versions in `gradle/libs.versions.toml` and add usages in `build.gradle.kts`.
  - Update verification metadata so `gradle/verification-metadata.xml` and keyrings reflect the new
    artifacts; use the commands in “Spotless + Dependency Verification” below.

Root build also includes:
- `:foundation-support`: extracted stable support/api/io/compress/math/transport subset plus
  `network.crypta.support.http`, `network.crypta.io.AddressIdentifier`,
  `network.crypta.io.WritableToDataOutputStream`, `network.crypta.node.FSParseException`,
  `network.crypta.node.FastRunnable`, `network.crypta.node.PrioRunnable`,
  `network.crypta.node.SemiOrderedShutdownHook`, `network.crypta.support.IllegalValueException`,
  and `network.crypta.support.JVMVersion`, including the generic `HTTPRequest` /
  `HTTPUploadedFile` / `MultiValueTable` / `SizeUtil` surface, generic helpers such as
  `URIPreEncoder`, `IOUtils`, `LegacyFileSupport`, and `HTMLDecoder`, and the cycle-safe
  file-backed support I/O slice.
- `:foundation-store-contracts`: neutral store contracts plus the store-maintenance alert seam
  shared by store code and root runtime/UI adapters.
- `:foundation-crypto-keys`: extracted `network.crypta.crypt`, `network.crypta.keys`, and the
  adjacent `BucketTools` / `NoFreeBucket` / `PrependLengthOutputStream` helpers.
- `:foundation-store`: extracted reusable `network.crypta.store` implementations, caching, and
  salted-hash storage code.
- `:interop-wire`: extracted wire/message/schema/address/version/probe nucleus plus
  `network.crypta.support.Serializer`.
- `:foundation-config`: extracted config/l10n code, main l10n resources, and shared sizing helpers
  such as `DatastoreSizingSupport`. Its public APIs re-export `:foundation-support` and
  `:foundation-fs` where required.
- `:launcher-desktop`: Swing launcher code and desktop/theme detection dependencies.
- `:thirdparty-onion`: Onion FEC and related vendored sources/resources.
- `:thirdparty-legacy`: Bitpedia, SevenZip, and Spaceroots vendored code.
- `:kernel-content`: compile-neutral phase-1 content leaf spanning selected
  `network.crypta.client`, `network.crypta.client.events`, `network.crypta.client.filter`,
  `network.crypta.client.async.alerts`, `network.crypta.client.async.persistence`, the
  `network.crypta.client.events` contract/helper subset (`ClientEventListener`,
  `ClientEventProducer`, `SimpleEventProducer`, `EventLogger`, `EventDumper`,
  `SplitfileProgressEvent`, `SplitfileCompatibilityModeEvent`, `SplitfileCompatibilityMode`), the
  leaf-safe `network.crypta.client.async` utility/value subset, the leaf-safe client
  failure/filter exception subset, selected filter policy/helper types such as
  `HTMLFilterPolicy`, concrete media/CSS/HTML parser and filter helpers,
  `network.crypta.support.MediaType`, `InsertUriChecks`, and the small manifest/model helper
  subset under `network.crypta.support.*`.
- `:kernel-transport`: compile-neutral phase-1 transport leaf spanning selected
  `network.crypta.io`, `network.crypta.io.comm`, and `network.crypta.io.xfer` helpers such as
  allowlist parsing, listener abstraction, `SSLNetworkInterface`, statistics collection,
  throttling, and partially received block assembly.
- `:kernel-routing`: compile-neutral phase-1 routing/helper leaf spanning selected
  `network.crypta.node` value, exception, callback, and request-item helper types such as
  `BaseRequestThrottle`, `LowLevelGetException`, `LowLevelPutException`, `RequestClient`,
  `PeerStatusCounts`, `RequestPriorityClasses`, and `SendableRequestItem*`.
- `:runtime-spi`: JDK-only runtime ports plus immutable config, alert, and runtime
  snapshot/value types and shared path constants such as `ConnectivityPagePaths` and
  `UpdaterPaths`.
- `:platform-api`: transport-neutral Platform API v1 built on top of `:runtime-spi` and
  `:platform-apphost`, currently mounted under `/api/v1/` through the legacy HTTP admin adapter.
  Its current family-level surface covers node, connectivity, queue, peers, config, security
  levels, updates, wizard/welcome, alerts, diagnostics, apps, app catalogs, app vault routes, app
  data backup/restore, app-service dependencies/grant bundles, local Trust Graph Local RC routes,
  and the platform compatibility contract.
- `:platform-apphost`: transport-neutral out-of-process AppHost v1 core for installed local apps.
  Local staged and verified catalog app updates now flow through this core. It also reports sandbox
  provider status, selects the Linux bubblewrap provider for enforced restricted-process launches
  when available, enforces positive AppHost-managed data/cache quotas at launch and restart
  boundaries, and bounds managed process logs.
- `:platform-app-ui`: app-owned static UI route and asset-resolution helpers used by the legacy
  HTTP admin adapter to serve isolated per-app loopback origins and the `/apps/{appId}/`
  compatibility path without exposing data/cache/run directories or traversal paths. It also owns
  origin-bound browser session issuance and verification for static app API calls.
- `:platform-appvault`: local app secret and identity vault records, grant metadata, wrapping-key
  provider, and audit/redaction values used by app/vault Platform API workflows.
- `:platform-design-system`: canonical CSS token, base class, and optional JavaScript resources
  for local app-owned static UI, plus safe helper APIs for copying and hashing those assets.
- `:platform-sdk-js`: browser-native SDK resource for app-owned static UI bootstrap, Platform API
  form/JSON helpers, error handling, and conservative legacy-fragment sanitization.
- `:platform-appdist`: local app distribution tooling for deterministic bundle digests, Ed25519
  signatures, trusted-key verification, bundle packaging, and the signing/verification helpers used
  by first-party app Gradle tasks.
- `:platform-appcatalog`: signed catalog source parsing, catalog writing, signature verification,
  app-store metadata parsing, Crypta catalog source fetching, artifact digest checks, safe ZIP
  extraction, and verified staging for AppHost install/update flows.
- `:platform-trustgraph`: local Trust Graph Local RC statement parsing, canonicalization,
  verification, process-local store/anchor behavior, lifecycle/status records, and deterministic
  direct-anchor scoring.
- `:platform-devtools`: standalone `crypta-app` developer CLI for scaffolding, validating,
  UI linting, signing, packaging, verifying, catalog-authoring, API contract snapshotting, and
  compatibility verification for standalone staged bundles.
- `:platform-web-shell`: browser-facing Web Shell v1 leaf owning the node-management shell route
  descriptors, bootstrap payload, and static browser assets that the legacy HTTP adapter mounts at
  `/app/node/`, including app-service dependency/grant-bundle review, app-data backup/restore, and
  explicit legacy security/diagnostic fallback actions.
- `:runtime-node`: extracted daemon runtime body across the remaining cyclic/high-level
  `network.crypta.client` body, the remaining peer/request/routing-engine and transport-heavy
  `network.crypta.node` / `network.crypta.runtime.*` slices, the retained node-coupled
  transport/message execution code in `network.crypta.io*`, and the remaining daemon-coupled
  support helpers after the generic HTTP, multimap, size-formatting, and file-backed bucket slice
  moved into `:foundation-support` and the manifest/model helper subset moved into
  `:kernel-content`.
- `:adapter-fcp`: detached `network.crypta.clients.fcp` protocol leaf. See
  [docs/fcp-boundary.md](docs/fcp-boundary.md) for the explicit maintenance boundary.
- `:bridge-fcp-runtime`: extracted concrete `network.crypta.clients.fcp.bridge` runtime-binding
  leaf and the only FCP leaf that depends directly on `:runtime-node`.
- `:adapter-http-legacy-admin`: extracted shared legacy `network.crypta.clients.http` shell plus
  `network/crypta/clients/http/**` main resources. The root project no longer owns that main
  HTTP source/resource tree, and the browse/FProxy implementation now lives in
  `:adapter-http-legacy-browse`. The shared shell uses browse-neutral bookmark, push, client-side
  localization, and route-registration seams instead of importing or instantiating the concrete
  browse-owned collaborators directly. It still hosts the current `/api/v1/` bridge for
  `:platform-api` and the `/app/node/` bridge for `:platform-web-shell`. See
  [docs/legacy-http-boundary.md](docs/legacy-http-boundary.md) for the explicit maintenance
  boundary.
- `:adapter-http-legacy-browse`: extracted concrete legacy browse/FProxy leaf owning the browse
  routes, toadlets, helper models, and browse-only packages under `network.crypta.clients.http`.
- `:bridge-http-runtime`: extracted concrete `network.crypta.clients.http.bridge`
  runtime-binding leaf plus the legacy HTTP `network.crypta.clients.http.geoip` helper package
  used by that bridge. Root bootstrap still selects the default production bridge set in
  `DefaultNodeRuntimeBridgeFactories`, and the bridge depends on the browse leaf for concrete
  browse construction while `network.crypta.clients.http.updater` remains in
  `:adapter-http-legacy-admin`.
- `:foundation-fs` and `:foundation-compat`: extracted filesystem/environment and compatibility
  leaf modules used by the root daemon. `:foundation-compat` also carries the wizard-neutral
  bandwidth-detection helpers now used by first-time setup flows, plus the shared
  `network.crypta.runtime.core.SSL` helper.
- `:runtime-alerts`: extracted leaf-safe alert/feed module owning the full
  `network.crypta.runtime.alerts.feed` package plus reusable alert model/base classes that stay
  free of direct `Node`/`NodeClientCore` coupling, including the detached `UserAlertSurface`
  contract for HTTP/admin consumers.

### Spotless + Dependency Verification

When Gradle dependency verification is strict, Spotless may fail to resolve formatter artifacts (e.g., `google-java-format`). If that happens:

1. Temporarily set verification to lenient in `gradle.properties`:
   - `org.gradle.dependency.verification=lenient`
2. Write verification metadata (SHA256 + PGP):
   - `./gradlew --write-verification-metadata sha256,pgp spotlessApply`
   - Optional exact version refresh:
     - `./gradlew --refresh-dependencies --write-verification-metadata sha256,pgp spotlessApply`
   - Faster alternative (no formatting run):
     - `./gradlew --write-verification-metadata sha256,pgp spotlessInternalRegisterDependencies`
3. Confirm entries in `gradle/verification-metadata.xml` for `com.google.googlejavaformat` and trusted keys.
4. Restore strict mode:
   - `org.gradle.dependency.verification=strict`
5. Validate:
   - `./gradlew spotlessApply`

Tip: Keep the Spotless formatter at the intended version (declared by `googleJavaFormat` in `gradle/libs.versions.toml`). If verification still blocks, re‑write metadata including `pgp` and ensure a group‑level trusted key entry. Commit updated verification keyring files as appropriate.

## Versioning

- The build number is a single integer in `build.gradle.kts` (e.g., `version = "<int>"`).
- During build, tokens are replaced into the generated version source file (e.g., `@build_number@`, `@git_rev@`).
- Version strings support both Cryptad and Fred formats for wire compatibility; protocol compatibility enforces minimum builds.

## Branching & Releases

- Standard branching and release workflow: see `docs/standard-git-branching-and-release-workflow.md` (validated copy). The original wiki page is also available: https://github.com/crypta-network/cryptad/wiki/Standard-Git-Branching-and-Release-Workflow-for-Cryptad
- [Release workflow and operations runbook](docs/cryptad-release-workflow-and-runbook.md)

## Update System

- Core updates use a package‑based updater (“CoreUpdater”). It subscribes to an `info/<N>` JSON descriptor via the existing update USK, selects an OS/arch‑specific installer (deb/rpm/dmg/exe/flatpak/snap), and downloads to `nodeDir/updates/core/<version>/`.
- Stable 1.0 support status is delivered separately through the trusted
  `support-lifecycle/<N>` document. The read-only subscriber remains active when package updates
  are disabled, persists only authenticated public-safe last-known-good bytes, and exposes unknown
  or stale state explicitly. The operator-only Platform API route and Web Shell show this local
  projection; the app-readable core-update response does not embed lifecycle data.
- Lifecycle editions are digest-linked and consumed in order. A node retains at most one
  future-effective descriptor and defers its exact successor until the intermediate policy
  activates, so support or recovery guidance cannot skip an authenticated interval. Effective
  build revocation is checked against the package fetch's complete originating selection at
  download, installer-launch, and store-handoff boundaries; it remains separate from update-key
  compromise.
- Installing the OS package is a user/OS action. On Linux, the UI may hand off to the system’s software center or PackageKit. On macOS/Windows, follow the platform guidance shown in the UI.
- JAR Update‑over‑Mandatory (UOM) for the core is disabled in favor of the package flow.
- For developer testing, replacing `build/libs/cryptad.jar` manually (as noted above) is fine; for production use CoreUpdater and platform packages.
- Local app lifecycle work is separate from CoreUpdater. The current platform can install, start,
  stop, uninstall, and replace an installed app bundle from a caller-supplied local staged
  directory through `:platform-apphost` and the Platform API v1. Signed local staged bundles are
  supported. Signed local and HTTPS catalog sources can now install or update apps through the
  same AppHost staged-directory semantics. Static app UIs are served from the installed bundle on
  isolated per-app loopback origins when available, with `/apps/{appId}/` retained as a
  compatibility fallback. Catalog-backed candidate detection and explicit apply-when-stopped
  updates are implemented. The background scheduler refreshes configured signed catalogs and checks
  installed apps, but silent automatic update is not the default. Bundle rollback restores only the
  immutable installed bundle and does not roll back app data or cache.

## Architecture Overview

- Build/module layout:
  - Root project `:cryptad` remains the daemon/application build and still owns the strongly
    coupled composition layer, most broad functional/unit/integration tests, packaging/runtime
    tasks, root-local bridge selection, and `network.crypta.tools`. Focused extracted-leaf
    boundary suites now live in the owning leaf modules.
  - Leaf subprojects are `:foundation-support`, `:foundation-store`,
    `:foundation-store-contracts`, `:foundation-crypto-keys`, `:interop-wire`,
    `:foundation-config`, `:foundation-fs`, `:foundation-compat`, `:kernel-content`,
    `:kernel-transport`, `:kernel-routing`, `:runtime-spi`, `:runtime-alerts`,
    `:platform-api`, `:platform-apphost`, `:platform-app-ui`, `:platform-appvault`,
    `:platform-design-system`, `:platform-appdist`, `:platform-appcatalog`,
    `:platform-trustgraph`, `:platform-devtools`, `:platform-sdk-js`,
    `:platform-web-shell`,
    `:runtime-node`,
    `:adapter-fcp`, `:bridge-fcp-runtime`, `:bridge-http-runtime`,
    `:adapter-http-legacy-admin`, `:adapter-http-legacy-browse`, `:thirdparty-onion`,
    `:thirdparty-legacy`, and `:launcher-desktop`.
- Core network (`network.crypta.node`): `Node`, `PeerNode`, `PeerManager`, `PacketSender`, `RequestStarter`, `RequestScheduler`, `NodeUpdateManager`.
- Storage (`network.crypta.store`): `FreenetStore`, `CHKStore`, `SSKStore`, `SlashdotStore`.
  `:foundation-store` now owns the reusable store implementations, cache layer, and salted-hash
  storage code. `:foundation-store-contracts` owns the neutral contracts plus the
  `network.crypta.store.alerts` seam used by root runtime/UI adapters such as
  `UserAlertManagerStoreAlertSink`.
- Crypto (`network.crypta.crypt`): AES, DSA/ECDSA, SHA‑256, `RandomSource`/Yarrow. This package
  now lives in `:foundation-crypto-keys`.
- Keys (`network.crypta.keys`): `ClientCHK`, `ClientSSK`, `FreenetURI`, USK. This package now
  lives in `:foundation-crypto-keys`.
- Wire/message nucleus (`network.crypta.io.comm`, `network.crypta.node.Version`,
  `network.crypta.node.probe`, `network.crypta.support.Serializer`): `:interop-wire` owns the
  leaf-safe message/schema/address/version/probe subset, including `Message`, `MessageType`,
  `Peer`, `FreenetInetAddress`, `Version`, and the probe enums. `:kernel-transport` now owns the
  compile-neutral transport helper slice across selected `network.crypta.io`,
  `network.crypta.io.comm`, and `network.crypta.io.xfer` classes such as `AllowedHosts`,
  `NetworkInterface`, `IOStatisticCollector`, `SocketHandler`, `PacketThrottle`, and
  `PartiallyReceivedBlock`. `:kernel-routing` now owns the compile-neutral phase-1
  `network.crypta.node` helper/value slice, including `BaseRequestThrottle`,
  `LowLevelGetException`, `LowLevelPutException`, `RequestClient`, `PeerStatusCounts`,
  `RecentlyFailedReturn`, and `SendableRequestItem*`. `:runtime-node` keeps the node-coupled
  transport/socket/filter side of `network.crypta.io*` plus the remaining peer, scheduler,
  request-sender, and routing-engine side of `network.crypta.node`, and `Message` now depends on
  the minimal `MessageSource` seam rather than directly on `PeerContext`.
- Clients: `network.crypta.client`, FCP (`network.crypta.clients.fcp`), HTTP
  (`network.crypta.clients.http`). `:kernel-content` now owns the compile-neutral phase-1 content
  slice: selected client value/archive/helper classes, immutable client event values, a
  conservative subset of filter helper/parser types, the client-facing
  fetch/insert/content-safety failure subset, the full
  `network.crypta.client.async.alerts` seam, the client-local persistence seams under
  `network.crypta.client.async.persistence`, the leaf-safe
  `network.crypta.client.async` utility/value subset, and the MIME helper
  `network.crypta.support.MediaType`, plus the small manifest/model helper subset under
  `network.crypta.support.*` (`ManifestElement` and `ContainerSizeEstimator`). `:runtime-node`
  still owns the cyclic async
  scheduler/request engine, high-level client APIs, and the remaining filter/archive surfaces that
  still depend on runtime-owned request and node types.
  `network.crypta.clients.fcp` now lives in `:adapter-fcp`. It consumes execution, randomness,
  transfer policy, lifecycle, config access, and detached peer mutations through `RuntimePorts`
  and FCP-local adapters instead of reaching directly into daemon internals for those concerns.
  FCP bootstrap now flows through `FcpServerDependencies` and
  `CoreFcpServerDependenciesFactory`, with package-local seams such as
  `FcpServerRuntimeSupport`, `FcpMessageRuntimeSupport`, `FcpFetchRuntimeSupport`, and
  `FcpInsertRuntimeSupport` splitting server-owned, message-owned, GET/fetch, and insert/USK
  concerns. FCP insert request options and mutable insert-context handles stay adapter-owned
  through `FcpInsertOptions`, `FcpInsertBehaviorOptions`, and `FcpInsertContextHandle`. The
  protocol leaf also keeps the persistent-bucket and filter seams detached from the
  concrete runtime, while runtime-owned FCP seam types now live under `network.crypta.runtime.fcp`
  and `network.crypta.runtime.endpoints.fcp`. Concrete persistent-request services, queue
  adapters, alert-feed adapters, persistent-bucket bindings, filter bindings, and endpoint-handle
  wrappers now live under `network.crypta.clients.fcp.bridge` in `:bridge-fcp-runtime`. See
  [docs/fcp-boundary.md](docs/fcp-boundary.md) for the maintained protocol/bridge split.
  `network.crypta.clients.http` now lives in `:adapter-http-legacy-admin` together with its
  `staticfiles/**` and `templates/**` resources, excluding `network.crypta.clients.http.bridge`
  and `network.crypta.clients.http.geoip`. The legacy HTTP surface now has a physical browse leaf:
  `:adapter-http-legacy-admin` keeps the shared shell, admin routes, and seam types;
  `:adapter-http-legacy-browse` owns the concrete browse/FProxy routes, toadlets, and helper
  models; and `:bridge-http-runtime` owns the concrete runtime-binding bridge code. The shared
  shell crosses neutral bookmark, push, client-side script, and route-registration seams instead
  of importing concrete browse-owned collaborators directly. Root-local bridge selection stays in
  `DefaultNodeRuntimeBridgeFactories`, which installs the admin-owned shell wiring and lets the
  bridge leaf depend on the browse leaf for concrete browse construction. The updater-action
  adapters remain under `network.crypta.clients.http.updater` in
  `:adapter-http-legacy-admin`. See [docs/legacy-http-boundary.md](docs/legacy-http-boundary.md)
  for the explicit maintenance boundary.
- Runtime SPI (`network.crypta.runtime.spi`): JDK-only ports and detached DTOs such as
  `RuntimePorts`, `ConfigPort`, `NodeInfoPort`, `PeerPort`, `ConnectionsPagePort`,
  `ConnectionsSupportPort`, `DarknetConnectionsPort`, `DarknetMessagingPort`, `QueuePagePort`,
  `QueueDownloadPort`, `QueueInsertPort`, `QueueMutationPort`, `QueueSupportPort`,
  `QueueCompletionPort`, `SecurityLevelsPort`, `PageChromePort`, `CoreUpdateActionPort`,
  `FirstTimeWizardPort`, `ToadletSymlinkPort`, `WelcomePagePort`, `WelcomeActionPort`,
  `ConfigSnapshot`, `ConfigFieldSet`, `QueuePageSnapshot`, `QueueInsertOutcome`,
  `SecurityLevelsSnapshot`, `PageChromeSnapshot`, `FirstTimeWizardSnapshot`,
  `FirstTimeWizardCurrentBandwidthLimits`, `ToadletSymlinkEntry`, and `WelcomePageSnapshot`.
- Runtime package families (`network.crypta.runtime.*`): most behaviorful runtime code now lives
  in `:runtime-node`, including startup/CLI wiring such as `NodeStarter`, `NodeBootstrap`,
  `NodeCli`, and `NodeConfigManager`; core SPI adapters such as `LegacyRuntimePorts`,
  `LegacyConfigPort`, `LegacyConnectivityPort`, `LegacyNodeInfoPort`, `LegacyPeerPort`,
  `LegacyRequestQueuePort`, `LegacySecurityLevelsPort`, and `LegacyCoreUpdateActionPort`;
  page-oriented admin adapters such as `LegacyConnectionsPagePort`, `LegacyQueuePagePort`,
  `LegacyPageChromePort`, `LegacyFirstTimeWizardPort`, and `LegacyWelcomePagePort`; endpoint glue
  such as `ClientEndpoints`, `NodeClientCoreInit`, and `NodeClientPersistence`; shell/password
  seams under `runtime.http`; and updater classes such as `NodeUpdateManager` and `CoreUpdater`.
  The extracted `:runtime-alerts` leaf now owns the reusable alert/feed model subset under
  `network.crypta.runtime.alerts`, plus the detached `UserAlertSurface` consumed by legacy HTTP,
  while `:runtime-node` keeps `UserAlertManager` and the daemon-coupled alert producers. The root
  project keeps the composition class
  `DefaultNodeRuntimeBridgeFactories`, which selects the concrete FCP and HTTP bridge
  implementations from the extracted adapter leaves.
- Config + localization leaf (`:foundation-config`): `network.crypta.config`,
  `network.crypta.l10n`, and the main l10n properties. Its public APIs re-export
  `:foundation-support` and `:foundation-fs` where config surfaces expose `SimpleFieldSet` or
  filesystem-facing types. Shared setup helpers such as `DatastoreSizingSupport` now also live in
  this leaf. It also owns narrow callback-level UI markers such as
  `DirectorySelectionCallback`, which lets legacy HTTP config code classify directory-selection
  fields without importing concrete runtime-owned callbacks such as `ProgramDirectory`.
  Higher layers should still prefer `RuntimePorts#config()` and the root
  `network.crypta.runtime.core.LegacyConfigPort` bridge instead of reaching through daemon
  internals.
- Support foundation leaf (`:foundation-support`): stable generic support, support-api,
  support-io, support-compress, support-math, transport-IP, and support-http classes plus
  `network.crypta.io.AddressIdentifier`, `network.crypta.io.WritableToDataOutputStream`,
  `network.crypta.node.FSParseException`, `network.crypta.node.FastRunnable`,
  `network.crypta.node.PrioRunnable`, `network.crypta.node.SemiOrderedShutdownHook`, and
  `network.crypta.support.IllegalValueException`, plus `network.crypta.support.JVMVersion`, the
  generic `HTTPRequest` / `HTTPUploadedFile` / `MultiValueTable` / `SizeUtil` surface, generic
  helpers such as `URIPreEncoder`, `IOUtils`, `LegacyFileSupport`, and `HTMLDecoder`, and the
  cycle-safe file-backed support I/O slice.
- Support (`network.crypta.support`): logging, data structures, threading, and helpers are now
  split between `:foundation-support` and the root project. Keep generic reusable utilities in the
  foundation leaf; daemon-coupled support code still remains in the root.
- Launcher/Desktop: `:launcher-desktop` provides `network.crypta.launcher`,
  `com.jthemedetecor`, launcher resources, and desktop-theme integration.
- Extracted foundations: `:foundation-support` provides the stable generic support subset,
  `:foundation-store-contracts` provides neutral store contracts and alert seams,
  `:foundation-crypto-keys` provides `network.crypta.crypt`, `network.crypta.keys`, and adjacent
  support-IO helpers such as `BucketTools`, `NoFreeBucket`, and
  `PrependLengthOutputStream`,
  `:foundation-store` provides reusable store implementations, `:interop-wire` provides the
  wire/version/probe nucleus, `:foundation-config` provides config/l10n plus datastore-sizing
  helpers,
  `:foundation-fs` provides `network.crypta.fs`, and `:foundation-compat` provides
  `network.crypta.compat` plus compatibility helpers such as the extracted bandwidth-detection
  support and the shared `network.crypta.runtime.core.SSL` helper.
- Runtime boundary leaves: `:kernel-content` provides the compile-neutral phase-1 content slice
  across selected `network.crypta.client*` classes, the leaf-safe client failure/filter
  exception subset, the `network.crypta.client.async.persistence` seam, the leaf-safe
  `network.crypta.client.async` utility/value subset, event/helper types such as
  `SplitfileCompatibilityMode*`, selected filter policy/helper types such as `HTMLFilterPolicy`,
  concrete media/CSS/HTML parser and filter helpers, plus `network.crypta.support.MediaType`,
  `InsertUriChecks`, and the small manifest/model helper subset under
  `network.crypta.support.*`;
  `:kernel-transport` provides the compile-neutral phase-1 transport slice across selected
  `network.crypta.io*` helpers including `SSLNetworkInterface`; `:kernel-routing` provides the
  compile-neutral phase-1 `network.crypta.node` helper slice across selected request/routing
  value, exception, callback, priority, and request-item types; `:runtime-spi` provides
  `network.crypta.runtime.spi`;
  `:runtime-alerts` provides the extracted leaf-safe `network.crypta.runtime.alerts`
  feed/model subset plus the detached `UserAlertSurface`;
  `:platform-api` provides the transport-neutral Platform API v1, the deterministic platform
  compatibility contract, app vault routes, and the AppHost control-plane routes;
  `:platform-apphost` provides the transport-neutral out-of-process AppHost
  v1 core for installed local apps; `:platform-app-ui` provides app-owned static UI route,
  asset-resolution, and browser-session helpers; `:platform-appvault` provides local app secret
  and identity vault records, grants, and redaction value types; `:platform-design-system`
  provides canonical app UI assets for local static bundles; `:platform-sdk-js` provides the
  browser SDK resource for app-owned static UI; `:platform-appdist` provides the local app bundle
  digest, signing, packaging, and verification tooling; `:platform-appcatalog` provides signed
  catalog source, app-store metadata, Crypta catalog fetching, artifact verification, and safe ZIP
  staging support; `:platform-trustgraph` provides local trust statement parsing and deterministic
  preview scoring; `:platform-devtools` provides the standalone `crypta-app` developer CLI,
  including offline UI linting, API contract, and compatibility checks;
  `:platform-web-shell` provides the browser-facing Web Shell v1 node-management assets and
  bootstrap contract; `:runtime-node`
  provides the extracted daemon runtime body across the remaining cyclic/high-level
  `network.crypta.client` body, the remaining peer/request/routing-engine
  `network.crypta.node` / `network.crypta.runtime.*` slices, the retained node-coupled
  transport/message execution code, and the remaining daemon-coupled support helpers outside the
  small `:kernel-content` manifest/model helper subset;
  `:adapter-fcp` provides `network.crypta.clients.fcp` plus the protocol-side persistent-bucket
  and filter seams;
  `:bridge-fcp-runtime` provides `network.crypta.clients.fcp.bridge` plus the concrete
  persistent-bucket and filter bindings;
  `:bridge-http-runtime` provides `network.crypta.clients.http.bridge` and
  `network.crypta.clients.http.geoip`;
  `:adapter-http-legacy-browse` provides the concrete legacy browse/FProxy classes and browse-only
  packages; and
  `:adapter-http-legacy-admin` provides the shared legacy `network.crypta.clients.http` shell,
  resources, seam types, and updater surface outside those browse- and bridge-owned packages.
- Vendored libraries: `:thirdparty-onion` provides `com.onionnetworks`,
  `:thirdparty-legacy` provides `org.bitpedia`, `org.sevenzip`, and `org.spaceroots`.

You generally do not need to install libraries manually; Gradle resolves them.

## License

**Crypta** is free software licensed under the GNU General Public License, version 3 only. See `LICENSE` for the full text.

Some bundled components may be under permissive licenses (e.g., Apache‑2.0, BSD‑3‑Clause). These are compatible with
GPLv3 and included under their respective terms.
