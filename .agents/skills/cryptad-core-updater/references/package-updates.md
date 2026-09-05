# CoreUpdater migration (conceptual overview) reference

Read for CoreUpdater migration (conceptual overview), System wiring changes, Versioning and discovery details, Endpoint and UI, Runtime-boundary classes to inspect. Commands and unlinked source paths are relative to the repository root.

## CoreUpdater migration (conceptual overview)
- Core package-based updates replace self-updating of `cryptad.jar`.
- The legacy plugin runtime has been removed. This skill only covers core package update flows.
- The updater:
  - Fetches `info/<N>` JSON from the existing update USK.
  - Treats `CoreInfo.version` as the release gate: it must be a base-10 integer string and be
    greater than `Version.currentBuildNumber()` for update availability.
  - Selects an OS/arch-specific installer (deb/rpm/dmg/exe/flatpak/snap).
  - Downloads to `nodeDir/updates/core/<version>/`.

## System wiring changes
- Legacy core jar updater was removed.
- `NodeUpdateManager` now coordinates core-package discovery, download, and install signaling.
- The legacy HTTP updater UI now crosses the runtime boundary through
  `RuntimePorts#coreUpdateAction()` and `network.crypta.runtime.spi.CoreUpdateActionPort`,
  implemented by the daemon-backed runtime adapter
  `network.crypta.runtime.core.LegacyCoreUpdateActionPort` in `:runtime-node`.
- Core updater state surfaces through CorePackage-named APIs:
  - `hasNewCorePackage()`, `newCorePackageVersion()`, `newCorePackageVersionLabel()`
  - `fetchingNewCorePackage()`, `fetchingNewCorePackageVersion()`
- Stable 1.0 support state crosses the runtime boundary as the immutable
  `CoreSupportLifecycleSnapshot` returned by `CoreUpdateActionPort#supportLifecycleSnapshot()`.
  Platform API and Web Shell must not reach updater internals directly.
- JAR Update-over-Mandatory for core payload transfer is disabled; legacy jar UOM paths remain
  gated/no-ops while revocation/dependency signaling is still active.

## Versioning and discovery details
- Discovery still follows USK editions (`info/<N>`) and keeps startup subscribe seeding logic from
  persisted fetched editions.
- Release gating and user-facing version labels come from descriptor `version`:
  - strict integer parse only
  - missing/non-integer/overflow => do not advertise update available
- Changelog link resolution still uses edition/build-based URIs when CHK links are absent.

## Endpoint and UI
- HTTP endpoint: `/core-update/`
- Actions: `download`, `install`, `openStore`
- Platform API separates app-readable update readiness from operator support state:
  - `GET /api/v1/updates/core` reports only updater availability and download readiness.
  - `GET /api/v1/updates/support-lifecycle` is host/operator-only and returns the redacted
    last-known-good lifecycle projection.
  - Web Shell fetches those routes independently; never add lifecycle state back to the
    app-readable core response.
- UI: alerts panel shows progress percent when available.
  - Failures surface clear retry guidance (non-fatal errors relabel to “Retry”).
- `NodeUpdater` intentionally delays retries for `FetchExceptionMode.RECENTLY_FAILED` instead of
  rescheduling immediately while the key is still in the recently-failed table. Preserve that
  throttle unless replacing it with an explicit, tested retry policy.
- Request parsing, redirects, `AppEnv` checks, and OS-specific installer or store-launching now
  live in the HTTP adapter layer at `network.crypta.clients.http.updater.CoreActionToadlet`,
  currently packaged in `:adapter-http-legacy-admin`.
- Daemon-backed availability checks, UI-triggered download start, downloaded-installer containment
  validation, and exact current store-target validation now live behind `CoreUpdateActionPort`.

## Runtime-boundary classes to inspect
- HTTP/action layer (`:adapter-http-legacy-admin`): `network.crypta.clients.http.updater.CoreActionToadlet`
- Updater coordinator/state (`:runtime-node`): `network.crypta.runtime.updater.NodeUpdateManager`
- Core package downloader (`:runtime-node`): `network.crypta.runtime.updater.CoreUpdater`
- Lifecycle subscriber/model/parser/store (`:runtime-node`):
  `CoreSupportLifecycleUpdater`, `CoreSupportLifecycleState`, `CoreSupportLifecycleParser`,
  `CoreSupportLifecycleStore`, `CoreSupportLifecycleDescriptor`, and
  `CoreSupportLifecycleEntry`
- SPI contract: `network.crypta.runtime.spi.CoreUpdateActionPort`
- SPI lifecycle values: `network.crypta.runtime.spi.CoreSupportLifecycleSnapshot` and
  `CoreSupportLifecycleStatus`
- Daemon-backed adapter (`:runtime-node`): `network.crypta.runtime.core.LegacyCoreUpdateActionPort`
- Aggregate runtime entry point: `network.crypta.runtime.spi.RuntimePorts`
