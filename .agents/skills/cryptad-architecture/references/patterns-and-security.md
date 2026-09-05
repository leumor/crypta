# Key design patterns reference

Read for Key design patterns, Security model (high level), Versioning system. Commands and unlinked source paths are relative to the repository root.

## Key design patterns
### Request routing (high level)
1. `RequestStarter` initiates requests
2. `RequestScheduler` manages queues and priorities
3. `SendableRequest` implementations perform request types
4. Routing uses location-based algorithms for discovery
- `ClientRequestSelector` returns the earliest useful cooldown wakeup, and
  `ClientRequestScheduler#scheduleWakeStarterAt` coalesces starter wakeup jobs. Selector code
  should not queue duplicate ticker wakeups directly.

### Update system (high level)
- `NodeUpdateManager` coordinates updates.
- Core updates use the package-based `CoreUpdater` (see the CoreUpdater skill for details).
- Stable 1.0 support state uses the separate `CoreSupportLifecycleUpdater` under the trusted
  `support-lifecycle` docname. It validates sequential descriptor editions and persists exact
  last-known-good bytes without changing historical `core-info.json`.
- Lifecycle state retains at most one future-effective descriptor. A validated next edition is
  deferred until that predecessor activates locally, so an intermediate status or recovery path
  cannot be skipped when the node clock trails the publisher.
- `CoreUpdateActionPort` exposes the redacted lifecycle snapshot to the host/operator-only
  `/api/v1/updates/support-lifecycle` route. The app-readable `/api/v1/updates/core` route contains
  only updater availability and download readiness. Web Shell treats the lifecycle read as
  best-effort so a transient diagnostic failure does not disable valid core-updater controls.
- Disabling package updates leaves lifecycle polling active. Authenticated update-key compromise
  durably invalidates both cached lifecycle authority and package-update authority across restart;
  build lifecycle `revoked` does not trigger that key-compromise path.
- Core package selection is an immutable descriptor/build/environment/package snapshot. Package
  fetch, installer launch, and store handoff retain that exact identity and run beneath ordered
  manager, selection, and lifecycle authorization. An update-URI change fences both subscribers and
  package actions until the new trust scope is active.
- The legacy plugin runtime has been removed; there is no separate plugin updater path in the
  current node.
- Core updater state is exposed through CorePackage APIs in `NodeUpdateManager`:
  - `hasNewCorePackage()`, `newCorePackageVersion()`, `newCorePackageVersionLabel()`
  - `fetchingNewCorePackage()`, `fetchingNewCorePackageVersion()`
- Release gating comes from `core-info.json` `version` (strict integer parse) rather than semantic
  version strings; invalid/non-integer values are ignored for update availability.
- JAR Update-over-Mandatory (UOM) payload transfer is disabled for core; revocation/dependency
  signaling remains and legacy UOM wire names are retained for compatibility.
- Config keys such as `node.updater.enabled` and `node.updater.autoupdate` remain.

## Security model (high level)
- Content-addressed storage with cryptographic verification
- Encrypted link-level communication; routing conceals origin/destination
- Digital signatures for content authentication

## Versioning system
- A single integer build number is set in `build.gradle.kts` (`version = "<int>"`).
- Version tokens are replaced into the `:interop-wire` `network/crypta/node/Version.java`
  template during build (`@build_number@`, `@git_rev@`).
- Version strings support both Cryptad and Fred formats; compatibility enforces protocol match and minimum builds.
- Freenet interop uses historical identifiers (e.g., `"Fred,0.7"`) for wire compatibility where applicable.
- Core update descriptors (`core-info.json`) must publish `version` as an integer string; this value
  is compared against `Version.currentBuildNumber()` to determine whether a core package update is
  available.
