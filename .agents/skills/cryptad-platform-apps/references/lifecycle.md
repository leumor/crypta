# Stable 1.0 lifecycle and deprecation governance reference

Read for Stable 1.0 lifecycle and deprecation governance. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 lifecycle and deprecation governance

Platform API 1.0 deprecation clocks are historical commitments. A maintenance baseline may carry
them forward but must not move `deprecatedSinceContractVersion` or scheduled removal later to reset
the clock. Do not remove a stable endpoint or capability while an authenticated supported Stable
1.0 build or required stable third-party sample depends on it. Lifecycle end-of-support never
rewrites a published contract snapshot or makes a prohibited critical-removal waiver valid.

Reuse signed catalog, review, app-maintenance, advisory/denylist, and content-profile metadata when
building lifecycle governance output. The projection informs certification and operator support;
it does not replace those trust models. Keep first-party app IDs and support commitments stable,
require explicit replacement/migration guidance for deprecation where policy requires it, preserve
backup/restore commitments, and never change a frozen content-profile canonicalization or signature
rule in place.

Expose the running build's lifecycle through the detached updater SPI, read-only update/operator
routes, the redacted support bundle, and the Web Shell. Distinguish unknown, stale, full support,
security-only, deprecated, end-of-support, and revoked states. Show integer build identifiers and
safe replacement guidance, and offer an update action only when the existing updater can honor it.
Use `recommendedBuild` for an optional upgrade from `supported-maintenance`; do not label it as a
required replacement. Do not expose changed future-effective guidance early. An already-effective
terminal revocation remains visible with its predecessor-authenticated recovery guidance until the
successor activates, including when the last-known-good descriptor is stale. Do not include raw
descriptors, private update URIs, advisory bodies, local paths, app data, or node identity in these
surfaces. Follow
`docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`.
