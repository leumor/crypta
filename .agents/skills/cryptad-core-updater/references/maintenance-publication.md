# Stable 1.0 maintenance descriptor publication reference

Read for Stable 1.0 maintenance descriptor publication. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 maintenance descriptor publication

For a Stable 1.0 maintenance or security-hotfix candidate, `stable-maintenance` generates
deterministic `core-info.json` bytes bound to the exact frozen packages. Require the canonical
integer `version`, public release page, sorted supported `<arch>.<ext>` package keys, public CHK or
store URLs, and authenticated package sizes. Every required candidate package must appear exactly
once; do not add a misleading local SHA-256 field, placeholder, private insert URI, or local path.

Include the descriptor digest in checksums, provenance, authorization, and the publication plan.
The update USK private insert URI/key is a protected secret supplied only at the publication
boundary. After insertion, fetch through the public request URI, compare exact descriptor bytes and
referenced package identities, and record a separate updater publication receipt. Conflict or an
unavailable public observation is not idempotent success and must not be overwritten.
Bind the plan and receipt to the exact public fetch URI and USK edition, not only to the descriptor
and package-map digests. The published descriptor's CHK/store references must use canonical public
destinations whose resolved addresses are global. A receipt for a different URI, edition, package
target, or fetched byte sequence cannot activate a successor baseline.
The protected workflow loads the reviewed provider named by
`CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND` and exposes
`CRYPTAD_CORE_UPDATE_PUBLICATION_INPUT` only to the CoreUpdater target operation. Never reuse the
catalog or maintenance-state protected input for update insertion, and never serialize the private
input into the descriptor, plan, receipt, logs, or uploaded artifacts.
The provider's public deployment-service verification receives the authenticated CoreUpdater plan
and descriptor inside its closed `verificationInputs` set. It must construct a complete updater
receipt from those exact records; it must not rely on an undocumented service-side copy. The
protected adapter independently validates `verificationStatus`, public fetch URI, edition,
descriptor bytes, and every referenced package before accepting that receipt.

Use `AppEnv` for platform/package-key mapping and follow
`docs/stable-1.0-maintenance-release-and-hotfix-path.md`.
