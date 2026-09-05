# Stable 1.0 support lifecycle descriptor reference

Read for Stable 1.0 support lifecycle descriptor. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 support lifecycle descriptor

Build support state is mutable and must not be added to or changed in an already published
`core-info.json`. The runtime obtains the separate `support-lifecycle` document under the same
trusted public update-key identity, validates its closed schema and release identities, and retains
the last-known-good exact bytes plus edition and digest on disk. Reject a wrong key scope/docname,
unknown schema or status, edition rollback, previous-digest mismatch, release-identity mutation,
multiple current builds, or a current build that is not the authenticated release-chain tip.

Keep the read-only lifecycle subscriber active when `node.updater.enabled=false`; that setting
disables package fetching and installation, not local support/security status discovery. A genuine
update-key blow still stops lifecycle fetching because the lifecycle document shares that public
trust key. Persist accepted bytes at
`nodeDir/updates/core/support-lifecycle-last-known-good.json`, seed the subscription from the
accepted edition after restart, and fetch digest-linked successor editions sequentially. Fetch,
validation, or persistence failure retains the prior descriptor. Persistence retry must remain
bounded/backed off, and stale callbacks or temporary blobs from a replaced URI/subscription must
not regress accepted state or leak files.
Persist the bounded public-safe
`support-lifecycle-last-known-good.json.revocation-activations` sibling before replacing the
descriptor. It records when each terminal revocation first became enforceable and retains the
running build's bounded predecessor-effective replacement or recovery guidance. A future-effective
successor therefore preserves both the revocation veto and its active recovery path across restart
without activating changed successor guidance early. Bind the recovery projection to both sides of
each immediate descriptor transition. The binding must remain valid with the old descriptor after
the sidecar rename and with the new descriptor after its rename. Retain at most one
future-effective descriptor: validate but defer its exact successor until the persisted predecessor
becomes locally effective, then retry that edition so every intermediate status and recovery
guidance interval remains observable. Deferral is not a validation failure and must leave the
accepted edition seed unchanged. Keep the highest announced USK edition monotonic while fetching
the immediate digest-linked successor. Discard the projection when its binding is absent or
invalid. If the derived activation state is absent or invalid, fail closed from each authenticated
revoked entry's own effective time rather than suspending a potentially prior terminal revocation.
Clear all derived revocation state with the descriptor after update-key compromise.

Local-only package-updater failure must leave both lifecycle polling and revocation-key polling
active; only authenticated update-key compromise invalidates documents under that key. Package
payload downloads remain serialized, but completion of an older CHK fetch must retry a newer
automatic selection that was advertised while the older fetch was active.

Treat an update-URI change as an exclusive trust-scope transition. Set the manager's transition
latch before publishing the new URI, block updater startup and package actions until both
subscriptions and lifecycle trust are rebound, and preserve an accepted edition seed only inside
the same normalized scope. `NodeUpdater` callbacks must retain a generation/scope claim through
side-effecting post-processing and delete their owned temporary blobs when superseded.

Lifecycle persistence is crash-durable and platform-aware. Force completed temporary bytes before
publishing them; synchronize the parent-directory entry where supported and use the Windows native
write-through move instead of opening a Windows directory as a file channel. Resolve and pin the
`ProgramDirectory`-accepted node root before deriving lifecycle paths; allow that configured root
to use a symlink while rejecting symlinks in controlled descendants and descriptor/marker leaves.
Do not treat an accepted symlinked node-directory path as compromise evidence when no marker exists.

An authenticated update-key compromise invalidates cached lifecycle authority and package-update
authority across restart. Maintain the fixed-content sibling marker and independent node-level
fallback marker, treat an existing malformed/symbolic/unreadable marker as fail-closed compromise
evidence, retry failed marker persistence with bounded backoff, restore the critical operator alert
on restart, and block both package and lifecycle subscribers. Local-only updater failure must not
create that durable compromise latch or permanently stop lifecycle polling.

Expose only the detached, public-safe lifecycle snapshot through `CoreUpdateActionPort`. Unknown or
stale state must remain explicit; never infer support from update availability or the running build
number. Build `revoked` is a lifecycle-policy decision and must not call, alias, or otherwise trigger
the update-key blow/revocation path. End-of-support and build revocation surface actionable local
warnings without deleting data, shutting down the node, disabling FProxy browse, or inventing a
forced-update path.

Recheck effective build revocation at every package-action boundary. A later accepted descriptor
whose activation time is ahead of the local clock must not suspend an already-effective terminal
revocation preserved in its entry chain. Publish descriptor metadata, integer build identity,
detected environment, selected package key, and package specification as one immutable atomic
snapshot. Every download, installer, store-handoff, retry, and UI reader must use one snapshot
instance and reject it if a newer snapshot replaced it before the action boundary. Downloaded
installer launch and `openStore` submission both cross `CoreUpdateActionPort`; never return a
detached installer path or authorize a store target with a point-in-time boolean. Run each bounded
process-launch callback while the manager identity, updater selection, and lifecycle-state
authorization remain held, then release those locks before rendering the HTTP response. Store
submissions must exactly match the daemon's current selected kind, derived id, and public URL before
the HTTP adapter may open or install them. Any platform helper invoked inside that guarded callback
must have a hard execution timeout so it cannot indefinitely block trust invalidation or URI
changes.

Bind each `PackageFetcher` to the complete originating selection identity, not only its CHK. When a
new selection appears during a serialized download, completion or failure of the old fetch should
retry the new automatic selection through current trust and lifecycle gates. Lifecycle acceptance
must inspect the active fetcher's originating build, cancel it when already revoked, and schedule a
state-derived recheck for a future activation time. Do not wait for another descriptor announcement
to enforce an already authenticated future revocation.

For descriptor entry timing, require `statusEffectiveAt <= effectiveAt` and require a revoked
entry's `securityRevocationEffectiveAt` to equal `statusEffectiveAt`. Before a future descriptor
activates, hide its ordinary guidance and recommendation. Preserve only an already-effective
predecessor revocation and its bounded predecessor guidance. Keep `replacementBuild` null for
`supported-maintenance`; optional upgrades use descriptor-level `recommendedBuild`.

The lifecycle descriptor's public schema, protected publication, and operator behavior are defined
in `docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`. Use deterministic local
fixtures for fetch, rollback, persistence, stale-state, and release-identity tests; do not require
live DNS or update-key publication.
