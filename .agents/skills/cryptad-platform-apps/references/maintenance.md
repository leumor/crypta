# Stable 1.0 maintenance compatibility reference

Read for Stable 1.0 maintenance compatibility. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 maintenance compatibility

Use `stable-maintenance` after GA for both routine maintenance and critical security hotfixes. It
compares Platform API, stable catalog, first-party apps, content profiles, security/support state,
limitations, and legacy boundaries against both the immutable GA baseline and the immediate
predecessor. Preserve original Platform API deprecation clocks and frozen v1 canonicalization and
signature rules. Reject app removal/id substitution, channel or support downgrade, untrusted
signers/reviewers, unexplained permission expansion, or missing migration, rollback, backup, and
restore evidence. If catalog bytes, signature, or signing-key identity changes, require the edition
or revision to advance. Validate known-limitations added/resolved/unchanged ids as a disjoint,
canonical partition of the authenticated predecessor membership; retain the sorted current ids in
each successor baseline so a later release cannot replace membership with an unauthenticated
digest.

Treat app support as a closed ordered commitment: promotion is allowed, downgrade or an unknown
level is not. Compare app versions with the canonical dotted-numeric `AppUpdateService` semantics.
A version cannot regress below GA or the predecessor, and changed bundle bytes require a strict
version increase so an installed node can discover the patch.

Bind all app/catalog/update and durable-state scenarios to the exact candidate and predecessor
digests. A security hotfix cannot waive these gates; only policy-listed observation windows may be
shortened, creating a follow-up obligation. Follow
`docs/stable-1.0-maintenance-release-and-hotfix-path.md`.
