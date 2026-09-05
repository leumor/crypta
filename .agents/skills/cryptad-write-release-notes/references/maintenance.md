# Maintenance note contracts

Paths are repository-root-relative.

## Stable 1.0 maintenance and security-hotfix notes

Generate maintenance notes through `stable-maintenance`, using integer build/tag identity and the
authenticated predecessor. Include the release class, user-visible fixes, Platform API
compatibility statement, catalog/app delta, migration/backup/rollback guidance, package matrix,
CoreUpdater availability, known-limitations delta, support guidance, and checksum/provenance links.
A security hotfix also names the public-safe advisory and accurately describes any outstanding
full-window follow-up without exposing embargoed details or private evidence.

The generated `Stable 1.0 maintenance train` section comes from the exact authorized
`stable-backport` result. For each non-superseded public row, include the opaque fix id, public
classification, affected public component summary, provenance mode, safe source-to-candidate
lineage digest or public commit link when allowed, disclosed advisory id when applicable, and
compatibility or migration guidance. Bind the exact train digest and list deferred public known
issues without claiming they shipped.

Before disclosure, a security fix uses only its digest-bound opaque public projection and bounded
safe wording. Reject duplicate or superseded note rows, private issue URLs, private fork names,
embargoed titles, raw patch or exploit text, credentials, private insert URIs, local paths, raw
support/app/content data, and unsafe Markdown or HTML.

Treat the rendered note digest as part of candidate authorization. Reject placeholders, unsafe
Markdown/control text, private URIs, tokens, raw content/data, and local paths. Before a verified
publication-complete receipt, describe the notes and assets as prepared or authorized, never as
published. Link only to the planned public checksum/provenance assets. The public checksum file
does not enumerate internal candidate, lineage, comparison, evidence, follow-up, activation, or
history records; those belong only to the audit checksum inventory. Follow
`docs/stable-1.0-maintenance-release-and-hotfix-path.md`.
