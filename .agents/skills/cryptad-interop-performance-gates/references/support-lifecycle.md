# Stable 1.0 support lifecycle evidence reference

Read for Stable 1.0 support lifecycle evidence. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 support lifecycle evidence

After authenticating the immutable GA root and complete no-fork maintenance history,
`python3 tools/release-certification/certify.py stable-lifecycle` derives the real published build
inventory and evaluates the policy-driven lifecycle ledger. It never accepts a manifest label as
publication evidence and never publishes from `evaluate`, `prepare-transition`, self-test, or pull
request execution. Use the checked-in support lifecycle policy and closed schemas; do not hardcode
support durations in Python or Java.

The lifecycle ledger is append-only and digest chained. Normal transitions advance through
`current-stable`, `supported-maintenance`, `security-fixes-only`, `deprecated`, and
`end-of-support`. An explicit advisory-backed protected transition may instead enter terminal build
`revoked`; it remains separate from update-key revocation. Authorization must bind the exact
transition request, previous state, resulting ledger, descriptor edition/digest, and target.
Publication then binds the authorization and exact descriptor bytes. Do not create a circular
authorization/ledger digest or represent a self-derived row digest as protected approval.

Keep producer output inside the runtime's closed descriptor contract: at most 256 complete
inventory entries; entry `statusEffectiveAt` no later than descriptor `effectiveAt`; identical
status/security effective timestamps for revocation; and bounded safe recovery text accepted by
both schema and Java parser. `supported-maintenance` carries no mandatory `replacementBuild`;
descriptor-level `recommendedBuild` provides the optional upgrade. A schema-valid producer result
that runtime nodes cannot parse or activate is a release blocker.

The protected workflow has six closed operations: `prove-genesis`, `evaluate`,
`prepare-transition`, `validate-authorization`, `publish`, and `verify-publication`. Bind every
dispatch to the exact release id, chain-tip integer build, source commit, producer run, artifact
name, and Actions artifact digest. Edition 1 requires an attested HTTP `404` proof for the exact
target; HTTP `410` is a tombstone, not genesis. Later editions require the exact prior
ledger/descriptor pair. Publish and verification consume a separately attested lifecycle-only
provider wheel; only publish receives insert material.

Lifecycle workflow source is trusted only when the dispatch ref is protected `main`, the exact
`release/<build>`, or the exact `hotfix/<build>` ref. Require the selected source commit to equal
the workflow-dispatch `GITHUB_SHA` and checked-out `HEAD` so artifact provenance and executed code
have one source identity. It must also remain reachable from the authenticated live remote tip;
that ancestry check permits the branch to advance after dispatch, not an independently selected
older commit. Require GitHub's protected-ref context before requesting an environment. Use a
credential-free preflight for producer inputs, then recheck branch protection and ancestry before
input credentials or publication insert material are exposed.
Configure the lifecycle evidence, authorization, and publication environments with
deployment-branch restrictions for protected `main`, `release/*`, and `hotfix/*`; keep the
workflow's exact-build allowlist as an independent gate.

Keep the complete post-publication component plus external receipt available for independent
verification, but remove protected input trees from the verification bundle. Read-only
verification may occur after approval expiry when it proves that the original receipt timestamp
fell inside the authorization interval. Authorization validation and publication still require a
currently valid approval. Resolve current ledger/descriptor subjects by canonical component path,
because successor bundles intentionally retain prior artifacts with the same basenames.

Stable maintenance certification consumes the authenticated lifecycle state to reject an ordinary
EOL/revoked predecessor, prevent support-clock resets, and propose successor lifecycle changes only
after verified release publication. The protected lifecycle workflow inserts the separate
`support-lifecycle` update-key edition, accepts identical existing bytes only after verification,
and never overwrites a conflict. Follow
`docs/stable-1.0-support-lifecycle-and-deprecation-governance.md` and run:

```bash
python3 tools/release-certification/certify.py stable-lifecycle --self-test
```
