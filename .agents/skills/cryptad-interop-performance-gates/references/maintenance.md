# Stable 1.0 maintenance evidence reference

Read for Stable 1.0 maintenance evidence. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 maintenance evidence

After GA, `python3 tools/release-certification/certify.py stable-maintenance` is the canonical
routine-maintenance and security-hotfix gate. It authenticates the GA root and latest predecessor,
then requires candidate-bound, fresh production live-network, Hyphanet interop, performance,
multi-node, sandbox, security, upgrade/recovery, and support evidence under the current policy
windows. Fixture, simulated-only, skipped, stale, dirty, test-signing, or wrong-candidate evidence
cannot satisfy production gates.

Routine maintenance uses the complete production windows and target matrix. A policy-qualified
critical security hotfix may shorten only the named prepublication observation windows; it still
passes every non-waivable gate and emits a deadline-bound full-window follow-up obligation. Closing
that obligation is side-effect-free and cannot change the published bytes. Preserve immutable
pre-release-train v1 authorizations for closure: the v1 schema may omit
`backportReleaseTrainDigest` only on this historical path, while every current preparation,
validation, and protected publication must require the exact train digest semantically. Follow
`docs/stable-1.0-maintenance-release-and-hotfix-path.md` and keep protected publication separate
from evidence production. Configure `STABLE_CATALOG_TRUSTED_KEYS_BASE64` on
`stable-1.0-maintenance-evidence` with the public-key-only production catalog registry. The freeze
must verify the exact catalog and detached signature under the declared key id, record the registry
SHA-256, and delete the decoded registry without publishing public-key bytes or embedding raw
signature content in JSON. The exact detached signature sidecar remains a frozen public asset.
Keep the publication provider's immutable source, wheel, signer, and
entry-point identity pins in repository-level Actions variables so the evidence-scoped independent
verifier and both publication environments authenticate the same backend without exposing any
publication-only target secret to the verifier.
Materialize target credentials before backend construction, then permanently remove their names
from both the adapter's environment snapshot and ambient process environment. Backend imports,
observations, and untargeted publication calls must see no catalog, CoreUpdater, or maintenance
state secret; deliver each opaque input only to its closed target operation.
Before authorization, expand and canonicalize every concrete publication-object URI—including
artifact-base children and the detached catalog-signature sibling—and reject aliases across
GitHub Release, artifacts, catalog primary/mirrors/rollback/signature, and CoreUpdater roles.
The canonical maintenance provider verifies but does not populate the public artifact base.
Pre-stage every planned object independently, then require an exact matching artifact-base prefix
before the tag is the first permitted mutation. An absent, partial, or mismatched artifact base
must fail protected preflight; it is not a resumable empty publication state.
Supplied maintenance publication receipts must bind the nested GitHub Release identity—including
release id, integer-build tag, and canonical public page URI—to the exact authorized target; a
passing operation, notes digest, and aggregate public observation are not sufficient.
Before authorization, require the GitHub Release page to be exactly
`https://github.com/crypta-network/cryptad/releases/tag/v<build>`. The protected provider owns that
fixed repository and must compare the deterministic `Cryptad v<build>` title as well as the tag,
commit, page, notes, draft/prerelease state, and assets when verifying exact existing state.
Allow the separately governed PR-290 companion asset names outside the maintenance-owned asset
plan only when the authenticated maintenance authorization and closed publication plan both bind
that the candidate freeze prospectively activates PR-290. Historical pre-activation releases
retain the original exact asset allowlist; a partial or arbitrary PR-290-named asset is a conflict.
Protected phase-ZIP intake must allowlist the complete extracted file tree, not only the
`protected-inputs/` subtree: the canonical phase manifest and files beneath explicitly referenced
directory inputs are the only survivors, and unrelated root-level or sibling files are blockers.
The latest-baseline activation job must retain its pre-adapter mutation-boundary marker on every
outcome. Its workflow audit conservatively reports that side effects may have occurred once that
marker exists and carries the observed pointer digest from an activation receipt when available;
never describe a missing receipt after that boundary as proof that the pointer was unchanged.
The deployment provider's `verify-publication` call must remain self-contained: send every closed,
digest-bound candidate, lineage, baseline, evidence, provenance, CoreUpdater, and nullable follow-up
record needed to construct the receipt, successor baseline, and history entry. Do not introduce an
undocumented service-side candidate store or treat service construction as producer
authentication; the protected adapter must independently validate every returned record.

Use this focused offline check while changing the maintenance engine, schemas, workflows, or
provider, followed by the broader suites appropriate to the touched integration:

```bash
python3 tools/release-certification/certify.py stable-maintenance --self-test
```
