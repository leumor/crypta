# Release certification tooling

Use `certify.py` to collect, evaluate, redact, and package Cryptad release evidence.

The tooling requires Python 3.12 or newer and uses only the Python standard library. Run commands
from the repository root unless a command supplies `--workspace-root` explicitly.

## Quick start

Run every offline characterization and contract test:

```bash
python3 tools/release-certification/certify.py self-test all
```

Run one focused suite:

```bash
python3 tools/release-certification/certify.py app-platform --self-test
python3 tools/release-certification/certify.py release-certification --self-test
python3 tools/release-certification/certify.py production-beta --self-test
python3 tools/release-certification/certify.py stable-rc --self-test
python3 tools/release-certification/certify.py stable-ga --self-test
python3 tools/release-certification/certify.py stable-backport --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py stable-lifecycle --self-test
python3 tools/release-certification/certify.py stable-supply-chain --self-test
python3 tools/release-certification/certify.py stable-dependency-vulnerability --self-test
python3 tools/release-certification/certify.py stable-vulnerability --self-test
python3 tools/release-certification/certify.py stable-protected-release --self-test
python3 tools/release-certification/certify.py stable-independent-reproducibility --self-test
python3 tools/release-certification/certify.py stable-catalog-authority --self-test
python3 tools/release-certification/certify.py stable-third-party-pilot --self-test
python3 tools/release-certification/certify.py stable-federated-catalog --self-test
python3 tools/release-certification/certify.py stable-platform-api-1x --self-test
python3 tools/release-certification/certify.py stable-legacy-plugin-migration --self-test
```

Before dispatching the protected Stable workflows, validate one versioned non-secret execution
contract:

```bash
python3 tools/release-certification/certify.py stable-protected-release \
  --mode preflight \
  --execution-contract build/protected-release/stable-1.0-protected-release.json
```

The contract distinguishes authenticated Stable producer evidence, exact caller-supplied RC input
bytes, and gates that the protected RC run regenerates. Native third-party intake remains an exact
`rcInputs` file; the production-beta aggregate is regenerated rather than relabeling the native
bytes. After preflight, bind its exact passing summary as `operationEvidence.preflight`. The RC
workflow first checks the complete contract, exact receipt digest, and canonical passing receipt in
its credential-free job, before requesting the protected RC environment. It then invokes the same
command with
`--mode rc-dispatch --rc-input-map <path>` after materialization. This second side-effect-free check
rejects a missing or substituted preflight receipt and any changed evidence byte, Stable producer
coordinate, known-issues/intake/waiver/exception file, refreeze predecessor, source, release, mode,
authority class, target, or runtime app-signing/reviewer/review-policy/catalog identity before
`stable-rc` can freeze the candidate.
The default preflight summary remains directly beneath
`build/release-certification/<execution-id>/stable-protected-release/`; default RC-dispatch and
closeout reports use its `rc-dispatch/` and `closeout/` subdirectories. A bound preflight receipt is
immutable input evidence. The command rejects any explicit output path that would overwrite the
contract, RC input map, or a contract-bound evidence file.

After real workflow receipts and an independently produced public-observation record exist, update
that contract with their exact repository-relative files, immutable workflow/run/attempt/artifact
coordinates, the canonical GA validation and publication-plan members retained in the protected
validation artifact, its canonical validation-authorization identity member, and the separate
read-only observation coordinate, then run the same command with `--mode closeout`. Closeout
also consumes the unmodified RC and GA-publication Actions ZIP downloads, binds their container
digests to the authenticated workflow coordinates, and requires the local RC freeze and GA
publication receipt to be byte-identical to their canonical ZIP members. The RC ZIP also carries
the exact canonical preflight summary consumed by `rc-dispatch`; bind those bytes as
`operationEvidence.rcPreflight`. Closeout rejects a regenerated or re-serialized substitute even
when its decision is semantically equivalent. It consumes the exact RC freeze record bound by the
authenticated lineage, reconstructs the GA
promotion identity from the authenticated validation-authorization identity, and requires the
exact passing preflight receipt before protected completion. The publication plan cannot
authenticate its own digest. Repository policy selects every upstream schema and canonical Stable
public target form; contract rows cannot substitute a permissive schema or private/non-global
target. The command delegates release semantics to `stable-rc` and `stable-ga`; it does not freeze,
rebuild, publish, or infer remote success. See
`docs/stable-1.0-protected-release-execution.md`.

Run a CI-safe app-platform collection with the checked-in manifest:

```bash
python3 tools/release-certification/certify.py app-platform \
  --manifest tools/release-certification/manifests/developer-dry-run.json
```

All non-test commands require a versioned JSON manifest. Copy one of the examples under
`tools/release-certification/manifests/`, replace its placeholders, and keep private keys,
passwords, tokens, private insert material, and reviewer key bytes out of the file.

## Command tree

The public entry point is `tools/release-certification/certify.py`.

| Command | Purpose |
| --- | --- |
| `app-platform` | Collect app-platform source, contract, app, security, recovery, and redaction evidence. |
| `app-platform-docs` | Validate developer portal, tutorial, beta-program, and documentation evidence. |
| `network-scale-soak` | Generate deterministic network-scale and budget evidence. |
| `live-network-beta` | Collect explicitly configured localhost live-network evidence. |
| `multi-node-beta` | Plan, run, or verify multi-node soak and previous-candidate upgrade evidence. |
| `security-response` | Verify the runbook or create and verify security drill artifacts. |
| `release-certification` | Aggregate release evidence and evaluate ecosystem certification gates. |
| `production-beta` | Build, certify, redact, and package a production-beta candidate. |
| `go-no-go` | Build the release-manager launch dashboard. |
| `stable-readiness` | Evaluate the Stable 1.0 promotion gate. |
| `stable-rc` | Execute, freeze, package, and verify a protected Stable 1.0 release candidate. |
| `stable-ga` | Validate and prepare explicit promotion of one exact frozen Stable 1.0 RC without rebuilding or publishing it. |
| `stable-backport` | Classify Stable 1.0 fixes, authenticate source-to-candidate provenance, account for one release train, and verify completion without changing Git or public state. |
| `stable-maintenance` | Authenticate, validate, freeze, and prepare one built-once Stable 1.0 maintenance or security-hotfix release. |
| `stable-lifecycle` | Evaluate and prepare authenticated Stable 1.0 build-support lifecycle transitions without publishing them. |
| `stable-supply-chain` | Assemble and verify Stable component, SBOM, license, isolated-rebuild, promotion, and publication-observation evidence; the CLI is side-effect-free and the protected workflow has an explicit publication boundary. |
| `stable-independent-reproducibility` | Prepare a candidate-byte-free verifier kit, authenticate a provider-distinct external build, reuse the Stable comparison authority, and produce protected closeout without publication. |
| `stable-catalog-authority` | Prepare and verify the role-separated Stable key ceremony, exact catalog publication, rotation and rollback drills, transparency artifact, and authenticated closeout without remote mutation. |
| `stable-third-party-pilot` | Authenticate one external developer handoff, reviewed/rejected/corrected/caution cohort, bounded publisher approval, PR-293 beta publication, exact live-collector bytes, isolated-node runtime drill, and read-only Actions-authenticated operational closeout without remote mutation. |
| `stable-federated-catalog` | Authenticate bounded signed discovery and non-transitive endorsements, local scoped trust and conflicts, pinned origin/runtime observations, and exact digest-bound PR-291–294 predecessor summaries and closeout coordinates without fetching or mutating local or remote state. |
| `stable-platform-api-1x` | Verify the append-only Platform API contract ledger, future-baseline proposals, experimental graduation records, monotonic deprecation timelines, static cross-release app matrix, bounded runtime observation, and exact PR-291–295 protected roots without activating a baseline or mutating release state. |
| `stable-legacy-plugin-migration` | Validate a closed sanitized local Sharesite observation while keeping private payloads out of evidence. Local claims remain unverified; runtime and closeout fail closed because no protected migration producer is configured. |
| `stable-dependency-vulnerability` | Validate authenticated advisory snapshots, exact PR-289 component matching, bounded dispositions, PR-288/287/285 remediation lineage, promotion, and public observation without live retrieval or remote mutation. |
| `stable-vulnerability` | Validate the protected Stable 1.0 vulnerability case lifecycle, exact disclosure authorization, publication observation, and closure without remote mutation. |
| `migrate-v1` | Convert validated v1 previous-candidate or history summaries for the first v2 release. |
| `self-test` | Run one focused `unittest` suite or all suites. |

Use `--help` on the entry point or a command for its exact syntax.

## Stable 1.0 vulnerability lifecycle

The unified vulnerability engine is side-effect-free. Run it only from an isolated protected
execution workspace after an approved protected assembler has materialized the exact phase input:

```bash
vulnerability_run_root="$(mktemp -d)"
# Resolve platform temporary-directory aliases before protected path validation.
vulnerability_run_root="$(cd "$vulnerability_run_root" && pwd -P)"
install -d -m 700 "$vulnerability_run_root/workspace"
install -d -m 700 "$vulnerability_run_root/protected-inputs"
git archive --format=tar HEAD | tar -xf - -C "$vulnerability_run_root/workspace"
# Materialize the authenticated flat phase set at
# "$vulnerability_run_root/protected-inputs", outside the archived checkout.
export CRYPTAD_STABLE_VULNERABILITY_PROTECTED_IN="$vulnerability_run_root/protected-inputs"
export CRYPTAD_STABLE_VULNERABILITY_PROTECTED_OUT="$vulnerability_run_root/protected-output"
(
  cd "$vulnerability_run_root/workspace"
  python3 tools/release-certification/certify.py stable-vulnerability \
    --manifest "$vulnerability_run_root/protected-inputs/manifest.json"
)
```

Its closed modes are `evaluate-intake`, read-only `evaluate-promotion`, `validate-triage`,
`record-reporter-update`, `prepare-remediation`,
`validate-disclosure-authorization`, `verify-disclosure-publication`, and `verify-closure`.
The checked-in policy is `stable-1.0-vulnerability-disclosure-policy.json`; the immutable empty
root is `stable-1.0-vulnerability-ledger-genesis.json`; and
`manifests/stable-1.0-vulnerability.example.json` shows the intake manifest shape. Its
`protected-inputs/<name>.json` values are names inside the isolated protected input root. A real
protected assembler materializes those exact flat names and never stores private material in the
repository build tree.

`evaluate-promotion` authenticates a genesis or unchanged predecessor ledger and emits a fresh
release/build-bound blocker summary without creating a case transition, successor ledger, or
public artifact. The protected workflow reseals that summary. Aggregate release certification
requires the exact summary, successor binding, materialization provenance, encrypted handoff,
protected handoff key, matching candidate release/build identities, and a current Actions
ledger-tip observation; self-digested, superseded, or wrong-candidate summaries fail closed. The
retention-independent authority is the closed, digest-chained
`STABLE_1_0_VULNERABILITY_LEDGER_TIP_ANCHOR` repository Actions variable. It must be explicitly
provisioned before first use to the compact, sorted JSON emitted by
`jq -cS . tools/release-certification/stable-1.0-vulnerability-ledger-tip-anchor-genesis.json`.
Missing, deleted, noncanonical, wrong-policy, or digest-invalid anchor state never means genesis.
Validators and promotion consumers receive only
`CRYPTAD_STABLE_VULNERABILITY_ANCHOR_READ_TOKEN`, scoped to repository Variables read. Every
appender compares its predecessor ledger digest and edition to
the freshly retrieved anchor before evaluation. Retained successor artifacts remain exact
producer and promotion evidence, but ordinary Actions retention cannot reset the ledger.
Backport and maintenance consumers use the same authenticator, but accept only
`evaluate-promotion` with null case-specific subject fields and the exact `ledger-wide` binding.
Their protected input artifacts carry the binding, provenance, and encrypted
`sealed-successor/` files, never a plaintext ledger-wide summary; only the protected consumer
environment opens and materializes the exact summary in a confined external temporary root.
Release-candidate aggregate certification runs only in the protected
`stable-1-0-release-certification` job. Configure the vulnerability handoff key and anchor-read
token on that environment; PR and nightly certification run in a separate non-promotion job and
receive neither credential.

`record-reporter-update` is a protected append-only case transition for contactable reports. It
accepts exactly one new `remediation-status-update`, resolves the current reporter-status
obligation with that record, and creates the next policy-cadence obligation until exact public
observation ends the pre-disclosure cadence. It accepts no reporter address or raw message body.

Case-transition artifacts are proposals until
`.github/workflows/stable-1.0-vulnerability-ledger-activation.yml` authenticates the exact
successful validator artifact and performs the final compare-and-swap. That separate protected
environment alone receives `CRYPTAD_STABLE_VULNERABILITY_ANCHOR_WRITE_TOKEN`, scoped to repository
Variables write. It compares the expected anchor digest and sequence, advances exactly one ledger
edition, binds the producer workflow/commit/run/attempt/artifact and successor-binding digest,
then freshly reads back the exact canonical anchor. The shared cross-workflow lock serializes the
read/compare/update boundary. `evaluate-promotion` is read-only and cannot activate an anchor.
Multiple validator proposals for the same successor edition may coexist before activation. The
activation and promotion verifiers authenticate only the explicitly selected run, attempt,
artifact name, digest, and binding; they never infer committed history or a fork from other
unactivated proposals. After one proposal advances the anchor, every alternative built from the
old predecessor is stale and fails the anchor comparison without blocking later operations.
The support-lifetime protected archive remains responsible for the encrypted ledger bytes; the
anchor contains only bounded governance digests and producer coordinates.

The authoritative case, ledger, report envelope, acknowledgements, authorizations, and operational
summary are never written into the repository’s ordinary `build/` tree. The case and successor
ledger go only to the mandatory protected output directory, which must be initially empty and
outside the repository and public run. Protected workflows seal it with
`protected/stable_backport_protected_handoff.py` using the separately configured
`CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64`. Policy and engine cap the exact canonical ledger
at the handoff primitive's 16 MiB per-file limit; the independent 4,096-case ceiling does not
authorize an oversized, untransportable ledger. Before disclosure, an Actions public upload
contains only the case-scoped public-safe projection and passing redaction result. The bounded operational
summary and its ledger-wide report remain encrypted even after disclosure. Independent exact-byte
observation permits only the current case's projection, advisory, publication receipt,
public-observation receipt, and passing redaction result to enter the public upload.

The checked-in workflows are validation shells, not a report collector or network publisher.
Configure the repository variable `STABLE_VULNERABILITY_PHASE_ASSEMBLER_WORKFLOW` to the exact
approved protected assembler workflow path. It authenticates the prior protected successor, joins
only the new phase-specific protected inputs, creates the canonical manifest, and emits the sealed
phase artifact. No initial case can enter until that configured producer exists; validators fail
closed rather than inventing a report source.

Mitigation, catalog-security, and key-lifecycle receipts are not trusted from their embedded
`producer` object. Before sealing a phase, the configured assembler must authenticate the native
authority workflow against its protected allowlist, exact commit, successful run attempt, one
non-expired exact artifact name/digest, and the exact bounded receipt member. It emits
`stableVulnerabilityAuthorityReceiptProvenance`, bound to the canonical receipt file and semantic
digests, in the encrypted bundle. Disclosure authorization and closure require that provenance
whenever one of those receipts is present. A mitigation-only case is noncritical and remains on the
policy's `routine-maintenance` lane; it cannot use `security-hotfix` as a lane exception.

Configure `STABLE_VULNERABILITY_OBSERVER_WORKFLOW` to the exact independent read-only observer
workflow path. Remote publication belongs to a separately protected, attested advisory provider.
The provider returns an append-only exact-byte receipt; the observer authenticates it and performs
a fresh public read without mutation credentials. The checked-in
`stable-1.0-vulnerability-disclosure-publication.yml` workflow authenticates the observer
run/artifact and validates those records. It never publishes.

All four validators require exact release id, integer build, source commit, producer run
id/attempt, artifact name/digest, phase-manifest digest, and predecessor ledger edition/digest.
Case-transition modes require an opaque case id, while `evaluate-promotion` requires the reserved
`ledger-wide` subject. The publication-observation validator also requires the publication-receipt,
public-observation, and advisory-byte digests. They authenticate one non-expired exact Actions
artifact before download, reconstruct the expected HMAC binding, execute in a temporary
Git-archive workspace, generate a successor-specific binding, and stage exact scanned protected or
public file allowlists.

The command validates PR-287, maintenance/hotfix, CoreUpdater, lifecycle, catalog, and key
receipts; it does not execute those authorities. It performs no network or Git mutation and does
not allocate CVE/GHSA identifiers. See
`docs/stable-1.0-vulnerability-intake-and-coordinated-disclosure-operations.md` for phase inputs,
SLAs, workflow roles, advisory publication boundaries, and closure rules.

## Source layout

`certify.py` is a thin entry point. Keep the public contract and shared safety boundaries in the
`cryptad_certification` package:

```text
cryptad_certification/
  cli.py                 command tree and collection orchestration
  manifest.py            strict release-run manifest loading
  workspace.py           marked, candidate-scoped workspace confinement
  envelope.py            evidence envelope v2 normalization and validation
  redaction.py           reusable evidence and migration scanning
  migration.py           one-time v1 history conversion
  legacy.py              controlled adapters for the split engines
  engines/               component implementations, split by responsibility
  tests/                 contract, characterization, workflow, and safety tests
```

Do not restore the removed top-level per-engine scripts or shell wrappers. Split an engine by
responsibility before a Python source file exceeds 5,000 lines; `self-test core` enforces that
limit.

## Release-run manifest

The manifest schema is `schemas/release-run-v1.schema.json`. A manifest contains:

- release identity, version, and profile;
- output and reset policy;
- required evidence and promotion gates;
- non-secret input paths;
- catalog, artifact, freshness, and signing-profile labels;
- execution controls and command-specific arguments.

The structured maps are closed contracts. Unknown keys and values of the wrong type fail before
the release workspace is prepared:

| Map | Supported fields |
| --- | --- |
| `requirements` | Boolean `history`, `liveNetwork`, `multiNodeSoak`, `sandboxProviderTests`, `stableReadiness`, and `thirdPartyIntake` gates. |
| `inputs` | Non-empty paths for interop, performance, app-platform, live-network, network-scale, multi-node, security-drill, production, dashboard, certification, Stable, waiver, policy, known-limitation, previous-candidate, release-history, stable catalog operations, previous Stable RC freeze, Stable RC freeze exceptions, and the selected Stable RC/GA validation, authorization, policy, lineage, or optional publication-receipt artifacts. |
| `policies` | `artifactBaseUri`, `catalogChannel`, `candidateSourceCommit`, `candidateSourceRef`, `expectedPreviousReleaseId`, `expectedPreviousProductDigest`, `historyDir`, `historyLabel`, `publicationIntent`, `stableRcFreezeMode` (`first-freeze` or `refreeze`), and string-valued `metadata`. |
| `execution` | Boolean collection/build/test controls plus positive integer `timeoutSeconds`. |

`commands.<name>.args` remains an advanced engine-specific escape hatch. The unified command owns
workspace, output, mode, and release identity arguments and removes attempts to override them.
Exact controlled options are removed, and abbreviated forms are rejected before legacy argparse
processing so prefixes cannot escape the marked workspace or replace candidate policy and identity.
For commands that evaluate release policy, `commands.<name>.mode` may only restate the mode derived
from `release.profile`; a conflicting value is rejected instead of weakening or relabeling the
candidate. `commands.multi-node-beta.mode` remains the separate topology execution mode.

Supported profiles are `pr`, `nightly`, `developer-dry-run`, `release-candidate`,
`production-beta`, and `stable-review`. Unknown fields, unsafe release IDs, incompatible types,
secret-like field names, and secret-bearing scalar values fail before a command creates artifacts.
The loader rejects private SSK/USK material, private keys, authorization values, credentials, and
secret assignments without copying the rejected value into its error message.

`--workspace-root` and `--out-root` are the only location overrides outside the manifest. Relative
input paths are resolved from the workspace. Secret inputs continue to use the protected
environment variables and protected files documented by the production release workflow.

## Release workspace

Every command writes below one release-scoped directory:

```text
<out-root>/<release-id>/
  .cryptad-certification-run.json
  <component>/
    summary.json
    report.md
    redaction-report.json
    artifacts/
```

For Stable 1.0 RC execution, copy
`manifests/stable-1.0-rc.example.json`, replace every placeholder, and run:

```bash
python3 tools/release-certification/certify.py stable-rc \
  --manifest build/stable-1.0-rc.json
```

The manifest retains the `stable-review` profile and integer build number. The command generates a
unified production-beta component inside the same marked run; that protected pipeline produces and
binds its go/no-go, release-certification, app-platform, ecosystem-matrix, and Stable-readiness
native artifacts for the Stable RC engine. Do not attach unrelated precomputed copies to the
canonical manifest. External prerequisites use the coordinated `stableCatalogOperations`,
`previousStableRcFreeze`, `stableRcFreezeExceptions`, and authenticated
`stableVulnerabilitySummary` input names. The manifest must set
`requirements.stableVulnerability=true` and
`policies.stableVulnerabilityGovernance=required`. The protected workflow accepts only the exact
current ledger-wide `evaluate-promotion` run/attempt/artifact coordinates, opens the encrypted
handoff outside public roots, and forwards the release/build-bound summary into nested aggregate
certification. The RC engine then requires the exact passing non-waivable PR-288 evidence and
child gate; a generic passing aggregate or omitted summary cannot authorize the RC. Stable RC
output lives under
`<out-root>/<release-id>/stable-rc/`; see the
[Stable RC runbook](../../docs/stable-1.0-rc-execution-and-release-freeze.md) for its freeze schema,
artifact inventory, drift and exception semantics, and protected workflow.

`stableCatalogOperations.artifactTimestamp` is the immutable producer timestamp for the signed
catalog and first-party review receipts. The same protected value is used on every refreeze. The
production pipeline emits `crypta-stable-1.0-rc-<build>-product.tar.gz` with normalized member
metadata and no run-specific evidence reports; this is the exact distribution bound by the Stable
RC freeze. The ordinary production-beta evidence archive remains available to its existing
consumers. These requirements apply only when `stable-rc` orchestrates the production stage; a
direct `production-beta` run with the `stable-review` profile keeps the pre-existing manifest and
intake contracts.

Set `policies.stableRcFreezeMode=first-freeze` only for the initial candidate baseline and omit
`inputs.previousStableRcFreeze`. Every later run uses `stableRcFreezeMode=refreeze` and must supply
the exact freeze from the latest successful protected workflow run. The workflow authenticates
that parent against the latest uploaded artifact when available. Each successful protected run
also creates a commit-bound check-run lineage anchor for the exact freeze file digest, release,
build, run, and attempt. After the uploaded artifact expires, a retained freeze is accepted only
when its digest matches that latest authenticated anchor; stale or unauthenticated lineage fails
closed. The canonical freeze binds the exact deterministic product-distribution digest. Rebuilding
the unchanged candidate must produce identical bytes; a catalog, review receipt, bundle, launcher,
policy, or product member change remains candidate drift even when semantic producer summaries are
unchanged.

For Stable 1.0 GA validation, copy
`manifests/stable-1.0-ga.example.json`, replace every placeholder, and run:

```bash
python3 tools/release-certification/certify.py stable-ga \
  --manifest build/stable-1.0-ga.json
```

`stable-ga` retains the `stable-review` profile and writes to
`<out-root>/<release-id>/stable-ga/`. It is side-effect-free: the command authenticates one exact
successful Stable RC, evaluates post-freeze production validation and explicit GA authorization,
and prepares promotion records. It does not rebuild the product, create a branch or tag, publish a
GitHub Release, change a catalog, insert an update descriptor, or perform a network insert.

The GA manifest uses these exact input names:

```text
selectedStableRcSummary
selectedStableRcFreeze
selectedStableRcFreezeSidecar
selectedStableRcArchive
selectedStableRcProduct
selectedStableRcChecksums
selectedStableRcProvenance
selectedStableRcLineage
previousCandidate
stableRcValidation
stableGaAuthorization
stableGaPolicy
stableGaPublicationReceipt
```

`stableGaPublicationReceipt` is optional and is used only to verify a returned protected
publication result. `stableGaPolicy` normally points to the checked-in
`stable-1.0-ga-policy.json`. The non-secret policy values bind the public HTTPS artifact base,
stable catalog primary/mirror/rollback confirmation URIs, stable catalog channel, exact candidate
source commit/ref, and publication intent. The canonical metadata keys are
`catalogPrimaryUri`, `catalogMirrorUris`, and `catalogRollbackUri`; all three are included in the
authorized publication-target digest. Stable GA also requires `expectedPreviousReleaseId` and
`expectedPreviousProductDigest`. The exact migrated `previousCandidate` envelope authenticates the
predecessor release/build against the PR-283 freeze and provenance, while the manifest supplies the
published predecessor product digest; the authorization identity binds all four predecessor
fields. Signing keys,
private insert URIs, GitHub credentials, authorization headers, tokens, and publication credentials
remain protected environment or file inputs and must never appear in the manifest.

The selected RC files must form one authenticated, symlink-free artifact set. Stable GA verifies
the common RC envelope; freeze schema, canonical digest, and sidecar; exact checksums; provenance;
outer archive; immutable product; catalog, app, Platform API, content-profile, limitation, waiver,
and freeze-exception bindings; and latest protected refreeze lineage. The post-freeze
`stable-1.0-rc-validation` record must bind every scenario to the exact frozen product digest and
meet the checked-in policy, including at least 24 hours of real production soak measured from the
long-soak scenario's own timestamps. Top-level validation and scenario start times must not precede
the authenticated protected RC run completion in the selected lineage.
Because the vulnerability ledger can advance during that interval, the RC-time decision is not a
GA-time authorization. Every `publish=true` GA dispatch supplies a new exact ledger-wide
`evaluate-promotion` run, attempt, artifact name, and artifact digest. The protected publication
job holds `stable-1-0-vulnerability-ledger`, authenticates the selected producer and current anchor,
opens and validates the sealed summary outside public roots, and rejects any promotion blocker
before the first tag, Release, or asset mutation. None of that handoff enters the GA artifact.

For the explicit authorization review pass, set `commands.stable-ga.mode` to
`prepare-authorization` and omit `stableGaAuthorization`. The command validates the exact RC and
writes `stable-1.0-ga-validation-authorization-identity.json`, but it does not report promotion
readiness. The protected authorization's `gaValidationDigest` is the canonical semantic SHA-256 of
that identity. The identity and authorization also bind a canonical publication-target digest for
the expected tag and release branch, artifact base, catalog primary, ordered mirror list, and
rollback catalog location.
Changing any destination requires a new preparation, authorization, and protected evidence pass.
Rerun in `validate-only` mode with the authorization input. This two-pass contract prevents an
authorization/final-record circular digest and rejects authorization or publication receipt inputs
during the preparation pass.

Input acquisition and producer authentication are separate controls. A confined repository path,
public HTTPS URL, or `actions-artifact://` reference only determines how the workflow obtains a
record. Before publication, run `.github/workflows/stable-1.0-ga-promotion.yml` with
`publish=false` on the exact `release/<build-number>` candidate. The protected
`stable-1-0-ga-evidence` job attests the exact validation, authorization, and canonical
publication-target identity bytes. A later `publish=true` dispatch accepts only identical bytes and
destinations with attestations from that workflow, release ref, candidate commit, and a
GitHub-hosted runner. After protected publication approval, it reruns `stable-ga` before every
tag, Release, asset-upload, or finalization mutation and again before recording completion. Thus,
evidence, waivers, authorization, or targets that expire or change during a lengthy publication
attempt fail closed at the next mutation boundary.

The protected publication environment also supplies `STABLE_CATALOG_TRUSTED_KEYS_BASE64`, a
base64-encoded production trusted catalog public-key properties registry. The workflow uses it
only to verify freshly fetched primary, mirror, and rollback catalog signatures and deletes the
decoded file before job exit. It must not contain private signing keys and is never a manifest or
public artifact input. The retained rollback revision must verify under the catalog signing-key
identity frozen by the selected RC.

The native public output includes:

```text
stable-1.0-ga-validation.json
stable-1.0-ga-validation-authorization-identity.json
stable-1.0-ga-authorization-summary.json
stable-1.0-ga-promotion-summary.json
stable-1.0-ga-go-no-go.md
stable-1.0-ga-known-limitations.json
stable-1.0-ga-release-notes.md
stable-1.0-ga-publication-plan.json
stable-1.0-ga-publication-receipt.json
stable-1.0-ga-checksums.txt
stable-1.0-ga-provenance.json
stable-1.0-maintenance-baseline.json
```

The public checksum file names the six non-checksum Release assets. The checksum file is the
seventh planned asset and is itself bound by its size and digest in the publication plan,
provenance, and receipt. Internal validation, authorization, and redaction records are not added to
the public checksum rows because they are not public Release assets.

All seven planned assets must already exist at the independently populated `artifactBaseUri`
before a protected `publish=true` dispatch. The publication job verifies them immediately before
its first mutation and again after GitHub publication. The canonical publication receipt is
generated only when a returned publication result is independently verified. A
passing pre-publication run records `validated` or `publication-authorized`; it must not claim
`publication-complete`. Publication verification fetches every planned asset from both the GitHub
Release and its exact `artifactBaseUri + <asset-name>` public location. The receipt binds that base
and each asset's exact public URI, size, and digest, and rejects every unplanned or non-passing
asset row. See the
[Stable GA runbook](../../docs/stable-1.0-rc-validation-and-ga-promotion.md) for exact-RC selection,
24-hour validation, authorization, protected publication, conflict recovery, catalog verification,
receipt semantics, and the post-1.0 maintenance baseline.

Nested operations use nested component names, for example `multi-node-beta/run/` and
`security-response/drill-run-all/`. JSON and Markdown artifact references are relative to the run
root. The common `summary.json`, `report.md`, and `redaction-report.json` are the public component
surface. Component-specific engine output remains below `artifacts/legacy/`; extracted reusable
inputs remain below `artifacts/inputs/`.

A manifest with `output.reset=true` may replace only a directory containing a matching run marker.
The command rejects unmarked directories and markers for another release, version, or profile.
This prevents a misspelled output path from deleting source-controlled files and prevents stale
candidate evidence from being silently reused.

When `execution.collectEvidence=true`, every internally collected component is deleted and rebuilt
before aggregation, even when `output.reset=false`. To reuse evidence intentionally, provide it
through the corresponding `inputs` field; the adapter then applies that evidence type's identity,
status, freshness, and redaction validation instead of treating an interrupted component as a
cache.
Before replacing an internally collected component, every path segment is checked for symlinks and
workspace confinement so cleanup cannot follow an intermediate link into another component.
Nested legacy-engine output directories are checked before and after creation so a restored or
tampered `artifacts/legacy` symlink cannot redirect engine writes outside the marked run.
The shared JSON and text writers also reject symlinked file targets. Extracted-input directories,
security-drill sidecars, and production output staging receive the same resolved-path confinement
checks before a write or cleanup.
When an aggregate `release-certification/summary.json` already exists, recollection is rejected
before any component is deleted or rebuilt; use `output.reset=true` for a complete rerun.

## Evidence envelope v2

Every `summary.json` follows `schemas/evidence-envelope-v2.schema.json`. The common envelope
contains:

- `subject`: release ID, version, profile, and component;
- `result`: normalized `pass`, `warn`, or `fail`, a component decision, promotion readiness, and
  exit code;
- evidence, blocker, warning, and waiver counts;
- standard evidence rows, issues, and waiver records;
- a redaction result and non-secret guarantees;
- relative input and artifact references;
- component-specific data under `payload`.

Consumers validate every required envelope field, nested field type, evidence kind, candidate
identity, profile compatibility, component identity, declared version, array count, result
consistency, and redaction status before unwrapping `payload.legacy`. Strict profiles reject
evidence produced by PR, nightly, or developer-dry-run policy. Stable review may consume the
production-beta evidence it evaluates, and release or production aggregation may consume an
explicit Stable-review summary; these are the only cross-profile input transitions.
For `release-candidate`, `production-beta`, and `stable-review`, an attached v2 input also requires
a non-null manifest `release.version`. The adapter rejects the input instead of treating an absent
expected version as a wildcard.
Relative and absolute manifest inputs are resolved against the workspace before publication and
rendered only as `<repo>/...` or `<external-input>`. A component process with a nonzero exit always
produces failed evidence; `pass` and `warn` envelopes require `exitCode: 0`.
Legacy outputs without native redaction metadata pass only after a complete payload scan; malformed
metadata, scan findings, or false direct/nested guarantees fail the envelope. Production-beta
envelopes expose the final nested `goNoGo.decision` through the common `result.decision` field.
Negative live-network safety facts such as `rawBodiesStored: false` are converted to positive v2
guarantees such as `rawBodiesNotStored: true`; an unsafe true value still fails closed.
Migration and fallback scans inspect nested JSON field names as well as values, rejecting
payload-bearing password, token, key, private-URI, raw-body, and raw-app-data fields. They also
reject POSIX, Windows drive, and UNC absolute filesystem paths outside the documented public route
shapes before any migrated artifact or envelope is written. Canonical sanitized
`<repo>/relative/path` values are allowed so existing release-certification history can migrate;
malformed, traversing, mixed, or backslash-bearing placeholders remain blocked.
Each unified component input has one expected v2 kind and rejects raw v1 summaries as well as v2
envelopes of another kind. Explicit external or non-envelope inputs—interop, performance,
ecosystem matrix, and third-party intake—retain their native JSON contracts, and their input slots
reject v2 envelopes instead of accepting an arbitrary kind.
Non-migration policy consumers may inspect `warn` evidence with
passing redaction so Stable waiver evaluation can run. Failed results and failed redaction remain
rejected, and migrated previous-candidate/history evidence remains pass-only. Reused
`inputs.securityDrills` envelopes also restore the referenced public drill JSON files beside the
extracted legacy summary so downstream digest and scenario validation sees the same complete
artifact set that the v2 producer published. Every referenced drill sidecar is parsed, scanned,
and checked against its recorded digest before it is copied. The verification adapter copies from
the effective configured input directory, not from a previous internally generated drill run.

Attached v2 payloads are scanned before extraction even when their outer redaction record says
`pass`. Safety-labelled fields are exempt only when their value has the expected scalar, boolean,
or digest shape; containers are still traversed. Credential assignments, cookie or authorization
values, credential-bearing URLs, local `file:` URIs, filesystem roots, and labelled absolute paths
remain findings. Canonical sanitizer output such as `<repo>/...`, `<path>/python3`, relative app
assets, and public API routes remains reusable.

If an engine writes unsafe output, the adapter removes the raw legacy copies from the publishable
workspace and emits only sanitized failed evidence. Early engine `SystemExit`, nonzero exits, and
redaction failures all produce a failed common envelope with `promotionReady=false`. Common
normalization preserves production failure reasons as blockers and release-certification
`waiverRecords` as auditable v2 waivers.

## V1 history migration

Normal v2 consumers reject legacy release-certification summaries. Convert the previous beta
candidate once with:

```bash
python3 tools/release-certification/certify.py migrate-v1 previous-candidate \
  --manifest path/to/release-run.json
```

Set `inputs.previousCandidate` in the manifest. Use `migrate-v1 release-history` with
`inputs.releaseHistory` for the previous certification record. Migration validates the source
shape, release binding, status, and redaction state, records its SHA-256 digest, and writes the
converted artifact under the marked release workspace. It does not run automatically.

Redaction must use either an explicit passing status with an empty findings array or the older
recognized boolean-guarantee form with every recognized guarantee set to true; missing,
unrecognized, malformed, or contradictory redaction metadata is rejected.

For the subsequent certification or production run, point `inputs.previousCandidate` or
`inputs.releaseHistory` at the corresponding migration component’s v2 `summary.json`. Normal
adapters validate its candidate binding and redaction result, then extract the legacy payload into
the current component’s adapter area. They reject a raw v1 path.

The migration manifest and the consuming run manifest must use the same `release.id`. For a
protected production workflow dispatch, set `candidate_release_id` to that value. Do not use a
workflow run number as the candidate identity because the migration artifacts must be prepared
before the consuming workflow starts.
The release workflows derive `release.version` from `./gradlew -q printVersion`. Bind migrated and
attached v2 evidence to that checked-out build version; a matching release ID does not authorize
evidence for another build version.
For a release-certification workflow dispatch, set `candidate-release-id` whenever
`previous-summary-path` is supplied; the workflow rejects migrated history without its bound
candidate identity. The same explicit identity is required for any attached candidate-bound v2
multi-node, security-drill, or Stable-readiness summary, even when the corresponding gate is
optional.

Migration output is immutable within a completed marked workspace. A second migration for the
same release and kind is rejected when `output.reset=false`; use an explicit matching reset to
replace the candidate-bound record and its source digest.

## Release history output

Set `execution.writeHistory=true` to archive a completed certification result. Unless
`policies.historyDir` is set, the legacy aggregator keeps its shared default at
`build/release-certification-history/`, outside the per-candidate run root. Passing runs update
`latest-summary.json`, `latest-history-comparison.json`, and
`releases/<history-label>/`; failed candidates are retained under `failed/<history-label>/`
without replacing the last passing summary. Set `policies.historyLabel` when the release label
cannot be derived safely. The release-certification workflow uploads both the candidate workspace
and this shared history directory.

## Failure and redaction policy

Release-candidate, production-beta, and Stable review modes remain fail closed. Missing, stale,
malformed, wrong-candidate, skipped, fixture-only, or redaction-unsafe required evidence cannot
promote a release unless the existing policy explicitly permits a valid waiver.
Requirements are evaluated by the gate engine rather than treated as manifest dependencies. In
particular, `requirements.history=true` without `inputs.releaseHistory` is valid configuration and
records the missing mandatory history in the certification report; release-candidate policy fails
the aggregate and blocks promotion.

Redaction findings involving private insert URIs, private keys, signing material, form passwords,
tokens, cookies, authorization headers, raw fetched content, raw app data, identity material,
browser sessions, local absolute paths, unsafe archives, symlinks, or special files remain
non-waivable. Do not publish private interop insert material or raw live-node fixtures.

## CI

The multi-OS CI job runs:

```bash
python3 tools/release-certification/certify.py self-test all
```

The characterization suite runs on Ubuntu, macOS, and Windows with Python 3.12. Ubuntu and macOS
retain a 30-minute job limit; Windows has a 60-minute limit because the same subprocess-heavy
scenarios run materially slower there. Integration assertions compare canonical paths so macOS
aliases such as `/var` and Windows temporary-directory aliases do not create false failures.

Release workflows generate their runtime manifest with `jq` from workflow-dispatch inputs. Secret
values remain in protected environment variables or files and are never serialized into the
manifest or uploaded workspace.

`.github/workflows/stable-1.0-rc-release.yml` is manual and protected. It requires an explicit
candidate release ID and integer build, JDK 25, a clean candidate commit, production
signing/reviewer material, full build/stage/sign/verify, and real live, sandbox, multi-node,
previous-candidate, network-scale, security-drill, third-party-intake, and catalog-operations
evidence. It verifies the post-package freeze, checksums, archive hygiene, final v2 redaction, and
`go`/`go-with-waivers` result before uploading only the public RC component. It does not tag,
release, merge, or publish Stable 1.0 GA.

`.github/workflows/stable-1.0-ga-promotion.yml` keeps validation, protected evidence attestation,
and publication in separate jobs. The validation job authenticates the latest protected Stable RC
run and has no tag or GitHub Release permission. Protected HTTPS acquisition rejects redirects,
URL credentials, query strings, fragments, non-public DNS results, and local/private targets;
repository and Actions-artifact inputs remain path-confined and reject symlinks and special files.
The evidence job requires `stable-1-0-ga-evidence` approval and attests the exact validation,
authorization, and canonical publication-target identity bytes. The publication job requires an
explicit dispatch selection, passing validation, prior evidence attestations, and approval in the
`stable-1-0-ga` environment. It reruns
the gate at every publication mutation boundary, holds the global vulnerability-ledger lock after
its current nonblocking handoff check, uses the required `leumor` GitHub identity,
creates or verifies the annotated `v<build-number>` tag and exact GitHub Release assets, fetches the
same assets from the declared artifact base, and verifies the unchanged stable catalog at the
primary, mirrors, and authorized rollback URI. It never merges a release branch automatically.
Matching existing public state is idempotent only after a fresh latest-RC lineage query;
conflicting state fails closed. The failure audit path is read-only and uploads a sanitized failed
receipt even when no side-effect marker or GitHub Release exists. Recovery distinguishes an
observed absence from an unavailable GitHub observation and records only counts and SHA-256
identifiers for unplanned remote asset names. The receipt must pass its closed schema, placeholder,
and redaction checks before upload. Only a verified publication receipt may record
`publication-complete`.

The Stable RC and Stable GA workflows share one integer-build concurrency group across validation,
protected approval waits, and publication. Cancel a waiting GA run before an urgent refreeze and
inspect the shared build queue, because GitHub retains at most one pending run for the group. During
publication the workflow also rereads `release/<build-number>` at every side-effect boundary,
before creating a tag reference from a newly created tag object, and before accepting idempotent or
new public state as `publication-complete`.

Follow the [production security response runbook](../../docs/production-security-response-runbook.md)
when collecting release-blocking drill evidence or responding to an app ecosystem incident.

## Stable 1.0 backport and release-train certification

Use `stable-backport` before `stable-maintenance` to govern the exact contents of one routine or
security-hotfix candidate:

```bash
python3 tools/release-certification/certify.py stable-backport \
  --manifest build/stable-1.0-backport.json
```

The component has four side-effect-free modes:

- `evaluate` validates intake, policy, lifecycle coverage, prior queue state, and proposed
  dispositions before any accepted fix is required to be landed;
- `prepare-candidate` binds the exact candidate, source-to-candidate provenance, evidence, and
  complete commit/change coverage;
- `validate-authorization` validates a narrow authorization for the exact train composition and
  candidate handoff;
- `verify-release-completion` authenticates publication, lifecycle activation or an explicit
  pending state, and no-squash `--no-ff` reconciliation into `main` and `develop`.

The candidate may advance between `evaluate` and `prepare-candidate` while approved fixes are
landed. Candidate equality is frozen from `prepare-candidate` through authorization, maintenance,
and completion; it is not required for the pre-landing evaluation handoff.

The versioned policy closes classifications, dispositions, states, provenance modes, deadlines,
roles, Git object rules, queue bounds, evidence windows, redaction, and non-waivable blockers. The
two release lanes are `routine-maintenance` and `security-hotfix`; `future-milestone`, `deferred`,
and `rejected` keep ineligible or unscheduled work outside a Stable candidate.

Git evidence uses full canonical commit object ids and verified object graph operations. It rejects
abbreviations, symbolic revision syntax, wrong repositories, spoofed branch roles, wrong bases,
parallel predecessors, patch-id misuse, missing candidate ancestry, and incomplete manual conflict
evidence. Routine manifests carry `policies.developmentLineageCommit`: the protected workflow
resolves and freezes the exact protected `develop` tip independently of `candidateBaseCommit`,
then the engine requires the declared base to be the exact candidate/lineage merge base and a
member of that protected tip's first-parent chain. A merged side-parent tip is not an authenticated
`develop` base. Patch
identity supports a reviewed `clean-cherry-pick`; it never authorizes one.
Clean cherry-pick and manual-conflict records also require an exact
`stableBackportReviewAuthorizations` protected input. Each row comes from the successful
`.github/workflows/stable-1.0-backport-review-authorization.yml` producer in the
`stable-1.0-backport-review` environment and binds the reviewer role, policy, source,
predecessor, candidate, normalized diff, path inventory, focused tests, validity interval, run,
workflow, and artifact. Matching caller-provided digests without that producer artifact fail.
Security-hotfix manifests instead carry `policies.mainLineageCommit`, independently resolved from
the exact protected `main` tip. The hotfix base must equal that tip, while the tagged publication
predecessor must remain its ancestor; branching directly from the predecessor cannot omit a later
`main` reconciliation merge or its resolution.

The queue is append-only and digest chained. It carries unresolved accepted fixes, deferred and
rejected history, superseding relationships, critical obligations, hotfix follow-up, and prior
merge-back obligations. Candidate coverage assigns every commit or change to an accepted fix,
approved release metadata/tooling/docs, explained merge context, or `unaccounted`; any
`unaccounted` entry blocks the train.

Each evidence row carries the exact reviewed policy and queue digests. The queue digest normalizes
only its embedded evidence queue-binding slots before hashing, which provides deterministic
self-binding without excluding the evidence content or any other queue field. Policy-designated
protected evidence must remain `visibility: protected`.

Landed fix provenance is immutable. Resolving a carried obligation requires a new evidence digest,
and both that digest and its resolution timestamp are immutable after resolution.
Security incident/advisory identity and severity are immutable across queue snapshots. A disposition
or lane change must be explained by an appended state transition, which prevents a critical
security record from being relabeled as noncritical routine work.

GA is the sole queue genesis. A later maintenance successor must provide both
`previousStableBackportQueue` and `previousStableBackportValidation`; the published successor
baseline authenticates the validation file digest, and that validation binds the exact queue
digest and predecessor commit. Critical 4/8/12-hour response windows are computed from state
transition timestamps, not from a caller-selected final deadline. An expired critical deferral
review remains blocking. Rejecting a critical record does not remove it from the blocker index;
an append-only authorized `rejected`-to-`triaged` transition reopens investigation without
rewriting that history. The record remains critical and blocking throughout re-triage.
superseding one requires a critical replacement with the same incident, advisory, and affected
scope.

Every accepted `security-hotfix` row is a critical `security-fix` under one incident/advisory pair;
package, app, or tooling effects are recorded in the security fix’s affected scope and evidence,
not as unrelated ordinary rows. A superseding hotfix may carry one publication-created follow-up
even when it was not present in the prior authorized train queue: the first queue projection must
bind the authenticated predecessor baseline’s exact open/overdue obligation digest, build/train and
generation time to the prior queue’s critical source fixes. Subsequent queues inherit it unchanged.
An authenticated overdue high PR-288 blocker remains on `routine-maintenance` and may proceed only
when every blocking case is present in the train's accepted fix scope with the exact severity and
vulnerability public-projection digest. This scoped remediation rule does not let an unrelated
high blocker pass and does not move a critical case out of `security-hotfix`.

A new transition to `released` is valid only from an authenticated prior queue and with the exact
`previousStableBackportCompletion` artifact. The fix transition and its
`stable-backport.release-completion` evidence row both bind that artifact's file digest, train,
queue, and candidate identity. The immutable per-fix provenance commit must be an ancestor of the
publication tip; it is not required to equal that tip. The intake snapshot, completion-evidence
row, and final state transition must be timestamped no earlier than the authenticated maintenance
publication receipt, completion artifact, and protected completion handoff. Backdating any of
those events cannot make a later train authorization appear to postdate publication.
Every fix included by the prior authorized validation must complete this released-state proof
before it can be superseded.
When an otherwise authenticated reconciliation merge contains non-automatic content, strict Git
inspection does not certify that content as reconciled. Completion instead derives the exact
policy-named blocker, marks `reconciliationStatus: content-review-required`, and binds its evidence
digest to the merge record and bounded resolution-path digest. The next intake must seed that exact
completion-created obligation before moving the published fixes to `released`; its queue remains
blocked pending separately authenticated content-review evidence. Other Git, parent, branch-tip,
or attestation failures still produce no completion artifact.
The successor also requires `previousStableBackportCompletionHandoff`. The protected workflow
creates this record only after authenticating the successful prior completion run and exact
Actions artifact, byte-comparing its completion and validation, resolving current protected
`main`/`develop`, and proving both merge commits remain on their first-parent chains.

Stable 1.0 remains one successor chain. Historical `supported-maintenance`,
`security-fixes-only`, or `deprecated` builds are upgrade/advisory coverage sources.
`end-of-support` and `revoked` builds are recovery sources only when policy explicitly permits it.
They are never mutable release targets or parallel LTS branches.

Every train re-authenticates the full existing GA promotion, validation, authorization-summary,
publication-plan, receipt, checksums, provenance, and maintenance-baseline bundle as its immutable
root. For the first post-GA train, the exact authenticated GA baseline and publication receipt are
the predecessor and `latestPublishedMaintenancePointer` must be absent. Every later train requires
that input and verifies that it selects the exact immediate maintenance predecessor. This matches
the existing `stable-maintenance` genesis/no-fork invariant.
The lifecycle authority input also includes a fresh public observation receipt bound to the exact
descriptor edition, descriptor bytes, ledger, publication plan, update-key scope, and prior
authorization. Train authorization must be issued no earlier than that observation or any state,
evidence, obligation, or intake event it approves.
The checked-in `stable-1.0-backport.example.json` deliberately models only that first post-GA
shape. Replace its complete predecessor identity—integer build, release id, and product
digest—before use. A later successor must add `latestPublishedMaintenancePointer`,
`previousStableBackportQueue`, and `previousStableBackportValidation`; copying the genesis shape
unchanged is rejected.

When an authenticated `hotfixFollowUpClosure` closes the predecessor's publication-created
shortened-window follow-up, the backport command uses the maintenance authority's closure-adjusted
predecessor state. Its protected queue, candidate, lineage, and validation bind the closure digest
so the next routine train can proceed without mutating the published baseline; the public
validation omits that protected digest, and train authorization cannot predate the closure.

Successful applicable modes write the canonical intake, plan, lineage, authoritative queue,
public queue projection, candidate,
authoritative validation, filtered public validation, authorization summary, optional completion,
train summary/report, checksums,
provenance, redaction, and component summary records below
`build/release-certification/<release-id>/stable-backport/`. Failure does not manufacture
placeholder success artifacts.

The authorization-summary filename contains the complete schema-validated train authorization.
The protected `validate-authorization` envelope contains that exact file together with the exact
train validation. `stable-maintenance` requires both manifest inputs, recomputes their complete
binding, and the protected maintenance workflow resolves the source run, workflow, candidate,
artifact name, and Actions artifact digest from the manifest’s
`stableBackportRunId`, `stableBackportArtifactName`, and
`stableBackportArtifactDigest` metadata. Producer copies must match the authenticated artifact
byte-for-byte. Maintenance then reseals those two authoritative files for every freeze,
preparation, validation, publication, and independent-verification handoff. Repository-readable
maintenance artifacts contain the encrypted envelope and no plaintext duplicate under either
`authenticated-inputs` or staged `protected-inputs`. Train `candidateDigest` is the candidate JSON
file digest and is intentionally not the maintenance candidate’s separate semantic
`candidateIdentityDigest`.

The protected `.github/workflows/stable-1.0-backport-release-train.yml` workflow maps
`evaluate-intake`, `prepare-candidate`, `validate-authorization`, and
`verify-release-completion` to those command modes. It binds an exact checkout and reviewed input
digest, runs with a read-only token, and separates the exact protected handoff from an allowlisted
public-safe projection. It
does not create or modify branches, commits, tags, pull requests, releases, catalogs, update
descriptors, or lifecycle state.

The authoritative `stable-1.0-release-train-queue.json` remains inside the protected component
and input chain. The workflow uploads two distinct artifacts: an authenticated encrypted envelope
for the next protected phase or maintenance consumer, and an allowlisted public artifact. The
latter contains
`stable-1.0-release-train-queue-public.json` and
`stable-1.0-release-train-validation-public.json`, not the authoritative queue, full validation,
authorization record, completion record, predecessor-completion handoff, or internal
checksums/provenance. The public schemas exclude touched/conflict paths, protected evidence ids
and digests, private-record digests, and exact per-fix source/backport internals while retaining
digest-bound public disposition, decision, and status projections.

Each non-initial phase resolves and downloads the exact prior Actions artifact and authenticates
its run, workflow, commit, operation, run attempt, digest, and encrypted-envelope binding before
decrypting the checksums, provenance, queue, and validation inside a protected environment. Use
the same canonical base64 32-byte
`CRYPTAD_STABLE_BACKPORT_HANDOFF_KEY_BASE64` secret in the protected backport-review,
backport-evidence, backport-authorization, maintenance-evidence,
`stable-1.0-maintenance-publication`, and
`stable-1.0-security-hotfix-publication` environments. Never expose that key in an input,
variable, log, summary, or artifact, and retain required plaintext records only in the separately
access-controlled support-lifetime input archive. The
completion phase uses that downloaded validation as `stableBackportFrozenValidation`. It also
supports a support-lifetime predecessor-completion reauthentication path: the protected input
bundle retains the exact completion, validation, authoritative queue, receipt, and lifecycle
authority after Actions retention expires. A new protected evaluation rechecks that digest-pinned
bundle and the current protected `main` and `develop` first-parent histories, then emits the exact
handoff consumed by later phases. Supplying an unexpired completion artifact remains an optional
byte-comparison fast path.

The release-train candidate-handoff authorization is bounded to 72 hours. That covers the required
24-hour post-freeze routine-maintenance soak plus up to 48 hours for evidence review and handoff;
it remains separate from, and never substitutes for, maintenance publication authorization.
The protected publisher requires that grant to have been current at the exact
maintenance-authorization handoff frozen into the bundle. It does not re-age that composition-only
grant against each later publication target or retry. Candidate evidence freshness and the separate
maintenance publication/activation authorizations retain their existing current-time checks.

The evaluate-to-prepare handoff is deliberately different from the later frozen-candidate
handoffs: the candidate may advance while approved fixes are landed, but the evaluated composition
may not be exchanged. The public queue contains a digest commitment to the protected immutable
fix/obligation composition and opaque transition digests. `prepare-candidate` requires the same
fix and obligation identities, the same composition commitment, and prefix-only state-transition
evolution. The obligation commitment includes its exact source train and source-fix identities;
otherwise rerun `evaluate-intake`.
The workflow resolves the protected `main` and `develop` tips and binds their exact reachability
evidence.
Routine phase provenance carries the frozen protected-development commit; a later phase rejects
the handoff if that commit is no longer reachable from the live protected `develop` tip.
Completion fetches the exact GitHub-API-selected protected-tip commit identities from the canonical
origin before checking their local object types and ancestry, so a protected branch advancing
after checkout does not create a false missing-object failure.

Completion verifies separate no-ff merges of the same published release/hotfix candidate into
`main` and `develop`; the `develop` merge does not name the `main` merge commit as its merged tip.
Because completion is read-only proof over the already published train digest, it may run after
the original candidate-handoff authorization expires. The receipt-bound frozen validation is
replayed at authorization issuance rather than re-aging candidate evidence against completion
time.

Authorization projections preserve the exact schema-valid `expiresAt` text from the full
authorization, including fractional seconds or an explicit UTC offset.
Protected provenance-review authorization uses an exclusive expiry boundary: it is invalid when
the captured validation time equals `expiresAt`.

See the [backport and release-train
runbook](../../docs/stable-1.0-backport-and-release-train-governance.md) for the full fix model,
Git provenance contract, security projection, maintenance integration, release-note behavior, and
manual operations.

## Stable 1.0 supply-chain and reproducible-build certification

Create a local Gradle resolution export for review:

```bash
./gradlew exportStableSupplyChainResolution
```

The exporter writes `build/stable-supply-chain/resolved-dependency-snapshot.json`,
`build/stable-supply-chain/resolved-dependency-export.json`, and
`build/stable-supply-chain/build-material-inputs.json`. The snapshot is the canonical selected
component, variant, edge, and artifact view for the policy-selected configurations. The raw export
retains the complete reviewed resolution projection. Build materials record source, wrapper,
toolchain, repository policy, external input, and build-recipe identities.

The export builds the jlink image and derives its module list from that generated runtime's
`java --list-modules` output, not only the requested `jdeps` roots. It also fingerprints the exact
Gradle-selected JDK installation with the policy's path-independent installed-tree algorithm. The
final material record contains distinct Linux, macOS, and Windows installation rows, and each
protected builder must independently observe the matching row before any product task. A local
system JDK whose tree contains escaping or absolute external symlinks is deliberately unsuitable
for this protected fingerprint and causes the exporter to fail closed.

Protected inventory, producer, and verifier runs authenticate exact files named
`resolved-dependency-export.json` and `resolved-dependency-snapshot.json` in the phase bundle before
running the strict comparison:

```bash
./gradlew exportStableSupplyChainResolution verifyStableSupplyChainResolution \
  -PstableSupplyChainExpectedResolutionExport=build/stable-supply-chain-phase/resolved-dependency-export.json \
  -PstableSupplyChainExpectedResolutionSnapshot=build/stable-supply-chain-phase/resolved-dependency-snapshot.json
```

Both expected paths must remain confined to the attested phase artifact. Aliases, unreferenced
files, links, and generated-output substitutions fail. The default no-property export is
intentionally unlocked and is not strict verification by itself.

The policy also closes direct build inputs to five named materials: the Gradle distribution,
seedrefs source archive, Tanuki wrapper delta pack, and the AMD64 and ARM64 Windows wrappers. The
wrapper checksum is pinned in `gradle-wrapper.properties`; protected jobs supply reviewed SHA-256
values for the other four Gradle downloads, verify before extraction, and bind the same identities
to final `packagingInputs` plus both authenticated builder receipts. Missing or drifting direct
material remains promotion-blocking.

The generated `build-material-inputs.json` has the raw
`cryptad-stable-build-material-inputs-v1` contract. It is not the final
`stable-1.0-build-materials-v1` manifest input and cannot replace it. The manifest's
`inputs.buildMaterials` path remains confined to the attested phase bundle. Inventory execution
cross-checks the raw export and Gradle/material digests across the generated document, reviewed
snapshot, and final build-material record, then retains the raw document as separately named
attested workflow evidence. Only the final record occupies the public `build-materials` role.

Use `tools/release-certification/stable-1.0-supply-chain-policy.json` as the checked-in policy and
`tools/release-certification/stable-1.0-supply-chain-license-overrides.json` as the checked-in
override set. The exact release-subject inventory is release-specific and must come from the
authenticated phase bundle path named in the manifest; it is not a checked-in template or a local
discovery result.

Each policy subject has an `evidencePhase`. Builder receipts and comparison records cover exactly
the selected `independent-builder` subjects: core, portable/runtime archives, native installers,
and seven app bundles. Frozen catalog/signature/updater bytes are `authenticated-post-build`: they
retain exact byte and freeze-signature bindings but are not claimed as independently reproduced by
the current Gradle recipe. Review/release/supply-chain records are `derived-governance` and
`not-a-product-subject`; their exact bytes are bound by inventory, promotion, and immutable
publication evidence instead of builder assertions.

The current native-installer builder matrix is closed to AMD64 DEB, RPM, DMG, and EXE subjects.
Flatpak and Snap remain valid maintenance package-format vocabulary, but are not authorized by the
current supply-chain policy. Selecting either format requires a future reviewed policy edition
that also introduces its isolated build, safe extraction, and normalized comparison evidence.

Set `inputs.licenseTextRoot` to the repository root, `.`. License registries may reference only the
root `LICENSE` or regular files below `docs/licenses/`; the broader root is a resolution anchor and
does not make arbitrary repository files eligible notice evidence.

Run one side-effect-free phase with a candidate-bound `stable-review` manifest:

```bash
python3 tools/release-certification/certify.py stable-supply-chain \
  --manifest build/stable-supply-chain-phase.json
```

`commands.stable-supply-chain.mode` is closed to `assemble-inventory`, `verify-inventory`,
`prepare-rebuild-comparison`, `compare-rebuilds`, `evaluate-promotion`, and
`verify-publication`. Each mode accepts exactly its declared `inputs` set; a caller cannot attach
an irrelevant earlier-phase file to cross a trust boundary. Native component, license, SBOM,
binding, build-material, builder, comparison, reverse-index, promotion, and publication-verification
records are written under
`build/release-certification/<release-id>/stable-supply-chain/artifacts/legacy/`. The common
candidate-bound summary, report, and redaction result remain at the component root.

`evaluate-promotion` requires `execution.evaluationClock` and the fixed-name authenticated
`stable-1.0-vulnerability-summary.json` handoff. The existing protected handoff verifier checks
the sealed producer bytes, provenance, summary expiry, and current durable vulnerability-ledger
tip; a raw JSON path is not promotion authority. Vulnerability ledgers that contain a
`runtime-component` scope likewise require `componentReverseIndex` in every later protected
phase. The current reverse index must match the manifest's authenticated full candidate commit and
immutable `commit:<sha>` source ref, and every newly resolved alias must map to the candidate build.
Historical scope rows retain their original inventory digest; this current-candidate routing check
does not retroactively rebind them. Historical ledgers with no such scope remain valid without that
irrelevant input.

Its promotion summary is a prepublication gate. Every non-publication evidence row must pass, but
`stable-supply-chain.publication` must not be reported as passing by `evaluate-promotion`; only
`verify-publication` can establish that row from the exact receipt and fresh public observation.
Downstream maintenance and generic release certification also require the sibling
`stable-1.0-supply-chain-summary-provenance.json`. That bounded record binds the summary byte
digest to the exact successful protected supply-chain workflow run/attempt, fixed comparison
artifact name, Actions artifact digest, candidate source commit, and verified attestation. A local
summary plus its own semantic digest is not release authority. After those GitHub and attestation
checks, the protected producer adds a domain-separated HMAC-SHA256 tag using the dedicated
`CRYPTAD_STABLE_SUPPLY_CHAIN_HANDOFF_KEY_BASE64` secret. Consumers require that tag and compare the
summary's `sourceCommit` and immutable `commit:<sha>` source ref with a direct read of the current
checkout; provenance booleans, caller-supplied metadata, and a stale genuine summary are
insufficient.

The protected `.github/workflows/stable-1.0-supply-chain.yml` workflow is manual-only. Its closed
orchestration operations are `inventory`, `producer-build`, `verifier-build`,
`compare-evaluate`, `publish`, and `verify-publication`. Producer and verifier jobs have isolated
workspaces; the verifier authenticates only the closed recipe and reviewed resolution expectation
files before its Java 25 wrapper build, then digests its own subjects while producer candidate
bytes remain unavailable. Every handoff is authenticated against the exact repository,
workflow path, protected source ref, source commit, run attempt, artifact name, artifact digest,
and file attestations.

Each producer or verifier run has four authenticated executions: `portable-apps`,
`linux-installers`, `macos-installer`, and `windows-installer`. The aggregate preserves the exact
runner-image, job, subject-partition, handoff, and attestation identities for all four; it does not
flatten platform provenance. `compare-evaluate` additionally requires the original producer and
verifier run/attempt/artifact/digest coordinates, downloads both originals directly, and derives
the formal receipts from their verified file attestations. For `evaluate-promotion`, the fixed
Stable vulnerability summary is opened and current-tip verified outside the checkout and public
output roots before the CLI runs.

Both roles receive the same product-byte-free five-input recipe plus the reviewed raw resolution
export before building. The recipe contains no builder receipt; the comparison job derives both
receipts only after authenticating the original completed builder artifacts. Per-execution
receipts bind Java, Gradle, verification, plugin/build-logic, task-set, canonical environment,
direct-input, payload-manifest-set, and extraction-manifest-set identities. Native package jobs
extract the actual DEB/RPM/DMG/EXE container, canonicalize the complete installed tree without
ignored files, and require one embedded app-image root to equal the pre-signing stage. The distinct
attested extraction record binds package, extractor, full extracted, embedded staged, and
candidate freeze signing/notarization identities. Unsupported layouts, unavailable tools, and
policy-bound expansion overflows fail closed.

For `producer-build`, candidate bytes are not downloaded until the local build has completed. The
workflow then authenticates the existing maintenance `freeze-candidate` run and the exact
run/attempt-bound `stable-1-0-maintenance-frozen-...` artifact. The closed freeze record and every
attested `freeze/assets` entry must agree with the subject inventory by canonical filename,
digest, size, signing receipt, and notarization receipt. Frozen bytes are used wherever that
maintenance freeze selected a subject; non-selected deterministic companions must still match the
authenticated inventory exactly.

Developer-ID-signed/notarized DMGs use the closed `macos-code-signature-normalized` view. The
producer authenticates the frozen DMG, signing and notarization receipts, signed mounted app, and
signature-material inventory; the verifier authenticates its independently built unsigned app.
Their role-specific `extractionManifestSetDigest` values intentionally differ. Equality is required
for the role-neutral `payloadManifestSetDigest`, normalized pre-signing payload, non-code entries,
package metadata, normalization rule/version, and empty ignored-path set. Any unaccounted code or
non-code payload difference remains a release blocker; signatures are accounted for, not stripped
from the publication identity.

The command-line component never creates a tag or GitHub Release, uploads a public SBOM, changes a
catalog, or publishes CoreUpdater state. The separate `publish` workflow job runs only in the
protected supply-chain publication environment and is the only supply-chain job with job-scoped
`contents: write`. It authenticates the exact promotion bundle, annotated tag, existing Release,
input attestations, and reviewed publication-backend wheel before it verifies the
`LEUMOR_GITHUB_TOKEN` identity as exactly `leumor`. Secrets are supplied through the step
environment, never interpolated into command-line arguments.

The fixed `cryptad_stable_maintenance_backend:supply_chain_factory` entry point accepts only the
eight policy roles—`build-materials`, `component-inventory`, `component-reverse-index`,
`license-inventory`, `release-subject-inventory`, `reproducibility-report`, `sbom`, and
`supply-chain-summary`. It records absent assets as `created`, accepts exact existing assets as
`verified-existing`, and never deletes or overwrites a conflict. It immediately re-observes the
eight public byte streams and emits the receipt and fresh observation in an attested immutable
handoff. `verify-publication` consumes that handoff without a publication credential and performs
no mutation. Report publication or reproducibility only when those exact records pass; a local
inventory or one successful build is informational.

The side-effect-free verifier derives all eight filenames and their
`https://github.com/crypta-network/cryptad/releases/download/v<build>/` targets from the reviewed
policy. Self-consistent plan, receipt, and observation records at any other HTTPS location fail.

See [Stable 1.0 supply-chain inventory and reproducible-build
governance](../../docs/stable-1.0-supply-chain-inventory-and-reproducible-build-governance.md) for
the authority model, component roles, app/catalog coverage, license rules, vulnerability reverse
index, redaction boundary, and external-verification procedure.

Provider-distinct verification is a separate layer around this same comparison authority. Run
`stable-independent-reproducibility` in the closed `prepare-verifier-kit`,
`verify-external-receipt`, `compare`, or `closeout` mode. The checked-in fixture and generic OIDC
template are non-operational; repository implementation or self-tests cannot complete the gate.
Operational success requires a concrete reviewed profile and real adapter verification of the raw
DSSE/Sigstore bundle and bounded verification transcript. The protected coordinator accepts all
six sealed external core files before it can download primary or selected-RC evidence. The
checked-in operational external-adapter allowlist is empty; changing a policy flag or supplying a
self-asserted transcript cannot complete the gate. See
[Stable 1.0 independent reproducible-build
verification](../../docs/stable-1.0-independent-reproducible-build-verification.md).

## Stable 1.0 federated catalog trust

Run the focused offline contract suite with:

```bash
python3 tools/release-certification/certify.py stable-federated-catalog --self-test
python3 tools/release-certification/certify.py stable-federated-catalog --help
```

The command has six closed modes: `preflight`, `verify-discovery`, `verify-local-trust`,
`verify-conflicts`, `verify-runtime`, and `closeout`. It verifies exact bounded evidence already
present beneath the workspace. It does not fetch descriptors, alter node trust, contact a runtime
node, install or update an app, publish a catalog, or mutate GitHub.

Discovery descriptors and endorsements are separate signed public formats. Descriptor import is
pending evidence only. Their certification schemas are the exact nested runtime wire formats, and
the execution contract separately binds the locally approved issuer SPKI used for verification.
The closed endorsement format has no transitive-trust or trust-creation field; neither format
installs a key, adds a source, authorizes a publisher/reviewer, or selects an app. The
signed runtime observation proves the bounded local properties: at least three catalog identities,
distinct local bindings, scoped catalog/publisher/reviewer policy digests, deliberate duplicate
and hard conflicts, disabled lexical tie-breaking, strongest security blocks, pinned origin,
explicit source/publisher switch consent, exact rollback origin restoration, isolated catalog
revocation, privacy-safe discovery, redacted support output, and complete cleanup.

`closeout` additionally requires exact successful PR-291, PR-292, PR-293, and PR-294 protected
artifact coordinates. Its runtime receipt must come from the exact successful attempt of
`stable-1.0-federated-catalog-runtime.yml`: the protected runtime-observation environment selects
the reviewed adapter digest and observer identity, the workflow publishes distinct immutable
observation and signed-receipt artifacts, and the evidence producer authenticates both before it
uploads the confined aggregate. A public key embedded only in a caller-authored receipt is not an
observer authority. Fixtures and self-tests can reach only `fixture-verification-complete`.
Fixture-, sample-, template-, and test-shaped identities cannot become operational merely by
changing classification flags. Missing, stale, substituted, partial, or unredacted evidence emits
bounded blockers and never reports operational completion.

See [Federated catalog discovery and local
trust](../../docs/stable-1.0-federated-catalog-discovery-and-trust.md) for the trust model,
certification contract, privacy boundary, state machine, and operational prerequisites.

## Platform API 1.x compatibility operations

Run the focused offline authority suite with:

```bash
python3 tools/release-certification/certify.py stable-platform-api-1x --self-test
python3 tools/release-certification/certify.py stable-platform-api-1x --help
```

The seven closed modes verify preflight, append-only contract history, a conditionally required
future-baseline proposal, descriptor graduation records, a monotonic deprecation ledger, the static
cross-release app matrix, an optional bounded runtime observation, and closeout. Exact inputs use
the closed `platform-api-1.x-*-v1` schemas and the checked-in compatibility policy. The example
execution contract is fixture-only and cannot produce operational completion. History verification
parses the real contract-envelope shape, recomputes its compatibility-window digest, validates the
complete named-baseline registry and its self-digested lifecycle, and binds the current history
head to the exact registry artifact bytes. Operational history additionally requires the exact
selected RC freeze authenticated by both PR-291 and PR-292: their selected-RC coordinates must
agree, and the freeze byte/content digests, product root, release/build/source identity, contract
version, and contract-snapshot digest must match the head. Proposal membership, graduation
descriptor semantics, and matrix verdicts are recomputed from the accepted registry and
digest-bound history snapshots; producer assertions do not substitute for those checks.

Production matrix verification also requires the closed app-subject inventory. It independently
commits the complete compatibility declaration behind every matrix row and the required release-app
set. Matrix rows and `requiredAppIds` are redundant projections that must exactly match this input;
removing an app from both matrix collections, or pairing authentic bundle digests with changed
permissions, baseline, or contract-range fields, fails. The policy fixes the seven required
first-party IDs, and operational input must additionally carry authenticated third-party-pilot
coverage. Existing PR-292, PR-294, and PR-295 summaries remain valid for their original purposes,
but summaries that omit full compatibility subjects cannot alone satisfy this new operational gate.
Version 1 fails closed before `app-matrix-verified` when only such a broad digest is supplied. It
does not infer complete compatibility metadata from legacy summaries; operational matrix completion
remains pending until a versioned protected subject-projection authority can authenticate every
matrix field.

The singular version-1 proposal binding may be absent only when the registry has no nonterminal
future definition. One such definition requires its exact proposal and app-matrix bytes; multiple
simultaneous future definitions require a later evidence schema. The verifier also rejects a
definition whose member descriptor was introduced after its claimed first-complete contract and a
graduation observation dated after the execution evaluation time.

The protected import is three-stage. `stable-1.0-platform-api-1x-runtime-observation.yml` verifies
the static matrix, runs the digest-pinned adapter selected by its protected managed-node
environment, and uploads the one bounded redaction-checked observation for its exact run and source.
`stable-1.0-platform-api-1x-evidence.yml` independently authenticates that observation and every
other protected input, constructs the runtime authority binding locally, and uploads one confined
aggregate from the exact protected source. The compatibility workflow accepts only that fixed
aggregate producer and authenticates its exact run, job, protected environment deployment,
dispatch actors, source, artifact ownership, timestamps, name, and digest before closeout.
Current authorities are checked against the execution source ref. The previous-history run is
checked against its authenticated ledger head's source ref so a valid successor may cross release
branches without weakening ref binding.

Operational closeout requires exact non-fixture PR-291 through PR-295 authority roots. The command
does not activate Platform API 1.1, change `/api/v1`, authorize an app capability, mutate a runtime,
publish a release, or claim the long-duration cross-version soak assigned to PR-300. See
[Platform API 1.x compatibility operations](../../docs/platform-api-1.x-compatibility-operations.md).

The runtime execution template must leave both runtime fields null; a checked-in or caller-filled
observation cannot bypass the dedicated producer. The protected evidence producer authenticates
each predecessor's exact run attempt, successful allowlisted job, protected deployment, artifact
ownership/name/digest, and bound summary bytes before closeout. History records bind both the
deprecation-ledger head and an explicit
`oldestSupportedRecordDigest`; matrix verification independently authenticates the published
Stable lifecycle receipt and descriptor, derives the minimum ordinarily supported build, and
requires the ledger projection to match. New deprecation rows must match their first authenticated
history notice. The version-1 authority permits future proposal and preview states but rejects any
future baseline activation. A production runtime result requires the separately authenticated
managed-node producer rather than caller-authored status or check labels; actual protected
execution remains a release operation and is not implied by this implementation.

## Stable 1.0 catalog authority

Run the focused local contract suite with:

```bash
python3 tools/release-certification/certify.py stable-catalog-authority --self-test
python3 tools/release-certification/certify.py stable-catalog-authority --help
```

Outside fixture self-tests, pass the exact authenticated handoff with `--evidence-dir`. Publication
modes hash and verify the canonical frozen catalog and detached signature, authenticate the PR-291,
PR-292, GA, and HTTPS-observation members, and compare a supplied sanitized live result when
`--live-publication-result` is present. A manifest containing only claimed digests or `pass` flags
fails closed for non-fixture verification.

The catalog-authority engine is deterministic and side-effect-free. Its closed operations prepare
or verify a ceremony and publication, use `verify-rotation-drill` for closed typed planned-rotation
or rollback evidence, and close out the authenticated result. It does not possess production
private keys, contact a live publisher, mutate a catalog, create a tag or GitHub Release, or infer
remote completion. The protected workflow exposes a distinct `rollback-drill` orchestration
operation and is the only place that may call the existing live USK publication boundary; only its
approved mutation job may materialize the private insert URI and form password.

Non-fixture drill verification additionally requires the original
`stable-1.0-catalog-drill-receipts.json` artifact from
`.github/workflows/stable-1.0-catalog-drill-acceptance.yml`. Its protected release and security
approval boundaries accept a bounded evidence-digest inventory and emit one closed bundle for the
exact six drill types. Each manifest `subjectDigest` must equal its matching receipt's semantic
digest, and rollback lifecycle checks use the authenticated receipt completion time. The authority
workflow cannot self-produce or reupload this bootstrap evidence; missing, substituted, replayed,
fixture, or non-operational receipts keep drill verification and closeout blocked.

The checked-in policy closes four key roles—catalog signing, first-party app signing, app review,
and offline recovery—and binds the exact PR-291 protected release root plus PR-292 independent
reproducibility result. Ceremony verification checks global key-ID and fingerprint uniqueness,
Ed25519 X.509 SubjectPublicKeyInfo, validity and lifecycle, acyclic same-role lineage, canonical
proof of possession, recovery-only usage, protected transition authorization, and evidence
classification. Public key bytes are confined to the public key-transparency artifact and derived
role registries; summaries and receipts use IDs, fingerprints, and digests.

Proof records are lifecycle-specific. Staged, active, and retiring routine keys use a
`current-keyset` statement and signature over the exact new keyset digest. Retired and revoked
routine keys use a `retained-historical` statement and its already-existing signature from an
earlier keyset; the verifier checks the historical signature and immutable public identity without
requesting a new signature from the predecessor. Offline recovery keys are
`not-applicable-recovery` and carry no routine proof material. Ceremony receipts and public
transparency rows preserve this classification so historical proof metadata cannot be confused
with current signing eligibility.

Publication verification reuses the frozen catalog and detached-signature identities instead of
forking Stable GA comparison semantics. It binds catalog ID, channel, revision, USK edition,
digests, sizes, signer ID and fingerprint, public Crypta USK primary, independently operated
mirror, and an older eligible rollback subject. Every source must return the same exact catalog
and signature. Duplicate or aliased locations, stale or unauthorized newer bytes, signature
sibling mismatch, changed signer without a later revision/edition, compromised-key rollback, and
conflicting existing state fail closed. Protected public-web locations are canonical
credential-free HTTPS on port 443, matching the exact port resolved, pinned, and fetched by the
collector.

Normal output is confined beneath the selected output root and includes ceremony, transparency,
publication, drill, closeout, Markdown report, and redaction records. Closed schemas reject
duplicate JSON keys and unknown roles, lifecycle states, ceremony types, locations, and drill
types. Redaction rejects private-key-shaped material, insert capability, credentials,
secret-bearing command lines, absolute or temporary paths, raw fetched bodies, unsafe archives,
and unpublished incident details.

Fixture and self-test inputs can prove only fixture verification. Authentic protected receipts are
required before the summary can report ceremony authentication, network-primary publication,
mirror observation, operational drills, transparency publication, or complete closeout. Preserve
sanitized partial evidence and bounded blockers on failure; never relabel it as success.

The protected network-primary mutation step preserves its sanitized local result across ordinary
publisher or post-publication verification failures. It records both exit statuses, removes the
insert URI and form password before certification, bounds and checks the result file, and stages it
only after the generated and receipt-local redaction checks pass and the receipt binds the exact
result digest. The atomically committed retention set contains exactly that result, its partial
receipt, and the redaction report. Its artifact upload uses `always()`, while the mutation step
returns the original failure status after staging. This retains authenticated retry evidence
without turning an incomplete insert or failed exact-subject check into success.

Every protected catalog-authority operation uses a closed v1 coordinate aggregate rather than one
catch-all artifact. The operation-specific aggregate authenticates every contributing Actions run
and artifact digest, then verifies the
digest of each selected member while flattening only the exact PR-291, PR-292, original
supply-chain primary subject bundle, Stable GA, live
publication, mirror observation, rollback, and applicable transition files into a confined input
directory. The subject bundle must come directly from the selected attempt-scoped supply-chain
producer; its inventory-bound app bundles and inline review receipts prove that the ceremony app
and reviewer public keys are the keys that authenticated the frozen Stable subjects. Successful
side-effect-free publication preparation retains the exact PR-291, PR-292,
subject-inventory, and public-observation members it already verified; it does not substitute the
earlier PR-291 RC-dispatch summary for the required publicly observed PR-291 closeout summary.
Stable GA separately stages the current and rollback catalog sidecars plus its exact plan and final
receipt only after its existing verifier passes. Network publication and observation remain
separate artifacts. A single coordinate, an incomplete aggregate, or a member supplied by the
wrong protected phase fails before certification starts.

The first mirror receipt comes only from
`.github/workflows/stable-1.0-catalog-mirror-observation.yml`, whose managed observer has no insert
capability and generates the root-level receipt after exact primary, mirror, detached-signature,
and scheduler checks. The dedicated collector revalidates its reviewed timestamp after protected
admission, requires the active catalog signer to remain valid through actual collection completion,
and accepts scheduler refresh verification only when an exact primary success falls within that
collection window and scheduler health exposes a configured mirror fallback. Normal refresh stops
after primary success, so the collector proves mirror availability through its separate exact-byte
catalog-and-signature fetches rather than requiring a synthetic fallback attempt. The closed receipt
binds both actual collection instants, and closeout
independently rechecks the signer against its completion instant. Its FProxy and HTTPS transfers
are bounded to the schema's 1 MiB catalog and
64 KiB signature limits before files or memory are accepted. The protected recovery-quorum
exception comes only from
`.github/workflows/stable-1.0-catalog-recovery-quorum.yml`; two fixed protected approval jobs derive
the count and emit the exact transition-bound root-level receipt. Catalog-authority verification
artifacts can consume these receipts but are never accepted as their origin. Drill and closeout
aggregates likewise accept the protected drill bundle only from the dedicated drill-acceptance
producer and bind every row to the exact PR-291 root, PR-292 result/inventory, keyset, ceremony,
catalog subject, completion time, and supporting evidence digests.

The first preparation does not depend on a previous preparation artifact. Run the protected
release closeout workflow over the reviewed PR-291 contract and its exact authenticated producer
artifacts; it calls the existing PR-291 closeout engine and emits the canonical
`publicly-observed` summary. PR-292 closeout now retains its already-authenticated subject
inventory beside its summary, and the public-observation receipt is consumed directly from its
producer. Later preparation artifacts may retain those verified members, but cannot bootstrap or
replace their original authorities.

The security-response and maintenance CLIs reject local `catalogAuthority` objects that claim
protected operational completion. Those digest-only objects remain reserved for a future
protected archive/coordinate intake; omitting the optional binding preserves historical operation.

The engine constructs and scans the complete output set before writing its first file. Any final
redaction finding aborts the command without uploadable evidence. The selected output directory
must be empty at entry, preventing stale evidence from an earlier successful attempt from
surviving a failed retry.

See the [Stable 1.0 catalog publication and key ceremony
runbook](../../docs/stable-1.0-catalog-publication-and-key-ceremony.md) for custody, approvals,
role-registry deployment, legacy fallback, exact-byte publication, retry, stop, and remaining
protected operations.

## Stable 1.0 dependency-vulnerability governance

Run the offline, phase-separated dependency security engine with:

```bash
python3 tools/release-certification/certify.py stable-dependency-vulnerability \
  --manifest build/stable-1.0-dependency-vulnerability.json
```

The command accepts only `validate-intelligence`, `match-inventory`,
`authorize-dispositions`, `prepare-remediation`, `evaluate-promotion`, or
`verify-publication`. Retrieval is deliberately absent: the protected producer emits bounded raw
digests, source provenance, and canonical records, while this command deterministically validates
snapshots, matches the exact PR-289 inventory, and enforces the four closed dispositions. The
companion promotion summary is prospectively required for Stable maintenance and security hotfixes
and becomes the non-waivable `ecosystem.stable-dependency-vulnerability` release-certification
gate. Publication uses the closed authenticated backend and verified-existing-or-create semantics;
self-tests never publish.

`stable-1.0-dependency-vulnerability-phase-bundle.yml` is the only protected producer accepted
for evaluator phase manifests. It authenticates every operation-specific upstream run, attempt,
artifact name, and Actions digest, downloads only those exact artifacts, and invokes the reviewed
phase-bundle helper to construct `manifest.json` itself. A caller-supplied manifest is never used.
Its chain is: producer records to `validate-intelligence`; the retained intelligence and exact
PR-289 artifacts to `match-inventory`; match output plus a protected bounded disposition proposal
to `authorize-dispositions`; the authorized output plus PR-288/remediation proposal to
`prepare-remediation`; and the authorized/remediation chain plus exact PR-289, PR-288, candidate,
freeze, closeout, and optional authenticated PR-287/PR-285 fixed evidence to
`evaluate-promotion`. Proposal artifacts are protected, bounded digest-only inputs; they are not
committed as repository history.
When fixed findings are present, the evaluation workflow—not the caller or phase bundle—creates
the remediation provenance sidecar. It binds the exact phase Actions digest, protected run and
attempt, PR-287 validation/completion/handoff bytes, PR-285 receipt bytes, current PR-289
summary/inventory/reverse-index bytes, and the exact fixed remediation set under the phase-scoped
remediation HMAC key before the offline engine is invoked.

The protected intelligence producer shares `stable-1-0-vulnerability-ledger` serialization with
PR-290 evaluation. It emits an exact source artifact and a separate activation proposal without a
lineage-write token. `stable-1.0-dependency-authority-activation.yml` is the serialized activation
drainer. Its single lock-holding activation job dispatches and awaits
`stable-1.0-dependency-intelligence-activation.yml` once for each retained candidate, oldest first;
it does not rely on matrix execution order. The dispatched authority authenticates the exact live
drainer run, protected branch, and commit before it requests the activation environment. The
finalizer requires the overall producer run to be completed-success,
requires both mandatory proposal/source pairs for a scheduled matrix run, reauthenticates their
exact Actions digests, and then constructs both successors and performs one compare-and-swap of
`STABLE_1_0_DEPENDENCY_INTELLIGENCE_SOURCE_LINEAGE_SET`. Failed or cancelled producer runs, and
failures while preparing either member, cannot partially supersede a usable source set. Seed that
variable with the exact compact bytes represented by
`stable-1.0-dependency-intelligence-source-lineage-set-genesis.json`; missing state never implies
genesis. Before the evaluation workflow creates its promotion HMAC, it rereads the durable
GitHub-public and OSV members and requires the selected source record and
provenance to match each current anchor's exact edition, snapshot/content/inventory digests,
workflow commit, run, attempt, artifact name, and Actions artifact digest. Configure the
least-privilege lineage-read token in the protected evaluation environment; it is not exposed to
ordinary PR or offline validation. Superseded but still fresh producer artifacts cannot authorize
promotion.
The final publication-verified handoff carries and HMAC-binds the exact source-status file; final
release certification compares both mandatory rows with this same lineage set immediately before
running the PR-290 gate.

OSV inventory selection has a separate retention-independent authority:
`STABLE_1_0_DEPENDENCY_OSV_INVENTORY_ANCHOR`. Seed it with the exact compact bytes from
`stable-1.0-dependency-osv-inventory-anchor-genesis.json`, then use the protected
`stable-1.0-dependency-osv-inventory-retention.yml` workflow to activate an exact PR-289
supply-chain comparison artifact. The anchor preserves that inventory's release, build, source
commit, semantic digest, byte digest, and original PR-289 coordinates. Its current retained
artifact may be renewed from protected `develop` without changing the inventory identity, so a
moving scheduled-workflow commit or ordinary 30-day Actions expiry cannot silently replace or
strand the Stable inventory. Renewal is required seven days before expiry; missing, expired, or
uninitialized state fails closed. The retention producer uploads a closed proposal and has no
write token. After source proposals have drained, the same serialized activation job dispatches
and awaits `stable-1.0-dependency-osv-inventory-activation.yml` for every retained
completed-success producer in oldest-first order. The finalizer independently authenticates the
exact run, attempt, artifact digest, source coordinates, inventory bytes, and predecessor, and
makes the anchor compare-and-swap its final
operation. Configure the read token in the producer and the write token only in the protected
activation environment.

The append-only PR-290 ledger tip is independently retained in the repository Actions variable
`STABLE_1_0_DEPENDENCY_VULNERABILITY_LEDGER_TIP_ANCHOR`. Provision it before the first protected
authorization with the compact sorted bytes from
`stable-1.0-dependency-vulnerability-ledger-tip-anchor-genesis.json`. Missing state is never
treated as genesis. The first successor is accepted only against that exact uninitialized anchor;
later authorizations use an exact predecessor digest-and-edition compare-and-swap. Evaluation is
read-only while it is running. Disposition authorization, dependency-evidence publication, and maintenance publication
or baseline activation share the Stable vulnerability ledger concurrency lock and recheck the
current PR-290 tip and the promotion summary's exclusive `validUntil` immediately before mutation.
Disposition, remediation, and retention producers upload only encrypted proposals and receive no
anchor-write token. The protected
shared drainer dispatches and awaits
`stable-1.0-dependency-vulnerability-tip-activation.yml` for each retained producer, oldest first,
only after source and inventory proposals have drained. GitHub must record every selected producer
as completed-success. The finalizer reauthenticates the exact run, attempt, artifact digest,
encrypted binding, and ledger predecessor before performing the final CAS.
Failed, cancelled, and still-running producers can never become the durable current tip. The
event-driven drainer also rediscovers retained proposals on a bounded schedule; this recovers an
older pending notification that GitHub concurrency replaced without weakening the single shared
ledger lock or combining the three environment-scoped write credentials.
Phase assembly therefore compares producer coordinates with this anchor only for disposition
authorization, `prepare-remediation`, and retention artifacts. Read-only evaluation artifacts,
including intentionally blocked `match-inventory` evidence needed for disposition review, remain
exact candidate-commit-bound inputs and are not misclassified as committed ledger producers.
The same anchor binds the exact ledger byte digest and Actions artifact expiry. The scheduled
`stable-1.0-dependency-vulnerability-ledger-retention.yml` workflow runs under the shared lock,
authenticates and copies the complete current artifact; the post-success activation workflow
compare-and-swaps its renewed artifact coordinate without advancing the ledger edition. Its
API-derived renewal deadline is seven days
before artifact expiry; ordinary current/predecessor verification blocks at that deadline. If the
exact bytes expire before renewal, the workflow fails closed and cannot synthesize a new genesis.
Configure the phase-handoff key plus anchor read/write tokens in the protected
`stable-1.0-dependency-vulnerability-ledger-activation` environment. Producer and retention
environments receive only the phase key and least-privilege anchor-read token they require.

The aggregate release-certification workflow uses `pre-publication` for release-branch pushes and
ordinary candidate checks. It does not request the final PR-290 handoff before a tag and non-draft
GitHub Release exist. After publication, dispatch it with
`dependency-vulnerability-stage=post-publication` and the exact PR-290 publication run, attempt,
artifact name, and Actions digest. The protected job then authenticates the `verify-publication`
handoff and rechecks its validity deadline and current ledger tip. Historical pre-activation
candidates remain on their original certification contract.

See the [governance and operations runbook](../../docs/stable-1.0-dependency-vulnerability-monitoring-and-remediation-governance.md)
and the [Phase 11 closeout](../../docs/phase-11-stable-1.0-assurance-closeout.md).

## Stable 1.0 maintenance and security hotfix certification

Use one command and policy family for both release classes:

```bash
python3 tools/release-certification/certify.py stable-maintenance \
  --manifest build/stable-1.0-maintenance.json
```

The manifest selects `maintenance` or `security-hotfix` and one side-effect-free mode:
`validate-only`, `prepare-authorization`, or `close-hotfix-follow-up`. Output is release-scoped
under `build/release-certification/<release-id>/stable-maintenance/`. Self-tests and ordinary local
execution never tag, publish, insert a CoreUpdater descriptor, or update the latest baseline.
The generated `stable-1.0-maintenance-checksums.txt` names only noncircular public payloads:
product and package bytes, the stable catalog and detached signature, release notes, the
known-limitations delta, provenance, and `core-info.json`. It does not name internal certification
records. The checksum file itself and the public authorization are separately bound by exact size
and digest in the publication plan and receipt because including either would introduce a checksum
or authorization cycle. The separate
`stable-1.0-maintenance-audit-checksums.txt` deterministically inventories every other file in the
component output for internal audit and recovery and is never a planned public asset.
Candidate construction has a separate protected `freeze-candidate` boundary. Its versioned
`stable-1.0-maintenance-candidate-freeze.json` records the one-build producer and source identities,
toolchain and dependency-verification state, latest predecessor observation, exact checksum digest,
and the complete product, catalog, and package byte/signing/notarization receipt set. Subsequent
validation supplies that file as `inputs.maintenanceCandidateFreeze`; the candidate declaration,
candidate provenance, authorization, evidence envelope, and every evidence row bind its exact file
digest. Evidence must start after the recorded `frozenAt`. A rebuild, stale predecessor, extra or
replaced asset, or pre-freeze evidence requires a new freeze and cannot be repaired during
authorization preparation.

Production evidence rows bind the immediate predecessor build and product. The
`stable-maintenance.direct-ga-upgrade` row also binds the separately authenticated immutable GA
release id, build, and product digest; all non-GA rows forbid those GA fields. Normal validation and
hotfix follow-up closure enforce both identities, so a later successor cannot relabel its immediate
predecessor as the direct-GA upgrade source.
For immutable security hotfixes published before release-train governance, the v1 maintenance
authorization schema continues to accept an absent `backportReleaseTrainDigest` only so
`close-hotfix-follow-up` can authenticate the original authorization digest. Current preparation,
validation, and protected publication still require that field semantically and reject its
absence.

The standard manifest supplies `previousStableLifecycleLedger`,
`previousStableLifecycleDescriptor`, `stableLifecycleAuthorization`,
`stableLifecyclePublicationPlan`, and `stableLifecyclePublicationReceipt` from
`build/protected-inputs/lifecycle/`. The five inputs are indivisible: the engine authenticates the
predecessor's lifecycle eligibility, exact mutable descriptor edition and bytes, approved
authorization digest, authorized plan digest, trusted update-key scope, ledger digest, and verified
public receipt before it can report promotion readiness. Every post-GA successor predecessor
requires the exact five-artifact authority chain. A chain-depth-0 GA genesis run may omit all five
only to evaluate the first proposal; that bootstrap result is deliberately
`promotionReady=false` and `decision=no-go` until the separately protected GA-rooted lifecycle
descriptor has been published and verified.

The protected maintenance workflow uses four closed operations in four runs:
`freeze-candidate`, `prepare-authorization`, `validate-authorization`, and `publish`. Freeze is the
only operation that builds packages; it signs, notarizes, staples, and verifies the DMG before
recording any digest. Prepare consumes the exact attested freeze plus later candidate-bound evidence
and cannot replace an asset. Authorization validation consumes the exact prepared artifact plus an
approval artifact containing only the authorization JSON. Publish consumes the exact authorized
bundle and rejects separately supplied candidate, evidence, package, manifest, or authorization
inputs. Its provider is one protected, attested wheel pinned by producer run, artifact digest,
source commit, wheel digest, signer workflow, and entry point, then installed on each clean hosted
runner without dependency resolution. Publication and latest-baseline activation reread the remote
release/hotfix ref at their mutation boundaries. Publication requires the original authorization to
remain current before every public target. After the protected activation environment gate, the
workflow issues a separate activation-only authorization, valid for at most one hour and bound to
the exact verified receipt, successor, history, original authorization, and predecessor pointer.
That renewable grant prevents an environment wait from stranding already-published exact bytes;
activation audit state is uploaded even if post-mutation verification fails.

The protected input producer requires the lifecycle authority chain's exact five files in the normal post-GA
freeze and preparation bundles. Authorization validation still accepts only the approval JSON, so
the maintenance workflow restores the complete prepared manifest and protected-input tree, proves
that only the mode and authorization field changed, and stages exact lifecycle audit copies again.
Publish consumes the authorized artifact unchanged and retains those copies in its publication
audit; it cannot substitute a new lifecycle state at a later phase. Before re-attesting the phase
manifest, the producer verifies every lifecycle file against the canonical lifecycle workflow and
the exact reviewed lifecycle source commit.

Hotfix closure authenticates the already published successor baseline, publication receipt,
latest-published pointer, original authorization, and obligation, then emits a separately versioned
closure overlay. The next release lineage binds that overlay digest; closure never changes the
published hotfix bytes or rewrites an activated baseline. When a later hotfix carries the
obligation, candidate-freeze authentication uses the original predecessor observation in the exact
authorized freeze while the latest baseline, receipt, and pointer independently authenticate the
current carrier.
Protected publication writes `stable-1.0-maintenance-publication-receipt.json` only for a complete,
independently verified result. Failure and partial state use the closed
`stable-1.0-maintenance-publication-failure-audit.json` schema so unavailable observations and
possible side effects are recorded without manufacturing a canonical receipt.
An interrupted operation can resume only when the observed public targets are an exact matching
prefix in canonical mutation order followed solely by absent targets; any other partial topology is
a conflict and is never overwritten or deleted automatically.
The protected evidence environment must configure exact input and Windows signer-workflow
identities. It must also configure `STABLE_CATALOG_TRUSTED_KEYS_BASE64` as a base64-encoded
`TrustedAppKeys` properties registry containing production catalog public keys only. Before
freezing, the workflow decodes that registry into a mode-`0600` temporary file, verifies the exact
candidate catalog and detached signature with `AppCatalogVerifier`, and requires the signature key
id to equal the candidate's declared `signingKeyId`. The workflow deletes the registry before job
exit and records only the catalog digest, signature digest, key id, trusted-key-registry SHA-256,
algorithm, verifier identity, and passing status. It never writes public-key bytes or raw signature
content into a JSON verification record. The exact detached signature sidecar remains a separately
frozen and published asset.

Configure the approved publication backend source commit, wheel digest, signer workflow,
and entry point as repository-level Actions variables so the evidence-scoped independent verifier
and both publication environments receive the same immutable, public-safe identity pins. Do not
scope those four backend identity variables only to a publication environment. Keep the separate
catalog, CoreUpdater, and maintenance-state protected inputs in their purpose-specific publication
environments. Private target values are environment indirections only and are forbidden in
manifests, component outputs, failure audits, and receipts.

Build that backend only through
`.github/workflows/stable-1.0-maintenance-publication-backend-producer.yml` at a reviewed `main`
commit. The consumer pins the producer run, artifact name and digest, source commit, deterministic
wheel digest, signer workflow, and `cryptad_stable_maintenance_backend:factory` entry point before
installing it outside the candidate import path. The deployment service accepts canonical public
HTTPS roots with or without a trailing slash and non-root endpoints with at most one terminal
slash; it rejects internal empty or dot segments and non-global destinations. Its
`verify-publication` request receives the closed, digest-bound `verificationInputs` record set
needed to construct receipts, successor state, and history without out-of-band candidate data.
See [the publication-backend protocol](publication-backend/README.md).

The adapter materializes each target input, permanently scrubs all target-input names from its
local and ambient environments before importing the provider, and passes an opaque value only to
the one matching target operation. It also expands every concrete artifact, catalog/signature,
mirror/rollback, GitHub Release, and update-descriptor URI before authorization and rejects any
canonical cross-role collision.
The canonical signer workflows are
`.github/workflows/stable-1.0-maintenance-input-producer.yml` and
`.github/workflows/stable-1.0-maintenance-windows-package-producer.yml`. The former authenticates an
exact-digest public-safe phase ZIP from a secret protected-environment HTTPS locator. It rejects any
non-global DNS answer, pins the connection to the validated numeric endpoints, verifies the actual
peer, and uses the original hostname for TLS certificate verification before transmitting an
optional bearer credential. The complete extracted tree is allowlisted: only the canonical phase
manifest and its referenced protected inputs may survive into the attested artifact, so unrelated
root-level or sibling files fail intake. The latter builds the Windows EXE once,
Authenticode-signs and verifies it, rechecks the immutable tracked source, and attests the exact
EXE and producer receipt. Neither
workflow publishes release state.

The protected workflow performs current-time revalidation before exact-byte public mutations and
independent receipt verification afterward. See the [Stable 1.0 maintenance release and security
hotfix path](../../docs/stable-1.0-maintenance-release-and-hotfix-path.md) for required inputs,
lineage, evidence, authorization, private secret boundaries, idempotency, and recovery.

## Stable 1.0 support lifecycle certification

The lifecycle command authenticates the immutable Stable 1.0 GA root and every published
maintenance or security-hotfix successor before it assigns support state:

```bash
python3 tools/release-certification/certify.py stable-lifecycle \
  --manifest build/stable-1.0-support-lifecycle.json
```

The command has four side-effect-free modes: `evaluate`, `prepare-transition`,
`validate-authorization`, and `verify-publication`. It writes below
`build/release-certification/<release-id>/stable-lifecycle/`. Evaluation derives the release
inventory from exact GA and maintenance publication receipts, successor baselines, history links,
and the latest published pointer. A manifest label cannot add a release to that inventory.

`stable-1.0-support-lifecycle-policy.json` is the reviewed source of product support windows,
transition rules, authorization roles, descriptor freshness, Platform API removal constraints,
governance references, and non-waivable blockers. The closed lifecycle order is
`current-stable`, `supported-maintenance`, `security-fixes-only`, `deprecated`, and
`end-of-support`. Any non-revoked state can instead enter the separately authorized terminal
`revoked` state. The engine does not infer update-key compromise from build revocation.

Normal descriptors select exactly one `current-stable` authenticated chain tip. The versioned
policy permits zero current builds only when that exact tip is explicitly revoked before a safe
successor is available. Recovery-only transitions keep current, recommended, and replacement build
fields null and publish bounded recovery guidance; certification never manufactures the unsafe tip
as its own replacement.

Generated descriptors must remain directly consumable by the runtime parser. The complete
inventory is capped at 256 entries, each `statusEffectiveAt` is no later than descriptor
`effectiveAt`, and a revoked entry uses the same value for `statusEffectiveAt` and
`securityRevocationEffectiveAt`. A `supported-maintenance` entry leaves `replacementBuild` null;
the descriptor-level `recommendedBuild` carries its optional upgrade guidance. Certification and
the protected adapter reject schema/runtime text or release-identity mismatches before
publication.

Lifecycle output includes the authenticated inventory, append-only digest-chained ledger, proposed
transition set, runtime descriptor, Platform API deprecation timeline, catalog/app/content-profile
governance projection, publication plan, provenance, checksums, summary, report, and redaction
report. Historical GA and maintenance artifacts, including already published `core-info.json`
files, remain immutable. Changing support state produces a new edition of the separately
authenticated `support-lifecycle` update-key document.

Descriptor edition 1 requires a fresh protected proof that the exact lifecycle target returned
HTTP `404` and has never been published. Bootstrap may occur against the authenticated GA alone or
against a complete no-fork history containing already-published maintenance/hotfix builds. The
proof binds the inventory digest, GA root, chain tip, public URI, and update-key scope. HTTP `410`
is a tombstone, not absence, and fails closed. Once edition 1 exists, both
`previousStableLifecycleLedger` and `previousStableLifecycleDescriptor` are mandatory.

Ordinary certification never inserts that document. The protected
`stable-1.0-support-lifecycle-input-producer.yml` workflow first fetches one reviewed public-safe
ZIP by exact digest, rejects redirects, private endpoints, unsafe archives, unreferenced files, and
non-production execution flags, then attests its manifest and every protected input. The
`stable-1.0-support-lifecycle.yml` consumer pins that canonical producer identity.

Lifecycle input and publication jobs run only from protected `main`, the exact
`release/<build_version>`, or the exact `hotfix/<build_version>` ref. Their job conditions first
require GitHub's protected-ref context. The `source_commit` input must equal both the
workflow-dispatch `GITHUB_SHA` and the checked-out `HEAD`, which keeps GitHub's attested source
digest aligned with the code handling protected inputs. The jobs then query the live GitHub branch
record, require `protected=true`, fetch the same remote branch, and require the dispatch commit to
remain its ancestor. This ancestry check tolerates the branch advancing after dispatch; it does not
permit an independently selected older commit. The publication job repeats that proof before
insert material is made available; the input producer first completes it in a credential-free job
before requesting its environment, then repeats it before receiving the protected bundle locator
and bearer token.

Configure the lifecycle evidence, authorization, and publication environments with deployment
branch rules limited to protected `main`, `release/*`, and `hotfix/*` refs. Workflow job conditions
retain the exact-build allowlist independently of those repository settings.

Authorization validation restores those attested inputs and reruns `stable-lifecycle`; it does not
trust a caller-assembled authorization summary or publication plan. Publication repeats the same
certification immediately before mutation, then performs a live read of the separately bound
maintenance latest-pointer URI. GA-only history requires pointer absence. Post-GA history requires
the exact pointer digest and tip identity. Lifecycle and maintenance publication share the
`stable-1-0-maintenance-publication` concurrency lock so the pointer cannot advance between that
read and lifecycle insertion within the protected workflows.

Publication material is supplied only through the protected lifecycle environment. The publisher
accepts identical existing bytes as an idempotent verification, rejects conflicting bytes without
overwrite, fetches the public result again, and emits an exact-byte receipt. It preserves the
authorized component and its checksum closure unchanged; the actual receipt, preflight, and
operation summary are root-level siblings in the complete published bundle. Independent
verification consumes that complete bundle, proves the original publication receipt was generated
inside the bound authorization window, and writes a separate receipt. The read-only re-fetch may
run after that approval expires; validation and publication may not. Pull requests,
self-tests, and the default `evaluate` path cannot invoke publication.

See the [support lifecycle and deprecation governance runbook](../../docs/stable-1.0-support-lifecycle-and-deprecation-governance.md)
for policy clocks, descriptor rollback protection, runtime behavior, Platform API and ecosystem
deprecation rules, security revocation, protected operations, recovery, and public-data boundaries.

## Sharesite migration observations

`stable-legacy-plugin-migration` accepts only a bounded sanitized observation, never a source
database, conversion package, private plan, backup, or raw content comparison. Use `--mode
preflight` or `--mode verify-migration` with `--observation`, `--workspace-root`, and a fresh
`--out-dir`. The example at
`manifests/sharesite-migration-local-observation.example.json` has synthetic identity placeholders
and unobserved outcomes; it does not prove an executable migration.

Output contains only `summary.json`, `report.md`, and `redaction-report.json`. The closed allowlist
permits exact public adapter/app identities, pinned source format, opaque operation ID, bounded
counts, exclusions and outcome enums. It rejects source paths/hashes, labels, old read references,
private payloads and arbitrary producer assertions before the shared redaction scan runs.

Local reports never become authenticated format/runtime/real-data evidence. `verify-runtime` and
`closeout` return nonzero with `protected-migration-producer-not-configured`; release eligibility
also retains `pr296-protected-subject-projection-pending`. A local self-digest, fixture, or resealed
receipt cannot bypass those prerequisites. No protected workflow or new release authority is
introduced. See [the pilot runbook](../../docs/real-legacy-plugin-migration-pilot.md) for conversion,
consent, identity, private-data recovery and the four evidence levels.

### Executable content profile review

`python3 tools/release-certification/certify.py stable-content-profile-review --mode review`
executes the policy-selected production Java/JavaScript conformance suites and exports the actual
five-profile registry through `crypta-app api content-formats`. `--mode inspect` only inspects
source/corpus identity; `--self-test` exercises review validation, not content interoperability.
See [the scoped review](../../docs/trust-social-stable-profile-review.md). Local outputs do not
promote profiles, authenticate remote runners, or satisfy PR-296/297 operational prerequisites.
Upload only the bounded public summary; execution logs can contain synthetic assertion payloads
and remain private. Historical RC/GA digest semantics and frozen bytes remain unchanged.
