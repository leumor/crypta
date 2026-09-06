# Release certification

The [Sharesite migration pilot](real-legacy-plugin-migration-pilot.md) adds deterministic binary
decoder, converter, owning-app UI, and guarded data recovery checks. Its
`stable-legacy-plugin-migration` command accepts only a closed sanitized local observation;
`--self-test` proves verifier behavior, not migration of a user's database. Source snapshots,
private plans/packages/backups, and raw content comparison hashes never belong in release
artifacts. Runtime authentication and real-data migration remain separate from format tests.
Release closeout retains the pending PR-296 protected subject-projection prerequisite.

Use release certification to collect a candidate’s compatibility, performance, app-platform,
security, soak, recovery, and release-policy evidence into one redacted release workspace.

For an actual Stable 1.0 freeze and exact-byte GA operation, follow
[Stable 1.0 protected release execution](stable-1.0-protected-release-execution.md). Its versioned
execution contract and `stable-protected-release` preflight/closeout command surround the existing
`stable-rc` and `stable-ga` authorities; they do not create a new artifact format or publication
path.

Provider-distinct rebuild verification is documented separately in [Stable 1.0 independent
reproducible-build verification](stable-1.0-independent-reproducible-build-verification.md). It
wraps, rather than replaces, the Stable supply-chain comparison authority and keeps repository,
self-test, protected coordinator, authenticated external-build, and public-verification states
distinct.

The later external ecosystem pilot is documented in
[Stable 1.0 external third-party app pilot](stable-1.0-external-third-party-app-pilot.md). Its
`stable-third-party-pilot` command authenticates external handoff, review cohort, beta publication,
runtime drill, and closeout receipts. It does not retroactively alter Stable GA and does not treat
the existing sample-oriented `third-party-intake.*` evidence as operational. A dedicated protected
producer creates the coordinator's exact aggregate artifact from authenticated public bytes;
operational closeout then uses read-only Actions metadata to authenticate the retained PR-291,
PR-292, and PR-293 ZIPs and their exact summary members.

Platform API release-to-release governance is documented in [Platform API 1.x compatibility
operations](platform-api-1.x-compatibility-operations.md). The side-effect-free
`stable-platform-api-1x` command verifies a digest-chained contract ledger, optional future-baseline
proposal and graduation records, monotonic deprecation history, a static cross-release app matrix,
and bounded runtime evidence. Fixture evidence cannot activate a baseline or produce operational
completion; operational closeout requires exact authenticated PR-291 through PR-295 roots. It does
not claim Platform API 1.1 activation or the PR-300 long-duration network soak.

Python 3.12 or newer is required. The public command is
`tools/release-certification/certify.py`; the previous per-tool Python scripts and shell wrappers
were removed when evidence envelope v2 became the release contract.

## Run locally

Run all offline tests first:

```bash
python3 tools/release-certification/certify.py self-test all
```

Copy and complete the release-candidate manifest, then run:

```bash
cp tools/release-certification/manifests/release-candidate.example.json \
  build/release-candidate.json
python3 tools/release-certification/certify.py release-certification \
  --manifest build/release-candidate.json
```

The manifest is the source of truth for release identity, profile, output policy, requirements,
input summaries, waivers, history, and command options. Keep private keys, passwords, tokens,
private insert material, and raw reviewer key bytes in their protected environment variables or
files, never in the manifest.

## Profiles

| Profile | Use | Gate behavior |
| --- | --- | --- |
| `pr` | Local and normal pull-request checks. | Missing release-only evidence is skipped or warned. |
| `nightly` | Scheduled evidence collection. | Optional evidence remains visible as warnings. |
| `developer-dry-run` | End-to-end local or PR-safe rehearsal. | May use fixtures or skip expensive build stages, but can never become promotion-ready. |
| `release-candidate` | Strict candidate certification. | Missing, stale, skipped, malformed, or failing required evidence blocks promotion unless policy permits a valid waiver. |
| `production-beta` | Protected beta candidate. | Adds production signing, live-network, previous-candidate, sandbox, archive, and dashboard requirements. |
| `stable-review` | Stable 1.0 readiness, RC freeze, GA, maintenance, and lifecycle review. | Requires production evidence, complete Stable domains, authenticated immutable release lineage, and the command-specific authorization policy. |

## Release workspace

Each run writes:

```text
<out-root>/<release-id>/
  .cryptad-certification-run.json
  app-platform/
  app-platform-docs/
  network-scale-soak/
  multi-node-beta/
  live-network-beta/
  security-response/
  release-certification/
  production-beta/
  go-no-go/
  stable-readiness/
  stable-rc/
  stable-ga/
  stable-supply-chain/
  stable-independent-reproducibility/
  stable-third-party-pilot/
  stable-maintenance/
  stable-lifecycle/
```

Each component contains `summary.json`, `report.md`, `redaction-report.json`, and `artifacts/`.
Artifact references are relative to the release-run root. Reset is allowed only for a directory
with a matching marker, release ID, version, and profile. Detailed engine-native output lives
below `artifacts/legacy/`; validated attached input extracts live below `artifacts/inputs/`.

Manifests are non-secret configuration: both secret-like field names and scalar values containing
private keys or URIs, credentials, private authorization material, or secret assignments are
rejected before workspace creation. The only GA authorization field is the exact
`inputs.stableGaAuthorization` path to a redaction-safe protected record; a similarly named field
elsewhere does not bypass manifest scanning. Published input references are resolved first and
represented only as `<repo>/...` or `<external-input>`. Evidence from a nonzero component exit is
always failed and cannot be reused as a passing or warning input.

Legacy outputs that lack a redaction block are scanned in full before the common envelope can pass;
malformed metadata, detected private/path material, and false direct or nested guarantees fail
closed. Production-beta envelopes copy the final `goNoGo.decision` into `result.decision`.
Known negative live-network safety facts are semantically inverted into positive v2 guarantees, so
safe `…Stored: false` metadata passes while an unsafe true value remains a blocker.
The full scan recursively rejects sensitive JSON field names that can carry passwords, tokens,
private keys or insert URIs, raw bodies, or raw app data. It also rejects local POSIX, Windows
drive, and UNC absolute filesystem paths instead of relying on a small directory-prefix list.
Canonical `<repo>/relative/path` values emitted by the existing sanitizer remain valid migration
inputs. Malformed placeholders, traversal segments, backslashes, and strings containing an
additional absolute path still fail closed.
Candidate-scoped recollection validates every component path segment before cleanup and refuses
intermediate symlinks without removing their targets.
Nested engine output directories, including `artifacts/legacy`, receive the same symlink and
resolved-path confinement checks before an engine can write through them.
Inputs produced by unified components must be candidate-bound evidence envelope v2 records of the
expected kind, component, compatible profile, and declared candidate version. Strict profiles
reject evidence produced under PR, nightly, or developer-dry-run policy even when its kind and
release ID match. Stable review may consume production-beta evidence, while release or production
aggregation may consume an explicit Stable-review summary. Explicit external or non-envelope
interop, performance, ecosystem-matrix, and third-party-intake artifacts retain their native JSON
contracts.
Any `release-candidate`, `production-beta`, or `stable-review` manifest that attaches a unified v2
input must set a non-null `release.version`. The adapter rejects the input before extraction when
the expected version is absent; `null` is never a wildcard for strict reusable evidence.
Command-specific policy modes cannot override the policy derived from `release.profile`.

Attached v2 payloads are scanned again before extraction instead of trusting their claimed outer
redaction status. Security-drill sidecars are scanned and digest-checked before copying. Unsafe
legacy engine output is removed from the publishable tree, and early exits, nonzero exits, or
redaction failures still produce a sanitized failed envelope with `promotionReady=false`.
Completed migration records and component summaries cannot be overwritten with
`output.reset=false`.

The `stable-rc/` component is created only by the canonical Stable 1.0 RC command under the
`stable-review` profile. It contains the common v2 summary/report/redaction surface plus the
versioned freeze, drift report, promotion summary, RC go/no-go report, known limitations, release
notes, checksums, provenance, and deterministic public archive. Its schema and release-manager
procedure are documented in
[Stable 1.0 RC execution and release freeze](stable-1.0-rc-execution-and-release-freeze.md).

The `stable-ga/` component is created only by the side-effect-free Stable 1.0 GA command. It
authenticates the selected RC summary, freeze, sidecar, outer archive, deterministic product,
checksums, provenance, latest successful freeze/refreeze lineage, and frozen catalog/app/API/profile
identities. It then validates protected post-freeze evidence and an explicit GA authorization bound
to those exact digests. Its native output includes GA validation and promotion records, release
notes, known limitations, a publication plan, checksums, provenance, and the post-1.0 maintenance
baseline. Publication remains a separate protected operation and is successful only after a
matching receipt passes a fresh `stable-ga` verification. See
[Stable 1.0 RC validation and GA promotion](stable-1.0-rc-validation-and-ga-promotion.md).

## Required evidence

Release-candidate certification continues to require:

- passing Hyphanet Tier 1 interop and comparable performance evidence;
- complete Platform API stable-baseline and compatibility-window evidence;
- signed first-party app, catalog, review, maintenance, update, and rollback evidence;
- app data, backup/restore, subscriptions, app services, consent, sandbox, and reference-app
  evidence;
- public-beta documentation, support, security, operator recovery, and privacy-preserving
  diagnostics evidence;
- fresh network-scale and multi-node soak evidence, including previous-candidate upgrade and
  support-bundle redaction drills;
- legacy plugin freeze/migration and legacy-admin retirement evidence;
- a complete ecosystem certification matrix and production beta go/no-go evidence when the
  selected profile requires them.

Live-network beta evidence is release-blocking only when required by the manifest profile or
requirements. Disabled live evidence is ignored; stale live artifacts must not be copied into a
new release record.

External pilot evidence is a separate post-GA ecosystem class. A schema-valid PR-294 summary may be
displayed as pending, blocked, partial, or complete by later closeout tooling, but current Stable GA
evidence is not made dependent on it. Only `operationalPilotComplete=true` with authenticated
protected roots supports an operational claim; fixtures remain `fixture-verification-complete`.

`requirements.history=true` may intentionally be used without `inputs.releaseHistory`. In that
case the manifest remains valid and the certification engine records the unavailable mandatory
history evidence; release-candidate policy emits a failed aggregate and report that blocks
promotion.

Required security-drill evidence follows the
[production security response runbook](production-security-response-runbook.md).

## History and v1 cutover

Normal v2 consumers reject legacy release-certification summaries. Convert the previous candidate
and release-history record explicitly:

```bash
python3 tools/release-certification/certify.py migrate-v1 previous-candidate \
  --manifest build/release-candidate.json
python3 tools/release-certification/certify.py migrate-v1 release-history \
  --manifest build/release-candidate.json
```

Migration validates the legacy shape, candidate binding, status, and redaction state. The v2
migration record contains the source digest and sanitized converted artifact; it does not make
normal consumers accept v1 indefinitely.

The legacy redaction block must contain either a passing status with an empty findings array or a
recognized set of all-true boolean guarantees. Missing, unrecognized, malformed, or contradictory
redaction metadata fails migration.

Use a second run manifest for certification. Its `inputs.previousCandidate` and
`inputs.releaseHistory` fields must point to the candidate-bound v2 migration summaries, not the
original v1 files. The aggregator unwraps those summaries only after validating their kind,
candidate identity, passing result, and redaction status.

Keep `release.id` unchanged between the migration manifest and the consuming certification or
production manifest. When dispatching the protected production workflow, enter that same value as
`candidate_release_id`; the workflow does not generate a new identity for migrated inputs.
Both release workflows set `release.version` from the checked-out build with
`./gradlew -q printVersion`. Prepare attached v2 evidence and migration records with that same
build version; matching only the candidate release ID is not sufficient.
When dispatching `.github/workflows/release-certification.yml`, supplying
`previous-summary-path` likewise requires `candidate-release-id` with that same value.
Supplying an optional `stable-readiness-summary-path` also requires that candidate ID because every
Stable v2 envelope is candidate-bound regardless of whether the Stable gate is mandatory.
Production workflow dispatches require the same explicit ID when attaching multi-node or
security-drill v2 evidence. The adapter preserves the validated envelope release ID when extracting
multi-node evidence, so custom candidate IDs are not reconstructed from version text.

## History archives

Set `execution.writeHistory=true` to write the current sanitized certification record. The default
shared store remains `build/release-certification-history/`; configure `policies.historyDir` only
when the release process preserves a different shared location. Passing runs update
`latest-summary.json` and `releases/<history-label>/`. Failed runs are retained under
`failed/<history-label>/` and do not replace the latest passing record. The GitHub workflow uploads
the shared history directory together with the release workspace.

## Waivers and redaction

Waivers remain evidence-specific, approved, owned, scoped, referenced, and time-bounded. A waiver
for release-candidate scope does not apply to production beta or Stable review. Existing RC
waivers carry into GA only when the frozen policy explicitly permits Stable GA scope and the waiver
remains valid. GA cannot create a broader waiver for lineage, archive identity, API/profile drift,
catalog/app trust, security, sandbox, live-network, upgrade, backup/restore, or redaction failures.
Malformed, expired, under-severity, unknown-evidence, or incomplete waivers fail validation.

Redaction findings involving secrets, private insert URIs, private or signing keys, tokens,
cookies, authorization headers, raw fetched content, raw app data, raw trust/social/profile/feed
documents, identity material, browser sessions, local absolute paths, unsafe archives, symlinks,
or special files are non-waivable. Stable redaction remains separate from dashboard and release
archive redaction, and every required redaction result must pass before publication.

See [the tooling README](../tools/release-certification/README.md) for the command tree, manifest
schema, evidence envelope v2, and focused self-test commands.

## Stable 1.0 supply-chain component

`stable-supply-chain` is the side-effect-free certification engine for the component inventory,
SBOM, license, isolated rebuild, promotion, and publication-verification gates for Stable 1.0
maintenance and security-hotfix candidates. It consumes the strict
Gradle resolution snapshot, exact release-subject inventory, license evidence, producer and
verifier receipts, payload manifests, the maintenance freeze, and the redaction-safe protected
vulnerability summary. Its common envelope is under `stable-supply-chain/`; canonical native
records are under `stable-supply-chain/artifacts/legacy/`.

The closed modes keep trust boundaries separate: `assemble-inventory`, `verify-inventory`,
`prepare-rebuild-comparison`, `compare-rebuilds`, `evaluate-promotion`, and
`verify-publication`. A passing inventory does not assert reproducibility. A passing rebuild
comparison does not authorize maintenance publication. Publication verification consumes an
existing plan, receipt, and independent public observation and performs no remote mutation.
The `evaluate-promotion` summary therefore requires the complete prepublication evidence set but
cannot report `stable-supply-chain.publication` as passing; that row becomes passing only in a
successful `verify-publication` result.

The protected manual workflow uses separate producer and verifier jobs. Both use Java 25, the
Gradle wrapper, and `exportStableSupplyChainResolution` plus
`verifyStableSupplyChainResolution`. Protected builds first authenticate the phase bundle's exact
reviewed raw resolution export and canonical snapshot, then pass their confined paths through
`stableSupplyChainExpectedResolutionExport` and
`stableSupplyChainExpectedResolutionSnapshot`. The verifier recipe allowlist excludes producer
candidate bytes, so the verifier still finishes its own build before such bytes can become
available. `stable-maintenance` requires the resulting candidate-bound promotion summary for every
current release and security-hotfix path except the historical follow-up-closure operation, which
changes no release bytes.

The existing producer and verifier remain same-provider evidence because both run under GitHub
Actions. The `stable-independent-reproducibility` command adds a provider-neutral identity and
attestation adapter, a candidate-byte-free verifier kit, protected receipt import, and exact
selected-RC closeout while reusing this component's comparison plan and result. No external or
public completion is inferred from fixtures, local files, an Actions upload, or coordinator
execution alone. Operational success additionally requires a concrete reviewed provider profile
and real adapter verification of the raw attestation bundle and transcript. Follow [the independent
verification runbook](stable-1.0-independent-reproducible-build-verification.md).

## Stable 1.0 dependency-vulnerability component

`stable-dependency-vulnerability` is the offline companion to the supply-chain component. Its
closed modes are `validate-intelligence`, `match-inventory`, `authorize-dispositions`,
`prepare-remediation`, `evaluate-promotion`, and `verify-publication`. Live public-source
retrieval is confined to the protected producer workflow; ordinary validation consumes exact,
authenticated snapshots and never contacts an advisory service. After prospective activation,
the non-waivable `ecosystem.stable-dependency-vulnerability` gate binds the snapshot and finding
ledger to the PR-289 reverse index, PR-288 public-safe case projection, PR-287 security fix, and
PR-285 publication evidence. Historical candidates frozen before activation retain their original
contract.

The protected release-certification workflow has two explicit dependency-vulnerability stages.
Release-branch pushes and ordinary candidate checks use `pre-publication`; they do not require the
final PR-290 publication handoff because the tag and non-draft GitHub Release do not exist yet.
After publication, dispatch the workflow with `dependency-vulnerability-stage` set to
`post-publication` and supply the exact successful PR-290 publication run, attempt, artifact name,
and Actions digest. That stage authenticates the final `verify-publication` handoff, checks its
exclusive validity deadline and durable ledger tip, and enables the non-waivable aggregate gate.
The workflow's early deadline check is only preflight: after all other evidence collectors finish,
the release-certification engine captures runner UTC again at the PR-290 evidence gate. It does not
reuse a timestamp frozen before the potentially long collection run, and equality with
`validUntil` is expired.
Candidates frozen before prospective activation remain on their historical contract and do not
run the post-publication PR-290 stage.

The public projection publishes bounded source status, opaque finding status, and disposition
counts only. Private case contents, reporters, embargoed analysis, raw feeds, credentials, and
runner paths remain outside that projection. See the
[dependency-vulnerability governance runbook](stable-1.0-dependency-vulnerability-monitoring-and-remediation-governance.md)
and [Phase 11 closeout](phase-11-stable-1.0-assurance-closeout.md).

Release certification does not accept a self-digested local promotion summary. Beside the fixed
summary filename it requires the canonical
`stable-1.0-supply-chain-summary-provenance.json` produced after the protected consumer resolves
the exact successful `compare-evaluate` run, run attempt, fixed artifact name and Actions artifact
digest and verifies the summary's GitHub/Sigstore attestation against the supply-chain workflow at
the candidate source commit. That protected step then authenticates the closed provenance record
with a domain-separated HMAC-SHA256 tag under the dedicated, environment-scoped
`CRYPTAD_STABLE_SUPPLY_CHAIN_HANDOFF_KEY_BASE64` key. The certification consumer requires the same
32-byte key, verifies the tag rather than trusting the record's attestation booleans, and compares
the summary commit and immutable `commit:<sha>` source ref with a direct `git rev-parse HEAD` of the
workspace being certified. Caller metadata and `--skip-git-metadata` cannot substitute for that
observation. New maintenance candidates bind those coordinates in protected manifest metadata.
The PR-289 policy applies that handoff requirement prospectively from
`governanceActivation.candidateFrozenAtNotBefore`; existing pre-activation maintenance records are
not changed.

Workflow orchestration adds one explicit `publish` operation outside the engine. Only its protected
`stable-1.0-supply-chain-publication` job has `contents: write` and the environment-scoped
`LEUMOR_GITHUB_TOKEN`; all other jobs remain mutation-free. Publish authenticates the exact
promotion handoff, source, annotated tag, existing Release, every input attestation, and the
reviewed `cryptad_stable_maintenance_backend:supply_chain_factory` wheel. It accepts exactly the
eight policy roles, including `release-subject-inventory`, creates only absent assets, verifies
identical existing assets as `verified-existing`, and never deletes or overwrites a conflict. Its
attested handoff contains the exact plan and summary plus a publication receipt and fresh public
observation for the independent `verify-publication` run.

See [Stable 1.0 supply-chain inventory and reproducible-build
governance](stable-1.0-supply-chain-inventory-and-reproducible-build-governance.md).

## Stable 1.0 catalog-authority component

`stable-catalog-authority` is the side-effect-free PR-293 authority for role-separated Stable
public keys, ceremony verification, exact frozen-catalog publication evidence, rotation and
rollback drills, public key transparency, and closeout. It consumes the exact authenticated PR-291
protected release root and PR-292 independently reproduced catalog subject. It never rebuilds,
rewrites, re-signs, inserts, or remotely fetches the selected Stable catalog.

Operational ceremony verification also consumes the original attempt-scoped supply-chain primary
subject bundle. Every bundled subject must match the PR-292 inventory before the engine verifies
the frozen first-party bundle signatures and inline review receipts against the role-specific
ceremony public keys. This closes same-ID/different-key substitution without adding a new
self-asserted fingerprint to the PR-291 summary.

The closed modes prepare and verify ceremonies and publication, verify rotation or rollback drill
evidence, and produce closeout. Outputs distinguish implementation, fixture verification,
authenticated ceremony, network-primary publication, mirror observation, drills, transparency
publication, `partial`, and `blocked`. Operational states require authentic protected receipts;
fixtures, self-tests, local JSON, and workflow definitions cannot advance them.

The keyset is closed to catalog signing, first-party app signing, app review, and offline recovery.
Certification rejects role reuse by key ID or public-key fingerprint, invalid lifecycle or
lineage, missing proof of possession, recovery-key routine signing, replayed authorization,
unbound PR-291/PR-292 identity, and secret-shaped or path-bearing evidence. Public key bytes are
allowed only in the dedicated transparency artifact and derived role registries; normal reports
remain fingerprint-only.

The protected workflow owns the separately approved live mutation through the existing
`crypta-app publish-usk --live` boundary. Stable GA's canonical HTTPS observations remain
mandatory. PR-293 additionally requires the same exact catalog and detached-signature bytes from
a public Crypta USK primary and at least one independently operated mirror, plus an eligible
previous signed revision for rollback. See
[Stable 1.0 catalog publication and key ceremony](stable-1.0-catalog-publication-and-key-ceremony.md).

## Stable 1.0 maintenance component

`stable-maintenance` is the canonical component for both routine maintenance and critical security
hotfix candidates after Stable 1.0 GA. It authenticates the immutable GA root and latest published
predecessor, freezes one new integer-build candidate, compares compatibility and production
evidence, prepares closed-scope authorization, and emits deterministic publication and successor
baseline records. Local modes are side-effect-free; only the protected workflow may publish the
authorized bytes. Once a lifecycle descriptor has been activated, post-GA promotion also requires
the exact authenticated lifecycle ledger, descriptor, authorization, publication plan, and
verified publication receipt. The protected workflow re-observes that descriptor under the shared
publication lock instead of trusting an old but still schema-valid receipt.

See the [Stable 1.0 maintenance release and security hotfix
path](stable-1.0-maintenance-release-and-hotfix-path.md).

## Stable 1.0 support lifecycle component

`stable-lifecycle` authenticates the GA publication root and complete maintenance successor chain
before it derives the real published-build inventory. It assigns every published build one status
from the closed lifecycle vocabulary, enforces monotonic normal transitions and terminal
advisory-backed revocation, and emits a digest-chained ledger plus a separately versioned
`support-lifecycle` descriptor. It never rewrites historical `core-info.json`, publication
receipts, or baselines.

The side-effect-free command modes are `evaluate`, `prepare-transition`,
`validate-authorization`, and `verify-publication`. Protected workflow orchestration adds the
one-time `prove-genesis` operation plus explicit `publish` and independent verification phases.
Only `publish` receives the purpose-specific private insert capability. A first descriptor requires
an attested HTTP `404` proof for the exact public target; HTTP `410` is a tombstone and cannot prove
genesis. Every later edition requires the exact prior ledger and descriptor.

CoreUpdater consumes the published descriptor locally, retains exact last-known-good bytes, and
exposes a redacted snapshot through the detached runtime SPI. Build revocation remains separate
from update-key compromise. The lifecycle subscriber continues when package updates are disabled,
but authenticated update-key compromise invalidates cached lifecycle authority and prevents both
package and lifecycle subscribers from restarting under that key.

See [Stable 1.0 support lifecycle and deprecation
governance](stable-1.0-support-lifecycle-and-deprecation-governance.md).

## Content profile executable evidence

The [Trust/Social stable profile review](trust-social-stable-profile-review.md) supplements
`app-platform.trust-social-content-format-profiles` source inspection with a separately labeled,
current-source-bound local conformance result. Run the unified `stable-content-profile-review`
command before collecting the optional executable result. Missing local results remain unobserved;
stale results fail binding. This evidence does not promote content profiles, activate an API
baseline, authenticate remote execution, or replace protected production prerequisites.
