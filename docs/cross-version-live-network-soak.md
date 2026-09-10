# Cross-version observed network experiments

Use `certify.py cross-version-soak` to validate a closed experiment, run the owned packaged-node
adapter, and verify its measured journal. This command extends the interop/certification tools;
it does not replace the Stable RC, GA, maintenance, catalog, or lifecycle authorities.

## Execution and authority boundaries

The implemented local adapter is Linux-only and uses independent processes on one host. It starts
the selected portable Cryptad distributions, establishes a private darknet through an app-free
relay, and uses the existing FCP clients for content operations. This topology does not establish
independent infrastructure, public-network scale, anonymity, or remote deletion.

| Evidence profile | Meaning | Admission |
| --- | --- | --- |
| `offline-self-test` | Fake clocks and transports test rejection and recovery logic | No live runner admission; no operational claim |
| `bounded-live` | Explicitly authorized disposable processes and actual bounded operations | Exact local package/runtime/helper pins and private target authorization; local source comparison is not original release authentication |
| `protected-long-live` | Original authenticated artifacts/runner plus measured policy coverage | The verifier preserves a separate minimum of 72 observed hours; local hash chains cannot authenticate this profile |

The production-artifact path reauthenticates original RC and portable producer artifacts rather
than accepting local pins as release authentication. Protected-long execution additionally needs
the original supervisor authority. A required missing scenario makes the result partial.
Successful local signature verification, a private journal, a workflow definition,
and a short smoke do not confer release eligibility. Existing 24-hour Stable gates retain their
own thresholds, freshness, exact products and post-freeze requirements.

Live execution requires separate current authorization naming the disposable root, exact plan,
content scope, duration and operation budget. An `--execute` flag alone supplies none of these.
Do not use an existing personal profile, publish real migrated text, or supply production signing
or insertion credentials. Ordinary PR tests never run this adapter against live nodes.

## Reuse and remaining boundaries

| Work | Reused implementation | New boundary / remaining prerequisite |
| --- | --- | --- |
| Packaged lifecycle and FCP | `tools/interop/interop_smoke.py` launch contract, FCP parser, peer/content operations | Exclusive root, exact input pins, private transcripts, owned process/start identities, scoped fault and cleanup |
| Multi-node reports | Existing `multi-node-beta` and `network-scale-soak` remain unchanged | New measured journal/verifier; old elapsed-time labels are not measured coverage |
| Mail | `tools/mail-prototype/two_node_demo.py`, normal AppHost install/start and own-app bootstrap | Real callable delivery path; complete origin, canary and restore coverage remain separate required findings |
| App declarations | Java catalog, bundle, manifest and review verifiers | `crypta-app subject-projection` derives fields from signed artifacts; protected cohort/original producer authentication is separate |
| Sharesite | Fixed converter, installed `drafts.js`, guarded app-data routes | Synthetic and separately root-authorized private-source adapters; missing recovery/browser cases, authentic execution and independent real-user confirmation remain distinct |
| Profiles | Existing production JS SDK/controllers and original five-profile corpus | Immutable source comparison executes recorded readers and generated Feed directions; missing Java/historical signed producers and external implementations remain explicit |
| Release consumers | Existing exact freeze, source, freshness and authority checks | `closeout` cannot manufacture protected identity or fill an unobserved mandatory row |

## Exact input roster

The public plan schema is validated by
[`cross_version_evidence.py`](../tools/release-certification/cryptad_certification/cross_version_evidence.py).
Its mandatory roles are `candidate-sender`, `candidate-recipient`, `previous`, and `relay-no-apps`.
The first two intentionally share candidate package bytes but require independent processes,
stores and compatible contract-25 Mail installations. The predecessor must have a different
source and package identity. A different archive digest alone does not authenticate old source.

The plan names each product, source commit, artifact digest/size, package target, runtime digest,
configuration digest and app bundle digests. The producer separately binds the installed runner
helper set and the interop adapter. `runner_identity()` in
[`cross_version_runtime.py`](../tools/interop/cross_version_runtime.py) derives the actual helper
identity; pin it after preparing the exact implementation. Changing a helper invalidates the plan.
The full selected JDK tree is bound independently of the build toolchain.

For `production-artifact-comparison`, private `productAdmission` selects each role's original RC
and portable supply-chain artifact coordinates. The adapter downloads the original immutable
artifacts, verifies successful producing attempts/jobs/environments, reuses the GA verifier for
the RC freeze/product/checksum set, and verifies exact portable package/handoff attestations.
The previous product retains its own source and lower authenticated build identity. No rebuild
can replace a selected historical package. App-bearing roles also need authenticated projection
coordinates and the independently selected cohort digest. Conservative prelaunch screening of
these declarations is separate from the Java static matrix and normal AppHost admission.

The existing RC frozen app product does not include a frozen portable daemon binding. Therefore
authenticating a same-source portable package establishes that package's original producer;
it cannot satisfy a post-freeze daemon requirement by itself. The public artifact identity keeps
`frozenPortableBinding: not-established` explicit.

An optional oldest-supported role must come from authenticated lifecycle selection. The current
local adapter rejects unsupported extra products/roles instead of substituting current bytes.
The repository-pinned Hyphanet 1506 artifact remains available through the separate existing
interop adapter. Its checksum and subscription/fetch limitations remain in the
[interop runbook](../tools/interop/README.md); Cryptad apps are never installed into Hyphanet.

The private configuration supplies an absolute new owner-only root and a role map. Each entry
contains `archivePath`, `javaHome`, `fnpPort`, `fcpPort`, `httpPort`, selected app ZIP paths/digests,
and the selected public publisher registry path/digest. Client access is literal loopback only.
These paths, ports, credentials and node references never belong in the public plan or result.
Do not copy a fixture plan into a live run and replace only its duration.

The separate owner-only authorization binds `experimentId`, `planDigest`, that same `root`,
`maxSeconds`, `maxOperations`, and explicit `syntheticContent`. Continuation additionally binds
the exact saved runtime-state digest. An operator must review these values; the runner cannot
infer that an arbitrary local root or large operation budget was approved.

## Commands

Offline verification is available without a release artifact or a node:

```bash
python3 tools/release-certification/certify.py cross-version-soak --self-test
python3 -m unittest discover -s tools/interop -p 'test_cross_version_*.py'
python3 -m unittest discover -s tools/mail-prototype -p 'test_*.py'
```

The following are command forms with placeholder private inputs, not permission to execute them:

```bash
python3 tools/release-certification/certify.py cross-version-soak plan \
  --plan REVIEWED_PUBLIC_PLAN.json --private-config PRIVATE_TARGETS.json \
  --authorization PRIVATE_AUTHORIZATION.json --out-dir NEW_PREFLIGHT_OUTPUT

python3 tools/release-certification/certify.py cross-version-soak run --execute \
  --plan REVIEWED_PUBLIC_PLAN.json --private-config PRIVATE_TARGETS.json \
  --authorization PRIVATE_AUTHORIZATION.json --journal-root PRIVATE_APPROVED_ROOT \
  --out-dir NEW_PUBLIC_OUTPUT

python3 tools/release-certification/certify.py cross-version-soak verify \
  --plan REVIEWED_PUBLIC_PLAN.json --journal-root PRIVATE_APPROVED_ROOT \
  --out-dir NEW_VERIFICATION_OUTPUT
```

Output directories must be new and separate from the private root. `plan` without private inputs
validates only the public contract and explicitly reports that artifact admission was not performed.
Private preflight checks exact input bytes without extracting packages or contacting a node.
The live runner rejects unsupported authority or missing authenticated production subjects before
launch. Pure `verify` does not fetch GitHub metadata or turn local hash integrity into authority.

## Measurement and continuation

`requestedSeconds` is the measured workload window, beginning at the opening probe after setup.
Authorization must cover setup as well as that window, one maximum probe-gap allowance and a
240-second cleanup reserve. The runner rejects an obviously insufficient bound during admission,
then rechecks actual remaining authority before the opening probe; it never shortens the requested
window to fit. The probe interval must be shorter than the maximum gap so actual work has time to
complete. Each sleep is followed by scheduled work and a closing probe, including the final window.
The normal deadline and protected authority still bound execution, and an overrun remains failed
or partial rather than inventing covered time.

Each append binds the exact plan, sequence, preceding digest, controller epoch, node runtime epoch,
scenario, operation and bounded counters. Checkpoints are atomically replaced after journal fsync.
The journal cap stops growth; no failure is discarded to make room for another sample.

Coverage comes from monotonic intervals bounded by scheduled probes and actual intervening passed
operations, a complete selected-app lifecycle sample on every app-bearing role, and actual JVM
memory/thread/file-descriptor samples on every role within that same window. These periodic samples
establish observation coverage; they do not satisfy the full lifecycle or budget matrix or supply
a missing reviewed resource baseline. Idle heartbeats and repeated content alone do not create
eligible coverage. Concurrent roles do not multiply elapsed time. Directional operations bind both
sender and recipient runtime epochs. A stopped participant cannot supply an operation or coverage.
Unknown gaps, future UTC times, clock discontinuities, replayed operations, substituted tails,
missing mandatory directions, and cleanup failures prevent complete results. A planned fault is
an observed fault/recovery operation, not healthy-node uptime.

An interrupted run retains a partial checkpoint. Bounded continuation requires the same OS owner,
root identity, boot and exact checkpoint digest under an exclusive lease, plus exact saved runtime
state. It does not authorize taking over an unrelated PID. A restarted controller starts a new
measured epoch; separate epochs cannot be summed into one uninterrupted soak. Previously failed
findings remain failed. Owned process scopes remain unresolved across continuation until observed
reconciliation; an earlier cleanup cannot cover a later restart. Never remove a lease or edit a
tail to force resumption.

The durable Mail initialization and sealed-operation identities must survive continuation.
Do not initialize another account to hide quotas, replay history or expiry. Mail remains bounded
to one account/key epoch, 16 contacts, 16 inbox records, eight outbox operations, 128 replay entries
and its byte caps. Run finite send/reply/crash cases and appropriate continuing health checks.
Restored Mail remains paused for sending/receiving; retained authenticated messages may be read.
Missing keys remain `key-unavailable`. Bundle rollback is distinct from data restore or unsafe
daemon downgrade.

The subscription scenario inserts a later explicit edition and requires an actual
`SubscribedUSKUpdate`, followed by exact private content comparison. A successful fallback fetch
does not satisfy notification. The persistent-request scenario journals the original durable
identifier before enqueue, observes it after daemon restart and completes/removes that request;
an unknown enqueue outcome is reconciled using the original identity.

The Stable API adapter uses a normally installed Site Publisher principal for queue/data reads,
a finite synthetic data round trip, stale-write denial with unchanged stored bytes, restart
persistence and observed cleanup of only its newly owned namespace. Missing installation on the
previous node remains a missing required direction. These representative routes do not establish
the full catalog, update, consent, rollback or network-budget matrix.

An optional `cohorts` plan entry selects `previous-to-candidate`, with `sourceRole: previous`,
`targetRole: candidate-sender`, and the canonical private recovery-selection `configDigest`.
The matching private `recovery` selection contains only that cohort ID and three distinct local
ports; `recoveryInputsDigest` binds it in the authorization. The isolated profile runs the actual
previous package first, creates synthetic app data through its own principal, takes a private
operator backup, stops, and starts the actual candidate package against that profile. It observes
changed writes, restart persistence and normal guarded private restore. Cohort journal epochs and
partial results cannot replace main-role epochs or contribute main soak duration. Interrupted
cohorts require private reconciliation; they are not reinitialized automatically. This Site
Publisher drill does not observe Mail restore or permit unsafe daemon downgrade.

The optional private `budget` selection binds candidate-sender and exact Node executable bytes;
its canonical digest must match both `workloadInputs.budget` and `budgetInputsDigest`. A normally
signed installed Feed Reader is required. The fixed own-app driver reserves at most 38 requests,
requires at least 365 seconds plus operation capacity for fixture preparation and the bounded
trial, and observes actual foreground quota/concurrency responses and recovery. Unknown outcomes
retain their conservative request charge. Scheduler pressure and the reviewed resource baseline
remain missing, so the full budget result stays partial.

The optional `catalog` selection binds the candidate-sender role, one confined local fixture root,
a complete pinned Java tool/JDK tree, and exact baseline/mirror/other-catalog/untrusted inputs.
Its canonical digest must match `workloadInputs.catalog` and `catalogInputsDigest`. The selected
publisher registry and baseline app must equal the node's already admitted subjects. The runner
stages only the separately selected public catalog/reviewer registries for that disposable role;
it does not import global publisher keys. Actual normal catalog routes observe signed admission,
exact mirror subject preservation and untrusted-signature denial. Source-switch consent remains
`not-observed`, including when `otherCatalog` is selected: staged-directory app installation does
not establish an installed catalog origin, and the selection does not establish a federation-scoped
update plan. The runner verifies the alternate subject but does not register it, stop the app or
attempt its update. Exercising this denial requires a separately implemented normal catalog-origin
installation and authenticated federation scope; adding catalogs after a staged install is insufficient.
Cleanup removes only newly owned catalog IDs and compares the final inventory privately. Mirror
registration is not fallback traffic, and the incomplete channel/conflict/rollback matrix remains
partial. Interrupted catalog operations retain reconciliation state and cannot rerun automatically.

## Persistent operation

A long experiment must keep the actual supervisor, nodes and workloads alive on a separately
approved disposable host. Short GitHub collection jobs cannot provide continuity by concatenating
their elapsed times. Hosted jobs have a six-hour limit; self-hosted jobs have a five-day limit,
and `GITHUB_TOKEN` lasts at most 24 hours or until job completion. See the current
[GitHub limits](https://docs.github.com/en/actions/reference/limits) and
[timeout contract](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idtimeout-minutes).

Persistent local source comparison and authenticated protected execution remain different
admissions. The local supervisor needs no GitHub token during its workload. Original protected
authorization/start/checkpoint/finish authentication is established by short jobs in the protected
supervisor workflow below. Extending a token lifetime or reuploading an old journal does not
provide it. An absent protected environment, installed supervisor or authentic predecessor remains
an operational prerequisite. Post-freeze product binding remains a separate release-consumer
requirement even for an authenticated pre-freeze long experiment.

The concrete tokenless local service is
[`cross_version_service.py`](../tools/interop/cross_version_service.py), with the supplied
[systemd unit](../tools/interop/systemd/cryptad-cross-version-soak.service). An authorized
administrator installs the exact reviewed checkout at `/opt/cryptad-cross-version/current` and
provisions the dedicated `cryptad-soak` account. It requires these owner-only directories:

```text
/var/lib/cryptad-cross-version/selected/
/var/lib/cryptad-cross-version/experiments/
/var/lib/cryptad-cross-version/public/
```

The selected directory contains reviewed `plan.json`, `private-config.json`, `authorization.json`
and `service-selection.json`. The experiment and public child directories must not already exist.
The selection object has exactly `schemaVersion: 1`, `serviceDigest`, `planDigest`,
`privateConfigDigest`, and `authorizationDigest`; these are SHA-256 digests of the exact corresponding
files, prefixed `sha256:`. Its `planDigest` is an exact-file digest, whereas the authorization's
`planDigest` is the canonical semantic digest returned by `cross-version-soak plan`.
Do not interchange them. The plan also binds the complete fixed workload helper set.

After separate topology and service-start authorization, install the unit into the systemd unit
directory, reload systemd and start `cryptad-cross-version-soak.service` through the host's normal
service administration. The executable accepts no custom script or path arguments and requires
its dedicated systemd cgroup. It uses no GitHub token, has `Restart=no`, and refuses an existing
experiment until explicit reconciliation. Stop first interrupts the controller to checkpoint and
clean its owned nodes; systemd bounds the remaining service cgroup after the stop deadline.
The service's resource caps and five-day ceiling do not establish a reviewed performance baseline.
The service also admits `protected-long-live` when the fixed protected control helper has created
the authentic activation described below. Product authentication remains independent: a protected
source comparison is not an original production-artifact comparison.

Read-only collection can invoke `verify` against an atomic partial checkpoint while the service
continues. It reads that checkpoint's exact journal prefix. A collector retry neither appends an
operation nor adds another copy of its duration. Public export remains separate from the service's
private experiment directory.

### Protected control installation and sequence

[`cross-version-live-network-soak.yml`](../.github/workflows/cross-version-live-network-soak.yml)
uses one dedicated `cross-version-live-network-soak` environment and
`cryptad-cross-version-supervisor` self-hosted runner label. It accepts only four fixed operations;
there is no dispatcher-provided node address, script or target path. The environment must approve
the exact disposable inputs and bounds, and the runner must never accept arbitrary PR jobs.

The privileged boundary is the fixed installed
[`cross_version_supervisor_authority.py`](../tools/release-certification/protected/cross_version_supervisor_authority.py).
An authorized administrator installs a clean, root-owned exact checkout, the dedicated service
account and unit, and the narrowly scoped
[sudoers template](../tools/interop/systemd/cryptad-cross-version-control.sudoers). The template
permits only the installed isolated Python command with each of the four literal operation
arguments. Validate it with the host's `visudo` before installation. No service or sudoers change
is performed by local tests or by reading this runbook.

The service's runner-identity Git command supplies a command-local `safe.directory` exception for
its exact executing checkout, after clearing any inherited safe-directory list. No global Git
configuration or wildcard exception is needed. This permits the unprivileged account to read the
administrator-owned checkout without relaxing the protected helper's ownership checks.

The service account owns the private selected/experiment/public directories. The root control
helper owns `/var/lib/cryptad-cross-version-authority`; the activation is root-written and readable
by the service, while the used-authorization ledger remains private. Fixed root-owned files under
`/etc/cryptad-certification` select original artifact coordinates. Their exact schema is the
shared original-artifact authenticator's closed coordinate object, never saved API responses.

1. `authorize` verifies the exact installed source/helper/service identities and selected bounds,
   requires a new topology, and attests only its bounded public authorization report. It starts
   no service. Wait for that original run to complete successfully.
2. Select its original coordinates in root-owned `cross-version-start.json`. A fresh `start` job
   reauthenticates the exact original attempt, job, environment, artifact and member attestation.
   It consumes that authorization once, records boot and monotonic lifetime privately, and starts
   only the fixed unit. The service retains no GitHub credential.
3. Select the completed original start or latest checkpoint artifact in root-owned
   `cross-version-previous.json`. Fresh `checkpoint` jobs verify the original lineage and exact
   journal prefix before attesting a new public observation. Re-reading a prefix adds no duration.
4. `finish` observes that the unit has stopped and verifies the terminal journal and cleanup
   result. It does not stop an unfinished experiment to manufacture success. A failed or partial
   scenario remains failed or partial in the attested report.

The helper reads service-owned inputs through confined file descriptors, binding the exact bytes
it read rather than reopening a checked path. Runtime admission checks the root activation,
actual service cgroup, boot identity, plan and input digests, installed producer and remaining
monotonic lifetime. Authority replacement or expiry stops further workload actions; cleanup
remains limited to owned resources. Automatic restart and protected crash takeover are disabled.
An interrupted service needs explicit private reconciliation; a collector retry is not a restart.

All jobs are short and obtain fresh job/OIDC credentials. Their allowlisted reports are separately
scanned, attested and uploaded as single files; no operational directory is uploaded. Even a
complete authenticated long observation reports non-release purpose until an existing consumer's
own artifact, duration, freshness and freeze rules are met. Budget startup, planned faults and
cleanup explicitly: requesting exactly 72 wall-clock hours cannot guarantee 72 eligible observed
hours after warm-up and observation gaps.

## Protected app-subject projection

The implemented producer is
[`stable-1.0-app-subject-projection.yml`](../.github/workflows/stable-1.0-app-subject-projection.yml).
Both operations require the selected protected source and actor policy. Preparing this workflow
or the files below does not authorize dispatch or provide an observed projection.

1. An authorized `build-tools` dispatch builds `:platform-devtools:distZip` at the exact workflow
   source in the `build-projection-tools` job and `stable-1-0-app-subject-projection-tools`
   environment. It attests and uploads only the complete `projection-tools.zip`. Wait for that
   original run to finish; a later upload cannot replace its producer identity.
2. The protected host selects that original completed artifact, installs its tool distribution
   through the approved host process, and pins the complete installed tree. The producer compares
   every file name, executable bit, size and digest against the authenticated archive, including
   adjacent JARs. It separately pins the complete selected JDK tree. A historical app's source
   remains historical; the current projection tool source is bound independently.
3. The root-owned, non-writable-to-others
   `/etc/cryptad-certification/app-subject-cohort.json` selects the cohort. Its closed fields are
   `schemaVersion`, `cohortPolicy`, `releaseId`, `sourceCommit`, `authorityRoots`, `toolRoot`,
   `toolTreeDigest`, `toolOriginal`, `toolMember`, `exporterRelativePath`, `javaHome`,
   `javaTreeDigest` and `sources`. `toolOriginal` uses the original-artifact coordinate schema with
   source family `projection-tools`; `toolMember` selects the exact attested member. Public subject
   and trust selection can be root-owned mode 0644; do not put credentials or private user data in
   this file.
4. Each source binds exact `original`, `originalInventory` and optional `catalogOriginal`
   coordinates, selected archive members, catalog/publisher/reviewer registry files and digests,
   catalog key, required app ID, upstream root and evidence digest. First-party declarations must
   match their authenticated release inventory. External declarations require the exact actual
   submission artifact and selected imported review cohort. The Java verifier recomputes the
   bundle, manifest, signature, review, baseline, contracts and capability declarations. A genuine
   unrelated bundle digest cannot authenticate caller-supplied compatibility fields.
5. A separately authorized `produce` dispatch uses the dedicated `cryptad-app-subject-projection`
   runner and `stable-1-0-app-subject-projection` environment. It writes a fresh allowlisted v2
   inventory, attests that exact member and uploads only it. The receiving protected environment's
   `APP_SUBJECT_COHORT_DIGEST` selects the expected cohort. Original coordinates accompany the
   evidence as `app-subject-projection-authority.json`; the `verify-matrix` wrapper reauthenticates
   them before static matrix or runtime preflight admission.

`historical-seven` preserves the earlier first-party cohort. `current-eight-experimental-mail`
adds Mail with its actual experimental declaration; neither policy omits authenticated external
app coverage. Selected federation projection currently fails closed as unsupported. No protected
cohort, tool artifact or projection was produced during this implementation work. The dependency
is authenticated artifacts → projection → static matrix → runtime → closeout; building the tool or
projecting declarations does not require the final closeout it enables.

## Protected Sharesite observations

[`stable-1.0-sharesite-runtime-observation.yml`](../.github/workflows/stable-1.0-sharesite-runtime-observation.yml)
is a dedicated protected execution path. It requires its selected disposable topology and bounds,
normal signed Site Publisher installation, real sandbox, own-app session and pinned converter,
Node, JDK and installed controller. The fixed root-owned topology selection seals runner-owned
mode-0600 operational input files. It never runs nodes as root and never uploads those inputs.
The actual runner creates a separate `sharesite-runtime-observation.json`; the producer binds its
original job coordinates afterward, attests that single public member and uploads only it.

The default `dataClass` is `upstream-writer-synthetic`. The optional
`operator-owned-private-observation` mode additionally requires explicit private-source authority
in `/etc/cryptad-certification/sharesite-topology/operator-source-selection.json`. That file is
root-owned, readable only by root and the dedicated runner group, with no group write permission
(for example mode 0640); its parent is root-owned and not writable by the runner. It has exactly:

- `schemaVersion: 1` and `sourceKind: stopped-private-snapshot`;
- private `sourcePath`, `sourceDigest`, `sourceBytes`, `maximumBytes` and `selectedIndex`;
- the public plan's semantic `planDigest`, selected node `role` and authorization `expiresAt`.

Do not place this private selection, its digest or a commitment to its source fields in the public
plan, observation or artifact. The source is selected only by this fixed authority file; an
arbitrary dispatcher path or a caller Boolean is insufficient. The snapshot must be a runner-owned
mode-0600 regular single-link file under `/var/lib/cryptad-sharesite-private-sources`, with mode-0700
accessible private directories, no symlinks/traversal, and exact authorized bytes. The implemented
selection supports one record index and at most 1 MiB of source snapshot. These are producer bounds,
not permission to read a real user's data.

The adapter validates authority before opening the source, snapshots the exact bytes privately,
runs the same converter/guarded app path and checks source preservation afterward. Its operation
deadline is bounded by both topology authority and private-selection expiry. The known public
upstream fixture cannot be relabeled private. Private paths, body/source hashes, selections,
backups and comparison data remain local even when conversion fails. Retained snapshots and
backups require the reviewed private retention/cleanup procedure; temporary-file deletion does
not prove the full migration cleanup case.

Before launching each migration JavaScript stage, the supervisor durably reserves its entire HTTP
allowance: 64 requests for import, 96 for recovery, and 256 for restore including quota cleanup.
The fixed driver enforces one shared request counter across all operations in that stage. Reads,
writes and denied requests consume capacity. Insufficient capacity prevents launch; a failed or
unknown child outcome retains the full charge, and the runner does not automatically refund or
repeat it. These reservations are included in the approved `maxOperations` budget in addition to
normal supervisor bootstrap and restart operations.

No private source or live migration was executed for this change. Even an authenticated
operator-private observation retains `realDataMigration: not-observed`; independently verified
real-user completion needs its own evidence. Neither data class performs CHK publication. Browser
literal preview, bundle rollback and complete cleanup remain missing adapter cases, and private
source secret-exclusion coverage is not inferred from the synthetic canary. The separate recovery
cohort is needed for implemented private-restore and quota stages.

## Remaining implementation and observation gates

The protected persistent control workflow, original projection producer and private migration
selection capability are implemented. They have not been executed against authorized resources.
The current change is not full PR-300 implementation readiness: complete catalog channel,
mirror-fallback, conflict and lifecycle coverage; the full app-budget/resource baseline matrix;
Mail restore and unsafe-daemon-downgrade drills; complete origin/process-token denial; and complete
Mail canary surfaces remain gaps. Missing actual selected historical/independent directions also
remain explicit. A prepared supervisor does not supply measured long coverage, and the existing
release authorities still need their exact scenario/duration/freshness/freeze adapter mapping.
No local or protected aggregate may turn these missing cells into pass or release eligibility.

## Source-pinned profile comparison

The source comparison executes immutable Git blobs, not the working tree with an old label:

```bash
python3 tools/release-certification/certify.py cross-version-soak profile-compare \
  --previous-source EXACT_PREVIOUS_40_HEX_COMMIT \
  --current-source EXACT_CURRENT_40_HEX_COMMIT --out-dir NEW_PROFILE_OUTPUT
```

It materializes only the fixed SDK/controllers and the selected public corpus, verifies their
identities, and runs them in separate Node VM contexts. Generated Feed documents cross both
directions. Signed profile/social/outbox corpus verification executes the actual selected readers;
it does not pretend that fixed documents were generated by an old vault. Public output binds
source files, runtime, adapter and corpus, and reports unsupported directions explicitly.
This is first-party local conformance with synthetic storage/DOM ports, not a real browser,
network operation, original signed release or independent implementation. The original five
profiles and experimental Mail descriptor retain their existing statuses.

## Privacy, recovery and handoff

All process logs, FCP transcripts, cards, CHKs, source snapshots, backups, session values and
private comparisons stay under the owner-only operational root. Ordinary public export creates
a new allowlisted summary and runs shared redaction before writing. Do not upload a work tree,
raw exception, journal or a private content/reference hash. Public code/product/corpus digests
are distinct from private content hashes.

Cleanup stops only resources owned by the supervisor and preserves private data for explicit
retention/recovery. `cleanup-incomplete` is a failure requiring reconciliation, not authority for
a broad kill or recursive deletion. Stopping a node, deleting a local draft or cancelling a queue
request does not recall network content.

PR-301 retains Mail key expiry/renewal/rotation and recovery-resume design/drills, external consumer
review and independent security review. PR-303 must separately verify real measured long duration,
original authorities, remaining maintenance/transparency requirements and tracker dispositions.
Neither this implementation nor its local tests complete Phase 12.

## Baseline verification record

PR-300 starts at `07600553ab359546632c5633ef989b988eb4e276`, containing PR-299 squash
`239c6a1e3916ae332e958f54d591d1578cfa0b79`. The inspected feature and GitHub merge commit
`e03e2c94fc3639ab11105e55f0092d2149d85ca5` have the identical tree
`9b191ec595e0906828e7d2be20790a8147640914`.

Private reproduction of the CI-safe production-beta workflow on that tree failed. Observing the
native failed summary before normal safe removal found 15 `raw-content-or-app-data` findings:
copies of the SDK's dynamic `payloadBase64` object construction in seven ZIPs, seven staged apps,
and the SDK JAR. The squash already replaces that construction with `URLSearchParams` and adds a
regression that still rejects embedded payloads. The corrected CI-safe pipeline passed locally
with zero redaction findings, `promotionReady=false`, and `decision=no-go`; its 20 self-tests passed.
Redaction and upload blocking were not disabled. This finding is not evidence of a leaked secret.

The separate inspected supply-chain run still reports failure without jobs; its cause remains
unestablished. Exact-head GitHub checks must be re-queried after authorized publication. Local
checks cannot be attributed to a different commit, PR merge commit or protected run.
