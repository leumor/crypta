# PR-304 exact runtime subjects and measured consumers

PR-304 is the dependency-selected Phase 12 remediation for exact daemon, API and app subject
binding. It does not start Phase 13 or create a release authority. The existing maintenance freeze,
original app projection and root-owned runtime supervisor retain their separate responsibilities.

## Starting identity and assessment

Implementation began on clean develop commit `27e478c2d1d72ce9f05925626e16c0c1fdcc8c71`,
tree `96f6fe8d7c17ed7a8beccaddb7625dae4c39daff`. PR #1405 was confirmed merged at
`2026-09-11T05:11:14Z`. Its planning/final feature commit
`07db8a53226cf3ee6ea5184022d16cc9c866254d` has the same tree as this squash integration.
Neither identity is a candidate product, predecessor product or protected execution receipt.

The original evaluator was run and verified at fixed assessment time `2026-09-11T05:13:26Z`
with a fresh private output root. It reported 49 mandatory requirements, 47 unresolved,
`phaseDecision=incomplete` and `phaseComplete=false`. Those numbers describe missing acceptance
dimensions, not a count of unimplemented features. Historical open-item Markdown and repository
status bytes remain unchanged.

## Audited gaps and selected changes

| Audited gap | Supported implementation and retained boundary |
| --- | --- |
| Maintenance v1 has no API/app freeze relationship | Closed v2 private metadata binding; unchanged historical v1 bytes and public assets |
| Current tool can describe its own API classes | Fixed isolated export from selected packaged JAR; explicit historical ABI bridge with no fallback |
| Existing first-party producer requires a future freeze and omits experimental Mail | Prefreeze operation under the existing maintenance authority; Stable and experimental catalogs remain separate |
| App-bearing maintenance selection rejects before supervisor admission | Original complete roster, Java admission and exact per-role products reach the existing typed capability |
| Older selected build need not be the actual named predecessor | Producer validates owning lineage before freeze; consumer matches independently authenticated release/build/product and rejects archive aliases |
| Blocked-only measurement v1 cannot express a supported component | Measurement v2 and supervisor report v3 bind original product/journal derivation; nine parent rows remain blocked |
| Historical policy pins cannot be rewritten as new evidence | Immutable PR-303 policy copy and explicit version-2 implementation disposition; mandatory acceptance scope unchanged |

## Producer and version boundaries

The prospective maintenance producer builds packages once, authenticates the original selected
app projection and its exact scoped sources, exports the selected portable JAR's API snapshot and
complete baseline registry, and runs native signed app admission against those exact bytes.
It seals `runtime/runtime-subjects.json` before the maintenance freeze binds that manifest.
The manifest never includes the final freeze digest. Original producer attestations cover the
freeze, public checksums and assets, and the private runtime members.

The pre-freeze signed app handoff belongs to the existing maintenance workflow. Its closed
original producer class is distinct from post-freeze independent reproduction. Runtime inventory
v3 carries that distinction; original API inventory v2 keeps its existing authority semantics.
The handoff must precede projection and freeze and cannot require a future freeze or publication
receipt. Stable seven and experimental Mail remain separately cataloged.

The two app operations are `produce-app-products` (Stable seven) and
`produce-experimental-app-products` (Stable seven plus separately cataloged experimental Mail).
Both app-product operations omit `expected_predecessor_pointer_digest` and reject a supplied
value: no daemon predecessor is authenticated by app-product preparation. Freeze, authorization
and publication operations still require an exact SHA-256 predecessor pointer digest.
They use the existing protected maintenance evidence environment. Set
`CRYPTAD_MAINTENANCE_APP_ARTIFACT_BASE` to the owner-approved artifact URL base and retain the
existing app-signing and `STABLE_CATALOG_SIGNING_*` environment secrets only in the producing job.
Catalog and app signing identities must be distinct. These operations prepare and attest bytes;
they do not publish a catalog or activate an app.

The prospective freeze manifest's `maintenanceRuntimeInputs` directory contains `cohort.json`,
`projection-selection.json` with `{"coordinates": ...}`, and separately scoped public trust
registries under `trust/<registry basename>`. The cohort pins the original authenticated tool
artifact and complete approved materialized JDK tree. Preparation dereferences internal links
from the setup-java installation into a new private `maintenance-runtime-jdk` directory, then
compares its exact tree digest to the existing `javaTreeDigest`. The prepared cohort uses that
staged path throughout projection and observation; the approved digest is never rewritten.
Dangling/cyclic links, links outside the selected installation, special files, excessive trees
and changed bytes reject. Link-free validation remains mandatory. Distro JDKs that link external
configuration files are not supported by this internal-link adapter. The freeze helper materializes
these exact inputs in its protected ephemeral job. Release-signing credentials never enter the
persistent runtime supervisor. The installed cohort remains root-owned and is readable only by
root and the producing runner's primary group (`0640`); its directory remains root-owned without
unprivileged write access. The producer runs as the ordinary runner. Offline metadata validation performs no process execution or
network collection; original artifact collection and exact-package observation are explicit
producer/admission operations.

Freeze v1 remains immutable. A strict version dispatcher accepts original v1 and prospective closed
v2; v2 adds `runtimeMetadata` while leaving the public asset roles and public checksum rows intact.
The metadata directory contains the manifest, exact snapshot, complete registry, original projection
inventory, and native admission declarations. These internal members remain outside public release
assets and publication plans. Preparation and frozen handoff retention preserve their original bytes.

The fixed `network.crypta.platform.api.PackagedApiExport` entry point takes no arguments. It emits
static contract and complete registry JSON as exact strings. Protected orchestration extracts only
`lib/cryptad.jar` from the governed portable archive and invokes that fixed class in an isolated,
credential-free, bounded process with a controlled classpath. Archive and executable identities are
checked before and after observation. Snapshot byte digest and canonical static contract digest
are distinct. Matching integer labels cannot conceal a different surface. The `/api/v1` URL,
integer contract, baseline name and integer daemon build remain separate identities.

The fixed historical bridge uses a platform-parent isolated classloader and four reviewed ABI calls
on the selected original JAR. It cannot fall back to API classes on the current helper classpath.
An unsupported original ABI remains blocked. The observed snapshot is labeled
`observed-from-original-package`, never `frozen-with-original-release`. Original RC app-product and
portable producer authorities remain distinct; this observation does not independently authenticate
GA publication. The prospective freeze first reuses the owning maintenance validator's GA-root and
latest-predecessor graph checks. Runtime admission then matches its authenticated predecessor
release/build/source/product identity against the independently reopened original product.
The prospective observation additionally binds the predecessor source commit; v1 remains unchanged.
GA publication and original RC release IDs may differ, so that path compares the exact RC product
digest, source and integer build and retains both names instead of demanding universal equality. A GA-derived
RC product is therefore selected through the owning release's predecessor observation, without
requiring the historical GA to possess future freeze-v2 metadata. A maintenance predecessor keeps
its original maintenance-product authority. The original candidate observation's baseline, receipt,
pointer and clock remain explicitly labeled `candidate-freeze-observed-published-predecessor`.
The same archive cannot be relabeled as the candidate's predecessor.
A historical source rebuild is never an original shipped package. Gates requiring original frozen
API evidence remain blocked when that authority lacks it.

## App sets and admission

The complete shipped Stable set remains the original seven first-party apps. The independently
approved experiment cohort comes from the existing protected app-subject policy and authenticated
inventory, including its external submission and explicit experimental Mail opt-in. The per-role
installed subset is separately fixed: sender and recipient use Site Publisher, Feed Reader and
opted-in Mail; the predecessor uses Site Publisher and Feed Reader; the relay installs no apps.
Omitting a required role app rejects. Experimental Mail does not enter the Stable shipped set.

The Java subject-projection command retains its original v1 declaration mode. Paired `--contract`
and `--baseline-registry` inputs select a prospective v2 declaration after exact registry-summary
verification and shared native `PlatformApiAppAdmission`. The separately identified release
`strict-tested-range` policy remains stricter than ordinary runtime warning semantics. Static
admission grants no permissions and establishes no successful runtime scenario. Ordinary AppHost
publisher, review, origin, sandbox, consent and source-pinning rules continue to apply. Selected
federation projection remains unsupported; keys are not merged globally to bypass scoped trust.

## Admission, observation and consumers

`authenticate_products` consumes original maintenance v2 freeze artifacts and independently
reauthenticates their app projection. Its existing sealed in-process capability binds the exact plan,
archive and required private app paths. Root supervisor activation preserves the safe identities;
launch and continuation recheck exact inputs and corroborate the running static contract surface.
A plausible endpoint or serialized admission flag cannot create original authority.

Historical measurement v1 remains blocked-only diagnostic data. Prospective measurement v2 derives
separate subject admission and journal derivation components from the exact plan, original journal,
checkpoint and admitted product rows. Supervisor report v3 binds their complete product-set digest
through start, checkpoints and finish. Phase 12 reopens the original report chain and recomputes the
measurement at its original evaluation cutoff; later assessment does not refresh observation time.

A narrow subject/derivation component can pass while every broader maintenance row remains blocked.
All nine rows retain their named missing adapter reasons. Required case/direction sets, routine or
hotfix policy windows, cleanup and uncertain outcomes remain separate. No supplementary caller
subcase, requested duration, fake clock, node-hour sum or pre-freeze work satisfies observed coverage.
A changed freeze or app cohort requires a new admission and experiment binding.

## Remaining work and authorization

Federated projection/catalog-origin runtime coverage is the provisional PR-305 dependency handoff.
Scheduler pressure, historical and independent profile readers, migration and Mail recovery,
complete API/runtime and sandbox/security/support cohorts remain separate adapter work. Original
provider configuration, independent reviews, real observations and public deployment proof retain
their owners. Full `p12-300-consumers`, `p12-300-adapters`, `p12-300-72h` and Phase 12 completion are
not established by these local components.

No protected workflow was dispatched, catalog or release published, live node operated, real Mail
or migration data accessed, PR merged, or 72-hour experiment performed during this implementation.
Synthetic test authorities and transport seams cannot be selected as production trust flags.

## Local verification record

`./gradlew spotlessApply test` passed with 17,201 JUnit tests, zero failures or errors and ten
skips. The skips cover a disabled benchmark, Windows/non-Linux directions and existing
crypto/provider assumptions. After the final native edits, focused admission/projection/export
checks passed 37 tests without skips (20 API admission, 16 signed projection, one real compiled
implementation/classpath test). These are local results, not hosted exact-source receipts.

`./gradlew build assembleCryptadDist :platform-devtools:installDist` passed. Local Linux DEB
packaging ran; RPM was skipped by the current environment, and other native operating-system
packaging was not executed. The final devtools formatting, tests and SpotBugs test task passed.
Inspected SpotBugs reports retain existing findings: API main/test 139/27; devtools main/test 8/9.
None refer to the touched admission/exporter/projection/fixture classes. Existing compiler warnings
remain, and SonarLint tasks were skipped by repository configuration; task success is not an
analyzer-clean claim.

| Python check | Final local result |
| --- | --- |
| cross-version-soak | 92 passed |
| stable-platform-api-1x | 88 passed |
| stable-maintenance | 243 passed |
| stable-maintenance-drill | 13 passed |
| stable-supply-chain | 86 passed |
| phase-12-closeout | 175 passed |
| stable-rc | 55 passed |
| stable-ga | 83 passed |
| public-ecosystem-transparency | 91 passed |
| release-certification | 50 passed |
| protected unittest discovery | 85 passed |
| Real signed producer/product/journal/Phase12 integration | 1 passed, 89.098 seconds, no skips |
| Focused supervisor / runtime / measurement checks | 16 / 66 / 14 passed |

The protected suite includes 11 bounded package/metadata tests and five owning GA/maintenance
predecessor-graph tests. The integration signs actual app bundles and catalogs, observes two
compiled API implementations with the same contract integer, and executes both maintenance and
historical product branches through native admission and original-context measured consumption.
Wrong package, API surface, cohort, original predecessor and source identities reject. Provider
transport/attestation and OS-ownership seams use isolated test authorities. It does not claim to
run a protected release, a live daemon workload, or the full production packaging matrix.

Actionlint passed for CI, maintenance and supply-chain workflow changes. The ordinary Linux PR
integration job builds the native tools and fails if the integration is skipped; it uses no
production secrets or protected environment. Its hosted execution has not occurred here.
`git diff --check` passed. Long-running release-certification checks were allowed to finish.

## Acceptance-policy successor and fixed-time result

Policy version 2 records the explicit `pr304-runtime-subject-binding-successor` scope decision.
The exact prior policy is retained under
`tools/release-certification/history/phase-12-acceptance-policy-pr303.json`. All 49 mandatory
requirement IDs, assertions, dimensions, subjects, prerequisites, owner mappings, closure rules
and original historical inputs remain unchanged. Updated implementation paths and their exact
source/test pins cover the producer, exporter, product admission and narrow original consumers.
This is a reviewable implementation delta, not permission to close missing operational evidence.

| Identity | Prior PR-303 | PR-304 successor |
| --- | --- | --- |
| Policy byte digest | `sha256:2217b58c2ff3f316f0105d1f93bba8122921ff35d42c836910bf9ec37d11ca3e` | `sha256:9a61b4b20646f1738c0cf0878580b37e1a2eb4f1d16c692144055e484c2f846e` |
| Effective evaluator tool digest | `sha256:7e8b217a90b16e67bba111f5eabcee294c787322b356e044846b8d98e0b1966e` | `sha256:b7264903947b87f06feab39c0c4fdaf7ca8ea4a2d0ad0c7149fa37c431379d2d` |

The evaluation and verification used `2026-09-11T05:13:26Z` in separate fresh private roots.
Both assessments report `phaseDecision=incomplete`, `phaseComplete=false` and 47 unresolved
requirements. Both `--require-complete` checks reject with exit 2. The original assessment and
historical source bytes were retained. The precommit assessment’s checkout commit/tree identify the starting
integration; its effective tool digest and policy source pins identify the prepared changes.

| Requirement | Prior implementation | Successor implementation | Other repository-only dimensions |
| --- | --- | --- | --- |
| p12-300-products | partial | implemented for the supported contract | localVerification not-run; originalProvenance not-supplied; coverage missing |
| p12-300-consumers | partial | partial | localVerification not-run; originalProvenance not-supplied; coverage missing |
| p12-296-subjects | implemented | implemented | localVerification not-run; originalProvenance not-supplied; coverage missing |

The evaluator does not import this local test log as an authenticated original evidence selection,
so `localVerification=not-run` in those requirement rows is expected despite the separate tests
above. `product-subject-binding` retains its original open reason and clock, with an explicit
`implementation-prepared-observation-outstanding` disposition. Federation, complete adapters,
72-hour coverage, Mail/migration scenarios, independent providers/reviews and public proof remain
open. The unresolved count was not used as an acceptance target.

PR-305 remains the next implementation workstream after this supported foundation: selected
federation projection and catalog-origin runtime coverage. The assessment continues to retain
product-original observation prerequisites; it does not treat prepared code as their fulfillment.

The cohort installation regression executes the actual workflow install commands in a temporary
directory as an unprivileged Linux user. It confirms native cohort loading succeeds, direct writes
and unlink attempts fail, and an unrelated user cannot read the file. It requires passwordless
sudo and reports a skip when that hosted-runner prerequisite is unavailable. No system `/etc`
configuration is changed by the test.

The JDK preparation regression exercises the actual preparation function with internal shared
legal links and an independently specified materialized identity. The full compiled-package
integration also invokes the production JDK staging helper before native execution. Original
provider authentication is isolated in the preparation test; no JDK is downloaded or executed
before the approved staged digest matches.

Both packaged exporters use Java 25 package-private static entry points; the historical
exporter also uses an unnamed catch parameter. Their stdout JSON and the historical exporter's
fixed stderr failure code remain protocol output with method-scoped S106 suppressions. The actual subprocess export integration passed after this
cleanup, and file-level SonarLint reported no findings.

The first PR-304 hosted integration attempt failed during JDK setup because its Java version
selector was not accepted by `setup-java`. The ordinary CI job now uses the supported Java 25
selector shared by the other CI jobs. The successor policy refreshes only the affected workflow
and test byte pins; acceptance scope and historical policy bytes are unchanged. Protected release JDK
selections are outside this correction. Hosted execution must be verified against the new head.
The same job also requested `:platform-api:jar` explicitly, which the repository build guard
rejects. Its build command now requests only `:platform-devtools:installDist`, whose dependency
graph produces the required API JAR. The test prerequisite diagnostic uses the same command.

The hosted Ubuntu runner also denied Bubblewrap's isolated loopback setup (`RTM_NEWADDR`).
An early no-product sandbox probe reproduces this prerequisite failure directly. The shared disposable-runner setup
loads a checked-in AppArmor user-namespace permission attached only to `/usr/bin/bwrap`.
AppArmor and the system-wide user-namespace restriction remain enabled; the exporter retains
`--unshare-all`, read-only input mounts, bounded temporary storage and execution limits. This
runner setup now also runs prospectively in the freeze job; no protected workflow or live
system was operated while implementing it.

A subsequent coverage pass added ten Java regression cases: selected-target admission below the
app's minimum, incomplete/malformed projection targets, unexpected exporter arguments, missing or
malformed historical packages, absent historical API classes despite a populated helper classpath,
and manifest-supplied external classes. The three affected test classes passed 47 tests with no
failures, errors or skips. Production Java is unchanged. The successor policy refreshes the existing
exporter integration-test byte pin without changing scope or treating these tests as runtime receipts.

Review follow-up: app-product preparation selects each app's unique packaging output, so the
Site Publisher `3.1` app version remains independent of the daemon build number. Missing,
ambiguous and linked package inputs reject; native signed manifest/catalog verification remains
mandatory. Ordinary integration and `freeze-candidate` now share
`.github/actions/setup-packaged-export-sandbox`, provisioning Bubblewrap and its scoped AppArmor
profile and testing isolation before any freeze metadata is sealed. The signed integration fixture
uses the independent Site Publisher version to exercise the actual producer.

Projection tools retain their separately approved `toolOriginal.sourceCommit`. That tool revision
need not equal the candidate, predecessor, or consuming workflow SHA. Original artifact
authentication and member attestation verify the pinned tool source/signer and run attempt, then
both archive and installed-tree digests must match the protected cohort. The develop-only tool
producer remains unchanged. Preparation tests exercise distinct cohort/consumer/tool revisions
and reject wrong source proofs, attempts, producer families and installed bytes; the signed
producer/consumer integration uses a third tool revision distinct from both daemon products.

An exporter-only coverage pass adds eight subprocess regressions for exact JSON envelope bytes
and preserved snapshot whitespace, symlink/directory rejection, and compiled historical ABI
failures (missing method, throwing factory, initialization error and wrong serializer return
type). Both production exporter classes are unchanged. All 16 tests in the owning exporter
integration class passed locally with no skips; the symlink case is scoped to Linux/macOS.
These are local tests, not protected release receipts or a measured coverage percentage.

The macOS CI fixture correction resolves the temporary root before constructing authenticated
product paths. A symlinked temporary root reproduced the original package-substitution rejection
on Linux; after correction all 23 product-admission tests passed under the same setup. Production
symlink rejection remains unchanged. The successor policy refreshes only that test's existing
source digest; requirement scope and historical inputs are unchanged.

Exporter subprocess tests now propagate the test worker's JaCoCo agent with append enabled and
instrumentation restricted to the two production exporters. The fixed commands, clean environment,
exact fixture package bytes, process exit checks and private diagnostic assertions remain intact.
Recompiled fixture contract classes do not contribute coverage. API and root coverage reports and
verification tasks include devtools execution data, because those tests execute the API exporter
across the module boundary. This changes test measurement only, with no production instrumentation,
coverage exclusion or threshold change.
The local JaCoCo XML, mapped to SonarCloud PR 1406's current new executable lines and conditions,
records 74/75 covered lines and 23/26 covered conditions: 97/101, or 96.0% new-code coverage.
The native exporter is 100.0% and the historical bridge 91.7%; the other two changed production
classes remain at 100.0%. These are locally measured results; the hosted percentage requires
the subsequent CI scan. The bridge's remaining defensive classloader branches stay in scope.
The final exporter suite adds a positive ordinary-manifest case (no external Class-Path), exercising
the layout accepted for real package manifests, and passes all 17 tests. Both module suites pass
(261 devtools, 1,165 API); the preceding full test/report run recorded 17,220 tests with zero
failures/errors and ten existing platform, benchmark and crypto-condition skips.

The protected Python discovery fixtures also canonicalize temporary roots for JDK preparation,
app package selection and runtime metadata checks. Running the full protected suite under a
symlinked temporary parent reproduces the macOS path-precondition failures; after correction all
91 tests pass locally. An explicit regression still rejects a symlinked subject parent even when
the file bytes match. Only test-source pins change; production path checks remain intact.

Prospective app handoffs bind their authenticated `releaseId`, integer `buildVersion` and product
`sourceCommit` to the candidate freeze before sealing. Cohort production also compares release
and product source, so changing only the cohort header cannot relabel an older app handoff.
Every first-party or experimental Mail source in a prospective freeze must use the maintenance
app-product authority; external submissions retain their separate reviewed authority. The original
artifact coordinates still bind the workflow revision, signer and attempt, which may legitimately
differ from the separately attested product source. No universal SHA equality is introduced.
The real producer/exporter integration rejects substituted release, build and source identities
without emitting a frozen artifact or retaining runtime metadata; isolated test authorities do
not create operational receipts. Existing historical formats keep their original meaning.

Normal maintenance and security-hotfix candidate authentication now includes the authenticated
predecessor source commit in its default freeze-observation mapping. Explicit follow-up mappings
remain authoritative. The caller regression fails for both normal release classes without this
fix; v1 remains compatible and v2 still rejects a substituted predecessor source independently
of its runtime-metadata gate. No schema, historical input or acceptance scope is changed.
