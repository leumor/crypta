# Phase 12 acceptance audit and operational closeout

Use `phase-12-closeout` to reconcile the accepted PR-291–303 requirements with exact source,
original evidence and the existing owning verifiers. A successfully executed audit can report
Phase 12 incomplete or blocked. Passing the audit's self-tests, merging PR-303 or publishing its
public view does not complete Phase 12.

The evaluator is bounded and read-only with respect to release and runtime state. Python 3 is
required. Local evaluation does not build a product, freeze an RC, start nodes, run a migration,
rotate keys, deploy a site or grant publication authority.

## Reproduce a repository assessment

Run from the repository root. Output directories must be fresh; retain each completed assessment
unchanged. Use the same fixed evaluation time and exact selection when verifying it.

```bash
python3 tools/release-certification/certify.py phase-12-closeout --self-test
python3 tools/release-certification/certify.py phase-12-closeout --mode inventory
python3 tools/release-certification/certify.py phase-12-closeout \
  --mode evaluate --as-of 2026-09-10T21:01:59Z \
  --output build/phase-12-assessment
python3 tools/release-certification/certify.py phase-12-closeout \
  --mode verify --as-of 2026-09-10T21:01:59Z \
  --assessment build/phase-12-assessment/phase-12-assessment.json
```

Without a selection, evaluation uses the complete checked-in requirement inventory and no
operational artifacts. This is useful for reporting the actual repository gaps. It invents no
receipts. Add `--require-complete` to the evaluation or verification command when using it as an
acceptance gate; an incomplete or blocked assessment must fail that gate even when its local
consistency is valid.

`inventory` also lists each finite adapter's exact required filenames and emits a selection
template. For a selected adapter, place those files under `<source-root>/<artifact-id>/` and bind
their exact byte digests and sizes in the selection. The input root may contain only the selected
members. Use the owning native evidence formats; a locally resealed summary cannot replace an
original receipt, protected context, product archive or signed declaration. The selection
schema and adapter checks reject unsupported members and scope substitutions.

For `site-deployment` and `site-observation` bootstrap evidence, retain the required `previous.zip`
member as a zero-byte file, with size `0` and the SHA-256 digest of empty bytes in the selection.
The site owner requires that marker when `previousManifestDigest` is absent and verifies the
bootstrap checkpoint. A selected predecessor instead requires its actual archive. Every other
artifact member remains nonempty; the bootstrap marker grants no original operational authority.

The private output contains `phase-12-assessment.json`, `phase-12-assessment.md` and
`phase-12-remediation-plan.json`. `--mode public-export` first recomputes the selected assessment
and writes the closed public status to the requested separate file. Its output root must not
overlap the private assessment or original evidence root.

```bash
mkdir -p build/phase-12-public
python3 tools/release-certification/certify.py phase-12-closeout \
  --mode public-export --as-of 2026-09-10T21:01:59Z \
  --assessment build/phase-12-assessment/phase-12-assessment.json \
  --output build/phase-12-public/phase-12-public-status.json
```

The example evaluation time is a reproducibility parameter, not an observed operational time.
Every supplied original retains its own producer, completion and observation times; freshness and
pre/post-freeze relationships must pass its original policy. A later evaluation does not refresh
an old receipt.

## Audited identities and immutable context

The starting checkout for this implementation was commit
`0b48951ebc7d3ea128a9e9d7d1cc73ec69011c6c`, tree
`08a29bc9ddb1fe90649c8bfe091eab99ac1b3a16`. This is distinct from the planning inspection's
PR-302 feature head `e6f67e979103c029b8a317249dc5df1663aa1cdc` and tree
`4339fc0ccb48b5bfe286e5a416abf3e1e01cae26`. A PR test-merge checkout or a later squash requires
its own identity reconciliation; a test merge SHA does not prove a merge was completed.

The refreshed [PR #1404](https://github.com/crypta-network/cryptad/pull/1404) record reports it
merged at `2026-09-10T19:26:13Z`. Its final feature head was
`c35302fbcc3394cee5e4c0c917e5dd3948744a4b`, whose Git tree equals the starting squash tree.
That establishes the code integration relationship; it transfers no protected authorization.
The planning head was amended before this merge.

The original hosted records inspected during implementation distinguish these scopes:

| Original source | Run, attempt | Observation |
| --- | --- | --- |
| Final PR-302 feature head | [Transparency 34517525094](https://github.com/crypta-network/cryptad/actions/runs/34517525094), 1 | Offline job succeeded; protected build, transfer, deploy and observe jobs were skipped. |
| Final PR-302 feature head | [Java CI 34517525352](https://github.com/crypta-network/cryptad/actions/runs/34517525352), 1 | Workflow succeeded. A build check retained ten warning annotations; inspected samples concern third-party Mantissa `PreferThrowsTag` Javadoc. This is not an analyzer-clean assertion. |
| Final PR-302 feature head | [Beta pipeline 34517525255](https://github.com/crypta-network/cryptad/actions/runs/34517525255), 1 | Dry-run/release-candidate path succeeded; production-beta was skipped. |
| Starting develop squash | [Java CI 34520399583](https://github.com/crypta-network/cryptad/actions/runs/34520399583), 1 | Succeeded; completion record updated at `2026-09-10T19:51:40Z`. |
| Starting develop squash | [CodeQL 34520398182](https://github.com/crypta-network/cryptad/actions/runs/34520398182), 1 | Succeeded for this integration identity. |

These are historical online observations of those sources. The local PR-303 edits have no hosted
attempt. Retained API JSON is not a portable authentication capability. Original raw test totals,
skips and complete analyzer reports must still be admitted for exact-source closeout; a workflow
conclusion or a selected warning sample cannot supply them.

The [acceptance policy](../tools/release-certification/phase-12-acceptance-policy.json) records
reviewed implementation assertions and exact source/test byte pins. These pins establish which
reviewed source assertion applies. They are neither source-presence heuristics nor records that
those tests executed. Drift in the affected source invalidates that implementation assessment;
it does not require historical released products to share the audit tools' commit.

The policy preserves exact pins for the [open-item tracker](phase-12-open-items.md), the original
[public repository statement](../tools/ecosystem-transparency/repository-status.json), and the
[Phase 11 closeout](../tools/release-certification/stable-1.0-assurance-closeout.json). The public
statement's original clock is `2026-09-10T12:09:39Z`; its source commit is
`ca54bcbc16f30a4edaf72f813a287ddc3a40e165` and source tree is
`5a4e6cdc3f9b3406c34d6e8545f758d9c07b7af6`. These historical statements are not operational
receipts. The Phase 11 file's implementation-delivery closeout cannot close unfinished Phase 12
implementation or protected operations.

## Requirement ownership

The inventory has 49 mandatory assertions. Every assertion retains its permanent ID, owning PR,
precise scope, original verifier/schema/policy, reviewed implementation/test pins, required
dimensions, mandatory subjects, prerequisites and closure conditions. The caller cannot shrink
the requirement set, substitute another app cohort or declare a mandatory assertion inapplicable.

| IDs | Owning authority | Separate acceptance boundaries |
| --- | --- | --- |
| `p12-291-*` | [Protected release execution](stable-1.0-protected-release-execution.md) | Exact RC freeze, post-freeze GA validation, explicit publication and independent public observation. |
| `p12-292-*` | [Independent reproduction](stable-1.0-independent-reproducible-build-verification.md) | Complete subject comparison and real provider-distinct original authority; same-provider evidence retains its original meaning. |
| `p12-293-*` | [Catalog and key ceremony](stable-1.0-catalog-publication-and-key-ceremony.md) | Role/recovery keyset, primary/mirrors, six rotation/recovery/rollback drills and separate key-transparency publication. |
| `p12-294-*` | [External app pilot](stable-1.0-external-third-party-app-pilot.md) | Real immutable external source, reviewed/rejected/resubmission/caution cohort and installed lifecycle/cleanup. |
| `p12-295-*` | [Federation](stable-1.0-federated-catalog-discovery-and-trust.md) | Local scoped trust, conflict resolution and installed-origin/consent/rollback/privacy. |
| `p12-296-*` | [API 1.x operations](platform-api-1.x-compatibility-operations.md) | Immutable 1.0 baseline/history, v2 signed app cohort, unsupported federation projection and runtime directions. |
| `p12-297-*` | [Sharesite migration](real-legacy-plugin-migration-pilot.md) | Plaintext conversion, recovery, private source observation, independent real-user confirmation and separately authorized publication. |
| `p12-298-*` | [Profile review](trust-social-stable-profile-review.md) | Exact-v1 maturity disposition, current executable interoperability and historical/independent directions. |
| `p12-299-*` | [Mail prototype](mail-app-service-prototype.md) | Authenticated vault/worker boundary, actual two-node ciphertext delivery, privacy cohort and independent review. |
| `p12-300-*` | [Cross-version soak](cross-version-live-network-soak.md) | Exact daemon/app/API products, complete runtime adapters, one qualifying continuous 72-hour epoch and measured consumer admission. |
| `p12-301-*` | [Maintenance drill](stable-maintenance-operations-drill.md) | Exact predecessor/train/freeze, fourteen isolated cases, same-key renewal, missing Mail recovery, maintenance publication/activation, and distinct support-lifecycle publication/observation. |
| `p12-302-*` | [Public transparency](public-ecosystem-transparency-site.md) | Typed disclosure/original proof, deterministic bundle, actual protected deployment and original bounded public observation. |
| `p12-303-*` | This audit | Complete reconciliation, exact-source hosted CI/analyzers and restricted public projection. |

The Sharesite-to-Site-Publisher selection is the accepted plaintext scope. FlogHelper is an
abandoned alternative, not deferred debt. Feed remains stable; retaining experimental Profile,
Trust, Social Message/Outbox and local `trust.score` can satisfy the maturity review. That
disposition does not waive their required historical or independent interoperability directions.
Experimental Mail status does not waive lifecycle recovery work.

The inventory's recorded scope decision separates maintenance successor activation from support
descriptor publication and observation. Both remain mandatory. The first uses the maintenance
owner's exact pointer/compare-and-swap authority; the second uses the support ledger, descriptor
edition, transition and lifecycle publisher. A receipt from one cannot satisfy the other.

An initial inventory correction also aligns catalog drills with their original six-receipt
authority. That schema has no separate cleanup result, so the inventory does not mechanically
impose one or infer one from a pass. Protected publication credential cleanup remains an unchanged
producer control. Pilot, migration, soak and maintenance cleanup obligations retain their own
requirements. Both scope decisions are recorded in the reviewed inventory.

## Evidence admission and adapter limits

Each selected logical artifact binds its exact bytes and size, original type/authority, source,
subject relationships, applicable environment and original workflow/run/attempt/job. Semantic
digests remain separate from byte digests. Original proof is authenticated before interpreting
protected producer claims. A locally matching hash, reupload, JSON success field or signature on
another subject cannot construct a protected authenticated capability.

The finite adapters call existing signature, subject, cohort, profile, measured-journal,
maintenance-drill and transparency verifiers. Their grants are scoped to what those calls actually
verify. For example, a valid signed catalog keyset does not establish a network publication, a
valid GA receipt relationship does not independently prove every missing private validation
input, and a measured local journal is not an authenticated protected run. Unsupported original
producer or consumer modes retain explicit adapter gaps. They cannot be replaced with a generic
caller-supplied verdict or an arbitrary import/command.

The original PR-291 and some PR-294 closeout paths deliberately authenticate GitHub metadata
online. Ordinary evaluation must not silently invoke that collection. Explicit original
collection is read-only and restricted to the existing producer authentication mechanism; it does
not grant access to private user data or perform an operation. Offline inputs without retained
original authority remain unverified. An offline trust-root snapshot also cannot reveal later
revocations.

Use `--collect-original` only for an explicit read-only refresh of the selected original
coordinates. Current protected capabilities cover the original app-subject projection, Sharesite
producer, measured supervisor chain, product archive admission, native protected GA closeout and
federation observer chain. They use the original owning helpers and revalidate exact selected
bytes and predecessor relationships. Protected GA checks an already-present original candidate
and release reference in an isolated local clone; it performs no fetch, rebuild, publication or
ref mutation in the audit checkout. Federation checks its upstream runtime observer separately
from the subsequent import job. Ordinary evaluation with the same retained coordinates stays
offline and unverified. No fixture trust flag is exposed.

The native GA closeout also admits the original catalog closeout's exact ceremony/keyset,
primary/mirror observations and six drills when the owner reaches `mirrors-observed`. Separate
public-key-transparency publication remains unproven by that archive. `pilot-closeout` verifies
the actual external source, complete signed review cohort, installed lifecycle/cleanup and its
original PR-291/292/293/runtime producer roots. The smaller semantic adapters remain useful for
partial inputs; they cannot substitute for these full original contexts.

Some earlier native authorities need several separately authenticated producer contexts. The
audit does not accept a convenient aggregate reupload as those contexts. Its adapters still run
the applicable native signature, receipt, archive and full-context verification; an unavailable
original-context bridge remains a fixed, actionable gap. The independent provider policy has no
operational external adapter. Lifecycle and maintenance inputs still require their original
protected handoff/backend authority, while API history requires its original producer context.
The native site adapter verifies the exact deployment bundle, Pages transfer, deployment records
and bounded observation result, but the original PR-302 contract does not retain every required
producer/body-transcript/deployment-artifact binding. Those omissions cannot be filled by
reuploading receipts. Missing original authority is different from a supplied signature or byte
binding that fails verification.

An [artifact attestation](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
authenticates origin; it does not establish inherent safety. The limitations of
[offline attestation verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)
also apply to retained trust-root snapshots. A skipped job may satisfy GitHub's
[status-check handling](https://docs.github.com/en/pull-requests/reference/status-checks)
while providing no executed operational evidence.

The direction of authority remains:

```text
original product and producer evidence
  -> signed subject projection
  -> compatibility/runtime/maintenance evidence
  -> Phase 12 assessment
  -> optional restricted public status
  -> public site
```

Required predecessors must form a DAG. Projection cannot require its future closeout, and the
assessment cannot require the site to display that same future assessment. The site requirement
uses independently existing PR-302 deployment and observation evidence. A later phase-status view
is a separate publication and must preserve the earlier exact bundle and approved source history.

## Assessment dimensions

`auditExecuted=true` and `assessmentIntegrity=verified-local-consistency` mean the bounded audit
ran consistently. `phaseDecision=incomplete` means required work or evidence remains;
`phaseDecision=blocked` records invalid supplied evidence or a blocking verification failure.
Only `complete-as-of` with `phaseComplete=true` satisfies the full selected acceptance policy.

Implementation, locally executed verification, original provenance, runtime/protected execution,
publication, activation, public observation, independent review, case coverage, cleanup and hosted
CI have separate values. Dimensions are selected by requirement scope, not mechanically imposed
on every row. Closure needs all mandatory dimensions and cases; there is no percentage threshold
or majority vote.

The current repository state must retain at least these concrete distinctions:

- PR-292 has no implemented operational external provider adapter. Templates and same-GitHub
  results cannot become provider-distinct reproduction.
- PR-296 implements first-party/external signed declarations but lacks selected federation
  projection and original protected execution.
- Sharesite browser preview, rollback and cleanup remain incomplete; synthetic conversion,
  private observation, independent confirmation and publication are separate claims.
- Source-based profile runs do not replace historical binaries, the production Trust JS reader,
  generated current Java-to-JS directions or independent implementations.
- Same-key Mail renewal is implemented. Recipient/storage rotation, account replacement,
  historical-purpose authority, safe degraded resume and host minimum-reader barriers remain
  incomplete. Restore stays paused. Live delivery and independent security review are unobserved.
- The owned soak journal/supervisor exists. Full adapter/product/consumer admission is incomplete
  and repository-reported live coverage is zero hours. Requested duration or node-hours cannot
  satisfy the required continuous 72-hour profile.
- All fourteen isolated maintenance cases can pass while implementation remains partial,
  original protected runtime remains unobserved, eligibility is blocked and publication,
  activation and independent review remain outstanding.
- The valid empty production transparency site proves deterministic local rendering. It proves
  no release inventory, approved original source coverage, deployment or public observation.

Hosted CI must identify the checked PR head, test merge or integration source and the immutable
attempt and required jobs. Skipped operational jobs, author-reported local tests and clean task
exit without inspected analyzer disposition remain separate. Previous-head success cannot retire
an exact-source blocker without explicit identity and closure evidence.

Required PR workflows follow the existing branch and path filters. The original CI adapter
uses the selected run's PR head/base coordinates and a complete original API file list, bounded
to 300 files, to determine applicability. It checks PR metadata before and after reading the list;
missing metadata, source drift, incomplete pagination or changed workflow trigger policy leaves
applicability unknown. Caller-supplied paths cannot exempt a workflow. Java-only or unrelated
documentation changes therefore do not require a transparency run when its path filter excludes
them. GitHub documents the underlying
[branch and path filter semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

The existing reusable build now retains a success-only typed report containing native JUnit
totals/skips and SpotBugs/Error Prone counts and execution clocks. The fixed producer derives
the module/source-set cohort and removes raw diagnostic payloads. The existing pinned provenance
action binds the exact artifact to its original source, signer, workflow attempt and job. The
adapter verifies those bindings and rejects incomplete cohorts, old cached reports, unexecuted
steps, skipped tests and unresolved findings. A PR product head, workflow test merge and reusable
workflow signer remain distinct identities. An authenticated matching push has a reachable
complete path under the existing no-Sonar-token owner mode. If SonarCloud actually ran, its
unavailable original external disposition remains a separate gap. SonarLint remains explicitly
`owner-skipped-standard-build`; this PR does not invent an executed SonarLint result.

## Carry-forward and next remediation

The residual ledger carries all ten approved public IDs unchanged: `pr296-federation`,
`pr297-migration`, `exact-source-ci`, `profile-runtime`, `profile-redesign`, `mail-prototype`,
`mail-lifecycle`, `runtime-adapters`, `cross-version-long-run` and `maintenance-drill`.
It also records the earlier independent-provider and protected-operation evidence gaps, exact
product binding, public deployment/observation requirements and the newly found original CI
report-retention gap. The latter retains its original reason and clock, with an explicit
disposition recording the local implementation and still-unobserved hosted execution.
There are 18 residuals, including the approved experimental-profile
limitation. A text edit, rename, deferral or
new summary cannot close an old row or reset its original clock. Closure requires an explicit
owner-authorized disposition with evidence; mandatory deferred work remains incomplete.

The generated remediation plan is a deterministic topological order of these dependencies.
High-fan-out product and consumer admission comes before another long run. The next smallest
product remediation slice is exact candidate/predecessor portable daemon, app and API binding
through the existing freeze and measured-consumer paths, with rejection tests for swapped
products, missing app-bearing subjects and wrong original producers. It must preserve historical
RC/GA bytes.

Federation projection and the missing runtime matrix follow that subject-binding slice. Mail
lifecycle, Sharesite recovery and independent profile/security reviews remain explicit
workstreams. Real long-run observation follows complete adapter admission. The separately missing
external provider adapter and approvals can progress under their original owners without being
redefined as local evidence. Any prospective PR-304 is a dependency-selected Phase 12 remediation
slice; no Phase 13 is authorized by this audit.

## Public disclosure and validation records

Detailed original receipts remain in confined private inputs. Public export admits only fixed
requirement/capability names, implementation/observation classifications, fixed blocker codes and
explicitly public identity fields. Private paths, URLs, topology, incident/contact/member
identities, messages, backup or migration data and their digests must never enter public JSON,
Markdown, downloads or errors. Public governance keys remain subject to PR-302's typed rules;
there is no directory-wide JSON exemption.

The local public status remains a repository assessment. Publishing it requires separate
authorization and PR-302's existing typed admission/history pipeline. The site never feeds its
badge back into original operational verification.

Record actual focused self-test/integration results with the exact checked source and disclose
skips and analyzer limitations. PR-303 changes certification tooling, CI report retention and
documentation. It changes no Java product behavior. The local wrapper checks below validate the
native report interface used by the new CI producer; they are not a full Java suite or a hosted
CI attempt. Predecessor CI results and author-reported test counts remain historical observations.

The original owner regression commands executed locally all passed:

| Certification self-test component | Tests |
| --- | ---: |
| `public-ecosystem-transparency` | 91 |
| `stable-maintenance-drill` | 13 |
| `cross-version-soak` | 91 |
| `stable-platform-api-1x` | 88 |
| `stable-legacy-plugin-migration` | 13 |
| `stable-content-profile-review` | 18 |
| `release-certification` | 50 |
| `stable-protected-release` | 120 |
| `stable-independent-reproducibility` | 39 |
| `stable-catalog-authority` | 111 |
| `stable-third-party-pilot` | 155 |
| `stable-federated-catalog` | 39 |
| `stable-backport` | 133 |
| `stable-maintenance` | 243 |
| `stable-lifecycle` | 120 |
| `stable-supply-chain` | 86 |
| `stable-vulnerability` | 170 |
| `stable-rc` | 55 |
| `stable-ga` | 83 |
| `app-platform-docs` | 3 |

Additional local checks passed: core self-tests (122), protected Python tests (44),
`stable-dependency-vulnerability` (304), and focused runtime integration tests (131).
The phase-specific suite and browser results are recorded with the generated example below.

Java 25.0.4.1 and the actual wrapper ran
`./gradlew :test --tests network.crypta.fs.AppEnvTest`: 13 passed, zero skipped.
`./gradlew :errorproneReport` also completed; the parser inspected 33 fresh native reports
containing 373 warnings and zero errors. The root test compilation contributes 98 of those
warnings. These are findings in unchanged Java sources, not an analyzer-clean result. A separately
inspected existing foundation-fs SpotBugs report dated 2026-09-07 contains one finding, no analysis
errors and no missing classes. SpotBugs was not rerun. Gradle also reports deprecated Kotlin
delegate syntax that needs attention before Gradle 10. The full Java suite, SonarLint, live
collectors and protected operations were not executed.

## Executed local example

The implementation evaluation at `2026-09-10T21:01:59Z` produced:

```json
{
  "auditExecuted": true,
  "assessmentIntegrity": "verified-local-consistency",
  "phaseDecision": "incomplete",
  "phaseComplete": false,
  "unresolvedRequirements": 47
}
```

The 49 implementation classifications are 33 implemented, 12 partial, 3 missing and 1 unknown.
Forty-seven requirements still need a required dimension or prerequisite. The default
repository-only selection satisfies the audit's own reconciliation and closed public projection
assertions; it supplies no operational artifacts. The report identifies the starting commit/tree
above and effective local tool digest
`sha256:496f78a70c036285eb88eecb02b6612039dc232311f0987847a850389db81ed7`, independently of the
historical product sources. Its acceptance policy byte digest is
`sha256:d28b7d58414e1605a9c4bb4d97ebf916d26159f2d0b86b757e3763e5336fa09a`.

A second local selection contains the actually executed fourteen-case isolated maintenance
rehearsal, PR-302's exact reviewed repository statement, a fresh empty production bundle and
retained original squash CI records. It also reports 47 unresolved requirements:

| Selected assertion | Local verifier | Original/operational interpretation |
| --- | --- | --- |
| Maintenance drill | Executed pass over the retained receipt | Partial implementation; the imported local execution remains author-reported at this admission boundary; no authenticated runtime, cleanup or independent review. |
| Typed public source admission | Executed pass | Exact reviewed repository statement; required original public source coverage remains missing. |
| Deterministic site bundle | Executed pass with complete local bundle coverage | Admission prerequisite remains incomplete; no deployment or public observation is inferred. |
| Historical CI record | Executed pass over retained record structure | Offline provenance remains unverified, applicable analyzer disposition is missing and current CI is unknown. The earlier live GET observation is retained separately. |

The local run retains detailed files under `build/phase-12-assessment/` and
`build/phase-12-example/assessment/`; public exports use the disjoint
`build/phase-12-public/` and `build/phase-12-example-public/` roots. The expanded selection and
confined inputs are in `build/phase-12-example/selection.json` and `build/phase-12-example/inputs/`.
These generated local artifacts are not production handoffs or publication approvals.

Both assessments successfully recomputed through `verify` and `public-export`. Adding
`--require-complete` to either verification returned exit 2, as required for this incomplete state.
The final phase-specific self-test passed **156 tests**. Browser conformance passed on the empty
production bundle, original repository statement, populated synthetic demo, isolated phase-status
renderer fixture and hostile-input renderer fixture. Each checked eight pages with JavaScript
enabled/disabled, mobile/desktop layouts, keyboard navigation, downloads, local-only requests and
fixture headers. The phase renderer fixture stays visibly synthetic and grants no approved
production source pin. The configured remote browser was incompatible with the available client;
the successful checks used local Chromium 153.0.8010.12 with Playwright 1.63.0.

The final checks also passed `actionlint` for the affected CI/build/transparency workflows,
relative documentation-link validation and `git diff --check`. A fresh evaluation and independent
temporary-root rebuild produce identical bytes for the same fixed inputs. Existing Phase 11,
open-item tracker, approved repository statement, production/repository selections and prior
approved public source pins remain unchanged.

PR-303 delivers the bounded local audit and admission implementation. Current hosted verification
of these edits, remaining owner-original context support, missing product/runtime work and actual
approved observations remain explicit acceptance limitations. No independent human security
review or independently operated builder was supplied by the parallel development audits.
The generated remediation order begins with `product-subject-binding`; the next Phase 12 slice
should close exact daemon/app/API freeze and measured-consumer admission before another long run.

The September 11 bootstrap-admission review corrected selection validation for the empty
predecessor marker described above. The September 10 example, tool/policy digests and test results
remain historical records of that earlier revision. The correction refreshes only affected
source/test byte pins; new assessments must use the corrected tool and policy identities rather
than overwrite or reauthenticate those earlier outputs as if their source had not changed.

The subsequent federation and CI review corrections preserve the same boundary. Successfully
authenticated federation observer and predecessor evidence now emits the coverage dimension
consumed by all three PR-295 assessment requirements. Missing predecessors still leave coverage
missing. CI reconciliation derives applicable workflows from original event context instead of
requiring every workflow for every PR. Regression authorities remain isolated test fixtures;
these corrections do not establish any new hosted CI or protected operational observation.

The corrected revision passed 169 Phase 12 self-tests and 39 existing federation owner tests.
The new repository-only assessment at `2026-09-11T04:14:00Z`, retained under
`build/phase-12-federation-ci-review/`, evaluated and recomputed successfully with 47 unresolved
requirements and `phaseDecision=incomplete`. Its `--require-complete` verification returned
exit 2. Java/Gradle and browser checks were not run for these Python admission corrections.

The scratch-path review subsequently reproduced the temporary-directory failure with a
symlink-backed `TMPDIR` on Linux. The evaluator now resolves only its internally allocated
scratch directory before offline or original-collection verification; caller-selected evidence
and adapter confinement checks retain their symlink restrictions. Test fixtures canonicalize
their own temporary roots too. All 171 Phase 12 tests passed with both ordinary and symlink-backed
temporary directories; this is a portability regression check, not a native macOS CI observation.
The fresh assessment under `build/phase-12-scratch-review/` at `2026-09-11T04:21:41Z` evaluated
and recomputed successfully and remains incomplete with 47 unresolved requirements.

The migration cutoff review corrected admission of observations whose original execution
completed after the assessment time. Original authentication now retains the selected job's
completion and artifact's last-update timestamps in the private migration capability. Phase 12
requires timezone-aware upload and completion times in order, with completion no later than
`asOf`, before crediting runtime, coverage or cleanup. Missing timing retains
`migration-original-execution-time-unavailable`; caller-selected observation times cannot fill
that gap. The receipt and public projection formats are unchanged. Isolated original-provider
tests cover historical cutoffs, equal/later cutoffs, equivalent timezone offsets, missing clocks
and invalid ordering without collecting live evidence.
