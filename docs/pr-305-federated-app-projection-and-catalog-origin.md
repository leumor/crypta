# Selected federation projection and catalog-origin runtime

PR-305 connects private selected federation declarations to the native exporter and exercises a
finite catalog-origin lifecycle in a disposable packaged daemon. It is Phase 12 remediation;
the separate original operational, independent-review and long-duration requirements remain open.

## Integration identity

Work started from clean `develop` commit `ffd8b227e7dbc88bad22b469f14cea9f2089d742`, tree
`a26dc78b73b701d2caa8260ba4f9bfde9e228733`. GitHub PR #1406 was verified merged at
`2026-09-11T17:12:57Z`; that squash tree equals final feature head
`91fdbfe13cb5371b10037b35abd25ba2ba3c66cf`. The earlier planning tree
`eeb34de3c6cbd8011bcdfd648658c27c309b8099` differs in subsequent package/export, CI,
producer-binding and test fixes. The integrated fixes are retained.

The fixed-time baseline evaluation at `2026-09-11T17:20:00Z` is retained separately under
`build/pr305-phase12-before`. It reports 49 mandatory requirements, 47 unresolved and
`phaseComplete=false`. These are acceptance dimensions, not a count of missing features.

## Reuse and ownership

| Area | Native owner reused | Added bounded path |
| --- | --- | --- |
| Signed projection | Devtools exporter, catalog verifier, bundle extractor/verifier, review receipt and scoped trust policies, conflict engine, API admission | Invocation-private snapshots and an explicit selected-context declaration |
| Local scope preparation | Appcatalog typed publisher/reviewer stores and canonical records | Fresh-root offline bootstrap; normal guarded catalog trust approval still follows |
| Installed provenance | AppHost origin v2, coordinated bundle/origin transaction and retained rollback slot | Exact durable postconditions through normal catalog install/update/switch/rollback routes |
| Runtime control | Packaged launcher, bounded supervisor HTTP client and process identity | Fixed isolated roles and a finite synthetic transition driver |
| Original sources | Existing protected artifact/member authentication and projection workflow | Separate encrypted pre-runtime local-selection handoff, preserving the bundle producer |
| Consumers | API matrix, maintenance package admission and Phase 12 native adapters | Prospective private inventory companion; legacy authority semantics remain intact |

Read-only projection, lifecycle, runtime and security audits preceded edits. Native projection,
appcatalog bootstrap/fixtures, runtime Python and protected producer/consumer changes had separate
file owners. Delegated development review is not independent human security review.

## Private selection and original inputs

The direction is acyclic:

```text
original signed catalog/bundle/submission + protected local selection
  -> native scoped projection and API admission
  -> selected product/cohort admission
  -> actual normal catalog-origin operations
  -> original measured observation
  -> scoped consumers and Phase 12 assessment
```

The root-owned `/etc/cryptad-certification/federation-selection.json` selects a closed roster of
context and member files. Public catalog/signature/bundle members require original artifact
coordinates and exact original member names. Local context/scope records are separately protected
operator choices. Neither the final runtime observation nor a future maintenance freeze is an input.

The `produce-selection` operation in the existing app-subject workflow authenticates every original
member before sealing the handoff. `sourceAuthority` continues to mean the original app build or
external handoff authority. A local selection producer cannot become the external developer's build
producer, and a separate catalog origin must match the authenticated selected catalog/signature
member coordinates exactly.

The private handoff contains all conflict candidates separately from explicitly selected contexts.
Each native context pins exact catalog/signature/revision/signer, app and bundle/content identity,
publisher and review identity, allowed channel, generation and canonical policy records. Generation
is a positive integer no larger than `2**53-1`. The independently reviewed cohort supplies the
expected generation; changing the file and its own digest cannot change that expectation.

Private selection is never uploaded as ordinary JSON. The Linux protected runner requires
`/usr/bin/openssl` with CMS AES-256-GCM support and separately provisioned root-owned recipient
certificate `/etc/cryptad-certification/federation-selection-recipient.pem`. Consumers also need
the mode-0600 recipient key at `federation-selection-recipient.key`. This key supplies
confidentiality only; it grants no app, catalog, observer or release signing authority. Keep it
separate from node credentials and observer signing keys. Local selection/config inputs must have
no world permissions and no unprivileged writes; mode 0640 permits an explicitly selected runner
group to read root-owned policy.

Only randomized `federation-selection.cms` is attested and uploaded. Consumers authenticate the
original workflow, source, run, attempt, artifact and exact ciphertext member before decryption.
Plaintext is bounded, parsed and materialized only under an invocation-owned private root. The
producer similarly encrypts prospective inventory v4 before any output enters its upload directory.
Public key material does not make a subscription, scope, installed origin or its hash public.

The maintenance freeze publication path does not yet support encrypted runtime companions.
It rejects selected-federation cohort v2 before acquiring the private inventory and also rejects
inventory v4 before writing runtime members. The metadata producer reports
`runtime-metadata-private-companion-unsupported`; the outer freeze sealer retains its fixed
`runtime-metadata-freeze-sealing-failed` diagnostic. Do not place decrypted inventory or native
`federationSelection` declarations under the freeze directory: the maintenance workflow copies
that entire directory into its candidate artifact. This is an implementation gap for selected
federation maintenance publication, pending encrypted member transport and consumer admission.
Ordinary inventory v2/v3 maintenance handling and private bounded runtime admission retain their
existing contracts.

## Native declaration and inventory versions

Ordinary exporter declaration v1 and contract-admitted v2 retain their meaning and field sets.
Federation mode requires the context/generation pair and selected contract/full baseline registry:

```text
crypta-app subject-projection <existing exact artifact/registry arguments>
  --federation-selection <private selection.json>
  --federation-generation <independently selected generation>
  --contract <selected packaged contract snapshot>
  --baseline-registry <selected complete registry>
```

The exporter snapshots all registries, scope records and candidate artifacts before verification.
It reuses native catalog binding lifecycle, publisher and reviewer scope checks, recomputes the
complete selected-app conflict set, rejects hard conflicts and denylist bypass, verifies every
signed candidate and derives declarations from actual manifests. It performs no fetch, live trust
write, app install or app-code execution. V3 output is created atomically with mode 0600.

| Contract | Authority and compatibility |
| --- | --- |
| Inventory v2 | Original full API cohort and original producer authentication; unchanged |
| Inventory v3 | Prospective maintenance runtime products; never independent reproduction |
| Inventory v4 | Private selected-federation companion with explicit `baseInventoryVersion=2|3` |
| Native declaration v3 | Existing v2 native admission plus exact private selection/policy/conflict commitments |
| Synthetic fixture, observer plan and observation v2 | Four preauthorized native subjects and the expanded finite role/case roster; the narrower observation v1 cannot satisfy it |
| Maintenance freeze v1/v2 | Historical v1 unchanged; existing v2 private metadata admits the prospective companion |

Inventory v4 retains one effective content subject per app and carries selected native context
separately. Its reviewed cohort projection, selected context roster and contract/registry digests
are bound to the independently expected cohort digest. Removing a required context, substituting
generation, changing content origin or promoting runtime-only products to independent API evidence
rejects. The complete Stable seven, experimental Mail opt-in, external subject and installed role
subset remain separate. Synthetic federation fixtures are not Stable shipped software.

## Disposable scope bootstrap and normal runtime gates

`network.crypta.platform.appcatalog.FederatedCatalogScopeBootstrap` is the explicit offline host
bootstrap. Invoke it from the approved package classpath with an **absent** apps root, a private
input directory and the exact raw SHA-256 of `bootstrap.properties`. The closed manifest lists
paired canonical publisher/reviewer records with exact byte digests. Native readers and store
`put` methods validate records before an atomic, no-replace destination move.

It refuses existing app roots, symlink paths, extra roster members, digest substitutions and missing
paired app scopes. It writes no catalog trust binding and no installed origin. Its private output
provides the policy digests for the normal guarded `/operator/catalog-federation/{catalogId}/trust`
operation. No direct active-store JSON or privileged origin setter is used.

The operator-only `publisher-scope-revoke` and `reviewer-scope-revoke` actions under
`/operator/catalog-federation/{catalogId}/` narrow an existing scope. They require its exact
scope ID and current canonical digest. The configured native store compares that identity under
the same exclusive fence used for policy mutation, waits for retained authorization leases, and
preserves key, app, channel and original approval fields while changing lifecycle to revoked.
The operation accepts no replacement scope or activation. A separate process rewriting live
policy files would miss those in-process leases and is not used by the driver.

The fixed driver admits exact A1, A2, B3 and B4 signed subjects before launch. Its owned roles
separate the main lifecycle, a permitted update on the switched origin, an originless staged
installation, and terminal publisher/reviewer scope revocation. All roles share one 600-request
limit and a reviewed duration of 30–1800 seconds (900 by default). The shared deadline also bounds
native export, projection and scope-bootstrap
subprocesses; expiry prevents preparation of another role. Owned process cleanup still runs after
expiry. Federation is enabled only in these owned processes, and selected catalogs are
approved through normal APIs. After installation the driver reopens origin v2 and installed
content; adding a catalog to an originless staged install cannot satisfy these postconditions.

For the same-publisher switch, the existing conflict engine requires an exact
`explicit_source_switch_required` local resolution before the source-switch preview. The driver
uses the current conflict ID and subject-set digest, then obtains and commits native consent.
Hard conflicts are isolated from the positive switch. Direct schema-compatible updates remain
bounded by normal consent and admission; schema changes still require normal stage/apply,
migration and backup checks.

Source-switch consent authorizes the exact transaction. The existing
`explicit_source_switch_required` resolution continues to block routine automatic work across
the competing catalogs. A subsequent native update check can therefore report
`unresolved_cross_catalog_conflict` while the exact installed origin remains B3. The driver records
that blocked disposition and leaves the local preference unchanged. The separate origin-update
role uses the pre-admitted B4 subject after normal removal of the competing A source. This keeps
the conflict denial and the permitted origin-pinned update as distinct observations.

Rollback uses the native update service and verifies both exact prior bundle content and origin.
It does not claim app-data rollback. The private journal records mutation intent before requests;
lost responses reconcile exact retained operation subjects. Completed continuation checks actual
current state rather than trusting a saved success row. Three owner-level interruption tests use
the existing retention dependency immediately before transaction commit, interrupt actual native
install/update/switch transactions, and construct a new host to run production recovery. They
verify both bundle slots, both origin slots, retained revision pins and unchanged shared data.
They create no transaction or origin records themselves and add no production failure flag.

The protected entry point refuses an existing activation/root. It does not automatically restart
an entire interrupted multi-role experiment. A failed run retains its private intent, operation
journals and owned state for explicit reconciliation; it cannot create a replacement daemon or
retroactively rebind an old journal. In-run lost-response reconciliation and native AppHost
transaction recovery are the executable recovery paths measured here.

A retained bundle that fails native signature verification now returns the specific
`409 rollback_bundle_verification_failed` response with a fixed message. This maps only
`AppBundleVerificationException`; catalog authorization and generic I/O failures retain their
own handling. The error does not imply that a missing rollback slot or unrelated server failure
proved revocation. The driver checks the exact retained subject before authority-denial drills.

Loss of current local publisher authority during normal catalog preparation or update returns
`409 catalog_publisher_scope_rejected`. Only the typed native authorization denial receives this
mapping; unrelated filesystem failures remain server errors. A stale source-switch preview after
scope revocation must be denied without changing the app, rather than counted as a successful
security check merely because it produced a generic error.

Suspension changes a catalog binding's identity. Reapproval does not silently rebind an existing
catalog subscription, so a drill must not reapprove a suspended catalog merely to make later
refresh checks pass. The finite late suspension roundtrip uses retained B3 and active A2 after
ordinary refresh/consent checks, then tests irrevocable B removal/revocation separately. No
source reapproval or history-reset workaround is added.

## Original observer and narrow consumer

The repository entry point is `tools/interop/cryptad-federated-catalog-runtime`. Its `run` and
`seal` operations delegate to the source-owned
`tools/release-certification/protected/federated_catalog_runtime_observer.py`; retain the reviewed
source tree with its imported modules rather than copying only the executable. The protected
policy pins the complete imported repository implementation, tool/JDK trees, exact package,
fixture tree, original selection and inventory, and all four planned native subjects before
any daemon is launched.

The existing federation runtime workflow has an explicit `catalog-origin-synthetic` dispatch
scope. It runs only on protected `develop` under the existing runtime-observation environment
and original operator identity. The ordinary legacy dispatch remains separate and cannot consume
this narrow result as its broad federation closeout. No workflow was dispatched for local
implementation validation.

The fixed private policy is `/etc/cryptad-certification/catalog-origin-runtime.json`; its closed
contract is maintained in the observer's `PLAN_FIELDS` and `_plan` validator. It includes the
independently reviewed original coordinates, public synthetic cohort identifier, finite time
budget and absent owned root. `packageDigest` commits the original portable archive member;
`daemonExecutableDigest` commits its contained daemon JAR; `projectionInventoryDigest` commits
the exact decrypted original inventory bytes. Producer and consumer compare these distinct
identities, together with tool, JDK, fixture and implementation commitments. The original
selection authorizes eligible subjects; normal guarded
runtime approvals create separate role-local activation records. Their signer and scope
relationships must be bound without pretending their record IDs or timestamps are identical.

`run` authenticates original selection, projection, tools and package before native preparation,
executes the shared fixed driver, and encrypts the exact private observation. `seal` retrieves the
original immutable uploaded ciphertext and signs its commitment with the separate observer key.
The key is available only to the sealing step. The public receipt includes no plaintext private
plan, selection or observation hash. Only an explicitly approved synthetic cohort summary and
randomized ciphertext enter the upload directory; private roots and transcripts are not uploaded.

The `catalog-origin-observation` Phase 12 adapter consumes private `plan.json` and
`observation.json`, checks their exact product, selection, transition, role and time relationships,
and derives scoped cases from operation records. Original authentication requires the typed
observer capability. Retained JSON alone cannot grant original provenance. Even an authenticated
short loopback run remains `synthetic-local`, with broader coverage and operational blockers;
it cannot close the nine maintenance rows or become a 72-hour observation.

## Local executable validation

Run on Linux with Java 25 and the approved portable distribution prerequisites:

```bash
./gradlew :platform-devtools:installDist assembleCryptadDist
python3 -m unittest discover -s tools/interop -p 'test_catalog_origin_packaged.py'
PYTHONPATH=tools/release-certification python3 -m unittest \
  cryptad_certification.tests.test_pr305_product_consumer_integration
```

The integration compiles the test-only Java signing fixture, produces actual signed catalogs,
reviews, bundles and submissions, executes native scoped admission against the selected packaged
API, and starts a disposable packaged daemon. Isolated original transport in the test helper
authenticates exact selection/source bytes before the same native exporter is invoked. Those seams
are unavailable in production manifests.

The second integration retains every required Stable and explicit experimental Mail member and
independently selects the synthetic external pilot for its prospective cohort. Historical test
cohorts remain unchanged. It produces and authenticates encrypted inventory v4 for the private
bounded experiment, while separately admitting ordinary maintenance metadata and its app-bearing
product. It requires maintenance publication of the selected cohort to fail before runtime output
is created, and rejects substituting the v4 projection for the ordinary product's projection.
It uses the same full daemon JAR for product export and runtime execution;
the original portable archive digest and contained executable digest remain distinct. It then
executes the finite catalog-origin driver with those exact native declarations and feeds the
actual observed operations into the scoped consumer. Adding the selected fixture to a legacy
staged startup role still fails. The original transport and observer identity in this test are
explicitly synthetic and grant no protected execution claim.

The finite positive path observes absent → install → origin v2 → restart → update → explicit
switch → exact rollback. Mirror tests use an owned loopback HTTP server: after an initial primary
fetch, the primary returns an authorized failure and the **daemon** must request both mirror
catalog and detached signature. Request counters distinguish traffic from cache/registration.
Stale catalog and mismatched signature responses reject; restoring the primary is observed.
This is local traffic, not independent public mirror availability evidence.

Private process logs, request records, roots, scopes and installed state are never CI upload
targets. Ordinary Linux CI builds the real prerequisites and treats a skipped or empty integration
suite as failure. The original PR-304 compiled product/consumer integration remains a separate
required check.

## Acceptance and remaining work

The repository-only before/after audit uses `2026-09-11T17:20:00Z` for both evaluations and
separate retained output roots. Both report 49 mandatory requirements, 47 unresolved and
`phaseComplete=false`. The sole requirement-dimension change is
`p12-296-federation.implementation: missing -> implemented`; its selected-subject adapter is now
`api-subjects-v4`. The catalog-related adapter and consumer parents remain partial. Verification
succeeds as an incomplete assessment, while `--require-complete` exits 2. Local executable test
results do not supply the missing original CI/protected evidence to those assessment dimensions.

The measured daemon driver covers its finite normal lifecycle, mirror traffic, hard byte/publisher
conflicts, stable-only beta denial, app/browser operator denial, public publisher/reviewer key
revocation with active local scopes, suspended historical rollback, catalog removal/revocation,
and stopped-process cleanup. Native coordinated interruption recovery is separately established
by the three AppHost tests.

The expanded fixture and observation v2 also measure exact-equivalent B registration preserving
A's origin, isolation of an untrusted endpoint, and a trusted critical denylist candidate that
remains blocking even after a catalog preference is recorded. The native policy may accept a
local preference record; the measured requirement is that it cannot authorize the denied work.

Separate roles measure a permitted B4 update on the switched origin, a real staged-directory
installation that stays originless after catalog registration, and terminal local publisher and
reviewer **scope-record** revocations after preview. The publisher role refreshes B3 to preauthorized
B4, satisfies current conflict and material-consent gates, and proves that the old source-switch
preview still fails. No generic server error counts as an authority-denial observation.

After its B4 update, the existing origin-update role re-adds the already approved A2 catalog and
removes, then revokes, the currently installed app's B binding. Exact B4 installed bytes, origin v2
and retained native revision remain present. After each narrowing operation, unrelated A must
refresh successfully with the exact admitted revision and actual catalog/signature requests.
Preserving an installed app does not grant executable rollback or renewed trust to its removed
catalog. This case uses the same pre-admitted subjects and shared operation budget.

Each observed installed origin carries native catalog revision, signer, review and scope-policy
identities. The consumer reconstructs the existing selected-subject commitment and binds the
origin to its own role's actual catalog approval. An opaque origin digest or matching version
alone is insufficient. The prospective native v3 companion separates the aggregate
`publisherPolicyDigest` from the exact authorized `publisherBindingDigest`. Existing origin v2
stores the latter under its historical `publisherPolicyDigestSha256` field. Similarly, origin v2's
historical `catalogRevisionDigestSha256` commits raw catalog content. The private observation
names that value `catalogContentDigest` and obtains the signed `catalogRevisionDigest` and signer
independently through normal native retained-revision history. The consumer verifies both against
the native projection, including after rollback when the current catalog has advanced. These
explicit fields finalize the new native v3 companion; they do not alter published origin v2 or
historical inventory v2/v3 formats.

The B4 drill establishes native candidate selection and normal explicit
update execution; it does not claim a scheduler automatically ran the update. Broader permission,
schema/migration and advisory-policy combinations retain their owning service and handler tests;
they are not additional daemon observations.

The synthetic app has no side effects and is not started as a worker. These observations make no
worker-health, worker-crash, migration-payload or app-data-rollback claim.

No protected workflow, production publication, merge, real-user data access or 72-hour operation
is established by these local tests. Narrow component verification does not complete all nine
maintenance rows. The full historical/provider directions, duration windows, original/protected
observations, independent review, migration/Mail recovery, scheduler/resource matrix and site
observations retain their own blockers.

The existing broad federation v1 observation cannot be upgraded by attaching a new label or local
result. Selected declarations and finite runtime observations require their own original typed
context. Historical policy and approved public repository-status bytes are retained. The
prospective implementation disposition records only supported behavior and source pins; every
mandatory requirement and closure dimension remains in the evaluator.

Scheduler-pressure and resource-baseline coverage remains the tentative PR-306 implementation
workstream. Original product/selection/runtime acquisition remains ordered by the evaluator's
unchanged dependencies; protected observation and broader runtime dimensions retain their
own requirements. Phase 12 stays incomplete until its verifier establishes every mandatory
requirement.
