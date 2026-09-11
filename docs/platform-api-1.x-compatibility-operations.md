# Platform API 1.x compatibility operations

Cryptad keeps four release identities separate:

- The URL API version remains `v1`, represented by `/api/v1`.
- The contract version is a monotonically managed integer. It is currently `25`, independently of
  any stable-baseline name. Version 24 records the app-visible named-baseline registry summary;
  version 25 adds the experimental own-app Mail capabilities without changing baseline 1.0.
- A stable baseline is an immutable named compatibility promise such as `1.0` or a reviewed future
  `1.1`.
- A daemon release/build identifies product bytes. It is not an API baseline or contract version.

Platform API 1.0 remains rooted at contract version 19. Its frozen capability membership, endpoint
identities, HTTP methods, required capabilities, audit actions, and allowed app principals are not
changed by the 1.x operations authority. The authority does not add `/api/v2`, activate Platform API
1.1, or grant an app permission to call an endpoint.

## Named baseline registry

`PlatformApiBaselineId`, `PlatformApiBaselineDefinition`, `PlatformApiBaselineLineage`, and
`PlatformApiBaselineRegistry` are the typed authority. A definition freezes exact capability
membership and endpoint method/route, route family, required capabilities, audit action,
host-bypass behavior, and app-principal access. Lifecycle records may move through the closed
`proposed`, `candidate`, `reviewed`, `documented`, `active`, `deprecated`, `end-of-support`, or
`rejected` states without editing a definition in place.

The current registry imports the checked-in Platform API 1.0 freeze by its existing SHA-256 and
projects exactly nine capabilities and 32 endpoints. It does not regenerate or rewrite that file.
Fixture lineage can exercise proposal transitions but cannot establish supported status. A future
versioned protected activation authority would have to bind its exact release, build, support
start, and authenticated activation receipt; PR-296 does not provide or claim that authority.
Once a protected activation establishes those release/build/support-start coordinates, every later
deprecation or end-of-support transition must preserve them exactly. The frozen 1.0 import is the
only bootstrap record without operational activation coordinates.

## App declarations and runtime admission

An explicitly stable app may declare:

```properties
api.minimumVersion=19
api.maximumTestedVersion=24
api.targetStability=stable
api.targetBaseline=1.0
```

An older explicit stable declaration without `api.targetBaseline` has effective target `1.0`, with
the omission retained in metadata. A legacy app without an explicit stability target remains
legacy experimental metadata with no stable baseline. Existing catalog v1-v6 and historical
bundles remain readable. A newly generated signed catalog that explicitly carries
`app.<id>.api.targetBaseline` uses catalog schema v7; the closed v1-v6 formats are not reinterpreted.

The app bundle, catalog descriptor, submission record, reviewed manifest, and packaged artifact
preserve the exact declaration. Explicit disagreement fails verification. The named baseline and
integer contract range are evaluated together during local install, catalog install, update,
automatic update selection, start, and federated source switching. Unsupported stable baselines
block admission. Experimental apps may name an inactive candidate for preview, but existing
experimental opt-in and consent still apply.

Baseline metadata never grants a capability. Manifest permissions, principal type, endpoint
requirements, consent, sandbox, review, catalog/publisher trust, and source-switch policy remain
independent authorities. Rollback continues to restore the prior immutable bundle and its exact
manifest/origin provenance rather than manufacturing new compatibility metadata.

## App-author preview

The existing CLI remains offline:

```bash
crypta-app api baseline inspect --output build/platform-api-baselines.json

crypta-app compat verify \
  --bundle-dir . \
  --target-stability stable \
  --target-baseline 1.0 \
  --strict

crypta-app api preview \
  --proposal build/candidate-baseline-registry.json \
  --contract build/candidate-contract.json \
  --bundle-dir . \
  --output build/platform-api-preview.json
```

The preview binds the SHA-256 of the exact supplied contract bytes and registry proposal bytes,
then requires the contract's version-24 `baselineRegistrySummary` to identify that same candidate
registry. Contradictory contract/registry inputs fail before a preview is written. The report also
includes candidate lifecycle, compatibility findings, deprecations, and an optional bundle result.
It is always marked `preview`, `nonProduction`, non-activating, non-authorizing, and not
runtime-observed. A byte change to the proposal or contract changes its digest and requires a new
preview.

## Public and operator views

`GET /api/v1/platform/contract` retains its route, capability, and descriptor semantics and adds a
bounded supported-baseline summary. It does not expose proposals, installed inventory, or release
history to app principals. Host/operator dashboards add the registry digest, support phase,
history health, candidate/graduation/deprecation counts, matrix and preview status, protected-state
freshness, and a prominent static-versus-runtime boundary. Missing protected receipts display as
not observed rather than success. PR-295 federation routes remain operator-only and outside the
1.0 projection.

## Side-effect-free certification authority

Use the unified command to validate checked-in fixture evidence or exact protected release
evidence:

```bash
python3 tools/release-certification/certify.py stable-platform-api-1x --self-test

python3 tools/release-certification/certify.py stable-platform-api-1x \
  --mode verify-history \
  --execution-contract <repo>/path/platform-api-1.x-execution.json \
  --evidence-dir <repo>/path/exact-evidence \
  --out-dir <repo>/build/platform-api-1x/history
```

The closed modes are `preflight`, `verify-history`, `verify-baseline-proposal`,
`verify-graduation`, `verify-app-matrix`, `verify-runtime`, and `closeout`. Every mode reads local,
digest-bound evidence and writes only a summary, a human-readable report, and a redaction report.
It does not contact a node, publish a release, change a catalog, activate a baseline, graduate a
descriptor, or mutate GitHub.

Fixture and self-test contracts can reach only `fixture-verification-complete`. The report states
that Platform API 1.1 is not active. Operational closeout additionally requires authenticated,
non-fixture PR-291 protected-release, PR-292 independent-reproducibility, PR-293 catalog-authority,
PR-294 third-party-pilot, and PR-295 federated-catalog roots for the exact source, release, build,
workflow, run attempt, artifact, and summary digests.

## Append-only contract history

The history ledger retains a self-digested release record for each daemon release. A record binds
the exact contract snapshot filename, byte size, SHA-256, contract version, baseline-registry
semantic digest, compatibility-window digest, deprecation-ledger digest, optional app-matrix digest,
release root, protected producer coordinates, and predecessor record digest. The execution
contract separately binds the complete current baseline-registry artifact. Every successor also
binds the predecessor registry bytes authenticated by the predecessor closeout summary.
Certification requires the current definitions and lifecycle records to retain that exact prefix,
so proposed, rejected, and other non-supported history cannot be edited or dropped between
releases. It validates the registry's closed schema and definition, lineage, and self-digests,
requires its supported set to match the execution subject, and requires the history head to name
that registry's exact semantic digest. The execution binding independently authenticates the
current registry artifact's exact bytes. Each version-24-or-later snapshot binds its own semantic
registry digest, so a later definition or lifecycle transition does not rewrite older release
records. The compatibility-window digest is recomputed from the parsed contract snapshot rather
than trusted as a caller-supplied label. Earlier version-1 summaries without the registry artifact
fields remain readable for audit, but cannot authenticate a production successor.

Production history also binds the exact selected Stable RC freeze authenticated independently by
the PR-291 protected-release and PR-292 reproducibility authorities. Both authorities must select
the same RC run, attempt, artifact, freeze, and product digest. The freeze file digest, its semantic
content digest, release/build/source subject, product root, Platform API contract version, and exact
contract-snapshot byte digest must match the newly supplied history head. The head's producer
coordinates must reproduce the authenticated protected-release receipt. Thus a self-digested
genesis record or successor with merely plausible workflow labels cannot become
`history-authenticated`.

The ledger also binds `oldestSupportedRecordDigest`, but that field is not its own support
authority. Operational verification authenticates the independently re-fetched Stable lifecycle
publication receipt, verifies the exact lifecycle descriptor bytes and semantic digest, derives
the minimum build in `current-stable` or `supported-maintenance`, and resolves that release by
release ID, build, and source commit in contract history. The ledger field must match the derived
record. Fixture mode may use its explicit fixture projection, but that path cannot produce an
operational state.

Verification rejects gaps, forks, duplicate release/build identities, release or source
substitution, contract-version regressions, and rewritten old records. Reusing one contract version
with different snapshot bytes fails. Changing snapshot bytes without advancing the contract version
also fails. Successor `generatedAt` values must be strictly later than their authenticated
predecessors, and a non-null `publishedAt` cannot precede its record's `generatedAt`. This prevents
an appended record from backdating a newly introduced deprecation notice. The explicit
genesis/import record bootstraps existing history; a repository file or mutable
`latest-summary.json` is not an authenticated production receipt.

## Future baseline proposals and graduation

A future 1.x proposal names its predecessor and exact candidate membership. The candidate is
compared with every lower-numbered baseline whose latest state is `active` or `deprecated`, even
when that definition is outside the candidate's declared predecessor chain. It must contain every
such member with identical endpoint semantics. Claimed removals are rejected. Incompatible behavior
belongs to a future major baseline and potentially `/api/v2`.

Proposal evidence binds compatibility analysis, rationale, security review, documentation, tests,
app-matrix evidence, reviewer identity, source commit, and release identity. A proposal is not an
activation record. Graduation records additionally bind the exact experimental descriptor,
capabilities, allowed principals, audit action, behavior contract, maturity window, reviews, docs,
tests, and representative app evidence. Operator-only and internal descriptors cannot graduate
through this process.

The version-1 execution contract has one proposal binding. A registry with no nonterminal future
definition may omit it and continue to verify the frozen `1.0` history. A registry with exactly one
nonterminal future definition must supply that definition's exact proposal; multiple simultaneous
future definitions require a later versioned evidence format. Certification recomputes the bound
app matrix and requires its digest to equal the proposal's `appMatrixDigest` before reporting the
proposal stage as reviewed.

The verifier derives proposal predecessor and candidate membership from the accepted baseline
registry; producer-supplied member lists are not authority. Every proposal addition requires one
exact graduation record. Graduation descriptor and behavior digests are recomputed from the
authenticated source snapshot, including the separate `app-process`, `app-browser`, and
`host-operator` access flags, before target-definition membership is accepted. Every definition's
first-complete contract version must be at least every member descriptor's introduction version.
Graduation observation timestamps must also be no later than the execution's deterministic
evaluation time.

No current experimental descriptor is automatically graduated by this implementation.

PR-296 models future lifecycle states for proposal and preview work, but the version-1
certification authority does not authenticate activation of a future baseline. Production support
is therefore restricted to the imported frozen `1.0` baseline. A later versioned authority must
define and authenticate a non-circular protected activation receipt before `1.1` or another future
baseline can enter `active`, `deprecated`, or `end-of-support`. A registry label, release record,
Boolean, fixture, or digest-shaped string cannot activate support.

## Deprecation and removal clocks

The deprecation ledger chains each descriptor timeline to its predecessor. The first deprecated
contract version and first authenticated public-observation time cannot be reset. Scheduled removal
cannot move earlier or provide less than two contract versions of runway. Removal remains blocked
while a supported baseline contains the descriptor or a required authenticated app depends on it.
Critical stable removals remain non-waivable.

The current release record must bind the exact current deprecation-ledger digest. Every successor
also supplies the previous ledger, which must match both the authenticated previous history head
and previous closeout summary. Membership and required-app blockers are recomputed from the
accepted baseline registry, current contract snapshot, and compatibility matrix; producer-supplied
empty arrays cannot erase them. A rejected or end-of-support baseline definition remains immutable
history, but no longer forces retired descriptors to remain in every later live snapshot.
Every timeline newly added by a successor must begin as `deprecated` or `scheduled`, name no
timeline predecessor, and match the first authenticated contract snapshot that publishes the
notice. Its contract version, release ID, build, and observation time are derived from that history
record; a newly introduced `removed` row or a backdated notice fails.

The existing Stable 1.0 maintenance and lifecycle authorities remain authoritative. PR-296 imports
their history rather than resetting it.

## App compatibility matrix

The deterministic matrix binds public app identity and digests, publisher/catalog/review identity,
target stability and baseline, contract range, required and optional capabilities, experimental
opt-in, evidence source, and fixture state. It evaluates the oldest supported release, previous
certified release, current candidate, and an optional preview. Certification reopens each exact
history-bound contract snapshot and derives every verdict and finding from its descriptors and the
accepted named-baseline registry. Producer-supplied `verdict`, `staticVerified`, and finding labels
must match that derivation and are never treated as proof on their own.

The matrix is not its own app inventory. A separate closed app-subject inventory binds every
compatibility input used by each row, the exact PR-291 through PR-295 authority roots that supplied
the subject, fixture classification, and the independently selected required-app set. Production
verification rejects a missing inventory, a matrix row or required ID omitted from that inventory,
any changed target/range/capability field paired with otherwise authentic digests, and any inventory
that omits the policy-fixed seven first-party apps or authenticated external-pilot coverage. The
existing PR-292 subject inventory can bootstrap first-party byte identities, but PR-294 and PR-295
summary files alone do not authenticate complete compatibility declarations; protected operations
must supply fresh bounded subject projections derived from their exact authenticated artifacts.
The version-1 authority therefore fails closed for every non-fixture subject that cites only one of
those broad legacy digests, before it can report `app-matrix-verified`. No checked-in inventory or
resealed matrix can stand in for a protected projection receipt. PR-300 implements the version-2
producer and admission path in
[`app_subject_projection.py`](../tools/release-certification/protected/app_subject_projection.py).
The dedicated workflow first builds and attests the complete Java tool archive, then a separately
selected protected run derives the required first-party/external cohort from exact authenticated
source artifacts. Its wrapper authenticates the original successful producer attempt, job,
environment, artifact and member attestation before passing an internal verified object to the
matrix consumer. Ordinary caller JSON cannot construct that object. The historical seven-app
cohort remains explicit; current-eight adds Mail with its experimental declaration. Selected
federation projection remains unsupported, and no protected projection was executed for this
change. See the [projection prerequisites](cross-version-live-network-soak.md#protected-app-subject-projection)
for the acyclic tool/source/cohort sequence.

Matrix results are static contract evaluations. `runtimeObserved` is always false in this artifact.
A separate bounded runtime observation can prove selected apps start, read contract metadata,
exercise representative stable endpoints, and preserve expected authorization failures. That
observation is not a soak and cannot be substituted with a sample or fixture. Production runtime
status additionally requires the exact observation to be bound to an allowlisted protected
runtime producer run, immutable attempt, successful job, protected environment deployment, and
artifact. `.github/workflows/stable-1.0-platform-api-1x-runtime-observation.yml` is that allowlisted
producer. It first verifies the static matrix, then invokes only the digest-pinned adapter installed
in its protected managed-node environment. The adapter performs the bounded app-start, contract
read, representative stable-endpoint, and expected-authorization-failure checks. A self-digested
JSON file, caller-selected adapter, or arbitrary check names cannot satisfy closeout.

## Protected workflow boundary

`.github/workflows/stable-1.0-platform-api-1x-runtime-observation.yml` checks out the protected
dispatch commit, admits a confined non-fixture execution template whose runtime fields are still
null, and verifies the static app matrix before accessing the managed node. Its protected
environment selects the local daemon endpoint, form password, and pinned runtime-adapter digest;
none is supplied by the dispatcher. It emits only the bounded, redaction-checked observation for
its exact source, run, attempt, and environment. The workflow does not activate a baseline, mutate
release state, or perform the PR-300 soak.

`.github/workflows/stable-1.0-platform-api-1x-evidence.yml` is the fixed protected, read-only
producer for one exact evidence aggregate. It accepts only a confined repository-relative static
evidence directory from the exact protected source commit, rejects links, sidecars, collisions,
prepopulated runtime results, and fixture-shaped execution subjects, and then independently
authenticates every PR-291 through PR-295 authority run attempt, exact successful job, protected
environment deployment, artifact ownership, canonical name and digest, and bound summary bytes.
It applies the same check to the previous Platform API closeout when the ledger is a successor, the
independently verified Stable lifecycle receipt used to derive oldest-supported coverage, and the
dedicated runtime-observation receipt. It constructs the runtime authority binding locally from the
authenticated GitHub coordinates and exact observation bytes; caller-authored runtime authority is
rejected. It also binds the supplied Stable RC freeze bytes to the exact selected-RC identity shared
by PR-291 and PR-292 before certification evaluates the current history head. Current-release
authorities must originate on the execution's exact source ref; a previous-history authority must
originate on the source ref bound by that authenticated history head. Only after those checks does
it run the complete side-effect-free closeout and upload a producer-bound artifact name.

`.github/workflows/stable-1.0-platform-api-1x-compatibility.yml` consumes only that allowlisted
producer. It authenticates the exact successful producer run and job, protected environment
deployment, repository, dispatch actors, source commit/ref, artifact ownership and time bounds,
name, and digest before extraction. It uses empty default permissions, full-SHA action pins, Java
25, the wrapper's pinned Gradle distribution digest, and bounded concurrency. Imported archives
pass the shared Stable supply-chain archive inspector before extraction. Both workflows retain
truthful failure or partial output and have no tag, GitHub Release, catalog, key, or trust mutation
authority.

Protected execution is still pending until real release-history, app-matrix, runtime, and PR-291
through PR-295 receipts are supplied and authenticated. Checked-in examples and self-tests cannot
produce operational completion.

## Scope boundaries

PR-297 owns real legacy-plugin migration. PR-300 owns long-duration, cross-version, multi-node
network soak. The bounded PR-296 runtime observation must never be described as PR-300 completion.

## Prospective exact runtime subjects

See [PR-304 runtime subject binding](pr-304-runtime-subject-binding.md) for the prospective
maintenance v2 private metadata, exact packaged API export, independently selected app sets and
versioned supervisor/measurement consumer path. Historical formats retain their original guarantees;
narrow admission success does not close missing runtime adapters or operational evidence.
