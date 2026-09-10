# Stable maintenance operations drill

Use this drill to exercise isolated maintenance failure handling while retaining the existing
maintenance, backport, publication and lifecycle authorities. Implementation coverage and production
operation completion are separate. This implementation is a partial PR-301 slice; the residual
matrix below is part of its acceptance record.

## Inspected source and authority chain

The clean starting commit was `cde5319829274b7df6517e37ab73ce72f8f71a18`, with source tree
`dbabbd25369ffefa4bf161b63e03d6535bde0869`. Work started on
`feature/pr-301-stable-maintenance-operations-drill` from local `develop`; no remote branch update,
merge, tag or publication was performed. The squash-replaced feature commit is not an ancestry
requirement.

The evidence dependency order remains:

```text
authenticated GA and immediate predecessor
  -> reviewed source fix and complete backport train accounting
  -> existing maintenance candidate freeze
  -> exact daemon, app, catalog, API and profile subjects
  -> original executed runtime observations
  -> maintenance validation -> explicit authorization
  -> existing publication -> independent public verification
  -> successor activation -> reconciliation and hotfix follow-up
```

The producer/helper source can differ from the candidate and historical product source. Exact
archive byte digests and semantic record digests have distinct roles. No prepublication producer
requires its eventual publication receipt. Missing real GA/predecessor history blocks a production
train; synthetic fixtures cannot bootstrap it.

The [maintenance runbook](stable-1.0-maintenance-release-and-hotfix-path.md),
[backport governance](stable-1.0-backport-and-release-train-governance.md), and
[lifecycle governance](stable-1.0-support-lifecycle-and-deprecation-governance.md) remain canonical.
The drill does not change their modes, policy windows, locks, tags or pointers.

## Local execution

Run from the repository with Python 3. Use a new disposable root beneath an existing owned directory.
The explicit execution switch authorizes only the fixed synthetic filesystem drivers. The runner
has no publication credentials, selectable commands, remote targets or live node adapter.

```bash
python3 tools/release-certification/certify.py stable-maintenance-drill --self-test
python3 tools/release-certification/certify.py stable-maintenance-drill --mode plan
python3 tools/release-certification/certify.py stable-maintenance-drill \
  --mode run --execute-isolated --root build/maintenance-isolated-drill
python3 tools/release-certification/certify.py stable-maintenance-drill \
  --mode verify --record build/maintenance-isolated-drill/summary.json
python3 tools/release-certification/certify.py stable-maintenance-drill \
  --mode closeout --record build/maintenance-isolated-drill/summary.json
```

Choose another new root for another execution. A pre-existing root or symlink is a safe denial.
Read-only modes do not run nodes or mutate publication. Verification checks local integrity only;
someone able to author a summary can recompute its digest. Such a summary never authenticates an
original protected producer or satisfies a maintenance gate.

The synthetic driver calls the actual maintenance publication adapter with finite filesystem
operations and synthetic fixture authorities. It executes absent artifact-base denial, interrupted
asset publication, exact-prefix retry, exact-existing idempotency, conflicting-byte preservation,
uncertain-response reconciliation, stale-predecessor denial and original hotfix-obligation
carry/reset/drop rules. Two additional cases execute the actual fixed production backend through an allowlisted injected
transport: exact-byte failure/retry and activation CAS/response-loss reconciliation. These cover
interrupted uploads, a response lost after write, stale and concurrently changed pointers, and
independent observation of an already activated pointer without a second mutation. There is no
network fallback. The transport model does not establish real GitHub authorization, infrastructure
durability or an operating-system process crash. Simulated clocks establish rules,
not elapsed observation time.

The scratch-train driver executes a clean cherry-pick, an actual conflicting cherry-pick and
manual resolution, and the synthetic candidate's own regression program. Existing backport Git
inspection and coverage logic reject mismatched patches/paths, missing conflict-test evidence,
hidden or omitted changes, duplicate fix accounting, wrong lanes and ineligible classifications.
Its temporary repository has no remote, and its synthetic commit identity applies only to those
test commands. A synthetic reviewer digest exercises plumbing; it is never human review or a
remote reconciliation receipt. The repository is removed before the fixed case IDs are returned.

Only fixed case identifiers and bounded classifications leave the disposable execution directory.
Synthetic input records and target bytes are removed after the driver. No synthetic publication
receipt is exported. Failed execution remains failed, cleanup is reported separately, and no result
claims that real public state changed or remained unchanged.

## Reuse and residual matrix

| Owner / scope | Existing authority and implemented slice | Missing implementation or original input | Required execution / postcondition | Compatibility and acceptance |
| --- | --- | --- | --- | --- |
| Maintenance train, C1/C6 | Existing GA/predecessor authentication, lane classification, complete diff accounting and reconciliation engines; real scratch Git clean/conflicting cherry-pick and negative accounting cohort | End-to-end actual reviewed fix train and packaged predecessor/candidate rehearsal | Old implementation creates state; candidate retains data and contract; hidden changes and wrong lane reject | One integer-build chain; production blocked |
| Portable admission, D1 | Existing maintenance freeze already binds portable product, exact assets and freeze time; prospective admission consumes that authority | Complete app-bearing maintenance roster with authenticated API snapshot and original protected artifacts | Exact frozen product selected; app-only freeze and substituted bytes reject | Old RC freeze remains unchanged; daemon binding alone is not cohort acceptance |
| Measured projection, D2 | PR-300 journal/checkpoint integrity and original producer authentication; v2 protected reports now materialize blocked scenario-level maintenance measurements | Complete required runtime adapters and original protected finish observations | Recompute every required case, postcondition, time and frozen subject from authenticated original observations | Supplementary subcases and local integrity remain ineligible |
| Hotfix, C2 | Current maintenance policy and successor obligation validation; isolated carry/reset/drop execution | Original published hotfix, full-window observations of original bytes and closure | Named windows only; deadline and original identities survive supersession; overdue routine release rejects | Fake clock is simulation; 72-hour experiment and maintenance gate are separate |
| Dependency finding, C3 | Existing private vulnerability and dependency disposition, SBOM and remediation authorities | Executed synthetic finding-to-fixed-subject integration and any separately authorized real finding | Complete shipped component/subject mapping and fixed-byte verification | Private handoffs stay encrypted; no invented advisory or incident |
| Catalog, C4/D3/D4 | Existing signing/reviewer/catalog role separation, compromise policy and consent flows | Full catalog-origin install/update, mirror traffic, channel/conflict/source-switch/rollback cohort; federation subject projection | Compromise blocks affected authority without uninstall, data deletion or global trust changes | Staged installation never becomes catalog origin retroactively |
| Publication, C5 | Actual maintenance adapter and fixed backend executed with disk/injected transport, including pointer CAS conflict and response loss | Protected original publication/activation observations and process-crash cohort | Exact bytes survive retry; conflicts persist; independent observation precedes activation | No live publication, activation or production receipt |
| Budget/profile/migration, D3 | Existing foreground counters, source-based profile comparison and installed Sharesite producer | Scheduler pressure/resource baselines, supported historical binary/external directions, literal browser-preview/bundle-rollback/cleanup | Real workloads and selected implementations produce bounded measured observations | Source comparison, binary execution, synthetic migration and real-user confirmation stay distinct |
| Mail renewal, E1 | Current signed AppHost worker, vault purpose checks and encrypted dataset CAS; explicit same-key renewal | Complete key-transition lifecycle and retirement authority | Exact dataset/grants/identity snapshot and one-use current-worker consent; remote renewed card requires approval | Experimental contract 26; network v1 and baseline 19 unchanged |
| Mail rotation/recovery, E1–E4 | Immutable account/key metadata, bounded retention, authenticated writer, paused restore | Recipient/storage rotation, account replacement, historical purposes, degraded resume epoch, host minimum-reader barrier and crash cohort | No regrant, lost replay history claim, silent reseal, eviction or unsafe old-reader write | Restore stays paused; these are implementation gaps, not missing credentials |
| Privacy/process, D3/E4 | Real child workers/vault/CAS tests and production bridge/router/session admission tests with test request objects | Combined real process/socket/browser origin cohort and complete audit/support/queue/diagnostic/failure canary surfaces | Denial precedes private side effects; no canary escapes any export surface | Simulated transport and internal tests are not live delivery or external security review |

Keep the full [Phase 12 tracker](phase-12-open-items.md) alongside this maintenance-specific matrix.
Passing the implemented cases does not waive any unimplemented mandatory row.

## CI and operational disposition

On the starting merge commit, Java CI run `34446210986` subsequently completed successfully and
CodeQL run `34446209123` succeeded. Supply-chain run [`34446209720`](https://github.com/crypta-network/cryptad/actions/runs/34446209720)
failed before jobs: the run-page annotation identifies an expression exceeding 21,000 characters
at line 2362. The API returned zero jobs/check runs and log download returned HTTP 404. PR-301
extracts the oversized platform handoff Python into a checked-in helper; its AST matches the
original body exactly, and local `actionlint` accepts the workflow. A hosted rerun is still required. The separate SonarCloud check
`102777988542` reported 79.2% new-code coverage (80% required), C reliability and E security ratings
(A required). Those findings are separate from successful Java task completion.

Local changes have no published-head CI result. Any later authorized publication must query that
exact head and its eventual merge independently. Earlier PR and merge successes cannot substitute.

No protected dispatch, real network insertion, private user migration, production publication,
successor activation or independent security review is established by this drill. Missing original
artifacts, reviewed baselines and authorized infrastructure remain explicit operational inputs;
missing adapters remain implementation work.

## Local validation record

These are working-tree results on the branch above, not checks on a published PR head. Python
self-tests passed for the following existing authorities and affected consumers. Counts include
negative fixtures; their expected denial messages are not suite failures.

| Suite | Tests passed |
| --- | ---: |
| Stable maintenance drill | 12 |
| Stable maintenance / backport | 243 / 133 |
| Private vulnerability / dependency vulnerability | 170 / 304 |
| Supply chain | 86 |
| Cross-version soak / protected discovery / interop runtime | 91 / 44 / 132 |
| Platform API 1.x / catalog authority | 88 / 111 |
| Legacy migration / content-profile review | 13 / 18 |
| Support lifecycle / RC / GA | 120 / 55 / 83 |
| Mail two-node driver unit tests | 5 |
| App-platform / security-response / release certification | 2 / 7 / 50 |

The isolated runner executed all fourteen implemented cases and removed its owned synthetic state.
Verification returned `verified-local-integrity`, with producer authentication `not-established`.
Closeout remained `partial`, with maintenance blocked and publication/activation `not-performed`.

The focused six-module Gradle test command, `spotlessApply test`, and
`spotlessApply build assembleCryptadDist` completed successfully. The latter took 7 minutes
15 seconds and included the new parsed-request HTTP admission tests. Linux skipped the RPM
installer task. After the final renewal guard edit, the Mail-only regression/analyzer command passed: 58 tests,
no failures or skips, and no findings in the inspected file SonarLint XML report. The Mail UI JavaScript harness,
`actionlint` and `git diff --check` passed.

The build is not analyzer-clean: existing non-blocking coverage gates reported shortfalls and
SpotBugs reports contain findings across multiple modules. The inspected Mail main/test SpotBugs
reports had no findings; Platform API reports had findings in other classes. No clean-base analyzer
comparison establishes all remaining findings as pre-existing. Hosted SonarCloud findings above
remain separate. Platform-conditioned, opt-in benchmark and existing cryptography tests were
skipped in local JUnit results; skipped directions are not observations.

## PR-302 handoff

Allowlist only the bounded drill summary/closeout, approved product/tool/policy digests, fixed
synthetic case identifiers, and immutable references to separately authenticated public governance
artifacts. A local integrity digest is labeled as such. Do not hand off fixture authority records,
raw test logs, incident composition, private vulnerability handoffs, Mail message/contact/backup
hashes, ciphertext references, migration content, topology, paths or support bundles. PR-302 owns
the public site; this work introduces neither a site nor telemetry.
