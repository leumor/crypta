# Scheduler pressure and runtime resource baselines

PR-306 adds bounded observations of the content-subscription scheduler, shared network budgets,
and exact daemon processes, plus an isolated packaged workload and a separate runtime baseline
comparator. These components remain Phase 12 remediation; their output does not establish release
eligibility, production publication, a reviewed production baseline, or 72 hours of observation.

Use Java 25+, the Gradle wrapper, Python 3 and Node for the packaged Linux experiment. The workload
owns fresh disposable roots and synthetic material. It does not authorize existing-node changes,
public-network operations, protected workflow dispatch, publication or access to real user data.

## Source and reuse boundary

Implementation started from the merged PR-305 source:

| Identity | Value |
| --- | --- |
| Starting commit | `214f863bc166412cb8a9e657dbb41fc4aed46c84` |
| Starting source tree | `bccfa2e6c40b989f40b5390e56b3ebbd30c63bc1` |
| Predecessor feature head, historical | `c2bf9d20f82dfc8fa4403123b360b9218367fbd4` |
| Working branch | `feature/pr-306-scheduler-pressure-resource-baseline` |

A matching source tree does not transfer original checks, signatures or protected authorization
between feature head, test merge and squash merge. The final delivery record must retain the actual
modified source/package identities and refreshed original checks. PR-305's older PR-body text is
not current packaged validation evidence.

The fresh read-only check audit found PR-head Java run `34692228640` and the CI-safe Beta run
`34692228589` successful; the latter's actual production job was skipped. The reusable Java build
used test-merge `63e5da4a28b795bb859ad459d000fca7fdc412de`. Squash-commit Java run `34706578938`
and CodeQL run `34706577825` also completed successfully for the starting squash commit. Those
results belong to their exact original inputs and do not validate this uncommitted PR-306 patch.

| Owner | Reused behavior | PR-306 observation or remaining gap |
| --- | --- | --- |
| `ContentSubscriptionScheduler` / `ContentSubscriptionService` in `platform-api` | Real fixed-delay executor, due/capability checks, shared service locking, bounded polls and retry state | Bounded causal events distinguish executor activity, due work, skips and actual fetch outcomes. |
| `ContentSubscriptionPressureGate` | Queue backend and persistence availability checks | Optional explicit contention threshold uses the actual bounded-content-fetch owner; native pending-key backlog remains unavailable. |
| `AppNetworkBudgetService` and stores | Durable fixed-window rates, process-local leases/reservations and composed family charging | Correlated family/window transitions and strict bounded diagnostics; tolerant historical snapshots remain unchanged. |
| `ContentFetchPort` / `LegacyContentFetchPort` | Actual bounded daemon content fetches | Detached active-call aggregates from the owning runtime boundary, with owner epoch and unavailable/truncated states. |
| `RuntimeWorkObservation` | Existing services share one process-local observation instance | Bounded causal history, numeric correlation and opaque scope labels; no request inventory. |
| `CoreHttpShellRuntimeSupport` | Packaged runtime service construction and scheduler startup | Wires the actual observation owner and opt-in policy through the normal scheduler. |
| `PlatformApiOperatorRoutes` | Existing host/operator authentication and routing | One read-only private aggregate route; no Stable 1.0 app surface expansion. |
| `cross_version_runtime.py`, `cross_version_budget.py`, fixed CJS driver | Packaged supervisor, principal requests and exact process checks | Finite scheduler workload and sustained resource reads; original protected provenance stays separate. |
| `tools/perf/runtime_baseline.py` | Existing performance tooling location | Separate pure collect/compare path; `performance-smoke.json` remains a startup/asset baseline. |
| Existing certification consumers | Original event authentication, product/time/scope requirements | Only independently derived narrow components may be admitted; other maintenance rows and Phase 12 requirements remain. |

See [PR-304 runtime subject binding](pr-304-runtime-subject-binding.md),
[PR-305 projection and catalog origin](pr-305-federated-app-projection-and-catalog-origin.md), and
[subscription budget policy](network-scale-soak-and-subscription-budget.md) for the preceding
ownership and admission boundaries.

## Pressure, admission and timing

Four conditions have different meanings:

| Condition | Source and meaning | Scheduler consequence |
| --- | --- | --- |
| Queue/persistence unavailable | Backend disabled, persistence awaiting a password or stopping, database already killed | Existing availability gate denies a due poll before budget reservation. |
| App/shared budget exhausted | Durable family rate limits or process-local concurrency/reservations | Existing stable denial codes; subscription and global fetch families retain their shared accounting. |
| Bounded fetch contention | Known count of executing calls in `bounded-content-fetch-operations` | Optional high/low-water admission policy described below. This count is not native selector keys, queued requests or backlog age. |
| OS/JVM resource pressure | Exact-process numeric measurements | Evaluated against a separately selected resource policy; it is not a queue gate or a new runtime resource governor. |

The immediate invariant is pressure before subscription budget acquisition/commit and fetch.
It does not mean that foreground requests preempt existing subscription polls. Subscription work
and foreground fetches share global fetch capacity; shared exhaustion may deny foreground work.

Pressure is assessed once per tick and applied to that tick's due work. The service rechecks
subscription state under its monitor, which remains held through the fetch. It therefore does not
execute concurrent subscription fetches. A stale scheduler snapshot or an empty tick cannot establish
a completed poll; `FETCH_INVOKED` and `FETCH_SUCCEEDED` come from the actual service boundary.

The optional contention policy blocks at `maximumInFlight` and resumes at or below
`resumeAtOrBelow`. The default high-water value is zero, so legacy constructors and ordinary runtime
configuration retain availability-only gating. A positive high-water value must be at most 1,024;
its low-water value must be smaller. Missing, unsupported or throwing signals preserve the existing
bounded permissive fallback and are recorded as unknown, never healthy evidence.

| Operator environment setting | Meaning |
| --- | --- |
| `CRYPTAD_CONTENT_SUBSCRIPTIONS_PRESSURE_MAX_IN_FLIGHT` | Opt-in high-water count of executing bounded fetch calls; `0` disables it. |
| `CRYPTAD_CONTENT_SUBSCRIPTIONS_PRESSURE_RESUME_AT_OR_BELOW` | Low-water count; default `0`. |
| `CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_JITTER_SECONDS` | Maximum jitter in seconds; zero is allowed. |
| `CRYPTAD_CONTENT_SUBSCRIPTIONS_FAILURE_BACKOFF_SECONDS` | Positive first failure retry delay. |
| `CRYPTAD_CONTENT_SUBSCRIPTIONS_MAXIMUM_FAILURE_BACKOFF_SECONDS` | Positive maximum retry delay, normalized to at least the first delay. |

Existing startup, scheduler wakeup, minimum poll interval and per-tick controls continue to apply.
The collector records effective normalized configuration as well as requested synthetic settings.
Defaults retain five-minute startup/minimum poll delay, one-minute wakeup/jitter, thirty-minute
normal interval, five-minute initial failure backoff and one-hour maximum backoff. A short profile
cannot establish default-profile throughput or recovery timing.

The synthetic workload also preselects the existing
`CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_CONCURRENT_GLOBAL=2` setting, lowering
the shared concurrency capacity from 16. Two actual held foreground calls then exhaust the same
global pool that a due subscription would acquire after pressure admission. Per-app foreground
concurrency stays two, and all fixed-window rate limits retain their defaults. A final bounded
cached-fetch burst exercises a real per-app rate denial. The helper never resets windows or edits
quota files. Family lease sums are not operation counts: the global hold is identified separately
by the native `content_fetch_global` family and opaque global scope.

Subscription rate limits retain their hourly windows and shared global content-fetch minute window.
Manual refresh uses the subscription family too. Trust Graph import-by-URI reserves import capacity,
performs the separately charged fetch prerequisite, then commits import usage. Closing a reservation
releases process-local holds; restart preserves durable rates but starts a new process-local lease
and observation epoch. No live quota reset, forced tick, fake clock or production sleep endpoint is
part of this workload.

## Causal and resource observations

`GET /api/v1/operator/runtime-observation` is authenticated host/operator-only, read-only, bounded
private metadata. App and browser app principals cannot use it to enumerate other apps or inspect
host telemetry. It exposes fixed aggregate reads, effective configuration and a bounded causal
history; it accepts no arbitrary management operation, host path, pressure mutation or counter reset.

`RuntimeWorkObservation` retains at most 4,096 events. Each event carries a monotonic sequence,
recording time, monotonic elapsed nanoseconds, fixed kind and applicable numeric metadata. Budget
operation IDs connect acquisition/reservation, original rate observation, family charges, commit,
fetch and release. Opaque process-local scope `1` represents global accounting; larger labels separate
application/internal scopes without exporting identifiers or hashes. Scope allocation is bounded.
Dropped events or exhausted scope/counter capacity make full accounting unavailable.

`RATE_OBSERVED` and `RATE_CHARGED` bind before/after counts to the same operation, scope, family and
original fixed-window epoch. A zero difference across a window reset is not evidence of unchanged
usage. Exact owner samples used for contention carry `sourceEpoch`, `sourceSequence` and
`sourceSampledAtEpochMillis`; later endpoint samples or summary event labels cannot substitute for
that causal assessment.

Budget `diagnostics()` uses strict bounded store observation, with failed/corrupt/truncated reads
marked unavailable. File observation bounds inspected directory/file entries and actual per-record
bytes read. Historical `snapshots()` still returns a tolerant list and can be empty on failure; that
legacy empty result must never prove zero usage or recovery.

| Metric | Unit and interpretation |
| --- | --- |
| RSS | Bytes resident in the selected Linux process; includes more than Java heap. |
| Heap used/committed/max | Bytes from fixed JVM management reads; used includes uncollected objects and is not a retained-live-object measurement. |
| Non-heap used/committed/max | Bytes from the matching JVM memory usage record; unsupported maxima remain unavailable. |
| Platform threads | `ThreadMXBean` platform-thread count; excludes Java virtual threads. |
| OS threads | Linux process thread count; distinct from application tasks or virtual threads. |
| File descriptors | Descriptor count without descriptor targets. |
| CPU | Cumulative process user+system nanoseconds converted using the platform clock-tick rate; deltas are CPU time, not a utilization percentage without a declared denominator. |
| GC | Supported collector-reported collection count and elapsed milliseconds; not an exact sum of stop-the-world pauses. |
| In-flight content work | Executing bounded-fetch port calls, including waiting/materialization in that port. |
| Oldest active age | Milliseconds since the oldest tracked executing port call began; not queued-key waiting time. |
| Native pending keys / pending-key age | Unavailable; never inferred from HTML, completed requests or CPU. |
| Progress | Offered/successful/failed/cancelled/timed-out/outstanding operations and terminal latencies; a quiet process is not useful progress. |

Linux collection retains executable digest plus PID/start ticks/boot ID checks before and after
sampling. A restart creates a new epoch. Daemon and selected synthetic worker measurements remain
separate; collector overhead is bound into the fingerprint. Routine samples contain no raw JVM
command line, heap/thread dump, JFR payload, descriptor targets, source keys or process tokens.
Unsupported metrics remain null/unavailable. NaN, infinity, invalid units/counts, counter rollback,
missing/out-of-order samples and coverage gaps cannot become a passing series.

## Run the isolated packaged experiment

Build supported prerequisites sequentially from the source being tested:

```bash
./gradlew :platform-devtools:installDist assembleCryptadDist
PYTHONPATH=tools/interop:tools/release-certification:tools/release-certification/protected \
python3 -m unittest discover -s tools/interop -p 'test_scheduler_pressure_packaged.py'
```

The native packaged test prepares a signed synthetic Feed Reader experiment app with the necessary
subscription permission, copies the distribution and JDK into owned roots, then runs the actual
background executor. The experiment app is not added to the Stable first-party release set. Missing
prerequisites are an explicit skip in the general test runner and must fail a CI lane that requires
this integration. Do not count a skipped integration as successful execution.

The focused helper also has an explicit retained-output CLI. Supply an already prepared signed
fixture, exact distribution, Java home and Node executable; the private runtime root must not exist:

```bash
PYTHONPATH=tools/interop:tools/release-certification:tools/release-certification/protected \
python3 tools/interop/scheduler_pressure_runtime.py \
  --private-root "$PR306_PRIVATE_ROOT" \
  --distribution "$PR306_DISTRIBUTION" \
  --java-home "$PR306_JAVA_HOME" \
  --fixture-root "$PR306_FIXTURE_ROOT" \
  --node-executable "$PR306_NODE_EXECUTABLE" \
  --source-commit "$PR306_SOURCE_COMMIT"
```

Fixture preparation is executable in
[`test_scheduler_pressure_packaged.py`](../tools/interop/test_scheduler_pressure_packaged.py), using
[`Pr306SignedSchedulerFixture.java`](../platform-devtools/src/test/java/network/crypta/platform/devtools/fixtures/Pr306SignedSchedulerFixture.java).
The helper validates the embedded daemon identity against the requested source before behavior
checks. A stale distribution is an error; rebuild it rather than weakening identity admission.

The closed synthetic profile has a finite overall deadline, operation/sample bounds and collector
cadence defined in [`scheduler_pressure_runtime.py`](../tools/interop/scheduler_pressure_runtime.py).
It observes normal scheduled success and foreground controls, starts an owned missing-content fetch
that occupies the real bounded fetch port, waits for due pressure skips, lets that finite owned
request finish, observes the real clear signal and useful scheduled recovery, then runs bounded
mixed work and restart/cleanup. Exact native events, not subscription labels alone, decide the
admissible causal claims. Generic server errors and zero due work do not prove pressure protection.

The helper retains raw numeric series, scheduler observations and partial failures under its private
root. It stops owned processes and retains state for reconciliation; it does not upload, sign or
publish the root. Its result remains synthetic/local and can remain partial despite observed
scheduler recovery. In particular, full Trust Graph/subscription budget-policy coverage is not
supplied by a foreground and subscription experiment alone.

## Collect and compare a separate baseline

[`runtime_baseline.py`](../tools/perf/runtime_baseline.py) is pure: it consumes existing bounded numeric
series and never starts nodes. Collection creates an unreviewed candidate with `review: null`.
[`runtime-synthetic-policy.json`](../tools/perf/baselines/runtime-synthetic-policy.json) is a deterministic
synthetic test policy, not an approved operational baseline or production safety limit.

Select and retain reference attempts before the candidate experiment. Use separate actual run IDs
and one process epoch per assessed curve. The helper retains per-epoch files in addition to its whole
run series; concatenating pre/post-restart points cannot establish uninterrupted resource behavior.
A per-epoch file missing required phases remains insufficient data.

```bash
python3 tools/perf/runtime_baseline.py collect \
  --series "$PR306_REFERENCE_A_SERIES" \
  --series "$PR306_REFERENCE_B_SERIES" \
  --policy tools/perf/baselines/runtime-synthetic-policy.json \
  --output "$PR306_BASELINE_CANDIDATE"

python3 tools/perf/runtime_baseline.py compare \
  --series "$PR306_CANDIDATE_SERIES" \
  --baseline "$PR306_PRESELECTED_BASELINE" \
  --output "$PR306_COMPARISON"
```

These commands do not supply approval. A candidate comparison binds the exact baseline selected
before execution. Reference content and summaries are recomputed; self-comparison, selection after
results, modified baseline bytes and incompatible workload/cohort/configuration/environment/collector
fingerprints cannot pass. Product/source identities may differ for regression comparison, while
comparable experiment conditions must agree. Container memory limits are not host RAM.

When a baseline is selected, its bounded original numeric reference is included in the prospective
runtime attachment and the pure consumer recomputes comparison claims. A compatible unreviewed
reference can establish comparability, but cannot establish reviewed bounds. Even a
`within-reviewed-local-bounds` result still requires external authentication of the original baseline
approval; the `runtime-within-reviewed-bounds` claim remains unobserved and the maintenance
`reviewed-runtime-baseline-missing` blocker remains. Neither a
caller-supplied comparison summary nor an uploaded summary substitutes for those original inputs.

The deterministic summaries are median, nearest-rank p95, peak, floor and ordinary least-squares
slope per second over predeclared phases. Warmup is excluded from selected phase summaries;
absolute safety checks still inspect samples. Recovery compares its predeclared metric with the
reference phase. Repetition count, dispersion, valid sample windows, success ratio and outstanding
work remain separate requirements. Terminal latency includes failures/timeouts/cancellations, and
outstanding work is retained instead of disappearing from completed-request p95.

A missing review produces measured/uncompared findings; incompatible or insufficient data cannot
pass. Even a local result named `within-reviewed-local-bounds` explicitly requires external original
review authentication and sets `releaseEligible: false`. No local review object creates a production
approval. A finite flat series establishes only the measured configuration/window, never a general
no-leak claim.

## Validation record and retained acceptance limits

The local delivery record below distinguishes executed checks from operational evidence. Logs and
numeric samples remain in private local build outputs; they are not original protected receipts.

| Required record | Delivery status |
| --- | --- |
| Starting source | `214f863bc166412cb8a9e657dbb41fc4aed46c84`, tree `bccfa2e6c40b989f40b5390e56b3ebbd30c63bc1`; local feature branch with uncommitted PR-306 changes. |
| Focused native scheduler/budget/runtime/authorization tests | Owning API, bridge, SPI, runtime-node and native fetch-port tests passed. Final reports total 17,296 tests, no failures/errors, 10 existing platform/benchmark/provider skips, including the two added defensive-copy regressions. |
| Actual packaged executor/pressure/recovery/resource run, duration and sample counts | Borrowed/local packaged tests: 2 passed in 235.317s, zero skips. Two subsequent final-code CLI runs each produced 73 first-epoch samples and 1,409 native events; detailed timing below. |
| Comparator and original-input contracts | 19 comparator tests and 42 runtime evidence/projection tests passed. These constructed negative/positive vectors are synthetic unit evidence. |
| Full shared-native checks | `spotlessApply`, full `test`, and `build assembleCryptadDist :platform-devtools:installDist` passed. Final retry took 6m20s, 765 tasks. An earlier Gradle daemon disappearance and one existing Mail header-timing assertion failure are retained; the Mail module passed unchanged on rerun. |
| Analyzer findings | Seven introduced SpotBugs findings fixed; two documented shared-native-recorder getter exposures remain reviewed. No new compiler warnings in the touched classes. Existing unrelated SpotBugs findings, non-blocking coverage warnings and skipped SonarLint tasks remain; build success is not an all-clean analyzer claim. |
| Affected PR-304/PR-305 integration checks | PR-304 product consumer (2) and PR-305 private-companion guard/product consumer (1) passed in 242.690s; packaged catalog install/update/source-switch/rollback/mirror test (1) passed in 57.054s. Zero skips. |
| Existing Python consumers | Interop 143; cross-version 111; stable-maintenance 247; Phase 12 177; app-platform 2; app-platform-docs 3; network-scale 3 tests passed. |
| Phase 12 before/after | Separate `build/pr306-phase12-before` and `build/pr306-phase12-after-final` roots, cutoff `2026-09-12T17:00:00Z`: 49 mandatory, 47 unresolved, `phaseComplete: false`; after assessment verifies locally. Existing implementation digests refreshed without changing acceptance scope or historical clocks. |

The final reference and preselected-baseline candidate used the signed synthetic cohort and actual
packaged executor. Both observed scheduler execution, pressure before budget, family accounting,
background recovery and a valid runtime series. Each offered 29 foreground operations: 25 succeeded,
two returned expected denials, and two timed out. The actual denial codes were
`network_budget_concurrency_limited` and `content_fetch_budget_exhausted`. The originally recorded
timeout durations (reference 20,541/20,298ms; candidate 20,551/20,300ms) included controller report
consumption delays. They are retained historical measurements, not valid request-terminal latency.

| Actual interval or metric | Reference | Candidate |
| --- | ---: | ---: |
| Requested maximum duration | 480s | 480s |
| Original journal start-to-finish span | 130,675ms | 131,092ms |
| First-epoch resource series span | 73,629ms | 73,645ms |
| Qualified selected resource intervals | 27,497ms | 27,478ms |
| Known pressure blocked to known clear | 20,030ms | 21,029ms |
| First useful scheduled success after clear | 1,014ms | 8ms |
| Peak process RSS | 261,525,504 bytes | 269,611,008 bytes |
| Peak heap used | 63,607,080 bytes | 66,850,792 bytes |
| Peak heap committed | 73,400,320 bytes | 73,400,320 bytes |
| Peak platform / OS threads | 57 / 77 | 57 / 77 |
| Peak open file descriptors | 54 | 53 |

Qualified resource intervals are not healthy uptime; fault intervals and restarted epochs are not
joined. The reference's original restart events establish same-window rate persistence for global
fetch (29 to 29), global subscriptions (23 to 23) and the approved synthetic app's subscriptions
(23 to 23). Process-local concurrency was reacquired in the new epoch; final observed leases and
reserved rates were zero. Changed minute windows and the foreground app family without a
post-restart read remain unproved.

The build used Temurin 25.0.4+7. These packaged runs selected Debian OpenJDK
25.0.4.1+1-1-deb13u1-Debian, G1, 64MiB initial heap and 1.5GiB maximum heap. The selected
whole-distribution digests differ because execution created two runtime log files in the copied
distribution. Every original package entry retained its fresh-build bytes, mode and symlink target;
daemon JAR and API identities match. This does not establish identical full distribution trees.
Exact identities, safe numeric results and collector fingerprints are retained in the local
`build/pr306-workload-validation-summary.json`; private originals and failed attempts are retained
separately and are not public upload assets.

Baseline collection exited zero and produced an unreviewed candidate. The standalone comparison
exited **2**, with `measured-but-uncompared`, `reviewed-runtime-baseline-missing` and
`runtime-reference-insufficient-data`: the collected reference has one repetition while the policy
requires two. Neither baseline claim passed. Collection did not approve the reference, change
tolerances or discard the intentional timeout observations. All owned PR-306 Java processes were
cleaned up after the runs.

### Request-latency review correction

Review found that pressure-request latency was measured when the controller consumed each child
report, including sampling, polling and time spent waiting for another child. The fixed CJS driver
now measures integer milliseconds with its monotonic clock from request start to the first terminal
callback (HTTP response completion, transport failure or timeout). Duplicate callbacks cannot change
the result. The controller accepts only a bounded nonnegative integer `latencyMillis` and exports
that value without adding collection time. Ordinary foreground measurements retain their existing
synchronous request-call boundary.

Deterministic regressions exercise overlapping requests that terminate out of order, delayed report
consumption, duplicate callbacks, transport failures and timeout callbacks. Invalid or missing driver
latencies fail observation rather than becoming zero. The driver/helper digests are already part of
the collector fingerprint, so prior series cannot be silently treated as using the corrected
collector. Earlier pressure-latency summaries and baselines need recollection for terminal-latency
comparison; their original bytes are not rewritten or upgraded by the fix.

Correction validation passed: 145 interop tests, 19 runtime comparator tests, 42 runtime
evidence/projection tests, and the actual packaged executor/contention/recovery/resource test with
zero skips. Java production code and the distribution were unchanged by this correction.

### Absolute-deadline review correction

Pressure mode previously passed the relative timeout directly to the request function, bypassing
the absolute monotonic deadline used by the foreground exercise. The shared request boundary now
uses the earlier of the relative timeout and `deadlineMonotonicNs`, after checking activation.
Expired windows and windows shorter than the one-millisecond timer minimum reject before opening
a request. The content-fetch timeout is capped to the remaining window, and the transport timer
is recalculated after request setup so setup time does not extend the selected deadline. An expired
window after setup destroys the request without sending its body. Timer dispatch remains subject to
the Node event loop; this is a bounded timeout policy, not a real-time scheduling guarantee.

Regressions cover the actual pressure CLI with an expired deadline and no connection, delayed
startup with only 750ms remaining from a requested 20 seconds, request setup consuming another
20ms, and exact/sub-millisecond expiration. Earlier observations are not retroactively upgraded
to proof of this deadline enforcement; the changed driver digest distinguishes the corrected
collector.

Deadline-correction validation passed: 147 interop tests, 42 runtime evidence/projection tests,
19 comparator tests, and one actual packaged executor/contention/recovery/resource integration
with zero skips. The existing Phase 12 assessment still verifies with 47 unresolved requirements.

### Hosted-runner cgroup observation

The environment collector resolves the selected process's cgroup v2 membership and mount instead
of assuming controller files at `/sys/fs/cgroup` describe that process. Before launch it observes
the collector; after launch it binds the daemon's exact process identity and brackets collection
with identity, membership and mount checks. It inspects at most 32 visible ancestors, retaining the
tightest memory limit and CPU quota ratio plus a digest of the observed controller configuration.
The process's allowed CPU mask and host RAM are recorded separately from cgroup limits.

The kernel's `cpu.max` and `memory.max` interfaces are non-root controls. Their absence at the
visible hierarchy root is distinct from an unreadable controller file. An absent child interface
counts as no direct child limit only when the parent's `cgroup.subtree_control` confirms that
controller is disabled; ancestor limits still apply. Missing enabled interfaces, permissions
failures, hidden ancestors, unsupported v1 layouts and changing process identity remain unknown.
The scope is the visible cgroup v2 hierarchy, without a claim about inaccessible outer namespaces.
This correction changes the collector/environment fingerprints; it does not change baseline
thresholds or weaken series validity. Packaged test failures print only the fixed resource finding
codes alongside the failed claim, retaining private runtime files separately.

Local validation of this correction passed 160 offline adapter tests, 42 evidence/projection
tests, 19 comparator tests and both fresh packaged scheduler cases (227.045s, zero skips).
Both cases also passed locally before the correction (237.704s); the original hosted log omitted
the underlying resource findings, so that local comparison alone does not prove the hosted cause.

Narrow claims remain separate: scheduler executor observation, pressure before budget, verified
budget-family accounting, background recovery, valid resource series, baseline comparability and
within-reviewed-bounds. Original producer authentication, synthetic/live classification, product and
freeze identity, elapsed duration, required nodes/operations, cleanup and overall release eligibility
must still be assessed by their existing owners. Passing one component does not complete all nine
maintenance rows or alter `ACCEPTANCE_SCOPE_DIGEST`.

Unobserved default-profile behavior, production/public-network operation, actual 24/72-hour windows,
authenticated reviewed production resource baselines, full Trust Graph/import budget coverage,
independent operator/security review, Mail/migration scenarios and remaining Phase 12 requirements
stay explicit. See [Phase 12 closeout](phase-12-operational-closeout.md),
[open items](phase-12-open-items.md) and [cross-version soak](cross-version-live-network-soak.md).

PR-305's selected-federation v4/private native declarations remain encrypted. Maintenance freeze
publication continues to reject unsupported private companions with
`runtime-metadata-private-companion-unsupported`; this workload neither decrypts them into public
freeze assets nor implements encrypted companion transport. That dependency remains a separate
prospective slice.
