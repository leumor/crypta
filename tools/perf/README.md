# Performance regression gate

Use this gate to collect lightweight, repeatable regression indicators for the packaged Cryptad
platform path.

This harness is separate from the Hyphanet interop gate under `tools/interop/`. Interop proves
compatibility with a pinned baseline node. The performance gate records local startup, control-plane,
and asset-size signals so release candidates have a comparable regression record.

The [cross-version observed runner](../../docs/cross-version-live-network-soak.md) records bounded
runtime counters separately. It cannot replace these reviewed baselines or treat unavailable
memory/thread/queue measurements as a pass. A small single-host topology is not a scale benchmark.

## Requirements

- Python 3.12 or newer for the runner and wrapper.
- Java 25 and the Gradle wrapper when the smoke wrapper builds `build/cryptad-dist/`.
- A packaged Cryptad distribution under `build/cryptad-dist/` when using `PERF_SKIP_BUILD=1`.

## Scope and modes

The gate favors stable smoke signals over benchmarking depth. It does not tune performance, publish
network-wide performance claims, or replace normal Gradle tests and interop validation.

| Mode | Command | Starts Cryptad | Comparison behavior |
| --- | --- | --- | --- |
| Self-test | `python3 tools/perf/perf_smoke.py --self-test` | No | Validates parser defaults, summary schema, baseline pass/warn/fail behavior, skipped metrics, redaction, and report generation. |
| Smoke | `PERF_MODE=smoke tools/perf/run-performance-smoke.sh` | Yes, when a packaged distribution and Java are available | Compares collected metrics against `tools/perf/baselines/performance-smoke.json`. Deterministic asset-size failures fail; environment-sensitive timings warn unless `PERF_FAIL_ON_REGRESSION=1`. |
| Collect | `PERF_MODE=collect tools/perf/run-performance-smoke.sh` | Yes, when available | Records metrics and comparison output without making threshold misses fail the run. Use this mode on new hardware or before refreshing a baseline. |

If a node, Java runtime, packaged distribution, port, or local API prerequisite is not available, the
runner records the affected metric as `skipped` with a reason. Skipped metrics are explicit in
`summary.json`, `raw-metrics.json`, `baseline-comparison.json`, and `perf-report.md`.
If a packaged node starts but does not reach FCP or Platform API readiness before
`PERF_STARTUP_TIMEOUT_SECONDS`, the readiness metric is recorded as `failed` with the timeout value;
that is treated as a smoke-gate failure rather than an optional skip.

## Run locally

Run the Python-only self-test:

```bash
python3 tools/perf/perf_smoke.py --self-test
```

Build the packaged distribution and run the smoke gate:

```bash
tools/perf/run-performance-smoke.sh
```

If `build/cryptad-dist/` already exists:

```bash
PERF_SKIP_BUILD=1 tools/perf/run-performance-smoke.sh
```

Collect metrics without failing on threshold comparison:

```bash
PERF_MODE=collect \
PERF_SKIP_BUILD=1 \
tools/perf/run-performance-smoke.sh
```

Refresh baseline values intentionally after reviewing the collected output:

```bash
PERF_MODE=collect \
PERF_SKIP_BUILD=1 \
PERF_UPDATE_BASELINE=1 \
tools/perf/run-performance-smoke.sh
```

The wrapper delegates to:

```bash
python3 tools/perf/perf_smoke.py \
  --workspace-root "$PWD" \
  --cryptad-dist-dir build/cryptad-dist \
  --out-dir build/perf-smoke \
  --baseline tools/perf/baselines/performance-smoke.json \
  --mode smoke
```

## Metrics

The smoke profile collects deterministic file-size metrics even when no node starts:

| Metric | Unit | Source |
| --- | --- | --- |
| `distribution.exists` | boolean | Whether `CRYPTAD_DIST_DIR` exists. |
| `distribution.size_bytes` | bytes | Total file size under `CRYPTAD_DIST_DIR`, excluding generated `logs/` and `tmp/` directories. |
| `distribution.build_ms` | ms | Time spent running `./gradlew assembleCryptadDist` when `PERF_SKIP_BUILD=0`. |
| `web_shell.index_html_bytes` | bytes | `platform-web-shell` source `index.html`. |
| `web_shell.web_shell_js_bytes` | bytes | `platform-web-shell` source `web-shell.js`. |
| `web_shell.web_shell_css_bytes` | bytes | `platform-web-shell` source `web-shell.css`. |
| `platform_sdk.crypta_platform_js_bytes` | bytes | `platform-sdk-js` source `crypta-platform.js`. |
| `apps.feed_reader_static_bytes` | bytes | Sum of Feed Reader `src/staged/static/` files. |
| `apps.queue_manager_static_bytes` | bytes | Sum of Queue Manager `src/staged/static/` files. |
| `apps.publisher_static_bytes` | bytes | Sum of Publisher `src/staged/static/` files. |
| `apps.profile_publisher_static_bytes` | bytes | Sum of Profile Publisher `src/staged/static/` files. |
| `apps.site_publisher_static_bytes` | bytes | Sum of Site Publisher `src/staged/static/` files. |
| `apps.social_inbox_static_bytes` | bytes | Sum of Social Inbox Preview `src/staged/static/` files. |
| `apps.trust_graph_static_bytes` | bytes | Sum of Trust Graph Preview `src/staged/static/` files. |
| `apphost.feed_reader_staged_bundle_bytes` | bytes | Staged Feed Reader bundle under `apps/feed-reader/build/cryptad-app/feed-reader`, when present. |
| `apphost.queue_manager_staged_bundle_bytes` | bytes | Staged Queue Manager bundle under `apps/queue-manager/build/cryptad-app/queue-manager`, when present. |
| `apphost.publisher_staged_bundle_bytes` | bytes | Staged Publisher bundle under `apps/publisher/build/cryptad-app/publisher`, when present. |
| `apphost.profile_publisher_staged_bundle_bytes` | bytes | Staged Profile Publisher bundle under `apps/profile-publisher/build/cryptad-app/profile-publisher`, when present. |
| `apphost.site_publisher_staged_bundle_bytes` | bytes | Staged Site Publisher bundle under `apps/site-publisher/build/cryptad-app/site-publisher`, when present. |
| `apphost.social_inbox_staged_bundle_bytes` | bytes | Staged Social Inbox Preview bundle under `apps/social-inbox/build/cryptad-app/social-inbox`, when present. |
| `apphost.trust_graph_staged_bundle_bytes` | bytes | Staged Trust Graph Preview bundle under `apps/trust-graph/build/cryptad-app/trust-graph`, when present. |

When a packaged node can run locally, the smoke profile also attempts environment-sensitive metrics:

| Metric | Unit | Source |
| --- | --- | --- |
| `node.startup_to_process_spawn_ms` | ms | Time to spawn `build/cryptad-dist/bin/cryptad`. |
| `node.startup_to_platform_readiness_ms` | ms | Time until the local Platform API responds and the readiness file is observed when available. |
| `node.startup_to_fcp_ready_ms` | ms | Time until the local FCP TCP port accepts a connection. |
| `fcp.client_hello_ms` | ms | `ClientHello` to `NodeHello` round trip on the local FCP port. |
| `platform_api.node_ms` | ms | `GET /api/v1/node/greeting`, the current node-info route. |
| `platform_api.peers_ms` | ms | `GET /api/v1/peers`. |
| `platform_api.apps_ms` | ms | `GET /api/v1/apps`. |
| `platform_api.diagnostics_ms` | ms | `GET /api/v1/diagnostics`. |

AppHost install/update timings are not part of the default smoke gate yet. The runner records staged
bundle sizes and keeps install/update operations skipped until the local credential and signed-bundle
flow is stable enough for CI.

## Configuration

The wrapper and Python runner support these environment variables:

| Variable | Default | Effect |
| --- | --- | --- |
| `PERF_MODE` | `smoke` | `smoke` compares against the baseline. `collect` records advisory output. |
| `PERF_OUT_DIR` | `build/perf-smoke` | Output directory for summaries and artifacts. |
| `PERF_BASELINE` | `tools/perf/baselines/performance-smoke.json` | Baseline JSON used for comparison. |
| `PERF_UPDATE_BASELINE` | `0` | Set to `1` to rewrite baseline values from collected numeric metrics. |
| `PERF_SKIP_BUILD` | `0` | Set to `1` when `build/cryptad-dist/` already exists. |
| `PERF_TIMEOUT_SECONDS` | `300` | Timeout for the Gradle distribution build launched by the runner. |
| `PERF_STARTUP_TIMEOUT_SECONDS` | `120` | Timeout for local node readiness checks. |
| `PERF_REQUEST_TIMEOUT_SECONDS` | `30` | Timeout for FCP and HTTP requests. |
| `PERF_FAIL_ON_REGRESSION` | `0` | Set to `1` to make environment-sensitive timing failures fail instead of warn. |
| `CRYPTAD_DIST_DIR` | `build/cryptad-dist` | Packaged distribution to inspect and run. |
| `CRYPTAD_FNP_PORT` | `29601` | Local FNP UDP port for the smoke node. |
| `CRYPTAD_FCP_PORT` | `29602` | Local FCP TCP port for the smoke node. |
| `CRYPTAD_WEB_PORT` | `29603` | Local HTTP/Platform API port for the smoke node. |

The default ports intentionally avoid the `tools/interop/` defaults.
When `PERF_OUT_DIR` already exists, the runner cleans or writes it only if it is below `build/` or
contains the `.cryptad-perf-smoke-output` marker written by a previous perf run. This prevents
typos such as `PERF_OUT_DIR=docs` from deleting or marking source-controlled files.

## Artifacts

The runner writes public, redacted outputs under `PERF_OUT_DIR`:

```text
build/perf-smoke/
  summary.json
  artifacts/
    baseline-comparison.json
    perf-report.md
    raw-metrics.json
    logs/
```

`summary.json` is the top-level machine-readable contract. It includes:

- `status`: `success`, `warning`, or `failure`
- `mode`: `self-test`, `smoke`, or `collect`
- `environment`: OS, architecture, Java version, and Python version
- `baseline`: baseline path, version, and update flag
- `metrics`: collected, skipped, and failed metric records
- `comparison`: `pass`, `warn`, `fail`, or `not_compared`, with regressions, warnings, skipped metrics, and untracked metrics

Node working directories live under `build/perf-smoke/work/` during a run. CI uploads only
`summary.json` and `artifacts/` so local node stores and run-state directories are not published.
Logs under `artifacts/logs/` are sanitized before reports are written; token-like values,
password-like values, private URIs, and local workspace or home-directory prefixes are redacted.

The release certification workflow consumes `build/perf-smoke/summary.json` as required
`performance.smoke` evidence and copies the sanitized `artifacts/perf-report.md` into
`<out-root>/<release-id>/release-certification/artifacts/legacy/` when present.

## Baselines

`tools/perf/baselines/performance-smoke.json` is a checked-in smoke baseline with conservative
thresholds. Each metric rule can define:

- `baseline`: reference numeric value
- `unit`: expected unit
- `warn_ratio` / `fail_ratio`: ratio against the baseline
- `warn_ms` / `fail_ms`: absolute timing limits
- `max_bytes`: absolute payload limit
- `fail_on_regression`: whether a fail-level threshold should fail by default
- `required`: whether a missing current metric is a failure

Deterministic asset sizes use stronger fail behavior. Startup, FCP, and Platform API timings are
environment-sensitive, so they warn by default unless `PERF_FAIL_ON_REGRESSION=1`.
Smoke mode requires an existing baseline file. `collect` mode and `PERF_UPDATE_BASELINE=1` may use
an empty baseline to bootstrap a new comparison file.

Do not update baselines only to silence a regression. A baseline update should include the before
and after summaries, host or runner details, Java version, commit SHA, and a short rationale.

## CI behavior

CI has two jobs:

- `performance-self-test` runs `python3 tools/perf/perf_smoke.py --self-test` with Python 3.12 on
  the regular multi-OS self-test matrix. It does not start Cryptad.
- `performance-smoke` runs only on `workflow_dispatch` and `schedule` on Linux. It builds
  `build/cryptad-dist/` through the perf runner so `distribution.build_ms` is collected, runs the
  smoke profile with Python 3.12 available, and uploads `summary.json` plus `artifacts/`.

Regular pull requests get the Python self-test without the full node smoke. That keeps the default
PR path low-flake while preserving scheduled/manual evidence for release candidates.

The separate `release-certification` workflow can run the performance smoke before generating
`<out-root>/<release-id>/release-certification/report.md` and
`<out-root>/<release-id>/release-certification/summary.json`.

## Interpreting results

Use the same mode, OS, JDK, runner class, and baseline when comparing runs. File-size metrics are
deterministic enough to treat threshold failures as actionable. Startup, FCP, and HTTP timings can
move because of CPU contention, filesystem speed, Java warmup, and shared CI runners.
Readiness timeouts after the packaged node has launched are failures because they mean the local
control plane never became usable within the configured smoke window.

When a threshold miss is legitimate, update the baseline intentionally and include the rationale in
the commit or release record. When a threshold miss is unexplained, inspect `summary.json`,
`artifacts/baseline-comparison.json`, `artifacts/perf-report.md`, and `artifacts/logs/` before
rerunning or cleaning the workspace.

The public summary, report, raw metrics, and logs redact token-like, password-like, key-like, and
private URI material. The runner does not dump the process environment or raw Platform API response
bodies.

## Bounded runtime resource baselines

The separate [`runtime_baseline.py`](runtime_baseline.py) collect/compare path consumes exact-process
numeric series from the packaged content-subscription workload. It does not reuse the startup or
asset limits in `baselines/performance-smoke.json`, launch nodes, or approve collected references.
Run `python3 -m unittest discover -s tools/perf -p test_runtime_baseline.py` for the pure verifier.

The checked-in `baselines/runtime-synthetic-policy.json` is a finite synthetic integration policy,
not a reviewed production baseline. Select the exact policy and optional baseline before workload
execution; collection preserves every selected attempt with `review: null`. Comparison checks
fingerprints, process epochs, complete phase coverage, all terminal outcomes, useful progress,
absolute safety, median/p95/peak, trend and recovery. CPU deltas use one logical CPU times elapsed
nanoseconds as their denominator; GC deltas are collector statistics, not exact pause totals.

See [the scheduler/resource runbook](../../docs/pr-306-scheduler-pressure-and-runtime-resource-baselines.md)
for actual commands, units, privacy constraints and retained operational requirements.
