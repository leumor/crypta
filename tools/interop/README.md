# Hyphanet interop gate

Use this gate to verify that a packaged Cryptad node can interoperate with a pinned Hyphanet
baseline over darknet peering and FCP content operations.

The [cross-version observed experiment](../../docs/cross-version-live-network-soak.md) reuses these
clients under an exclusive packaged-process supervisor. It keeps all FCP transcripts and node
references private and exports separate bounded results. It does not reinterpret this gate's
datastore, polling fallback or skipped subscription directions as stronger evidence.

PR-194 records this existing harness as a Phase 3 release gate. The closeout summary is in
[docs/phase-3-platform-primacy-closeout.md](../../docs/phase-3-platform-primacy-closeout.md), and
the release checklist is in
[docs/cryptad-release-workflow-and-runbook.md](../../docs/cryptad-release-workflow-and-runbook.md).

## Scope and modes

The gate is Linux-only and runs two local nodes:

- Cryptad from `build/cryptad-dist/bin/cryptad`
- Hyphanet from the configured baseline in `hyphanet-baseline.env`

Both nodes bind client/FCP access to `127.0.0.1`. The default harness disables opennet,
browser/FProxy, and the console endpoint so the test stays deterministic and local to the CI runner
or developer machine.

Interop has two tiers:

| Tier | Mode | Required for release readiness | Runtime | Coverage |
| --- | --- | --- | --- | --- |
| Tier 1 | CI smoke | Yes. A release candidate must pass this tier locally on Linux or in the `interop-smoke` CI job. | Bounded by `INTEROP_TIMEOUT_SECONDS` (`900` seconds by default). | FCP handshake, darknet peer exchange, CHK/SSK/USK cross-fetch, Cryptad restart, peer reconnect, persistent request listing, and post-restart refetch. |
| Tier 2 | Extended soak | Required before widening compatibility claims or changing interop-sensitive behavior. It runs from scheduled/manual CI and can also run locally. | Bounded by `INTEROP_EXTENDED_TIMEOUT_SECONDS` (`3600` seconds by default in the wrapper). | Long-lived `SubscribeUSK`, persistent request replay with a deliberately unfinished request, optional opennet plumbing, multi-OS self-tests, and longer diagnostics. |

The mandatory flows are:

| Flow             | Validation                                                                                                                             |
|------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| FCP handshake    | `ClientHello`, `NodeHello`, `GetNode`, and `NodeData` on both nodes                                                                    |
| Peer exchange    | `AddPeer`, `ListPeers`, connected darknet status, and `ModifyPeer` disable/re-enable by default                                        |
| CHK cross-fetch  | Cryptad inserts a CHK and Hyphanet fetches it; Hyphanet inserts a CHK and Cryptad fetches it                                           |
| SSK cross-fetch  | Each side generates an SSK keypair, inserts deterministic bytes, and the other side fetches them                                       |
| USK smoke        | Each side inserts editions `0` and `1`; the other side fetches deterministic edition URIs                                              |
| Restart recovery | Cryptad restarts, FCP returns, the peer relationship reconnects, persistent requests are listed before and after restart, and Hyphanet refetches content inserted by the restarted Cryptad node |

Content inserts use `ConsecutiveRNFsCountAsSuccess=0` so the gate treats route-not-found results as
real insert failures. That prevents FCP `PutSuccessful` from masking a block that never reached the
baseline peer in the two-node test network. For single-block payloads the harness may keep the
source insert local and make the opposite node fetch the resulting URI; the compatibility assertion
is the cross-node fetch and byte comparison, not broad network propagation in a two-node topology.

The restart flow uses the current minimum release gate: restart and refetch. The harness also calls
`ListPersistentRequests` before and after restart and records the results. Full persistent request
replay belongs to the Tier 2 soak profile because it needs a request that intentionally survives the
restart unfinished, plus enough runtime to prove that the restarted node resumes it instead of
starting a new one.

Tier 1 keeps USK coverage in the pre-restart USK smoke, where both nodes publish and fetch
deterministic editions. The restart flow does not refetch USK editions because the pinned two-node
baseline can spend the rest of the CI budget polling for a post-restart USK result even after FCP,
peer reconnect, CHK refetch, and SSK refetch have succeeded. The summary records the post-restart
USK refetch as a deferred check so release evidence shows the boundary explicitly. The CHK and SSK
restart checks still use `IgnoreDS=true` so local datastore hits do not mask their network refetch
assertions.

`SubscribeUSK` is also Tier 2. The CI smoke proves deterministic edition fetches, but it does not
hold a subscription open while a later edition is published. Extended mode inserts an initial USK
edition, opens `SubscribeUSK` on the opposite node, inserts a later edition, and waits for the
subscriber to observe it. If the pinned baseline accepts the subscription but does not emit the
target update before the soak timeout, the harness records a bounded fetch fallback and the
limitation in `summary.json` and `artifacts/usk-subscribe-soak.json`.

Opennet remains off in Tier 1 and Tier 2 by default. `INTEROP_ENABLE_OPENNET=1` launches both
nodes with `node.opennet.enabled=true` and records the `opennet_optional` flow as requested, but
the current pinned Linux baseline does not have a deterministic local opennet path-validation flow.
The flow is reported as skipped with a reason, not as a replacement for the darknet gate.

## Run locally

Build the packaged distribution and run the gate:

```bash
tools/interop/run-hyphanet-interop-smoke.sh
```

If `build/cryptad-dist/` already exists:

```bash
INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
```

Run the extended tier locally after a distribution has been built:

```bash
INTEROP_MODE=extended \
INTEROP_SKIP_BUILD=1 \
tools/interop/run-hyphanet-interop-smoke.sh
```

Run only the Python parser/client self-test:

```bash
python3 tools/interop/interop_smoke.py --self-test
```

Useful local overrides:

```bash
INTEROP_SKIP_BUILD=1 \
INTEROP_WORKDIR=/tmp/cryptad-interop \
CRYPTAD_FCP_PORT=29402 \
HYPHANET_FCP_PORT=29502 \
tools/interop/run-hyphanet-interop-smoke.sh
```

Set `INTEROP_KEEP_WORKDIR=1` only for interactive debugging. That mode leaves child node processes
running and writes their PIDs to `artifacts/kept-processes.json`.

Peer mutation validation defaults to `ModifyPeer` disable/re-enable:

```bash
INTEROP_VALIDATE_PEER_MUTATION=modify tools/interop/run-hyphanet-interop-smoke.sh
```

Set `INTEROP_VALIDATE_PEER_MUTATION=remove-readd` to exercise destructive `RemovePeer` followed by
`AddPeer`. That mode is useful for manual investigation, but the default release gate avoids it
because deleting a peer can destabilize the two-node baseline before content-flow validation.

## Configuration reference

The shell wrapper reads environment variables, validates Linux and `python3`, optionally builds the
Cryptad distribution, and then passes deterministic CLI arguments to `interop_smoke.py`.

| Environment variable | Default | Effect |
| --- | --- | --- |
| `CRYPTAD_DIST_DIR` | `build/cryptad-dist` | Packaged Cryptad distribution to run. |
| `INTEROP_MODE` | `smoke` | `smoke` keeps the short Tier 1 gate. `extended` enables Tier 2 flows unless explicitly disabled. |
| `INTEROP_ENABLE_USK_SUBSCRIBE_SOAK` | unset | Set to `1` to enable `usk_subscribe_soak` outside extended mode. Set to `0` to disable it in extended mode. |
| `INTEROP_ENABLE_PERSISTENT_REPLAY` | unset | Set to `1` to enable `persistent_request_replay` outside extended mode. Set to `0` to disable it in extended mode. |
| `INTEROP_ENABLE_OPENNET` | `0` | Launches both nodes with opennet enabled and records optional opennet plumbing. The current harness reports `opennet_optional` as skipped because deterministic local opennet path validation is not pinned. |
| `INTEROP_SKIP_BUILD` | `0` | Set to `1` when `CRYPTAD_DIST_DIR` already exists. |
| `INTEROP_WORKDIR` | unset | Primary output/work directory override. Takes precedence over `INTEROP_OUT_DIR`. |
| `INTEROP_OUT_DIR` | `build/interop-smoke` for smoke, `build/interop-extended` for extended | Output/work directory when `INTEROP_WORKDIR` is unset. |
| `INTEROP_CACHE_DIR` | `build/interop-cache` | Reusable baseline download cache. |
| `INTEROP_KEEP_WORKDIR` | `0` | Set to `1` to leave child node processes running and write `artifacts/kept-processes.json`. |
| `INTEROP_TIMEOUT_SECONDS` | `900` | Whole-suite timeout. |
| `INTEROP_EXTENDED_TIMEOUT_SECONDS` | `3600` | Whole-suite timeout used by the wrapper when `INTEROP_MODE=extended` and `INTEROP_TIMEOUT_SECONDS` is unset. |
| `INTEROP_STARTUP_TIMEOUT_SECONDS` | `180` | Per-node FCP startup timeout. |
| `INTEROP_PEER_TIMEOUT_SECONDS` | `120` | Darknet peer connection timeout. |
| `INTEROP_REQUEST_TIMEOUT_SECONDS` | `300` | Content request timeout; restart refetch uses twice this value. |
| `INTEROP_SOAK_DURATION_SECONDS` | `300` | `SubscribeUSK` observation window for extended mode. |
| `INTEROP_SOAK_POLL_INTERVAL_SECONDS` | `15` | Maximum FCP read interval while waiting for subscription updates. |
| `INTEROP_VALIDATE_PEER_MUTATION` | `modify` | `modify`, `remove-readd`, `none`, `skip`, `false`, or `0`. |
| `CRYPTAD_FNP_PORT` | `19401` | Cryptad FNP UDP port. |
| `CRYPTAD_FCP_PORT` | `19402` | Cryptad FCP TCP port. |
| `HYPHANET_FNP_PORT` | `19501` | Hyphanet FNP UDP port. |
| `HYPHANET_FCP_PORT` | `19502` | Hyphanet FCP TCP port. |
| `HYPHANET_BASELINE_JAR` | unset | Local Hyphanet baseline jar. |
| `HYPHANET_BASELINE_CLASSPATH` | unset | Classpath for non-executable local baseline jars. |
| `HYPHANET_BASELINE_MAIN_CLASS` | unset | Main class for classpath-based local baseline launches. |
| `HYPHANET_BASELINE_URL` | verified 1506 `.deb` URL | Remote baseline asset URL. |
| `HYPHANET_BASELINE_SHA256` | verified 1506 `.deb` SHA-256 | Required checksum for remote baselines. |
| `HYPHANET_BASELINE_VERSION` | `1506` | Version label written to `summary.json`. |
| `HYPHANET_VERSION` | `0.7.5` | Compatibility alias used to construct the default release asset name. |
| `HYPHANET_BUILD` | `HYPHANET_BASELINE_VERSION` | Compatibility alias for older local invocations. |
| `HYPHANET_RELEASE_TAG` | `build01506` | Compatibility alias used to construct the default GitHub release URL. |
| `HYPHANET_DEB_ASSET` | `freenet_0.7.5+1506-1_amd64.deb` | Compatibility alias for the default Debian package asset. |
| `HYPHANET_DEB_SHA256` | verified 1506 `.deb` SHA-256 | Compatibility alias for the default Debian package checksum. |
| `HYPHANET_RELEASE_URL` | verified 1506 `.deb` URL | Compatibility alias for the default remote baseline URL. |

Direct Python arguments are available for CI and debugging:

```bash
python3 tools/interop/interop_smoke.py \
  --workspace-root "$PWD" \
  --cryptad-dist-dir build/cryptad-dist \
  --out-dir build/interop-smoke \
  --download-cache-dir build/interop-cache \
  --mode smoke \
  --suite-timeout-seconds 900 \
  --startup-timeout-seconds 180 \
  --peer-timeout-seconds 120 \
  --request-timeout-seconds 300 \
  --soak-duration-seconds 300 \
  --soak-poll-interval-seconds 15 \
  --cryptad-fnp-port 19401 \
  --cryptad-fcp-port 19402 \
  --hyphanet-fnp-port 19501 \
  --hyphanet-fcp-port 19502
```

Extended-only switches are also available:

```text
--mode extended
--enable-usk-subscribe-soak
--disable-usk-subscribe-soak
--enable-persistent-replay
--disable-persistent-replay
--enable-opennet
```

Add `--keep-workdir` to the Python invocation to match `INTEROP_KEEP_WORKDIR=1`. Use
`python3 tools/interop/interop_smoke.py --self-test` for the parser/client self-test; it does not
start nodes and does not require the workspace, distribution, output, or cache arguments.

Use the wrapper for normal runs. It enforces the Linux-only check before invoking Python and keeps
the default Gradle build path aligned with the repository.

## Baseline configuration

`hyphanet-baseline.env` defines defaults and lets caller-provided environment variables win.

The checked-in default uses the verified Hyphanet 1506 Debian package:

- `HYPHANET_BASELINE_VERSION=1506`
- `HYPHANET_BASELINE_URL=https://github.com/hyphanet/fred/releases/download/build01506/freenet_0.7.5+1506-1_amd64.deb`
- `HYPHANET_BASELINE_SHA256=b97d04d8a8f34d8e168e296de82e74dc527a6a02b2aa98c46d1fe9d76e2d1ee3`

For local testing with a pre-downloaded baseline:

```bash
HYPHANET_BASELINE_JAR=/path/to/hyphanet-baseline.jar \
INTEROP_SKIP_BUILD=1 \
tools/interop/run-hyphanet-interop-smoke.sh
```

If the jar is not executable with `java -jar`, also set:

```bash
HYPHANET_BASELINE_CLASSPATH=/path/to/dependencies/* \
HYPHANET_BASELINE_MAIN_CLASS=freenet.node.NodeStarter
```

For a remote baseline, provide both URL and checksum:

```bash
HYPHANET_BASELINE_URL=https://example.invalid/hyphanet-baseline.jar \
HYPHANET_BASELINE_SHA256=<sha256> \
tools/interop/run-hyphanet-interop-smoke.sh
```

The harness fails before node startup if it cannot find a local jar or a verified URL/checksum pair.
It never downloads an unverified remote jar or package.
Verified baseline packages are cached in `build/interop-cache/` by default so reruns can work
without re-downloading the baseline. Set `INTEROP_CACHE_DIR` to use a different cache location.
Extracted `.deb` contents are staged under the per-run `downloads/` diagnostics directory, not in
the reusable cache, so concurrent runs with separate work directories cannot replace each other's
classpath while nodes are starting.

## Timeouts and ports

Default timeouts:

- `INTEROP_TIMEOUT_SECONDS=900`
- `INTEROP_EXTENDED_TIMEOUT_SECONDS=3600`
- `INTEROP_STARTUP_TIMEOUT_SECONDS=180`
- `INTEROP_PEER_TIMEOUT_SECONDS=120`
- `INTEROP_REQUEST_TIMEOUT_SECONDS=300`
- `INTEROP_SOAK_DURATION_SECONDS=300`
- `INTEROP_SOAK_POLL_INTERVAL_SECONDS=15`

Default ports:

- `CRYPTAD_FNP_PORT=19401`
- `CRYPTAD_FCP_PORT=19402`
- `HYPHANET_FNP_PORT=19501`
- `HYPHANET_FCP_PORT=19502`

The harness checks each port before startup and fails clearly if another local process is using it.

## Artifacts

Every run writes diagnostics under `build/interop-smoke/` unless `INTEROP_WORKDIR` or
`INTEROP_OUT_DIR` overrides the location. Extended mode defaults to `build/interop-extended/`.

```text
build/interop-smoke/
  downloads/
  cryptad/
  hyphanet/
  logs/
  transcripts/
  artifacts/
  summary.json
```

Important files:

- `summary.json` contains machine-readable status, flow results, ports, baseline details, URI
  records, artifact paths, process statuses, and the failure reason when a run fails.
- `transcripts/*.fcp.txt` logs sent and received FCP message names, identifiers, key fields, and
  data payloads. Private insert URIs are redacted in transcripts.
- `artifacts/*-node-reference.fref` and `artifacts/*-node-reference.json` contain exported node
  references.
- `artifacts/*peers*.json` records peer lists after add, optional mutation, and restart.
- `artifacts/cryptad-persistent-requests-before-restart.json` and
  `artifacts/cryptad-persistent-requests-after-restart.json` record persistent request listings
  around the restart flow.
- `artifacts/usk-subscribe-soak.json` records the extended `SubscribeUSK` source/subscriber,
  initial edition, observed edition, timing, fallback status, and transcript names.
- `artifacts/persistent-requests-before-restart.json`,
  `artifacts/persistent-requests-after-restart.json`,
  `artifacts/persistent-requests-after-completion.json`, and
  `artifacts/persistent-request-replay.json` record the extended persistent replay flow.
- `artifacts/interop-report.md` is a concise, redacted text report safe to upload to CI.
- `artifacts/private-insert-uris.json` contains temporary SSK/USK insert URIs and is written with
  owner-only file permissions. Do not publish this file in CI artifacts or release records.
- `artifacts/port-assignments.json` records the FNP/FCP ports selected for the run.
- `artifacts/kept-processes.json` is written only when `INTEROP_KEEP_WORKDIR=1`.
- `logs/*.stdout.log` and `logs/*.stderr.log` capture each launched process.

The release certification workflow consumes `build/interop-smoke/summary.json` as required
`interop.smoke` evidence and `build/interop-extended/summary.json` as optional
`interop.extended` evidence unless compatibility-sensitive behavior makes Tier 2 mandatory under
the release runbook. The certification aggregator filters `artifacts/private-insert-uris.json`
even if a source summary references it.

`summary.json` uses these top-level fields:

| Field | Meaning |
| --- | --- |
| `status` | `success` or `failure`. |
| `failure_reason` | Present on failure. Mirrors the exception message that stopped the run with private URI and splitfile key material redacted. |
| `mode` | `smoke` or `extended`. |
| `enabled_flows` | Ordered list of flows selected for this run. Smoke mode contains only Tier 1 flows by default. |
| `skipped_flows` | Map of skipped flow name to reason. |
| `flows` | Map of flow name to an object with `status` (`passed`, `failed`, `skipped`, or `running` while in progress), `duration_seconds` when available, and flow-specific fields. |
| `baseline` | Hyphanet baseline kind, version label, asset path, and SHA-256. |
| `cryptad` / `hyphanet` | Node ports and Hyphanet baseline metadata. |
| `ports` | Complete FNP/FCP port assignment. |
| `uris` | Public CHK/SSK/USK request URIs used for cross-fetch validation. |
| `artifacts` | Paths, relative to the output directory when possible, for diagnostics produced by the run. Public JSON diagnostics are redacted before writing. |
| `transcript_refs` | Stable transcript names for smoke and extended flows. |
| `workspace_root` | Repository root passed to the harness. |
| `cryptad_dist_dir` | Cryptad distribution directory under test. |
| `node_references` | Cryptad and Hyphanet node identities captured during handshake. |
| `peer_exchange` | Peer mutation mode used in the run. |
| `payload_seed` | Deterministic seed used to generate test payloads. |
| `restart_recovery_level` | Current Tier 1 level, `restart-and-refetch`. |
| `restart_recovery_checks` | Restart checks completed by the Tier 1 flow. |
| `restart_recovery_deferred_checks` | Restart checks intentionally deferred from Tier 1 with machine-readable reasons. |
| `elapsed_seconds` | Wall-clock duration until success or failure handling. |
| `processes` | PID, exit code, stdout path, and stderr path for launched nodes. |

Extended flow entries include stable fields:

```json
{
  "flows": {
    "usk_subscribe_soak": {
      "status": "passed",
      "source": "cryptad",
      "subscriber": "hyphanet",
      "initial_edition": 0,
      "observed_edition": 1,
      "duration_seconds": 0
    },
    "persistent_request_replay": {
      "status": "passed",
      "request_identifier": "cryptad-persistent-request-replay-get",
      "present_before_restart": true,
      "present_after_restart": true,
      "completed_after_restart": true,
      "duration_seconds": 0
    }
  }
}
```

CI uploads `build/interop-smoke/` on Tier 1 failure and `build/interop-extended/` on every Tier 2
run. The upload globs exclude `artifacts/private-insert-uris.json`; publish the redacted report,
summary, transcripts, logs, and flow artifacts instead of private insert keys.

## CI tiers and OS limitations

The GitHub `interop-smoke` job runs on `ubuntu-latest` for pull requests and pushes. It builds the
runnable distribution with:

```bash
./gradlew assembleCryptadDist
```

Then it runs:

```bash
INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
```

This job is the Tier 1 release gate. It is Linux-only because the checked-in baseline path uses a
Hyphanet Debian package and the harness requires Linux process, filesystem, and package-extraction
behavior.

The GitHub `interop-extended` job runs on schedule and through `workflow_dispatch`. It uses:

```bash
INTEROP_MODE=extended \
INTEROP_ENABLE_USK_SUBSCRIBE_SOAK=1 \
INTEROP_ENABLE_PERSISTENT_REPLAY=1 \
INTEROP_ENABLE_OPENNET=0 \
INTEROP_SKIP_BUILD=1 \
tools/interop/run-hyphanet-interop-smoke.sh
```

The GitHub `interop-self-test` job runs the parser/client self-test on Ubuntu, macOS, and Windows.
It invokes `python3 tools/interop/interop_smoke.py --self-test` on Unix runners. On Windows it uses
`py -3 tools/interop/interop_smoke.py --self-test` because Git Bash on `windows-latest` does not
provide a `python3` executable. That matrix covers parser, summary, and redaction behavior without
starting the pinned Linux-only Hyphanet baseline. Full node interop on macOS and Windows remains
blocked until the project pins a portable baseline artifact for those platforms.

A release record should name the host OS, baseline, command line, timeout settings, whether opennet
was enabled, the `SubscribeUSK` duration, persistent replay identifier, and the final
`summary.json` path. The release certification report copies sanitized interop summaries into
`<out-root>/<release-id>/release-certification/artifacts/legacy/`. Release records must not include
`artifacts/private-insert-uris.json`.

## Release-readiness expectations

Before promoting a release candidate:

- Tier 1 must pass on Linux, either locally or in the `interop-smoke` CI job for the candidate.
- If Tier 1 fails, preserve `build/interop-smoke/` before cleaning or rerunning.
- If the candidate changes FCP, peer handling, datastore persistence, restart behavior, USK/SSK
  request handling, packaging layout, or node startup, run or verify the Tier 2 extended job and
  keep its redacted artifacts with the release record.
- Do not replace the darknet Tier 1 gate with opennet-only evidence. Opennet runs are additional
  diagnostics.
- macOS and Windows release readiness comes from installer and application smoke tests, not this
  Linux-only interop harness.

## Debug failures

Start with `summary.json`. Check `failure_reason`, the `flows` map, and the recorded process exit
statuses. Then inspect the matching FCP transcript and node stderr log.

Common failures:

- Missing baseline: set `HYPHANET_BASELINE_JAR` or both `HYPHANET_BASELINE_URL` and
  `HYPHANET_BASELINE_SHA256`.
- Port conflict: override the four port variables listed above.
- Startup timeout: inspect `logs/cryptad*.stderr.log`, `logs/hyphanet*.stderr.log`, and the node
  config files under `cryptad/` and `hyphanet/`.
- Peer timeout: inspect `artifacts/*peers*.json` and both FCP transcripts for `AddPeer`,
  `ListPeers`, and `ProtocolError`.
- Content timeout: inspect `PutFailed`, `GetFailed`, or `ProtocolError` entries in the transcripts.

## Follow-ups

These are intentionally out of scope for this PR:

- Portable full-node Hyphanet baseline artifacts for macOS and Windows.
- Deterministic full opennet validation.
- Browser/UI automation.
- Performance benchmarking.
