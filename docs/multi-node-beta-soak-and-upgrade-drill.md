# Multi-node beta soak and upgrade drill

Use the multi-node beta command to plan, run, and verify app ecosystem behavior across a bounded
multi-node topology and a previous-candidate upgrade.

For owned packaged processes and measured operation journals, use the separate
[`cross-version-soak` path](cross-version-live-network-soak.md) in this tool family. It preserves
the existing simulated/hybrid/live summary meanings; reachability or a duration label alone does
not establish executed cross-version scenarios or continuous live coverage.

## Commands

Copy the release-candidate template and configure topology, mode, candidate inputs, freshness, and
output options under `commands.multi-node-beta` in the release-run manifest. Replace every
placeholder before running a candidate-bound action.

```bash
cp tools/release-certification/manifests/release-candidate.example.json \
  build/release-candidate.json
python3 tools/release-certification/certify.py multi-node-beta plan \
  --manifest build/release-candidate.json
python3 tools/release-certification/certify.py multi-node-beta run \
  --manifest build/release-candidate.json
python3 tools/release-certification/certify.py multi-node-beta verify \
  --manifest build/release-candidate.json
```

Focused offline tests run with:

```bash
python3 tools/release-certification/certify.py multi-node-beta --self-test
```

## Modes

`simulated` is deterministic and appropriate for PR, CI, and developer dry runs. `hybrid` combines
deterministic orchestration with attached release-manager evidence. `live` records a real bounded
topology. Production promotion cannot use the checked-in self-test topology or simulated-only
evidence.

When `requirements.multiNodeSoak=true` and the effective topology mode is `live`, collection also
requires at least one configured localhost node to be reachable. Deterministic scenario fallback
can remain visible as warning evidence for optional live runs, but it cannot satisfy a required
live gate.

## Scenarios

The gate covers catalog channel updates, app install/update/health rollback, app-data migrations,
backup and clean-node restore, subscription pressure and backoff, bounded Trust Graph import,
multi-source Social Inbox behavior, support-bundle redaction, and upgrade from the previous beta
candidate.

Previous-candidate upgrade evidence binds the previous summary digest and release identity. It
records daemon upgrade, first-party app migrations, backup-before-update, failed-migration
rollback, Social Inbox and Trust Graph state migration, clean restore, and post-failure support
bundle redaction without raw app data, messages, trust statements, or backup payloads.

## Output and release policy

Each action writes its v2 summary below `<out-root>/<release-id>/multi-node-beta/<action>/`.
Release-candidate and production evidence must be fresh, explicitly attached or generated for the
current run, candidate-bound, and redaction-safe. A stale default summary from another workspace
must never be reused.

For Stable GA, general beta evidence is not sufficient unless a protected post-freeze validation
record binds every required scenario to the selected RC source commit, freeze digest, deterministic
product digest, outer archive digest, and stable catalog digest. Scenario start times must be at or
after the authenticated protected freeze completion. The production matrix must cover the required
clean install, previous-candidate upgrade, rollback/recovery, app-data migration, backup/restore,
first-party state preservation, and deliberately failed-upgrade support-bundle drill; simulated or
fixture-only topology results cannot satisfy that gate.

Private insert URIs, tokens, browser sessions, raw app data, raw messages, raw trust documents,
node profile paths, rollback backup paths, and local absolute paths are excluded from release
artifacts.

## Stable 1.0 maintenance binding

For a Stable maintenance candidate, every required upgrade, rollback, migration, backup, restore,
state-preservation, and recovery scenario records the exact candidate product digest and immediate
predecessor product digest. Policy may also require a direct-GA upgrade path. Only fresh production
evidence for the declared environment, node count, operation count, and package targets satisfies
the gate; a security hotfix cannot replace these non-waivable checks with fixtures or simulation.

See the [Stable 1.0 maintenance release and security hotfix
path](stable-1.0-maintenance-release-and-hotfix-path.md).
