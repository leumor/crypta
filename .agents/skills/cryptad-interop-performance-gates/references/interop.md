# Hyphanet interop gate reference

The measured cross-version path is documented in `docs/cross-version-live-network-soak.md`.
Use `certify.py cross-version-soak --self-test` and the offline `test_cross_version_*.py` suites
without live authorization. Its exclusive supervisor, private journal and public verifier do not
upgrade old simulated/attached summaries, authenticate historical packages by labels, or reduce
existing protected release durations. Keep unexecuted and unsupported mandatory scenarios visible.

Read for Hyphanet interop gate. Commands and unlinked source paths are relative to the repository root.

## Hyphanet interop gate

- Tier 1 smoke is the release-readiness compatibility gate. It is Linux-only and runs a packaged
  Cryptad node against a pinned Hyphanet baseline.
- Tier 2 extended soak runs locally or through scheduled/manual CI when compatibility-sensitive
  behavior changed. It adds long-lived `SubscribeUSK`, persistent request replay, optional opennet
  plumbing, and longer diagnostics.
- Normal local commands:

```bash
python3 tools/interop/interop_smoke.py --self-test
tools/interop/run-hyphanet-interop-smoke.sh
INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
INTEROP_MODE=extended INTEROP_SKIP_BUILD=1 tools/interop/run-hyphanet-interop-smoke.sh
```

- Do not publish `artifacts/private-insert-uris.json`; it contains temporary insert keys and CI
  excludes it from uploads.
- Preserve `build/interop-smoke/` or `build/interop-extended/` when a gate fails or when a release
  record needs compatibility evidence.
