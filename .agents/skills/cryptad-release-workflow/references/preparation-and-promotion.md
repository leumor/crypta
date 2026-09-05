# Procedure reference

Read for Procedure, Checklist. Commands and unlinked source paths are relative to the repository root.

## Procedure
1) Sync `develop` and create the release branch:
```sh
git checkout develop
git pull
git checkout -b release/<build-number>
```

2) Set the build number in `build.gradle.kts` (e.g., `version = <build-number>`), and run CI/tests per repo conventions.
   Follow the release gates in `docs/cryptad-release-workflow-and-runbook.md`; load
   `$cryptad-build-test`, `$cryptad-platform-apps`, and `$cryptad-interop-performance-gates` when
   those areas are involved.

   Before promotion, run the unified certification suite, copy the example manifest, and replace
   every placeholder. The checked-in example is a template and must not be executed directly.
   ```sh
   python3 tools/release-certification/certify.py self-test all
   cp tools/release-certification/manifests/release-candidate.example.json \
     build/release-candidate.json
   # Set release.id, release.version, inputs, policies, requirements, and execution controls.
   python3 tools/release-certification/certify.py release-certification \
     --manifest build/release-candidate.json
   ```
   Unified component inputs must be expected-kind, candidate-bound v2 envelopes. For the first v2
   release, use `certify.py migrate-v1` with the finalized candidate ID, then point
   `inputs.previousCandidate` and `inputs.releaseHistory` at those immutable migration summaries.
   Keep manifest values non-secret; signing keys, credentials, private URIs, and other private
   material belong only in protected environment variables or files.
   Preserve the complete marked `<out-root>/<release-id>/` workspace. With the example output root,
   preserve `build/release-certification/<release-id>/`, including
   `build/release-certification/<release-id>/release-certification/summary.json`,
   `build/release-certification/<release-id>/release-certification/report.md`,
   `build/release-certification/<release-id>/release-certification/redaction-report.json`,
   `build/release-certification/<release-id>/release-certification/artifacts/`,
   `build/release-certification/<release-id>/network-scale-soak/summary.json`,
   `build/release-certification/<release-id>/multi-node-beta/run/summary.json`, and
   `build/release-certification/<release-id>/security-response/`. Replace `<release-id>` with the
   finalized manifest `release.id`. If `execution.writeHistory=true`, also preserve the shared
   `build/release-certification-history/` archive; failed candidates do not replace its latest
   passing summary.

   When the release includes production beta app-ecosystem artifacts, run the top-level production
   beta pipeline instead of manually assembling app bundles, catalogs, review receipts, lower-level
   certification output, and the public archive:
   ```sh
   cp tools/release-certification/manifests/production-beta.example.json \
     build/production-beta.json
   # Replace every placeholder and bind every v2 input to the same release.id.
   python3 tools/release-certification/certify.py production-beta \
     --manifest build/production-beta.json
   ```
   Set the release identity, output root, production profile, catalog channel, artifact base URI,
   required gates, and evidence inputs in the manifest before running either command.
   Preserve the common JSON/Markdown summaries and production redaction report. Detailed go/no-go
   dashboard JSON/Markdown, dashboard redaction, extracted evidence, and checksums live under
   `<out-root>/<release-id>/production-beta/artifacts/legacy/`, including `reports/`, `evidence/`,
   and `dist/checksums.txt`. Validated attached extracts live under `artifacts/inputs/`. Any summary
   with `nonRelease=true`, `promotionReady=false`, `goNoGo`
   decision `no-go`, failed production or dashboard redaction, dirty workspace, fixture evidence,
   test signing, skipped production-beta build stages, or an emergency live-network skip is not
   promotable. A `go-with-waivers` decision is launchable only when every residual blocker has a
   valid, scoped, approved, unexpired waiver and none of the non-waivable production-beta evidence,
   redaction, signing, live-network, sandbox, multi-node, or artifact-hygiene gates failed.

   For the Stable 1.0 milestone, continue with the canonical freeze and promotion path:

   ```sh
   cp tools/release-certification/manifests/stable-1.0-rc.example.json \
     build/stable-1.0-rc.json
   # Replace every placeholder and provide protected production inputs.
   python3 tools/release-certification/certify.py stable-rc \
     --manifest build/stable-1.0-rc.json

   cp tools/release-certification/manifests/stable-1.0-ga.example.json \
     build/stable-1.0-ga.json
   # Bind the latest successful freeze, exact product, post-freeze evidence, and authorization.
   python3 tools/release-certification/certify.py stable-ga \
     --manifest build/stable-1.0-ga.json
   ```

   Treat the commands above as validation/preparation boundaries. `stable-rc` does not publish GA,
   and `stable-ga` never publishes by itself. Dispatch
   `.github/workflows/stable-1.0-ga-promotion.yml` with publication explicitly enabled only after
   protected approval. The workflow must revalidate the exact RC, authorization, release branch,
   public artifact base, catalog targets, and any existing tag/Release/assets before side effects.
   Retain the verified publication receipt and `stable-1.0-maintenance-baseline.json`. If any frozen
   payload or release input needs a fix, stop and complete an authorized RC refreeze, then restart
   post-freeze validation.

3) Stabilize on `release/<build-number>` (critical fixes only). Keep diffs minimal.

4) Tag the release on the release branch. For an ordinary release, create the tag manually:
```sh
git tag v<build-number>
```

For Stable 1.0 GA or a later Stable 1.0 maintenance release, do not run that command manually. The
applicable explicitly authorized protected publication job creates or idempotently verifies the
annotated `v<build-number>` tag at the exact authorized commit. It does not merge the release
branch.

5) Merge forward to `main` (no squash; preserve branch context):
```sh
git checkout main
git pull
git merge --no-ff release/<build-number>
```

6) Back-merge to `develop` (no squash):
```sh
git checkout develop
git pull
git merge --no-ff release/<build-number>
```

7) Push branches and tag for an ordinary release:
```sh
git push origin main develop release/<build-number>
git push origin v<build-number>
```

For Stable 1.0, push the branches after the release-manager-approved merges and verify the tag
against the retained publication receipt; the protected GA publication job already owns tag and
GitHub Release creation.

---

## Checklist
- [ ] `build.gradle.kts` version is the intended integer build number.
- [ ] CI green on `release/<build-number>`.
- [ ] Release certification report generated in `release-candidate` mode and required evidence
      passed or has an explicit release-manager waiver.
- [ ] Production beta app-ecosystem pipeline summary reviewed when first-party app artifacts ship;
      `promotionReady=true`, `nonRelease=false`, production signing, complete in-pipeline build,
      clean workspace, public HTTPS artifact base URI, required live-network evidence, required
      multi-node beta evidence, and redaction `pass` are all present before publication. Confirm the
      security response section reports `production-security.response-runbook` passing with no
      blockers and confirm `developerBetaProgram.status=pass`.
- [ ] First-party AppHost bundles staged, signed, and verified when shipping app-platform artifacts.
- [ ] `crypta-app` CLI smoke completed when `:platform-devtools` changed.
- [ ] Signed catalog, first-party beta catalog, production catalog channels, catalog operations
      and mirrors, first-party maintenance policy, catalog security advisory/denylist gates,
      trusted app-review receipt, Platform API contract, Platform API 1.0
      stable baseline, target-stability, and stable breaking-change evidence, app-vault capability,
      generated-document insert, content-fetch/subscription, shared
      app-network budget, network-scale soak, durable app-data, app-data backup/restore, app-service
      registry/grant/dependency/grant-bundle/redaction, app UI design-system/lint, app-owned UI
      smoke, Site Publisher reference-content, Profile
      Publisher identity-profile, Social Inbox RC threading/trust/service-dependency, Feed Reader
      content-subscription, Trust Graph Local RC durable exchange/scope, live USK catalog refresh,
      app-review governance/reviewer-key lifecycle and transparency-log, app platform beta
      docs/program/redaction, third-party developer beta docs, template, sample-flow, checklist,
      compatibility, feedback, plugin-migration and redaction, multi-node beta soak, upgrade,
      rollback, backup, support-bundle and redaction, AppHost sandbox-provider, app-update
      lifecycle, app-update scheduler, app-update rollback, app-update data migration contract,
      developer beta toolkit, operator RC recovery/support, production security response runbook,
      legacy plugin freeze, and legacy-admin retirement/removal Wave 1-5/final-surface evidence
      are present in the certification summary.
- [ ] Hyphanet interop smoke passed or CI evidence recorded; extended interop captured when
      compatibility-sensitive behavior changed.
- [ ] Performance smoke passed or scheduled/manual CI evidence recorded when release readiness or
      performance-sensitive changes require it.
- [ ] For Stable 1.0, the selected RC is the latest successful protected freeze/refreeze;
      freeze/product/archive/catalog/app/API/profile digests match; post-freeze production
      validation and explicit GA authorization pass; `rcProductDigest == gaProductDigest`; and the
      protected publication receipt verifies the tag, Release assets, notes, artifact base, and
      catalog primary/mirrors before publication is called complete.
- [ ] For Stable 1.0, retain `stable-1.0-maintenance-baseline.json`; do not create the tag or
      GitHub Release from tests, local validation, or an ordinary PR workflow.
- [ ] When the release policy requires PR-293 evidence, authenticate the exact catalog-authority
      protected receipt against PR-291 and PR-292. Do not substitute a fixture, self-test, local
      report, workflow definition, partial publication, or mirror upload claim.
- [ ] Release record excludes `artifacts/private-insert-uris.json`, private signing keys, private
      reviewer keys, form passwords, app tokens, browser-session tokens, raw request bodies, raw
      feed bodies, raw social message bodies, raw trust documents, raw app-data values, raw
      app-data backup payloads, raw diagnostic exports, raw app-service subject URIs, private
      insert URIs, raw trusted reviewer public key bytes, provider app data, raw signatures, raw
      incident artifacts, raw fetched content, command lines containing secrets, CI secret values,
      and unsanitized local paths.
