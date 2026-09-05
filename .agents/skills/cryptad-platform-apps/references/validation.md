# Validation reference

Read for Validation. Commands and unlinked source paths are relative to the repository root.

## Validation

Use `$cryptad-build-test` for Gradle rules and timeouts. Common focused checks:

```bash
./gradlew :platform-api:test
./gradlew :platform-apphost:test
./gradlew :platform-app-ui:test
./gradlew :platform-appdist:test
./gradlew :platform-appcatalog:test
./gradlew :platform-trustgraph:test
./gradlew :platform-design-system:test
./gradlew :platform-appvault:test
./gradlew :platform-devtools:test
./gradlew :platform-sdk-js:test
./gradlew :platform-web-shell:test
./gradlew :adapter-http-legacy-admin:test
./gradlew :apps:queue-manager:test
./gradlew :apps:publisher:test
./gradlew :apps:site-publisher:test
./gradlew :apps:profile-publisher:test
./gradlew :apps:social-inbox:test
./gradlew :apps:feed-reader:test
./gradlew :apps:trust-graph:test
./gradlew stageFirstPartyApps
python3 tools/release-certification/certify.py self-test all
python3 tools/release-certification/certify.py stable-rc --self-test
python3 tools/release-certification/certify.py stable-ga --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py stable-lifecycle --self-test
python3 tools/release-certification/certify.py stable-catalog-authority --self-test
```

When changing route contracts or bridge wiring, also run the relevant root router/toadlet tests
with `./gradlew :test --tests '*PlatformApiRouterTest' --tests '*PlatformApiToadletTest'`.

When changing `crypta-app` command wiring or distribution behavior, also run
`./gradlew :platform-devtools:installDist` and smoke the generated
`platform-devtools/build/install/crypta-app/bin/crypta-app --help` launcher.

For a local change, run the affected component's offline self-test when its evidence contract changes.
Run `python3 tools/release-certification/certify.py self-test all` for shared certification logic,
cross-component evidence contracts, or required release/CI validation. Pure prose edits use the
docs collector when applicable. Do not run every command above for each app-platform edit.

Run a candidate-bound component only after copying the appropriate example manifest to `build/`,
replacing every placeholder, and arranging any required v2 migration or attached evidence with the
same finalized `release.id`.
