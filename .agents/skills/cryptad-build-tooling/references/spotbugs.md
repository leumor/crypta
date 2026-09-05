# SpotBugs (Gradle) usage reference

Read for SpotBugs (Gradle) usage. Commands and unlinked source paths are relative to the repository root.

## SpotBugs (Gradle) usage
### Current repo wiring
- Version catalog pins SpotBugs at `6.4.8` and exposes a plugin alias in `gradle/libs.versions.toml`.
- Build logic includes the plugin marker dependency in `build-logic/build.gradle.kts`.
- The shared convention plugin applies `com.github.spotbugs` in build logic.
- Default behavior is non-blocking: `spotbugs { ignoreFailures = true }`.
- All SpotBugs tasks are configured via `tasks.withType<SpotBugsTask>()` to emit XML reports at `build/reports/spotbugs/<taskName>.xml`.
- Text reports are disabled (`reports.matching { it.name == "text" }`) so findings are read from XML files instead of large stdout dumps.

### Tasks
- Run the main analysis:
  - `./gradlew spotbugsMain`
  - Report: `build/reports/spotbugs/spotbugsMain.xml`
- Run test analysis:
  - `./gradlew spotbugsTest`
  - Report: `build/reports/spotbugs/spotbugsTest.xml`
- SpotBugs tasks are also part of `check` once the plugin is applied.

### Enforcing SpotBugs failures
- To make findings fail the build, set:
  - `spotbugs { ignoreFailures = false }`

### Verification refresh on SpotBugs bumps
If strict verification blocks SpotBugs/plugin marker resolution:
1) Set `org.gradle.dependency.verification=lenient`
2) Run:
```bash
./gradlew --write-verification-metadata sha256,pgp :build-logic:classes
```
3) Restore `org.gradle.dependency.verification=strict`
4) Validate:
```bash
./gradlew help
./gradlew spotbugsMain
./gradlew spotbugsTest
```

Confirm `gradle/verification-metadata.xml` contains SpotBugs entries such as:
- component `com.github.spotbugs:com.github.spotbugs.gradle.plugin`
- trusted key/group entries for `com.github.spotbugs`
