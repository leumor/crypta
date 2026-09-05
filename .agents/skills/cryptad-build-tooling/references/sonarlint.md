# SonarLint (Gradle) usage reference

Read for SonarLint (Gradle) usage. Commands and unlinked source paths are relative to the repository root.

## SonarLint (Gradle) usage
### Key behaviors
- SonarLint does **not** run during regular lifecycles (`build`, `check`).
- `sonarlintMain` / `sonarlintTest` run only when explicitly requested (task name contains `sonarlint`).
- Default config: `ignoreFailures = true` (non-failing by default).
- `sonarIssues` queries server-side issues from SonarQube/SonarCloud (`/api/issues/search`) for a
  specified rule set and can report issues that local `sonarlintMain`, `sonarlintTest`, and
  `sonarlintFile` do not.
- `sonarIssues` reads the latest uploaded server analysis; after fixing code locally, its issue list
  can remain stale until CI runs analysis successfully and uploads fresh results.

### Tasks
- Full main sources:
  - `./gradlew sonarlintMain`
- Test sources:
  - `./gradlew sonarlintTest`
- Single file analysis:
  - `./gradlew --quiet sonarlintFile -Psonarlint.file=src/main/java/SevenZip/LzmaAlone.java`
  - Aliases: `-Pfile=...`, `-Psonarlint.sources=...`
  - Report: `build/reports/sonarLint/sonarlintFile/sonarlintFile.xml`
- Server-side rule query:
  - `./gradlew sonarIssues -PsonarIssues.rules=java:S1172`
  - Task name is `sonarIssues` (sometimes informally referred to as “sonarlintIssues”).
  - Uses `SONAR_TOKEN` automatically when present (required for private projects).
  - Default report: `build/reports/sonar/issues-page-1.json`
  - Useful properties:
    - `-PsonarIssues.rules=<repo:rule>` (comma-separated supported by API)
    - `-PsonarIssues.page=<n>`
    - `-PsonarIssues.pageSize=<1..500>`
    - `-PsonarIssues.output=<path>`

### Rule-specific investigation workflow
For a file-local issue, run `sonarlintFile` and inspect its XML report. Run `sonarlintMain`
or `sonarlintTest` for a module/source-set-wide investigation. Query `sonarIssues` when the user
asks about server findings or a local/server discrepancy; it requires server access and may lag
behind local fixes. Do not make a local fix depend on unrelated remote analysis.

### Verification refresh on SonarLint bumps
If strict verification blocks resolution:
1) Set `org.gradle.dependency.verification=lenient`
2) Run:
```bash
./gradlew --write-verification-metadata sha256,pgp :build-logic:classes
```
3) Restore `org.gradle.dependency.verification=strict`
4) Optionally `./gradlew --export-keys`

### Memory note
Gradle daemon heap was increased to reduce OOM during SonarLint indexing:
- `gradle.properties`: `org.gradle.jvmargs=-Xmx8g -XX:MaxMetaspaceSize=2g -Dfile.encoding=UTF-8`
