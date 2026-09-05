# JaCoCo + SonarCloud coverage reference

Read for JaCoCo + SonarCloud coverage. Commands and unlinked source paths are relative to the repository root.

## JaCoCo + SonarCloud coverage
- JaCoCo toolVersion: `0.8.14`
- XML/HTML reports are enabled:
  - XML: `build/reports/jacoco/test/jacocoTestReport.xml`
- `check` depends on:
  - `jacocoTestReport`
  - `jacocoTestCoverageVerification`
- Coverage rule: 80% line coverage (LINE/COVEREDRATIO >= 0.80)
  - Builds do not fail on coverage by default (`isFailOnViolation = false`)

### SonarCloud configuration
- Host: `https://sonarcloud.io`
- Project: `crypta-network_cryptad`
- Org: `crypta-network`
- Coverage is read from the JaCoCo XML path above (`sonar.coverage.jacoco.xmlReportPaths`).
- Upload requires token:
  - Set env `SONAR_TOKEN` (mapped to `sonar.token` by convention; no CLI flag required).

### Typical local runs
- Tests + coverage:
  - `./gradlew test jacocoTestReport`
- Enforced check (non-failing gate):
  - `./gradlew check`
- Upload:
  - `export SONAR_TOKEN=<token>`
  - `./gradlew sonarqube`

### CI minimal step
- `./gradlew test jacocoTestReport sonarqube`
