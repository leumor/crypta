---
name: fix-file-until-green
description: Fix a Java file's test and SonarLint failures with focused, behavior-preserving changes.
---

# Fix one file until green

Resolve the target and load [build/test](../cryptad-build-test/SKILL.md) and
[build tooling](../cryptad-build-tooling/SKILL.md).
Preserve packages, public behavior, and features. Fix causes without suppressing diagnostics.

Ignore `java:S120` and `java:S107`; also ignore `java:S100` for unit tests. Report these exclusions.
Use the dedicated S107 workflow when that refactoring is requested.

Run owning-module relevant tests and file analysis:

```bash
./gradlew sonarlintFile -Psonarlint.file=<repository-relative-java-file>
```

Inspect `build/reports/sonarLint/sonarlintFile/sonarlintFile.xml`; task exit zero is insufficient
because analysis is non-blocking. Fix remaining non-ignored issues and test regressions, then rerun
affected checks until both pass. Consult exact dependency-version docs when an API is unclear.

Broaden checks under the build skill's risk-based policy. Use a full suite for explicit requests or
shared/cross-module behavior changes. Diagnose infrastructure failures without repeated approval.
Report issues that cannot be resolved within scope, actual check results, and ignored diagnostics.
