---
name: cryptad-build-tooling
description: Run or maintain Cryptad formatters, static analysis, dependency verification, and coverage tooling.

metadata:
  area: tooling
  domain: cryptad
---

# Cryptad build tooling

Use [build/test guidance](../cryptad-build-test/SKILL.md) for wrapper and verification scope.
Select the tool relevant to the change. SonarLint is opt-in and analyzers may be non-blocking;
inspect the generated report instead of equating exit zero with no findings.
Use file SonarLint for a file-local issue. Preserve strict dependency verification after any
metadata refresh and investigate artifact/signature changes rather than accepting them blindly.
For Spotless-owned changes, run the appropriate formatter and review its diff; prose-only changes
need no Gradle invocation. Docker/Playwright changes use the dedicated Docker skill.

## Read for the current task

- [Gradle wrapper and build-logic toolchains](references/gradle-toolchains.md).
- [Spotless + dependency verification (common failure mode); JUnit 6 + dependency verification](references/formatting-and-verification.md).
- [SpotBugs (Gradle) usage](references/spotbugs.md).
- [SonarLint (Gradle) usage](references/sonarlint.md).
- [Error Prone](references/error-prone.md).
- [JaCoCo + SonarCloud coverage](references/coverage.md).
