---
name: cryptad-build-test
description: Build, test, and run Cryptad with the Gradle wrapper and module-scoped Java 25/JUnit 6 checks.

metadata:
  area: build
  domain: cryptad
  lang: java
---

# Cryptad build test

Use Java 25+ and the wrapper. Root application tasks include `buildJar`, `run`, and `runLauncher`.
Use `./gradlew :<module>:test --tests 'package.ClassTest'` for leaf-owned tests and
`./gradlew :test --tests 'package.ClassTest'` for root-owned tests. Find ownership before choosing.
Unqualified `test` selects tasks across the multi-project build; do not use it for one root test.

For prose/metadata changes, check the actual document or schema without starting Gradle.
For Java behavior, run affected tests and add regression coverage when it establishes the contract.
Broaden for shared behavior, module boundaries, explicit full-suite requests, or required CI/release
checks. Run `./gradlew test` once when a full suite is warranted; repeat only after changes or
unresolved failures. Allow more than 15 minutes and keep the process pollable.

Diagnose toolchain/build failures and fix local regressions without repeated approval.
Do not hide failed checks or weaken dependency verification. Run Gradle sequentially per checkout;
never use `--no-daemon`, `--parallel`, or CLI JVM overrides. `gradle.properties` owns tuning.
When moving classes/resources to a leaf, update its `gradle/owned-output-patterns.txt` and run
`./gradlew verifySelectiveLeafOwnershipMetadata buildJar`.
Use [build tooling](../cryptad-build-tooling/SKILL.md) when formatting or analyzers are involved.

## Read for the current task

- [Build layout](references/build-layout.md).
- [Core build commands; Testing; Compile-only / quick checks](references/commands.md).
- [First-party app bundle checks](references/app-bundles.md).
- [Run tasks; Run your build (manual deployment)](references/running.md).
- [Environment expectations; JUnit 6 notes (when touching tests); Test helpers (test sources only); Tip: GitHub API rate limits during builds](references/junit-and-environment.md).
