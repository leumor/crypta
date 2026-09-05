---
name: unittest-remove-public
description: Remove unnecessary public modifiers from JUnit classes and lifecycle/test methods in one file.
---

# Use package visibility for JUnit tests

Resolve the Java test file. Remove unnecessary `public` from test classes and JUnit test/lifecycle
methods while preserving annotations, static modifiers, signatures, and behavior.

Keep visibility required by overrides, interfaces, or cross-package/module references.
Do not rewrite callers or production code just to make a modifier disappear.
Inspect structural matches before applying changes.

Run the owning module's affected test using [build/test](../cryptad-build-test/SKILL.md).
For the requested Sonar cleanup, use [file SonarLint](../cryptad-build-tooling/SKILL.md) and inspect
the report for the public-modifier issue. Broaden checks only for an actual dependency or failure.
Report removed modifiers, required exceptions, and validation.
