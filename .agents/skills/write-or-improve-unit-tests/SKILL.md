---
name: write-or-improve-unit-tests
description: Add deterministic JUnit tests for one Java class without changing production code.
---

# Write focused unit tests

Inspect behavior and existing owning-module tests. Extend the appropriate test file; create
`<ClassName>Test` when needed. Preserve intentional splits across classes and source sets.

Cover meaningful contracts, branches, errors, and boundaries. Use configured JUnit Jupiter/JUnit 6
and Mockito where collaborators need isolation. Prefer real values, fixed seeds, controlled clocks,
and `@TempDir`; avoid network, sleeps, and timing assumptions.

Use AAA, `method_whenCondition_expectOutcome` names, legal package visibility, and explicit imports.
Keep assertions about a coherent outcome. Use existing S100 naming suppression only when necessary.
Do not modify production code; report any specific testability limitation.

Run changed test classes using [build/test guidance](../cryptad-build-test/SKILL.md).
Broaden for shared fixtures, integration contracts, or an explicit full-suite request.
Complete requested SonarLint checks through [file analysis](../cryptad-build-tooling/SKILL.md),
not an assumed `sonarlint` task. Reuse checks until subsequent changes invalidate them.

Report covered behavior, actual checks, and residual gaps. Claim percentages only with measurement.
