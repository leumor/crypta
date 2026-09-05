---
name: improve-unit-test-coverage-for-current-changes
description: Add focused regression coverage for Java changes in the working tree and current branch.
---

# Cover current Java changes

Use an explicit base/limit when given. Otherwise, on `develop` compare against `HEAD`; on another
branch use its merge base with `origin/develop`, falling back to local `develop`, then `HEAD`.
Report the selected base and any fallback. Include staged, unstaged, and untracked Java work.

Discover candidates and inspect actual hunks:

```bash
git diff --name-only --diff-filter=ACMR <base> -- '*.java'
git ls-files --others --exclude-standard -- '*.java'
git diff --unified=0 <base> -- <path>
```

Include module-local `src/main/java/` and `src/test/java/` sources. Honor any requested path limit.
Skip generated sources, comment/format-only changes, and unrelated files. If nothing needs coverage,
report that outcome without running tests.

Prioritize changed observable behavior, regression scenarios, exceptions, and meaningful boundaries.
Extend existing owning-module tests; add a new class only when no sensible home exists.
Use [unit-test guidance](../write-or-improve-unit-tests/SKILL.md) for deterministic JUnit/Mockito
tests and [build/test](../cryptad-build-test/SKILL.md) for task selection.
Keep production changes outside a coverage-only request; use the narrowest existing higher-level
test when direct unit testing is impractical and report remaining gaps.

Run affected test classes during iteration. Broaden verification for shared fixtures, cross-module
behavior, applicable gates, or an explicit request; run the full suite once when warranted, with
enough time to finish. Do not infer a coverage percentage without a coverage measurement.
Report the base, scoped files, covered behaviors, executed checks, and residual gaps.
