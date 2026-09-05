---
name: reduce-cognitive-complexity
description: Refactor one Java method to Sonar cognitive complexity at most 15 without behavior changes.
---

# Reduce cognitive complexity

Resolve the file/method and inspect callers and the S3776 diagnostic.
Use guard clauses, cohesive helpers, or clearer branching where useful; choose transformations
from the code rather than a fixed recipe.

Preserve APIs, null handling, exceptions/logging, evaluation order, resource lifetime, thread safety,
and relevant performance. Do not add dependencies, suppressions, speculative guards, or unrelated
cleanup. Keep extracted helpers at complexity at most 15 too.

Use [build/test](../cryptad-build-test/SKILL.md) for relevant regression tests and
[build tooling](../cryptad-build-tooling/SKILL.md) for file SonarLint.
Verify the analyzer result instead of guessing a score.
Finish when threshold, behavior, and readability are verified. Report changes and actual checks.
