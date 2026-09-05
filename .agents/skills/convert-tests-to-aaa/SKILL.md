---
name: convert-tests-to-aaa
description: Convert non-AAA methods in one Java test file and give converted tests descriptive names.
---

# Convert tests to Arrange–Act–Assert

Resolve the target test file from the request. Preserve production code, inputs, assertions,
exception expectations, and mock verification. Leave existing AAA tests and unrelated formatting alone.

Separate setup, the primary action, and assertions using existing comment or blank-line conventions.
Keep stateful multi-step scenarios together when splitting would alter what the test proves.
Rename converted tests to `method_whenCondition_expectOutcome`; preserve parameterized-test
providers and any method-name references. Use existing S100 naming suppression only if needed.

Use [build/test](../cryptad-build-test/SKILL.md) to run the owning module's changed test class.
No new tests or full suite are needed for a structural-only conversion unless a discovered
dependency or failure justifies broader checks. Report conversions, renames, and actual validation.
