---
name: fix-s107-too-many-parameters
description: Resolve java:S107 in a Java file using coherent parameter objects and updated callers.
---

# Reduce excessive parameter lists

Inspect the target's S107 diagnostics and callers. Use
[build tooling](../cryptad-build-tooling/SKILL.md) and
[architecture](../cryptad-architecture/SKILL.md) for cross-module ownership decisions.

Search for existing objects representing the same domain concept before adding one. Reuse suitable
types across affected callers. Similar names or three matching fields alone do not justify coupling
unrelated modules, expanding public APIs, or consolidating unrelated types.

Group parameters by meaning and lifetime. Prefer records for immutable carriers where appropriate;
records can validate in compact constructors. Keep classes for identity/framework/mutability needs.
Use a private nested type for a class-private concept or an existing dependency-safe shared owner.

Update offending signatures and required callers. Preserve evaluation/validation order, exception
timing, nullability, side effects, and persistent/wire formats. Do not suppress S107.
Keep delegators only for actual compatibility needs and report unresolved diagnostics honestly.

Run affected compilation/tests and file SonarLint, inspecting S107 results. Broaden tests as caller
scope warrants. Document new production types. Report types, callers, compatibility, and validation.
