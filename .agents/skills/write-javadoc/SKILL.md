---
name: write-javadoc
description: Fix doclint issues and document one Java file's API behavior without changing code.
---

# Document one Java file

Resolve the target and inspect implementation, callers, and relevant contracts.
Use [Java style](../cryptad-style-docs/SKILL.md) and
[writing guidance](../cryptad-writing-guides/SKILL.md).
Limit edits to comments. Log strings are observable behavior, outside a Javadoc-only task.

Document actual purpose, parameters, results, errors, units, lifecycle, ownership, concurrency,
and compatibility where applicable. Explain complex APIs; simple accessors need no word quota.
Do not invent guarantees or stop after an arbitrary member count. Preserve licenses and useful docs.

Place Javadoc above annotations. Use valid HTML, `{@code ...}`, resolvable links, accurate
parameter/type-parameter/return/throws tags, and `{@inheritDoc}` where sufficient.
Keep private comments focused on non-obvious intent. Avoid vague TODOs and implementation history.

## Verify

Run focused `javadoc -quiet -Xdoclint:all` with the owning module's actual compile classpath and
source roots and a unique temporary output directory. Add `-private` for a package-private type.
Use [build guidance](../cryptad-build-test/SKILL.md) if symbol resolution needs compilation.
Use resolved dependency versions, never an arbitrary cached JAR.

Preserve failure status when capturing output (`set -o pipefail` with `tee`).
Do not hide compilation failures with `|| true` or treat unresolved symbols as clean doclint.
Fix target documentation diagnostics and rerun after the final edit. Report toolchain/dependency
blockers separately instead of changing unrelated source.

Confirm only comments changed. Run doclint and applicable formatting checks; a full runtime suite
is unnecessary for Javadoc-only edits. Report the file and actual validation result.
