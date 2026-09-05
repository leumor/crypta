---
name: cryptad-style-docs
description: "Apply Cryptad Java style, file layout rules, and long-lived documentation/commenting practices."
metadata:
  area: style
  domain: cryptad
  lang: java
---

## When to use
Use this skill when you:
- Add/edit Java sources.
- Touch comments, deprecations, or docs.
- Need to ensure changes match the repo’s style and documentation practices.

## Java layout rules
- Java sources go under `src/*/java/` (for example `src/main/java`, `src/test/java`).
- For extracted production leaves such as `:runtime-node`, `:kernel-content`, `:platform-api`,
  `:platform-apphost`, `:platform-app-ui`, `:platform-appvault`, `:platform-design-system`,
  `:platform-appdist`, `:platform-appcatalog`, `:platform-trustgraph`, `:platform-devtools`,
  `:platform-web-shell`, and the adapter modules, keep `package-info.java` in each production
  package you add or move.
  Boundary tests currently enforce this for the runtime, kernel, platform, FCP, and HTTP leaves,
  and the adapter packages follow the same convention.
- Resource-owned leaves such as `:platform-sdk-js` still keep Java tests under `src/test/java`.
  Add `package-info.java` only when a production Java package is added.

## Style guides
- Java: follow the Google Java Style Guide.

(Use the canonical upstream docs; do not invent new local style rules unless the repo already enforces them.)

## Documentation expectations (Javadoc)
Keep docs accurate for the API or behavior being changed. Document new public APIs, non-obvious
invariants, and protocol/format details; do not expand an unrelated edit into whole-file Javadoc work.

## Commenting guidelines (very important)
Prefer clean diffs over in-code historical explanations.
- Do **not** add “Removed …” style comments to explain code you just deleted in the same change.
- Change history belongs in commit/PR text. Keep enduring design rationale near the code it explains.

### Deprecations
When deprecating behavior that remains in code:
- Use standard `@Deprecated`.
- Add a brief forward-looking note (preferably linking to an issue/PR).
- Avoid PR-number narratives or “history of the removal” in comments.

## Where to put long-lived context
If additional context is valuable long-term:
- Put domain procedures in the relevant skill/reference and durable product context under `docs/`.
  Keep root `AGENTS.md` limited to shared working agreements and routing.
