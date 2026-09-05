---
name: cryptad-architecture
description: Navigate Cryptad module ownership, subsystem boundaries, routing patterns, and compatibility constraints.

metadata:
  area: architecture
  domain: cryptad
---

# Cryptad architecture

Locate the affected module in `settings.gradle.kts` and source paths before choosing an owner.
The daemon remains root-assembled while extracted leaves own reusable code and focused tests.
Preserve dependency direction, runtime SPI boundaries, and package/resource ownership metadata.
For a known local edit, read its subsystem section rather than the complete module map.

## Read for the current task

- [Build/module layout (current)](references/modules.md).
- [Architecture overview (by package)](references/subsystems.md).
- [Key design patterns; Security model (high level); Versioning system](references/patterns-and-security.md).
- [Release-tooling boundary](references/release-tooling.md).
