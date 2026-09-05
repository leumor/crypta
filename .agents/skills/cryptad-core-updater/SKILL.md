---
name: cryptad-core-updater
description: Modify CoreUpdater package discovery, installer actions, descriptors, and support-lifecycle state.

metadata:
  area: updater
  domain: cryptad
---

# Cryptad core updater

Core updates install platform packages, not replacement node JARs. Keep strict integer build
gating, descriptor integrity, revocation, and retry semantics intact. HTTP/UI crosses the detached
`CoreUpdateActionPort`; do not couple the Web Shell or Platform API to updater internals.
Support lifecycle is a separate signed descriptor and host/operator-only projection.
Use [AppEnv](../cryptad-appenv/SKILL.md) for platform detection changes.

## Read for the current task

- [CoreUpdater migration (conceptual overview); System wiring changes; Versioning and discovery details; Endpoint and UI; Runtime-boundary classes to inspect](references/package-updates.md).
- [Platform specifics (selected behaviors); Environment detection (important); Descriptor format and integrity; UOM compatibility note](references/platform-and-format.md).
- [Stable 1.0 maintenance descriptor publication](references/maintenance-publication.md).
- [Stable 1.0 support lifecycle descriptor](references/support-lifecycle.md).
