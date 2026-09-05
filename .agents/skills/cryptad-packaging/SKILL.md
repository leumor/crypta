---
name: cryptad-packaging
description: Build or troubleshoot Cryptad distributions, native installers, Flatpak, and frozen release packages.

metadata:
  area: packaging
  domain: cryptad
---

# Cryptad packaging

Packaging remains root-owned; leaf modules contribute JARs/resources to one daemon distribution.
Use [build/test](../cryptad-build-test/SKILL.md) for Gradle execution and select the target platform.
Stable RC/GA and later maintenance packages have protected exact-byte contracts: select that
reference before building or publishing a release candidate. Local installer work does not imply
permission to replace a live installation or publish artifacts.

## Read for the current task

- [Ownership in the partial multi-project build; Distributions and Windows wrapper sources](references/layout-and-wrappers.md).
- [Stable 1.0 RC and GA archives](references/stable-rc-ga.md).
- [Installers (jpackage)](references/jpackage.md).
- [Linux installer behavior (DEB/RPM)](references/linux.md).
- [Flatpak build (local dev)](references/flatpak.md).
- [Stable 1.0 maintenance candidate packaging](references/maintenance.md).
