---
name: cryptad-platform-apps
description: Modify Platform API, AppHost, app bundles/catalogs, app UI/SDK, and legacy platform migration.
---

# Cryptad platform apps

Identify the affected leaf and read the applicable guardrails before changing app behavior.
Keep app process tokens out of browser/UI/log/support data. App principals authenticate and pass
central capability checks; browser origin isolation does not grant authority. Preserve signed
bundle/catalog verification, consent snapshots, durable-state ownership, and rollback semantics.
Platform API 1.0 is a frozen app-facing baseline, distinct from integer contract/build versions.
Do not treat local fixtures as protected release or live-network evidence.

For ordinary implementation work, use ownership and guardrails plus the relevant topic in the docs
index. Load certification, maintenance, or lifecycle references only when that behavior is involved.
Validation commands are a menu: choose affected modules/components, with shared certification
self-tests when the change affects their integration.

## Read for the current task

- [Read first](references/docs-index.md).
- [Ownership map](references/ownership.md).
- [Guardrails](references/guardrails.md).
- [Release certification smoke](references/certification.md).
- [Validation](references/validation.md).
- [Stable 1.0 maintenance compatibility](references/maintenance.md).
- [Stable 1.0 lifecycle and deprecation governance](references/lifecycle.md).
