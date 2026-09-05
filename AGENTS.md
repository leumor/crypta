# Agent guidance

Cryptad is the Java reference daemon for Crypta, a distributed encrypted datastore and local
app platform forked from Hyphanet. Java sources belong in each module's `src/*/java/` directories.

## Working agreement

Complete the requested change, relevant verification, and necessary docs together. Resolve routine
choices from context; ask only when a missing answer materially changes scope, correctness, or
authorization. Existing user authorization carries forward. User instructions take precedence
over skill guidelines, within the session's permissions.

Inspect affected code and callers before changing behavior; expand discovery when evidence calls
for it. Preserve unrelated working-tree changes. Diagnose command failures, fix regressions caused
by the requested change, and rerun affected checks without repeated approval. Report external
blockers with the failed command and continue independent work.

Prefer `rg` for local discovery and `ast-grep` for structural Java changes when useful; inspect
matches before non-interactive rewrites. Batch independent reads. Keep Gradle invocations sequential
in a shared checkout. Use subagents only when the session authorizes delegation and a bounded
independent task justifies it; assign separate file ownership.

## Project invariants

- Preserve wire protocols, persistent formats, and on-disk layouts unless the task includes an
  explicit migration plan.
- Use `network.crypta.fs.AppEnv` for OS, architecture, sandbox, and service detection.
- Use `python3` and the Gradle wrapper (`./gradlew`; Windows: `gradlew.bat`) with Java 25+.
  Do not use `--no-daemon`, `--parallel`, or CLI JVM overrides; `gradle.properties` owns those
  settings. Allow full test runs more than 15 minutes; keep long commands pollable.
- Fix compiler/typechecker errors in touched code. Inspect relevant analyzer reports:
  a successful task exit does not prove a non-blocking analyzer is clean.
- Use `leumor` explicitly for repository GitHub operations. Load
  [Git policy](.agents/skills/cryptad-git-workflow/SKILL.md) before commits, pushes, or GitHub work.
- Local preparation does not authorize publication, merges, destructive operations, live-node
  changes, or messages to others. Preserve protected release approvals, provenance, signatures,
  redaction, and exact-byte verification. A request for a specific external action counts as
  authorization for that action; do not ask for the same approval again.

## Skills and references

Read the relevant skill before domain-specific changes. Skills live at
`.agents/skills/<directory>/SKILL.md`; use the session catalog for names and descriptions.
Read only references relevant to the operation. A typo or isolated prose edit does not require
loading a subsystem's operational runbooks.

| Work | Skill directory |
| --- | --- |
| Module ownership or cross-module changes | `cryptad-architecture` |
| Build/test; formatting, analyzers, dependencies | `cryptad-build-test`; `cryptad-build-tooling` |
| Java style and API comments; contributor/operator prose | `cryptad-style-docs`; `cryptad-writing-guides` |
| Environment detection; AEAD formats | `cryptad-appenv`; `cryptad-crypto-aead` |
| CoreUpdater and support lifecycle; Swing launcher | `cryptad-core-updater`; `cryptad-launcher-ui` |
| AppHost, Platform API, bundles/catalogs, app UI/SDK, legacy retirement | `cryptad-platform-apps` |
| Distributions/installers; live JVM diagnosis | `cryptad-packaging`; `cryptad-runtime-debugging` |
| Interop, performance, certification, protected release CI | `cryptad-interop-performance-gates` |
| Codex Docker helpers and Playwright service | `cryptad-codex-docker` |
| Branch creation; releases/hotfixes; release notes | `cryptad-start-work-branch`; `cryptad-release-workflow`; `cryptad-hotfix-workflow`; `cryptad-write-release-notes` |

Use focused task skills for requested test coverage, Javadoc, refactoring, CI fixes, commits,
and PRs. If a referenced skill/tool is unavailable, use an equivalent available capability;
report a blocker only when its missing guidance or access is necessary. For external facts,
use current primary sources and cite them; do not require a particular search provider.

## Verification and completion

Choose checks for the changed behavior: docs/metadata checks for prose, owning-module focused
tests for Java, and applicable offline self-tests for tooling. Add regression tests that establish
behavior; avoid tests that merely copy implementation or check wording.
Run a full suite for cross-module/shared behavior changes, explicit user requests, or applicable
release/CI gates. After checks pass, repeat or broaden them only for new changes or unresolved risk.

Report what changed, why, actual check results, and remaining limitations. Use the user's language
and detail proportional to the task. Never equate local tests, fixtures, prepared artifacts, or
uploads with live publication. Maintain specialized procedures in skills and references.
