# Agent guidance audit

This audit streamlines Cryptad's repository instructions and agent workflows while preserving
project compatibility, identity, and protected publication requirements.

## Basis and scope

Reviewed on 2026-09-05 against the [official GPT-6 Astra guidance](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-6-astra).
Its relevant recommendations are to audit instruction conflicts, respect existing user intent,
calibrate verification, and define useful delegation and completion boundaries. These are design
criteria, not evidence of a measured performance gain.

Eric Provencher's [Rethinking skills and prompts for GPT-6 Astra](https://x.com/pvncher/status/2095991462416490862)
was evaluated from the full text supplied by the requester after direct retrieval failed.
The changes apply its short-trigger, progressive-disclosure, task-specific-boundary, and
completion guidance. No secondary summary was used as a substitute for the supplied article.

The [official skills documentation](https://learn.chatgpt.com/docs/build-skills) explains that
names/descriptions participate in discovery and full skill content is loaded on demand.
The [AGENTS.md documentation](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
explains repository instruction discovery and its size limit. The resulting instructions retain
model-independent project facts rather than pinning one model or reasoning effort.

Scope: the tracked root `AGENTS.md`, all 35 repository `SKILL.md` files (including two under
`.system`), their referenced helpers/metadata and instruction-bearing references, and all 48
GitHub Actions workflows (116 jobs). Workflow review covered syntax, events, runner declarations,
model/prompt coupling, and consistency with the agent/release instructions; it was not a new
end-to-end production security certification of all jobs. The Docker helper surface has no tracked
model/effort configuration to migrate. Host-managed Codex settings were not changed.

## Findings and changes

| Finding | Change |
| --- | --- |
| Root catalog and always-on section repeat the same routing; unavailable `skill(...)`/`web-search` requirements | One contextual routing table and available-tool fallback |
| Ordinary edits load long operational manuals | Short skill entrypoints with 50 task-specific reference pages |
| Build skill stops for approval after any command failure | Diagnose and fix in-scope failures, with explicit external blockers |
| PR/CI/review recipes request approval already provided by the task | Honor existing authorization; retain separate publication and message boundaries |
| Single-file changes trigger broad tests and local plus server analysis | Owning-module tests, file analysis, broader checks for shared behavior or explicit gates |
| Javadoc has arbitrary word/member quotas and changes log strings | Document actual contracts; comments-only scope and honest doclint results |
| S107/test skills require unrelated consolidation | Reuse relevant types/tests while preserving module boundaries and intentional test layout |
| Old skill creator regenerates verbose recipes and mandatory archives | Compact initializer; package only when an archive is requested |
| Manual PR workflows verify the wrong account after a write | Verify `leumor` before writes; preserve author/committer identity safeguards |
| CI tag trigger expects semantic versions | Match integer build tags with `v[0-9]+` |
| Existing dedicated runner labels fail actionlint | Register the four exact labels without a wildcard or ignored diagnostic |

The tag filter uses GitHub's documented [filter pattern semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#filter-pattern-cheat-sheet):
`[0-9]+` denotes one or more digits. Existing protected jobs, environments, permissions, evidence
contracts, signing/provenance rules, and runtime matrices remain in place.

## Instruction size

These are UTF-8 byte counts and physical line counts, not tokenizer measurements or latency benchmarks.
The baseline is the checkout before this audit.

| Surface | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| Root AGENTS.md bytes | 9,726 | 4,999 | 48.6% |
| Skill entrypoint bytes | 444,772 | 67,492 | 84.8% |
| Skill entrypoint lines | 7,542 | 1,381 | 81.7% |
| Skill description characters | 7,647 | 3,416 | 55.3% |

The 50 new references retain 321,178 bytes of specialized detail. Entrypoint reduction does not mean
those details were deleted or that all skills are loaded together in a real task. A preservation
comparison covered 67 moved sections: 64 retained their text after normalizing relative-link
adjustments and shell filter quoting; three validation sections were deliberately revised
(test command selection, SonarLint scope, and app-platform check scope).

## Skill-by-skill disposition

Existing skill names and directory paths remain stable, including the two historical directory/name
mismatches. The local system helpers and licenses are retained for callers that use those paths.

| Skill directory | Entrypoint bytes before → after | Decision |
| --- | ---: | --- |
| [.system/skill-creator](../.agents/skills/.system/skill-creator/SKILL.md) | 18,517 → 2,402 | Replace recipe/packaging mandates with focused authoring; simplify initializer template. |
| [.system/skill-installer](../.agents/skills/.system/skill-installer/SKILL.md) | 2,815 → 2,935 | Use actual session network permissions; preserve helper/install contracts. |
| [convert-tests-to-aaa](../.agents/skills/convert-tests-to-aaa/SKILL.md) | 3,451 → 1,049 | Remove invocation boilerplate; preserve stateful scenarios and test semantics. |
| [create-pr](../.agents/skills/create-pr/SKILL.md) | 7,817 → 1,847 | Honor existing authorization/draft intent; verify identity before writes; scope formatting. |
| [cryptad-appenv](../.agents/skills/cryptad-appenv/SKILL.md) | 1,899 → 1,875 | Retain platform invariants; remove obsolete OpenCode-only metadata. |
| [cryptad-architecture](../.agents/skills/cryptad-architecture/SKILL.md) | 51,805 → 928 | Route to module, subsystem, design/security, and release-tooling references. |
| [cryptad-build-test](../.agents/skills/cryptad-build-test/SKILL.md) | 23,235 → 2,080 | Remove stop-on-any-error rule; module-qualified tests and risk-based verification. |
| [cryptad-build-tooling](../.agents/skills/cryptad-build-tooling/SKILL.md) | 10,271 → 1,319 | Separate analyzers; remove mandatory full/local/server analysis combination. |
| [cryptad-codex-docker](../.agents/skills/cryptad-codex-docker/SKILL.md) | 3,223 → 3,604 | Make validation conditional; distinguish running-container restart authorization. |
| [cryptad-core-updater](../.agents/skills/cryptad-core-updater/SKILL.md) | 16,510 → 1,219 | Route package updates, platform/format, maintenance, and lifecycle separately. |
| [cryptad-crypto-aead](../.agents/skills/cryptad-crypto-aead/SKILL.md) | 2,855 → 2,831 | Retain format/migration invariants; remove obsolete compatibility metadata. |
| [cryptad-git-workflow](../.agents/skills/cryptad-git-workflow/SKILL.md) | 11,052 → 4,862 | Keep identity/branch policy visible; defer protected-release details. |
| [cryptad-hotfix-workflow](../.agents/skills/cryptad-hotfix-workflow/SKILL.md) | 11,084 → 961 | Separate ordinary commands from protected security-hotfix operation. |
| [cryptad-interop-performance-gates](../.agents/skills/cryptad-interop-performance-gates/SKILL.md) | 81,226 → 1,524 | Route interop, performance, certification, train, maintenance, lifecycle, and protected execution. |
| [cryptad-launcher-ui](../.agents/skills/cryptad-launcher-ui/SKILL.md) | 4,781 → 4,757 | Retain concise launcher behavior; remove obsolete compatibility metadata. |
| [cryptad-packaging](../.agents/skills/cryptad-packaging/SKILL.md) | 22,891 → 1,132 | Route layout, native packaging, Linux, Flatpak, and frozen release packages. |
| [cryptad-platform-apps](../.agents/skills/cryptad-platform-apps/SKILL.md) | 52,262 → 1,481 | Route ownership/guardrails and specialized evidence; scope validation by impact. |
| [cryptad-release-workflow](../.agents/skills/cryptad-release-workflow/SKILL.md) | 32,058 → 1,288 | State mode and authorization boundaries before detailed release recipes. |
| [cryptad-runtime-debugging](../.agents/skills/cryptad-runtime-debugging/SKILL.md) | 7,478 → 7,369 | Shorten trigger; make potentially pausing histogram conditional; quote filters. |
| [cryptad-start-work-branch](../.agents/skills/cryptad-start-work-branch/SKILL.md) | 1,321 → 1,304 | Preserve existing work; local branch creation no longer implies push/PR. |
| [cryptad-style-docs](../.agents/skills/cryptad-style-docs/SKILL.md) | 2,317 → 2,427 | Document affected contracts; remove whole-file documentation expansion trigger. |
| [cryptad-write-release-notes](../.agents/skills/cryptad-write-release-notes/SKILL.md) | 11,392 → 1,030 | Scope requested outputs; support hotfix/candidate sources; defer frozen-note contracts. |
| [cryptad-writing-guides](../.agents/skills/cryptad-writing-guides/SKILL.md) | 2,655 → 1,106 | Select prose reference by task; align release-body versus changelog scope. |
| [fix-s107-too-many-parameters](../.agents/skills/fix-s107-too-many-parameters/SKILL.md) | 8,021 → 1,435 | Reuse semantic concepts without compulsory whole-project type consolidation. |
| [fix_file_until_green](../.agents/skills/fix_file_until_green/SKILL.md) | 4,923 → 1,290 | Focused tests/file analysis; remove automatic full-suite and provider dependencies. |
| [gh-address-comments](../.agents/skills/gh-address-comments/SKILL.md) | 1,777 → 1,122 | Address requested actionable comments without a redundant selection round. |
| [gh-fix-ci](../.agents/skills/gh-fix-ci/SKILL.md) | 4,263 → 1,556 | Remove missing plan-skill dependency and repeat approval; verify requested fixes. |
| [git-commit-helper](../.agents/skills/git-commit-helper/SKILL.md) | 4,372 → 882 | Message generation does not imply staging, amend, commit, or push. |
| [git-commit-push](../.agents/skills/git-commit-push/SKILL.md) | 4,382 → 1,459 | Scope formatting; allow requested fixes; preserve unrelated staged changes. |
| [improve-unit-test-coverage-for-current-changes](../.agents/skills/improve-unit-test-coverage-for-current-changes/SKILL.md) | 7,875 → 1,841 | Keep branch/local selection; make verification proportional; align UI metadata. |
| [junit6-package-visibility](../.agents/skills/junit6-package-visibility/SKILL.md) | 3,598 → 940 | Keep required visibility; remove caller-rewrite and generic analyzer recipe. |
| [reduce-cognitive-complexity](../.agents/skills/reduce-cognitive-complexity/SKILL.md) | 4,584 → 957 | Keep measured threshold; remove mandatory refactoring itinerary/output sections. |
| [write-javadoc](../.agents/skills/write-javadoc/SKILL.md) | 8,752 → 1,875 | Comments only; remove word quotas, log edits, hidden failures, and arbitrary cached JARs. |
| [write-javadoc-for-new-java-files](../.agents/skills/write-javadoc-for-new-java-files/SKILL.md) | 4,726 → 1,456 | Keep deterministic helper selection; permit shared preparation with per-file checks. |
| [write-or-improve-unit-tests](../.agents/skills/write-or-improve-unit-tests/SKILL.md) | 4,584 → 1,349 | Preserve intentional test layout; remove forced consolidation/full-suite-per-test wording. |

## Validation

- All 35 skills pass the repository's `quick_validate.py` metadata validator.
- All 95 concrete local Markdown links in `AGENTS.md` and skill Markdown resolve.
- All 48 Actions workflows pass `actionlint -oneline` after registering the four existing labels.
- YAML parsing succeeds for the workflows, actionlint configuration, and three skill UI files.
- The initializer passes disposable-directory checks for plain creation, resource/example creation,
  metadata validation after replacing placeholders, refusal to overwrite an existing directory,
  and an end-to-end package smoke check.
- `git diff --check` passes.

The Java runtime and production certification engines were not changed; their full test suites
were not run for this instruction/template and workflow-configuration change. No hosted workflow,
publication, node restart, Git push, or PR creation was performed. Local checks do not establish
hosted CI success or production publication.

To recheck metadata from the repository root:

```bash
for skill in .agents/skills/*/SKILL.md .agents/skills/.system/*/SKILL.md; do
  python3 .agents/skills/.system/skill-creator/scripts/quick_validate.py "${skill%/SKILL.md}" || exit 1
done
actionlint -oneline
git diff --check
```

For behavioral follow-up, compare representative typo, single-file bug, branch-coverage, PR-creation,
and Stable-preparation tasks with the same model, effort, tools, and starting checkout. Record
unnecessary questions, loaded reference bytes, repeated checks, completion, and correctness.
Require protected-release tasks to retain their approvals and exact-byte constraints. This audit
establishes structural improvements and validated helper behavior, not an A/B model evaluation.
