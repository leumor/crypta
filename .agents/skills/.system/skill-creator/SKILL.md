---
name: skill-creator
description: Create or update a focused repository skill and its necessary supporting resources.
metadata:
  short-description: Create or update a skill
---

# Create or update a skill

Use this repository-local workflow when maintaining its skills. The session may also provide a
system skill creator; inspect which version is being used rather than assuming both are current.

Describe the actual capability and a precise trigger in one short description.
Assume the model already knows general programming and tool use. Include project facts,
decision criteria, non-obvious constraints, and useful executable helpers.

Keep the entrypoint as short as the task permits. For multiple operations, link to focused references
and say when each applies. Do not load every reference, copy entire manuals, or use a size ceiling as
a target. Keep small self-contained skills simple.

Preserve user intent, existing authorization, supported metadata, and automatic discovery defaults.
Define completion and any actual mutation boundary. Routine local preparation and fixing failures
within an authorized task should not require repeated approval.
Use fixed sequences only where order protects correctness, security, or reproducibility.
Avoid keyword-based catchalls, word quotas, universal test matrices, mandatory roleplay, and
unavailable tools or skills.

## Local helpers

For a new skill, use the initializer when useful:

```bash
python3 .agents/skills/.system/skill-creator/scripts/init_skill.py <name> --path .agents/skills
```

Choose a lowercase hyphenated name under 64 characters. Add `--resources scripts,references,assets`
only for resources the task needs. Replace scaffold placeholders. Do not initialize existing skills.

Validate metadata with:

```bash
python3 .agents/skills/.system/skill-creator/scripts/quick_validate.py <skill-directory>
```

This local validator checks frontmatter, not link validity or behavioral quality.
Also check referenced paths, matching script interfaces, trigger precision, and overlapping guidance.
Run changed helpers with safe inputs. Evaluate realistic tasks for complex workflows when useful;
use independent agents only when delegation is authorized.

Use `scripts/package_skill.py` only when a distributable archive is requested.
Keep existing licenses and working helpers. Do not generate an archive for every repository edit.
