---
name: write-javadoc-for-new-java-files
description: Find new non-test Java files in branch/local changes and document them with focused doclint.
---

# Document newly added Java files

Use [write-javadoc](../write-javadoc/SKILL.md) as the per-file contract.
Default to local additions on `develop`; elsewhere include additions since the merge base with
`origin/develop` (local `develop` fallback). Include staged, unstaged, and untracked additions.
Honor an explicit base or path limit.

Run the helper from the repository root:

```bash
python3 .agents/skills/write-javadoc-for-new-java-files/scripts/list_new_non_test_java_files.py
# Local additions in a selected subtree:
python3 .agents/skills/write-javadoc-for-new-java-files/scripts/list_new_non_test_java_files.py --base-ref HEAD --limit src/main/java/network/crypta/client
```

The helper excludes test source sets and test-like basenames and retains new production
`package-info.java`. Inspect its selected files; if none remain, report that outcome.

Document each selected file's actual contract, changing comments only. Group related files when
shared context or classpath preparation makes that efficient, while tracking doclint results per file.
Use the owning module's resolved classpath and rerun validation after final edits. Avoid unrelated
runtime tests for comment-only changes.

Report the comparison base, selected/processed/skipped files, and actual doclint results or blockers.
