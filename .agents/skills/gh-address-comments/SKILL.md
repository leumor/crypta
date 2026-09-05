---
name: gh-address-comments
description: Inspect and address review comments on the current branch's GitHub PR.
metadata:
  short-description: Address GitHub PR review comments
---

# Address PR review comments

Load [Git policy](../cryptad-git-workflow/SKILL.md) for explicit `leumor` authentication.
Use existing network permissions; additional access is needed only if the environment requires it.

```bash
python3 .agents/skills/gh-address-comments/scripts/fetch_comments.py
```

Follow a user-selected subset. For a general request to address the review, handle all actionable
unresolved comments without asking the user to select them again. Inspect the code; evaluate
review suggestions rather than assuming they are correct. Ask about conflicting requirements or
product decisions that cannot be inferred.

Apply fixes and verify affected behavior. Explain comments already addressed, obsolete, or unsuitable
to implement. Posting replies, submitting reviews, and resolving threads require authorization for
those actions; prepare fixes and response text first. Report changes, checks, and unresolved decisions.
