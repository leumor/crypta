# Rules reference

Read for Rules, Procedure, Checklist. Commands and unlinked source paths are relative to the repository root.

## Rules
- Hotfix branches are `hotfix/<build-number>` and must be based on `main`.
- If the hotfix changes the shipped build, bump the integer `version` in `build.gradle.kts` to the next build number.
- Tag an ordinary hotfix as `v<build-number>` on the hotfix branch. For a Stable 1.0 security
  hotfix, the protected maintenance workflow creates or verifies the annotated tag after
  authorization; do not tag it manually.
- Merge `hotfix/*` into `main` and back-merge into `develop` using **no squash** and `--no-ff`.
- Do not rebase/squash hotfix merges.

---

## Procedure
1) Sync `main` and create the hotfix branch:
```sh
git checkout main
git pull
git checkout -b hotfix/<build-number>
```

2) Apply the fix, run tests/CI per repo conventions.
- If the hotfix changes the shipped build, set `version = <build-number>` in `build.gradle.kts`.

3) For an ordinary hotfix, tag the hotfix on the hotfix branch:
```sh
git tag v<build-number>
```

For a Stable 1.0 security hotfix, do not run that command. Validate the exact candidate with
`stable-backport`, then `stable-maintenance`, and let the protected maintenance workflow create or
idempotently verify the annotated tag. The workflows never merge the hotfix branch.

4) Merge to `main` (no squash; preserve branch context):
```sh
git checkout main
git pull
git merge --no-ff hotfix/<build-number>
```

5) Back-merge to `develop` (no squash):
```sh
git checkout develop
git pull
git merge --no-ff hotfix/<build-number>
```

6) Push branches and tag for an ordinary hotfix:
```sh
git push origin main develop hotfix/<build-number>
git push origin v<build-number>
```

---

## Checklist
- [ ] `build.gradle.kts` version is the intended integer build number (if shipped).
- [ ] CI green on `hotfix/<build-number>`.
- [ ] Ordinary hotfix: tag `v<build-number>` created. Stable 1.0 security hotfix: protected
      publication receipt verifies the annotated tag.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tag pushed.
