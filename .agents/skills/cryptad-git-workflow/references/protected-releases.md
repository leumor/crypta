# Release policy details

Paths are repository-root-relative.

## Ordinary release checklist

Use this checklist only for an authorized release operation; Stable releases use the protected sequence below.

## Release/hotfix checklist
- [ ] `build.gradle.kts` has the intended integer `version`.
- [ ] CI is green on the release/hotfix branch.
- [ ] Tag created as `v<build-number>`.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tags are pushed.
- [ ] Release notes updated (if applicable).


## Protected Stable release policy

- The Stable 1.0 protected GA workflow may create or verify the annotated `v<build-number>` tag and
  GitHub Release only after exact-RC validation and environment approval. It never merges the
  release branch. Continue to use explicit release-manager-approved `--no-ff` merges into `main`
  and `develop`.
- The protected Stable 1.0 maintenance workflow applies the same boundary to later routine
  `release/<build-number>` and security `hotfix/<build-number>` candidates: it may create or verify
  the annotated tag and exact public state, but it never creates or merges branches.
  Follow `docs/stable-1.0-maintenance-release-and-hotfix-path.md` for the protected sequence and
  verify that the eventual `main` merge contains the tagged shipped commit; a `--no-ff` merge gives
  `main` a distinct merge-commit tip.
- Before a Stable 1.0 maintenance or security-hotfix freeze, use `stable-backport` to classify
  every proposed fix, authenticate its full source/candidate commit identities and provenance,
  carry the prior queue forward, and account for every candidate change. Routine work uses only
  `routine-maintenance`; critical incident work uses only `security-hotfix`. Patch-id equality is
  supporting evidence for a reviewed clean cherry-pick, not authorization. Candidate handoff
  requires `verified` fixes; post-publication completion requires separate `main` and `develop`
  no-ff merge commits on those protected tips' first-parent chains.
- Clean cherry-pick and manual-conflict approval must come from the exact successful protected
  provenance-review workflow artifact; matching caller-selected digests are not approval. Keep the
  authoritative queue protected and upload only its bounded public projection in plaintext.
  Transport full phase and review handoffs only as exact authenticated encrypted envelopes, and
  decrypt them with the shared protected-environment handoff key.
- For a routine train, never reuse `candidateBaseCommit` as proof of its own branch role. The
  protected train workflow freezes the independently resolved protected `develop` tip as
  `developmentLineageCommit`; certification requires the candidate base to be the exact merge
  base with that lineage. Once a fix is landed, its provenance is immutable.
- For a security-hotfix train, freeze the independently resolved protected `main` tip as
  `mainLineageCommit` and require `candidateBaseCommit` to equal it. The tagged publication
  predecessor must remain an ancestor of that tip. Do not branch from the tagged candidate when
  `main` has advanced through its required no-ff reconciliation merge.
- Treat GA as the sole queue genesis. A later published predecessor must authenticate the exact
  `previousStableBackportQueue` and `previousStableBackportValidation`; absence never means “start
  over.” For merge coverage, compare against Git's automatic merge and both parents rather than
  trusting an empty combined diff.
- Cryptad has one authenticated Stable 1.0 publication chain. Historical supported, security-only,
  deprecated, end-of-support, or revoked builds may be policy-qualified upgrade or recovery test
  sources; never create a parallel patch branch, LTS line, or latest pointer for them.
- After publication and the explicit no-squash, `--no-ff` merges, run `stable-backport` in
  `verify-release-completion` mode. Missing `main`/`develop` reconciliation or hotfix merge-back
  remains a carried blocker for the next train. Completion accepts only a merge tree matching
  Git's isolated automatic merge result as reconciled; a manual resolution is not authenticated by
  parent shape or protected-tip reachability alone. Once the graph and protected attestation pass,
  the completion layer records that content-review failure as the exact policy-derived carried
  obligation and marks reconciliation `content-review-required`. The next queue must seed that
  exact row before the published fixes move to `released`, and remains blocked pending separately
  authenticated review.
- Before the next train advances prior fixes to `released`, use an unexpired successful completion
  artifact when available, or reauthenticate the support-lifetime protected completion bundle
  after Actions retention expires. Re-resolve protected `main` and `develop` in both cases and
  carry the resulting predecessor-completion handoff through all train phases.
- Record the published `release/<build>` or `hotfix/<build>` candidate as the merged tip of both
  independent no-ff merge records. Do not describe the `main` merge commit as the tip merged into
  `develop`. A fix provenance commit may be earlier than the publication tip, but it must remain
  an authenticated ancestor. Completion must bind exact protected `main` and `develop` tips and
  consume the receipt-bound frozen validation from the authorized prior workflow phase.

For Stable 1.0, also verify:

- [ ] The selected RC is the latest successful protected freeze/refreeze for the release/build and
      commit.
- [ ] The protected authorization, promotion plan, and publication receipt bind the same source,
      freeze, archive, product, catalog, validation, notes, and maintenance-baseline digests.
- [ ] An existing tag/Release is accepted only when its target, notes, planned assets, sizes, and
      digests match exactly; conflicting or partial state is recorded as
      `publication-verification-failed` without recovery code mutating it.
- [ ] No test, local default, pull-request workflow, or validate-only run can create a tag, Release,
      branch, public catalog update, update descriptor, or network insert.
- [ ] For a later Stable 1.0 release, `stable-maintenance` authenticated the immutable GA root and
      latest published predecessor, and the protected receipt verifies exact candidate bytes before
      the manual no-squash, `--no-ff` merge-back.
- [ ] `stable-maintenance.backport-release-train` binds the exact accepted fix set, train policy
      and queue, candidate and predecessor, zero-unaccounted coverage result, authorization, and
      unresolved obligations.
- [ ] The post-release completion record authenticates the exact receipt and `main`/`develop`
      merge parents without performing those merges.
- [ ] Any Stable 1.0 support-state change uses the separate protected `support-lifecycle`
      descriptor workflow after authenticating the complete published chain; it does not rewrite a
      tag, Release asset, baseline, receipt, history entry, or historical `core-info.json`.
