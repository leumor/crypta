# Stable 1.0 backport and release-train governance

Use this runbook to classify a proposed Stable 1.0 fix, transfer an accepted fix into the next
authorized release candidate, account for the candidate's complete Git change set, and verify
post-publication branch reconciliation.

This process governs release-train composition. It does not replace the Stable maintenance,
security-hotfix, support-lifecycle, catalog, CoreUpdater, tag, or GitHub Release publication
authorities.

## Single publication chain

Cryptad has one authenticated Stable 1.0 publication chain. A backport transfers an approved fix
from its canonical source commit or development lineage into the next authorized
`release/<candidate-build>` or `hotfix/<candidate-build>` candidate.

The following rules are non-waivable:

- routine maintenance is a successor of the latest authenticated publication pointer;
- a security hotfix is a successor under the existing narrowly scoped hotfix policy;
- integer builds increase strictly and published tags remain `v<build-number>`;
- a historical build is an upgrade, advisory, or recovery test source, not a mutable branch;
- `release/<old-build>-patch`, parallel LTS lines, a second latest pointer, and forked publication
  descendants are forbidden;
- certification never cherry-picks, merges, creates branches, pushes, tags, publishes a GitHub
  Release, changes a catalog, inserts a CoreUpdater descriptor, or publishes lifecycle state.

The authenticated predecessor, latest-pointer digest, publication history, and lifecycle ledger
remain the authorities. Every train re-authenticates the existing full GA promotion, validation,
authorization-summary, publication-plan, receipt, checksums, provenance, and maintenance-baseline
bundle as its immutable root. For the first post-GA train, that GA maintenance baseline and GA
publication receipt are the predecessor and the maintenance latest pointer must be absent.
Every later train requires the exact active latest-published maintenance pointer. This is the same
genesis/no-fork distinction enforced by `stable-maintenance`. A branch name, pull-request number,
issue label, or commit trailer is not release authorization.

## Command and modes

The checked-in example is specifically the first post-GA train: its predecessor fields select the
authenticated GA receipt and maintenance baseline, and it intentionally omits a maintenance latest
pointer and prior train queue. Replace all three predecessor identity placeholders—the integer
build, release id, and product digest—along with the candidate placeholders before running the
side-effect-free component:

```bash
cp tools/release-certification/manifests/stable-1.0-backport.example.json \
  build/stable-1.0-backport.json
python3 tools/release-certification/certify.py stable-backport \
  --manifest build/stable-1.0-backport.json
```

For every later train, add the exact active `latestPublishedMaintenancePointer`,
`previousStableBackportQueue`, and `previousStableBackportValidation` inputs described below; do
not reuse the example's GA-genesis shape for a maintenance successor.

If the predecessor published an open shortened-window hotfix follow-up that has since been
closed, also supply the exact authenticated `hotfixFollowUpClosure`. The maintenance authority
applies that closure as an overlay without rewriting the published predecessor. The authoritative
queue, candidate, lineage, and validation bind its exact digest; the public queue commits to it
only through the opaque intake-composition digest, and the public validation does not disclose
the closure digest. Train authorization cannot predate the closure's authenticated completion
time. A routine train remains blocked when the closure is absent, substituted, or does not
authenticate the published obligation.

`commands.stable-backport.mode` is closed to:

| Mode | Purpose |
| --- | --- |
| `evaluate` | Validate intake, policy, prior queue state, lifecycle coverage, and proposed dispositions before fixes are landed. |
| `prepare-candidate` | Bind the exact candidate commit, branch role, fix set, provenance, evidence, and change coverage. |
| `validate-authorization` | Validate a narrowly scoped authorization for the exact train composition and candidate handoff. |
| `verify-release-completion` | Authenticate publication, lifecycle activation or pending activation, and main/develop reconciliation evidence. |

Protected inputs are accepted only in the modes that require them. Repeating a run against the
same authenticated inputs produces the same semantic JSON and Markdown content, apart from
policy-approved producer metadata.

`evaluate` is intentionally pre-landing. The release or hotfix branch may advance while approved
fixes are transferred after evaluation. The protected `evaluate-intake` to `prepare-candidate`
handoff therefore preserves the train, build, lane, policy, queue lineage, and authenticated
development or main base without requiring the earlier evaluated commit to equal the later
candidate. Candidate equality becomes mandatory after `prepare-candidate`, when the candidate is
frozen for authorization and maintenance.

## Versioned policy

`tools/release-certification/stable-1.0-backport-release-train-policy.json` is the reviewed source
for the closed vocabularies, transition rules, release eligibility, Git identity requirements,
evidence windows, critical deadlines, roles, authorization lifetime, carry-forward behavior,
redaction bounds, queue limits, and non-waivable blockers. Certification binds the exact policy
digest into the queue, plan, validation, authorization, completion, checksums, and provenance.

Do not reproduce policy deadlines or authorization role names in a manifest, workflow expression,
or release note. Changing the policy requires normal review and produces a different policy
digest.

## Fix classifications

Every fix uses one classification:

| Classification | Stable 1.0 treatment |
| --- | --- |
| `compatible-bug-fix` | Routine-eligible when candidate-bound tests prove behavioral and persistent, wire, and API compatibility. |
| `security-fix` | Requires an opaque incident or advisory reference, severity, affected scope, disclosure state, and public-safe summary. Critical urgent fixes use `security-hotfix`; other fixes may use routine maintenance only when policy permits it. |
| `platform-api-compatible-addition` | Normally routine; must pass the Platform API 1.0 compatibility window and stable third-party sample checks without redefining an existing stable endpoint or capability. |
| `platform-api-deprecation` | Requires the original deprecation clock, removal window, compatibility evidence, and public-safe developer guidance. It cannot remove a dependency still used by supported builds or apps. |
| `stable-catalog-app-patch` | Requires the existing catalog, signing, review, compatibility, permission-delta, app-data migration, backup/restore, and stable app-id gates. |
| `packaging-installer-fix` | Names affected package keys and platforms and runs the exact relevant package checks. Routine maintenance still requires its policy-defined complete package matrix. |
| `release-tooling-fix` | May repair certification or publication tooling only when product bytes and authority remain truthfully represented. It cannot weaken signing, redaction, exact-byte, archive, provenance, or conflict gates. |
| `documentation-support-fix` | May align notes or support guidance with shipped behavior. It cannot conceal a product or behavioral change. |
| `unsupported-feature-change` | Never eligible for Stable 1.0 publication. Use `future-milestone`, `deferred`, or `rejected` with a public-safe rationale. |
| `breaking-change` | Never eligible for Stable 1.0 maintenance or hotfix publication and cannot be waived into a train. |

A breaking change includes an incompatible Platform API, wire or persistent format, content-profile
canonicalization or signature change, destructive data change, or incompatible app/catalog
change.

## Dispositions, lanes, and states

The disposition vocabulary is:

- `routine-maintenance`;
- `security-hotfix`;
- `future-milestone`;
- `deferred`;
- `rejected`.

`routine-maintenance` maps only to `release/<candidate-build>`. `security-hotfix` maps only to
`hotfix/<candidate-build>` and the existing critical incident rules. There is no generic emergency
lane.

The monotonic fix-state vocabulary is:

```text
submitted
triaged
accepted
scheduled
landed
verified
released
deferred
rejected
superseded
```

The policy defines the permitted transitions. In particular:

- a fix cannot jump from `submitted` to `released`;
- `scheduled`, `landed`, and `verified` bind one intended train and candidate; changing that
  schedule requires an append-only transition that first moves the scheduled fix to `deferred`;
- once a fix reaches `landed`, its exact candidate provenance, tree/diff identities, touched paths,
  and reviewer authorization are immutable through `verified` and `released`;
- once a fix enters an authenticated queue, its security incident/advisory identity and severity
  cannot be rewritten; release disposition or lane changes require an append-only state transition,
  so a critical obligation cannot be relabeled as noncritical routine work;
- `prepare-candidate` and later authorization-capable modes require `verified`; a merely `landed`
  fix remains omitted and cannot receive a `go` validation;
- `released` requires a prior authenticated queue plus
  `previousStableBackportCompletion`, whose exact file digest is bound by the fix transition and
  evidence row; the same fix must have been `verified` in that queue and included by its exact
  authorized validation, and the completion already authenticates the maintenance receipt plus
  verified lifecycle activation or an explicit pending-activation state;
- the successor intake timestamp, completion-evidence timestamp, and final `released` transition
  timestamp must be no earlier than the authenticated publication receipt, completion record, and
  protected completion handoff; backdated state cannot satisfy authorization ordering;
- every fix included by a prior authorized validation must make that exact
  `verified`-to-`released` transition before a successor train can replace or supersede it;
- `deferred` retains its owner, rationale, review deadline or target train, and carry-forward
  status;
- `rejected` retains a non-sensitive reason and can re-enter `triaged` only through a new
  append-only authorized transition before it can become accepted;
- `superseded` names one replacement fix with compatible affected scope; a critical security fix
  additionally requires a critical replacement with the same incident and advisory identities;
- a rejected critical security record remains in the non-waivable critical blocker index during
  re-triage and until it is released or reaches an incident-, advisory-, severity-, and
  scope-equivalent supersession;
- deferred, rejected, superseded, unresolved accepted, critical security, hotfix follow-up, and
  merge-back obligations cannot silently disappear from a later queue snapshot.

For a critical security fix, the engine derives the intake-to-triage, triage-to-decision, and
accepted-to-scheduled durations from the immutable transition timestamps. A caller-supplied final
deadline cannot extend or replace those policy windows. Every residency interval is checked,
including a re-entered state and the currently open state. Each completed critical deferral must
remain within the policy maximum, and its transition evidence digest must match the policy-named
security-decision evidence. An open critical deferral also stops being valid once its
policy-bounded `reviewAt` time passes, even if `deadlineAt` is absent. Its `decisionAt` must equal
the append-only transition into `deferred`, and the maximum deferral is measured from that
transition, so a successor intake cannot reset the clock.

## Intake identity and queue

Each fix has a bounded opaque `fixId`. Public and protected security projections share that
identity and a digest-bound projection relationship. A fix record binds the classification,
disposition, state history, affected components and risks, exact source commit, intended candidate,
required evidence, owners and reviewers, deadlines, and public-safe note material.

Every evidence row binds the exact reviewed `policyDigest` and current `queueDigest`. Queue
identity normalizes only the embedded evidence `queueDigest` slots to the fixed all-zero SHA-256
placeholder before hashing; every other queue and evidence field remains covered. This
deterministic self-binding avoids a circular hash while making a changed fix, state, evidence row,
obligation, predecessor, policy, or candidate invalidate the evidence binding.

Evidence ids listed by policy as protected must use `visibility: protected`. In particular,
incident scope and provenance-review receipts cannot be relabeled as public merely because their
payload uses opaque ids.

The fix `publicProjectionDigest` is the canonical semantic digest of `fixId`, classification, and
public summary. A security record has a second canonical projection digest over the same `fixId`
plus its opaque incident/advisory ids, severity, disclosure state, and public-safe summary. Its
protected-record digest must match the fix record’s protected-record digest and must differ from
the public projection. Certification recomputes these relationships; it does not trust digest
claims supplied by intake.

The release-train queue is append-only and digest chained to:

- the exact policy digest;
- the prior authenticated queue digest, when present;
- the latest maintenance publication and lifecycle state;
- the exact repository and candidate identity.

The GA-root train is the only permitted queue genesis. Every later authenticated maintenance
successor must supply both `previousStableBackportQueue` and
`previousStableBackportValidation`. The successor baseline’s physical train-validation digest
must authenticate that exact validation; the validation must bind the same queue digest and the
published predecessor commit. Omitting both inputs cannot start a second genesis or discard
history.

Rows have a deterministic documented order. Duplicate fix ids, duplicate candidate commits,
contradictory state or lane declarations, incompatible overlapping security scopes, reordered
history, or an omitted unresolved row fail certification. Queue bounds fail closed; the command
does not silently truncate history. Any future compaction requires a separately authenticated
checkpoint design.

Post-release main/develop merges, hotfix merge-back, and hotfix follow-up use closed obligation
records. Each record binds an opaque obligation id, type, source train and fix ids, creation time,
status, and exact evidence digest. An open obligation cannot disappear; a resolved obligation
cannot reopen; resolution requires a timestamp plus an evidence digest different from the prior
open/failure evidence; and the resolution timestamp and evidence are immutable afterward while
preserving the immutable source identity. Open obligations make the queue `blocked`. If completion
verification finds a missing merge, the release manager records the failure-attestation digest as
an open obligation in the next authenticated intake; ordinary certification never performs or
fabricates the missing merge.

A fix provenance `candidateCommit` is the exact inherited, cherry-picked, or conflict-resolved fix
commit. It need not be the release branch tip. A transition to `released` proves that commit is an
ancestor of the authenticated publication commit and separately binds candidate-scoped completion
evidence; it never rewrites provenance to make every fix appear to be the tip.

## Git object and branch authentication

Git inspection runs in the exact confined repository and accepts only full canonical commit object
ids for the repository object format. It rejects abbreviations, ambiguity, symbolic refs, revision
expressions such as `HEAD~1`, reflog syntax, `branch:path`, missing objects, non-commit objects,
wrong repositories, and object substitution.

The Git inspector uses argument-vector subprocess calls with an explicit working directory,
sanitized environment, bounded output, and no arbitrary remote fetch. It verifies:

- each source, candidate, predecessor, base, merge base, and reconciliation object;
- exact ancestry through the authorized lineage;
- the branch role and authenticated branch base independently of its displayed name; for a routine
  train the protected workflow resolves the exact protected `develop` tip, freezes it in the
  checksummed phase handoff, proves the frozen lineage remains reachable from protected `develop`,
  and requires the declared branch base to be the exact candidate/lineage merge base;
- the integer candidate build and `build.gradle.kts` version;
- the candidate commit consumed by both release-train and `stable-maintenance` certification;
- the latest authenticated predecessor and no-fork pointer;
- exact no-squash, `--no-ff` merge graph parents or a protected-workflow attestation bound to the
  exact merge commit and parent ids.

Remote branch names and GitHub labels remain advisory unless an authenticated protected input binds
them to exact commit ids.

## Source-to-candidate provenance

Every landed fix uses one provenance mode:

| Mode | Required proof |
| --- | --- |
| `inherited` | The exact source fix commit is an ancestor of the candidate through the authorized development/release lineage. |
| `clean-cherry-pick` | Distinct source and candidate commits have the same stable patch id, matching affected scope and touched-path inventory, exact tree/diff digests, candidate ancestry, and a `stable-backport.clean-cherry-pick-review` protected evidence row. The review authorization comes from the protected provenance-review workflow and binds the configured role, policy, source, predecessor, candidate, normalized diff, path inventory, and evidence digest. |
| `manual-conflict-resolution` | Exact source, candidate, merge-base and base-tree identities; conflict paths; normalized diff or changed-hunk evidence; public-safe rationale; focused candidate tests; and an explicit no-unrelated-feature finding. The additional reviewer authorization uses the same protected-workflow artifact contract and also binds the focused-test ids. |

Patch-id equality is supporting provenance, never release authorization. A matching patch id with
unrelated hunks, different scope, wrong ancestry, or a switched candidate fails. Merge commits,
empty commits, binary changes, renames, generated files, and copy changes receive explicit
policy-defined handling; a merge commit is never silently treated as a normal single-parent patch.

Repeating a caller-selected digest in the fix, ownership, and evidence rows is not review
authorization. Run
`.github/workflows/stable-1.0-backport-review-authorization.yml` in the
`stable-1.0-backport-review` environment, then give the train workflow the exact successful run,
artifact name, Actions artifact digest, source commit, and workflow identity. The train workflow
downloads every declared reviewer artifact and builds the bounded
`stableBackportReviewAuthorizations` protected input. Extra, missing, expired, or substituted
review records fail before certification. Review validity is half-open: a record is valid before
`expiresAt` and invalid at that exact instant.

A semantic reimplementation is a new reviewed fix with its own identity and evidence. There is no
unreviewed “equivalent implementation” shortcut.

## Candidate change accounting

`prepare-candidate` compares the exact predecessor/development/candidate graph and assigns every
commit or change to one category:

```text
accepted-fix
approved-release-metadata
approved-release-tooling
approved-docs-support
merge-context
unaccounted
```

The coverage report binds the predecessor, candidate, merge base, policy digest, queue digest,
commit ids, paths, and diff evidence. Every verification row binds both the exact predecessor and
candidate and must remain inside the policy’s lane-specific freshness window. The train validation
preserves each evidence row’s normalized `generatedAt` and `expiresAt` plus its derived
`freshnessDeadlineAt`; Stable maintenance and the protected publication adapter independently
recompute that deadline and reject it after expiry. `unaccounted` is a blocker. A commit cannot be
assigned to conflicting fixes. For a two-parent merge, Git inspection reproduces the automatic
merge tree. Only an exact automatic-tree match is `merge-context`; otherwise coverage uses the
union of paths changed from each parent. A resolution that matches one parent while discarding work
from the other therefore remains accountable. Generated release notes/checksums/provenance remain
bound to the train.

The public report contains safe commit ids or links only when policy permits it. It never contains
private branch names, local paths, embargoed patches, or protected incident data.

## Routine maintenance train

A routine train:

1. authenticates the immutable GA root, the latest publication pointer when a maintenance
   successor already exists, the current lifecycle descriptor, a fresh read-only public
   observation of that exact descriptor edition and bytes, and the immediate publishable
   predecessor;
2. binds the exact `release/<candidate-build>` commit derived from the authorized development
   lineage, using `policies.developmentLineageCommit` supplied by the protected workflow rather
   than treating `candidateBaseCommit` as its own authorization; the base must be on that
   protected `develop` tip's first-parent chain, so a merged side-parent feature tip is not a
   valid release-branch base;
3. carries every unresolved accepted, deferred, superseded, follow-up, and reconciliation row
   forward;
4. requires every scheduled fix to be landed, verified, and candidate-bound;
5. accounts for every candidate commit and change;
6. rejects breaking changes, unsupported features, missing fixes, stale tests, unexplained changes,
   wrong bases, overdue security obligations, and incomplete prior merge-backs;
7. prepares public-safe fix lineage for the maintenance notes and history.

Work on `develop` is not Stable-eligible merely because it is reachable. The release branch is a
filtered and explicitly accounted candidate.

## Security-hotfix train

A security-hotfix train starts from the exact authenticated protected `main` tip and predecessor
state and uses a narrow accepted fix set. The protected workflow freezes that independent tip as
`policies.mainLineageCommit`; `candidateBaseCommit` must equal it, and the tagged publication
predecessor must remain its ancestor. This preserves changes made by the prior no-ff `main`
reconciliation instead of branching from the older tagged candidate. The train requires the
existing critical-severity, incident/advisory,
affected-build/package/app/API, authorization, shortened-window, and follow-up policy.
Every included row must be classified as a critical `security-fix` and share one exact
incident/advisory identity pair so the authorized train and mandatory maintenance consumer cannot
disagree about hotfix scope. Required package, app, or release-tooling changes remain part of that
incident-bound security fix’s affected scope and evidence; a separately classified ordinary change
cannot ride the shortened lane.

Unrelated features, cleanup, and ordinary bug fixes are blockers. Protected vulnerability details
remain outside public train artifacts. Before disclosure, public output contains only the opaque
fix/advisory identity and bounded safe wording.

The hotfix publication and follow-up obligations share the same fix and train identity. A verified
back-merge places the fix in `develop`; an incomplete follow-up or merge-back remains a blocker in
the next incompatible queue. A separately authorized superseding security hotfix may carry exactly
one open `hotfix-follow-up`. When maintenance publication created that obligation after the prior
train queue was authorized, its first queue projection must match the authenticated predecessor
baseline’s open/overdue obligation digest, obligated build/train, generation time, and the prior
queue’s critical source-fix identities. Every later queue inherits the row byte-for-byte. An
unbound new follow-up, a second concurrent follow-up, or any main/develop reconciliation obligation
still blocks candidate preparation. A hotfix replacing a revoked or
`security-fixes-only` predecessor uses the same lifecycle and advisory authority required by the
lifecycle runbook.

## Lifecycle-aware coverage

The train consumes the authenticated lifecycle vocabulary instead of creating another support
model:

| Lifecycle state | Train treatment |
| --- | --- |
| `current-stable` | Ordinary authenticated publication predecessor. |
| `supported-maintenance` | Affected-build and safe-upgrade coverage source, never a mutable parallel target. |
| `security-fixes-only` | Security advisory and safe-upgrade coverage source under its existing restrictions. |
| `deprecated` | Upgrade-guidance and policy-approved upgrade-test source. |
| `end-of-support` | Recovery-test source only with explicit authorization; never a normal target. |
| `revoked` | Recovery/advisory source only; never presented as normally supported. |

A critical fix is not operationally complete until each in-scope supported build has a safe upgrade
or recovery path. The report states that the fix is published in a new current build; it never
claims historical bytes were changed. Queue transitions cannot reset lifecycle, Platform API,
app, catalog, content-profile, advisory, or hotfix-follow-up clocks.

## Stable maintenance integration

Future Stable maintenance candidates require the non-waivable evidence row:

```text
stable-maintenance.backport-release-train
```

`stable-maintenance` authenticates the train policy, queue, candidate, predecessor, release
class/lane, landed and verified fix set, zero-unaccounted coverage result, security projection,
authorization, unresolved obligations, and evidence freshness. Candidate, build, commit, and
predecessor identities must match exactly between both components.

For `security-hotfix`, maintenance additionally requires the candidate change scope’s incident id
to equal the train’s sole opaque incident id and requires the candidate
`hotfixPolicyAuthorizationDigest` to equal the train’s
`stable-backport.security-incident-scope` evidence digest.

The protected handoff contains both `stable-1.0-release-train-validation.json` and the complete canonical
`stable-1.0-release-train-authorization-summary.json` authorization record. Despite the historical
file suffix, the latter is the full closed authorization, not only its four-field projection.
Maintenance recomputes its semantic digest, prepare-candidate validation subject, role, scope,
accepted-fix set, validity window, repository/workflow identity, and exact predecessor/candidate
binding. The maintenance workflow also authenticates the successful protected
`stable-backport` run and exact Actions artifact digest named by the manifest metadata, then
requires any producer-supplied copies to match those downloaded bytes.

Digest domains remain explicit: validation `candidateDigest` identifies the canonical
`stable-1.0-release-train-candidate.json` file, while maintenance `candidateIdentityDigest`
identifies the maintenance candidate’s semantic content. They are not compared to each other.
The shared candidate identity is the exact authenticated candidate commit plus release/build and
predecessor bindings, all transitively covered by the full authorization and validation digests.

The exact train digest is bound into maintenance validation and summary, release notes, checksums,
provenance, publication plan, history entry, successor governance, and the pending lifecycle
transition context. Train governance does not rewrite historical baselines, receipts, lifecycle
ledgers, descriptors, or `core-info.json`.

## Authorization boundary

Release-train authorization approves the exact candidate composition and handoff. It binds the
train, release, build, predecessor and candidate commits, queue/plan/validation digests, accepted
fix ids and public classifications, opaque security references, operation, role, validity window,
repository/workflow identity, and policy digest. Wildcards are forbidden.
The canonical `expiresAt` spelling is preserved byte-for-byte in the validation projection so a
schema-valid fractional-second or UTC-offset timestamp cannot diverge from the full authorization.
`issuedAt` must be at or after the latest completed state transition, evidence generation,
obligation event, intake generation, and authenticated public lifecycle observation included by
the handoff. An authorization cannot approve evidence that did not yet exist.
The checked-in policy permits at most 72 hours. That bounded window covers the mandatory 24-hour
post-freeze routine-maintenance soak and leaves up to 48 hours for evidence review and the exact
maintenance handoff. It is not an open-ended publication grant, and a grant longer than 72 hours
fails closed.

This authorization does not authorize publication. The existing Stable maintenance publication
authorization remains authoritative for the tag, GitHub Release, catalog, CoreUpdater, exact
package bytes, and latest-pointer activation.

## Release completion and reconciliation

After publication, `verify-release-completion` authenticates:

- the exact Stable maintenance publication receipt, integer build, tag, and candidate commit;
- the lifecycle activation receipt plus the exact activated ledger/descriptor selecting the
  candidate as `current-stable`, or an explicit pending lifecycle publication state;
- an explicit no-squash, `--no-ff` merge into `main`;
- an explicit no-squash, `--no-ff` merge or back-merge into `develop`;
- for a hotfix, reachability of the exact fix from reconciled `develop`;
- preservation of the already published candidate bytes and identity.

Both no-ff merge records name the published release/hotfix candidate as `mergedTip`; `main`’s merge
commit is not substituted as the tip merged into `develop`. The original candidate-handoff
authorization must have been valid when the authorized validation was created and consumed by
maintenance, but it need not still be current during later read-only completion verification. The
publication receipt’s exact train-validation digest preserves that earlier authorized handoff.
Completion consumes `stableBackportFrozenValidation`, reproduces the time-bound checks at the
authorization issue time, requires byte-for-byte equality with the reconstructed authorized
validation, and then verifies the receipt against those frozen bytes.

Each merge record also binds `refs/heads/main` or `refs/heads/develop` and the exact protected
branch tip. The protected workflow resolves those branches through GitHub, verifies protection,
then fetches those exact API-selected commit identities from the canonical origin before local
object and ancestry checks. This avoids treating the earlier checkout snapshot as proof that a
newly advanced protected tip does not exist. It proves the two-parent merge is on the supplied
tip's first-parent chain. The `main` and `develop` reconciliation commits must be distinct;
reaching one merge only through a side parent does not attest that branch's reconciliation. The
deterministic attestation digest binds repository, protected ref and tip, merge commit, and both
parents. Each recorded merge tree must also equal Git's isolated automatic merge result. A manual
reconciliation result remains an open obligation because the current completion contract has no
separate protected content-review authorization; parent shape and reachability alone cannot prove
that it retained the published fix. The command performs no merge. Strict Git inspection still
rejects that merge as reconciled, but the completion layer catches only this typed content-review
failure after the exact graph, protected tip, parents, and workflow attestation pass. It emits
`reconciliationStatus: content-review-required` and derives a deterministic
`post-release-main-merge`, `post-release-develop-merge`, or
`hotfix-develop-merge-back` obligation. The obligation binds the source train and included fix ids
plus a digest of the exact merge evidence and bounded resolution-path inventory; raw paths are not
stored in the obligation.

Missing or conflicted reconciliation becomes a carried obligation and blocks the next incompatible
train. Completion normally reproduces the queue's exact policy-permitted carried-obligation ids.
The typed manual-resolution case may append only the obligation derived by the verifier. When the
next intake advances the published fixes from `verified` to `released`, it must seed that exact
completion-created obligation row; omission or substitution fails. The resulting queue remains
blocked until new, separately authenticated content-review evidence resolves the obligation. A
malformed graph, forged attestation, wrong branch tip, or other Git failure still produces no
completion artifact. Completion may retain the one inherited hotfix follow-up allowed for a
superseding security hotfix, but it cannot silently clear or substitute an obligation.

## Release notes and history

The maintenance note generator adds a deterministic “Stable 1.0 maintenance train” section. It
contains each public fix id, public classification and component summary, provenance mode, a safe
lineage digest or public commit link, disclosed advisory id when applicable, carried known issues,
compatibility and migration guidance, and the exact train digest.

Before publication verification, notes describe fixes as prepared or authorized, not released.
Superseded or duplicate note rows fail validation. Private issue URLs, private fork names,
embargoed titles, exploit detail, raw patches, credentials, private insert URIs, local paths, and
raw support/app/content data are forbidden.

The successor baseline and history retain the train identity plus unresolved obligations, so the
next queue can prove carry-forward without changing prior records.

## Deterministic artifacts

The authoritative component output is under:

```text
build/release-certification/<release-id>/stable-backport/
```

A successful applicable run emits canonical versions of:

```text
stable-1.0-fix-intake.json
stable-1.0-backport-plan.json
stable-1.0-backport-lineage.json
stable-1.0-release-train-queue.json
stable-1.0-release-train-queue-public.json
stable-1.0-release-train-candidate.json
stable-1.0-release-train-validation.json
stable-1.0-release-train-validation-public.json
stable-1.0-release-train-authorization-summary.json
stable-1.0-release-train-completion.json
stable-1.0-release-train-summary.json
stable-1.0-release-train-report.md
stable-1.0-release-train-checksums.txt
stable-1.0-release-train-provenance.json
redaction-report.json
summary.json
```

`stable-1.0-release-train-completion.json` exists only in completion mode. A failed run does not
emit placeholder success records. JSON is canonical and schema-validated; Markdown is derived and
public-safe, while JSON remains authoritative.

`stable-1.0-release-train-queue.json` is the authoritative protected queue. The Actions
public-safe artifact uploads only `stable-1.0-release-train-queue-public.json`. That projection
retains the queue digest, opaque fix and obligation ids, public summaries, classifications, state
indexes, and status. It excludes exact source/candidate lineage fields, touched and conflict
paths, protected evidence ids/digests, private-record digests, and embargoed implementation
details.

The authoritative validation is likewise protected because its evidence results include exact
protected evidence ids and digests. The public Actions artifact contains only
`stable-1.0-release-train-validation-public.json`. That schema-validated projection retains the
public fix, decision, candidate, queue, and authorization-summary bindings and binds the exact
authoritative validation/file digests, but filters every evidence result whose intake visibility
is `protected`. The full queue, full validation, full train authorization, completion record,
predecessor-completion handoff, and internal checksums/provenance remain only in the separately
checksummed protected handoff. That authoritative handoff is never uploaded to Actions in
plaintext.

## Protected workflow

`.github/workflows/stable-1.0-backport-release-train.yml` exposes four closed, side-effect-free
manual-dispatch operations:

- `evaluate-intake`;
- `prepare-candidate`;
- `validate-authorization`;
- `verify-release-completion`.

The workflow does not expose `workflow_call`; a reusable caller would make the top-level Actions
run and `github` context identify the caller rather than this security-sensitive producer. Before
either evidence or authorization environment is requested, a credential-free job with no checkout,
token permission, or protected secret requires a manual dispatch, `github.ref_protected`, the exact
workflow path/ref/SHA, the selected source commit, and the operation-specific `main`, `develop`,
`release/<build>`, or `hotfix/<build>` ref. The environment-bearing job depends on that preflight
and repeats the identity checks after its exact checkout. Configure both environments with
deployment-branch restrictions as an independent second gate: the evidence environment permits
only protected `main`, `develop`, `release/*`, and `hotfix/*` refs, while the authorization
environment permits only protected `release/*` and `hotfix/*` refs.

The workflow binds the exact protected source ref, checkout commit, operation, release/build/lane,
reviewed input-bundle digest, workflow identity, run id, and output digests. Its default token and
preflight job have no permissions; the validation job receives only `actions: read` and
`contents: read`. Authorization uses the protected train-authorization environment.

Every phase after `evaluate-intake` resolves the declared prior Actions run, proves the workflow,
source commit, operation, successful conclusion, artifact name, and Actions digest, downloads its
authenticated encrypted envelope, binds that envelope to the exact run attempt and phase
identity, and decrypts it only inside the next protected environment. The envelope uses
AES-256-CTR with a fresh salt, PBKDF2-HMAC-SHA-256, and an independent HMAC-SHA-256 over the exact
binding plus ciphertext. Wrong keys, changed context, substituted ciphertext, links, unsafe
archive members, or unexpected files fail before protected records are materialized.

Configure the same canonical base64 encoding of one 32-byte handoff key as
`CRYPTAD_STABLE_BACKPORT_HANDOFF_KEY_BASE64` in
`stable-1.0-backport-review`, `stable-1.0-backport-evidence`,
`stable-1.0-backport-authorization`, `stable-1.0-maintenance-evidence`,
`stable-1.0-maintenance-publication`, and
`stable-1.0-security-hotfix-publication`. Do not put that key in repository variables, workflow
inputs, logs, job summaries, or artifacts. Maintenance must reseal the exact train validation and
authorization before each phase or publication-audit upload and remove any plaintext duplicate
from staged protected inputs. Rotate the key only after all still-required encrypted phase
artifacts have either been consumed or retained in the separately access-controlled,
digest-pinned support-lifetime archive.

The durable public-safe artifact is separate from the encrypted protected phase envelope. It
contains exactly the public queue and public validation projections, never ciphertext metadata
masquerading as a public train record and never the authoritative queue or validation. Completion
copies the exact prior authorized validation into the protected manifest as
`stableBackportFrozenValidation`; it does not reconstruct that file outside the authorization
environment.

`prepare-candidate` permits the release or hotfix candidate commit to advance after the
pre-landing evaluation, but it does not permit the evaluated work to be replaced. The public queue
projection carries an `intakeCompositionDigest` that commits the exact protected immutable fix and
obligation composition without disclosing it, plus opaque per-fix transition digests. The
protected handoff requires the same composition digest and exact fix/obligation identities, and
requires every evaluated transition list to remain a prefix of the prepared list. A changed
classification, route, affected scope, source identity, security scope, target train, terminal
replacement, new/removed fix, rewritten transition, obligation source train, obligation source-fix
set, or new/removed obligation therefore requires a fresh `evaluate-intake` run.

At the first phase of every successor train, retain the exact prior completion, validation, queue,
publication receipt, and lifecycle authority in the support-lifetime protected input archive. If
the prior `verify-release-completion` Actions artifact is still available, provide its exact run
and artifact coordinates; the workflow byte-compares that artifact with the archived records.
After Actions retention expires, omit those optional coordinates. The current protected
`evaluate-intake` workflow instead authenticates the digest-pinned input bundle, revalidates the
archived records, resolves current protected `main` and `develop`, and proves both completion
merges remain on those first-parent chains. Both paths create
`previousStableBackportCompletionHandoff`, and later phases copy that exact checksummed handoff.
An expired Actions artifact therefore cannot strand the publication chain, while a locally
fabricated merge-tip digest or an unverified protected bundle still cannot move a fix to
`released`.

When a successor intake omits an already `released`, `rejected`, or `superseded` row, queue
construction deep-copies that terminal history and deterministically rebinds only its evidence
queue-binding slots to the successor queue digest. The authenticated predecessor object remains
unchanged. Active or explicitly supplied rows with the wrong queue binding still fail closed.

The maintenance handoff normally requires a `ready` queue. Its only accepted `blocked` queue is a
successful `security-hotfix` validation carrying exactly one open `hotfix-follow-up`; the carried
id and matching obligation row must be the sole open obligation. This mirrors the train engine's
authenticated immediately-prior-queue check and never admits a new, second, wrong-type, routine,
or reconciliation obligation.

The workflow does not create a branch, cherry-pick, merge, push, tag, open a pull request, publish a
release, mutate a catalog, insert update data, or activate a lifecycle state. It uploads only an
authenticated encrypted envelope for the next protected consumer and a distinct allowlisted
public-safe projection after redaction passes. The Actions service never receives the
authoritative queue, full validation, authorization, completion, or private review evidence in
plaintext.

## Manual and protected operations

Release managers still perform or explicitly authorize:

- selecting and reviewing the fix and its disposition;
- creating the release or hotfix branch;
- performing a clean cherry-pick or reviewed conflict resolution;
- producing candidate-bound tests and protected security evidence;
- the four protected Stable maintenance phases and separate lifecycle publication;
- no-squash, `--no-ff` merges into `main` and `develop`;
- branch and tag pushes, GitHub Release publication, catalog publication, CoreUpdater insertion,
  and public announcements.

For GitHub operations, use the `leumor` identity explicitly. The certification command and
backport workflow remain validators; they do not exercise those authorities.

## Local validation

Run the focused, network-independent suites:

```bash
python3 tools/release-certification/certify.py stable-backport --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py stable-lifecycle --self-test
```

The tests use isolated temporary Git repositories with deterministic author, committer, and
timestamp configuration. They do not depend on the developer checkout, global Git identity, a
network remote, or publication credentials.

Continue with the [Stable maintenance and security-hotfix
runbook](stable-1.0-maintenance-release-and-hotfix-path.md) only after the train authorization
matches the exact candidate. Publish lifecycle state separately through the [support lifecycle and
deprecation runbook](stable-1.0-support-lifecycle-and-deprecation-governance.md).

## Vulnerability case and release-train ownership

[Stable 1.0 vulnerability intake and coordinated-disclosure
operations](stable-1.0-vulnerability-intake-and-coordinated-disclosure-operations.md) owns the
private case, reporter coordination, embargo, disclosure authorization, public observation, and
closure. This release-train process continues to own fix classification, disposition,
source-to-candidate provenance, candidate coverage, train authorization, publication completion,
and merge-back reconciliation.

An accepted case authenticates an exact PR-287 `security-fix`: `incidentOpaqueId`, optional
`advisoryOpaqueId`, severity, disclosure state, `privateRecordDigest`,
the legacy PR-287 `publicProjectionDigest`, the separate
`vulnerabilityPublicProjectionDigest`, `fixId`, lane, train, source and candidate commits,
provenance, and candidate-test evidence must agree. A branch, issue, pull request, commit
message, shortened SHA, or external advisory id is not evidence.

`stableVulnerabilitySummary` is a bounded, authenticated protected release input. Its ledger-wide
case, severity, exposure, deadline, obligation, and blocker rows are never public disclosure artifacts. A
critical or unrelated overdue high/critical case blocks a routine train. An overdue high case may
proceed only when the routine train's accepted PR-288 fix set contains every blocking case with the
exact authenticated severity and public-projection digest. Critical cases remain on the existing
security-hotfix lane. A one-incident hotfix may proceed when its PR-287 public fix scope contains
exactly one authenticated critical blocking incident, even when other cases remain blocking. The
other blockers stay active and still block routine promotion or an unrelated hotfix; they do not
force unrelated incident scopes into one train. Hotfix follow-up remains a
PR-287/maintenance obligation and must close, or use an explicitly allowed successor, before
vulnerability closure.
When vulnerability governance is required or a PR-288-bound fix is present, the summary must be
materialized from an authenticated producer handoff in a single-link, flat external directory and
that directory must be supplied through
`CRYPTAD_STABLE_VULNERABILITY_SUMMARY_ROOT`. A self-digest or checkout-local summary is not
producer authentication. The consumer requires the fixed-name summary, successor binding,
materialization provenance, and original two-file `sealed-successor/` envelope, then reopens the
envelope with `CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64` and byte-compares the summary.
Promotion accepts only an `evaluate-promotion` summary with null case-specific subject fields and
an exact `ledger-wide` successor binding. An authenticated case-transition result is not promotion
evidence.
The validation job holds the vulnerability-ledger concurrency lock while it freshly authenticates
the durable `STABLE_1_0_VULNERABILITY_LEDGER_TIP_ANCHOR`. The anchor's exact ledger digest and
edition must equal the supplied promotion handoff and its provenance; the selected retained
artifact still authenticates the exact promotion bytes and producer attempt. Missing, deleted,
malformed, or wrong-policy anchor state and any later activated successor are non-waivable
failures. Actions retention cannot restore genesis, and timestamp freshness does not make a
superseded summary current. Completion replay does not reapply this current promotion decision
after publication.
Protected input artifacts carry the encrypted envelope, binding, and provenance—not a plaintext
ledger-wide summary; plaintext exists only in the confined temporary consumer root.
Configure the same canonical base64 32-byte
`CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64` secret on the vulnerability producer
environments and `stable-1.0-backport-evidence`; absence or mismatch is a hard stop.

## Isolated operations rehearsal

The [maintenance operations drill](stable-maintenance-operations-drill.md) executes bounded local
failure/retry checks against existing maintenance logic. Its synthetic authorities and local
integrity summary cannot satisfy this runbook's production prerequisites, authorization,
publication, reconciliation or follow-up requirements. The drill keeps missing adapters distinct
from missing original artifacts and approved infrastructure.
