# Stable 1.0 backport and release-train evidence reference

Read for Stable 1.0 backport and release-train evidence. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 backport and release-train evidence

Before Stable maintenance freezes or authorizes a candidate, run
`python3 tools/release-certification/certify.py stable-backport`. Its closed modes are
`evaluate`, `prepare-candidate`, `validate-authorization`, and
`verify-release-completion`; every mode is side-effect-free.

Treat `tools/release-certification/stable-1.0-backport-release-train-policy.json` as the source of
the classification, disposition, state, provenance, evidence, deadline, role, queue, no-fork, and
redaction contracts. Authenticate only full commit object ids and exact repository/object-graph
relationships. Do not trust branch names, labels, trailers, or patch-id equality as authorization,
and do not fetch arbitrary remotes during evaluation.

The queue is append-only and digest chained. Carry unresolved accepted fixes, deferred/rejected
history, superseding relationships, critical obligations, hotfix follow-up, and branch
reconciliation forward. Account for every candidate change as an accepted fix, approved release
metadata/tooling/docs, explained merge context, or `unaccounted`; `unaccounted` always blocks.
GA is the only queue genesis. Every later published predecessor must authenticate both the prior
queue and prior validation; never accept a missing prior queue as a fresh chain.
Bind every evidence row to the exact reviewed policy and queue digests. Compute the queue identity
by normalizing only embedded evidence queue-binding slots to the fixed all-zero SHA-256 value;
do not omit evidence content or another queue field from that digest. Evidence ids listed as
protected by policy must remain `visibility: protected`.

Cryptad has one authenticated Stable 1.0 publication chain. Historical builds are lifecycle-aware
upgrade, advisory, or recovery coverage sources, never independent mutable release targets.
Routine trains use `release/<build>` and `routine-maintenance`; critical incident trains use
`hotfix/<build>` and `security-hotfix`. Every accepted hotfix row must be a critical
incident-bound `security-fix` under one incident/advisory pair. Record incident-required package,
app, or release-tooling effects inside that security fix’s scope and evidence, never as an unrelated
ordinary row.
An overdue high PR-288 case remains on the routine lane and may proceed only when the accepted train
contains every authenticated blocking case with its exact severity and vulnerability projection
digest. Never use this exact-remediation exception for an unrelated blocker or a critical case.
One incident-scoped security hotfix may carry exactly one authenticated critical blocker even when
other cases also block promotion. Those unrelated blockers remain active and continue to block
routine promotion and unrelated hotfixes; they do not force incompatible incidents into one train.
The protected severity must come from the producer's closed, digest-bound case-summary row; a
consumer-side or PR-287-only severity assertion is insufficient.
Transport PR-290 authoritative phase manifests and inputs, full findings/dispositions,
authorizations, remediations, and ledger history only through the domain-separated authenticated
encrypted Actions envelope. Bind the exact repository, workflow and commit, run and attempt,
operation, subject, artifact name, release/build where applicable, and source commit; open it only
in the next protected environment with the canonical base64 32-byte
`CRYPTAD_STABLE_DEPENDENCY_VULNERABILITY_PHASE_HANDOFF_KEY_BASE64` secret. Preserve the policy's
256 MiB document and 512 MiB phase-root bounds in this transport. Public artifacts may contain
only a redaction-passing public projection, ciphertext, the public-safe publication input, or the
four-file public-safe maintenance promotion handoff; never copy authoritative manifest inputs into
another plaintext artifact.
Never compare-and-swap the PR-290 durable ledger anchor to a producer whose Actions run is still
in progress. Disposition, remediation, and retention workflows upload encrypted proposals only.
A separate protected `workflow_run` finalizer must require GitHub's completed-success conclusion,
reauthenticate the exact run attempt and artifact digest, open the exact bound ciphertext, and make
the anchor CAS its last action. Failed or cancelled producers remain uncommitted alternatives and
must not make the prior durable tip unreadable.
Do not put independent exact-event finalizers directly in the shared concurrency group: GitHub
retains only one pending run and may replace an older pending notification. Route every producer
completion through one shared activation drainer that holds the ledger group across all authority
domains, rediscovers retained completed-success proposals, and dispatches then awaits each
domain-separated protected finalizer sequentially from one job. Do not use a matrix as an ordering
mechanism. Each dispatched finalizer must authenticate the exact still-running drainer run,
attempt, workflow, protected branch, and commit before requesting its environment. Run the drainer
on a bounded schedule as recovery for a replaced pending notification. Replaying the exact current
coordinates, encountering an authenticated same-predecessor alternative, or revisiting a scheduled
source pair after either member was superseded is a whole-proposal no-op; none may rewrite, roll
back, or partially advance durable authority.
When assembling the next protected phase, compare anchor producer coordinates only for artifacts
that can represent the committed tip: disposition authorization, `prepare-remediation`, and
retention. `validate-intelligence`, `match-inventory`, and `evaluate-promotion` are read-only
candidate evidence; authenticate their exact candidate commit and encrypted operation binding,
but do not require their run or artifact coordinates to equal the ledger anchor. This distinction
must preserve intentionally blocked matching evidence so it can advance to disposition review.
Apply the same post-success rule to the retained PR-289 inventory used for mandatory OSV queries.
The OSV retention producer uploads exact bytes plus a closed predecessor/source proposal and has no
anchor-write token. A separate protected `workflow_run` finalizer must require completed-success,
reauthenticate the exact run attempt and Actions artifact digest, validate the proposal and
inventory bytes, and perform the inventory-anchor compare-and-swap as its last action.
Apply that post-success rule to the closed dependency-intelligence source-lineage set. The
source producer must upload a digest-bound source artifact plus a separate closed activation
proposal and must never receive the lineage-write token. Its protected `workflow_run` finalizer
must require the overall matrix run to be completed-success, require both mandatory source pairs
for scheduled runs, reauthenticate every exact source/proposal Actions digest, build every
successor in memory, and only then perform one compare-and-swap of the combined lineage-set
variable. Never loop over independently mutable source variables: a failed second write must not
leave only one mandatory source advanced. A failed or cancelled matrix run must leave the whole
predecessor set authoritative.
While evaluating promotion, hold
the vulnerability-ledger serialization lock and require the supplied `evaluate-promotion` handoff
to match the retention-independent, digest-chained repository Actions-variable anchor's exact
ledger digest and edition. Authenticate the selected promotion run, attempt, and artifact digest
separately. Missing or deleted anchor state never means genesis. Case-transition artifacts become
authoritative only after the separately protected exact-predecessor anchor compare-and-swap;
`evaluate-promotion` remains read-only. Time freshness never makes a superseded summary current,
and a queued ledger append must compare its predecessor to the same durable anchor before running.
Authenticate only the exact selected proposal coordinates. Multiple unactivated successors for
one edition are alternatives, not committed forks; after one activation, stale alternatives must
fail the anchor comparison without blocking later activation or promotion.
Keep PR/nightly aggregate certification separate from protected release-candidate certification.
Only the protected `stable-1-0-release-certification` job receives the vulnerability handoff key
and anchor-read token; a shared step list must condition secret injection on release-candidate mode.
For post-publication certification, an early runner-time comparison is preflight only. Capture
runner UTC again inside the final PR-290 evidence evaluation after other evidence collection has
completed, and use that observation for the exclusive `validUntil` check; never carry a timestamp
captured before the release-certification command through a long collection run.
RC-time vulnerability evidence cannot authorize GA after the mandatory post-freeze interval. The
actual GA publication job must hold the global ledger lock, independently authenticate a newly
selected current ledger-wide promotion handoff, validate its sealed nonblocking summary for the
exact release/build, derive a digest-bound runner-only freshness assertion, re-age that assertion
against runner UTC before every tag, tag-reference, Release, asset-upload, and finalization
mutation, and retain the lock through every mutation. Maintenance publication likewise
holds that lock, reauthenticates its attested promotion binding against the current anchor before
preflight, and reopens and re-ages the exact sealed summary against runner UTC immediately before
the mutation boundary. Any intervening ledger edition or expired summary requires new validation
and authorization. After independent public verification, latest-baseline activation reacquires
the same global lock and repeats both the current-anchor and runner-UTC summary checks immediately
before its pointer compare-and-swap; publication-time authorization cannot cover an intervening
ledger transition or deadline expiry at that final mutation boundary.
Bind the PR-290 companion publication plan to the exact protected release title. Evaluations on
protected `main` target the Stable GA title `Cryptad Stable 1.0 (v<build>)`; evaluations on exact
protected `release/*` or `hotfix/*` refs target `Cryptad v<build>`. Preserve the engine-generated
closed plan, derive that one title from the authenticated evaluation ref, recompute its semantic
digest, and validate it again. The provider may recognize only those two build-derived forms and
must require the observed Release title to equal the single title carried by the plan.
The protected workflow independently freezes the exact protected `main` tip as
`mainLineageCommit` for a hotfix. Require the hotfix base to equal that tip and the tagged
publication predecessor to remain its ancestor; the older tagged candidate is not an adequate
base after the required no-ff `main` reconciliation.
Candidate handoff includes only fixes in `verified` state; `landed` alone is not release
authorization. Check every critical-fix response interval after state re-entry as well as an open
current interval, and reject a critical deferral after its bounded review time. A rejected
critical record remains a blocker, but a new append-only authorized `rejected`-to-`triaged`
transition may reopen its investigation without rewriting history. Superseding a critical record
requires an affected-scope, incident, advisory, and critical-severity equivalent replacement. A
separately authorized
superseding security hotfix may carry exactly one
`hotfix-follow-up`. If maintenance publication created it after the prior train queue was
authorized, the first queue row must bind the authenticated predecessor baseline’s exact
obligation digest, obligated build/train and generation time to the predecessor queue’s critical
source fixes; later queues inherit the row unchanged. Routine trains, unbound or multiple
follow-ups, and branch-reconciliation obligations remain blocked. Preserve the obligation id
through release completion.
The maintenance workflow may therefore consume a `blocked` train queue only when a successful
`security-hotfix` validation carries that one sole open follow-up; every routine, multi-obligation,
new, wrong-type, or reconciliation-blocked queue still fails.

Clean cherry-picks require the policy-defined protected review evidence in addition to matching
patch identity. Manual conflict resolution requires the corresponding protected review plus
focused tests. Authenticate the exact successful
`.github/workflows/stable-1.0-backport-review-authorization.yml` run and Actions artifact in the
`stable-1.0-backport-review` environment, then bind its role, policy, source, predecessor,
candidate, normalized diff, path inventory, focused tests, and validity window. Repeating a
caller-selected digest in provenance, ownership, and evidence is not authorization.

`stable-maintenance` consumes the exact result as the non-waivable
`stable-maintenance.backport-release-train` evidence row and binds the train digest into notes,
checksums, provenance, history, successor governance, and lifecycle context. Release-train
authorization approves composition only and does not replace maintenance publication
authorization.
The maintenance freeze artifact retains the exact train validation and full train authorization;
prepare and validation byte-compare both files with the preceding attested artifact before they
can authorize the frozen candidate.
At the protected publication boundary, require the train authorization to have been current at the
exact maintenance-authorization handoff recorded in that immutable bundle. Do not re-age this
composition-only grant against each later publication target, resumable-prefix retry, or
verify-public-state-only run. Continue to enforce current candidate-evidence deadlines plus the
separate maintenance publication and activation authorizations at their side-effect boundaries.

The maintenance handoff must retain both the exact train validation and the complete canonical
train authorization (stored under the historical authorization-summary filename). Authenticate
the protected backport workflow run and exact Actions artifact digest before materializing those
files; never accept a validation or authorization synthesized only by the maintenance input
producer. Keep the train candidate-file digest distinct from the maintenance candidate semantic
identity digest and compare their shared exact commit/release/predecessor bindings instead.
Before accepting a train, authenticate a fresh public lifecycle observation bound to the exact
descriptor edition and bytes, ledger, plan, update-key scope, and prior lifecycle authorization.
Train authorization must not predate that observation or any intake, state-transition, evidence,
or obligation event it approves.

The backport producer is manual-dispatch only. Do not add `workflow_call` without a separate
caller-run plus referenced-workflow attestation model. A credential-free, no-checkout preflight
must authenticate the manual event, exact workflow ref/SHA, protected source ref, source commit,
lane, and operation before any evidence or authorization environment is requested. Retain
environment deployment-branch restrictions as an independent second gate: evidence may run only
on protected `main`, `develop`, `release/*`, or `hotfix/*` refs, and authorization only on
protected `release/*` or `hotfix/*` refs. Repeat exact identity checks after checkout.

Completion verifies that the published candidate itself is the merged tip in each separate no-ff
merge to `main` and `develop`. Per-fix provenance commits may precede the publication tip but must
be ancestors of it. Read-only completion may occur after the original train handoff authorization
expires because the maintenance receipt freezes the exact validation digest accepted while the
authorization was current. Consume that exact frozen validation, and require authenticated
protected `main`/`develop` tips that contain the attested merge commits. For merge coverage, compare
the recorded tree with Git's automatic merge and use the union of per-parent changed paths when it
differs; combined diff alone can hide a one-parent resolution. The two reconciliation commits must
be distinct and each must be on its protected tip's first-parent chain, not merely reachable
through a side parent.
If that authenticated graph contains non-automatic merge content, keep strict Git inspection
failing it as reconciled, then let the completion layer derive the exact policy-named
reconciliation obligation and mark `reconciliationStatus: content-review-required`. Bind the
obligation evidence to the merge record and a digest of the bounded resolution-path inventory,
without exposing raw paths in the obligation. The next intake may advance the published fixes to
`released` only when it seeds the exact completion-created row; the resulting queue remains
blocked pending separately authenticated content-review evidence. Do not convert another Git,
branch-tip, parent, or attestation failure into an obligation.
Do not allow a fix included by the prior authorized validation to transition directly from
`verified` to `superseded`; authenticate publication and reconciliation and transition it to
`released` first.
For the next train, use the successful prior completion workflow run and exact Actions artifact
while it remains available and byte-compare the protected completion and validation. After Actions
retention expires, reauthenticate the same completion, validation, queue, receipt, and lifecycle
authority from the digest-pinned support-lifetime protected input bundle. Both paths independently
resolve current protected `main` and `develop`, require both recorded merges on those first-parent
chains, and carry the resulting `previousStableBackportCompletionHandoff` through every phase.
Keep the authoritative queue and validation protected. Public phase artifacts may contain only
`stable-1.0-release-train-queue-public.json` and the filtered
`stable-1.0-release-train-validation-public.json`; they must not contain the full validation,
authorization record, completion record, predecessor-completion handoff, or internal
checksums/provenance. Those public projections omit touched/conflict paths, protected evidence
ids/digests, private-record digests, and exact per-fix source/backport internals.
Transport authoritative phase and provenance-review handoffs through authenticated encrypted
Actions envelopes only. Bind each envelope to the exact repository, workflow/commit, run attempt,
operation, subject, and artifact name; decrypt it only inside the next protected environment with
the canonical base64 32-byte `CRYPTAD_STABLE_BACKPORT_HANDOFF_KEY_BASE64` secret. Keep that same
secret in the backport-review, backport-evidence, backport-authorization, and
maintenance-evidence environments, plus both Stable maintenance publication environments that
must independently reopen the frozen train at the side-effect boundary. Never put it in workflow
inputs, repository variables, logs, summaries, or artifacts. Repository-readable Actions
artifacts must never contain those authoritative records in plaintext. Retain support-lifetime
plaintext only in the separately access-controlled digest-pinned input archive.
After maintenance consumes the backport envelope, reseal the exact train validation and full
authorization for every freeze, preparation, validation, publication, and independent-verification
handoff. Strip duplicate plaintext copies from staged protected inputs and publication audits.
Allow a candidate-handoff authorization at most 72 hours so the exact grant can survive the
mandatory 24-hour post-freeze soak and bounded review/handoff time. It remains composition-only
authority and cannot authorize publication.
The public queue's digest-only `intakeCompositionDigest` commits those protected immutable fields.
For `evaluate-intake` to `prepare-candidate`, require that digest and the exact fix/obligation
identity sets to remain unchanged, and require every opaque per-fix transition-digest list to be
an exact prefix of its prepared successor. Bind every obligation's exact `sourceTrainId`,
`sourceFixIds`, type, identity, and generation time inside that commitment. The candidate and
candidate-bound evidence may advance; any composition or history rewrite requires a new
evaluation. After resolving protected completion tips through GitHub, fetch those exact
API-selected commit identities from the canonical origin before local object and ancestry checks.
Treat provenance-review `expiresAt` as exclusive; equality with the captured validation time is
expired.

Use the focused offline check while changing the train engine, schemas, workflow, or docs:

```bash
python3 tools/release-certification/certify.py stable-backport --self-test
```
