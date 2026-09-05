# Stable 1.0 maintenance releases after GA reference

Read for Stable 1.0 maintenance releases after GA. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 maintenance releases after GA

For a later routine Stable 1.0 release, copy
`tools/release-certification/manifests/stable-1.0-maintenance.example.json`, replace every
placeholder, select `policies.releaseClass=maintenance`, and run:

```bash
cp tools/release-certification/manifests/stable-1.0-backport.example.json \
  build/stable-1.0-backport.json
python3 tools/release-certification/certify.py stable-backport \
  --manifest build/stable-1.0-backport.json

python3 tools/release-certification/certify.py stable-maintenance \
  --manifest build/stable-1.0-maintenance.json
```

The checked-in backport example is the first post-GA train: it points the predecessor fields at
the authenticated GA receipt/baseline and omits the maintenance latest pointer and prior train
queue. For every later successor, add the exact `latestPublishedMaintenancePointer`,
`previousStableBackportQueue`, and `previousStableBackportValidation` inputs before running it.

Use the closed `stable-backport` modes `evaluate`, `prepare-candidate`,
`validate-authorization`, and, after publication and manual merges,
`verify-release-completion`. Routine maintenance maps only to `routine-maintenance` on the exact
`release/<build-number>` candidate. Historical Stable builds remain upgrade/recovery coverage
sources and never receive independent patch branches or pointers.
For every clean cherry-pick or manual conflict, authenticate the exact successful
`stable-1.0-backport-review-authorization.yml` artifact from the protected review environment.
Do not accept repeated caller-selected digests as reviewer approval. Keep the authoritative queue
in protected inputs. The repository-readable public artifact carries only the public queue and
validation projections; any full phase or review handoff uses an authenticated encrypted envelope
and is decrypted only in the next protected environment.

Between `evaluate-intake` and `prepare-candidate`, the candidate commit may advance as the already
evaluated work lands. The fix and obligation identities and their protected immutable composition
must not change: authenticate the public queue's `intakeCompositionDigest` and require each opaque
transition-digest list to evolve by prefix-only append. If classification, routing, affected/source
or security scope, target train, replacement identity, or the fix/obligation set changes, run
`evaluate-intake` again.

The protected initial phase independently resolves the protected `develop` tip and freezes it as
`policies.developmentLineageCommit`. Keep that exact value through later phase manifests:
`candidateBaseCommit` must be the candidate/development-lineage merge base and cannot authorize
itself. It must also be on the frozen `develop` tip's first-parent chain; reachability through a
merged side parent does not prove that the release branch was based on `develop`. A
security-hotfix uses `policies.mainLineageCommit` instead: it is the independently
resolved exact protected `main` tip, `candidateBaseCommit` must equal it, and the authenticated
tagged predecessor must remain its ancestor.

Carry the exact protected backport workflow run, artifact name, and Actions artifact digest in the
maintenance manifest metadata. The maintenance workflow must download that
protected `validate-authorization` handoff and retain both its complete train authorization and
validation. The separately uploaded public artifact may contain only the public queue and filtered
`stable-1.0-release-train-validation-public.json`; it must not contain protected evidence ids or
digests, the full validation/authorization, or the predecessor-completion handoff;
a generic input producer cannot recreate either handoff. The later read-only completion phase may
verify reconciliation after the train-composition authorization expires by consuming the exact
receipt-bound frozen validation. Every backport phase after initial evaluation must likewise
resolve and authenticate its prior Actions artifact, rather than merely copying prior-run labels
into provenance. Candidate handoff requires every included fix to be `verified`, not merely
`landed`. Completion requires distinct `main` and `develop` no-ff merges on the respective
protected tip's first-parent chain. Each recorded merge tree must match Git's isolated automatic
merge result to count as reconciled. After the exact graph and protected attestation pass, a manual
reconciliation result is emitted as `content-review-required` with the deterministic
completion-created obligation; the next queue must seed that exact row and remains blocked until a
separately authenticated content-review contract resolves it.
At the first phase of the next successor, use the prior successful completion run and artifact
while it remains available, or reauthenticate the support-lifetime protected completion bundle
after Actions retention expires. The artifact path byte-compares completion and validation; both
paths independently resolve protected `main`/`develop` and verify the same receipt-bound records
and first-parent merge graph. The resulting predecessor-completion handoff is mandatory for
released-state transitions and remains byte-identical through later phases.

Do not resolve a carried obligation with its existing failure evidence. Resolution needs a new
evidence digest, after which both the digest and resolution timestamp are immutable.

The command is side-effect-free. It authenticates the immutable GA v1 baseline and complete GA
receipt, authenticates the latest published predecessor, freezes one new candidate, enforces
compatibility and evidence gates, and prepares an authorization or closes a hotfix follow-up. The
protected `.github/workflows/stable-1.0-maintenance-release.yml` workflow revalidates current public
state, creates or verifies the annotated tag, publishes exact bytes, and activates a successor v2
baseline only after receipt verification. It never creates or merges `release/<build-number>`.
Publication retries may continue only after an exact matching target prefix; non-prefix partial
state is a conflict. Latest-baseline activation uses a fresh, activation-only authorization issued
inside the protected activation environment and bound to the verified receipt, successor, history,
original authorization digest, and expected pointer. Do not extend or replace the immutable public
publication authorization merely because an activation approval wait crossed its expiry.
The evidence environment must configure exact producer identities in
`CRYPTAD_STABLE_MAINTENANCE_INPUT_SIGNER_WORKFLOW` and
`CRYPTAD_STABLE_MAINTENANCE_WINDOWS_SIGNER_WORKFLOW`. Configure the reviewed publication-backend
source commit, wheel digest, signer workflow, and entry point as repository-level Actions variables
so they are visible to the evidence-scoped independent verifier and both publication environments;
never scope those four immutable identity pins only to a publication environment. Missing producer
authentication or publication infrastructure is a hard stop, not permission to accept a path or
URL as identity.
Use the checked-in protected input and Windows package producer workflow identities. The input
producer retrieves only the exact-digest, public-safe phase ZIP through the evidence environment's
secret locator. It must reject every non-global DNS result, connect only to the validated numeric
addresses, verify the connected peer, and retain the original hostname for TLS SNI and certificate
verification before sending any bearer credential. The Windows producer builds once,
Authenticode-signs and verifies the amd64 EXE, rechecks tracked source state, and attests both the
EXE and its receipt.

Run `.github/workflows/stable-1.0-maintenance-release.yml` through its four closed operations:
`freeze-candidate`, `prepare-authorization`, `validate-authorization`, then `publish`. Only freeze
may build candidate assets. Prepare consumes the exact attested freeze plus post-freeze evidence;
authorization validation consumes the exact prepared bundle plus one exact authorization JSON; and
publish consumes only that authorized bundle. The macOS producer must Developer-ID-sign, notarize,
staple, and verify its DMG before the freeze record is written. Publication jobs authenticate and
install the pinned provider wheel on the clean runner and recheck the remote release/hotfix ref and
authorization before mutation. Never collapse the four operations into one run or accept a
replacement candidate/evidence/authorization input at publication time.
The freeze artifact must retain the exact protected train validation and full train authorization;
prepare and authorization validation compare both files byte for byte with the preceding attested
artifact so the train cannot change after candidate bytes are frozen.
Record the exact producing run id, artifact name, and Actions artifact digest at every handoff.
Freeze additionally requires the protected Windows producer coordinates and exact EXE SHA-256;
publish additionally requires the reviewed publication-backend producer coordinates. A path,
artifact name, run id, or digest by itself is not a complete producer identity.

Configure `LEUMOR_GITHUB_TOKEN` on both maintenance publication environments. The protected
workflow must verify that token's `/user` login is exactly `leumor` and give it, rather than the
job-scoped Actions token, to tag, GitHub Release, and release-asset mutations. Keep the Actions
token read-only and use it only to authenticate workflow artifacts and attestations.

The canonical provider verifies a separately pre-staged artifact base and uses a closed deployment
service for catalog, CoreUpdater, publication verification, and latest-pointer state. Its
`verify-publication` request carries the digest-bound records needed to build the receipt,
successor, and history; do not provision an undocumented service-side candidate copy. Follow
`tools/release-certification/publication-backend/README.md` for the exact protocol and accepted
public-HTTPS endpoint forms.

Follow `docs/stable-1.0-maintenance-release-and-hotfix-path.md`. Preserve manual no-squash,
`--no-ff` merges into `main` and `develop` after the release-manager-approved publication flow.

After a Stable 1.0 maintenance publication and successor-baseline activation are independently
verified, prepare the separate support lifecycle transition from the authenticated history. The
release publication itself does not make a candidate `current-stable` in mutable lifecycle state.
Use the protected lifecycle workflow to authorize, publish, and verify the exact next
`support-lifecycle` descriptor edition; never rewrite the release's historical `core-info.json` or
activate lifecycle state from an unverified/partial release publication. Follow
`docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`.
- [ ] The exact `stable-maintenance.backport-release-train` evidence has no unaccounted changes,
      omitted required fixes, wrong lane/base, stale candidate evidence, or prior merge-back
      blockers.
- [ ] After publication, `stable-backport` completion verification authenticates the exact
      receipt, lifecycle activation or pending state, and no-squash `--no-ff` reconciliation into
      `main` and `develop`.
- [ ] Tag `v<build-number>` created.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tag pushed.
- [ ] Release notes updated (if applicable).
