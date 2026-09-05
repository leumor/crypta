# Stable 1.0 protected execution reference

Read for Stable 1.0 protected execution. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 protected execution

Before the first real Stable RC freeze or any refreeze, complete the side-effect-free
`stable-protected-release --mode preflight` contract on the exact protected `release/<build>`
commit. The RC workflow consumes exact protected PR-288, PR-289, and PR-290 producer coordinates
plus the exact reviewed contract and passing preflight receipt. It runs
`stable-protected-release --mode rc-dispatch` after materializing every external input,
preserves the preflight evaluation time across protected approval instead of treating its
five-minute clock-skew check as a dispatch TTL, rechecks evidence freshness at dispatch,
compares the actual protected runtime signing/reviewer/review-policy/catalog labels with the
reviewed contract, regenerates the policy-selected same-run gates, retains the exact consumed
preflight receipt in the authenticated RC artifact, and invokes
`stable-rc` only after those byte and coordinate bindings pass. `stable-rc` remains the only freeze
authority. GA selects one immutable successful RC attempt,
runs `stable-ga` without rebuilding, obtains separate evidence and publication approvals, and
records publication and public observation separately. Public observation runs only through the
read-only `stable-1.0-public-observation.yml` workflow after publication. A missing protected
receipt is not replaceable by a repository claim. Follow
`docs/stable-1.0-protected-release-execution.md` before continuing the merge/tag workflow.

For PR-293 bootstrap, produce the final `publicly-observed` PR-291 summary with the dedicated
protected-release closeout workflow over exact contract-bound RC, GA, and observation artifacts.
The bootstrap contract must leave its optional catalog-authority coordinate and binding null so
PR-291 can precede PR-293 without a digest cycle. Consume PR-292 summary/inventory and public
observation from their direct protected producers on the first ceremony; a retained preparation
artifact may be used only after it has already authenticated those origins. Never treat a local
digest-only catalog-authority binding as operational security-response or maintenance authority.

Provider-distinct reproducibility is a separate protected closeout input. Do not describe the
existing GitHub Actions producer/verifier runs as independent providers. Prepare the
product-byte-free kit and authenticate an already sealed external receipt with
`stable-independent-reproducibility`, including its raw provider attestation and real adapter
verification transcript; only then may the protected coordinator download the bounded primary
supply-chain comparison handoff, its separately attested attempt-scoped subject bundle, and the
selected RC and reuse the Stable comparison
authority. Fixture/self-test, coordinator execution, authenticated external build, successful
comparison, and public verification are separate states. An approved external provider profile
and real protected receipts are required before closeout can report `independently-reproduced`.
The external app partition must run
`:packageUnsignedFirstPartyAppsForIndependentReproducibility`; never transfer the producer's app
signing key or substitute the signed `packageFirstPartyApps` task. Provider-distinct app comparison
uses the closed `crypta-app-signature-envelope-v1` view, which excludes only
`cryptad-app.digests` and `cryptad-app.signature`. The signed selected-RC bundle and its signature
authority remain authenticated separately.
Follow
`docs/stable-1.0-independent-reproducible-build-verification.md`.

Stable catalog-authority closeout is another separate protected input. Run
`stable-catalog-authority --self-test` locally, but treat that result only as fixture or
implementation verification. A real ceremony, USK publication, independent mirror observation,
rotation, rollback, and transparency publication remain pending until their authentic protected
receipts are verified. PR-293 must reuse the exact PR-291 release root, PR-292 catalog subject,
Stable RC freeze, and Stable GA HTTPS observations; it never authorizes rebuilding or re-signing
the selected catalog. Only its approved publication job receives insert capability, and mirrors
remain transport availability rather than trust authorities.

For every protected PR-293 operation, supply the closed v1 aggregate of exact Actions coordinates
and per-member digests required by that operation. The workflow authenticates each producer and
assembles a fresh allowlisted evidence directory; one catch-all artifact, a legacy single
coordinate, or a locally resealed summary cannot satisfy a protected phase.
Source the first exact mirror receipt from `stable-1.0-catalog-mirror-observation.yml` and any
protected recovery-quorum receipt from `stable-1.0-catalog-recovery-quorum.yml`. Do not use the
catalog-authority verifier's retained or reuploaded copy as the origin coordinate.
