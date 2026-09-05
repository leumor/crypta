# Stable 1.0 protected execution contract reference

Read for Stable 1.0 protected execution contract. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 protected execution contract

For the first protected Stable 1.0 execution, require the versioned non-secret contract in
`stable-1.0-protected-release-execution-v1.schema.json` and run `stable-protected-release` preflight
before workflow dispatch. The contract is an orchestrator around the existing `stable-rc` and
`stable-ga` authorities, not a third release format. It binds exact source, build, producer
run/attempt/artifact digests, exact dispatch-input bytes, RC-generated gate identities,
environments, public targets, and authorization. The RC workflow must consume the exact reviewed
contract, its exact passing preflight receipt, and pass `stable-protected-release --mode
rc-dispatch` against the materialized input map before invoking `stable-rc`; transport locators are
never evidence authentication. Bind the actual runtime app-signing, reviewer, review-policy
ID/version, and catalog-signing labels in that map, and retain the exact RC-consumed preflight
summary as a byte-checked member of the authenticated RC artifact. Keep native third-party intake
as an exact `rcInputs` binding while
the protected run regenerates its production-beta aggregate. Closeout keeps RC
completion, GA validation, GA publication, public observation, and independent reproducibility as
separate facts and must never promote a fixture, self-test, missing receipt, or upload inference to
protected success. Closeout binds the exact freeze record through RC lineage, reconstructs the GA
promotion identity from the canonical validation-authorization identity, and accepts public
observation only from the read-only `stable-1.0-public-observation.yml` authority. Follow
`docs/stable-1.0-protected-release-execution.md`.

For provider-distinct reproducibility, use the closed
`stable-1.0-independent-reproducibility-execution-v1.schema.json` contract and
`stable-independent-reproducibility`. Its `prepare-verifier-kit` output excludes candidate bytes,
candidate product digests, and the primary receipt. Authenticate the external workload identity,
provider/control-plane/trust-domain separation, immutable pipeline, runner image, receipt, and
sealed output bundle by verifying the exact raw attestation bundle and bounded adapter transcript
before making the selected RC artifact available. `compare` delegates product
comparison to the existing Stable supply-chain plan/result authority. Authenticate and download
the bounded primary comparison handoff and its separately attested attempt-scoped subject bundle
only after the external seal, separately from the selected RC;
`closeout` binds those results to PR-291. Never promote a same-GitHub-provider run,
fixture/template profile, self-test, Actions transport upload, or protected coordinator run to
external or public completion. The external app partition must run the kit-bound
`:packageUnsignedFirstPartyAppsForIndependentReproducibility` task without producer signing
material. Compare those unsigned outputs through the closed
`crypta-app-signature-envelope-v1` payload view, which excludes only
`cryptad-app.digests` and `cryptad-app.signature`; continue authenticating the selected RC's signed
ZIPs and signature receipts as release evidence. Never describe the external authority as an app
signer. Follow
`docs/stable-1.0-independent-reproducible-build-verification.md`.

For PR-293, use `stable-catalog-authority` as a side-effect-free wrapper around the existing
authorities. It must bind the exact authenticated PR-291 release root and PR-292 catalog subject,
verify the closed catalog/app/reviewer/recovery keyset and proofs of possession, and reuse the
frozen catalog/signature identity. It must not rebuild, re-sign, publish, fetch live state, or infer
operational completion. Only the protected catalog-authority mutation job may call the existing
live USK publisher after approval and secret materialization; verification and closeout remain
separate and credential-free.
Require staged, active, and retiring routine keys to prove the exact current keyset. Retired and
revoked routine keys must carry a separately labeled, cryptographically verified historical proof
from an earlier keyset; never require them to sign a successor digest, and never let their retained
proof satisfy current-signing eligibility. Offline recovery keys carry no routine proof.
Authenticate the immediately preceding signed transparency artifact for every non-genesis
ceremony, including protected-quorum recovery. Keep key membership append-only and retain every
non-staged catalog/app identity in its runtime role registry, projecting suspected, compromised,
or revoked material to `revoked`, so old IDs and fingerprints cannot be pruned and reassigned.

Every protected catalog-authority operation requires a closed v1 multi-artifact coordinate
aggregate with an exact operation-specific member set. Authenticate every producer
workflow/run/attempt/artifact digest, isolate every download, and flatten only the
fixed canonical evidence members after their individual digests pass. The protected preparation
artifact may retain the exact upstream PR-291, PR-292, subject-inventory, and public-observation
members that preparation already verified; it must not substitute the RC-dispatch PR-291 summary.
Bootstrap the first preparation from the dedicated PR-291 closeout producer, the direct PR-292
closeout summary/inventory, the direct public-observation artifact, and the original attempt-scoped
primary subject bundle from the selected supply-chain producer. Match every subject-bundle member
to the authenticated PR-292 inventory, then verify the exact frozen first-party bundle and review
receipt signatures against the role-specific ceremony public keys; a matching key ID alone is not
a public-key binding. Never accept a catalog-authority reupload as the subject-bundle producer. The
PR-291 bootstrap
contract must leave catalog-authority evidence and coordinates null, and its workflow must call the
existing protected-release closeout engine over exact contract-bound producer bytes; never accept
a prior preparation artifact as the first producer.
Stable GA owns the exact current/rollback sidecar, plan, and receipt handoff. Keep preparation, GA,
network publication, mirror observation, and transition verification as distinct artifacts, and
bind mirror observation to the protected collector's actual bounded execution window. Revalidate
the reviewed observation time after environment/runner admission, require the catalog signer to
remain active and valid through collection completion, reject scheduler refresh timestamps outside
that window, and bound catalog/signature transfers before disk or memory acceptance. Require a
fresh exact primary scheduler refresh and a configured mirror fallback, but do not require a fresh
mirror scheduler attempt after primary success: prove every mirror independently through the
collector's exact catalog-and-signature fetches. Keep
their evidence trees separated; never merge whole producer trees or let a local bundle stand in
for them.
The first mirror-observation receipt must come from the dedicated protected read-only collector,
not from a catalog-authority verification artifact that merely reuploads an input. Likewise, a
protected recovery-quorum receipt must come from its fixed multi-boundary approval producer, with
the approval count derived from completed protected jobs rather than caller JSON. Authenticate the
original root member and canonical producer artifact in every consumer; retained copies are never
bootstrap authorities.

For PR-293 operational drills, require the original closed
`stable-1.0-catalog-drill-receipts.json` bundle from the dedicated protected drill-acceptance
workflow. Bind its exact six receipt rows to PR-291, PR-292, the ceremony, keyset, frozen catalog,
completion instants, and nonempty supporting-evidence digests. A manifest drill `subjectDigest`
must equal the matching semantic receipt digest. Derive rollback signer eligibility from the
authenticated rollback receipt time, never a caller-authored manifest timestamp. Catalog-authority
verification output and retained/reuploaded copies are not original drill authorities.

Reject digest-only local catalog-authority bindings that claim protected operational status in
security-response or maintenance certification. Operational reuse requires an authenticated
protected archive and coordinate; field shape, nonzero digests, and caller-authored classification
flags are not evidence.

Construct and redaction-scan all catalog-authority outputs in memory before the first write. Abort
with no uploadable files on any finding, and require an empty output directory so a failed retry
cannot expose stale passing evidence.

Keep the Crypta USK primary additive to Stable GA's canonical HTTPS observations. Require an
independently operated mirror to return the same exact catalog and detached signature, and reject
aliases, stale or conflicting bytes, sibling mismatch, signer/revision/edition drift, compromised
rollback signers, and partial state presented as success. Fixture or local drill evidence can
prove only fixture verification. Public key bytes belong only in the dedicated transparency
artifact and derived role registries; every other output is fingerprint-only and must exclude
private keys, insert capability, credentials, secret-bearing command lines, and local paths.
After the live publisher starts, capture publisher and verification statuses explicitly, remove
publication secrets before constructing evidence, and retain only bounded results whose generated
and receipt-local redaction checks pass and whose exact digest is bound by the receipt. Atomically
stage only the result, receipt, and redaction report. Run the mutation artifact upload under
`always()` and return the original nonzero status after staging, so post-mutation verification
failure preserves sanitized retry evidence without becoming publication success. Run:

```bash
python3 tools/release-certification/certify.py stable-catalog-authority --self-test
```
