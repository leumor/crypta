# Experimental Mail lifecycle and recovery

Mail contact validity, key material, current app/grant authority and replay-history confidence are
separate state. Contact renewal changes only a signed public validity statement. It does not rotate
keys, restore a revoked grant, authenticate continuity between different accounts or resume a
restored mailbox. Mail remains experimental; local tests are not independent security review or
Stable eligibility.

## Explicit same-key renewal

The own-origin worker channel accepts `preview-renew-contact` with an empty input and
`confirm-renew-contact` with the returned `renewalToken`. Preview returns `status=preview`, the
private one-use token, proposed `expires`, `approvalExpires`, account and signing/recipient
fingerprints, and a warning that counterparts must
explicitly approve the new statement. Confirmation returns `status=renewed` and the new expiry.
These integer timestamps are seconds since the Unix epoch. The token is private transient consent,
not a process credential or exportable authority.

The plan belongs to one mailbox instance in the current worker process. It binds the exact
CAS-loaded encrypted dataset, account/card/key selection, current public identity metadata and
current app-visible grant snapshot. Confirmation consumes it once, rejects a changed snapshot,
clock reversal or a deadline at or beyond thirty seconds, and signs through the existing current
vault authority. Worker restart or app replacement loses the plan. Every ordinary load still
checks current purpose grants; renewal does not make revoked/hidden/expired identity authority
available. An expired contact card can be renewed when its keys and grants remain valid.

The validity statement uses the same account, fingerprints and epochs with a new creation time
and a one-year validity interval, matching existing contact creation policy. A preview in the same
clock second as the current statement returns `renewal-too-soon`; retry after that second rather
than manufacturing a future creation time. Preview does not write data. Confirmation CAS-publishes
the complete existing authenticated schema-1 dataset with its replacement own card and clears old
send approval. Signed network messages and already sealed outbox bytes are never rewritten.

A counterpart imports the new card, compares the fingerprints and explicitly approves it through
the existing contact flow. Approval permits only identical immutable binding fields and strictly
later creation and expiry times. Recipient-key or account changes remain `pin-change-blocked`.
Import alone leaves the original pin installed. Contact revocation tombstones still block use;
approving a renewed card does not remove a tombstone. Any contact update clears old send previews.

## Recovery and rotation prerequisites

Restore remains `paused-after-restore`. There is no renewal shortcut to `normal`, and no new
resume, recipient/storage rotation or signing-account replacement command. Missing implementations
remain implementation work rather than missing operator credentials.

The existing vault stores independent Ed25519 signing, X25519 recipient and X25519 storage keys.
Identity kind, owner and account are authenticated by the private envelope's metadata AAD. Each
kind is capped at three retained identities; current creation/listing checks all retained Mail
identities to prevent hidden or revoked keys from being mistaken for permission to create an empty
replacement. Existing purpose grants are `mail.sign`, `mail.open` and `mail.storage`.

A future reviewed transition must separate historical public writer verification from private
signing authority; explicit historical ciphertext opening must not confer new signing/sealing
rights. Retired keys and compromised/revoked keys need distinct policies. Creation must reconcile
an exact idempotent transition after uncertain responses, and storage rotation must CAS-publish one
complete writer-authenticated dataset with its active selection and transition record. Capacity
exhaustion must deny rather than evict keys or replay tombstones automatically.

Resume needs a closed state machine binding the authenticated backup, current dataset generation,
retained key epochs, current purpose grants, surviving replay/conflict/revocation evidence,
uncertain outbox queue identifiers and sealed bytes. Missing or compromised keys deny recovery.
A fresh one-use current-launch consent cannot by itself prove intact replay history: a complete
snapshot rollback has no independent monotonic authority. A reviewed degraded epoch must either
remain paused or explicitly quarantine/reject historical traffic under a newly confirmed receive
boundary. No elapsed threshold reconstructs lost history or proves exactly-once delivery.

New lifecycle storage requires an explicit migration and a host-enforced minimum-reader policy.
An old bundle must not clear a new recovery generation by restoring an older schema-1 snapshot and
writing through generic app data. App rollback, app-data restore, vault policy and daemon downgrade
are separate operations. Replacing the whole trusted endpoint remains outside this claim. Unsigned
experimental storage continues to be rejected; decrypting and re-signing it is not safe migration.

## Evidence

`MailContactRenewalTest` uses real independent vault/data services and a fake policy clock.
`MailWorkerProcessTest` exercises signed AppHost child processes, independent vaults/stores and
CAS through the fixed broker with simulated transport. Their execution results must be reported
from actual test runs. Neither establishes live network observation, full production browser-origin
integration, complete export canary coverage or independent security approval.

## Original contact intervals and bounded history

Renewal retains up to three exact prior signed own cards, and explicit remote renewal approval
retains up to three exact prior cards for each pinned contact. The encrypted schema-1 dataset adds
`own-card-history.<index>` and `contact-card-history.<fingerprint>.<index>` records. These private
records are not public evidence. Capacity returns `contact-history-capacity`; no card, key or replay
entry is automatically evicted and no deletion/retirement command is implied.

Incoming messages can use an original retained interval only when its signature and every immutable
identity claim match the current selection and its original signed creation/expiry cover the
message. All retained cards in that history are checked for a contiguous bounded sequence and
strictly increasing validity statements. A renewal never extends an old statement's validity or
rewrites sealed messages. Current contact revocations, grants, message expiry and replay admission
still apply. Already accepted local copies retain existing read behavior.

Older schema-1 bundles ignore these additive history fields and conservatively deny some pending
messages that predate the new card. They do not gain a wider historical acceptance interval. This
compatibility behavior is not the host-enforced lifecycle floor required for future rotation or
restore-resume. Raw snapshot rollback limitations remain unchanged.

Renewal rechecks the complete authority snapshot and clock after storage encryption, immediately
before submitting its CAS write. It also validates the exact selected contact through the typed
vault signing operation, which rechecks signing and recipient-purpose grants with the vault's
clock. Raw grant metadata can remain unchanged after expiry, so metadata equality alone is
insufficient. A regression expires a separately granted recipient purpose during encryption and
checks that confirmation leaves the encrypted dataset unchanged. A slow crypto response cannot consume an expired approval and
publish a new dataset. The vault still checks current authority at each actual private operation.
These requests do not hold one cross-service lock over vault metadata and app-data persistence;
the worker-side final check is not an atomic grant-revocation fence for an already submitted CAS.
A later revocation remains effective at the next private operation and does not get restored by
renewal. A response timeout after CAS submission remains uncertain local commit state, requiring
status/reload rather than replaying a consumed approval.

`MailHttpAdmissionTest` separately exercises the production HTTP bridge/router/session store and
real vault at the parsed-request boundary. It checks hostile/mismatched/missing origins, other-app
sessions, expiration, stale launch credentials, private-route denial and unauthorized result
retrieval without consuming the private reply. HTTP request/context and host lifecycle are test
doubles; this is not socket/browser or combined child-process topology evidence. Full audit,
support, queue, diagnostic and failed-collector canary coverage remains incomplete.
