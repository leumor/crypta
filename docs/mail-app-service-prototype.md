# Mail app prototype

Mail is an experimental, manually addressed one-recipient plain-text app. Implementation
and evidence status are recorded separately below; this document is not a security certification.

## Base and reviewed gaps

The work branch starts at `05975676618690069e708100fc96e125215ad5fa`, fetched from `develop`
on 2026-09-07 using the repository's `leumor` identity. This is the PR-298 squash merge (#1399).
Compared with inspected `9f51bbcc2de35655fb5151f7fbc0a4a855d98902`, it retains additional XML
fallback, profile verification snapshot, mock signature and review-policy/output-path fixes.

| Boundary | Audited gap | Design decision |
| --- | --- | --- |
| Crypto | Ed25519 exists; no implemented mail HPKE | Use pinned BC LTS 2.73.12.1 HPKE base X25519/SHA256/AES128GCM; separate mail inner signature |
| Vault | Publisher identity is a placeholder; generic signing grants do not authorize opening | Independent dedicated signing, recipient and storage identities with purpose-scoped operations |
| Worker | Existing app launchers idle; platform adapters do not forward to processes | Real signed Java worker and fixed authenticated poll/reply broker, never stdout IPC |
| Persistence | Atomic CAS is single-record, not a multi-record transaction | One encrypted bounded dataset contains contacts, drafts, outbox, inbox and replay ledger |
| Transport | Existing generated-document and bounded content-fetch paths | Worker fixes insertion to CHK and validates manually imported CHK read references |
| Lifecycle | Uninstall deletes vault identities even with preserved app data | Data-only recovery requires the same retained vault; uninstall warning is mandatory |
| Evidence | Local tests cannot close protected producer or independent-review gaps | Report crypto, process, live network, recovery and independent review separately |

## Threat model and decision

Remote datastore/transport parties can observe size, timing, the visible recipient selector and
CHK access patterns, and can replay, reorder, withhold or corrupt ciphertext. HPKE protects message
contents assuming trusted uncompromised endpoints. The out-of-band channel can disclose its own
metadata. There is no anonymity or forward-secrecy guarantee: later compromise of a retained
recipient private key can expose historical messages. Local expiry or deletion cannot erase
network copies.

A substituted contact can redirect future encryption. A contact's self-signature proves control
of its signing key, not a person's identity. Full fingerprint comparison and explicit local approval
are required. A changed pin invalidates any pending send approval. Contact graphs remain private.

Unrelated apps and origins are denied by current signed manifests, app authentication, purpose
capabilities and vault grants. Browser sessions never receive worker tokens or private keys.
Malformed inputs are bounded before crypto, fully authenticated before parsing plaintext, and never
create replay evidence before signature, pin, recipient and time checks succeed.

The daemon, vault, OS account, worker and own UI are trusted endpoint components. Non-exportable
keys do not protect against compromise of those components. Plaintext exists transiently in the
worker, vault open/sign calls and intentional browser compose/read responses. It must not persist
in ordinary app-data, browser storage, process logs, support exports or public test evidence.

The Java Mail process owns all mailbox decisions and persistence. The daemon owns only vault
cryptography, fixed transient IPC mediation, app-scoped storage and existing network transport.
There is no daemon mailbox engine or generic RPC/proxy. Worker unavailability fails closed.

## Selected limits and recovery

One recipient, UTF-8 `text/plain`, no attachments or HTML. Body limit is 16 KiB, signed inner
payload 32 KiB, network envelope 64 KiB. The combined private dataset has a 112 KiB plaintext cap
and must also fit the 262144-byte app-data record cap after protection. Contacts, records, replay
entries and outstanding operations have positive application caps: 16 contacts, 16 inbox records,
8 outbox operations and 128 replay entries, with four pending worker requests. The byte cap can be
reached first. Intake pauses at quota rather than evicting unexpired replay evidence. Each unfinished
outbox reserves completion metadata space before commit.

Send approval binds exact draft/contact bytes. Sealed bytes and stable operation/queue identifier
commit before insertion. Retry reuses those bytes, including after uncertain enqueue outcomes.
Inserted means network insertion only; it does not mean delivered or read. Acceptance commits
message and authenticated replay identity together. Re-encryption of the same signed message is
a duplicate; conflicting authenticated content under the same identity is rejected.

Private backups contain protected app state, not vault keys, and remain sensitive. Restore merges
available current replay tombstones and contact revocations and enters a recovery state. New sending
and receiving remain paused after restore; this version intentionally has no resume operation.
Retained messages remain readable. An older full operator backup can
revert all local evidence; no independent monotonic authority exists, so replay protection is not
rollback-proof. Missing keys block recovery and must never create a misleading empty account.
Bundle rollback preserves current keys/grants/data. Default uninstall destroys required keys,
even when app data is preserved; data-only backups can consequently become unreadable.

The complete storage ciphertext carries a vault-created Ed25519 signature in a separate storage
domain, bound to the app, account and retained storage/signing identities and epochs. The vault
verifies it before returning plaintext for dataset load or restore. HPKE base-mode encryption alone
cannot prove local provenance: anyone with a storage public key could otherwise forge a dataset,
including inbox entries. Only the current process-only storage operation can produce this proof;
the existing Mail signing route does not accept its domain. Both key-purpose grants are required.
This protects against replacement data from outside the trusted endpoint, not an authorized
compromised worker. See [exact storage framing](mail-wire-specification.md#vault-authenticated-local-state).

Earlier unsigned experimental Mail datasets and backups are rejected as invalid. No automatic
migration is safe because legacy data has no writer proof. Preserve old data for separate trusted
recovery; do not treat it as verified Mail state. The inner schema-1 dataset and retained vault
identity records remain unchanged. App-bundle rollback continues to use the current vault's checks.
Downgrading the daemon to a vault implementation without writer verification reintroduces this
flaw and cannot open the new authenticated storage format.

## Scope and evidence

The external app-service interface remains closed and disabled; consumer proposals are deferred.
The own-app UI/worker path is the selected implementation scope. No automatic inbox delivery,
rendezvous, USK mailbox, email address, SMTP/IMAP, Freemail interoperability, receipts, unattended
sending, ratchet or production security approval is implied.

The Java worker, fixed own-app broker, purpose-scoped vault operations, encrypted CAS dataset,
manual ciphertext insertion/fetch and own-origin control surface are implemented. Platform API
contract 25 adds experimental `mail.control`, `vault.mail.sign`, `vault.mail.open` and
`vault.mail.storage`; baseline 1.0 remains frozen at contract 19. The new queue completion route
is process-only and requires Mail control as well as queue read permission. The six-profile
current export keeps the original five-profile review as an explicit unchanged selection.

Local integration on Java 25.0.4.1 passed all 26 Mail app tests. These include two independently
signed AppHost workers with separate real vaults and durable app-data stores, the production
`MailWorkerBroker`, literal read/reply, signed update/rollback and restart deduplication. Actual
child-process kills after sealed commit and after simulated insertion recover the same operation
and ciphertext. Stop/re-entrant vault/data races reject old tokens and replies without deadlock.
Transport in these tests is deliberately simulated; this is level 2 evidence, not a live-node test.
The SDK's 36 tests and developer tool's 226 tests also passed, including new executable SDK Mail
routing, session, Unicode and size-bound checks. Primitive vector tests use the published RFC
known answers and a separately generated public signed-message fixture; see the
[wire specification](mail-wire-specification.md).

The process-log check rejects private-value canaries and permits only an empty log or the exact
observed Java 25 native-access advisory for the pinned BC JAR. This is narrower than a complete
support-bundle/audit-export canary sweep. HTTP origin policy has existing platform coverage and
Mail principal-denial tests; the local process harness does not simulate a hostile browser origin.
Neither limitation is independent security-review evidence.

`./gradlew spotlessApply build assembleCryptadDist` completed successfully with strict dependency
verification on Java 25. The root suite reported 13719 tests, zero failures and seven skipped
platform/provider/benchmark cases. AppHost separately retained two Windows-only skips. Distribution
assembly and the configured Debian packaging path completed; the configured RPM task was skipped.
Existing non-blocking analyzer findings and below-threshold coverage reports remain visible; build
success is not a claim that every repository analyzer is clean. The new Mail production SpotBugs
report has no findings. Focused doclint covers all 15 new production Java files with no warnings.

The requested `stable-content-profile-review`, `stable-platform-api-1x`,
`stable-legacy-plugin-migration`, `app-platform` and `app-platform-docs` self-tests passed. These
self-tests exercise their tools and fixtures; only the separate executable profile review can
establish the selected original profiles' current local conformance. No new Mail certification
command is introduced: local evidence comes from the executed Java/JavaScript tests, not
caller-written pass receipts. No Stable Mail eligibility is asserted.

Live insertion requires an explicit operator-approved pair of independent disposable nodes and
public synthetic text. The [opt-in demonstration](../tools/mail-prototype/README.md) is provided
but was not executed during implementation. Offline checks cannot report live operations as
observed. PR-296/297 protected producers, PR-298 exact-head CI and historical/independent profile
interoperability remain open in [Phase 12](phase-12-open-items.md).

## PR-300 handoff

Review the composition and deployment boundaries independently before using real private mail.
Observe the exact-target two-node command, including restart and reply, only with explicit operator
authorization. Complete hostile-origin and full support/audit canary integration coverage. Design
retained-key rotation, expiry renewal and a reviewed restore-resume policy separately: this version
uses one active account/key epoch, does not export private keys, and remains paused after restore.
Keep external consumer proposals disabled until a narrow approval interface is implemented and
tested. None of this work activates Stable, baseline 1.1 or the missing protected Phase 12 producers.

## Interrupted first-time setup

The app worker writes the exact fixed `crypta.mail.initialization.v1` marker to the existing
`mail-state/dataset` record before the first vault mutation. The marker contains only its format
identifier, without account identifiers, key material or user data. Until the marker is replaced,
only initialization or explicit retained-key restore can produce usable mailbox state.
Initialization reconciles at most one identity per Mail role, reuses successful creations whose
responses were lost, and CAS-replaces the marker with the encrypted schema-1 mailbox. Normal
schema-1 dataset layout is unchanged. No extra journal remains after completion. Its encrypted
storage wrapper requires the writer authentication described above.
The initial absent-record write relies on the existing single current worker; subsequent writes
use the observed record digest.

Retained identity authority is checked by the vault before new key creation, including identities
hidden from an app by revoked metadata grants. Reconciliation never restores grants or replaces
unavailable keys. Missing data with retained identities and no marker remains recovery-required;
an unmarked partial setup from an older bundle cannot safely be inferred to be a new account.
Complete setup before rolling back to a bundle that does not recognize the marker. App-owned
backup is available only after completion. An operator restoring an older raw app-data snapshot
containing a setup marker is subject to the existing rollback limitation: without an independent
monotonic authority, the worker cannot distinguish that snapshot from actual unfinished setup.
Every resumed setup therefore persists a fresh `initializationRecoveryEpoch` and displays it with
an explicit prior-replay-history warning in initialization/status results. Intake is available in
that visibly flagged epoch; it is not a claim of rollback-proof replay prevention.
