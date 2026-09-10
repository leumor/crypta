# Mail Prototype (experimental)

Mail is a Java worker launched by AppHost with an own-origin static control surface. It implements
one-recipient plain UTF-8 text using manually approved contact pins and explicit CHK-reference
handoff. This is an experimental composition, not an independently audited secure-mail protocol.

## Setup and signed bundle

Use Java 25+ and the repository Gradle wrapper. `:apps:mail-prototype:stageApp` stages the worker JAR,
its runtime dependencies and local UI/SDK assets. `signApp`, `verifyApp` and `packageApp` follow the
same publisher signing inputs as other first-party apps. Use dedicated app-publisher signing
material for bundle governance; it is never mail content-key material. Install through normal
signed-bundle verification and explicitly accept experimental permissions. Mail is beta-only and
must not be automatically selected from Stable.

The host must configure the exact loopback Platform API endpoint before launching Mail. The
launcher accepts the endpoint, process credential and explicit Java executable only from AppHost.
It uses the daemon's Java 25+ runtime, including bundled runtimes, rather than system `PATH` Java.
Keys remain in AppVault;
the app worker owns contacts, state and scheduling. Browser state is transient and no process token
or plaintext is placed in browser persistent storage.

## Manual workflow

1. Initialize or unlock the retained account. Export your public contact card explicitly.
2. Exchange contact cards through a separate channel. Import the other card, compare the full
   displayed fingerprint out of band, and explicitly approve it. Labels never establish identity.
3. Select that fingerprint, compose subject and plain text, and save the encrypted draft. Preview
   the exact recipient, epoch and content, then confirm insertion. Editing the draft or contact
   clears the browser's previous approval.
4. Inspect private status for the encrypted envelope's successful CHK reference. Inserted is not
   delivered or read. Transfer the reference to the recipient through the separate channel.
5. The recipient explicitly approves fetching that reference. Read only an authenticated accepted
   message. Markup-like content is literal text and never creates remote images or automatic links.
6. Reply by composing a separate new message to the approved sender and repeating this process.

Opening UI, importing a contact or displaying a message does not automatically fetch/send/acknowledge.
The generic private result panel shows bounded worker statuses, including unavailable vault,
unknown sender, wrong recipient, expired, rejected, duplicate, quota and network failures. Private
operation identifiers let you retry committed sealed operations after an uncertain insert outcome.
Retry refuses a new enqueue or queue restart once the retained signed message expires, preserving
its sealed bytes; an already successful insertion remains visible even after expiry.
Incoming messages must fit within both the pinned sender card's and the local recipient card's
validity intervals before inbox or replay state is recorded.

Draft admission checks both UTF-8 content and JSON-encoded size before replacing saved state.
The subject/body limits remain 256 bytes and 16 KiB; the composed unsigned message also has a
20 KiB encoded budget to leave room for signed and encrypted outbox copies. Control characters,
quotes and backslashes consume additional encoded space. Oversize input returns `quota` and
preserves the saved draft and approval. Mailbox capacity and contact validity are still checked
when previewing and sending.

First-time initialization writes a fixed, non-sensitive setup marker before creating vault keys.
If setup fails or its response is lost, choose Initialize again: the worker reuses the marked
setup's retained identities and creates only missing roles. The first encrypted mailbox atomically
replaces the marker. No drafts, contacts or key material are stored in the marker, and ordinary
mailbox operations remain unavailable until setup completes. Missing data with retained identities
and no marker still requires recovery. Resumed setup displays and retains a new recovery epoch
and a warning that prior replay history cannot be verified after a raw snapshot rollback; it is
not proof of a fresh account. Older unmarked partial setups cannot be distinguished from
lost mailboxes. Revoked or unavailable key grants block setup instead of creating replacements.

## Backup, rollback and key loss

Explicit export returns a deterministic private data backup for the bounded encrypted state. It
remains sensitive and must never enter support bundles or public issues. Restore targets the same
compatible installation with the required retained vault identities and grants. A data backup does
not contain private keys. Missing keys report key-unavailable; creating new keys cannot recover old
ciphertexts, drafts or sent copies.

Backups require vault-authenticated storage: the complete ciphertext is signed in a separate
storage domain by the account's retained Mail signer before it can be loaded or restored. Both
signing and storage grants must remain valid. Public storage keys cannot create a trusted backup.
Unsigned backups/datasets from earlier experimental builds are rejected as invalid; there is no
automatic migration that can safely distinguish them from forged state. Preserve old files for
separate trusted recovery, and do not downgrade the daemon to a vault implementation without this
check. Such a daemon both reintroduces the vulnerability and cannot read the new authenticated
format. App-bundle rollback continues to use the current daemon vault's checks.

An older backup can contain older replay state. Recovery must preserve current replay tombstones
where available. Restore pauses new sending and receiving; this version has no recovery-resume
operation. Retained messages remain readable. This is not rollback-proof replay prevention.
Bundle rollback independently replaces code and does not revert data, grants or
security revocations. Removing required keys or uninstalling without compatible retention can make
data-only backups unreadable. Default uninstall deletes required vault identities even when app
data is preserved. Network ciphertext cannot be recalled by local deletion or rollback.

## Scope and evidence

No automatic inbox/rendezvous delivery, SMTP/IMAP, Freemail interoperability, attachments, HTML,
multiple recipients, receipts, anonymity or forward secrecy is implemented. Ciphertext size,
timing, selectors and reference access patterns remain observable. Compromised daemon, vault,
worker, browser UI, account or OS remain trusted-endpoint failures outside remote confidentiality.
Later compromise of retained recipient keys can expose historical encrypted messages.

Module tests, separate-process local tests, opt-in actual two-node delivery and independent review
are separate evidence levels. A staged or signed bundle establishes none of those execution claims.
No live network demonstration or independent security review is implied by this README. Use only
public synthetic text and explicitly approved independent node targets for a live demonstration.

## Contact renewal

The experimental contract-26 worker adds `preview-renew-contact` and `confirm-renew-contact`.
A short-lived single-use plan binds the exact current dataset, public identity metadata and grants.
Renewal signs a new same-key statement and requires counterpart approval; it never regrants or
rotates key material. Original signed contact intervals have finite retention with explicit capacity
denial. Restore remains paused. See [Mail lifecycle and recovery](../../docs/mail-lifecycle-recovery.md) for
state, compatibility limits and the remaining rotation/resume implementation work.
