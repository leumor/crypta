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
launcher accepts the endpoint and process credential only from AppHost. Keys remain in AppVault;
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

## Backup, rollback and key loss

Explicit export returns a deterministic private data backup for the bounded encrypted state. It
remains sensitive and must never enter support bundles or public issues. Restore targets the same
compatible installation with the required retained vault identities and grants. A data backup does
not contain private keys. Missing keys report key-unavailable; creating new keys cannot recover old
ciphertexts, drafts or sent copies.

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
