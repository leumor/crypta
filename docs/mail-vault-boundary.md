# Experimental Mail vault boundary

The Mail worker owns contacts, acceptance policy, replay state, drafts and transport scheduling.
The daemon vault is part of the trusted endpoint and holds three independently generated,
non-exportable identities: pure Ed25519 signing, X25519 network recipient, and X25519 local
storage. Private bytes remain wrapped by the existing vault AES-GCM envelope and its metadata AAD.
This does not protect plaintext from a compromised daemon, worker, UI, OS account or endpoint.

Only the installed `mail-prototype` process may request typed Mail private operations. Central
Platform API authorization must check the current live launch, manifest and experimental opt-in
on every call. The vault additionally checks exact owner, immutable key kind, active purpose grant
and uninstall access block. Generic signing grants never authorize Mail signing or decryption.
Mail creation uses a separate typed entry point, not generic browser identity creation. Each kind
is limited to three retained immutable identities; epoch 1 identifies each newly generated key.
Changing a key requires a new contact pin and invalidates previous send approval; key deletion is
an explicit operator operation, not automatic retirement.

Signing accepts only validated fixed contact or message payloads bound to the actual signing
fingerprint. Contact signing additionally proves that its recipient key is owned locally and
currently granted for the same immutable account. Recipient/storage creation requires exactly one
active granted Mail signing account, and authenticates that account in its private-envelope AAD. Network and storage HPKE use separate keys, selectors and fixed purpose domains.
No raw private key, DH output, exporter or symmetric key is returned. Plaintext is returned only
to the authorized process after complete authenticated open and strict inner-message parsing with
exact local recipient fingerprint, account and epoch validation. The worker additionally verifies
the inner signature, pinned sender and contact policy before acceptance or display.

Local storage additionally authenticates the writer. `seal-storage` signs the complete encrypted
state with the account's retained Mail signer in the distinct `crypta.mail.storage-auth.v1` domain,
binding app, account and both key identities/epochs. `open-storage` verifies that signature using
authoritative vault metadata before decrypting. Both current signing and storage grants are required;
the ordinary Mail signing route cannot sign this domain. Public storage metadata alone therefore
cannot create a trusted mailbox dataset. See the exact [storage framing](mail-wire-specification.md#vault-authenticated-local-state).
Earlier unsigned experimental state and backups are rejected without automatic migration, since
decrypting and re-signing them would authenticate attacker-supplied data. Existing private vault
key formats and network Mail envelopes are unchanged. Authenticated snapshots are still subject
to the documented rollback/replay limitations.

Typed operations are bounded synchronous vault work; none calls the worker or transport while
holding the vault lock. Public errors reveal bounded operation codes and no crypto inputs.

Data-only backups contain no vault private identities. Restore needs the same retained identities
and fresh valid grants. Current uninstall deletes app-owned identities even when app data is
preserved: uninstall can make backups, old network ciphertext and drafts permanently unreadable.
Bundle rollback does not restore vault grants, identities or revocations. Later compromise of a
retained recipient key can expose earlier messages: this composition provides no forward secrecy.

Identity creation checks all retained app-owned Mail identity metadata before generating a new key.
If any retained identity has revoked, expired, hidden metadata or missing purpose authority,
creation fails without creating replacement material or restoring grants. An empty app-visible
identity listing is not proof that the vault contains no retained Mail account.

The Mail identity-list API performs the same retained-authority preflight before returning the
ordinary grant-filtered list. A revoked or hidden retained account therefore fails before the
worker writes an initialization marker; later reauthorization cannot turn that failed attempt
into permission to recreate an empty mailbox. Other apps retain their existing list semantics.

## Contact renewal

The experimental contract-26 worker adds `preview-renew-contact` and `confirm-renew-contact`.
A short-lived single-use plan binds the exact current dataset, public identity metadata and grants.
Renewal signs a new same-key statement and requires counterpart approval; it never regrants or
rotates key material. Original signed contact intervals have finite retention with explicit capacity
denial. Restore remains paused. See [Mail lifecycle and recovery](mail-lifecycle-recovery.md) for
state, compatibility limits and the remaining rotation/resume implementation work.
