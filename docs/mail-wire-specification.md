# Experimental Mail wire specification

This prototype composition is not an independently audited secure-mail protocol. The daemon,
vault, worker, browser and OS form a trusted endpoint. HPKE protects content against remote peers;
it does not hide sizes, timing, selectors or CHK access patterns, authenticate a real person, prevent
replay, or provide forward secrecy against later recipient-key compromise. Local deletion cannot
recall network ciphertext.

The only suite is RFC 9180 base mode, X25519/HKDF-SHA256/AES-128-GCM (32,1,1), implemented by
pinned BC LTS. Ed25519 is pure Ed25519 over application framing, not Ed25519ctx or Ed25519ph.
All public keys are raw 32 bytes; signatures are 64 bytes; Base64 is padded canonical standard
Base64. Fingerprints are lowercase SHA-256 of UTF-8 role followed by LF and the raw public key.
Keys for signing, network recipient and local storage are independently generated.

All wire objects are flat ordered JSON objects containing strings only. Encoding is UTF-8 without
BOM, whitespace or normalization. Quote and backslash use escaped forms; controls use lowercase
four-digit Unicode escapes; other Unicode scalars use their UTF-8 encoding. Lone surrogates,
duplicate/unknown fields, nulls, alternate escapes and noncanonical encodings are rejected by
round-trip byte comparison. Integers are canonical nonnegative decimal strings bounded to signed
64-bit values; epochs are positive. There are no optional fields.

Contact payload order: profile, signingKey, signingFingerprint, account, signingEpoch,
recipientKey, recipientFingerprint, recipientEpoch, created, expires, suite.
Profile is crypta.mail.contact.v1; suite is 32/1/1. Account is a random 32-hex identifier.
The pairing signature preimage is UTF-8 crypta.mail.contact.v1, LF, canonical payload.
Approval requires out-of-band comparison; a self-signature only proves possession.

Message payload order: profile, messageId, sender, senderAccount, senderEpoch, recipient,
recipientAccount, recipientEpoch, created, expires, subject, body, format.
Profile is crypta.mail.message.v1; format is text/plain; messageId is 32 random lowercase hex.
Sender is signing fingerprint; recipient is encryption fingerprint; account and epoch bind the
approved contact. Subject is at most 256 UTF-8 bytes, body 16384; payload at most 32768 bytes.
The message signature preimage is UTF-8 crypta.mail.message.v1, LF, canonical payload.
Signed wrappers contain payload (Base64 canonical payload) then signature (Base64).
Contact validity and message timestamp acceptance, pinning and replay admission belong to the
worker; signature or HPKE success alone never admits mail.

Envelope order: profile, kem, kdf, aead, selector, enc, ciphertext. Header AAD contains the first
five fields in this order. Network profile and info are crypta.mail.envelope.v1; local-storage
profile and info are crypta.mail.storage.v1. Info is exact UTF-8 profile with no LF. Selector is
recipient or storage role-qualified fingerprint and must equal the actual local private key's
public fingerprint. Enc is 32 bytes, ciphertext includes the 16-byte GCM tag. Every seal creates
one fresh sender context. Network envelope limit is 65536 bytes; storage plaintext limit is
131072 bytes with a 196608-byte encoded storage envelope cap. Stored retry bytes are immutable.
No raw DH, exporters or AEAD context is exposed to apps.

Independent known answers are from RFC 9180 Appendix A.1.1 and RFC 8032 section 7.1.
Tests embed the published expected bytes rather than regenerating expectations. These primitive
vectors are distinct from any future independent review of this application composition.

X25519 encodings must represent u strictly below 2^255-19, with no high-bit alias. Contact keys
and encapsulations are checked using BC's agreement rejection with a fixed public validation
scalar, solely to reject low-order/all-zero agreement inputs; that scalar never participates in
message encryption, key generation or secret derivation. Ed25519 uses BC full public-key validation.

The public signed-message fixture under `foundation-crypto-keys/src/test/resources/network/crypta/crypt/mail`
is pinned to SHA-256 `c6cbf1f9cc932ee50df63c75ada1e0edb6ae96b42bab430893feb4a05dad3ba5`.
Its adjacent Python3 reference generator uses Python JSON and OpenSSL 3.5.7 Ed25519, without
production imports. This independently exercises the signing primitive and framing; it is not an
independent external Mail implementation or a golden complete encrypted application envelope.

## Additive registry selection

Mail is the sixth descriptor in current registry-v1 exports, with MIME
`application/vnd.crypta.mail+json` and filename `mail-envelope.json`. Its `signed=false` registry
field describes the absence of an **outer** sender signature; HPKE authenticates the envelope,
and sender authentication requires the encrypted inner signature and approved contact pin.
The descriptor is experimental and separate from the original five-profile review.

Current review and RC candidate-export consumers explicitly select the original five from either
a historical registry-v1 five-profile export or the exact six-profile export with the reviewed
experimental Mail descriptor. They reject unknown schemas, reordered/missing/duplicate subjects,
additional unreviewed subjects and changed Mail lifecycle/metadata. The projected five descriptor
digests and historical freeze subjects remain unchanged. Accepting the additional registry row is
not executed Mail conformance evidence or Stable admission.
