# Trust and social v1 wire contract audit

The registry in `ContentFormatProfileRegistry` remains the authority: profile, trust statement,
social message and social outbox are experimental; Feed Snapshot is stable. This review does not
activate a baseline, change contract 24, or promote a lifecycle. `trust.score` is a separate local
service. The registry snapshot and RC/GA digest definitions remain unchanged.

## Exact signed bytes

JSON writers preserve the following insertion order. A question mark means the builder omits
an absent optional field. Arrays preserve order and duplicate tags. These are profile-specific
serializations, not RFC 8785/JCS. Unicode is not normalized. Ordinary BMP, astral pairs and combining
sequences are preserved; JSON quote/backslash and controls are escaped. Java text limits count
UTF-16 code units, while document limits count UTF-8 bytes.

| Object | Ordered members |
| --- | --- |
| Profile root | schema, profile, identity, signature |
| Profile payload | schema, appId, identityId, displayName, bio?, website?, avatarUri?, contactUri?, tags? |
| Profile identity | identityId, fingerprint, algorithm, publicKeyBase64 |
| Profile signature | scope, purpose, payloadSha256, domainSeparatedPayload, signatureBase64 |
| Trust root | type, payload, signature |
| Trust payload | issuer, subject, context, score, confidence, reason?, tags?, issuedAt, expiresAt? |
| Trust issuer | identityId, publicKeyFingerprint, publicKeyBase64?, profileUri? |
| Trust subject | kind, uri, fingerprint? |
| Trust signature | algorithm, domain, value |
| Social root | type, message, signature |
| Social signed object | type, message |
| Social message | appId, identityId, authorFingerprint, authorLabel?, profileUri?, messageId, createdAt, channel, subject, body, format, replyTo?, recipientFingerprint?, tags? |
| Social signature | algorithm, domain, payloadHash, publicKeyFingerprint, publicKeyBase64, signatureBase64 |

Profile signs UTF-8 `CryptaAppVault:v1:<appId>:<identityId>:profile.publish.v1:<hash>`.
`hash` is lowercase hexadecimal SHA-256 of the canonical profile payload, including its schema,
app and identity claims. The signature scope is `sign.domain-separated`; algorithm is `Ed25519`.
`AppVaultService.useIdentity` adds this colon framing. A reader must reconstruct it from the displayed
payload and compare all envelope claims, rather than trusting `domainSeparatedPayload` alone.

Trust signs UTF-8 `crypta.trust.statement.v1` followed by one LF and canonical payload JSON.
Its historical algorithm label is **`app-vault-ed25519-preview`**, while the JCA primitive is
Ed25519. `TrustStatementVerifier` binds the decoded public key to the issuer fingerprint and
verifies the canonical typed payload. Missing public key is parseable but unverified evidence.

Social signs UTF-8 `crypta.social.message.v1`, LF, and canonical `{type,message}` JSON. Its
`payloadHash` hashes that entire preimage. Its message ID is `msg-` plus lowercase SHA-256 hex
of the message object with `messageId` omitted, before adding the type wrapper or domain. The
server emits even an empty subject. A subject's omission on receive must not be confused with
an empty subject's signed bytes. `recipientFingerprint` is public metadata, not encryption.

For all three, fingerprints hash the complete DER X.509 SubjectPublicKeyInfo bytes, not the raw
32-byte public key. Generation uses the standard Base64 alphabet with padding; Java's decoder
also accepts omitted final padding. Signatures are the standard 64-byte Ed25519 signature, encoded
as Base64. Content identities are separate from release/catalog/reviewer governance keys.

## Generation bounds and receive gaps

All registry document caps are 65536 bytes. Signed payload caps are 32768 bytes; profile counts
payload JSON, social counts its domain-framed object, and trust uses its canonical signing payload.
Envelope overhead is separate. These caps do not imply every byte length is constructible given
field limits. Test document bounds separately from reachable generator field bounds.

Profile generation requires displayName (80 units); bio (512) permits LF/CR; website, avatarUri
and contactUri are bounded text (512 each), not fetch grants. Tags allow 16 entries of 32 units.
Request normalization trims names and optional text, drops blank optionals, and preserves tag
order/duplicates. These request transformations are not permission to transform received signed
fields. Unknown request parameters fail before signing.

Social generation allows authorLabel 80, profileUri/replyTo 512, channel 64, subject 160, body
4096, recipientFingerprint 128, and 12 tags of 32. Body preserves whitespace, including LF/CR/tab;
other controls fail. Optional fields trim before signing. Server `Instant.toString()` emits UTC
with zero, three, six or nine fractional digits. The route does not accept a caller timestamp.
Social Inbox's own-app admission rule is narrower than format validity for other app IDs.

Trust allows identityId 192, fingerprint 128, inline public key 4096, issuer profileUri and subject
URI 1024, context 64 from the fixed five-context set, reason 280 and 16 tags of 32. Score is
-100..100 and confidence 0..100. JSON integer syntax excludes fractions and exponent forms, and
parsing first bounds numbers to signed 64-bit, then signed 32-bit, then semantic ranges. Expiry
must be after issuedAt; at expiry exactly the statement no longer contributes. Signature validity
alone does not establish local anchor policy, revocation status, conflict resolution or admission.

The initial trust receive implementation normalized typed fields: trim of text, null/blank optional
omission, and `Instant.parse` then `Instant.toString`. Consequently lexical timestamp alternatives
such as offsets and redundant fractional zeros can reconstruct the same signature preimage. This
historical behavior must be recorded separately from builder canonical output; changing it requires
an explicit compatibility decision. The initial JSON implementation also accepted lone surrogates
and used Java `Character.digit` for Unicode escapes. Replacing malformed Unicode with UTF-8 fallback
bytes can collapse distinct inputs. This review rejects unpaired surrogates before profile/social request signing and in the trust
parser/validator. This is malformed-input hardening: valid surrogate pairs, combining sequences and
canonical valid document bytes are preserved. It does not justify rewriting legitimate v1 bytes.

## Public corpus and evidence limits

The versioned corpus lives at
`platform-api/src/test/resources/content-profile-conformance/v1/manifest.json`. Profile/social
expected bytes were independently assembled in insertion order with Python 3 standard-library
JSON and hashed with SHA-256. OpenSSL signed their fixed preimages using the public RFC 8032
section 7.1 test-1 seed. The trust vectors independently assemble fields and sign with Node crypto.
Every identity and body is intentionally synthetic and public. The seed is published standard test
material, never production identity material. Goldens are checked in, not regenerated by tests.

`ContentProfileConformanceTest` executes production profile/social requests and signed envelope
builders, compares complete documents and preimages to those independent fixed bytes, signs using
the JDK provider, verifies, and rejects a one-byte preimage mutation. Additional isolated temporary-vault tests execute `AppVaultService.useIdentity` and
`signDomainSeparatedPayload`, verify their actual generated signatures, and check grant denial.
Parameterized production request tests exercise individual field bounds at limit-1/limit/limit+1,
blank omission, malformed tags and forbidden envelope claims. These are local builder/provider/vault
conformance; they are not a Java receive-side profile/social verifier or operational grant receipt. The actual browser receive path must supply its own execution evidence. Reusing the same
key across these domain-separated test purposes does not imply a prohibition on authorized user
identity reuse.

Goldens created for this review are not historical release artifacts. Existing exact-string
canonicalizer tests remain historical regression witnesses, but without an executable prior reader
there is no claim of a complete cross-release runtime matrix or external independent implementer.
The corpus demonstrates selected cases only; a report must expose missing boundaries and test
families instead of inferring complete profile maturity from its existence.

## Additional lexical and byte-boundary cases

The corpus includes exact 65535, 65536 and 65537 byte Feed documents using ASCII whitespace
padding and multibyte title text. At or below the cap parsing is allowed; above it both SDK and
Feed Reader reject. Whitespace padding contributes to the input cap even though canonical output
omits it. Invalid escape grammar, unescaped controls, excessive depth, malformed JSON numbers,
null item arrays and unknown fields are separate rejection cases.

Feed has no defined numeric field. Vectors with safe-integer and signed-64-bit boundary numbers,
fractions and exponents in an unknown field establish schema rejection, not a fictitious Feed
integer contract. Trust's score/confidence tests own integral numeric semantics.

The existing stable Feed reader treats `updatedAt` as text: offset/precision lexicals and even an
invalid calendar date are retained. The explicit vectors expose that limitation; they do not grant
freshness or validate a source timestamp. Tightening the stable field contract needs reviewed
compatibility treatment. Signed social/trust timestamp semantics remain separate.

Malformed UTF-8 is represented by a raw binary document with `expectedDecodeOutcome=rejected`
and `expectedParseOutcome=not-executed`. The conformance runner uses a fatal UTF-8 decoder for this
boundary. The SDK's public parser accepts strings/objects, so this result is decoder evidence and
must not be presented as production byte-ingress validation. A transport that replaces malformed
bytes before returning a string remains a separate receive-boundary audit item.

The signed corpus additionally includes a minimal profile and profile/social documents with every
optional field present at its production request limit, including maximum tag counts and repeated
ordered tags. `generatorQuery` records their public synthetic request inputs. Java executes those
requests through the production builders and compares the complete signed output to independent
fixed documents. The social maximal reference and recipient strings demonstrate bounded public
metadata; they do not establish a resolvable reply, recipient identity binding, or confidentiality.
