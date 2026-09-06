# Trust and social consumer review

This review records the browser consumers exercised by the public synthetic content corpus and the
remaining limits of their v1 contracts. It accompanies the [format profiles](trust-social-content-format-profiles.md)
and does not change the registry, contract 24, `/api/v1`, or the frozen Platform API 1.0 baseline.

## Executable paths and disposition

| Identity | Existing producer and actual consumer | Executed path | Effective / recommended status | Remaining gap |
| --- | --- | --- | --- | --- |
| `crypta.profile.v1` | AppVault profile builder; Profile Publisher and Social Inbox preparation controllers | Fixed signed document → SDK verifier; actual Profile Publisher controller → verifier | experimental / experimental | No remote profile reader exists in these apps; historical executable readers and a separate external implementation are absent |
| `crypta.feed.snapshot.v1` | Feed Reader `buildPublishedSnapshot`; SDK `feed.parseSnapshot`; Feed Reader `parseCanonicalSnapshot` | Fixed current and legacy alias documents → SDK and app; actual app generator → SDK | stable / stable | SDK retains URI/time text normalization rather than a complete field-level validator; no Java production feed parser exists |
| `crypta.trust.statement.v1` | Java AppVault builder and Trust Graph parser/verifier; SDK calls local import routes | Shared trust vectors → separate first-party Node field assembly and established Node crypto; production Java is tested separately | experimental / experimental | Node reference verifier is test code, not a shipped JavaScript importer or an independent external implementer |
| `crypta.social.message.v1` | AppVault social builder; Social Inbox `ensureSignedSocialMessage` and `verifySocialMessageSignature` | Fixed signed document → actual app verifier; tampered body, hash, fingerprint, signature, message ID rejected | experimental / experimental | Own-app `social-inbox` admission; no current Java receive verifier; wider timestamp and optional-field policy requires review |
| `crypta.social.outbox.v1` | Social Inbox publishing controller and `importOutboxText` | Fixed wrapper → actual import/persistence path; invalid embedded message rejected; replay deduplicated | experimental / experimental | Wrapper membership, ordering, labels, time and completeness remain unauthenticated |
| local `trust.score` version 1 | Trust Graph adapter/coordinator; Social Inbox `normalizeTrustScore` | Real zero with evidence differs from no evidence in the app; Java service grant tests are separate | local experimental service / retain | Error categories preserve provider unavailability, malformed requests and refreshed grant lifecycle; unknown invocation failures remain distinct from no evidence |

The harness executes entire production app scripts in a Node VM with DOM and local storage ports.
It exposes private lexical functions only inside that test VM; it does not substitute parser,
canonicalizer, or verification implementations. The profile response port returns a fixed signed
public vector, and the imported-message storage port is in memory. Those ports test local controller
behavior, not a running daemon, real browser engine, remote network, or operational interoperability.

Run the same manifest through the JavaScript runner with Node already installed:

```bash
node platform-sdk-js/src/test/resources/content-profile-conformance.cjs .
./gradlew :platform-sdk-js:test --tests '*CryptaPlatformSdkResourceTest.contentProfileConformance*'
```

The Java test requires Node and fails if the executable is missing. The standalone runner reports
its actual runtime, manifest digest and executed case IDs; it does not persist a pass receipt.
Trust cases use a separately assembled Node reference preimage and Node's Ed25519 primitive.
Canonical fixture bytes are stored independently and never regenerated during tests.

## Exact receive behavior and security corrections

`profile.verifyDocument` reconstructs payload fields in this order: `schema`, `appId`, `identityId`,
`displayName`, then present `bio`, `website`, `avatarUri`, `contactUri`, `tags`. It preserves string
contents and tag order. The profile root is `schema`, `profile`, `identity`, `signature`; identity
fields are `identityId`, `fingerprint`, `algorithm`, `publicKeyBase64`; signature fields are `scope`,
`purpose`, `payloadSha256`, `domainSeparatedPayload`, `signatureBase64`. Identity and signature
object order does not contribute to the profile payload signature.

The verifier hashes UTF-8 payload JSON using SHA-256, encoded as 64 lowercase hexadecimal digits.
It reconstructs exactly `CryptaAppVault:v1:<appId>:<identityId>:profile.publish.v1:<payloadSha256>`,
compares the supplied preimage and digest, checks payload/root schema and identity binding,
requires `sign.domain-separated` scope and `Ed25519`, recomputes the fingerprint over decoded X.509
SPKI public-key bytes, and verifies Ed25519 using Web Crypto. It never verifies a supplied preimage
in isolation. Both preparation apps call this verifier before displaying a signed profile preview.
It performs no fetch, authorization change, signing, identity creation or publication.

Profile public-key and signature encodings use the standard base64 alphabet and required padding.
Unavailable Web Crypto fails closed. Display labels and URI references still describe untrusted
content. Valid signatures do not prove real-world identity, local trust or permission to fetch.
The new local SDK method is a verification helper; it adds no daemon route or stable-baseline grant.

Feed string input and Social Inbox JSON import reject duplicate members, including escaped-equivalent
names and nested duplicates, unpaired UTF-16 surrogates, and nesting deeper than 16 containers.
Native `JSON.parse` remains the grammar authority. Feed Reader propagates structured-input
failures instead of treating malformed or duplicate-typed JSON as a text feed. It passes the original
text into the SDK size check, including envelope whitespace, so trimming cannot bypass the byte cap. These are rejection-only corrections for ambiguous
or malformed input; existing builders and signed preimages are unchanged. Feed input containing both
`items` and `entries` is rejected; a lone legacy `entries` still normalizes to generated `items`.
These consumer changes must follow the existing candidate/refreeze and maintenance review; frozen
RC/GA profile snapshot bytes are not edited retroactively.

The SDK's existing unsigned feed normalization remains observable: missing source and author become
empty objects, empty textual fields disappear, strings trim, and tags trim, deduplicate and sort.
Schema-disallowed nulls and nonobject source/author are rejected; present scalar text fields require strings. Root normalization order is `type`, `source`, `author`, optional `title`, optional `updatedAt`, `items`.
Source order is `uri`, `resolvedUri`; author order is `name`, `profileUri`; item order is `id`, `title`,
`summary`, `uri`, `publishedAt`, `tags`, omitting empty values. This is a profile-specific normalization
contract, not RFC 8785/JCS. Array item order is preserved. Limits currently enforced by the SDK are
whole-document bytes and item count, plus unknown-field and scalar-type rejection. Unsafe URI strings
and timestamp calendar/offset text remain representation and admission-policy gaps. Feed Reader independently removes
unsafe URI references before rendering. Parsing itself never grants HTTP, file or LAN egress.

Social signed canonicalization preserves raw tag strings when reconstructing the signature and
message-ID payload. It no longer trims a received signed tag into a different authenticated value.
Scalar optional nulls are rejected, and scalar/tag bounds and control checks use the raw value
rather than a trimmed surrogate. Producers still normalize unsigned requests before signing. Social required
payload fields and ordering are unchanged; `subject` is emitted as an empty string when absent by
canonical reconstruction, while absent/empty other optional strings and empty tags are omitted.
A message from another app can be format-valid but is rejected by this consumer's own-app policy.

## Explicit limitations and future closure

The corpus covers representative Unicode, signatures, mismatches, ambiguous JSON and alias behavior.
ASCII and multibyte Feed documents execute at byte limit minus one, at the limit, and above it.
Malformed escapes, depth, disallowed numeric lexical forms, unsupported numeric members, and
retained timestamp text also execute. This is not exhaustive proof of every field boundary or historical version.
Malformed UTF-8 must be rejected at the byte decoding boundary; these app parsers receive JavaScript
strings, so they cannot recover whether upstream decoding already replaced invalid bytes. The harness
uses fatal UTF-8 decoding of corpus files but does not claim that this validates a remote fetch port.
JavaScript Date parsing remains a separate admission-policy limitation for social timestamps.

Social outbox import verifies every message before persistence. Changing unsigned wrapper labels or
time does not invalidate embedded signatures; replay merges existing message IDs. Actual imports
execute envelope sizes of 65,535, 65,536 and 65,537 UTF-8 bytes, including padding and multibyte
message content. Two individually signed messages survive unsigned wrapper reordering, and an
empty subsequent wrapper does not erase already imported messages. An old outbox or
omitted message cannot establish fresh or complete disclosure. Public `recipientFingerprint` is
metadata, never encryption. Adding authenticated aggregate membership requires a new format proposal.

A nonzero evidence count and an eligible trust status can yield an actual score of zero. Absent
local evidence remains unscored. The invocation catch refreshes current grant metadata, then preserves provider unavailability,
invalid-request and stale-grant categories, and current revoked/expired/pending grant summaries.
Unknown errors remain invocation failures rather than no evidence. Optional scoring failure
preserves messages; deliberate local mute and block filters are separate policy. The harness tests
the actual `refreshTrustAnnotations` controller with four rejected service calls, service/grant
rediscovery, unchanged valid message state, and the real DOM renderer retaining the body and
distinct failure badge. The service ports and DOM run in Node; a full browser/daemon failure-path
runtime remains absent. Public certification output must omit subject URI hashes,
queried subjects, anchors, subscription inventories and private imported-message summaries.

PR-300/301 can coordinate missing producer/runtime evidence and full boundary coverage. PR-303 must
verify closure or explicitly retain Phase 12 as incomplete. PR-299 must independently design recipient
confidentiality and binding, replay, metadata exposure, key custody, app-owned state and its threat
model. These signed public documents are not an email protocol or an encrypted mail transport.
