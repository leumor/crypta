# Trust statement and local score contract review

The `crypta.trust.statement.v1` disposition is **retain-experimental**. The separate
`trust.score` version `1` service remains an experimental local app-service. This review
changes neither `/api/v1`, contract 24, baseline 1.0, grants, nor profile registry status.

## Wire contract and local policy gap matrix

| Subject | Production authority and behavior | Evidence and remaining limit | Decision |
| --- | --- | --- | --- |
| Trust statement | `TrustStatementParser`, `TrustStatementCanonicalizer`, `TrustStatementVerifier`, AppVault signing, `TrustGraphApiHandler`, stores and scorer | Fixed public vectors exercise Node primitive generation and Java receive/scoring; existing tests cover direct/URI import budgets, preview, lifecycle, and coordinator grant drift. First-party code is not external implementation evidence. | Retain experimental; preserve normalized historical semantics; reject malformed surrogate input explicitly. |
| Local `trust.score` v1 | `TrustGraphScoreAppServiceAdapter` behind `AppServiceCoordinator`; provider `trust-graph`, consumer `social-inbox`, adapter `trust-graph.score`, scope `score.read`; advertised contexts `message-author,profile` | Empty evidence and anchored zero have distinct status/counts. Grant status listing distinguishes expiry/revocation; invocation intentionally uses a common grant-required denial. Browser annotation failures distinguish provider, request and refreshed grant state; the harness executes the actual annotation controller, rejected invocation, rediscovery and renderer through synthetic local ports. | Retain experimental; no new service response version or permissions. |

## Exact trust serialization

The root field order is `type,payload,signature`. Payload order is
`issuer,subject,context,score,confidence,reason?,tags?,issuedAt,expiresAt?`.
Issuer order is `identityId,publicKeyFingerprint,publicKeyBase64?,profileUri?`;
subject order is `kind,uri,fingerprint?`; signature order is `algorithm,domain,value`.
The signed bytes are UTF-8 `crypta.trust.statement.v1\n` followed by compact payload JSON.
The writer preserves those orders; it is not RFC 8785 JCS.

The legacy algorithm label is `app-vault-ed25519-preview`. Verification uses the Java Ed25519
provider, standard Base64 signature bytes and X.509 SubjectPublicKeyInfo public-key bytes.
The fingerprint is lowercase SHA-256 hex of the decoded public-key encoding, with no prefix.
Java's basic Base64 decoder accepts omitted terminal padding; canonical producers emit padding.
Missing keys or malformed signatures remain unverified evidence after valid shape parsing.
They cannot contribute even when an attacker supplies a locally anchored fingerprint.

Unknown fields and duplicate keys, including nested duplicates, fail. Object/array nesting
is limited to 64 and input to 65,536 UTF-8 bytes. Integral JSON values must fit Java `long`,
then signed score/confidence must fit `int` and their field bounds; fractions/exponents fail.
Scores span -100 through 100; confidence spans 0 through 100. These fit JavaScript's safe range.
Text bounds use UTF-16 code units after trimming: identity 192, fingerprint 128, public key
4096, issuer profile URI 1024, subject URI 1024, subject fingerprint 128, context 64, reason
280, tags 16 entries of 32 units, signature algorithm/domain 96 and value 4096.
Contexts are `general,profile,feed-source,app-review,message-author`; subject kind parsing
and query matching are owned by the trust model. Subject references are not fetch permission.

Historical received documents are parsed into normalizing records: required strings trim;
optional missing/null/blank strings become absent; missing/null/empty tags become absent;
nonempty tags trim while preserving order and duplicates. Controls are rejected. Unicode
normalization is not applied: combining sequences remain distinct. Instants accept the
`Instant.parse` lexical forms, including offsets and fractional precision, then serialize with
`Instant.toString`; expiry must exceed issue time. The added alias regression deliberately
records that surrounding reason spaces or an equivalent timestamp offset still verify.
Thus this v1 verifies a normalized typed payload, **not the original received JSON bytes**.
Changing that legitimate historical behavior requires a separately reviewed version decision;
request normalization must not be mistaken for a guarantee about raw received lexical bytes.

Unpaired UTF-16 surrogates are now rejected both by parsed-string validation and model text
validation before signing. Previously UTF-8 encoding could replace them with `?`, causing
distinct malformed strings to share signed bytes. This is a malformed-input security hardening,
not a new canonicalization rule for valid Unicode. Valid BMP, astral pairs and combining
sequences remain valid. A String parser alone does not establish rejection of malformed raw
UTF-8 in every transport; transport coverage remains separately required.

## Admission, scoring and privacy

At the injected clock, `expiresAt <= now` is expired. No future-issued-at contribution gate
exists. The scorer matches the query subject/context and contributes only verified signatures
from active local anchors, positive confidence, unexpired statements and active local lifecycle.
Local revocation/deprecation remove contributions without destroying explanation evidence.
Exact document duplicates are idempotent; distinct signed statements from the same issuer all
count. There is no one-issuer-one-vote or latest-statement-wins promise. Contradictory positive
and negative contributions produce `mixed`, with a confidence-weighted rounded score. This
statement weighting is a concrete maturity limit, not global reputation or full Web of Trust.
Only 25 explanation rows are returned, while totals include all retained matching statements.

An empty graph returns `status=unknown,score=0,contributingEvidenceCount=0`; an anchored,
verified zero statement returns `status=mixed,score=0,contributingEvidenceCount=1`. Provider
unavailability, malformed input and grant denials are errors, not manufactured zero results.
Invoke-time coordinator checks include current consumer permission, provider installation,
descriptor scopes/contexts, effective expiry/revocation and approval descriptor/version drift.
Expired/revoked grants are separately visible in grant state; their invocation error may share
`app_service_grant_required`. Social Inbox retains valid messages on optional annotation failure.
After refreshing service state, its error categorizer distinguishes provider unavailability,
malformed requests, stale grants and current revoked/expired/pending grants; other failures remain
invocation failures. The behavioral harness executes the actual `refreshTrustAnnotations`
controller for provider-unavailable, revoked-grant, expired-grant and malformed-request failures.
It checks rejected service calls, grant rediscovery, unchanged message state, and the actual DOM
renderer retaining the valid body alongside the distinct failure summary. Synthetic service ports
and a Node DOM harness do not establish a real browser/daemon operational run. Deliberate user
filters remain separate from annotation availability.

The response keys remain `subjectKind,subjectUriHash,context,status,score,confidence,
evidenceCount,contributingEvidenceCount,completeWot`. `completeWot` is false. `subjectUriHash`
is an unsalted `sha256:` hash of the input URI, useful for local correlation and **not anonymity**.
Do not export it, subjects, anchors, statement inventories, graph state, or subscriptions into
public evidence. The bounded public review describes case IDs and aggregate test counts only;
no global redactor exemption follows from synthetic corpus resources.

## Corpus and closure boundary

The shared corpus is `platform-api/src/test/resources/content-profile-conformance/v1`.
Trust vectors use the publicly known RFC 8032 test 1 seed solely as a synthetic content identity.
Expected JSON was constructed once using independent ordered JavaScript object literals,
Node JSON serialization and Node `crypto` Ed25519, then stored as literal bytes. Tests must not
regenerate those expectations. The three trust cases cover zero, Unicode/ordered duplicate tags,
and exact expiry, with fixed clock `2026-09-06T00:00:00Z`. They are current public synthetic
conformance vectors, not historical published documents or independent reviewer approval.

PR-299 receives this local score/identity limit, not a mail protocol: signatures provide no
recipient confidentiality, authenticated completeness, anti-replay service or moderation power.
Mail must review those separately. Future changes to raw-byte signature semantics or issuer
aggregation require explicit compatibility and version review. PR-296 protected projection and
PR-297 protected migration producer remain missing prerequisites; this review supplies neither.
Producer/runtime work may coordinate with PR-300/301, and PR-303 must verify closure or explicitly
retain Phase 12 as incomplete.
