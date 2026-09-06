# Trust and social stable profile review

This review records the executable conformance scope and maturity limits of the five existing
content profiles and the separate local `trust.score` service. Completion of a local test run does
not promote a profile or authenticate a release, runner, reviewer, or remote implementation.

## Source and scope

Work starts from `develop` commit `d50f3de340b0c2decbfd54c83d8387dfd2d27f63`, verified against
GitHub on 2026-09-06. It contains PR-297's Sharesite implementation in squash commit `d5ab0742ba`.
The original inspected predecessor `be4711e449aa7898ed84e6045185a98f8049f4c2` is not an ancestor
under its original identity; the containing implementation is the branch base. Site Publisher 3.1,
baseline 1.0 and contract range 9–24 remain unchanged. No Flog app or format is introduced.

The initial exact-head CI inspection found Java CI `34016299825` and develop push
`34016299264` in progress, and supply-chain run `34016299178` failed with zero job records.
A later inspection found develop push `34016299264` successful while Java CI remained in progress;
the supply-chain failure remained. This is an observation, not a causal diagnosis. Local checks below do not replace CI for the final
implementation. This review does not authorize workflow dispatch, release or live publication.

## Audited gap matrix

Detailed syntax, nested field order, lexical alternatives, limits and verification behavior are in
[wire contracts](trust-social-wire-contracts.md), [consumer review](trust-social-consumer-review.md)
and [local service review](trust-social-local-service-review.md). The registry export from
`crypta-app api content-formats` remains the descriptor authority.

| Subject | Effective / recommended | Producer → consumer | Signed identity and admission | Evidence gaps / resolution |
| --- | --- | --- | --- | --- |
| `crypta.profile.v1`, major 1 | experimental / experimental | `ProfileDocumentRequest`, `SignedProfileDocumentBuilder`, `AppVaultService.useIdentity` → SDK verification and publishing preview | Colon-delimited AppVault frame binds app, identity, purpose and canonical payload hash; SPKI fingerprint recomputed; valid signature is no real-world identity or fetch permission | Retain experimental. Fixed synthetic bytes and actual SDK verification cover selected cases; historical cross-release executables and external implementations absent. |
| `crypta.feed.snapshot.v1`, major 1 | stable / stable | SDK snapshot generation → SDK parser, Feed Reader | Unsigned; preserved `entries` alias, generated `items`; dual aliases rejected as ambiguity | Retain stable. Duplicate/null/Unicode limits are parser hardening; unsigned normalization remains distinct from signing. CHK integrity is separate from source authentication. |
| `crypta.trust.statement.v1`, major 1 | experimental / experimental | Trust canonicalizer / AppVault → parser, verifier, bounded import, local scorer | Newline domain plus typed canonical payload; legacy algorithm label preserved; local anchors, lifecycle, confidence and expiry determine contribution | Retain experimental. Historical typed normalization remains; multiple different statements from one issuer can affect weighting. New raw-lexical guarantees or a changed voting model require explicit version/policy review. |
| `crypta.social.message.v1`, major 1 | experimental / experimental | Java request/builder → actual Social Inbox controller verifier | Newline domain plus `{type,message}`; message ID hashes public fields excluding ID; Social Inbox admits its own app ID | Retain experimental. Format validity and app-specific admission differ. No confidentiality, recipient binding beyond public metadata, global moderation or completeness. |
| `crypta.social.outbox.v1`, major 1 | experimental / experimental | Social Inbox snapshot generator → actual controller import | Unsigned bounded collection of individually signed messages; wrapper labels, time, order and membership unauthenticated | Retain experimental. Signed aggregate freshness/completeness requires a new version/proposal; no guaranteed deletion. |
| `trust.score`, service version 1 | experimental local service / unchanged | `TrustGraphScoreAppServiceAdapter` via `AppServiceCoordinator` → optional Social Inbox annotation | Provider `trust-graph`, consumer `social-inbox`, scope `score.read`, invoke-time grants/context/dependency checks | Separate from content registry. Unknown evidence and genuine zero differ. Expired/revoked grants have distinct lifecycle states but can share invocation denial. Unsalted subject hashes are local correlation, not anonymity. |

No effective status, wire lifecycle enum, app-service version, `/api/v1`, integer contract 24,
frozen Platform API baseline 1.0, catalog trust or permission changes follow from the review.
A stable document does not stabilize its vault/service/publishing routes or activate baseline 1.1.
Experimental opt-in and grants remain required.

## Executable local review

Java 25+, the repository Gradle wrapper and the installed Node runtime are required. No package
installation, remote content fetch or live-node access is a command side effect. Production vault
tests create ephemeral identities only inside isolated test stores; no operational identity is
created or imported.

```bash
python3 tools/release-certification/certify.py stable-content-profile-review --self-test
python3 tools/release-certification/certify.py stable-content-profile-review --mode inspect
python3 tools/release-certification/certify.py stable-content-profile-review --mode review
```

Inspection binds the common public corpus and current source bytes without claiming execution.
Review executes the fixed policy-selected production tests, exports the existing registry through
the actual CLI, and requires every declared JUnit case with no failures, errors or skips. Browser
behavior runs through the Node/DOM harness invoked by JUnit. The manifest and fixed goldens live in
`platform-api/src/test/resources/content-profile-conformance/v1`; expected bytes are independently
constructed public synthetic vectors, never regenerated by tests.

`build/content-profile-review/summary.json` is a bounded public local result. It binds the source
commit plus current source bytes (so dirty work is not mislabeled as the committed executable),
corpus, policy, exported registry and exact test-result bytes. Changes during execution fail.
`evaluationTime` is the policy-fixed review clock; per-vector clocks remain in the manifest.
It is not a wall-clock or remote-runner attestation. Raw assertion/process output stays in local
`*-private.log` files and must not be uploaded.
Only the summary and its declared public metadata belong in normal release reporting.

The existing `app-platform.trust-social-content-format-profiles` collector labels its historical
checks `source-inspection` and separately attaches a currently bound executable review when one
exists. Missing review evidence stays `not-observed`; interrupted or failed review runs retain a bounded
failure marker and block the collector until a successful rerun. Stale or substituted local results fail the
binding check. A digest validates local integrity, not authentication of a remote runner. The
command accepts no caller-authored pass receipt or protected authority. Existing RC/GA descriptor
and canonicalization digest algorithms are unchanged, and historical frozen artifacts are untouched.

## Compatibility and security classification

Duplicate-key and dual-alias rejection removes ambiguous input, not legitimate profile-generated
bytes. Unpaired surrogates are malformed Unicode: reject them before replacement encoding can
make distinct strings share signed UTF-8 bytes. These are explicit malformed-input hardening
changes. They require ordinary reviewed maintenance/new-candidate checks; a selected RC cannot
be retroactively patched or authorized with altered parser bytes.

Trust's historical parser normalizes typed values, including whitespace and equivalent timestamp
forms. The tests expose that supported behavior; this review does not rename it raw-byte signature
verification. UTF-8 transport behavior and complete cross-language number/time/size matrices need
separate evidence where the production reader does not expose a matching path. [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) is only
a comparison checklist: insertion-ordered profile JSON is not JCS. Domain framing here is not
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) Ed25519ctx or Ed25519ph.

Unknown fields, optional omission, empty/null values and array order are profile-specific; consult
the detailed contracts rather than apply a generic sorted serializer. Changing legitimate signed
preimages, field meanings, key encodings, required signatures, limits or supported version semantics
requires the existing version policy and migration review. No production governance signing key is
used for content vectors; using an authorized user identity across correctly separated purposes is
not prohibited.

## Evidence and Phase 12 closure

The checked-in vectors prove those specific public cases. They are not historic release receipts,
a supported-prior-reader runtime matrix, an independent external implementation, human security
sign-off or a production closeout. Existing historical tests and frozen registry checks remain
useful without being relabeled as cross-release runtime evidence.

[Phase 12 open items](phase-12-open-items.md) retains PR-296's missing versioned app-subject projection,
PR-297's missing protected migration producer, CI validation, independent runtime observations and
possible versioned redesign. Local conformance has no dependency on impossible global closeout;
it also cannot satisfy those outstanding gates.

## PR-299 handoff

The Mail prototype receives exact public content/signature and local-service limitations. It must
separately review confidentiality, recipient binding, replay, metadata leakage, key custody,
app-owned state and its threat model. A public `recipientFingerprint` is not encryption; a valid
signature grants no trust, permission, moderation authority or assurance that all messages were
disclosed. PR-298 supplies no email protocol, SMTP/IMAP, Freemail compatibility, remote service
discovery, spam consensus or daemon-core mailbox storage.
