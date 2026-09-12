# Federated catalog discovery and local trust

This runbook defines how a Cryptad node discovers, verifies, trusts, and operates multiple independently managed app catalogs without creating a global app-store authority.

## Scope and prerequisites

Federation is a local operator policy layered over existing signed catalogs, signed app bundles, independent review receipts, catalog operations, consent, update, and rollback authorities. It does not replace the PR-293 Stable catalog authority or the PR-294 external third-party app pilot.

Before treating federation evidence as operational, retain the exact authenticated closeouts for:

- PR-291 protected Stable release execution;
- PR-292 independent reproducibility;
- PR-293 Stable catalog authority and role-separated keyset;
- PR-294 external third-party app pilot;
- a protected federation runtime observation for the same source commit and release identity.

Local verification is side-effect-free:

```bash
python3 tools/release-certification/certify.py stable-federated-catalog --self-test
python3 tools/release-certification/certify.py stable-federated-catalog --help
```

The certification command does not fetch descriptors, change node trust, install an app, contact a runtime node, publish a catalog, create a tag or GitHub Release, or mutate a remote service.

## Trust boundaries

A valid catalog signature proves that the catalog bytes were signed by a key. It does not authorize that key for a catalog ID, authorize an app publisher, approve a reviewer, or grant installation consent.

The local node keeps these decisions separate:

| Role | Authority | Federation rule |
|---|---|---|
| Catalog signer | Local catalog-ID/signer binding backed by the catalog key registry | A signer authorizes only the exact locally bound catalog ID and channels. |
| App publisher | Local catalog/app-scoped publisher policy backed by trusted app-key material | A publisher accepted for one catalog/app does not authorize another catalog or app. |
| Reviewer | Local catalog/app reviewer scope backed by `TrustedReviewerKeys` | Catalog reviewer metadata and transparency are evidence, not local trust. |
| Offline recovery | PR-293 recovery role | Recovery material never becomes a routine catalog, publisher, or reviewer key. |

Key IDs and public-key fingerprints remain role-distinct. A mirror is a transport alternative for the same authenticated catalog bytes; it is never a trust root.

## Discovery is pending evidence

A signed discovery descriptor contains bounded public metadata: the subject catalog ID, catalog signer fingerprint, public source hints, supported channels, display metadata, transparency digests, validity dates, issuer identity, signature, and self-digest.

Importing a valid descriptor creates a pending local recommendation. It does not:

- install a catalog signing key;
- create or activate a local catalog trust binding;
- add or refresh a catalog source;
- trust a publisher or reviewer;
- install or update an app.

The live runtime authenticates descriptor and endorsement issuers with the locally configured
catalog-authority public-key material. That registry supplies public verification bytes only: the
descriptor's subject signer still needs a separate exact local catalog trust binding before it can
authorize refresh, install, or update. Import persists the recommendation below the node's private
app-data tree and never changes the catalog source store.
Operator reads reverify retained descriptors and direct endorsements against current issuer
lifecycle and freshness. Revocation or expiry changes only the displayed evidence contribution;
the pending record remains local until the operator discards it.

Descriptors accept only bounded `crypta:` or public HTTPS source hints. Private insert capability, URL credentials, local paths, tokens, subscription state, installed-app state, raw catalog bodies, and user identifiers are invalid.

Discovery is one-way. The node may fetch an operator-selected exact descriptor or recommendation document. It does not upload configured catalogs, source URIs, installed apps, local trust anchors, endorsements, reviewer/publisher choices, conflict decisions, or a stable discovery identifier.

## Endorsements are non-transitive hints

A signed endorsement may recommend one exact descriptor and subject signer fingerprint. Its closed runtime wire format contains no transitive-trust or trust-creation action, so verification can produce evidence only.

The node does not follow endorsement chains, calculate a global reputation score, install keys from endorsements, add sources automatically, or publish local accept/reject decisions. Conflicting endorsements remain bounded local evidence. Revoking an issuer stops that issuer's active contribution without changing unrelated catalogs.

Operator surfaces must distinguish:

```text
known
recommended
endorsed
locally trusted
suspended
revoked
conflicted
```

## Local trust and conflicts

Every production federated catalog requires an explicit local catalog-ID/signer binding. Catalog refresh cannot modify or expand that host-owned binding. Suspended, revoked, removed, unknown, mismatched, or substituted bindings fail closed for new refresh, install, and update decisions.

Conflict evaluation is deterministic but does not convert lexical order into trust. It classifies exact duplicates, metadata disagreements, same-version payload conflicts, publisher/namespace collisions, competing versions, security-policy disagreements, and reviewer-policy disagreements.

Unresolved hard conflicts block automatic install and update. Same-version payload and publisher conflicts fail closed. A catalog preference applies only after policy permits the candidate set. A security denylist or block remains stronger than a catalog preference.

Local resolutions bind the exact conflict-set and subject digests. Any later catalog, publisher, review, advisory, or payload change makes stale consent invalid. Local decisions are not published as global moderation claims.

## Installed origin and source switching

Catalog installs retain host-owned origin provenance for the exact catalog, catalog signer,
revision, bundle artifact, publisher, review receipt, and local trust-policy digests. Origin schema
v2 also records the verified publisher-key fingerprint and a SHA-256 commitment to the exact
digest-sidecar bytes authenticated by the bundle signature. AppHost recomputes both identities from
its own copied bundle before install, update, or rollback. A different globally trusted signer, or
different content signed under the same app ID and version, cannot satisfy that provenance. The
installed app cannot write this state.

Schema-v1 origin records remain readable for restart compatibility, but they do not contain the
signed-content commitment and cannot authorize an exact retained catalog rollback. The next
catalog update requires current operator authorization and writes schema v2; Cryptad does not infer
or backfill the missing identity from a mutable installed tree.

Updates stay pinned to the installed catalog and approved publisher lineage. An unavailable or removed origin produces an operator-action-required state; another catalog does not silently take over. An exact duplicate from another trusted catalog may be shown as an alternative, but it is not selected automatically.

Pinning is applied only after Cryptad classifies the complete authenticated cross-catalog subject
set. An unresolved payload, publisher, reviewer, or security-policy conflict blocks automatic work
even when the pinned catalog still has an otherwise eligible candidate. Pinning is not a bypass for
the local conflict authority.

A catalog or publisher switch requires a digest-bound preview, material operator consent, applicable backup or migration checks, and an audit record. Rollback restores the exact prior bundle bytes and prior origin provenance. Removing a catalog leaves installed apps in place but blocks automatic updates that no longer have a valid local origin decision.

The direct catalog-update route permits a source switch only when it can read the current installed
manifest and prove that the durable app-data schema target is unchanged. An unreadable current
manifest is not treated as an undeclared schema: the installation must first be repaired, after
which any source or schema switch proceeds through the app-update stage/apply lifecycle.

## Runtime configuration and migration

Federation is opt-in with `cryptad.appCatalogFederationEnabled=true`. The live runtime keeps host-owned state below the node's private app data tree:

Legacy catalog plans retain authenticated signer and revision context only while a staged plan is
open so the manager can detect refresh or signer changes before apply. When federation is disabled,
that transient context is not persisted as installed origin provenance and does not activate
catalog pinning or source-switch consent. Existing first-party catalog behavior therefore remains
unchanged on default nodes.

- `apps/catalog-trust` for exact catalog-ID/signer bindings;
- `apps/catalog-publisher-bindings` for catalog/app publisher approvals;
- `apps/catalog-reviewer-scopes` for catalog/app reviewer acceptance;
- `apps/catalog-conflict-resolutions` for exact-subject local conflict decisions;
- `apps/catalog-discovery-pending` for bounded signed recommendations that remain untrusted and
  unconfigured;
- `apps/catalog-origins` for current and rollback provenance;
- `apps/catalogs/<catalogId>/history/<revision>/.origin-pins` for derived, host-private retention
  markers that protect signed revisions referenced by those provenance slots;
- `apps/mutation-transactions` for host-private write-ahead recovery of coordinated bundle and
  provenance changes.

Before catalog install, catalog or generic update, rollback, or uninstall changes a canonical
bundle or origin slot, AppHost publishes an active transaction containing the exact prior current
and rollback bundles and origins. An interrupted active transaction is restored before persistent
AppHost reads or mutations proceed. Only an atomic active-to-committed rename preserves the target;
committed leftovers are cleanup-only. This recovery state is host-private and is never exposed to
apps or support artifacts.

Before the transaction commits, AppHost retains every revision in the prospective current and
rollback provenance snapshot without releasing the prior pins. After the durable commit it removes
markers that no remaining slot references. Failed mutations and recovered active transactions
reconcile against their restored provenance; failed post-commit cleanup leaves only safe extra pins
and is retried before later persistent work. Provenance rotation and uninstall therefore cannot
retain obsolete revisions indefinitely.

The `AppHost` compatibility defaults do not claim federation support. Catalog install, catalog
update, and standalone origin persistence fail before bundle mutation unless the implementation
explicitly provides coordinated provenance storage. Rollback uses the authorized overload only
when the retained rollback slot has catalog provenance; an untracked legacy rollback continues to
use the original `rollback(String)` method.

The trusted-key files remain the source of public verification material. Enabling federation does not copy keys from a catalog and does not make every legacy registry key valid for every catalog. Existing source records remain readable in legacy mode. In federation mode a legacy source record without an exact binding ID and digest is omitted from new-work selection until the operator explicitly re-approves and re-adds that source. Trust-policy changes likewise invalidate the persisted source-policy digest and require explicit re-approval.

The host/operator-only API exposes `GET /operator/catalog-federation`, lifecycle mutations below `/operator/catalog-federation/{catalogId}/`, `GET` and guarded `POST /operator/catalog-federation/discovery`, guarded `POST /operator/catalog-federation/discovery/{descriptorId}/discard`, `GET /operator/catalog-federation/conflicts/{appId}`, guarded `POST /operator/catalog-federation/conflicts/{appId}/resolve`, `GET /operator/apps/{appId}/catalog-origin`, and guarded `POST /operator/apps/{appId}/catalog-origin/switch-preview` with a URL-encoded `targetCatalogId`. A `trust` mutation accepts matching repeated `signerKeyId` and `signerFingerprintSha256` parameters as the explicit complete signer set; an overlapping rotation therefore submits both predecessor and successor, while a later deliberate update may remove the predecessor. Discovery import accepts one Base64-encoded exact signed descriptor and up to eight repeated Base64-encoded direct endorsements. Its response and the Web Shell show bounded public identities, digests, lifecycle dates, and explicit `trustGranted=false`, `sourceConfigured=false`, and `transitive=false` states; they do not return raw documents, signatures, key bytes, or local paths. Discard changes pending evidence retention only.

The conflict read returns the exact `conflictId`, `subjectSetDigestSha256`, classifications, and public subject digests. A resolution write must repeat those exact identifiers; it fails as stale if a refresh, trust-policy change, or subject change has altered the set. `explicit-source-switch-required` blocks automatic selection while making the separate exact source-switch preview and consent path available. The decision remains host-local and is never published as moderation or reputation evidence.

Preview preparation downloads, extracts, and verifies the selected bundle, so it requires the form-password guard and is never exposed through a resource-consuming `GET`. A source-switch preview returns an exact `consentDigestSha256`; the guarded direct catalog update or lifecycle-stage mutation must receive that value as `sourceSwitchConsent`. Lifecycle staging also receives the preview's exact `targetCatalogId`, so an unavailable pinned source does not make the selected alternate impossible to stage. The digest binds the exact retained catalog signer key ID and fingerprint, catalog revision, trust binding, publisher policy, bundle, and review receipt. A re-sign, refresh, policy change, or different target therefore invalidates stale consent. App-process and app-browser principals are rejected before these routes inspect local state. These routes are outside the Stable 1.0 app-facing contract.

The runtime selects only catalogs whose current bindings authorize routine work. A suspended, revoked, removed, corrupt, or stale catalog is isolated from automatic selection without preventing an unrelated active catalog from operating. PR-294 publisher keys can remain in their separately authenticated pilot registry; federation composes that registry with the Stable publisher registry only for the publisher role and continues to require an exact local catalog/app binding.

Suspension blocks refresh, install, and update authorization but preserves explicit rollback to an
exact retained revision. Historical rollback requires the source's stable binding identity and the
current binding's suspended-or-active lifecycle, signer fingerprint, catalog ID, and channel scope;
it does not replace the source's original admission digest or re-enable routine work. Revoked,
removed, and pending bindings cannot authorize historical rollback.
App-bundle rollback uses the exact host-owned rollback-origin slot selected under the AppHost
lifecycle lock. Before swapping bytes or provenance, the node reauthenticates the retained catalog
revision and signer, the current historical publisher binding for the exact catalog/app/channel,
and the current reviewer registry and local reviewer scope. A revoked catalog, publisher, reviewer,
or receipt therefore blocks executable rollback; suspension permits only the exact bounded
historical subject described above.

## Certification modes and states

Use one closed execution contract and one confined evidence directory:

```bash
python3 tools/release-certification/certify.py stable-federated-catalog \
  --mode verify-runtime \
  --execution-contract build/federation/execution.json \
  --evidence-dir build/federation/evidence \
  --out-dir build/federation/result
```

The closed modes are:

| Mode | Result |
|---|---|
| `preflight` | Validates the non-secret contract and policy binding. |
| `verify-discovery` | Authenticates descriptor and endorsement schemas, signatures, self-digests, source hints, and freshness. |
| `verify-local-trust` | Authenticates the signed runtime observation and its distinct catalog trust bindings and scoped policy digests. |
| `verify-conflicts` | Verifies the required conflict classes and fail-closed selection scenarios. |
| `verify-runtime` | Verifies pinning, explicit source switching, rollback provenance, per-catalog revocation isolation, privacy, redaction, and complete cleanup. |
| `closeout` | Binds successful runtime evidence to exact PR-291, PR-292, PR-293, and PR-294 protected coordinates. |

Possible states are:

```text
implementation-complete
fixture-verification-complete
discovery-authenticated
local-trust-configured
conflict-policy-verified
runtime-federation-verified
operational-federation-complete
blocked
partial
```

Fixtures and self-tests can reach only `fixture-verification-complete`. False fixture flags do not help: fixture-, sample-, template-, self-test-, and test-shaped execution or protected-artifact identities are rejected for operational closeout. Each PR-291 through PR-294 authority entry must bind the canonical predecessor summary by file name, byte size, and SHA-256. Closeout validates that summary's closed schema, self-digest where the predecessor format provides one, release identity, source commit, operational state, redaction state, and predecessor-root links. Workflow source, an upload, a checked-in manifest, a copied receipt, a digest-only claim, or partial cleanup is not operational evidence.

## Evidence and redaction

Certification inputs use five closed schemas:

- `stable-1.0-federated-catalog-execution-v1.schema.json`;
- `stable-1.0-catalog-discovery-descriptor-v1.schema.json`;
- `stable-1.0-catalog-endorsement-v1.schema.json`;
- `stable-1.0-federated-catalog-runtime-observation-v1.schema.json`;
- `stable-1.0-federated-catalog-summary-v1.schema.json`.

The runtime observation carries semantic digests and bounded counts rather than raw trust-store contents, catalog bodies, signatures, app data, or fetched content. Outputs reject private keys, private insert URIs, bearer/session/app tokens, credentials, absolute POSIX/Windows/UNC paths, raw payload fields, and user subscription lists.

Input and output paths must resolve beneath the selected workspace, contain no symlink components, and refer to regular files or real directories. Each evidence file is checked against its exact size and SHA-256 binding before parsing. The output directory must be empty, and generated JSON and Markdown are scanned before atomic writes.

Descriptor and endorsement evidence uses the same nested wire objects, canonical field order, unprefixed self-digests, final newline, and Ed25519 signature payload as `CatalogDiscoveryDescriptor` and `CatalogEndorsement`. The execution binding carries the operator-approved issuer SPKI outside the public document and authenticates the exact evidence bytes by size and `sha256:` digest; certification does not accept a separate flat descriptor dialect.

## Operational boundary

Protected environments produce and authenticate operational receipts. They must reuse PR-293 catalog publication and PR-294 external handoff/review/pilot evidence. A federation coordinator has no catalog, publisher, reviewer, or recovery signing authority and no tag, GitHub Release, USK publication, or production trust-store mutation authority.

Operational imports use three separately protected workflows. `stable-1.0-federated-catalog-runtime.yml` runs the reviewed node-side adapter on a dedicated runner, uploads the immutable unsigned observation, and then seals the exact receipt with an independently approved observer key held by the runtime-observation environment. The protected environment—not workflow-dispatch input—selects the adapter digest, observer key ID, and observer fingerprint. `stable-1.0-federated-catalog-evidence.yml` fetches one operator-selected public archive by exact size and SHA-256, confines it, rejects fixture/self-test subjects, and requires the extracted tree to equal the execution contract's file allowlist. Before upload, it authenticates each predecessor and the runtime observer's exact original workflow run and attempt, protected ref and commit, successful job and environment deployment, artifact names and digests, canonical summary or receipt bytes, and the observer key binding. A self-generated key embedded only in the runtime receipt is not authority. Unbound files, including otherwise unreferenced runtime dumps or app data, block the producer upload. `stable-1.0-federated-catalog-trust.yml` accepts only the exact successful attempt of that allowlisted evidence producer at the same protected ref and commit; it verifies the producer job, actor, event, environment deployment, canonical artifact name, artifact ID, and archive digest before extraction. An artifact from another successful workflow cannot enter operational closeout.

Do not report that public federation or a protected runtime operation occurred unless the exact original producer coordinates and signed runtime observation pass `closeout`. Until then, report implementation or fixture verification only.

## Non-goals

Federation does not create:

- a centralized Crypta app store;
- a global source of truth;
- global moderation or network-wide trust scoring;
- transitive trust propagation;
- subscription gossip;
- automatic cross-catalog source or publisher switching.

## Selected app projection and packaged lifecycle

The [PR-305 runbook](pr-305-federated-app-projection-and-catalog-origin.md) adds the private pre-runtime selected-subject handoff, native scoped exporter and fresh-root publisher/reviewer bootstrap. Normal catalog trust, conflict resolution, source-switch consent and AppHost origin/rollback remain authoritative. The executable loopback cohort supplies local process/HTTP/persistence evidence only; original protected observers and broad federation closeout retain their existing requirements.
