# Platform API compatibility contract

The Platform API compatibility contract is the deterministic app-facing description of the current
Platform API v1 surface. It is separate from the URL version in `/api/v1/`: the URL version names
the transport route family, while the integer contract version is what app manifests, catalog
metadata, developer tooling, and release certification compare.

The current app-facing values are:

```text
apiVersion=v1
contractVersion=25
```

The contract does not change Platform API behavior. It publishes metadata that answers which
routes/actions exist, which manifest capabilities app principals need, and whether capabilities or
endpoints are stable, experimental, deprecated, scheduled for removal, or internal.

## Public snapshot

The current node exposes the contract at:

```text
GET /api/v1/platform/contract
```

Host/operator requests use the existing local-admin model. App process and browser principals can
read the endpoint only when their manifest grants:

```text
platform.contract.read
```

The response shape is:

```json
{
  "contract": {
    "apiVersion": "v1",
    "contractVersion": 25,
    "generatedBy": "cryptad",
    "stabilityPolicy": "...",
    "stableBaseline": {
      "name": "1.0",
      "contractVersion": 19,
      "capabilityCount": 9,
      "endpointCount": 32,
      "capabilities": ["platform.contract.read"],
      "endpoints": ["GET /platform/contract"]
    },
    "compatibilityWindow": {
      "schemaVersion": 1,
      "baselineName": "1.0",
      "baselineContractVersion": 19,
      "currentContractVersion": 25,
      "supportPhase": "beta",
      "minimumDeprecationWindowContractVersions": 2,
      "minimumScheduledRemovalWindowContractVersions": 2,
      "criticalStableRemovalWaiverAllowed": false,
      "previousSnapshotRequiredInProductionBeta": true,
      "policyDocument": "docs/platform-api-compatibility-support-window.md"
    },
    "baselineRegistrySummary": {
      "schemaVersion": 1,
      "registryDigest": "...",
      "supportedBaselines": [
        {"id": "1.0", "status": "active", "definitionDigest": "..."}
      ]
    },
    "capabilities": [],
    "endpoints": []
  }
}
```

The snapshot is deterministic and excludes raw app process tokens, browser session tokens,
bootstrap nonces, form passwords, request bodies, query strings, filesystem paths, sandbox command
lines, environment variables, private keys, and private insert URIs.

Contract version 24 adds the bounded named-baseline registry summary shown above. This is an
app-visible compatibility-metadata change, so it advances the integer contract version even though
it adds no route, capability, or permission. The URL API version remains `v1`, and the immutable
Platform API 1.0 membership remains rooted at contract version 19.

The developer beta toolkit uses the same contract metadata in `crypta-app test` and
`crypta-app compat verify`. When either command consumes a custom version-24-or-later snapshot, it
verifies the snapshot's `baselineRegistrySummary` against the selected registry; use
`--baseline-registry` to supply the registry paired with a candidate snapshot. `crypta-app api
policy` prints the stable support-window policy from a snapshot, and `crypta-app api diff` compares
two snapshots for Platform API 1.0 stable breaking changes. Scaffolded beta templates declare
conservative `api.minimumVersion` and `api.maximumTestedVersion` values, and catalog entry
generation copies the manifest compatibility metadata into descriptor output. See
[developer-beta-toolkit.md](developer-beta-toolkit.md).

## Descriptor fields

Capability descriptors contain:

- `name`
- `stability`
- `sinceContractVersion`
- optional `deprecation`
- short `description`

Endpoint descriptors contain:

- route family, HTTP method, and route template relative to `/api/v1`
- audit/authorization action label
- required manifest capabilities
- whether host/operator bypass is allowed through the existing local-admin model
- whether app process and app browser principals can call the route
- stability level, first contract version, optional deprecation/removal metadata, and description

The runtime app authorization path reads the same endpoint descriptors that the snapshot publishes,
so the contract and route-to-capability policy do not maintain separate route lists.
Host/operator-only descriptors can be recorded for local audit and Web Shell routing without
advancing the app-facing contract version.

## Stability levels

| Stability | Meaning |
| --- | --- |
| `stable` | Covered by the current Platform API compatibility contract. |
| `experimental` | Available for explicit adopters, but may change in a later contract. |
| `deprecated` | Still callable, but app authors should migrate away. |
| `scheduled-for-removal` | Still callable now, with planned removal metadata. |
| `internal` | Not app-facing; developer tooling treats app use as an error. |

Contract version 2 adds the installed-app update lifecycle endpoints under
`/apps/{appId}/updates`. Contract version 3 adds the app vault and identity vault descriptors.
Contract version 4 adds the first-party catalog onboarding routes under
`/app-catalogs/recommended`. Contract version 5 adds profile-publishing support for app-owned
static UIs:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/app-vault/identities` | `vault.identities.create` | Create an app-owned identity from a browser-safe app principal or app process principal without returning private identity material. |
| `POST /api/v1/app-vault/identities/{identityId}/profile-document` | `vault.identities.read`, `vault.identities.use` | Ask Cryptad to produce a profile document for an identity the app can see and use, without exporting private keys or recording raw signatures in evidence. |
| `POST /api/v1/queue/inserts/app-document` | `content.insert.app-document`, `queue.write` | Queue an app-generated document insert without requiring or authorizing a local source path in the request. |

`POST /api/v1/app-vault/identities` keeps `sinceContractVersion=3` because app-process
identity creation was introduced with the app-vault contract. Contract version 5 expands that
same descriptor to browser app principals for app-owned identity creation; the complete browser
profile-publishing workflow still requires the v5 profile-document and app-document routes.

Existing version 1 capabilities and endpoints remain stable, and their descriptors keep
`sinceContractVersion=1` so tooling can distinguish old and newly introduced surface area.

Contract version 14 extends app update summaries with path-free `dataMigration` status for signed
app-data migration contracts, including namespace schema steps, rollback compatibility, and
stopped-app requirements. It does not add app-facing backup/restore routes and does not expose
bundle paths, migration command paths, raw migration logs, tokens, private insert URIs, or raw
app-data values. See [app-upgrade-data-migrations.md](app-upgrade-data-migrations.md).

Contract version 15 moves Trust Graph from broad Preview wording into the bounded local RC trust
service surface. It adds path-free local RC scope metadata on `GET /api/v1/trust-graph/status`,
redacted statement lifecycle summaries, and imported statement lifecycle mutation routes:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `GET /api/v1/trust-graph/statements/{fingerprint}` | `trust.read` | Read one redacted imported statement summary, including local lifecycle status and safe source metadata. |
| `POST /api/v1/trust-graph/statements/{fingerprint}/deprecate` | `trust.write` | Mark one imported statement deprecated under local operator/app policy. |
| `POST /api/v1/trust-graph/statements/{fingerprint}/revoke` | `trust.write` | Mark one imported statement revoked under local operator/app policy. |
| `POST /api/v1/trust-graph/statements/{fingerprint}/reactivate` | `trust.write` | Return one imported statement to active local lifecycle status. |

Lifecycle records are local policy, not globally propagated revocation truth. Re-importing an old
statement keeps any existing local deprecated or revoked status. Score evidence now includes
bounded contribution reason codes and an `evidenceTruncated` flag; revoked, deprecated, expired,
unverified, unanchored, or zero-confidence statements do not contribute. The `trust.score`
app-service remains read-only and no more permissive than direct score reads.

Contract version 16 extends the app-service contract with dependency graph and grant-bundle
review routes:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `GET /api/v1/app-services/dependencies` | `app.services.read` | List caller-visible dependency graph nodes and edges. Host/operator sees all apps; app principals see only their own app dependencies. |
| `GET /api/v1/app-services/dependencies/consumers/{consumerAppId}` | `app.services.read` | Read one consumer app's dependency graph, with app-principal scoping enforced by the route and no conflict with provider service routes. |
| `GET /api/v1/app-services/grant-bundles` | `app.services.read` | List caller-visible grant-bundle proposals and approved/expired/revalidation states. |
| `POST /api/v1/app-services/grant-bundles` | `app.services.call` | Request a pending bounded bundle for the caller's declared dependencies; host/operator may specify a consumer app. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/approve` | Host/operator only | Approve a pending bundle after revalidating the signed consumer manifest and current provider descriptors. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/reject` | Host/operator only | Reject a pending bundle without leaving active grants. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/renew` | Host/operator only | Renew or revalidate bundle-approved grants after descriptor compatibility checks. |

Contract version 17 adds redacted ecosystem security advisory and review revocation summaries to
catalog/update surfaces. App-facing and operator-facing summaries can expose bounded status,
advisory IDs, receipt fingerprints, lifecycle status, and block flags. They must not expose raw
public keys, private keys, raw signatures, raw receipt contents, local registry paths, catalog
scratch paths, staged bundle paths, private insert URIs, tokens, request bodies, or raw fetched
content. The enforcement APIs remain the existing catalog install/update and app update stage/apply
routes; `securityAcknowledged=true` can acknowledge only warning-level security decisions.

Contract version 18 adds app-visible network budget status and safe budget-exhausted errors for
content fetch, content subscriptions, and Trust Graph import routes. The route descriptors remain
where they first appeared, but app-facing callers can now observe `429` budget denials and the
subscription status `budget_exhausted`.

Contract version 19 adds the signed first-party `maintenance` object to catalog app listing/detail
responses. The existing catalog routes and capability requirements do not change; the new response
metadata reports owner, support level, data schema policy, migration policy, backup/restore support,
security policy, deprecation policy, and safe owner/support links from signed catalog v5 fields.

Dependency metadata is review and UX metadata, not authorization. Bundle proposals do not approve
access. Invocation still requires a non-expired active grant on every call. Provider descriptor
version, scope, context, kind, adapter, and compatibility fingerprint drift produces
`revalidation-required` behavior until an operator explicitly renews or revalidates the bundle.

Contract version 6 adds bounded content fetch support for static feed apps:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/content/fetch` | `content.fetch` | Fetch a bounded Crypta content document for an app workflow such as feed reading without granting queue mutation or local file-path authority. |

The v6 fetch descriptor is separate from insert permissions. `content.fetch` lets the app ask the
local node to retrieve a specific content URI through the Platform API; it does not grant
`content.insert`, `content.insert.app-document`, `queue.write`, catalog management, vault access,
or local filesystem access. Certification evidence for this route must record only sanitized fetch
metadata and must exclude raw feed bodies, raw request bodies, private insert URIs, app process
tokens, app browser-session tokens, form passwords, and local paths.

`POST /api/v1/content/fetch` accepts `application/x-www-form-urlencoded` parameters. `uri` is
required and must be a Crypta/Freenet content key in `CHK@...`, `SSK@...`, `USK@...`, `KSK@...`,
`crypta:CHK@...`, `crypta:SSK@...`, `crypta:USK@...`, or `crypta:KSK@...` form, with the key-type
prefix accepted case-insensitively. Optional `maxBytes`, `timeoutMillis`, `format`, and `purpose`
values are bounded by the daemon: the default byte cap is 262144, the hard byte cap is 1048576, the
default timeout is 30000 milliseconds, and the hard timeout is 60000 milliseconds. `format=text`
returns UTF-8 `contentText`; `format=base64` returns `contentBase64`. App principals cannot use this
route for `file:`, `http:`, `https:`, loopback, LAN, or absolute local-path fetches.

Contract v18 applies a shared app-network budget after this validation and before the runtime
fetch port is called. Budget exhaustion returns safe `429` errors such as
`content_fetch_budget_exhausted` or `network_budget_concurrency_limited`; it does not call the
runtime fetch port, consume budget for rejected unsafe sources, or expose raw daemon exception
text.

Contract version 7 adds the local Trust Graph service and the bounded AppVault
trust-statement signing route:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `GET /api/v1/trust-graph/status` | `trust.read` | Read local RC service status, scope, limits, lifecycle support, and document type metadata. |
| `GET /api/v1/trust-graph/anchors` | `trust.read` | List local trust anchors. |
| `POST /api/v1/trust-graph/anchors` | `trust.write` | Add or replace one local trust anchor. |
| `DELETE /api/v1/trust-graph/anchors/{fingerprint}` | `trust.write` | Remove one local trust anchor. |
| `POST /api/v1/trust-graph/import` | `trust.write` | Import one bounded `crypta.trust.statement.v1` document into the local store and record whether its AppVault trust-statement signature verifies. |
| `GET /api/v1/trust-graph/subjects` | `trust.read` | List subjects that have imported trust statement evidence. |
| `GET /api/v1/trust-graph/statements` | `trust.read` | List redacted trust statement summaries with optional filters. |
| `GET /api/v1/trust-graph/score` | `trust.read` | Query a deterministic local score and optional bounded evidence for one subject/context. |
| `POST /api/v1/app-vault/identities/{identityId}/trust-statement` | `trust.write`, `vault.identities.read`, `vault.identities.use` | Ask AppVault to sign one bounded trust statement payload without exporting private identity material. |

`trust.read` lets an app read local trust scores and evidence; it does not grant import,
anchor mutation, queue access, vault access, catalog access, moderation authority, or content
blocking. `trust.write` lets an app import trust statements and manage local anchors; it does not
publish anything automatically, export private identity material, or create a global trust policy.

The service is intentionally local and operator-curated. It is not a full Web of Trust
implementation, does not crawl the network, does not perform global moderation or blocking, does
not make routing decisions, and does not provide old WebOfTrust/Freetalk/Sone/Freemail
compatibility. Trust anchors are local, imported statements are persisted locally,
non-contributing until anchored and verified, and the scorer uses direct local anchors with a simple
confidence-weighted average. No FNP/FCP/wire protocol, routing, datastore, peer-management, or
FProxy browse behavior changes are part of contract v7 or v15. See
[trust-graph-preview.md](trust-graph-preview.md).

Contract version 8 adds app-owned, durable, bounded USK content subscriptions under
`/api/v1/content/subscriptions`:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `GET /api/v1/content/subscriptions` | `content.subscribe` | List the caller app's safe subscription metadata. |
| `POST /api/v1/content/subscriptions` | `content.subscribe`, `content.fetch` | Create one bounded USK subscription for the caller app. |
| `GET /api/v1/content/subscriptions/{subscriptionId}` | `content.subscribe` | Read one subscription owned by the caller app. |
| `POST /api/v1/content/subscriptions/{subscriptionId}/refresh` | `content.subscribe`, `content.fetch` | Trigger one bounded foreground refresh of the caller app's subscription. |
| `POST /api/v1/content/subscriptions/{subscriptionId}/pause` | `content.subscribe` | Pause background polling for one caller-owned subscription. |
| `POST /api/v1/content/subscriptions/{subscriptionId}/resume` | `content.subscribe` | Resume background polling and make the subscription due. |
| `DELETE /api/v1/content/subscriptions/{subscriptionId}` | `content.subscribe` | Delete one caller-owned subscription. |

All subscription routes require an app process or app browser principal. Host/operator principals
do not implicitly bypass app scoping for these routes. If an operator-facing subscription console
is needed later, it must be a separate API that names the target app explicitly.

Background subscriptions are intentionally narrower than foreground content fetches. They accept
only `USK@...` and `crypta:USK@...` source URIs, reject local paths, relative paths, query strings,
fragments, whitespace, multiline text, `file:`, `http:`, `https:`, `CHK@`, `SSK@`, and `KSK@`,
and normalize only the safe runtime fetch URI for the bounded `ContentFetchPort`. Creation and
manual refresh require both `content.subscribe` and `content.fetch` because each subscription is a
durable background fetch grant. The background scheduler must also skip apps that are no longer
installed or no longer declare both capabilities.

Subscription summaries are metadata only. They may include the app-owned `sourceUri`, sanitized
`lastSeenResolvedUri`, `lastSeenEdition`, `contentSha256`, byte length, timestamps, status,
failure count, stable error code, update count, and short message. They must not include raw
fetched content, raw request bodies, browser-session tokens, app process tokens, form passwords,
private insert URIs, private keys, absolute staging paths, store root paths, queue HTML, or raw
daemon exception messages. The scheduler records queue pressure with stable runtime signals, not
by parsing legacy queue HTML; when pressure is clear, it records safe statuses such as
`queue_pressure`, `runtime_unavailable`, or `budget_exhausted`. Queue pressure skips do not consume
network budget or call the fetch port. Budget skips record safe retry metadata and error codes such
as `content_subscription_budget_exhausted`. This is not a generic crawler and does not add
arbitrary HTTP/HTTPS fetch support.

Contract version 9 adds bounded durable app-owned data under `/api/v1/app-data`:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `GET /api/v1/app-data/status` | `app.data.read` | Read the caller app's record count, namespace count, stored bytes, effective caps, quota status, and sanitized warnings. |
| `GET /api/v1/app-data/namespaces` | `app.data.read` | List namespace metadata for the caller app. |
| `GET /api/v1/app-data/namespaces/{namespace}` | `app.data.read` | Read one namespace and its bounded schema migration history. |
| `POST /api/v1/app-data/namespaces/{namespace}/schema` | `app.data.write` | Record a schema-version update or migration summary without executing app-provided code. |
| `DELETE /api/v1/app-data/namespaces/{namespace}` | `app.data.write` | Clear one caller-owned namespace. |
| `GET /api/v1/app-data/records` | `app.data.read` | List bounded record summaries with optional namespace, limit, and cursor filters. |
| `GET /api/v1/app-data/records/{namespace}/{key}` | `app.data.read` | Read one caller-owned record with metadata and bounded value output. |
| `POST /api/v1/app-data/records` | `app.data.write` | Create or replace one bounded caller-owned record. |
| `DELETE /api/v1/app-data/records/{namespace}/{key}` | `app.data.write` | Delete one caller-owned record. |
| `GET /api/v1/app-data/export` | `app.data.read` | Export bounded caller-owned data as a structured JSON payload with base64 values. |
| `POST /api/v1/app-data/import` | `app.data.write` | Import a bounded app-data export in merge or replace-namespace mode. |

All app-data routes require app principals and scope records to
`request.principal().appId()`. Apps never name a host filesystem path or another app id when
accessing records. Namespace and key identifiers are normalized and bounded; record values are
stored under hashed key directories in the file-backed store rather than raw logical path segments.

`app.data.read` grants reads of the caller app's status, namespace metadata, record values, and
bounded exports. `app.data.write` grants create, replace, delete, import, clear, and schema
metadata updates for the caller app only. Store-level caps remain positive even when the manifest
omits `quota.data.bytes` or sets it to zero; positive manifest data quotas are also enforced when
an installed app can be described.

The app-data store is not AppVault, not secret storage, not a generic filesystem API, and not a
database engine. Certification evidence must summarize counts, byte sizes, schema versions, caps,
digests, booleans, and sanitized error codes. It must not include raw app-data values, raw request
bodies, store roots, app data directories, staging paths, private insert URIs, private keys, app
process tokens, browser-session tokens, form passwords, or raw vault secret material. See
[app-data-store.md](app-data-store.md).

Contract version 10 adds durable Trust Graph exchange and audit routes:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/trust-graph/import-uri` | `trust.write`, `content.fetch` | Fetch bounded Crypta content by URI, parse one `crypta.trust.statement.v1` document, optionally verify `expectedDocumentFingerprint` from a prior preview, persist the normalized public statement in the local trust graph store, and return a redacted import summary. |
| `GET /api/v1/trust-graph/audit` | `trust.read` | Read bounded redacted local trust graph mutation and exchange audit entries. |

Contract version 22 adds the Trust Graph beta hardening preview routes after the original v10
exchange surface. `POST /api/v1/trust-graph/import-preview` previews pasted documents and requires
`trust.write`. `POST /api/v1/trust-graph/import-preview-uri` previews content URI imports and
requires both `trust.write` and `content.fetch` in the published endpoint descriptor before any
fetch occurs. Previews discard raw content, cap statement and candidate-summary counts, summarize
duplicate issuers and conflicts, consume Trust Graph import budget for pasted and URI previews, and
require a later normal import to mutate local graph state. Pasted previews may summarize a direct
statement, an array, or a `{ "statements": [...] }` wrapper, but only one extracted
`crypta.trust.statement.v1` document can be committed through the direct import route. URI previews
reject fetched arrays and wrappers because `import-uri` imports exactly one root
`crypta.trust.statement.v1` document. First-party URI import commits pass
`expectedDocumentFingerprint` to `import-uri`; if a mutable source resolves to a different document
after preview, the commit fails with `trust_import_preview_stale`.

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/trust-graph/import-preview` | `trust.write` | Preview bounded pasted-document statement imports with redacted source, duplicate issuer, conflict, lifecycle, budget, and score-impact summaries before commit. |
| `POST /api/v1/trust-graph/import-preview-uri` | `trust.write`, `content.fetch` | Fetch and preview bounded content URI statement imports with redacted source, duplicate issuer, conflict, lifecycle, budget, and score-impact summaries before commit. |
| `POST /api/v1/trust-graph/anchors/{fingerprint}/deprecate` | `trust.write` | Mark one local anchor deprecated under local operator/app policy. |
| `POST /api/v1/trust-graph/anchors/{fingerprint}/revoke` | `trust.write` | Mark one local anchor revoked under local operator/app policy. |
| `POST /api/v1/trust-graph/anchors/{fingerprint}/reactivate` | `trust.write` | Return one local anchor to active local lifecycle status when local policy allows it. |

The existing v7 trust routes remain compatible. Runtime embeddings can still inject an in-memory
store for tests, but the full HTTP runtime wires a shared file-backed trust graph store under the
platform-owned AppHost data tree. The store persists local anchors, imported public statements,
redacted source metadata, and enough public document data to score after restart. It does not
persist raw request bodies, raw fetched content outside normalized trust statement records,
private insert URIs, private identity material, browser-session tokens, form passwords, absolute
paths, or raw signatures.

Contract v18 budgets both Trust Graph import paths. Direct `import` consumes Trust Graph import
budget before parsing and storing a statement. `import-uri` consumes Trust Graph import budget and
the content-fetch budget family, so it cannot bypass content-fetch limits. If import budget is
denied, `import-uri` does not fetch. If content-fetch budget is denied, `import-uri` does not import.

Contract version 11 adds bounded Social Inbox RC message signing:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `POST /api/v1/app-vault/identities/{identityId}/social-message` | `vault.identities.read`, `vault.identities.use` | Ask AppVault to sign one bounded `crypta.social.message.v1` plain-text message document for an app-visible identity without exposing a generic browser signing API. |

The social-message route fixes the signing purpose to `crypta.social.message.v1`, uses the server
clock for `createdAt`, bounds subject, body, tags, profile URI, reply metadata, and total canonical
payload bytes, and rejects caller-supplied signing domains, raw payload bytes, or arbitrary signing
purposes. The response contains the public signed document and verification metadata only. It must
not include private key material, private identity material, local vault paths, browser-session
tokens, app process tokens, raw request bodies, domain-separated payload bytes, or private insert
URIs.

This route exists so `apps/social-inbox` can implement threaded social inbox workflows using
AppVault identity, content insert/fetch/subscriptions, durable app data, and local Trust Graph
annotations outside daemon core. Contract v12 moves those annotations behind app-service grants,
so Social Inbox no longer needs direct `trust.read` for the proving path. Threading uses the
existing signed `replyTo` field locally and does not require a new Platform API route. It is not
full WoT, old plugin ABI compatibility, Freetalk, Sone, Freemail, encrypted mail transport, a
moderation system, crawler, daemon-core message protocol, or network protocol change. See
[social-inbox-reference-app.md](social-inbox-reference-app.md).

Contract version 12 adds local app-service discovery, operator-approved grants, redacted audit, and
mediated invocation. Contract version 16 adds the dependency and grant-bundle routes listed above:

| Route | Required app capabilities | Purpose |
| --- | --- | --- |
| `GET /api/v1/app-services` | `app.services.read` | List advertised local service descriptors and the caller-visible manifest service requests. |
| `GET /api/v1/app-services/dependencies` | `app.services.read` | List caller-visible dependency graph nodes and edges. |
| `GET /api/v1/app-services/dependencies/consumers/{consumerAppId}` | `app.services.read` | Read one consumer app's dependency graph with app scoping. |
| `GET /api/v1/app-services/grant-bundles` | `app.services.read` | List caller-visible grant bundles. |
| `POST /api/v1/app-services/grant-bundles` | `app.services.call` | Request a pending bundle for declared service dependencies. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/approve` | Host/operator only | Approve a pending bundle. App principals cannot approve bundles. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/reject` | Host/operator only | Reject a pending bundle without activating grants. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/renew` | Host/operator only | Renew or revalidate bundle-approved grants. |
| `GET /api/v1/app-services/{providerAppId}/services` | `app.services.read` | List services advertised by one installed provider app. |
| `GET /api/v1/app-services/{providerAppId}/services/{serviceId}` | `app.services.read` | Read one public service descriptor. |
| `GET /api/v1/app-services/grants` | `app.services.read` | List caller-visible service grants; app principals see their own consumer grants and host/operator sees all. |
| `POST /api/v1/app-services/grants` | `app.services.call` | Request a pending grant for a provider/service/scope/context. |
| `POST /api/v1/app-services/grants/{grantId}/approve` | Host/operator only | Approve a pending grant. App principals cannot approve their own grants. |
| `POST /api/v1/app-services/grants/{grantId}/revoke` | `app.services.call` for app self-revoke, host/operator for any grant | Revoke a service grant so future invocations fail. |
| `GET /api/v1/app-services/audit` | Host/operator only | Read bounded redacted app-service grant and invocation audit events. |
| `POST /api/v1/app-services/{providerAppId}/services/{serviceId}/invoke` | `app.services.call` | Invoke an explicitly registered platform adapter through an active grant. |

`app.services.read` allows discovery of public descriptors, dependency status, bundle state, and
grant state, not provider app data. `app.services.call` allows a consumer app to request bundles or
grants and invoke services only when an active consumer/provider/service grant exists at call time.
Approval, rejection, renewal, and revalidation remain host/operator-only.

The initial first-party service is `trust-graph` / `trust.score` using adapter
`trust-graph.score`. Its manifest descriptor is metadata-only: provider app id/name/version,
service id/name/version, kind, adapter, scopes such as `score.read`, contexts such as
`message-author`, description, stability, and availability. Bundle approval and grant invocation
check provider app id, service id, version range, scopes, contexts, kind, adapter, and a safe
compatibility fingerprint. Invocation accepts bounded `subjectKind`, `subjectUri`, `context`, and
optional `scope`, then returns a service-call envelope with a redacted score summary and subject
URI hash.

App-service invocation is not generic RPC, not a localhost proxy, not a plugin ABI, and not remote
service discovery. The platform dispatches only to registered in-process adapters. Responses,
audit, Web Shell, docs, and release evidence must not expose provider app data, Trust Graph store
files, raw statement bodies, raw request bodies, raw subject URIs, private insert URIs, private
identity material, browser-session tokens, app process tokens, form passwords, absolute local
paths, app-data backup payloads, or raw service bearer tokens.

The app secret and identity vault capability names are also part of the app permission vocabulary:
`vault.secrets.read`, `vault.secrets.write`, `vault.identities.read`,
`vault.identities.create`, and `vault.identities.use`. They are documented in
[app-secret-and-identity-vault.md](app-secret-and-identity-vault.md). `vault.identities.manage` is
host/operator-only identity management surface, not a third-party app-facing permission. Developer
tooling recognizes vault names for manifest validation and UI permission disclosure, then rejects
operator-only names in third-party app manifests. Runtime route authorization still depends on the
endpoint descriptors exposed by the node's selected contract snapshot.

Catalog-backed update lifecycle mutations preserve the catalog capability boundary for app
principals. App principals need `apps.manage` plus `catalogs.manage` for update `check`, `stage`,
and `apply` actions because those routes can refresh signed catalogs, prepare catalog install
plans, or apply catalog-staged bundles. Host/operator calls keep the existing local-management
bypass.

Recommended catalog onboarding follows the catalog capability boundary. Reading recommendations
requires `catalogs.read`; adding a recommendation through
`/app-catalogs/recommended/{catalogId}/add` requires `catalogs.manage` and still uses the verified
signed-catalog add path.

Contract version 13 adds production first-party catalog channel metadata to existing catalog and
app-update response summaries. Catalog app listing/detail responses include `channel`,
`supportStatus`, `maximumCryptaVersion`, `deprecation`, and `securityAdvisories`. Recommended
catalog responses include a production-safe `defaultEntryChannel` of `stable` and the available
entry channels `stable`, `beta`, `nightly`, and `deprecated`. App-update candidate summaries
include the same channel/support/deprecation/advisory fields plus `channelPolicyAllowed` and
`policyBlockReason`; policy summaries include `allowedChannels` and
`deprecatedAutoUpdatesBlocked`. These fields are app-facing metadata and are path-free,
token-free, and secret-free.

Contract version 19 extends catalog app listing/detail responses with a nested `maintenance`
object. The object is present for old catalogs with `null` values and populated from signed catalog
v5 metadata when declared. It is metadata-only and must not expose local paths, tokens, private
insert URIs, raw app data, raw fetched content, or signing material.

Contract version 20 extends catalog app listing/detail responses with a nested `thirdPartyReview`
object for third-party app submission metadata. The object summarizes submitted, reviewed, caution,
rejected, and resubmitted state, pre-review outcome, reviewer key status, receipt fingerprint, and
redacted transparency-log status when present. It remains metadata-only and must not expose
submission package bodies, rationale text, local paths, tokens, private keys, private insert URIs,
raw app data, or raw fetched content.

Contract version 21 adds host/operator-only consent route descriptors for install, update,
catalog-update, service-grant, decision, and audit workflows. These descriptors make the existing
local `/api/v1/consent/*` surface discoverable through `/api/v1/platform/contract` while keeping
the routes outside the Platform API 1.0 app-facing stable baseline.

App-update summaries also include scheduler metadata for background catalog refresh and app update
checks. The scheduler fields are path-free and token-free: they expose enabled/status, last and
next check timestamps, result, failure count, sanitized error code, and a short message. The
scheduler does not add new app-facing routes and does not change the default `manual` update
policy.

## Platform API 1.0 stable baseline

Contract version 19 freezes the Platform API 1.0 stable baseline. The baseline is named `1.0` and
is distinct from the integer `contractVersion`: the baseline name identifies the app-facing
compatibility promise, while the contract version identifies the exact snapshot schema and
descriptor set.

Current snapshots include a deterministic `stableBaseline` object with `name`, `contractVersion`,
`capabilityCount`, `endpointCount`, `capabilities`, and `endpoints`. Capability and endpoint
descriptors also include `audience`, `stableBaselineMember`, and `stableBaseline` fields so tools
can distinguish stable labels from baseline membership without string matching route families.
Snapshots generated by pre-freeze contract version 19 builds may omit `stableBaseline`; the parser
keeps those artifacts readable and derives the same version-19 baseline from descriptors. Contract
versions after 19 must include `stableBaseline`, and parsed baseline metadata must match descriptor
membership instead of being silently recomputed.

Current snapshots also include a deterministic `compatibilityWindow` object. It binds baseline
`1.0` to baseline contract version `19`, identifies the current contract version, records the
active `beta` support phase, and publishes the support policy used by release certification:

- minimum deprecation window: 2 contract versions;
- minimum scheduled-removal runway: 2 contract versions;
- stable removal requires a future stable baseline;
- stable removal requires previous contract snapshot comparison;
- critical stable removal waivers are rejected;
- production beta requires previous snapshot history;
- experimental-to-stable graduation requires review evidence and stable reference updates.

Release artifacts store redacted snapshots below
`<out-root>/<release-id>/production-beta/artifacts/legacy/evidence/` as
`platform-api-contract-current.json`, `platform-api-contract-previous.json`, and
`platform-api-stable-diff.json`. The checked-in baseline reference is
`docs/platform-api/contracts/platform-api-1.0-baseline.json`. The current and previous files are
parseable contract snapshot JSON, not only evidence-row summaries, so later `crypta-app api diff`
runs can use them as previous-history inputs.

The stable-baseline diff emits deterministic finding codes including
`stable_api_capability_removed`, `stable_api_endpoint_removed`,
`stable_api_capability_reclassified`, `stable_api_endpoint_reclassified`,
`stable_api_endpoint_required_capabilities_changed`,
`stable_api_endpoint_app_principal_changed`, `stable_api_deprecation_window_too_short`,
`stable_api_removal_window_too_short`, `stable_baseline_metadata_missing`, and
`stable_baseline_identity_changed`. Stable removal, undeclared stable-baseline mutation, current
metadata gaps, redaction/security blockers, and production-beta history gaps are not waiverable.

Release certification records descriptor-level stable deprecation metadata under
`platform-api.contract.details.stableDescriptorDeprecations`. The
`platform-api.deprecation-window-policy` evidence row exposes `descriptorErrors` and
`descriptorWarnings`; missing deprecation metadata, future `deprecatedSinceContractVersion`, and
too-short `removalContractVersion` windows are release blockers for Platform API 1.0 stable
descriptors.

Stability and audience terms are:

- `stable`: app-facing Platform API 1.0 surface with compatibility guarantees.
- `experimental`: app-facing but outside the Platform API 1.0 guarantee; app use requires explicit
  opt-in.
- `internal`: daemon implementation API; third-party apps cannot declare it.
- `operator-only`: host/Web Shell operator API; third-party apps cannot declare it, even with
  experimental opt-in.
- `deprecated`: still available but produces compatibility warnings.
- `scheduled-for-removal`: still available during a migration window, but excluded from new stable
  target use.

The stable baseline reference is maintained in
[platform-api-1.0-stable-reference.md](platform-api-1.0-stable-reference.md). Internal,
operator-only, app-vault, app-service, and Trust Graph Local RC entries may remain in the full
contract with explicit non-stable classifications, but they are not advertised as third-party
stable API.

## App manifest metadata

App manifests may declare optional API compatibility metadata:

```properties
api.minimumVersion=1
api.maximumTestedVersion=1
api.targetStability=stable
api.targetBaseline=1.0
api.experimentalCapabilitiesAccepted=false
```

Missing fields remain valid for old apps. `app.permissions` remains the authoritative capability
grant request; `api.optionalCapabilities` is advisory metadata for verification and review.
Stable-target manifests must not list non-baseline optional capabilities because the compatibility
verifier evaluates optional capability metadata too.

`api.minimumVersion` means the app expects at least that Platform API contract version.
`api.maximumTestedVersion` means the app was tested up to that contract version. A local node below
the minimum is incompatible. A local node above the maximum-tested version is a warning by default
and a failure in strict verification.

`api.targetStability=stable` means the app expects only capabilities in its named stable baseline.
`api.targetBaseline` is a canonical 1.x identity such as `1.0`; it is not a URL suffix or a
permission grant. An explicit stable target that omits the new field has the backward-compatible
effective target `1.0`, while the declaration remains recorded as omitted. Legacy manifests that
omit `api.targetStability` remain effective experimental metadata with no baseline and are not
silently reclassified as stable 1.0. `api.targetStability=experimental` means the app knowingly
uses non-stable app-facing API, and the missing stability declaration is reported when legacy API
compatibility metadata is otherwise present. `api.experimentalCapabilitiesAccepted=true` is still
required whenever an app declares experimental capabilities. Neither target accepts `internal` or
`operator-only` capabilities.

The integer minimum/maximum range and named baseline are verified together. A range that excludes
the baseline's complete candidate contract is incompatible. A candidate baseline named by an
experimental app remains preview-only until authenticated lifecycle evidence makes it active.

## Catalog metadata

Signed catalogs can mirror or summarize app API compatibility with optional entry fields:

```properties
app.<id>.api.minimumVersion=1
app.<id>.api.maximumTestedVersion=1
app.<id>.api.targetStability=stable
app.<id>.api.targetBaseline=1.0
app.<id>.api.experimentalCapabilitiesAccepted=false
```

Bundle manifest metadata remains authoritative for the app artifact. Catalog metadata preserves
the exact target-baseline declaration, and an explicit catalog/bundle baseline disagreement is a
hard verification failure. Old v1-v6 catalogs and catalogs without API metadata remain readable.
Catalogs that carry the explicit target-baseline field use the cumulative signed-catalog v7 format;
the field is not added to the closed v1-v6 formats. Target-baseline metadata never grants an
optional capability or manifest permission.

## Developer tooling

Create an offline snapshot:

```bash
crypta-app api snapshot --output build/platform-api-contract.json
```

Verify a staged bundle against the built-in current contract:

```bash
crypta-app compat verify --bundle-dir path/to/staged-app
```

Inspect a digest-verified registry, or produce a non-authorizing preview:

```bash
crypta-app api baseline inspect --output build/platform-api-baselines.json
crypta-app api preview \
  --proposal build/candidate-baseline-registry.json \
  --contract build/candidate-contract.json \
  --bundle-dir path/to/staged-app \
  --output build/platform-api-preview.json
```

Preview output is explicitly `preview` and `nonProduction`. It cannot activate a baseline,
graduate a descriptor, change runtime authorization, or stand in for protected release history.
The command hashes the exact supplied contract bytes and rejects a version-24 contract whose
`baselineRegistrySummary` does not match the candidate registry proposal.
See [Platform API 1.x compatibility operations](platform-api-1.x-compatibility-operations.md).

Verify against an explicit target snapshot:

```bash
crypta-app compat verify \
  --bundle-dir path/to/staged-app \
  --contract build/platform-api-contract.json \
  --baseline-registry build/platform-api-baselines.json
```

Verify a catalog entry descriptor and referenced bundle:

```bash
crypta-app compat verify \
  --catalog-entry descriptor.properties \
  --contract build/platform-api-contract.json \
  --baseline-registry build/platform-api-baselines.json
```

For version 24 and later, the command rejects a contract whose embedded registry digest, supported
baseline set, lifecycle statuses, or definition digests differ from the selected registry.
Historical snapshots that predate the registry summary remain readable.

`crypta-app validate --strict` also runs compatibility checks against the current contract.
Malformed `api.*` metadata is always a hard failure. Unknown future capability names, deprecated
or scheduled capabilities for experimental-target apps, a target above
`api.maximumTestedVersion`, and non-stability catalog-vs-bundle metadata mismatches are warnings by
default and failures with `--strict`. Experimental capability use without
`api.experimentalCapabilitiesAccepted=true`, stable targets that declare capabilities outside the
Platform API 1.0 baseline, scheduled-for-removal capability use by stable-target apps, internal
capability use, and operator-only capability use are always incompatible for third-party app
compatibility.

## Platform API and Web Shell display

Installed app summaries and catalog app summaries include an `apiCompatibility` object:

```json
{
  "minimumVersion": 1,
  "maximumTestedVersion": 2,
  "currentVersion": 2,
  "targetStability": "stable",
  "targetStabilityDeclared": true,
  "optionalCapabilities": [],
  "experimentalCapabilitiesAccepted": false,
  "declared": true,
  "status": "compatible",
  "warnings": []
}
```

Status values are `compatible`, `below_minimum`, `newer_than_tested`, `unknown`, and
`incompatible`. The Web Shell shows the status, current contract version, app minimum version,
maximum-tested version, optional capabilities, and warnings in app/catalog review cards.

## Release certification

`tools/release-certification/certify.py app-platform` now emits required
`platform-api.contract`, `platform-api.stable-baseline`,
`platform-api.stable-breaking-change-check`, `platform-api.compatibility-window`,
`platform-api.previous-contract-snapshot`, `platform-api.deprecation-window-policy`,
`platform-api.experimental-graduation-policy`, `platform-api.manifest-target-stability`,
`platform-api.first-party-stability-declarations`, and `platform-api.stable-reference-docs`
evidence. It generates a contract snapshot with `crypta-app api snapshot`, records descriptor
counts, stable baseline counts, non-stable entries, stable descriptor deprecation metadata, and
runs offline `crypta-app compat verify` checks for first-party staged apps and the generated sample
app. Release certification compares the current stable baseline against previous production
release evidence; production beta manifests set `requirements.history=true`, so missing previous
stable-baseline or compatibility-window evidence is a release blocker unless the existing release
waiver mechanism records an approved waiver. Profile publishing also has
separate release evidence: `app-platform.identity-profile-publish` for the profile-document route,
`app-platform.generated-document-insert` for the app-generated document insert route, and
`reference-app.profile-publisher` for the first-party Profile Publisher bundle. Networked content
has separate release evidence: `app-platform.content-fetch` for `POST /api/v1/content/fetch`,
`app-platform.content-subscriptions` for the v8 subscription routes,
`network-content.subscription-scheduler` for deterministic bounded scheduler behavior, and
`network-scale.app-network-budget`, `network-scale.content-fetch-budget`,
`network-scale.subscription-budget`, `network-scale.queue-pressure-backoff`,
`network-scale.trust-graph-import-budget`, `network-scale.social-inbox-multi-source-soak`, and
`network-scale.redaction` for PR-256 network-scale budget behavior, plus
`network-scale.rc-soak-summary` for attached simulated or live RC soak summary evidence, and
`reference-app.feed-reader` plus `reference-app.feed-reader-subscriptions` for the first-party
Feed Reader bundle. Social Inbox RC has separate evidence:
`app-platform.social-message-signing` for the bounded v11 AppVault social-message route,
`reference-app.social-inbox`, `reference-app.social-inbox-signed-message`,
`reference-app.social-inbox-subscriptions`, `reference-app.social-inbox-app-data`,
`reference-app.social-inbox-trust-annotations`, `app-services.registry`,
`app-services.grants`, `app-services.dependency-graph`, `app-services.grant-bundles`,
`app-services.grant-expiry-renewal`, `app-services.provider-revalidation`,
`app-services.trust-score-provider`, `reference-app.social-inbox-service-grant`,
`reference-app.social-inbox-service-dependency`, `reference-app.social-inbox-rc-threading`,
`app-platform.trust-social-beta-hardening`,
`app-services.web-shell`, `app-services.redaction`, `app-services.dependency-redaction`, and
`migration.social-mail-preview`.
Trust Graph Local RC has
separate evidence: `reference-app.trust-graph` for the first-party app,
`app-platform.trust-graph-preview` for the original v7 trust routes and SDK helpers,
`app-platform.trust-graph-rc-scope-and-safety` for the local RC scope, lifecycle, scoring, UI, and
redaction checks, `app-platform.trust-social-beta-hardening` for import preview, duplicate issuer,
anchor lifecycle, Social Inbox grant, schema migration, and redaction hardening, and
`app-platform.trust-statement-signing` for the bounded AppVault signing route
and redaction checks.

In release-candidate mode, missing contract evidence, snapshot generation failure, descriptor
parse failure, or strict compatibility verifier failure blocks promotion unless an explicit
release-manager waiver is recorded in the aggregate certification report.

## Experimental Mail additions (contract 25)

Contract 25 adds `mail.control`, `vault.mail.sign`, `vault.mail.open`, and
`vault.mail.storage`. `/api/v1` and frozen baseline 1.0 at contract 19 are unchanged;
baseline 1.1 is not activated. Mail requires explicit experimental admission and consent.

`POST /api/v1/mail/command` and `/api/v1/mail/result` are restricted to the own Mail browser principal.
`POST /api/v1/mail/poll`, `/api/v1/mail/reply`, `/api/v1/mail/create-identity`, `/api/v1/mail/sign`, `/api/v1/mail/open`,
`/api/v1/mail/seal-storage`, and `/api/v1/mail/open-storage` are restricted to the live Mail process.
The fixed broker is not a generic app-service RPC or endpoint proxy.
`GET /api/v1/queue/app-document-status` provides a typed process-only result for a stable app-prefixed
insert identifier; `inserted` is not delivery or reading. See the
[Mail design](mail-app-service-prototype.md) and [wire specification](mail-wire-specification.md).
