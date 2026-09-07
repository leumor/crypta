# App-service dependencies, bundles, and grants

This page describes the local app-service layer for narrowly scoped, platform-mediated app
workflows.

Contract v12 added service discovery, individual grants, redacted audit, and mediated invocation.
Contract v16 adds signed dependency metadata, dependency graph views, operator-review grant
bundles, grant expiry, renewal, and provider descriptor revalidation. The platform, not arbitrary
app localhost servers, mediates discovery, review, grant approval, invocation, audit, expiry,
renewal, and revocation.

The current proving path is:

```text
Trust Graph Local RC advertises trust.score
Social Inbox RC declares an optional trust.score dependency for Trust score annotations
Social Inbox requests the trust-annotations grant bundle
the operator reviews the dependency graph and approves the bounded bundle in Web Shell
Social Inbox invokes trust.score through /api/v1/app-services
expiry, revocation, provider drift, or a missing provider makes future invocations fail closed
Social Inbox keeps the annotation feature in a neutral unavailable state
```

This is not generic RPC, not a daemon plugin ABI, not remote service discovery, and not a localhost
proxy. There is no ambient localhost trust: apps do not receive ambient access to each other's run
directories, data stores, cache directories, launch tokens, private identity material, provider
process ports, raw service tokens, or app-data backup payloads.

## Provider descriptors

Providers declare optional service metadata in their signed `cryptad-app.properties` manifest.
The core manifest parser continues to ignore unknown keys; app-services code parses only the
`app.services.*` properties from installed signed manifests.

Trust Graph Local RC declares:

```properties
app.services.provides=trust-score
app.service.trust-score.id=trust.score
app.service.trust-score.name=Trust Score Service
app.service.trust-score.version=1
app.service.trust-score.kind=platform-adapter
app.service.trust-score.adapter=trust-graph.score
app.service.trust-score.scopes=score.read
app.service.trust-score.contexts=message-author,profile
app.service.trust-score.description=Returns a local redacted Trust Graph Local RC score summary for an app-provided public subject.
```

`trust-score` is only a path-safe manifest alias. `trust.score` is the public service id used by
discovery, dependency matching, grants, and invocation. `kind=platform-adapter` means the service
dispatches to a registered platform adapter. It does not forward HTTP traffic to a provider app
port.

Public descriptors expose provider app id/name/version, service id/name/version, kind, adapter,
scopes, supported contexts, description, stability, and availability. They must not expose
installed paths, data directories, cache directories, process tokens, private keys, raw stores, or
raw app data.

Provider compatibility is checked against:

- provider app id;
- service id;
- service version range;
- requested scopes;
- requested contexts;
- service kind and adapter;
- current provider installation and advertised availability.

The coordinator records a deterministic compatibility fingerprint over safe descriptor fields:
provider app id, service id, service version, kind, adapter, sorted scopes, sorted contexts, and
stability. It does not include installed paths, timestamps, runtime ports, process tokens, private
app data, or raw provider state.

## Consumer dependencies

Consumers can declare intended service requests in their signed manifest for operator visibility:

```properties
app.services.requests=trust-score
app.service-request.trust-score.provider=trust-graph
app.service-request.trust-score.service=trust.score
app.service-request.trust-score.scopes=score.read
app.service-request.trust-score.contexts=message-author
app.service-request.trust-score.purpose=Annotate Social Inbox message authors using the local Trust Graph Local RC score service.
```

Legacy manifests with only those fields still parse. The platform treats them as optional request
metadata so existing apps do not fail during review.

Contract v16 adds explicit dependency metadata:

```properties
app.service-request.trust-score.dependency.kind=optional
app.service-request.trust-score.dependency.required=false
app.service-request.trust-score.dependency.featureId=trust-score-annotations
app.service-request.trust-score.dependency.featureName=Trust score annotations
app.service-request.trust-score.dependency.reason=Annotates message authors with a local Trust Graph score when the operator approves the service bundle.
app.service-request.trust-score.dependency.degradeBehavior=disable-feature
app.service-request.trust-score.dependency.minServiceVersion=1
app.service-request.trust-score.dependency.maxServiceVersion=1
app.service-request.trust-score.dependency.grantBundle=trust-annotations
app.service-request.trust-score.dependency.grantExpiresAfter=PT720H
```

Dependency metadata is transparent review input, not authorization. It does not create, renew, or
approve a grant. The consumer still needs `app.services.read` for discovery, dependency, bundle,
and grant visibility, and `app.services.call` for bundle request, grant request, self-revoke, and
invocation routes.

The parser keeps the new fields bounded: aliases, app ids, service ids, scopes, contexts, feature
ids, bundle aliases, display text, and ISO-8601 durations are normalized or rejected. It rejects
duplicate request aliases, duplicate bundle aliases, invalid version ranges, unsafe durations, raw
paths, URLs, private insert URI forms, command-like strings, and unbounded lists.

## Dependency graph

The platform builds a deterministic dependency graph from installed signed manifests and current
provider descriptors.

Host/operator principals can view the full graph:

```text
GET /api/v1/app-services/dependencies
```

App principals can view only their own dependencies:

```text
GET /api/v1/app-services/dependencies/consumers/{consumerAppId}
```

Each app node contains app id, display name, version, and declared dependencies. Edges contain the
consumer app id, provider app id, service id, and current status. Status values include
`available`, `missing-provider`, `missing-service`, `version-mismatch`, `scope-mismatch`,
`context-mismatch`, `grant-pending`, `grant-active`, `grant-expired`, `revalidation-required`, and
`unavailable`.

Required dependencies can block install, update, or app start depending on their
`degradeBehavior`. Optional dependencies are shown as degraded when unavailable, but they do not
block app start. Social Inbox's Trust Graph dependency is optional and uses
`degradeBehavior=disable-feature`, so missing, expired, rejected, revoked, or revalidation-required
state disables Trust score annotations without hiding or reordering messages.

Graph JSON is path-free and redaction-safe. It contains app ids, service ids, bounded display
labels, scopes, contexts, version ranges, feature ids, grant ids, and status labels. It must not
include local paths, raw provider data, raw request bodies, launch tokens, bearer tokens, private
insert URIs, private keys, app-data backup payloads, raw Trust Graph statements, raw subject URIs,
or raw signatures.

## Consent, install, and update review

PR-253 exposes deterministic dependency graph and grant-bundle APIs for install, update, and app
review surfaces. Web Shell uses the same path-free graph and bundle records that app principals see
under their own scope. The unified consent layer now includes those graph and bundle records in
install, update, and service-grant previews. Required missing dependencies are marked with blocking
metadata; optional missing dependencies are marked as degraded.

Automatic update policy must not stage or apply a candidate that introduces a required service
dependency, a new grant bundle, provider descriptor drift, or `revalidation-required` state without
operator consent. Bundle approve, renew, reject, and defer decisions write redacted consent audit
events. See [user-consent-and-permission-upgrade-ux.md](user-consent-and-permission-upgrade-ux.md).

## Grant bundles

A grant bundle is an operator-review object for one consumer app's declared service dependencies.
It groups a bounded set of proposed grants into one review surface. A bundle id is not a bearer
secret, and a bundle proposal does not approve access.

Apps can request a pending bundle for their own declared dependencies. Host/operator principals can
list pending bundles, approve a bundle, reject a bundle, or renew/revalidate an approved bundle:

| Route | App capability or principal | Purpose |
| --- | --- | --- |
| `GET /api/v1/app-services/grant-bundles` | `app.services.read`; app principals see their own bundles only | List visible bundle proposals. |
| `POST /api/v1/app-services/grant-bundles` | `app.services.call`; host/operator may specify a consumer app | Request a bounded pending bundle. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/approve` | host/operator only | Approve a pending bundle after revalidating manifest and provider descriptors. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/reject` | host/operator only | Reject a pending bundle without leaving active grants. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/renew` | host/operator only | Revalidate dependencies and renew bundle-approved grants. |

Bundle creation accepts `consumerAppId` for host/operator callers, optional `bundleAlias`,
`includeOptional=true|false`, and bounded `purpose`. App principals cannot create, read, approve,
reject, or renew bundles for another app. Apps cannot approve or reject their own bundles.

Bundle approval revalidates the signed consumer manifest and current provider descriptor at
approval time. It creates or activates only grants that still match provider app id, service id,
version, scope, context, kind, and adapter. Repeated requests for the same consumer and dependency
set reuse a safe pending bundle instead of creating unbounded records.

Rejecting a bundle leaves no active grants. Optional dependencies may be rejected without blocking
app start. Required dependencies can block install, update, or app start according to the declared
degrade behavior and the surrounding install/update policy.

## Grant lifecycle

Grant records are bounded, deterministic, and safe to serialize in operator-facing JSON. They
record:

- `grantId`
- `consumerAppId`
- `providerAppId`
- `serviceId`
- scopes and contexts
- purpose
- status: `pending`, `active`, `revoked`, `inactive`, `expired`, or `revalidation-required`
- `bundleId` when a bundle created or renewed the grant
- `expiresAt` and `renewedAt` when the lifecycle has bounded expiry
- `compatibilityFingerprint`
- `providerServiceVersionAtApproval`
- created, updated, approved, revoked, and last-used timestamps
- use count
- optional token fingerprint for older grant metadata

PR-253 does not issue raw service bearer tokens. The authenticated app principal plus an active
grant record is the access boundary.

Grant behavior is default-deny:

- a consumer app can request a grant or bundle, which starts as `pending`;
- apps cannot approve their own grants or bundles;
- the host/operator approves, rejects, renews, or revokes in Web Shell;
- apps can list their own consumer grants and bundles;
- host/operator can list all grants, bundles, dependency graph entries, and redacted audit events;
- revocation, expiry, or provider descriptor drift takes effect on the next invocation attempt;
- if an app is uninstalled or app state is cleared, related grants become inactive.

Existing grant files without `expiresAt`, `bundleId`, `renewedAt`, compatibility fingerprint, or
provider approval version still load. Missing fields preserve prior behavior unless local policy
expires the grant. Malformed records fail closed instead of becoming active.

## Expiry, renewal, and revalidation

Dependency metadata may suggest `grantExpiresAfter`, but the platform caps the value with a local
maximum. Bundle-approved grants receive `expiresAt` when expiry is configured. Expired grants are
visible as `expired` and do not authorize invocation.

Renewal requires host/operator action. The platform does not silently renew. Renewal revalidates
the signed consumer manifest and current provider descriptor before extending or reactivating
bundle-approved grants.

Provider descriptor drift also fails closed. If the provider app updates and the descriptor no
longer satisfies the active grant's version range, scopes, contexts, kind, adapter, or
compatibility fingerprint, the effective status becomes `revalidation-required`. Invocation fails
until the operator explicitly renews or revalidates through bundle review.

## Platform API

Routes live under `/api/v1/app-services`:

| Route | App capability or principal | Purpose |
| --- | --- | --- |
| `GET /api/v1/app-services` | `app.services.read` | List public service descriptors and visible request metadata. |
| `GET /api/v1/app-services/dependencies` | `app.services.read`; host/operator sees all, app principals see their own graph | List dependency graph nodes and edges. |
| `GET /api/v1/app-services/dependencies/consumers/{consumerAppId}` | `app.services.read` with app scoping | Read one consumer's dependency graph without conflicting with provider service routes. |
| `GET /api/v1/app-services/grant-bundles` | `app.services.read` with app scoping | List visible grant bundles. |
| `POST /api/v1/app-services/grant-bundles` | `app.services.call`; host/operator may create for a consumer | Request a bounded grant bundle. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/approve` | host/operator only | Approve a bundle. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/reject` | host/operator only | Reject a bundle. |
| `POST /api/v1/app-services/grant-bundles/{bundleId}/renew` | host/operator only | Renew or revalidate a bundle. |
| `GET /api/v1/app-services/{providerAppId}/services` | `app.services.read` | List one provider's advertised services. |
| `GET /api/v1/app-services/{providerAppId}/services/{serviceId}` | `app.services.read` | Read one descriptor. |
| `GET /api/v1/app-services/grants` | `app.services.read` | List caller-visible grants. |
| `POST /api/v1/app-services/grants` | `app.services.call` | Request a pending individual grant. |
| `POST /api/v1/app-services/grants/{grantId}/approve` | host/operator only | Approve an individual grant. |
| `POST /api/v1/app-services/grants/{grantId}/revoke` | `app.services.call` for consumer self-revoke; host/operator for any grant | Revoke a grant. |
| `GET /api/v1/app-services/audit` | host/operator only | List redacted audit events. |
| `POST /api/v1/app-services/{providerAppId}/services/{serviceId}/invoke` | `app.services.call` | Invoke a registered adapter through an active grant. |

The Trust Score Service invocation accepts:

```text
subjectKind=identity
subjectUri=crypta:identity:example
context=message-author
scope=score.read
```

The response envelope includes provider app id, service id, grant id, status, invocation
timestamp, and a redacted score result. The result contains a subject URI hash instead of the raw
subject URI and does not include raw Trust Graph statement bodies, raw signatures, store paths,
private identity material, request bodies, tokens, or private insert URIs.

## SDK

Browser apps use `CryptaPlatform.services`:

```js
await CryptaPlatform.services.list();
await CryptaPlatform.services.get("trust-graph", "trust.score");
await CryptaPlatform.services.dependencies.list();
await CryptaPlatform.services.dependencies.get("social-inbox");
await CryptaPlatform.services.bundles.list();
await CryptaPlatform.services.bundles.request({
  bundleAlias: "trust-annotations",
  includeOptional: true,
  purpose: "Annotate message authors.",
});
await CryptaPlatform.services.grants.list();
await CryptaPlatform.services.invoke("trust-graph", "trust.score", {
  subjectKind: "identity",
  subjectUri: "crypta:identity:example",
  context: "message-author",
  scope: "score.read",
});
```

Host/operator contexts may also call the host-only bundle mutation helpers with an explicit
`formPassword`:

```js
await CryptaPlatform.services.bundles.approve(bundleId, { formPassword });
await CryptaPlatform.services.bundles.reject(bundleId, { formPassword });
await CryptaPlatform.services.bundles.renew(bundleId, { formPassword });
```

Those host-only SDK helpers omit the app browser-session header and submit the legacy
`formPassword` in the form body. The server enforces host/operator-only approval, rejection, and
renewal; app-facing helpers cannot bypass that policy.

The SDK wraps Platform API routes with form-encoded requests and keeps the app browser session in
memory. It does not log request bodies, cache raw service tokens, expose local paths, or call
provider app ports.

## Operator UI

Web Shell's installed apps view shows:

- advertised service descriptors;
- manifest-declared requests and dependencies;
- dependency graph edges, required/optional labels, feature names, and degrade behavior;
- bundle proposals and approve, reject, renew, or revalidate actions;
- pending, active, revoked, inactive, expired, and revalidation-required grants;
- grant expiry, renewal time, bundle id, and provider version at approval;
- consumer and provider app ids;
- service id, scopes, contexts, purpose, timestamps, last used time, and use count;
- redacted audit event type, reason code, status, and subject hash.

Operators can approve or reject pending bundles in one action, renew or revalidate approved
bundles, approve pending individual grants, and revoke pending or active grants. The UI must not
display raw app launch tokens, raw service bearer tokens, private insert URIs, private keys, raw
Trust Graph statement bodies, raw request bodies, raw subject URIs, raw signatures, app-data
backup payloads, or absolute local store paths.

## Reference apps

Trust Graph Local RC provides `trust.score` as a local-only RC service. It is not complete WoT, not
a moderation system, and not a compatibility bridge for old WebOfTrust, Freetalk, Sone, or
Freemail plugin APIs.

Social Inbox RC declares the optional Trust Graph dependency as `trust-annotations`, requests an
operator-reviewed bundle, invokes the service only through
`CryptaPlatform.services.invoke(...)`, and renders a neutral unavailable state when the dependency
is missing, pending, rejected, revoked, expired, inactive, or revalidation-required. Scores are
advisory annotations on local threaded message summaries; they do not hide messages, archive
content, block replies, alter subscription refresh, change sorting policy, or trigger fetches. The
app must not fall back to `CryptaPlatform.trust.score` or direct Trust Graph score routes when the
grant boundary denies access.

Former plugin authors should use
[legacy-plugin-migration-cookbook.md](legacy-plugin-migration-cookbook.md) for app-service
migration examples. The cookbook shows Social Inbox consuming Trust Graph `trust.score`, a generic
migrated app declaring an optional service dependency, provider-unavailable degradation, grant
revocation, provider descriptor revalidation, and support-bundle redaction.

## Security and evidence

Release evidence should prove descriptor parsing, legacy request parsing, dependency graph routes,
bundle creation, app-principal scoping, host/operator-only approval/rejection/renewal, rejected
bundle behavior, bundle-approved invocation, expiry denial, provider descriptor drift denial,
explicit renewal/revalidation recovery, Web Shell controls, SDK helpers, Social Inbox optional
dependency metadata, and redaction.

Required evidence IDs include:

```text
app-services.registry
app-services.grants
app-services.dependency-graph
app-services.grant-bundles
app-services.grant-expiry-renewal
app-services.provider-revalidation
app-services.trust-score-provider
reference-app.social-inbox-service-grant
reference-app.social-inbox-service-dependency
app-platform.trust-social-beta-hardening
app-services.web-shell
app-services.redaction
app-services.dependency-redaction
```

Evidence must use safe identifiers, counts, booleans, hashes, route names, status labels, and
reason codes. It must not include raw provider app data, Trust Graph store files, raw statement
bodies, raw signatures, raw request bodies, raw subject URIs, browser-session tokens, app process
tokens, form passwords, private keys, private identity material, private insert URIs, absolute
local paths, raw service tokens, or app-data backup payloads.

`app-platform.trust-social-beta-hardening` additionally checks that Social Inbox keeps Trust Graph
annotations behind this app-service grant path, stops score lookups when the grant is revoked or
requires revalidation, and documents its degraded but usable unscored state. The evidence also
checks that Trust Graph import preview and anchor lifecycle actions do not become an ambient
localhost trust channel for Social Inbox.

## Mail prototype boundary

Mail's own UI uses a fixed transient process channel, described in
[Mail worker channel](mail-worker-channel.md). The Mail process owns mailbox behavior and state.
No external Mail provider service or consumer proposal route is implemented or advertised; that
interface remains closed. Existing `trust.score` and its grants remain unchanged.
