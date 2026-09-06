# Platform JavaScript SDK

This document describes the browser-side `CryptaPlatform` SDK for app-owned static UI bundles.

## Scope

The SDK is a small, dependency-free JavaScript file for static app pages served from app-owned UI
origins. The preferred runtime path is an isolated loopback origin per static app, with
`/apps/{appId}/` retained as a same-origin compatibility fallback. The SDK carries the browser app
session token issued by app-owned UI bootstrap, but it is not the server-side authorization
boundary and it is not an AppHost process sandbox.

Static app bundles should load the staged SDK before app-specific JavaScript:

```html
<script src="./crypta-platform.js" defer></script>
<script src="./app.js" defer></script>
```

The first-party Queue Manager, Publisher, Site Publisher, Profile Publisher, Social Inbox RC,
Feed Reader, and Trust Graph Local RC bundles receive `crypta-platform.js` during their Gradle
`stageApp` tasks. The canonical source
lives in `platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js`.

The standalone developer CLI follows the same static filename. When `crypta-app init --ui-mode
static` can see the SDK resource, its template copies or vendors the file as
`static/crypta-platform.js` in the staged bundle. The scaffolded HTML should still load it with the
relative `./crypta-platform.js` path shown above.

The developer beta toolkit also serves scaffolded static bundles through `crypta-app dev`. That
mock server exposes both `/.well-known/cryptad-bootstrap.json` and
`/apps/{appId}/.well-known/cryptad-bootstrap.json`, then requires the SDK's
`X-Crypta-App-Session` header for mock Platform API calls. See
[developer-beta-toolkit.md](developer-beta-toolkit.md) for the local mock-server flow and its
limits.

## Third-party stable example

Third-party authors should start with the `hello-stable` template or the checked-in sample at
`samples/third-party/hello-stable-app/`. The sample declares
`api.targetStability=stable`, `api.experimentalCapabilitiesAccepted=false`, and
`app.permissions=platform.contract.read`, then reads `GET /api/v1/platform/contract` through
`CryptaPlatform.api.get("platform/contract")`.

See [examples/third-party-hello-stable.md](examples/third-party-hello-stable.md) for the concise
SDK snippet and [third-party-developer-beta-program.md](third-party-developer-beta-program.md) for
the full local test, lint, compatibility, submission, pre-review, and catalog-candidate flow.

## Bootstrap

Call `CryptaPlatform.bootstrap.load()` before using API helpers:

```js
await CryptaPlatform.bootstrap.load();
```

On the same-origin compatibility route, the SDK infers the app id from paths such as
`/apps/queue-manager/static/`. Isolated app origins normally pass or receive the app id through
bootstrap, and first-party apps still pass it explicitly:

```js
await CryptaPlatform.bootstrap.load({ appId: "queue-manager" });
```

On isolated app origins, bootstrap data comes from the current origin:

```text
GET /.well-known/cryptad-bootstrap.json
```

When Web Shell opens an isolated app, it first checks a token-free origin probe on the app loopback
listener from the current browser. If that probe is reachable, Web Shell sends an explicit launch
request through the admin compatibility route, which adds a short-lived launch proof to the app URL
fragment. The SDK reads `cryptadBootstrapNonce` from that fragment, keeps it only in memory, and
sends it to the same-origin bootstrap endpoint as `X-Crypta-App-Bootstrap-Nonce`. Directly opening a
public isolated `uiUrl` without that launch proof can load static assets, but bootstrap will not
issue an app browser-session token.

On the compatibility route, bootstrap data comes from:

```text
GET /apps/{appId}/.well-known/cryptad-bootstrap.json
```

The SDK keeps a sanitized in-memory copy of the bootstrap fields used by browser apps: `appId`,
`name`, `uiRoot`, `assetRoot`, `platformApiRoot`, `shellRoot`, `uiOrigin`, `uiOriginMode`,
`uiOriginStatus`, `sameOriginFallbackUrl`, and `browserSessionExpiresAt`. It reads
`browserSessionToken` into private in-memory state and does not expose it through
`CryptaPlatform.bootstrap.current()`. `CryptaPlatform.app.currentId()` returns the current app id
when it can be inferred or has been loaded.

The SDK does not write the browser session token to `localStorage`, `sessionStorage`, cookies, or
query strings. It also does not expose the bootstrap launch nonce through public SDK state.

## Platform API reads

`CryptaPlatform.api.url(path)` builds a URL beneath the bootstrap `platformApiRoot`, falling back to
`/api/v1/` when the root is missing or invalid. Isolated app bootstrap supplies an absolute local
admin Platform API root such as `http://127.0.0.1:<adminPort>/api/v1/`. Invalid roots such as
remote URLs, protocol-relative URLs, roots outside `/api/v1/`, and roots with query strings or
fragments are ignored.

Use `CryptaPlatform.api.get(path, options)` for JSON reads:

```js
const snapshot = await CryptaPlatform.api.get("queue", {
  params: { page: "downloads" },
});
```

Queue-oriented static apps can use the convenience wrapper:

```js
const snapshot = await CryptaPlatform.queue.snapshot({
  page: "downloads",
  sortBy: "identifier",
  reversed: true,
});
```

The SDK sends `Accept: application/json` and `X-Crypta-App-Session` with the in-memory browser
session token. Cross-origin API calls use `credentials: "omit"`; app-owned browser authentication
uses only the session header, not cookies or local-admin form credentials. The SDK normalizes
common Platform API error bodies into readable `Error` messages.

## Mutations

Mutating app-owned helpers submit `application/x-www-form-urlencoded` bodies and authenticate with
the same `X-Crypta-App-Session` header used for reads. They do not add the legacy local-admin
`formPassword` to app-owned UI requests. The host/operator-only app-service bundle approval,
rejection, and renewal helpers are the exception: they omit the app session header and send only an
explicit `formPassword` supplied by the host page.

```js
await CryptaPlatform.queue.directDownload(new FormData(form));
await CryptaPlatform.queue.mutate("queue/requests/remove", formData);
await CryptaPlatform.content.insertFile(formData);
await CryptaPlatform.content.insertDirectory(formData);
```

Profile Publisher uses the profile-specific helpers rather than constructing form bodies by hand:

```js
await CryptaPlatform.vault.identities.create({
  label: "My profile identity",
  scopes: ["metadata.read", "sign.domain-separated"],
});

const signedProfileResponse = await CryptaPlatform.vault.identities.createProfileDocument(
  identityId,
  {
    displayName,
    bio,
    website,
    avatarUri,
    contactUri,
    tags,
  },
);
const signedProfile = signedProfileResponse.profileDocument;

await CryptaPlatform.content.insertAppDocument({
  insertUri,
  identifier,
  document: signedProfile,
  contentType: "application/vnd.crypta.profile+json",
  targetFilename: "profile.json",
});
```

Social Inbox RC uses the bounded social-message helper instead of the process-only generic
identity-use route. Reply and thread behavior stays in the app: outgoing replies set the existing
`replyTo` field to a safe parent `msg-<sha256>` id, and no extra Platform API route is needed.

```js
const signedMessageResponse =
  await CryptaPlatform.vault.identities.createSocialMessageDocument(identityId, {
    channel: "general",
    subject,
    body,
    authorLabel,
    profileUri,
    replyTo,
    recipientFingerprint,
    tags,
  });

const signedMessage = signedMessageResponse.socialMessage;
```

`CryptaPlatform.vault.identities.createSocialMessageDocument` posts to
`app-vault/identities/{identityId}/social-message`, preserves SDK request options such as
`signal`, `headers`, `bootstrap`, `force`, and `refreshBootstrap`, and serializes only bounded
document fields. It does not accept a caller-selected signing purpose, signing domain, or raw
payload. The server fixes the domain to `crypta.social.message.v1`, and the helper normalizes the
route envelope so `signedMessageResponse.socialMessage` is the public signed document. Social apps
should keep inserted outbox documents bounded, render user content as text, and avoid storing raw
message bodies in release evidence, raw fetched social documents,
private insert URIs, private identity material, raw signatures, browser-session tokens, form
passwords, or local paths.

## App Services

Contract v12 adds `CryptaPlatform.services` for local app-service discovery, individual grant
requests, grant revocation, and mediated invocation. Contract v16 adds dependency graph and
grant-bundle helpers. These helpers wrap `/api/v1/app-services`; they do not create or cache
bearer tokens and they do not call provider localhost ports directly.

```js
const services = await CryptaPlatform.services.list();
const trustScore = await CryptaPlatform.services.get("trust-graph", "trust.score");
const dependencies = await CryptaPlatform.services.dependencies.list();
const ownDependencies = await CryptaPlatform.services.dependencies.get("social-inbox");
const bundles = await CryptaPlatform.services.bundles.list();
const grants = await CryptaPlatform.services.grants.list();

await CryptaPlatform.services.bundles.request({
  bundleAlias: "trust-annotations",
  includeOptional: true,
  purpose: "Annotate message authors with the local Trust Graph Local RC score service.",
});

const score = await CryptaPlatform.services.invoke("trust-graph", "trust.score", {
  subjectKind: "identity",
  subjectUri: "crypta:identity:example",
  context: "message-author",
  scope: "score.read",
});

await CryptaPlatform.services.grants.revoke("asg-111111111111111111111111");
```

Discovery, dependency graph reads, bundle listing, and grant listing require `app.services.read`.
Bundle requests, individual grant requests, and invocation require `app.services.call`, and
invocation also requires an active operator-approved grant checked on each call. A pending,
rejected, revoked, inactive, expired, missing, or no-longer-authorized grant makes the service call
fail. Apps cannot approve, reject, renew, or revalidate their own bundles; those actions are Web
Shell host/operator actions even though the SDK exposes convenience methods for host/operator
contexts:

```js
await CryptaPlatform.services.bundles.approve("asb-111111111111111111111111", {
  formPassword,
});
await CryptaPlatform.services.bundles.reject("asb-111111111111111111111111", {
  formPassword,
});
await CryptaPlatform.services.bundles.renew("asb-111111111111111111111111", {
  formPassword,
});
```

For the v16 proving path, Social Inbox RC declares an optional `trust-annotations` bundle for
Trust score annotations and invokes `trust-graph` / `trust.score` only through
`CryptaPlatform.services.invoke(...)`. The Trust Graph Local RC provider advertises a
`platform-adapter` descriptor, so the platform dispatches to a built-in Trust Graph score adapter
instead of proxying an arbitrary app server. Bundle approval records a safe descriptor
compatibility fingerprint and may attach expiry. Responses include service-call metadata and a
redacted score result. Apps should render missing, rejected, revoked, expired, or
revalidation-required grants as neutral unavailable states and must not fall back to direct Trust
Graph score routes after revocation. Score results are annotations only; Social Inbox must not use
them to hide messages, block replies, archive threads, route network behavior, or refresh
subscriptions.

Feed Reader uses the v8 feed and content subscription helpers instead of constructing fetch forms
by hand:

```js
const text = await CryptaPlatform.content.fetchText({
  uri: feedUri,
  maxBytes: 262144,
  timeoutMillis: 30000,
  purpose: "feed-source",
});

const binary = await CryptaPlatform.content.fetchBase64({
  uri: feedUri,
  format: "base64",
});

const fetched = await CryptaPlatform.feed.fetchSnapshot({
  uri: feedUri,
  maxBytes: CryptaPlatform.contentFormats.feedSnapshot.maxDocumentBytes,
  timeoutMillis: 30000,
});

const feed = fetched.snapshot;

await CryptaPlatform.feed.publishSnapshot({
  insertUri,
  identifier,
  snapshot: feedDocument,
});

const { subscription } = await CryptaPlatform.content.subscriptions.create({
  uri: "USK@example/feed/0/feed.json",
  label: "Example feed",
  pollIntervalSeconds: 1800,
  maxBytes: 262144,
  timeoutMillis: 30000,
});

const subscriptionId = subscription.subscriptionId;
const subscriptions = await CryptaPlatform.content.subscriptions.list();
const refreshed = await CryptaPlatform.content.subscriptions.refresh(subscriptionId);
await CryptaPlatform.content.subscriptions.pause(subscriptionId);
await CryptaPlatform.content.subscriptions.resume(subscriptionId);
await CryptaPlatform.content.subscriptions.remove(subscriptionId);
```

`CryptaPlatform.feed.fetchSnapshot` wraps `POST /api/v1/content/fetch`, requires
`content.fetch`, and returns both the raw fetch response and the parsed snapshot. The Feed Reader
reference app uses `content.fetchText` with the broader 262144-byte route bound for raw RSS, Atom,
and plain text sources, then applies the 65536-byte profile cap only when the fetched body declares
a `crypta.feed.snapshot.*` profile type.
`CryptaPlatform.content.fetchText` and `CryptaPlatform.content.fetchBase64` call the same route
with the app browser session header and return the JSON fetch response. Feed apps should pass
Crypta content keys only, including `CHK@`, `SSK@`, `USK@`, `KSK@`, and matching `crypta:` forms;
the key-type prefix is accepted case-insensitively, and the daemon rejects local files, arbitrary
HTTP(S) URLs, loopback/LAN URLs, and absolute local paths for app principals.
`CryptaPlatform.content.subscriptions.*` wraps `/api/v1/content/subscriptions`, requires
`content.subscribe`, and preserves SDK request options such as `signal`, `headers`, `bootstrap`,
`force`, and `refreshBootstrap`. Creating or refreshing a subscription also requires
`content.fetch`. The helper validates `subscriptionId` path segments, builds form parameters with
`URLSearchParams`, and returns only the API's safe subscription metadata. Subscription sources are
USK-only (`USK@...` or `crypta:USK@...`); this helper is not arbitrary HTTP/HTTPS fetch support
and is not a generic crawler.
`CryptaPlatform.feed.publishSnapshot` wraps the generated-document insert path and requires
`content.insert.app-document` plus `queue.write`. Feed apps should render summaries, item counts,
timestamps, and sanitized errors, but they must not persist raw feed bodies, raw request bodies,
private insert URIs, app process tokens, browser-session tokens, form passwords, queue HTML, raw
fetched content, or local paths in browser storage or release evidence.

Durable app-owned state should use the v9 app-data helpers:

```js
await CryptaPlatform.data.records.putJson({
  namespace: "ui-state",
  key: "reader-state",
  schemaVersion: 1,
  value: {
    selectedSubscriptionId,
    sourceCount,
  },
});

const state = await CryptaPlatform.data.records.getJson("ui-state", "reader-state");
const records = await CryptaPlatform.data.records.list({ namespace: "ui-state", limit: 25 });
const namespaces = await CryptaPlatform.data.namespaces.list();
const status = await CryptaPlatform.data.status();
```

`CryptaPlatform.data.status()`, `CryptaPlatform.data.namespaces.*`,
`CryptaPlatform.data.records.*`, `CryptaPlatform.data.export()`, and
`CryptaPlatform.data.import()` wrap `/api/v1/app-data`. Reads require `app.data.read`; mutations,
schema migration metadata, namespace clears, and imports require `app.data.write`. The helpers
validate namespace and key path segments, use `URLSearchParams` for form bodies, bound obvious
integer fields, and preserve standard SDK request options such as `signal`, `headers`,
`bootstrap`, `force`, and `refreshBootstrap`.

The SDK never writes durable app state to `localStorage` or `sessionStorage`. App data is for
bounded app-owned user state, not secrets or identity material. Use AppVault for private material
and keep raw app-data values out of release evidence.

Trust Graph Local RC uses the trust helpers:

```js
const status = await CryptaPlatform.trust.status();
const anchors = await CryptaPlatform.trust.anchors.list();
await CryptaPlatform.trust.anchors.add({
  issuerFingerprint,
  label,
  source: "manual",
});
await CryptaPlatform.trust.anchors.deprecate(issuerFingerprint, { reasonCode: "local-policy" });
await CryptaPlatform.trust.anchors.revoke(issuerFingerprint, { reasonCode: "local-policy" });
await CryptaPlatform.trust.anchors.reactivate(issuerFingerprint);
const preview = await CryptaPlatform.trust.previewImport({
  document: trustStatementJson,
  sourceLabel: "pasted statement",
});
await CryptaPlatform.trust.importStatement({
  document: trustStatementJson,
  sourceUri,
  sourceLabel: "fetched",
});
const imported = await CryptaPlatform.trust.importUri({
  uri,
  sourceLabel: "reviewed statement",
  expectedDocumentFingerprint: preview.candidateSummaries[0].documentFingerprint,
  maxBytes: 65536,
});
const score = await CryptaPlatform.trust.score({
  subjectKind: "profile",
  subjectUri,
  context: "profile",
  includeEvidence: true,
});
const audit = await CryptaPlatform.trust.audit.list({ limit: 25 });
```

Trust import preview responses expose capped counts and redacted candidate summaries:
`candidateStatementCount`, accepted/rejected counts, duplicate and duplicate issuer counts,
conflict counts, revoked/deprecated/expired counts, approximate score impact, warning codes, and
`rawContentDiscarded`. Trust import responses expose document fingerprints, payload hashes,
verification status, and redacted source URI summaries plus `sourceUriHash` when a source URI was
supplied. They do not echo the raw URI, raw fetched body, raw statement JSON, or raw signature
value. Preview does not mutate graph state; apps should commit through the normal import route only
after the operator approves any material-risk consent snapshot.

To create and publish a bounded trust statement, apps should use the trust exchange helper instead
of constructing API forms directly:

```js
await CryptaPlatform.trust.exchange.publish({
  identityId,
  subjectKind: "profile",
  subjectUri,
  context: "profile",
  score: 50,
  confidence: 80,
  reason,
  tags,
  expiresAt,
  insertUri,
  identifier,
});
```

`CryptaPlatform.trust.publishStatement` and `CryptaPlatform.trust.exchange.publish` call the
bounded AppVault trust-statement route when given an identity and payload, queue the public
statement through `insertAppDocument`, default `contentType` to
`application/vnd.crypta.trust+json` and `targetFilename` to `trust.json`, and import the local
public statement summary into the durable trust graph backend with source `local-publish`.

For mutable URI sources, apps should preview with `CryptaPlatform.trust.previewImport({ uri, ... })`,
retain only the redacted candidate `documentFingerprint`, and pass it as
`expectedDocumentFingerprint` to `importUri` or `trust.exchange.fetchAndImport`. The Platform API
rejects the commit with `trust_import_preview_stale` if the fetched document no longer matches the
preview.

`CryptaPlatform.trust.exchange.fetchAndImport` is an alias for the URI import workflow.
`CryptaPlatform.trust.exchange.subscriptions.*` wraps the content subscription helpers with a
trust-statement default label:

```js
await CryptaPlatform.trust.exchange.fetchAndImport({
  uri,
  expectedDocumentFingerprint,
  maxBytes: 65536,
});
await CryptaPlatform.trust.exchange.subscriptions.create({ uri, maxBytes: 65536 });
await CryptaPlatform.trust.exchange.subscriptions.refresh(subscriptionId);
await CryptaPlatform.trust.exchange.subscriptions.pause(subscriptionId);
await CryptaPlatform.trust.exchange.subscriptions.resume(subscriptionId);
await CryptaPlatform.trust.exchange.subscriptions.remove(subscriptionId);
```

Trust helpers require the corresponding manifest capabilities: `trust.read` for status, anchors,
subjects, statements, audit, and score reads; `trust.write` for import and anchor mutation;
`content.fetch` for URI import, URI import previews, and subscription refresh/create;
`content.subscribe` for subscription metadata and lifecycle; `content.insert.app-document` plus
`queue.write` for publication; and `vault.identities.read` plus `vault.identities.use` for bounded
trust-statement signing. Apps should render pasted trust fields as text, keep document sizes
bounded, and avoid
storing raw trust documents from real users, raw fetched bodies, raw request bodies, signatures,
private insert URIs, private identity material, browser-session tokens, form passwords, or local
paths in browser storage or release evidence. Imported statements that lack a verifiable AppVault
preview signature are still visible as evidence, but the local scorer marks them non-contributing.

`app-vault/identities` creates an app-owned identity for an authorized static app browser session.
`app-vault/identities/{identityId}/profile-document` asks Cryptad to create the profile document
without exporting private identity material. `app-vault/identities/{identityId}/social-message`
asks Cryptad to create a bounded `crypta.social.message.v1` signed message document for the
selected identity without exposing generic browser signing. `queue/inserts/app-document` queues app-generated
document content with `content.insert.app-document` instead of local source-path authority. The SDK
Base64-encodes the JSON document for `insertAppDocument` and preserves the same
`X-Crypta-App-Session` header path as other browser mutations. Apps should render returned status
and queue metadata, but should not persist raw profile documents, signatures, browser-session
tokens, private insert URIs, or request bodies in browser storage or release evidence.

`CryptaPlatform.api.postForm(path, formDataOrParams)` and
`CryptaPlatform.api.deleteForm(path, formDataOrParams)` are available for other app-browser
Platform API form mutations. If no browser session token is available, the SDK rejects the call
before it sends a request.
When an in-memory browser session is still live, mutation helpers reuse it instead of forcing a new
bootstrap exchange. This avoids depending on the short-lived isolated-origin launch nonce after the
app tab is already open.

The helper accepts `FormData`, `URLSearchParams`, arrays of pairs, or plain objects. Non-string
`FormData` entries such as `File` values are not submitted because the current Platform API bridge
is text-form oriented.

## Errors

Use `CryptaPlatform.api.errorMessage(error)` when rendering failures:

```js
try {
  await CryptaPlatform.queue.directDownload(new FormData(form));
} catch (error) {
  status.textContent = CryptaPlatform.api.errorMessage(error);
}
```

The SDK recognizes these Platform API response shapes:

```json
{ "error": "message" }
{ "error": { "message": "message" } }
{ "message": "message" }
{ "detail": "message" }
```

When the response body does not contain a message, the SDK falls back to the HTTP status and status
text.

`401 invalid_app_browser_session` means the in-memory browser session is missing, expired, unknown,
or stale. The SDK clears the in-memory token and raises an error marked with
`code="invalid_app_browser_session"` and `sessionRefreshRequired=true`. First-party apps should
surface that as a reload or session-refresh condition.

`403 origin_mismatch` means the Platform API rejected the browser session because the request
origin did not match the origin bound into the session. Apps should tell the user to reopen the app
from Web Shell instead of retrying with stored state.

## HTML fragments

Some queue endpoints still return legacy HTML fragments in JSON. Use
`CryptaPlatform.dom.sanitizeFragment(html)` before inserting those fragments into the page:

```js
const fragment = CryptaPlatform.dom.sanitizeFragment(snapshot.contentHtml);
container.replaceChildren(fragment);
```

The sanitizer removes executable and document-control elements such as `script`, `style`,
`template`, `iframe`, `object`, `embed`, `link`, `meta`, and `base`. It also removes event handler
attributes, inline `style`, `srcdoc`, and cross-origin `href`, `src`, `action`, and `formaction`
values. Relative links, hash links, query-only links, and same-origin absolute paths remain
available for app-owned handlers.

This sanitizer is intentionally small and deterministic. It is only meant for the daemon-provided
legacy fragments used by app-owned UI, not as a general-purpose sanitizer for arbitrary untrusted
HTML.

## Security boundary

The SDK runs in the app-owned browser origin. In the preferred Phase 6 path that origin is a
per-app loopback origin distinct from the Web Shell/admin origin. The Platform API still lives on
the admin origin and accepts app-browser calls only through restricted CORS plus
`X-Crypta-App-Session`. The same-origin `/apps/{appId}/` route remains a compatibility fallback,
not the preferred third-party app UI boundary.

AppHost process launch tokens such as `CRYPTAD_APP_TOKEN` are not exposed to browser apps, SDK
state, app summaries, or bootstrap JSON. Browser code receives route metadata and an app browser
session token bound to the expected app origin. Permission enforcement and audit for
app-originated API calls remain server-side Platform API behavior, not a browser SDK guarantee.

## First-party examples

Queue Manager loads a snapshot and renders the sanitized legacy fragment:

```js
await CryptaPlatform.bootstrap.load({ appId: "queue-manager" });
const snapshot = await CryptaPlatform.queue.snapshot({ page: "downloads" });
queueContent.replaceChildren(CryptaPlatform.dom.sanitizeFragment(snapshot.contentHtml));
```

Publisher queues a local file insert with the app browser session established by bootstrap:

```js
await CryptaPlatform.bootstrap.load({ appId: "publisher" });
const formData = new FormData(fileForm);
const result = await CryptaPlatform.content.insertFile(formData);
```

These apps keep their own UI state, sort handling, key export behavior, and legacy form filtering.
The SDK owns only bootstrap, app-browser API transport, mutation form submission, error parsing,
and conservative fragment sanitization.

Site Publisher uses the same browser SDK content helpers for a content-oriented reference workflow:
`CryptaPlatform.content.insertDirectory`, `CryptaPlatform.content.insertFile`, and
`CryptaPlatform.queue.snapshot({ page: "uploads" })`.

## Content profile verification

`CryptaPlatform.profile.verifyDocument(value)` verifies a bounded signed profile locally using
Web Crypto and returns the verified public document. It reconstructs the profile payload, AppVault
frame and key fingerprint; failure rejects the promise. It grants no trust or fetch authority.
See the [content profile review](trust-social-stable-profile-review.md) for field semantics and
actual first-party consumer coverage. The helper does not expand the frozen Platform API baseline.
