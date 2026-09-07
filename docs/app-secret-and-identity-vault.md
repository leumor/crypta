# App secret and identity vault

This document describes the app-facing secret and identity vault model for local Cryptad apps.

## Scope

The app vault is a local Platform API capability boundary for app secrets and app identities. It is
not a remote key-management service, a hardware-backed secure enclave, a browser credential store,
or an OS process sandbox. AppHost sandboxing, app-owned browser origins, and app-token
authorization still apply as separate controls.

The local vault model and storage value types live in `:platform-appvault` under
`network.crypta.platform.appvault`. Platform API handlers consume that leaf but remain responsible
for route authentication, capability checks, and response redaction.

The vault capability names are:

| Capability | Purpose |
| --- | --- |
| `vault.secrets.read` | Read app-granted secret metadata and secret values. |
| `vault.secrets.write` | Create, update, rotate, or delete app-owned secret values. |
| `vault.identities.read` | Read app-granted identity metadata and public identity material. |
| `vault.identities.create` | Create app-owned identities. |
| `vault.identities.use` | Use an app-granted identity for signing or identity-scoped work without exporting private material. |
| `vault.identities.manage` | Host/operator-only identity management, including renaming, rotating, disabling, deleting, or changing grants. |

Third-party app manifests may request the app-facing vault capabilities in the table above except
`vault.identities.manage`. Developer tooling rejects `vault.identities.manage` in app manifests
because it is host/operator-only Platform API surface, not app-facing compatibility surface.

`app.permissions` remains the app's grant request. The Platform API authorization path remains
server-side and default-deny: a valid process token or browser session is not enough unless the
installed app's manifest and local grant state allow the required vault capability.

## App-owned and shared identities

An app-owned identity is created for one app. The app can use it only through the vault APIs and
only while its active grant still includes the required identity capability. App-owned identities
are the normal choice for app-local publishing profiles, signing keys, or account material that
should not be shared with other apps.

A shared identity is operator-controlled identity material that more than one app may be allowed to
read or use. Shared identity access requires an explicit grant to each app. A grant to one app does
not imply access by another app, even when both apps are signed by the same publisher or installed
from the same catalog.

Apps should treat identity private material as non-exportable. `vault.identities.use` is the
preferred shape for signing or identity-bound operations because the app asks Cryptad to perform
the operation and does not receive the private key bytes.

## Profile publishing routes

Profile Publisher uses the app-vault identity routes to keep profile signing inside Cryptad while
still allowing a static app UI to drive the workflow.

```text
POST /api/v1/app-vault/identities
POST /api/v1/app-vault/identities/{identityId}/profile-document
```

`POST /api/v1/app-vault/identities` creates an app-owned identity for the calling app. It is
browser-safe for app-owned static UIs when the browser principal is bound to that app and the
manifest/grant state includes `vault.identities.create`. The response exposes identity metadata and
public material only; it does not return private keys, seeds, recovery phrases, process tokens,
browser-session tokens, form passwords, or local vault paths.

`POST /api/v1/app-vault/identities/{identityId}/profile-document` asks Cryptad to produce a
profile document for an identity the app is allowed to see and use. The route requires
`vault.identities.read` plus `vault.identities.use` and must keep private identity material inside
the vault. It may return a profile document suitable for app display or insertion, but
release-certification evidence must record only path-free booleans, route names, capability names,
counts, and sanitized status. Do not place raw request bodies, private keys, identity seeds,
recovery phrases, signatures, tokens, form passwords, or local staging paths in evidence.

Profile Publisher inserts the generated document through the queue app-document insert route
instead of writing a temporary local file path into the request. See
[platform-api-surface.md](platform-api-surface.md) and
[platform-api-contract.md](platform-api-contract.md) for the route family contract.

## Trust statement signing route

Trust Graph Local RC uses a separate bounded identity-use route:

```text
POST /api/v1/app-vault/identities/{identityId}/trust-statement
```

The route requires `trust.write`, `vault.identities.read`, and `vault.identities.use`. It accepts
only the documented trust statement fields: subject kind/URI, optional subject fingerprint,
context, score, confidence, reason, tags, optional expiry, and optional issuer profile URI.
Cryptad generates `issuedAt`, canonicalizes the bounded payload as
`crypta.trust.statement.v1\n<canonical-payload-json>`, and asks AppVault to sign that domain only.
The signed payload includes the issuer public verification key so later imports can verify that the
signature matches the anchored fingerprint before using the statement for scoring.

This route is not generic arbitrary signing and does not make the process-only identity-use route
browser-safe. The response may include the public trust statement, public identity metadata,
payload hash, and fixed signing domain. It must not expose private keys, seeds, recovery phrases,
vault file paths, raw generic signing inputs, app process tokens, browser-session tokens, form
passwords, or raw request bodies. Release-certification evidence should record the route name,
capability labels, fixture hashes, and redacted checks rather than raw trust statement bodies or
raw signatures.

## Social message signing route

Social Inbox RC uses a separate bounded identity-use route for threaded social inbox messages:

```text
POST /api/v1/app-vault/identities/{identityId}/social-message
```

The route requires `vault.identities.read` and `vault.identities.use`. It accepts only the
documented `crypta.social.message.v1` plain-text message fields, generates `createdAt` from the
server clock, fixes the signing domain to `crypta.social.message.v1`, and rejects caller-selected
signing domains, raw payload bytes, and arbitrary signing purposes. It is not a generic browser
signing API and it does not make the process-only identity-use route browser-safe.

The response may include the public signed social message document, public identity metadata,
payload hash, public verification key, and public signature bytes. It must not expose private
keys, seeds, recovery phrases, vault file paths, raw generic signing inputs, app process tokens,
browser-session tokens, form passwords, raw request bodies, or private insert URIs. Release
certification should record route names, capability labels, bounds, fixture hashes, and redacted
checks rather than raw social message bodies, raw fetched content, raw profile documents, raw
signatures, or private identity material. See
[social-inbox-reference-app.md](social-inbox-reference-app.md).

## Process and browser restrictions

App process calls authenticate with the current AppHost launch token in `CRYPTAD_APP_TOKEN`.
Cryptad injects that token only into the child process environment. The token is not exposed in
static UI bootstrap JSON, Web Shell bootstrap, app summaries, app audit entries, runtime status,
process-log responses, release-certification output, or diagnostics.

Static browser UI calls authenticate with the browser app session from app-owned UI bootstrap and
send it with `X-Crypta-App-Session`. Browser sessions are not process launch tokens and do not
grant host/operator authority. Browser sessions are bound to one installed static app, its current
manifest permissions, and the expected app UI origin.

Vault APIs must not return process launch tokens, browser session tokens, local-admin form
passwords, raw secret values in audit entries, identity private keys, seed phrases, recovery
phrases, host filesystem paths, catalog scratch paths, or signing-key material through UI
bootstrap, Web Shell summaries, logs, diagnostics, or release evidence.

Static browser UI can request vault-backed operations only through Platform API calls authorized
for that app browser principal. It cannot bypass process/browser restrictions by reading AppHost
environment variables or local vault files.

## At-rest local protection limits

Vault data is local node data at rest. Local protection depends on the host operating system, the
daemon account, filesystem permissions, backups, disk encryption, and operator handling. It does
not protect against malware running as the same OS user, a compromised daemon process, a debugger
attached to the process, a stolen unlocked account, or plaintext values that an app intentionally
copies into its own files or network requests.

Cryptad should avoid exposing vault storage paths and raw vault values through APIs and reports,
but path redaction and log redaction are not a general secret scanner. Apps remain responsible for
not printing secrets, identity seeds, recovery phrases, or private identity material to their own
logs.

## Grant lifecycle

Vault grants are evaluated against the active installed app manifest and local grant state.

During update, existing grants remain usable only for capabilities that the updated manifest still
declares. Newly added vault capabilities are permission deltas and require the same install/update
review path as other new app permissions. Removing a vault capability from the manifest makes the
corresponding grant inactive for that installed version.

Rollback restores the immutable installed bundle. It does not roll back vault records, app data,
cache, process logs, browser state, or operator grant decisions. After rollback, effective vault
access is recalculated from the rolled-back manifest and current local grant state.

Uninstall revokes active process tokens, browser sessions, and app grants, and the default v1
policy purges app-owned secret values for that app id. A later reinstall is a new grant lifecycle
event: the app must request capabilities in its manifest, and the operator or policy gate must
grant them again before vault APIs are available. Reinstall must not silently recover shared-identity
grants or app-owned secret values from a previous install.

Other app-owned vault records should either be removed during uninstall or retained only through an
explicit, operator-visible retention policy. Retained records must not become accessible to a new
install until that install receives fresh grants.

## Audit and redaction

Vault authorization decisions should be visible in the app audit model with the app id,
authentication source, route family, action, required capabilities, decision, status, and reason
code. Audit entries must not include raw secret values, identity private keys, seed phrases,
recovery phrases, request bodies, full query strings, app process tokens, browser session tokens,
form passwords, signatures, or local filesystem paths.

Release-certification and developer-tooling output may record the vault capability names and
path-free counts or booleans. It must redact secret values, private identity material, recovery
phrases, private insert URIs, command-line key material, app/session/process tokens, local vault
paths, signatures, absolute staging paths, and raw request bodies.

## Future extension point

The vault model is intentionally small enough to support future app families without exporting raw
private material. Content publishing can use identities for author signatures, social apps can use
shared identities for profiles or contact-level signing, and mail apps can use vault-managed
account identities or per-recipient secrets. New content, social, or mail routes should add their
own capability checks while keeping the same process/browser restrictions, grant lifecycle, audit,
and redaction rules.

## Experimental Mail identities

Mail adds independently generated `mail-signing-v1`, `mail-recipient-v1` and `mail-storage-v1`
identities. Existing generic signing grants authorize none of their private operations. The fixed
process-only Mail operations enforce owner, account, role, current grants and bounded wire inputs;
keys remain in the existing encrypted vault. See [Mail vault boundary](mail-vault-boundary.md).
Default uninstall deletes these identities even with preserved app data. A data-only backup cannot
restore them or make retained ciphertext readable after key loss.
