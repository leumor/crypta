# Durable app data store

This document describes the bounded app-owned data store exposed through Platform API contract v9.

## Scope

Site Publisher adds a narrow guarded dataset in `sharesite-drafts`, schema 1, key `dataset`.
The owning app must check `status.sharesiteWriteGuard=1` before submitting a draft write. Its
record POST uses `writeIntent=preview|commit`, `writeMode=import|edit|undo|restore`,
`ifMatchSha256=absent|<current-private-digest>`, and `backupReady=true`; commit also sends the
returned `writePreviewId`. Preview does not create a namespace or record. Consent expires after
five minutes or a daemon restart, and binds exact proposed bytes, all current app-data summaries,
installed signed bundle identity, permissions, quota, schema, and operation mode.

The service holds its app-data monitor and AppHost's verified installed-bundle guard through
commit. The file store fails closed when atomic generation-pointer replacement is unavailable.
Import and restore add only non-colliding operations; edit preserves lineage; undo changes one
operation to an enduring tombstone and refuses edited imported drafts. Generic app-facing import
and delete cannot bypass this namespace's guard. An interrupted first commit may leave empty
namespace metadata, but the visible dataset is old or complete. A failed response after pointer
publication requires reading current state before retrying.

This behavior is a pilot extension discovered by its explicit marker, not a new stable baseline.
The immutable Platform API 1.0 capability set remains unchanged. See the
[Sharesite pilot runbook](real-legacy-plugin-migration-pilot.md).

The durable app data store is for app-owned user state that should survive daemon restarts, app
updates, and live catalog refreshes. Typical records include Feed Reader source lists, Profile
Publisher drafts, publish summaries, selected subscription ids, UI filters, and redacted import
summaries.

The store is not a filesystem API, database engine, cache, crawler, or secret vault. Apps must not
store private identity material, seed material, private keys, private insert URIs, browser session
tokens, AppHost process tokens, form passwords, or raw vault secrets in app-data records. Use
[app-secret-and-identity-vault.md](app-secret-and-identity-vault.md) for secrets and identity
material.

## Capabilities

Apps must declare explicit app-data capabilities in `app.permissions`:

| Capability | Grants |
| --- | --- |
| `app.data.read` | Read the caller app's status, namespace metadata, records, and bounded exports. |
| `app.data.write` | Create, replace, delete, import, clear, and record schema migration metadata for the caller app's own records. |

All app-data routes require an app process principal or app browser-session principal. Host/operator
requests are not an app-data bypass. The route implementation derives the app id from the
authenticated principal, so an app cannot name or access another app's records through the API.

The file-backed daemon store lives in host-managed app-platform storage, not inside the
`CRYPTAD_APP_DATA_DIR` tree that an app process can mutate directly. Apps access durable records
only through the Platform API and SDK. Operator uninstall choices still control cleanup:
`preserveData=true` keeps both the app-visible persistent data directory and the host-managed
durable app-data records.

## Routes

The route family is mounted under `/api/v1/app-data`:

| Method and route | Capability | Result |
| --- | --- | --- |
| `GET /api/v1/app-data/status` | `app.data.read` | App id, record count, namespace count, stored bytes, effective caps, quota status, and warnings. |
| `GET /api/v1/app-data/namespaces` | `app.data.read` | Namespace metadata summaries. |
| `GET /api/v1/app-data/namespaces/{namespace}` | `app.data.read` | One namespace plus bounded migration history. |
| `POST /api/v1/app-data/namespaces/{namespace}/schema` | `app.data.write` | Records a schema-version update or migration summary. |
| `DELETE /api/v1/app-data/namespaces/{namespace}` | `app.data.write` | Deletes all records and metadata for that namespace. |
| `GET /api/v1/app-data/records` | `app.data.read` | Bounded record summaries, optionally filtered by `namespace`, `limit`, and `cursor`. |
| `GET /api/v1/app-data/records/{namespace}/{key}` | `app.data.read` | One record with metadata and a bounded value representation. |
| `POST /api/v1/app-data/records` | `app.data.write` | Creates or replaces one record. |
| `DELETE /api/v1/app-data/records/{namespace}/{key}` | `app.data.write` | Deletes one record. |
| `GET /api/v1/app-data/export` | `app.data.read` | Bounded JSON export payload with base64 record values. |
| `POST /api/v1/app-data/import` | `app.data.write` | Imports a bounded export payload in `merge` or `replaceNamespace` mode. |

Mutations use `application/x-www-form-urlencoded` form parameters. The router does not accept host
filesystem paths, arbitrary JSON request bodies, or unbounded raw request bodies for this route
family.

## Records

Records are scoped by app id, namespace, and key. Namespaces and keys are logical identifiers, not
filesystem paths. Namespaces use a safe segment pattern and a 64-character maximum. Keys are also
bounded and path-safe as logical identifiers; on disk the key is hashed before it becomes part of a
directory name.

`POST /api/v1/app-data/records` accepts:

| Field | Meaning |
| --- | --- |
| `namespace` | Required app-owned namespace. |
| `key` | Required logical record key. |
| `schemaVersion` | Required positive integer. |
| `contentType` | Optional bounded content type. Defaults to text, JSON, or binary depending on the value field. |
| `valueBase64` | Base64 bytes for binary records. |
| `valueText` | Text value for UTF-8 records. |
| `valueJson` | JSON value submitted as text and stored as UTF-8 bytes. |
| `ifMatchSha256` | Optional optimistic concurrency guard. |

Exactly one value field must be supplied. List responses include record summaries only: key,
content type, schema version, byte size, SHA-256 digest, and timestamps. They do not include raw
values. Read responses return the value to the owning app as `valueBase64` and, for text or JSON
content types, `valueText`.

## Schema metadata

Apps own their record schemas. The app-facing schema route records metadata only; it does not let
an app principal submit arbitrary migration code at runtime.

Use:

```text
POST /api/v1/app-data/namespaces/{namespace}/schema
```

with `fromSchemaVersion`, `toSchemaVersion`, and optional `summary`. Downgrades are rejected.
Namespace metadata includes the current schema version, timestamps, and bounded migration history.
The app is responsible for transforming its own records before or after it records the migration.

App bundle updates have a separate signed migration contract. When `cryptad-app.properties`
declares `app.data.schema.*` and `app.data.migration.*` fields, `AppUpdateService` can run the
declared bundle-owned migration entrypoint during staging/apply. That flow performs a dry-run
before bundle replacement, creates an internal app-scoped rollback snapshot before schema-changing
apply, records namespace schema metadata after success, and restores the snapshot if migration
apply fails. The snapshot is internal update machinery, not PR-250 user-facing backup/restore
portability. See [app-upgrade-data-migrations.md](app-upgrade-data-migrations.md).

## Quotas and limits

The store always enforces positive platform-level caps:

| Setting | Default |
| --- | --- |
| `cryptad.appData.maxRecordBytes` | `262144` |
| `cryptad.appData.maxRecordsPerApp` | `4096` |
| `cryptad.appData.maxNamespacesPerApp` | `64` |
| `cryptad.appData.maxExportBytes` | `778240` |
| `cryptad.appData.maxImportBytes` | `778240` |

When an installed manifest has a positive `quota.data.bytes`, app-data writes and imports also
respect the app's data quota. Manifest-quota checks reserve space for the store's metadata files
as well as value bytes, so metadata-only schema updates and zero-length records still need quota
headroom. The file-backed store is outside the app-visible data directory, so quota checks add the
current durable app-data usage to the AppHost data usage before accepting a write or import. If the
manifest omits the quota or sets it to zero, the platform caps still apply.
Quota errors use stable codes such as `app_data_quota_exceeded` and must not include store roots,
app data directories, staging paths, or other host filesystem details.

## Export and import

`GET /api/v1/app-data/export` returns a bounded export envelope for the authenticated app. The
payload includes an export version, optional app id, namespace metadata, record summaries, and
base64 record values. Use the optional `namespace` query parameter to export one namespace.

`POST /api/v1/app-data/import` accepts `payloadBase64` and optional `mode`. Export responses use
URL-safe base64 without padding for `payloadBase64` so the SDK can round-trip default-sized
exports through the URL-encoded Platform API bridge; import also accepts standard base64 payloads.

| Mode | Behavior |
| --- | --- |
| `merge` | Adds or replaces records from the payload without clearing unrelated namespaces. |
| `replaceNamespace` | Clears each imported namespace before importing that namespace's records. |

Import rejects payloads that name a different app id. It also rejects unsupported export versions,
oversized payloads, invalid identifiers, and payloads that would exceed record, namespace, record
count, import, or data-quota limits.

## Operator backup and restore

Operators can use the host/operator-only backup routes documented in
[app-data-backup-restore-portability.md](app-data-backup-restore-portability.md). That layer wraps
the app-facing export/import payloads in a deterministic `backupVersion = 1`
`crypta-app-data-backup` envelope for `single-app` or `all-apps` scope. Backups are sensitive user
data because they may contain raw app-owned values.

Operator restore always builds a metadata-only preview before commit and supports `merge`,
`replaceNamespace`, and `replaceApp`. The restore path reuses app-data export parsing, app id and
namespace validation, import size limits, record and value caps, namespace caps, and quota
preflight checks. The operator routes do not grant app principals cross-app read or write access,
and they are separate from the app-facing Platform API compatibility contract.

Schema-changing app updates also participate in the operator consent flow. Update consent previews
show current and target schema versions, migration status, dry-run state when available, rollback
compatibility, and backup-before-update recommendation or requirement. If a migration requires
operator review or a required backup is missing, automatic staging/apply is blocked until an
operator approves a fresh consent snapshot. See
[user-consent-and-permission-upgrade-ux.md](user-consent-and-permission-upgrade-ux.md).

## Browser SDK

Static browser apps should use `CryptaPlatform.data` helpers:

```js
await CryptaPlatform.bootstrap.load({ appId: "feed-reader" });

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
const status = await CryptaPlatform.data.status();
const namespaces = await CryptaPlatform.data.namespaces.list();
```

The SDK exposes:

```text
CryptaPlatform.data.status()
CryptaPlatform.data.namespaces.list()
CryptaPlatform.data.namespaces.get(namespace)
CryptaPlatform.data.namespaces.migrate(namespace, options)
CryptaPlatform.data.namespaces.clear(namespace)
CryptaPlatform.data.records.list(options)
CryptaPlatform.data.records.get(namespace, key)
CryptaPlatform.data.records.put(options)
CryptaPlatform.data.records.putJson(options)
CryptaPlatform.data.records.getJson(namespace, key)
CryptaPlatform.data.records.remove(namespace, key)
CryptaPlatform.data.export(options)
CryptaPlatform.data.import(payload, options)
```

The SDK keeps browser session tokens in memory only and does not use `localStorage` or
`sessionStorage` for durable app state.

## Update Migration Barrier

Schema-changing app updates hold an internal app-scoped app-data write barrier from immediately
before the update snapshot is created until the migration apply, rollback handling, health checks,
and snapshot cleanup have finished. While this barrier is active, app-facing writes such as record
put/delete, namespace clear, schema migration metadata updates, import, and app-data cleanup fail
with `app_data_migration_in_progress`.

The barrier is intentionally app-scoped because update snapshots and rollback restores are
app-scoped. Blocking only the namespace named by a migration step would still allow browser sessions
or app principals to write other namespaces after the snapshot, and those writes could be lost if
the update later rolls back. Internal update migration imports and snapshot restore operations are
allowed under the barrier so the platform can finish the migration or restore the pre-update
snapshot without exposing raw values.

## Uninstall behavior

Default app uninstall removes the immutable bundle and host-owned data, cache, and run state.
Operators can request data preservation with `preserveData=true` on app uninstall. Preserve-data
uninstall removes the immutable bundle, cache, run state, rollback state, and runtime bookkeeping
while leaving the persistent data directory and durable app-data records for a future reinstall or
migration.

The Web Shell also exposes export-before-delete as a two-step operator flow: download the app-data
backup first, then explicitly confirm uninstall with data deletion. This keeps the existing
`preserveData=true` behavior distinct from backup/export and from destructive delete.

## Redaction rules

API errors, audit events, diagnostics, support bundles, release evidence, and model `toString()`
output must not include store root paths, app data directories, temporary paths, raw request
bodies, raw backup payloads, private insert URIs, private keys, seed material, raw vault secrets,
form passwords, app process tokens, or browser session tokens.

Release evidence should use route names, capability labels, record counts, namespace counts, byte
counts, schema versions, booleans, sanitized error codes, and digests. It must not include raw
app-data values unless the owning app receives them through the app-data read API.

## Experimental Mail dataset

Mail stores one protected `mail-state/dataset` record with schema 1. The worker owns contacts,
drafts, outbox, accepted messages and replay evidence inside that encrypted dataset. A single CAS
publication commits acceptance and replay together. The combined plaintext cap is 112 KiB and the
encoded stored record must fit 262144 bytes; limits on individual messages do not override it.
See [Mail design](mail-app-service-prototype.md) for bounds and full-restore replay limitations.
