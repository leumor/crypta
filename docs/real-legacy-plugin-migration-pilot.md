# Sharesite plain-text migration pilot

Use this pilot to convert selected active Sharesite pastebin pages into private, durable Site Publisher drafts and explicitly publish approved text at a new CHK address.

This is a **selected-workflow migration**, not migration of the entire Sharesite plugin. Textile rendering, CSS, activelinks, scheduling, deleted pages, plugin ABI compatibility, and old USK writer continuity are outside the supported profile. Current Cryptad has no legacy plugin runtime; keep the old environment isolated.

## Implementation baseline

The requested inspected PR-296 commit was `32b1bc81ab646caf550b2b4166d03a39a7cc8790` on `feature/pr-296-platform-api-1-x-compatibility-operations`. Its final branch revision was `54030d6da77b591285c58045c0021c854ec1ba55`. PR-296 merged as #1395, so PR-297 starts from containing `develop` commit `55a37fa59239cf1a7fae0456bb58f136663a3e2f`; it does not use an older develop without that work.

The previous Site Publisher was stateless, had zero data quota, and requested `queue.read`, `queue.write`, and `content.insert`. Draft storage and generated-document publishing require a new signed app bundle and explicit consent to added permissions. The app requests a 1 MiB data quota; its single dataset is capped at 192 KiB, leaving room for file-generation metadata and transition overhead under the platform quota checks. The active stable baseline remains `1.0`; its contract root is 19 and the current contract is 24.

The changes since the inspected commit include PR-296's original-dispatcher and rerun-actor authentication fix, stricter baseline checks, and app-update admission refactoring and tests. This pilot preserves those changes. Site Publisher advances from app version `3` to `3.1`; the daemon's integer build version is unchanged. Its contract range is 9–24, with explicit stable baseline `1.0` and no experimental opt-in.

| Inspected gap | Implemented path or remaining boundary |
| --- | --- |
| Legacy loader mutates files and hides parse failures | Independent bounded binary decoder, fixed snapshot input, source recheck, private inspect/plan/export commands. |
| Stateless publisher with no data permission/quota | Existing Site Publisher app gains one bounded draft dataset, guarded writes, private export/restore, literal editing and preview. The seven-app inventory is unchanged. |
| Generic data merge can replace records | A narrow Site Publisher consent guard validates an additive transition and atomically replaces one complete dataset generation. Generic mutation paths cannot bypass this namespace guard. |
| Preview alone cannot protect concurrent writes | Daemon-held one-time consent binds the exact signed installed target, namespace schema, quota, data generation and proposed bytes. Existing data-migration barriers and the host lifecycle monitor coordinate commit. |
| Old writer identity cannot transfer safely | No private insert identity is imported. Explicit generated text publication uses a new CHK address. |
| Synthetic fixtures cannot prove user migration | Pinned-writer fixtures and an executable synthetic data-path test remain labeled synthetic. No operator snapshot or network observation is supplied by this change. |
| Original protected observations are missing | PR-300 implements separate migration/projection producers and v2 consumers. No protected or real-user observation has been executed; local conversion/import remains independent of release closeout. |

## Prepare a consistent snapshot

1. Stop the Sharesite writer on the OLD supported legacy node. Record that decision and snapshot provenance in private operator notes. A copied database from a running writer is not a consistent snapshot merely because it parses.
2. Preserve the old database and its independent old-node backup. The active database is `Sharesite.db` beneath that node's user directory.
3. Inspect the old environment for a `.tmp` sidecar or unresolved corrupt/recovery files. Resolve recovery with the old environment and its owner, then stop it again and create a fresh snapshot. The converter refuses ambiguous recovery and does not repair the source.
4. Copy one regular file into an explicit private operation workspace. Do not submit a directory tree, symlink, device, pipe, or live node directory. Limit workspace access to the owner.
5. Keep the snapshot, operator notes, private plan, converted package, fidelity comparisons, and target backup local. Never attach them to a PR, CI artifact, support report, or diagnostics export.

The decoder implements the binary format independently. It never invokes `FileStorage.load()`, instantiates `Freesite`, deserializes Java objects, fetches embedded URIs, or loads legacy plugin classes. Source bytes are checked again after inspection/conversion, including failure paths; a changed source fails rather than becoming a repaired or successful migration. This detects observable changes, not malicious changes that are made and perfectly reverted between checks.

## Format and field profile

The source is [`hyphanet/plugin-sharesite` at `c99ad9c8e83004f904f8ee742ab2861f5751ee3b`](https://github.com/hyphanet/plugin-sharesite/tree/c99ad9c8e83004f904f8ee742ab2861f5751ee3b), identified by the archived aggregator's `projects/plugin-sharesite` submodule. The framing is the literal ASCII/UTF-8 header `ShareWiki-db-ver1`, a big-endian signed 32-bit entry count, then big-endian signed 32-bit byte lengths and UTF-8 key/value bytes. Map iteration order does not identify a page.

The independently inspected source files have these exact Git blob identities:

| Source at pinned revision | Git blob |
| --- | --- |
| [Database.java](https://github.com/hyphanet/plugin-sharesite/blob/c99ad9c8e83004f904f8ee742ab2861f5751ee3b/src/plugins/Sharesite/Database.java) | `bf87f512db62a5e77e82493ada688fead74f007f` |
| [Freesite.java](https://github.com/hyphanet/plugin-sharesite/blob/c99ad9c8e83004f904f8ee742ab2861f5751ee3b/src/plugins/Sharesite/Freesite.java) | `a462d33d6d93f7652c0cad28183596c3b436c9ce` |
| [FileStorage.java](https://github.com/hyphanet/plugin-sharesite/blob/c99ad9c8e83004f904f8ee742ab2861f5751ee3b/src/plugins/Sharesite/common/FileStorage.java) | `49b33cd7e3736481b50b454d78730b6dd53c98ba` |
| [MapToData.java](https://github.com/hyphanet/plugin-sharesite/blob/c99ad9c8e83004f904f8ee742ab2861f5751ee3b/src/plugins/Sharesite/common/MapToData.java) | `9725e87fc6d5cc22434579b06f5f8122f963d2bc` |
| [SmartMap.java](https://github.com/hyphanet/plugin-sharesite/blob/c99ad9c8e83004f904f8ee742ab2861f5751ee3b/src/plugins/Sharesite/common/SmartMap.java) | `e5aeeea9d477b38db049517fc7b5dda64e1b06ff` |

The upstream [LGPL 2.1 license](https://github.com/hyphanet/plugin-sharesite/blob/c99ad9c8e83004f904f8ee742ab2861f5751ee3b/LICENSE) has blob `4362b49151d7b34ef83b3067a8f9c9f877d72a0e`. The production decoder is independently implemented; the legacy runtime and Textile dependencies are not vendored. Source-derived conformance fixtures retain [explicit pinned-writer provenance](../platform-devtools/src/test/resources/network/crypta/platform/devtools/migration/sharesite/PROVENANCE.md), exact synthetic input construction, and fixture checksums.

| Field or category | Pilot treatment |
| --- | --- |
| `keys` | Explicit active logical IDs, serialized as a space-separated integer list. Select supported IDs privately. |
| `deleted_keys` | Excluded; never reactivate recently deleted records. Conflicting active/deleted membership is an error. |
| `increasingCounter`, `lastDeletedTime` | Legacy bookkeeping; no new writer/scheduler authority. |
| `collection-<id>/pastebin=true` | Eligible plain-text record after validation and explicit selection. |
| `pastebin=false` or absent | Unsupported Textile profile; no silent flattening. Malformed booleans fail. |
| `name`, `description`, `text` | Private user data. Supported literal text preserves Unicode and newline sequences without rendering markup. |
| `path` | Historical document metadata only; missing historical path falls back to name. Never filesystem or fetch authority. |
| `edition` | Bounded historical metadata; does not create a new edition under the old key. |
| `requestSSK` | Optional validated public read reference, private historical metadata only. A prefix alone is not validation. |
| `insertSSK` and secret/key/token fields | Excluded from app data; no old insertion key transfer. Selected content containing prohibited insertion/private-key material is blocked with a bounded reason. |
| `css`, `activelinkUri`, templates and external resources | Explicitly excluded from active rendering/fetching. |
| `insertHour`, `l10nStatus`, queue/scheduler state | No scheduler or queue restoration. |
| Unknown fields or unsupported framing | Explicit findings or rejection; never silent success after skipping all records. |

A zero-entry database is valid framing but does not mean any pages migrated. Negative lengths, truncation, invalid UTF-8, trailing bytes, duplicate keys/IDs and ambiguous membership are failures. Input, decoded allocation, per-field, selected-page and final encoded payload limits are enforced independently.

Known secret-field values are validated and skipped without creating ordinary value strings. The
original bounded input bytes still exist in JVM memory; this is not guaranteed memory erasure.
Selected metadata/text is checked for private insertion URIs, private-key markers and common
credential assignments, including bearer tokens. This bounded rejection scan complements the
operator's private content review; it cannot identify every arbitrary secret a person might paste.

The converter caps source files at 8 MiB, map entries at 4,096, encoded keys at 1,024 bytes, individual values at 131,072 bytes, each ID list at 512 entries, selected pages at 16, selected text at 65,536 UTF-8 bytes, draft dataset at 196,608 bytes, and final private package at 409,600 bytes. It requires POSIX owner-only workspace/file access; platforms without that enforcement fail closed rather than pretending to apply ACL protection.

## Private conversion and target consent

The offline CLI uses an existing owner-only operation directory and an explicitly selected snapshot. For example, after creating a consistent snapshot and private directory:

```bash
crypta-app migration sharesite inspect \
  --snapshot PRIVATE_SNAPSHOT --workspace PRIVATE_OPERATION_DIRECTORY --writer-stopped
crypta-app migration sharesite plan \
  --snapshot PRIVATE_SNAPSHOT --workspace PRIVATE_OPERATION_DIRECTORY --writer-stopped \
  --select 0,2 --operation-id OPERATION_UUID --provenance PRIVATE_PROVENANCE --ack-exclusions
crypta-app migration sharesite export \
  --snapshot PRIVATE_SNAPSHOT --workspace PRIVATE_OPERATION_DIRECTORY --writer-stopped \
  --select 0,2 --operation-id OPERATION_UUID --provenance PRIVATE_PROVENANCE --ack-exclusions \
  --ack-plan-sha256 REVIEWED_PRIVATE_PLAN_SHA256
```

Replace the selection and operation UUID with the exact locally reviewed values. `inspect` writes PRIVATE `inspection.json`; `plan` writes PRIVATE `plan.json`. The inspection includes the exact source snapshot digest as PRIVATE metadata. Plan and export require that preceding inspection in the same workspace and verify its exact current contents, so changes to text or other source fields invalidate it even when page eligibility stays the same. Inspections created without this binding must be regenerated in a fresh workspace. If the source/preview changes, start a fresh private operation workspace; the CLI does not overwrite or clean up prior private outputs. Review that plan locally and obtain its exact SHA-256 locally. `export` recomputes the exact plan from source, selection, operation ID and provenance, verifies the acknowledged digest, and writes PRIVATE `migration.json`. Do not paste a private plan digest or provenance into public review/evidence. All commands are offline; none installs or publishes.

Inspect before selecting. Review the excluded categories, each selected page, metadata loss and the unsupported identity continuity. A supported subset is permitted only with acknowledgement of the exact selection. A selected record with prohibited private material must be rejected; the tool must not silently redact or modify literal content to obtain success.

The conversion package is a typed Sharesite-origin wrapper around the existing app-data export representation. It must not claim to be a backup exported by an installed Cryptad app. Exact source/payload bindings and fidelity comparisons are PRIVATE even when they are only hashes. Secret-free user content is still sensitive.

Before import, use the normal signed catalog/app update flow for Site Publisher. Review the exact bundle, publisher, manifest, stable baseline, positive data quota and permission delta. Approve `app.data.read`, `app.data.write`, and `content.insert.app-document` through normal update consent. Compatibility admission alone does not grant permissions. See [permission consent](user-consent-and-permission-upgrade-ux.md) and [app updates](app-update-lifecycle.md).

## Draft import, edit and recovery

Use Site Publisher's own app session for its draft data. The raw Sharesite database never enters the browser or node API. Import only the converted private package into the allowlisted Site Publisher migration namespace. Keep host/operator backup credentials out of the app.

Preview binds the selected payload, current target generation and app declaration. Check backup readiness before committing. The daemon enforces old-or-complete dataset visibility, preserves unrelated data, rejects collisions, and invalidates stale previews after changes. The app recognizes exact completed replay as a no-op; a changed package under an existing operation ID is rejected. The app checks the daemon's `sharesiteWriteGuard=1` status before proposing any write. An older daemon cannot silently accept a migration without the guard.

The guard permits one `application/json` record, `sharesite-drafts/dataset`, at schema 1. It bounds the dataset to 196,608 bytes, 512 drafts and 32 operation-ledger entries, with at most 16 pages per import. Preview consent expires after five minutes and is discarded on restart. A failed commit consumes that preview; reload visible data before creating a new preview. Atomic filesystem replacement is required for the store's current-generation pointer. This provides process interruption visibility, not a promise of power-loss durability on every filesystem.

After commit, read selected drafts back and compare literal content privately, then restart the app/node and repeat. Edit and save a harmless test draft. Preview uses literal text rather than Textile, raw HTML, CSS, or embedded fetches. Saving and importing do not publish.

Preserve source and target backups separately. App-data private backup envelopes currently declare `encryption.mode=none`: they are not encrypted. Use the owning app's private export/restore controls for its data and the existing operator backup surface when a complete app backup is needed. Before committing a private restore, review the displayed added drafts and operation entries; already-present identical data is preserved and omitted from that addition list. Changing the selected file or preview mode clears the prior selection and consent. Generic restore may replace data and is not an additive migration shortcut; consult [backup/restore portability](app-data-backup-restore-portability.md).

| Recovery action | What it changes |
| --- | --- |
| Import undo | Only this import, when its committed generation still matches. Later user edits require manual recovery and must not be erased silently. |
| Private data restore | The explicitly selected target data; review collisions and current generation. |
| App-update rollback | Retained immutable app bundle and provenance. It does not automatically undo user data. |
| Old-node rollback | Resume the separately isolated old node using its own preserved snapshot/backup. No current Cryptad plugin ABI support is involved. |
| Queue cancellation | May stop pending work; it cannot guarantee removal of bytes already inserted into the network. |

If an import fails or is interrupted, inspect the visible generation and use bounded recovery guidance. Do not infer a successful import from record counts or delete the old snapshot to clean up. There is no broad cleanup command or forensic secure-deletion guarantee.

## Explicit new-address publication and cutover

The identity strategy is fixed:

- The legacy owner retains the source private insert identity; it is not imported.
- An old public read reference can remain optional PRIVATE historical metadata.
- Explicit publication creates a new CHK content address.
- Same-USK continuity is unsupported.

Publish only after reviewing the draft's literal content and approving network insertion. The generated-document input carries generated bytes (`documentBase64`) with an explicit plain-text content type, never a browser-supplied host path or old private insert key. Publication is separate from import/save. Cancelling a queue item or undoing local drafts cannot guarantee removal of already published content.

A runtime drill may publish only operator-approved non-sensitive test text. If no network insertion/fetch ran, report publication as `not-observed`. Verify draft fidelity and usability before deciding to disable automatic publishing in the OLD environment. That decision is separate and explicit; the pilot never uninstalls the old plugin or deletes its database. The old site remains readable and the new CHK is not its next USK edition.

## Evidence levels and certification

The [cross-version experiment](cross-version-live-network-soak.md) adds a callable synthetic
observation adapter that uses the fixed converter and installed Site Publisher controller with
an admitted own-app session. The separate `observe_operator_private` capability accepts only a
root-sealed exact stopped-snapshot selection on the dedicated protected topology. It reads no
operator source before that authority is verified. The known upstream fixture cannot be relabeled
private, and `operator-owned-private-observation` does not establish independently verified
real-user migration. Neither path accepts operator data through ordinary CI or publishes CHKs.
No live migration or operator-owned source was executed for this change. Browser literal preview,
bundle rollback and full cleanup remain missing runtime adapter cases; their existing local tests
do not fill those observations. Private restore/quota stages require the declared recovery cohort.

Keep four evidence levels distinct: parser/converter unit tests, upstream-format conformance vectors, an isolated executable demonstration, and an authentic operator-approved user migration. Synthetic bytes produced by the pinned upstream writer prove format compatibility, not migration of a real user's data.

[`SharesiteSyntheticDataPathTest`](../platform-devtools/src/test/java/network/crypta/platform/api/appdata/SharesiteSyntheticDataPathTest.java) runs the real offline CLI on the pinned-writer synthetic fixture, signs a private copy of the staged Site Publisher bundle with an ephemeral test key, and imports through the guarded service into `FileAppDataStore`. It checks exact readback after reconstructing the host/store, source preservation, edit, undo, private restore, and independent signed-bundle rollback. The separate Site Publisher behavior harness exercises its actual controller and DOM handlers, including inert markup and explicit publishing requests. These tests do not perform a production catalog install, launch an app process, insert/fetch network content, or migrate a real user's database.

Run the narrow local observation checks with:

```bash
python3 tools/release-certification/certify.py stable-legacy-plugin-migration --self-test
python3 tools/release-certification/certify.py stable-legacy-plugin-migration \
  --mode preflight \
  --observation tools/release-certification/manifests/sharesite-migration-local-observation.example.json \
  --out-dir build/sharesite-observation-example
```

The example contains synthetic identity placeholders and only `not-observed` outcomes. It is a schema illustration, not a fixture proving an executable migration. The output directory must be new. The command reads a bounded, sanitized observation, never a private package or database; it emits only `summary.json`, `report.md`, and `redaction-report.json`.

Modes are `preflight`, `verify-migration`, `verify-runtime`, and `closeout`. The first two validate the closed local observation and retain claims as `reportedLocalOutcomes`; they do not independently verify format or runtime execution. `verify-runtime` and `closeout` retain the v1 fail-closed `protected-migration-producer-not-configured` prerequisite. The separate v2 protected wrapper authenticates an original produced observation before invoking its narrowly admitted consumer path. No caller label, opaque digest, resealed receipt or self-reported `pass` can grant operational success. Publication remains `not-observed` without an authenticated producer.

Public observations allow only source profile/revision, public adapter/app identities, an opaque operation ID, bounded counts/categories and outcome enums. They reject private labels/text, old URIs, source paths, raw source/content hashes, payloads, arbitrary notes and caller-supplied producer authority. Shared redaction runs after this closed allowlist; opaque public artifact digests remain valid metadata.

PR-296's `pr296-protected-subject-projection-pending` prerequisite remains explicit for v1 local inputs and missing authentic v2 evidence. Its existing non-fixture app-matrix rejection must not be weakened: broad PR-294/PR-295 summary digests do not authenticate complete app compatibility declarations. Missing projection evidence blocks release closeout independently of successful local conversion/import.

The dependency graph is: authenticated source daemon release → existing runtime admission; new signed migration-app release → app update consent → local migration; protected observation authority → authenticated migration evidence; complete upstream projection/release evidence → release closeout. A post-migration receipt is not a prerequisite for building the app, and historical daemon release roots are never relabeled with this implementation commit.

PR-300's dedicated `stable-1.0-sharesite-runtime-observation.yml` producer uses the fixed adapter,
separately selected private topology and single-member public allowlist. Its consumer reauthenticates
the original producing run/attempt/job/environment/artifact and exact member attestation, retaining
synthetic versus operator-private classification. This local v1 command does not dispatch it.
The [private migration prerequisites](cross-version-live-network-soak.md#protected-sharesite-observations)
define source selection and retention. Ordinary CI runs synthetic tests and never downloads user
snapshots or accesses an operator node, release credentials, or signing keys.

PR-298 may review Trust/Social content-profile maturity. It does not broaden this Sharesite profile, add old-key continuity, activate API 1.1, or establish a new release-authority framework. PR-300 retains long-duration cross-version soak ownership.
