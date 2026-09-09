# First-party app maintenance policy

Crypta first-party apps are long-term platform commitments, not demos. This policy defines the
signed catalog metadata that tells operators who owns each app, what support level it receives, how
its app-data state is handled, and how deprecation or replacement decisions are communicated.

The canonical reviewable policy source is
`tools/release-certification/first-party-app-maintenance-policy.json`. Production beta release
tooling consumes that file when it generates first-party catalog entry descriptors. The generated
catalog then carries the same policy under `app.<id>.maintenance.*` signed catalog fields.

Release certification evidence id: `app-catalog.first-party-maintenance-policy`.

Beta usability readiness is tracked separately by
[first-party-app-beta-quality-pass.md](first-party-app-beta-quality-pass.md) and release
certification evidence id `first-party-app.beta-quality-pass`. The maintenance policy remains the
owner/support/data-policy source of truth; the beta-quality metadata proves that each app exposes
empty states, bounded error states, retry and recovery actions, permission rationales,
app-data backup/export/import status, support metadata, accessibility markers, design-system
classes, and `redacted-summary-only` diagnostics.

## First-party policy table

| App | Catalog channel | `support.status` | Maintenance support | Data schema | Migration | Backup/restore | Security | Deprecation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `queue-manager` | `stable` | `supported` | `core` | `stateless` | `none` | `not-applicable` | `catalog-advisories` | `none` |
| `publisher` | `stable` | `supported` | `core` | `stateless` | `none` | `not-applicable` | `catalog-advisories` | `none` |
| `site-publisher` | `stable` | `supported` | `maintained` | `declared` | `operator-approved` | `export-import` | `catalog-advisories` | `none` |
| `profile-publisher` | `stable` | `supported` | `maintained` | `declared` | `declared` | `operator-supported` | `catalog-advisories` | `none` |
| `feed-reader` | `stable` | `supported` | `maintained` | `migratable` | `dry-run-required` | `export-import` | `catalog-advisories` | `none` |
| `social-inbox` | `stable` | `supported` | `local-rc` | `declared` | `operator-approved` | `operator-supported` | `catalog-advisories` | `none` |
| `trust-graph` | `stable` | `supported` | `local-rc` | `migratable` | `dry-run-required` | `operator-supported` | `catalog-advisories` | `none` |

`Trust Graph Local RC is not global WoT`. It is a local RC trust surface with local anchors,
operator-approved grants, redacted audit state, and no global moderation, routing, crawling, or
legacy WebOfTrust compatibility.

`Social Inbox RC is not legacy Freemail/Freetalk/Sone protocol compatibility`. It is a bounded
social/mail-like RC reference app using app-owned state, content subscriptions, AppVault identity
routes, generated app documents, and optional Trust Graph Local RC annotations. It is not encrypted
mail transport, old plugin ABI compatibility, a crawler, or a daemon-core social protocol.

## Signed catalog fields

Maintenance metadata starts at `catalog.version=5`. Existing v1-v4 catalogs remain valid when they
do not declare maintenance fields. A v1-v4 catalog that declares `maintenance.*` fields is rejected
instead of being partially accepted.

The signed entry fields are:

```properties
app.<id>.maintenance.owner=crypta-core
app.<id>.maintenance.ownerUri=https://example.invalid/crypta/owners/core
app.<id>.maintenance.supportLevel=core|maintained|reference|local-rc|preview|maintenance|deprecated|unsupported
app.<id>.maintenance.dataSchemaPolicy=stateless|declared|migratable|external|not-applicable
app.<id>.maintenance.migrationPolicy=none|declared|dry-run-required|operator-approved|not-applicable
app.<id>.maintenance.backupRestore=not-applicable|export-only|export-import|operator-supported|unsupported
app.<id>.maintenance.securityPolicy=catalog-advisories|project-security-policy|unsupported
app.<id>.maintenance.deprecationPolicy=none|notice-only|replacement-required|security-only
app.<id>.maintenance.supportUri=https://example.invalid/crypta/apps/<app-id>/support
```

The catalog `channel`, `support.status`, `minimumCryptaVersion`, `maximumCryptaVersion`,
`deprecation.status`, `deprecation.message`, `replacementAppId`, and `securityAdvisories` fields
remain authoritative for their existing meanings. Do not duplicate them under `maintenance.*`.

## Field meanings

`maintenance.owner` is the accountable first-party maintenance group. For current first-party apps
the value is `crypta-core`.

`maintenance.ownerUri` and `maintenance.supportUri` are operator-facing metadata links. They must
use the same safe metadata URI rules as homepage, source, changelog, screenshot, and advisory URI
fields. They must not contain private insert URIs, tokens, credentials, or local file paths.

`maintenance.supportLevel` describes the long-term maintenance commitment:

| Value | Meaning |
| --- | --- |
| `core` | Core operator workflow maintained with daemon release quality expectations. |
| `maintained` | First-party app with ongoing fixes, review, and release certification coverage. |
| `reference` | Reference implementation with explicit scope limits. |
| `local-rc` | Local release-candidate app whose scope is intentionally bounded to local platform behavior. |
| `preview` | Preview feature with lower stability expectations. |
| `maintenance` | Supported only for security or critical fixes. |
| `deprecated` | Kept for deprecation guidance and migration/replacement notices. |
| `unsupported` | Not maintained for production use. |

`maintenance.dataSchemaPolicy` says whether the app is stateless, declares app-data schema, can
migrate schema, uses external state, or has no applicable data schema.

`maintenance.migrationPolicy` says whether migration is not needed, declared by manifest metadata,
requires a dry-run, requires operator approval, or is not applicable. It must stay consistent with
`app.data.schema.*` and `app.data.migration.*` manifest declarations.

`maintenance.backupRestore` says whether the app has no backup scope, export-only support,
export-import support, operator-supported backup/restore, or no supported backup path. Profile
Publisher, Social Inbox RC, and Trust Graph Local RC backups must not include vault private identity
material, app-service tokens, private insert URIs, raw fetched content, or raw app-data payloads in
release evidence.

`maintenance.securityPolicy` links the app to catalog advisory handling. Current first-party apps
use `catalog-advisories`, so entry-level `securityAdvisories` and catalog-level security policy
records remain the signed security response path.

`maintenance.deprecationPolicy` explains the deprecation handling expectation. A replacement target
uses the existing signed `replacementAppId` field.

## API and Web Shell

Starting with Platform API contract version 19, catalog API summaries include a nested
`maintenance` object with the signed fields:

```json
{
  "maintenance": {
    "owner": "crypta-core",
    "ownerUri": "https://example.invalid/crypta/owners/core",
    "supportLevel": "maintained",
    "dataSchemaPolicy": "migratable",
    "migrationPolicy": "dry-run-required",
    "backupRestore": "export-import",
    "securityPolicy": "catalog-advisories",
    "deprecationPolicy": "none",
    "supportUri": "https://example.invalid/crypta/apps/feed-reader/support"
  }
}
```

The existing top-level `channel`, `supportStatus`, `compatibility`, `deprecation`, and
`securityAdvisories` fields stay unchanged. Web Shell displays the maintenance policy as compact
metadata on catalog app cards and keeps existing channel, support, deprecation, review, and
security-advisory logic authoritative. Deprecated or beta-only apps must not be presented as
stable-supported apps just because they have maintenance metadata.

## Release certification

The unified `certify.py app-platform` collector records
`app-catalog.first-party-maintenance-policy` evidence. The deterministic check verifies:

- the policy file exists and covers exactly the seven current first-party apps;
- each app declares owner, owner URI, support level, data schema policy, migration policy,
  backup/restore support, security policy, deprecation policy, and support URI;
- enum tokens are known and single-line;
- first-party app class expectations match the policy table above;
- catalog v5 parser/writer/descriptor support, CLI flags, Platform API exposure, and Web Shell
  rendering markers are present;
- production beta tooling consumes the policy when generating signed first-party catalog entries;
- docs explain the local-RC and legacy-protocol non-goals.

The `certify.py production-beta` pipeline copies the policy into
`<out-root>/<release-id>/production-beta/artifacts/legacy/inputs/first-party-app-maintenance-policy.json`
and includes a redacted per-app maintenance summary in the engine-native
`catalog/channel-metadata.json`. Strict release-candidate and production-beta modes fail when a
required first-party app is absent from the policy or has an incomplete maintenance block.
Developer dry-runs warn so maintainers see the problem without needing release credentials.

## Stable 1.0 maintenance baseline

The Stable RC freeze binds this policy to the signed stable catalog and to the exact first-party
bundle and review-receipt digests. Stable GA does not regenerate, relax, or reinterpret those
commitments. Its deterministic `stable-1.0-maintenance-baseline.json` copies the frozen owner,
support, app-data schema, migration, backup/restore, security, deprecation, app version, bundle,
and review identities for every first-party app.

Future maintenance and hotfix candidates compare against that published baseline. Compatible app
patches still require signed catalog/app review, migration and backup/restore evidence, rollback
coverage, and any applicable Platform API/content-profile compatibility evidence. If a commitment
or bundle must change before the initial Stable GA, stop promotion and complete a new Stable RC
refreeze instead of patching the GA record.

## Updating the policy

When adding or changing a first-party app:

1. Update `tools/release-certification/first-party-app-maintenance-policy.json`.
2. Reuse existing catalog fields for channel, support status, deprecation status, replacement app
   id, security advisories, and Crypta version bounds.
3. Choose the smallest accurate `maintenance.*` values from this document.
4. Keep owner, support, and URI text single-line and free of secrets, local paths, private insert
   URIs, tokens, raw fetched content, raw app-data payloads, and private key material.
5. Update this document if the support table changes.
6. Run `python3 -u tools/release-certification/certify.py app-platform --self-test` and
   `python3 -u tools/release-certification/certify.py release-certification --self-test`.
7. If Stable RC bytes have already been frozen, treat the policy change as payload drift and start
   the authorized refreeze path before any new GA validation.

## Stable 1.0 maintenance application

For a later Stable 1.0 release, compare every first-party app against both the immutable GA app set
and the immediate predecessor. Only compatible patch or security changes are eligible: app ids and
stable channel membership remain fixed, support commitments cannot decrease, reviewed bundle bytes
must match the catalog, and any data-schema or permission change needs candidate-bound migration,
rollback, backup, restore, consent, and rationale evidence.

App versions must use the release-canonical dotted-numeric grammar that `AppUpdateService` can
compare. A version cannot regress below either Stable GA or the immediate predecessor, and changed
bundle bytes require a strictly newer version so installed clients can select the update.

The [Stable 1.0 maintenance release and security hotfix
path](stable-1.0-maintenance-release-and-hotfix-path.md) defines the fail-closed delta and
authorization process.

## Supply-chain and license binding

Every frozen first-party bundle is a supply-chain release subject. Its canonical row binds the app
id and version to the exact bundle, manifest, bundle-signature, and trusted-review-receipt digests,
permissions, maintenance-policy fields, data-schema/migration identity, license conclusion, and
signed catalog entry. The signed catalog and detached signature are separate release subjects;
the release freeze binds their revision, signer identity, and digests.

The component reverse index maps copied Platform SDK and design-system assets, app-project
outputs, and other identified bundle components to every bundle and catalog entry that contains
them. Use that index during vulnerability intake; do not infer affected apps only from the daemon
runtime classpath. Catalog `license` display metadata does not replace the reviewed license
inventory, and a local policy scan does not replace the protected candidate-bound SBOM binding.

A first-party bundle or catalog change in maintenance requires the passing supply-chain promotion
summary for the same candidate freeze. An omitted bundle, incomplete license conclusion, stale
review/signing identity, or producer/verifier mismatch is non-waivable. See [Stable 1.0
supply-chain inventory and reproducible-build
governance](stable-1.0-supply-chain-inventory-and-reproducible-build-governance.md).

Supply-chain publication attaches the public `release-subject-inventory`, component inventory,
reverse index, license inventory, SBOM, build materials, reproducibility report, and summary to the
already created maintenance Release. It does not republish or replace an app bundle or catalog;
those product bytes remain governed by their own frozen release subjects and signatures.

## Lifecycle governance projection

Stable lifecycle certification reuses this policy and the signed catalog's existing channel,
support, deprecation, replacement, advisory, denylist, and review metadata. Its public projection
must retain all seven first-party app ids and fail on app removal, id substitution, support-level
downgrade, missing replacement guidance where policy requires it, or loss of migration and
backup/restore commitments. The projection informs core support decisions but does not replace the
signed catalog or trusted-review governance model.

A new core maintenance build does not reset an app's deprecation clock or silently rename,
uninstall, or replace the app. See [Stable 1.0 support lifecycle and deprecation governance](stable-1.0-support-lifecycle-and-deprecation-governance.md).

## Additional experimental prototypes

Mail Prototype is selected separately in
`tools/release-certification/first-party-experimental-apps.json`: beta-only, explicit experimental
opt-in, no automatic installation, and no Stable eligibility. Its support level is prototype and
independent security review/live two-node observation remain unobserved until actual evidence is
supplied. The existing seven-app readiness and historical Stable selections remain exact. Mail's
private data backup requires the same compatible retained vault identities; bundle rollback never
restores keys or grants. See `apps/mail-prototype/README.md` for the manual reference workflow.
