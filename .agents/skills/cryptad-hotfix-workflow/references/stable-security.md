# Stable 1.0 security hotfix path reference

Read for Stable 1.0 security hotfix path. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 security hotfix path

A Stable 1.0 hotfix uses `policies.releaseClass=security-hotfix` on
`hotfix/<build-number>` based on the exact current protected `main` tip. The protected train
workflow freezes that independently resolved commit as `policies.mainLineageCommit`; require
`candidateBaseCommit` to equal it and the tagged publication predecessor to remain its ancestor.
Keep the authoritative hotfix queue, incident evidence, review authorization, train authorization,
and completion record out of repository-readable plaintext artifacts. Protected phase handoffs
use the exact authenticated encrypted envelope and shared protected-environment handoff key; the
public artifact contains only the bounded public queue and validation projections.
Do not branch directly from the tagged candidate after `main` has advanced through its prior
no-ff reconciliation merge. Run the side-effect-free train gate before the maintenance command:

All fixes in one train must be critical security fixes under one exact incident/advisory identity
pair. Split different incident or advisory scopes into separate authorized trains; the hotfix lane
is not a multi-incident emergency bypass. Represent incident-required package, app, or
release-tooling effects inside the critical security fix’s affected scope and evidence; do not add
a separately classified ordinary row to the shortened lane.

```bash
python3 tools/release-certification/certify.py stable-backport \
  --manifest build/stable-1.0-backport.json
python3 tools/release-certification/certify.py stable-maintenance \
  --manifest build/stable-1.0-maintenance.json
```

The train disposition is exactly `security-hotfix`; there is no generic emergency lane. Require a
narrow accepted fix set, exact incident/advisory and affected scope, authenticated published
`main`/predecessor base, full source/candidate commit identities, reviewed provenance, candidate
tests, and zero unaccounted changes. Patch-id equality cannot authorize the transfer. Unrelated
features, cleanup, and ordinary bugs block the train.
If the incident fix uses a clean cherry-pick or manual conflict resolution, require the exact
successful protected provenance-review workflow artifact. Matching provenance, ownership, and
evidence digests supplied by the fix author are not independent approval.

Protected and public fix views share one opaque digest-bound fix identity. Do not put an embargoed
title, exploit detail, raw patch, private issue/fork URL, credential, private insert URI, or local
path into train, note, support, or certification output. Shortened evidence and follow-up
obligations remain bound to the same fix and train identity.

The critical-security policy requires an incident/advisory id, qualified severity and affected
scope, release-manager authorization, exact candidate identity, full non-waivable compatibility,
packaging, updater, upgrade, rollback, migration, backup, signing, and redaction gates, and a
deadline-bound follow-up obligation for any shortened observation window. It is not a generic skip
or waiver. Declare a nonempty `affectedPackageKeys` subset even when publishing the complete
package matrix. A narrowed matrix requires a passing unaffected-target proof and must equal that
affected set exactly; a complete matrix uses `unaffectedPackageProofStatus=not-applicable`. Close
the obligation later with the side-effect-free `close-hotfix-follow-up` mode; do not rebuild or
mutate the published hotfix. The aggregate interval and every obligated row must independently
meet the normal duration and freshness policy, must have completed by the validation time, and must
bind both the original hotfix predecessor and the immutable GA identity where the scenario is a
direct-GA upgrade. When another authorized hotfix carries an open or overdue
obligation, closure evidence and authorization remain bound to the originally obligated build and
bytes. The latest activated baseline, receipt, and pointer separately authenticate where that
obligation is currently carried; do not substitute the superseding hotfix's evidence or
authorization. Release-train governance permits exactly one such inherited `hotfix-follow-up`;
if maintenance publication created it after the prior train queue was authorized, its first queue
projection must bind the authenticated predecessor baseline’s obligation digest, obligated
build/train, generation time, and the prior queue’s critical source-fix identities. Every later row
must be unchanged from the immediately prior authenticated queue, and its id remains in release
completion. An unbound new or second follow-up, or an unresolved main/develop reconciliation
obligation, blocks the superseding hotfix. Authenticate the original candidate freeze against the
predecessor observation recorded in that freeze, not against a later baseline carrying the
obligation. Protected pointer activation uses a fresh activation-only authorization after
environment approval; it does not alter the published hotfix authorization or bytes.
The maintenance workflow accepts the intentionally `blocked` queue only when the exact successful
security-hotfix validation carries that one sole open follow-up; it must reject every other
blocked composition.

Follow `docs/stable-1.0-maintenance-release-and-hotfix-path.md`. The protected workflow publishes
but never merges; explicit no-squash, `--no-ff` merges into `main` and `develop` remain required.
Before approval, confirm the protected environment has exact producer identities in
`CRYPTAD_STABLE_MAINTENANCE_INPUT_SIGNER_WORKFLOW` and
`CRYPTAD_STABLE_MAINTENANCE_WINDOWS_SIGNER_WORKFLOW` and a reviewed
`CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND`. A hotfix does not weaken those provenance or
publication-boundary requirements. Pin the two producer identities to the checked-in
`.github/workflows/stable-1.0-maintenance-input-producer.yml` and
`.github/workflows/stable-1.0-maintenance-windows-package-producer.yml` workflows at the exact
candidate commit; do not substitute a generic artifact upload or a URL-only producer.

If the hotfix replaces a lifecycle-revoked or security-fixes-only build, its lifecycle transition
must bind the same public advisory/incident authorization and authenticated hotfix publication.
Only the separate protected lifecycle workflow may make the verified hotfix `current-stable` and
retain the predecessor's revocation or support history. Build revocation never blows the update key
and cannot be cleared by routine maintenance. Follow
`docs/stable-1.0-support-lifecycle-and-deprecation-governance.md`.

After the verified publication and explicit no-squash, `--no-ff` merges, run `stable-backport` in
`verify-release-completion` mode. It must prove that the published fix is reachable from
`develop`, and both reconciliation merge trees must match Git's isolated automatic merge result.
A manual resolution is not authenticated by merge parents or protected-tip reachability alone.
Once those graph and protected-attestation checks pass, completion records the content-review
failure as the exact `post-release-main-merge` or `hotfix-develop-merge-back` obligation and marks
reconciliation `content-review-required`; the next queue must seed that row and remains blocked
pending separately authenticated review.
A missing merge-back or follow-up remains a carried blocker for the next train. Follow
`docs/stable-1.0-backport-and-release-train-governance.md`.
The next train uses that successful completion run and exact Actions artifact while available.
After Actions retention expires, it reauthenticates the support-lifetime protected completion
bundle instead. Both paths re-resolve protected `main` and `develop` before the prior fix may
transition to `released`.

The `main` merge and `develop` back-merge are separate merges of the same published
`hotfix/<build-number>` candidate. Completion evidence names that candidate—not the `main` merge
commit—as each merge record’s merged tip. Preserve the exact protected train authorization and
validation artifact through maintenance publication; completion may be verified after the earlier
composition authorization expires. Bind the candidate change scope's incident id and hotfix-policy
authorization digest to the same train incident and `stable-backport.security-incident-scope`
evidence, and require the attested merge commits to be reachable from the exact protected
`main`/`develop` tips on their first-parent chains. A merge reachable only through a side parent
does not prove reconciliation.
