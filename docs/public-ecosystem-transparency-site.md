# Public ecosystem transparency site

Build and verify a static, public-only view of selected Crypta ecosystem evidence with
`certify.py public-ecosystem-transparency`. The site presents evidence with its original scope;
it does not authorize releases, install apps, import trust, operate nodes, or close Phase 12.

This implementation supplies a deterministic static export, closed source admission, offline
verification, a guarded Pages reference workflow, and explicit bounded observation. Original
operational public inputs and host approval are separate prerequisites. Internal release,
maintenance, and vulnerability receipts are not public site assets. The source-owned exporter
reruns their existing scoped authority verifiers and emits separate, closed public projections;
the original private context and its proof material remain outside the site.

## Source and integration identity

Implementation started from clean `develop` commit
`ca54bcbc16f30a4edaf72f813a287ddc3a40e165`, tree
`5a4e6cdc3f9b3406c34d6e8545f758d9c07b7af6`, on local branch
`feature/pr-302-public-ecosystem-transparency-site`.
[PR #1403](https://github.com/crypta-network/cryptad/pull/1403) merged on
2026-09-10 at 12:09:39 UTC with that squash commit. Its final feature head was
`3c8f56090ccf4da7e997ddfe067d569d3f50c967`; the earlier inspected
`bcb8bb1192ab459167a90086c99271704ce91735` is not a required ancestor of the squash.

The final PR-head Java run
[34472243115](https://github.com/crypta-network/cryptad/actions/runs/34472243115)
and Beta dry-run
[34472243125](https://github.com/crypta-network/cryptad/actions/runs/34472243125)
reported success. Production jobs were skipped. GitHub's PR rollup reported successful CodeQL and
SonarCloud checks. A PR-triggered workflow can check out its merge ref; these results do not prove
execution of the eventual squash tree. At initial implementation inspection, squash-head Java CI
`34475158913` remained in progress. The old supply-chain expression failure and its extracted helper
must not be reclassified as successful hosted supply-chain execution by these observations.

No commit, push, PR creation, workflow dispatch, Pages configuration, release, tag, catalog
publication, deployment, or public-byte observation is authorized by the local implementation.

## Local build and preview

Use Python 3 and the repository checkout matching the selected tool identity. No daemon, Java
runtime, database, frontend framework, or browser-side verification service is required.
Choose a new output directory for every build; existing output and linked ancestors are rejected.

```bash
mkdir -p build/transparency
python3 tools/release-certification/certify.py public-ecosystem-transparency --mode plan
python3 tools/release-certification/certify.py public-ecosystem-transparency \
  --mode build --as-of 2026-09-10T12:09:39Z \
  --output build/transparency/empty-production
python3 tools/release-certification/certify.py public-ecosystem-transparency \
  --mode verify --production --bundle build/transparency/empty-production
python3 -m http.server 8080 --bind 127.0.0.1 --directory build/transparency/empty-production
```

Open `http://127.0.0.1:8080/` explicitly for local preview. That local server is a development
operation, not a production source collector. The site does not contact local daemon ports.

The checked-in `production-selection.json` intentionally has an empty source list. Empty production
states that no authenticated public release was supplied and makes no complete inventory claim.
The reviewed `repository-status.json` is separately pinned in `source-policy.json`; use `--selection tools/ecosystem-transparency/repository-selection.json` to show the
repository-reported Phase 12 obligations with exact role, file, digest and size bindings. It does not become an operational receipt.

```bash
python3 tools/release-certification/certify.py public-ecosystem-transparency \
  --mode build --demo --as-of 2026-09-10T12:09:39Z \
  --output build/transparency/demo-site
```

Demo output names must contain `demo`, every page retains its banner, and production verification
rejects it. Demo inputs never serve as fallback for absent or invalid production sources.

## Data ownership and adapter matrix

The reviewed policy at
[`tools/ecosystem-transparency/source-policy.json`](../tools/ecosystem-transparency/source-policy.json)
selects exact source bytes; local source names are replaced with fixed opaque export names.
The closed selection contains no arbitrary JSON paths, imports, shell
commands, templates, recursive links, or open API queries. The source package is separate from
private verification scratch. Source-selection and site-bundle v1 schemas define those external
JSON boundaries; the source-owned projection uses its own closed disclosure contract; type-specific checks reuse existing artifact schemas. Only admitted safe original bytes can enter the public source
snapshot. A filename, URL, signature, clean scanner result or `public=true` field is not a
disclosure rule.

| Logical role and actual source | Original authority / reusable verifier | Public presentation and copying | Current boundary |
| --- | --- | --- | --- |
| `release`: GA publication receipt v1 | GA selected RC, promotion and `publication_receipt_errors` | Integer build/source and approved public product references only | Full receipt is rejected; the source-owned exporter invokes the existing contextual verifier and emits safe identity/product/metadata references |
| `maintenance`: maintenance publication receipt v1 | Existing maintenance publication and activation authority | Public payload checksums, approved notes and product references only | Internal inventories and pointers are rejected; source-owned export verifies the original candidate/plan/receipt context and selects approved payload roles |
| `catalogs`: canonical catalog properties subset v1–v7 | Exact original catalog plus detached signature and selected role key | Catalog/app identity and scoped edition/channel fields | Supported properties and exact signature sidecar verification; richer security-policy/submission fields reject; original producer proof remains separate |
| `reviews`: review properties v1/v2 | Existing ordered review signing payload and Ed25519 verifier | Exact app/version/bundle/reviewer/policy scope and reviewed-at eligibility | Selected trusted reviewer and signature verified where supplied by reviewed policy; review is no safety guarantee |
| `keys`: PR-293 public-key transparency v1 | Existing recovery-key/signature and SPKI helpers | Dedicated governance SPKI, roles, validity, lifecycle and lineage | Approved governance-key exception only; a valid historical signature does not authorize new signing |
| `lifecycle`: support descriptor v1 | Existing lifecycle descriptor contract and semantic digest | Exact edition, effective time, staleAt, windows, revocation and nullable tips | No build-number sorting or refreshed support promise; original producer proof remains separate |
| `advisories`: vulnerability advisory v1 | Original disclosure authorization and publication authority | Explicitly disclosed component/fix/correction information only | Original disclosure chain executes privately before the source-owned public export; case identifiers, reporter associations and private digests are omitted |
| `supply-chain`, `sbom`, `reproducibility`: existing v1 inventories/bindings/results | Existing schemas, semantic digests and source comparison rules | Component roles and exact listed comparison subjects/classes | Same-control-plane result cannot establish PR-292 provider-distinct reproduction; missing proof remains unavailable |
| `drill`: PR-301 isolated drill v1 | Fixed contract, fourteen cases, historical helper/policy/source bindings and local seal | Bounded case outcomes and original partial/blocked/pending dimensions | Local integrity only; no historical code execution and no HEAD identity rewrite |
| `repository-status`: reviewed public repository statement v1 | Exact checked-in policy pin and closed residual contract | Phase 12 obligations and Mail contract/baseline distinctions | Repository-reported incomplete state, never protected operational evidence |

Release and advisory pages accept only the new closed source-owned public projections, with
separate exact downloads of those derived statements. A raw schema-shaped receipt cannot enter
these families. The consumer labels reported source verification/publication separately from
its own unavailable original-producer proof; it never attaches an original signature to the
derived bytes. Supplied-invalid sources block the build; they cannot be silently omitted from a
claimed complete inventory.

The existing vulnerability “public projection” includes `privateRecordDigest`, `caseSnapshotDigest`,
`caseOpaqueId` and reporter associations. These are excluded from site admission. Mail contact,
message, backup and ciphertext identifiers, migration contents and digests, incident composition,
subscription lists, support bundles, private insertion material, paths and credentials are not
anonymized by hashing them. Governance SPKI keys are permitted only through the dedicated typed key
artifact; the exception never applies to arbitrary fields named `publicKey`.

## Claims and time

Each public row separately records provenance, signature/semantic verification, disclosure,
evidence class, publication, activation, original observation time and stale time. Upstream fields
remain visible; site generation does not turn schema validity into authenticated production
operation. Missing proof is distinct from a failed supplied signature.

The fixed snapshot `asOf` identifies the presentation. Source `observedAt`, descriptor `effectiveAt`
and `staleAt` remain unchanged across builds. A static page cannot know later revocation. Current
support and recommended builds come from the descriptor, including the valid emergency case in
which a revoked tip has no current or recommended successor. Mail stays experimental: milestone
1.0, URL v1, contract 26, baseline contract 19 and integer product builds are distinct.

Passing all fourteen PR-301 synthetic cases still means `implementationCoverage=partial`,
`originalProtectedRuntime=not-observed`, `maintenanceEligibility=blocked-original-authority-required`,
publication and activation `not-performed`, and independent security review `pending`. The
[maintenance handoff](stable-maintenance-operations-drill.md#pr-302-handoff) and
[Phase 12 tracker](phase-12-open-items.md) remain authoritative for those repository statements.

## Export integrity and offline verification

The public index binds the admitted source snapshot, source policy, tool/assets identity, mode and
fixed time. Rendered pages display that snapshot identity. `site-bundle-manifest.json` lists the
exact generated regular files and excludes itself. Later external attestations and observations
are separate records and are not inserted into the already hashed bundle.

Verification reads every member, rejects extras/sidecars, unsafe names, links, nonregular files,
duplicate JSON keys and limits, re-admits the exact source bytes, reconstructs the public index,
and compares regenerated files byte for byte. This binds rendering to content, not merely a
caller-edited file list. The verifier needs the matching reviewed tool and policy checkout, but no
daemon or network. It does not accept arbitrary embedded verifier code.

```bash
python3 tools/release-certification/certify.py public-ecosystem-transparency \
  --mode verify --production --bundle build/transparency/empty-production \
  --expected-manifest-digest sha256:REPLACE_WITH_SEPARATELY_APPROVED_MANIFEST_DIGEST
```

Without a separately authenticated expected digest, successful verification means local
consistency, not site authentication. A site build attestation, if separately authorized, proves
site provenance only. Do not use catalog, reviewer, recovery or Mail signing keys for the site.
Original signature verification requires explicitly selected trusted roots and historical proof
material. Offline roots have a snapshot/time limitation; see GitHub's
[offline attestation verification guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline).
Attestations bind provenance and do not guarantee artifact security, as described in
[GitHub's attestation model](https://docs.github.com/en/actions/concepts/security/artifact-attestations).

## Source-owned exports, acquisition and observation

For release, maintenance or advisory input, use the existing original authority manifest and its
complete original private evidence graph. `project` executes fixed source-owned verification code
and writes a fresh public projection only after success. It never accepts a caller `verified`
Boolean, runs artifact-selected code, or copies its private scratch. The original production
producer must authenticate its full context through its existing authority before this projection
is used as production evidence.

```bash
python3 tools/release-certification/certify.py public-ecosystem-transparency \
  --mode project --role release --authority-manifest ORIGINAL_GA_MANIFEST.json \
  --private-root NEW_PRIVATE_VERIFICATION_DIRECTORY --output NEW_PUBLIC_PROJECTION.json
```

Use `--role maintenance` or `--role advisories` with that authority's matching manifest. GA and
maintenance are fixed to `validate-only`; advisory runs the existing disclosure-publication
verification. Private scratch is new, confined and mode 0700. Public output must be separate and
fresh. Failure produces a fixed diagnostic and no public projection. Existing private reports
may remain in the private scratch for the source owner; do not upload them with the site.

The default denies DNS resolution. Some original GA/maintenance HTTPS-target validation requires
real DNS. Only an explicit `project --online` allows that existing read-only check, with finite
query, result and time bounds; it adds no HTTP collector or publisher. Offline builds and bundle
verification never make network calls. This local change does not execute `project --online`.

The projection's digest identifies derived public bytes, not the withheld private receipt. The
site reports `originalProducerProof=not-exported-private-context`; a source-owned verifier report
alone is not an authenticated operational badge. Select the exact resulting public projection
through reviewed policy and original acquisition authority before a production build. The demo
factory exercises actual original GA, maintenance and complete advisory disclosure verifiers on
fixed synthetic contexts, and visibly labels the output synthetic.


Local `collect` reads only the selection's exact files. `collect --online` is an explicit read-only
operation that permits only reviewed source URLs and original-artifact coordinates; build and
verify never fetch. Configure approved original producers, source members, roots, immutable byte
identities and disclosure rules through code review before selecting operational sources. No such
live source is added by the example empty policy.

```bash
python3 tools/release-certification/certify.py public-ecosystem-transparency \
  --mode collect --online --selection REVIEWED_SELECTION.json --output NEW_PUBLIC_PACKAGE.json
python3 tools/release-certification/certify.py public-ecosystem-transparency \
  --mode build --source-package NEW_PUBLIC_PACKAGE.json --output NEW_SITE_DIRECTORY
```

Observation is also explicit. Add the exact HTTPS site base to the reviewed policy's `siteTargets`
and configure the same host/path in the deployment environment. URLs with credentials, sensitive
queries, encodings, private addresses or redirects fail. Existing HTTP transport pins validated
DNS addresses, bounds bytes/time, and never follows linked resources. The observer performs one
pass over the exact manifest and every required asset, returning exact-match, partial, conflict
or unavailable with fixed counts. A homepage HTTP 200 is insufficient.

```bash
python3 tools/release-certification/certify.py public-ecosystem-transparency \
  --mode observe --bundle build/transparency/empty-production \
  --url https://APPROVED_PUBLIC_HOST/APPROVED_SITE_PATH/ \
  --observed-at 2026-09-10T13:00:00Z \
  --expected-manifest-digest sha256:REPLACE_WITH_APPROVED_SITE_MANIFEST_DIGEST
```

Record this output outside the bundle. CDN propagation and mixed generations may make a single
observation partial or conflicting. Do not poll without bounds or call source releases published
because site bytes match. A separate job on the same provider is not independent infrastructure.

## Guarded GitHub Pages reference path

The dedicated
[workflow](../.github/workflows/public-ecosystem-transparency.yml) separates ordinary PR offline tests
from a manually dispatched, protected build on `develop`, artifact transfer verification, Pages
packaging, protected deployment and optional read-only observation. Actions are pinned to exact
commits; checkout uses the event's exact SHA and does not persist credentials. Deployment receives
only the already verified public site artifact and has no source checkout or node/release secrets.
It has only `pages: write` and `id-token: write`; no job receives release/tag/catalog mutation
permissions. Transfer verification binds the original manifest digest and rejects a substituted
artifact before Pages upload. No rebuild occurs after the protected build.

A maintainer must separately approve the reviewed source policy, confirm that the target does not
overwrite another site, configure Pages and branch/environment protections, and approve actual
execution. The workflow does not create Pages settings, domains, or environments. Serialize the
selected production target. Configure `PUBLIC_ECOSYSTEM_SITE_URL` only after the reviewed target exists.
The reference workflow's default production selection is intentionally empty; it does not promote
PR artifacts or receive private incident repository credentials.

GitHub requires deployment permissions, a build dependency and an environment for custom Pages
workflows; see the [official Pages boundary](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
A checked-in workflow does not establish that these protections were configured or that any
remote job ran. Deployment and public observation have not been performed for this implementation.

The observation step preserves its failing exit status for partial, unavailable or conflicting
results. Its artifact-retention step runs even after that failure when the fixed, nonempty
`public-observation.json` report was produced. It uploads only that file; a failed transfer
verification or an observer that produces no report does not enable retention.

## Required deployment checkpoint approval

Every protected Pages dispatch rejects a snapshot `as_of` later than the runner's current UTC time
before rendering. Transfer verification repeats this check against the actual bundled public index
before Pages packaging. Offline generation remains deterministic and does not consult the clock.

Every protected Pages dispatch now verifies the currently served checkpoint before rendering,
and verifies it again in the transfer job before packaging for Pages. The workflow remains
serialized for the site target. Configure the exact approved URL in `siteTargets` and the
protected build environment's `PUBLIC_ECOSYSTEM_SITE_URL`.

For a successor, set `PUBLIC_ECOSYSTEM_CURRENT_MANIFEST_DIGEST` to the independently approved
`sha256:` digest of the currently published site manifest. Leave
`PUBLIC_ECOSYSTEM_BOOTSTRAP_MANIFEST_DIGEST` empty. The explicit `checkpoint` command fetches
that manifest through the bounded, DNS-pinned site transport, checks its approved digest before
fetching members, and verifies all exact files and snapshot bindings. Only the resulting verified
prior bundle enters the build's `--previous-bundle` / `--previous-manifest-digest` checks.
Transfer verification repeats collection and history checking; an older timestamp, removed row,
changed current manifest, missing asset or expired checkpoint availability blocks packaging.
No partial checkpoint or network-error fallback is used. Old tool code is never executed.

For the first publication only, independently prepare and approve the exact initial production
bundle with the intended tool/policy/source bytes and fixed `as_of`. Set its manifest digest in
`PUBLIC_ECOSYSTEM_BOOTSTRAP_MANIFEST_DIGEST`, leaving the current-manifest variable empty.
Both preflights require an actual HTTP 404 at the approved manifest URL; 403, 410, redirects,
timeouts and other failures do not establish absence. The generated and transferred bundle must
match the approved initial digest exactly. This is a protected first-publication approval, not
permission to reclaim an existing site. After publication, retire the bootstrap approval and
advance the current-manifest pin through protected operator approval. If the pin is not advanced,
a subsequent dispatch fails against the changed current bytes. Withdrawal or missing-current-site
recovery requires separate reviewed authorization; never reuse bootstrap approval as a rollback.

Example read-only successor checkpoint collection:

```bash
python3 tools/release-certification/certify.py public-ecosystem-transparency \
  --mode checkpoint --url "$APPROVED_SITE_URL" \
  --previous-manifest-digest "$APPROVED_CURRENT_MANIFEST_DIGEST" \
  --output build/transparency/previous-site
```

The two checkpoint checks bound the observed state; they are not a global transparency log or a
cross-provider lock. The target must be dedicated to this serialized publication workflow.
Concurrent external writes, a compromised host serving stale bytes, and stale operator approvals
remain outside that guarantee. No environment variables were configured and no deployment or
live checkpoint acquisition was performed while implementing these checks.

## History, corrections and withdrawal

Repository-status statements have revision identities bound to their exact public-byte digests.
When updating the checked-in statement, retain the old revision's role/digest/size pin and
`reviewed-repository-status-v1` disclosure rule in `approvedSources`, add the reviewed new pin,
and select both exact public revisions in the successor input. Historical files need not equal
the current `repository-status.json`; they must still match their explicitly retained policy pins.
Removing a historical pin blocks its admission, and omitting its row blocks checkpoint succession.
Legacy checkpoints with the fixed `repository-status` identity are compared using their existing
`originalPublicBytesDigest`; all other row fields remain subject to the unchanged-history check.
The original checkpoint files and manifest remain untouched.

Store approved exports under distinct immutable snapshot directories outside the working checkout
where storage policy permits. `--previous-bundle` selects a checkpoint during build. When the
reviewed tool or policy changed, also supply `--previous-manifest-digest` from the separately
approved prior checkpoint. That path verifies the exact prior file inventory and snapshot binding
without executing old code or relabeling old source identities. A caller-provided checksum does
not create independent authentication; its trust must come from the existing approval boundary.
Without the explicit prior pin, prior verification requires the matching current tool/policy.
Snapshot time must
advance and previously selected rows must remain byte-equivalent. It rejects same-identity changes
and removed rows, including known revocations. Supplied lifecycle and keyset successors must bind
the previous semantic digest and retain known revoked builds/key identities. This conservative presentation rule is not an
upstream release/catalog ledger; full authority-specific successor/correction validation remains
owned by original authorities. First use without an independently pinned checkpoint cannot detect
every validly signed stale snapshot or global equivocation.

A current-site pointer is presentation metadata only; it must not select release tips or support
windows. Restore an older UI only by rendering the latest admitted evidence with that reviewed UI,
so known revocations are retained. Do not copy an old snapshot over current evidence and call it
fresh. For a disclosure incident, stop publication, quarantine unsafe export material, and follow
an approved withdrawal/correction process. Suppression of public presentation does not rewrite
original signed release records. Do not promise erasure from caches or mirrors or require
accidentally exposed secrets to remain published forever.

## Browser, privacy and host headers

All assets are local. Core content and navigation work without JavaScript; no SDK, Web Shell,
external fonts/images, analytics, persistence, service worker, forms, trust buttons or app installs
are included. Upstream text is escaped, never interpreted as HTML or Markdown. The application
adds no user telemetry or subscription reporting. Hosting providers and CDNs may still observe
visitor network requests: static hosting is not an anonymity guarantee.

The HTML meta CSP restricts content to local styles and disables script, object, frame and network
content by default. `Referrer-Policy: no-referrer` is also represented by HTML metadata. For a host
that supports custom headers, configure and independently observe at least:

```text
Content-Security-Policy: default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

A meta CSP cannot enforce `frame-ancestors`; see
[MDN's directive reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors).
Local browser fixture headers do not prove production host headers. This change does not configure
or assert GitHub Pages custom response headers.

## Validation and remaining ownership

Local validation on the implementation working tree passed the source, adapter, bundle and
workflow conformance suites, plus real Chromium tests of empty production, reviewed repository
status, populated synthetic data, the executed isolated drill and hostile renderer text. The
original-authority regressions passed: maintenance drill 13, maintenance 243, catalog authority
111, lifecycle 120, supply chain 86, independent reproducibility 39, app-platform 2, shared release
certification 50 and security-response 7 tests. No Java/API code changed, so no new Gradle run was
needed; the actual checkout retains wrapper 9.7.1. Workflow lint and changed-document local links
passed. These results do not establish hosted checks on unpublished local changes or production
host headers.


```bash
python3 tools/release-certification/certify.py public-ecosystem-transparency --self-test
node tools/ecosystem-transparency/tests/browser.cjs build/transparency/empty-production
node tools/ecosystem-transparency/tests/browser.cjs --renderer-fixture
```

The browser suite requires installed Playwright and a compatible Chromium binary. It checks actual
navigation, downloads, mobile layout, keyboard focus, no-JavaScript content and captured network
traffic. Its hostile renderer fixture is synthetic presentation testing, not source-authentication
evidence. Python tests exercise admission/projection, malicious inputs, deterministic exports,
content/manifest substitution, history and synthetic local HTTP observation. Original authority
regressions remain separate from this site's tests.

PR-303 owns actual Phase 12 closeout. The site leaves PR-296 federation projection, PR-297 migration
browser/rollback/cleanup, PR-300 runtime adapters and measured consumer mappings, original long-run
observations, Mail lifecycle/restore/security work and PR-301 protected maintenance observations
open. Completing a site build does not remove any of those obligations. Production operation also
requires eligible original public data, approved site deployment and actual observed bytes.
