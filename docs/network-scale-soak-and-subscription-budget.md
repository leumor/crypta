# Network-scale soak and subscription budget

PR-256 adds a shared app-network budget around the app-facing content and Trust Graph network
surfaces. The goal is to let first-party apps keep long-lived subscription workflows active without
turning a node into a crawler, bypassing queue pressure, leaking raw content, or starving the core
request queue.

This is a Platform API and release-certification boundary. It does not add FNP/FCP wire protocol
changes, global crawling, global Web of Trust, old plugin runtime compatibility, Freemail/Sone/
Freetalk compatibility, encrypted mail, daemon-core message storage, automatic app uninstall, or
operator RC recovery workflows.

## Budget model

The runtime creates one shared `AppNetworkBudgetService` under:

```text
<data-dir>/apps/network-budget/
```

The store writes safe counter metadata only: normalized app id, operation, fixed-window start,
window length, count, last decision, and next available time. It never writes raw fetched content,
request bodies, queue HTML, app-data values, private insert URIs, app or browser tokens, private
keys, raw signatures, source document bodies, rejected source strings, or absolute local paths.

The default limits are conservative and finite:

| Setting | Default |
| --- | ---: |
| Foreground content fetch per app per minute | 20 |
| Foreground content fetch global per minute | 200 |
| Foreground content fetch concurrent per app | 2 |
| Foreground content fetch concurrent global | 16 |
| Subscription poll/manual refresh per app per hour | 48 |
| Subscription poll/manual refresh global per hour | 1024 |
| Subscription poll/manual refresh concurrent per app | 1 |
| Subscription poll/manual refresh concurrent global | 8 |
| Trust Graph import per app per hour | 120 |
| Trust Graph import global per hour | 1024 |
| Trust Graph import concurrent per app | 1 |
| Trust Graph import concurrent global | 8 |

The configuration can be overridden with system properties or environment variables. Invalid,
blank, zero, or negative values keep the finite defaults rather than creating unlimited budgets.

| Property | Environment variable |
| --- | --- |
| `cryptad.appNetworkBudget.foregroundContentFetchPerAppPerMinute` | `CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE` |
| `cryptad.appNetworkBudget.foregroundContentFetchGlobalPerMinute` | `CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_GLOBAL_PER_MINUTE` |
| `cryptad.appNetworkBudget.foregroundContentFetchConcurrentPerApp` | `CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_CONCURRENT_PER_APP` |
| `cryptad.appNetworkBudget.foregroundContentFetchConcurrentGlobal` | `CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_CONCURRENT_GLOBAL` |
| `cryptad.appNetworkBudget.subscriptionPollPerAppPerHour` | `CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_PER_APP_PER_HOUR` |
| `cryptad.appNetworkBudget.subscriptionPollGlobalPerHour` | `CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_GLOBAL_PER_HOUR` |
| `cryptad.appNetworkBudget.subscriptionPollConcurrentPerApp` | `CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_CONCURRENT_PER_APP` |
| `cryptad.appNetworkBudget.subscriptionPollConcurrentGlobal` | `CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_CONCURRENT_GLOBAL` |
| `cryptad.appNetworkBudget.trustGraphImportPerAppPerHour` | `CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR` |
| `cryptad.appNetworkBudget.trustGraphImportGlobalPerHour` | `CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_GLOBAL_PER_HOUR` |
| `cryptad.appNetworkBudget.trustGraphImportConcurrentPerApp` | `CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_CONCURRENT_PER_APP` |
| `cryptad.appNetworkBudget.trustGraphImportConcurrentGlobal` | `CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_CONCURRENT_GLOBAL` |

## Content fetches

`POST /api/v1/content/fetch` remains a bounded app content-read route. App principals still need
`content.fetch`, and `ContentFetchPolicy` still rejects local paths, arbitrary HTTP/HTTPS URLs,
loopback/LAN URLs, generic schemes, query strings, fragments, whitespace, and unsupported key
families before the runtime fetch port is called.

Budget is acquired after source validation and before the runtime content-fetch port. If the app or
global budget is exhausted, the route returns safe `429` errors such as
`content_fetch_budget_exhausted` or `network_budget_concurrency_limited`. Budget denial does not
call the fetch port and does not include the rejected source string or daemon exception text.

## Subscriptions

Subscriptions remain app-owned, USK-only, metadata-only durable records. They are not a generic
crawler and do not discover sources by walking the network.

Manual refresh and scheduler polls consume the shared budget service. The scheduler still applies
all pre-existing controls:

- per-app and global durable subscription limits;
- `perTickFetchLimit`;
- minimum/maximum poll intervals;
- bounded failure backoff and jitter;
- no-overlap scheduler guard;
- stable queue pressure checks through runtime SPI signals;
- metadata-only storage of status, due times, digest, byte length, resolved URI summary, edition,
  failure count, and update count.

Queue pressure takes precedence over budget acquisition. When the pressure gate reports
`queue_pressure` or `runtime_unavailable`, the scheduler skips due polls, records safe metadata,
and does not consume fetch budget or call the fetch port. When pressure is clear but budget is
exhausted, the subscription records `budget_exhausted`, a stable error code such as
`content_subscription_budget_exhausted`, and a bounded retry time. No raw queue HTML is parsed or
exposed.

## Trust Graph imports

`POST /api/v1/trust-graph/import` consumes the Trust Graph import budget before parsing and storing
a statement. `POST /api/v1/trust-graph/import-uri` consumes both the Trust Graph import budget and
the content-fetch budget family before importing fetched content. If import budget is denied,
`import-uri` does not fetch content. If content-fetch budget is denied, `import-uri` does not import
a statement.

Trust Graph Local RC remains local and bounded. It is not full WoT, global moderation, routing
policy, peer scoring, background crawling, or old WebOfTrust plugin compatibility. Import errors and
audit entries use stable codes such as `trust_graph_import_budget_exhausted` and never include raw
statement bodies, raw fetched content, raw signatures, private insert URIs, tokens, or local paths.

## First-party app soak behavior

Social Inbox and Feed Reader inherit the same platform budgets. Their subscription workflows are
bounded by app-owned source lists, the platform subscription service, and the shared content-fetch
budget. Social Inbox refresh-all remains capped by its local source limit and refreshes sources
sequentially rather than starting unbounded parallel requests.

Social Inbox surfaces safe status wording for queue pressure, runtime unavailable, backoff, budget
exhausted, and stale source states. Trust Graph score annotations remain optional and mediated by
operator-approved app-service grants. Budget status or Trust Graph score does not hide, archive,
block, or moderate messages.

## Release evidence

Release certification records PR-256 under:

```text
network-scale.app-network-budget
network-scale.content-fetch-budget
network-scale.subscription-budget
network-scale.queue-pressure-backoff
network-scale.trust-graph-import-budget
network-scale.social-inbox-multi-source-soak
network-scale.redaction
network-scale.rc-soak-summary
```

`tools/release-certification/certify.py network-scale-soak` emits deterministic simulated soak evidence for
normal PR and CI use. The fixture
`tools/release-certification/fixtures/self-test-network-scale-soak.json` validates the summary
schema. Release-candidate runs can attach a live or external 24-hour summary with the same redacted
shape through manifest `inputs.networkScaleSoak`.

A literal 24-hour live soak is an RC release activity. It is not required for ordinary unit tests,
normal PR tests, or the Python self-tests.

The [observed cross-version runner](cross-version-live-network-soak.md) uses a separate measured
journal and policy. Its 72-hour protected target does not replace this gate's duration or authority
requirements. Missing budget/runtime observations remain required findings; an FCP content loop
does not by itself exercise `AppNetworkBudgetService` through app principals.

The Stable GA post-freeze record must identify the exact frozen product/catalog/archive digests
used by every node. Its `longSoak` scenario interval, not merely the enclosing evidence interval or
a claimed duration field, must meet the authoritative Stable GA policy minimum and begin after the
selected protected freeze completed. The record must also carry production live-network,
interoperability, performance-baseline, memory/thread/queue, restart, corruption, and bounded
subscription-growth outcomes. Stale, simulated-only, fixture, or wrong-candidate soak evidence is
not GA proof.

## Redaction boundary

Network-scale budget and soak evidence must not include raw fetched content, raw request bodies,
queue HTML, browser-session tokens, app process tokens, form passwords, private insert URIs,
private keys, raw signatures, raw Trust Graph statement bodies, raw app-data values, app-data
backup payloads, absolute local paths, rejected unsafe source strings, or raw daemon exception
text.

Safe fields include normalized app ids, operation names, bounded counts, booleans, status labels,
stable error codes, window timestamps, next retry timestamps, public key kinds, digests, and
redacted source summaries.

## Maintenance evidence windows

Routine Stable maintenance uses the normal production soak, live-network, interoperability, and
performance windows recorded by the authenticated baseline and current policy. Evidence must be
fresh and bound to the exact frozen candidate. A critical security hotfix may shorten only the
closed scenarios named by policy and authorization; publication then creates a deadline-bound
full-window follow-up obligation without changing the published bytes.

See the [Stable 1.0 maintenance release and security hotfix
path](stable-1.0-maintenance-release-and-hotfix-path.md).

## Prospective scheduler and resource observations

[PR-306's bounded runtime path](pr-306-scheduler-pressure-and-runtime-resource-baselines.md) observes
the existing content-subscription executor and shared network budgets. The optional admission
policy counts active bounded content-fetch port calls with explicit high/low-water thresholds;
it is disabled by default. It does not measure native pending keys or establish strict foreground
priority. Availability denial, budget exhaustion, active-operation contention and OS/JVM resource
measurements remain distinct.

The operator-only observation route records actual pressure-source epochs and correlated
reservation/family-charge/fetch/release events. Its strict bounded budget read distinguishes
unavailable storage from zero usage without changing the legacy tolerant `snapshots()` API.
The measured journal can derive narrow scheduler/accounting/recovery components. The existing
network-scale policy still requires its full Trust Graph/subscription cohort, original evidence
and duration; a passing narrow component does not complete `app-budgets` or the RC soak summary.
