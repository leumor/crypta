"""Prospective bounded runtime component derivation from original measured event attachments.

This pure contract grants neither original authentication nor a release decision. Historical
journals without an attachment keep their original semantics. Counts are derived from native
causal records; a caller-authored claim label is never accepted as an observation.
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path
import re

PERF = Path(__file__).resolve().parents[2] / 'perf/runtime_baseline.py'
_spec = importlib.util.spec_from_file_location('cryptad_runtime_baseline', PERF)
baseline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(baseline)
MAX_ATTACHMENT_BYTES = 1024 * 1024
CLAIMS = ('scheduler-executor-observed', 'pressure-before-budget-observed',
          'budget-family-accounting-verified', 'background-recovery-observed',
          'runtime-series-valid', 'runtime-baseline-comparable', 'runtime-within-reviewed-bounds')
KINDS = frozenset(('EXECUTOR_TICK TICK_ENTERED TICK_COMPLETED TICK_ALREADY_RUNNING STORE_UNAVAILABLE '
    'PAUSED NOT_DUE DUE TICK_LIMIT CAPABILITY_DENIED PRESSURE_KNOWN_CLEAR PRESSURE_UNKNOWN '
    'PRESSURE_AVAILABILITY_BLOCKED PRESSURE_CONTENTION_BLOCKED PRESSURE_SKIP BUDGET_CHECK '
    'BUDGET_RESERVE BUDGET_ACQUIRE BUDGET_RATE_DENIED BUDGET_CONCURRENCY_DENIED BUDGET_RESERVED '
    'BUDGET_COMMITTED BUDGET_RELEASED RATE_CHARGED RATE_OBSERVED RATE_RESERVED RATE_RESERVATION_RELEASED CONCURRENCY_HELD CONCURRENCY_RELEASED FETCH_INVOKED FETCH_SUCCEEDED FETCH_FAILED '
    'RETRY_SCHEDULED NEXT_DUE').split())
OPERATIONS = {None, 'foreground_content_fetch', 'content_fetch_global', 'subscription_poll',
              'subscription_manual_refresh', 'trust_graph_import', 'trust_graph_import_uri'}
EVENT_FIELDS = {'sequence', 'observedAt', 'elapsedNanos', 'kind', 'operation', 'windowStartEpochSecond',
                'value', 'operationId', 'scope', 'sourceEpoch', 'sourceSequence', 'sourceSampledAtEpochMillis'}
FETCH_FIELDS = {'known', 'family', 'unit', 'epoch', 'sequence', 'sampledAtEpochMillis',
                'inFlightOperations', 'oldestActiveAgeMillis', 'startedOperations', 'successfulOperations',
                'failedOperations', 'truncated', 'pendingKeys', 'oldestPendingKeyAgeMillis'}


class RuntimeEvidenceError(ValueError):
    """Public fixed diagnostic without private input material."""


def _closed(value, fields, code):
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeEvidenceError(code)


def _number(value):
    return type(value) is int and 0 <= value <= 2**53 - 1


def validate(value, *, workload_digest, observation_time=None):
    """Check bounded original inputs before they can be admitted to a measured journal."""
    fields = {'schemaVersion', 'workloadDigest', 'collectorDigest', 'configurationDigest',
              'series', 'policy', 'workEvents', 'contentFetchSamples', 'budgetValid', 'droppedEvents'}
    if isinstance(value, dict) and 'baseline' in value:
        fields.add('baseline')
    _closed(value, fields, 'runtime-evidence-fields-invalid')
    if (type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['workloadDigest'] != workload_digest
            or any(not baseline.DIGEST.fullmatch(str(value[key])) for key in ('workloadDigest', 'collectorDigest', 'configurationDigest'))
            or type(value['budgetValid']) is not bool or not _number(value['droppedEvents'])):
        raise RuntimeEvidenceError('runtime-evidence-binding-invalid')
    try:
        baseline.validate_series(value['series'])
        baseline.validate_policy(value['policy'])
        if 'baseline' in value:
            baseline.compare(value['series'], value['baseline'])
    except (baseline.BaselineError, TypeError, KeyError):
        raise RuntimeEvidenceError('runtime-evidence-series-invalid') from None
    if len(json.dumps(value, separators=(',', ':'), allow_nan=False).encode()) > MAX_ATTACHMENT_BYTES:
        raise RuntimeEvidenceError('runtime-evidence-byte-cap-exceeded')
    fingerprint = value['series']['fingerprint']
    if any(fingerprint[key] != value[key] for key in ('workloadDigest', 'collectorDigest', 'configurationDigest')):
        raise RuntimeEvidenceError('runtime-evidence-series-binding-invalid')
    if len(value['series']['samples']) > 240:
        raise RuntimeEvidenceError('runtime-evidence-sample-cap-exceeded')
    finish = baseline._time(value['series']['finishedAt'])
    start = baseline._time(value['series']['startedAt'])
    if observation_time is not None and finish > baseline._time(observation_time):
        raise RuntimeEvidenceError('runtime-evidence-post-assessment-sample')
    events = value['workEvents']
    if not isinstance(events, list) or len(events) > 2048:
        raise RuntimeEvidenceError('runtime-evidence-event-cap-exceeded')
    previous = None
    for event in events:
        _closed(event, EVENT_FIELDS, 'runtime-native-event-fields-invalid')
        if (event['kind'] not in KINDS or event['operation'] not in OPERATIONS
                or any(not _number(event[key]) for key in EVENT_FIELDS - {'observedAt', 'kind', 'operation', 'sourceEpoch'})
                or event['sequence'] < 1
                or event['sourceEpoch'] is not None and (not isinstance(event['sourceEpoch'], str) or not re.fullmatch(r'[a-zA-Z0-9._-]{1,96}', event['sourceEpoch']))):
            raise RuntimeEvidenceError('runtime-native-event-value-invalid')
        observed = baseline._time(event['observedAt'])
        window = event['windowStartEpochSecond']
        window_seconds = 3600 if event['operation'] in {'subscription_poll', 'subscription_manual_refresh', 'trust_graph_import'} else 60
        if window and (window > observed.timestamp() or window % window_seconds):
            raise RuntimeEvidenceError('runtime-native-rate-window-invalid')
        # Ring may start before warmup collection; it must never contain future observations.
        if observed > finish or (previous and (event['sequence'] != previous['sequence'] + 1
                or event['elapsedNanos'] < previous['elapsedNanos']
                or observed < baseline._time(previous['observedAt']))):
            raise RuntimeEvidenceError('runtime-native-event-order-invalid')
        if event['sourceSampledAtEpochMillis'] > int(observed.timestamp() * 1000) + 1:
            raise RuntimeEvidenceError('runtime-native-pressure-source-future')
        previous = event
    samples = value['contentFetchSamples']
    if not isinstance(samples, list) or len(samples) > 240:
        raise RuntimeEvidenceError('runtime-content-sample-cap-exceeded')
    previous_owner = None
    for sample in samples:
        _closed(sample, FETCH_FIELDS, 'runtime-content-sample-fields-invalid')
        if (type(sample['known']) is not bool or type(sample['truncated']) is not bool
                or sample['family'] != 'bounded-content-fetch-operations' or sample['unit'] != 'port-calls'
                or sample['pendingKeys'] is not None or sample['oldestPendingKeyAgeMillis'] is not None
                or any(sample[key] is not None and not _number(sample[key]) for key in FETCH_FIELDS -
                       {'known', 'truncated', 'family', 'unit', 'epoch', 'pendingKeys', 'oldestPendingKeyAgeMillis'})
                or not isinstance(sample['epoch'], str) or (not re.fullmatch(r'[a-zA-Z0-9._-]{1,96}', sample['epoch']) and not (sample['known'] is False and sample['epoch'] == ''))
                or not _number(sample['sampledAtEpochMillis'])
                or sample['sampledAtEpochMillis'] > int(finish.timestamp() * 1000) + 1):
            raise RuntimeEvidenceError('runtime-content-sample-value-invalid')
        numeric = ('inFlightOperations', 'oldestActiveAgeMillis', 'startedOperations', 'successfulOperations', 'failedOperations')
        if sample['known'] and (any(sample[key] is None for key in numeric)
                or sample['startedOperations'] != sample['successfulOperations'] + sample['failedOperations'] + sample['inFlightOperations']):
            raise RuntimeEvidenceError('runtime-content-sample-totals-invalid')
        if previous_owner and sample['epoch'] == previous_owner['epoch']:
            if (sample['sequence'] < previous_owner['sequence'] or sample['sampledAtEpochMillis'] < previous_owner['sampledAtEpochMillis']
                    or any(sample[key] is not None and previous_owner[key] is not None and sample[key] < previous_owner[key]
                           for key in ('startedOperations', 'successfulOperations', 'failedOperations'))):
                raise RuntimeEvidenceError('runtime-content-sample-counter-rollback')
        previous_owner = sample
    return value


def derive(value, *, workload_digest, observation_time=None):
    """Derive independent narrow predicates, never full app budgets or maintenance eligibility."""
    validate(value, workload_digest=workload_digest, observation_time=observation_time)
    events = value['workEvents']
    valid = value['budgetValid'] and value['droppedEvents'] == 0 and (not events or events[0]['sequence'] == 1)
    valid = valid and not any(event['kind'] == 'STORE_UNAVAILABLE' for event in events)
    ticks, tick, executor_pending = [], None, False
    for event in events:
        if event['kind'] == 'EXECUTOR_TICK':
            executor_pending = True
        elif event['kind'] == 'TICK_ENTERED':
            tick = {'executor': executor_pending, 'events': []}
            executor_pending = False
        if tick is not None:
            tick['events'].append(event)
        if event['kind'] == 'TICK_COMPLETED' and tick is not None:
            ticks.append(tick)
            tick = None
    def successful(row):
        kinds = [event['kind'] for event in row['events']]
        invoked = {event['operationId'] for event in row['events'] if event['kind'] == 'FETCH_INVOKED' and event['operation'] == 'subscription_poll' and event['operationId'] > 0}
        return row['executor'] and 'DUE' in kinds and any(event['kind'] == 'FETCH_SUCCEEDED' and event['operation'] == 'subscription_poll' and event['operationId'] in invoked and any(prior['kind'] == 'FETCH_INVOKED' and prior['operationId'] == event['operationId'] and prior['sequence'] < event['sequence'] for prior in row['events']) for event in row['events'])
    normal = [row for row in ticks if successful(row)]
    owner_samples = value['contentFetchSamples']
    owners_known = bool(owner_samples) and all(sample['known'] and not sample['truncated'] for sample in owner_samples)
    owner_epochs = {sample['epoch'] for sample in owner_samples}
    valid = valid and owners_known and len(owner_epochs) == 1
    pressure = []
    for row in ticks:
        kinds = [event['kind'] for event in row['events']]
        sources = [event for event in row['events'] if event['kind'] == 'PRESSURE_CONTENTION_BLOCKED' and event['sourceEpoch'] is not None]
        if (row['executor'] and sources and 'DUE' in kinds and 'PRESSURE_SKIP' in kinds
                and kinds.index('PRESSURE_CONTENTION_BLOCKED') < kinds.index('PRESSURE_SKIP')
                and sources[0]['sourceEpoch'] in owner_epochs and sources[0]['sourceSequence'] > 0
                and sources[0]['sourceSequence'] <= max(sample['sequence'] for sample in owner_samples)
                and any(sample['known'] and not sample['truncated'] and sample['inFlightOperations'] is not None and sample['inFlightOperations'] > 0 for sample in owner_samples)
                and sources[0]['value'] > 0
                and not any(event['kind'] in {'BUDGET_RESERVE', 'BUDGET_ACQUIRE', 'BUDGET_COMMITTED', 'FETCH_INVOKED'}
                            and event['operation'] == 'subscription_poll' for event in row['events'])):
            pressure.append(row)
    recovery = bool(pressure and any(successful(row) and row['events'][0]['sequence'] > pressure[-1]['events'][-1]['sequence']
                    and any(event['kind'] == 'PRESSURE_KNOWN_CLEAR' and event['sourceEpoch'] in owner_epochs and event['value'] == 0
                            for event in row['events']) for row in ticks))
    # Correlate each successful poll to its reservation and the three actual durable family charges.
    operations = {}
    for event in events:
        if event['operationId']:
            operations.setdefault(event['operationId'], []).append(event)
    accounting = []
    windows = {}
    for group in operations.values():
        if not any(event['kind'] == 'FETCH_SUCCEEDED' and event['operation'] == 'subscription_poll' for event in group):
            continue
        kinds = [event['kind'] for event in group]
        charges = [event for event in group if event['kind'] == 'RATE_CHARGED']
        families = {(event['operation'], 'global' if event['scope'] == 1 else 'app') for event in charges}
        expected = {('subscription_poll', 'app'), ('subscription_poll', 'global'), ('content_fetch_global', 'global')}
        ordered = all(kind in kinds for kind in ('BUDGET_RESERVED', 'BUDGET_COMMITTED', 'FETCH_INVOKED', 'FETCH_SUCCEEDED', 'BUDGET_RELEASED'))
        if ordered:
            ordered = kinds.index('BUDGET_RESERVED') < kinds.index('BUDGET_COMMITTED') < kinds.index('FETCH_INVOKED') < kinds.index('FETCH_SUCCEEDED') < kinds.index('BUDGET_RELEASED')
        balances = {}
        balance_valid = True
        for event in group:
            kind = event['kind']
            if kind in {'RATE_RESERVED', 'RATE_RESERVATION_RELEASED', 'CONCURRENCY_HELD', 'CONCURRENCY_RELEASED'}:
                family = 'rate' if kind.startswith('RATE_') else 'concurrency'
                key = family, event['operation'], event['scope'], event['windowStartEpochSecond']
                balances[key] = balances.get(key, 0) + (1 if kind in {'RATE_RESERVED', 'CONCURRENCY_HELD'} else -1)
                if balances[key] not in {0, 1}:
                    balance_valid = False
        balance_valid = balance_valid and len(balances) == 6 and all(count == 0 for count in balances.values())
        accounting.append(ordered and balance_valid and len(charges) == 3 and families == expected and
                          all(event['windowStartEpochSecond'] > 0 and event['scope'] > 0 for event in charges))
    # All concurrent families remain in the same event stream, checked at their own fixed window.
    initial = {}
    for event in events:
        if event['kind'] in {'RATE_OBSERVED', 'RATE_CHARGED'}:
            key = event['operation'], event['scope'], event['windowStartEpochSecond']
            operation_key = event['operationId'], key
            if event['kind'] == 'RATE_OBSERVED':
                if key in windows and event['value'] != windows[key]:
                    valid = False
                initial[operation_key] = event['value']
            else:
                if operation_key not in initial or event['value'] != initial.pop(operation_key) + 1:
                    valid = False
                windows[key] = event['value']
    assessed = baseline.assess(value['series'], value['policy'])
    # Exceeding a measured bound does not make the underlying numeric observation unavailable.
    series_valid = not set(assessed['findings']) - {
        'runtime-hard-safety-exceeded', 'runtime-recovery-floor-exceeded'}
    comparison = None
    if 'baseline' in value:
        try:
            comparison = baseline.compare(value['series'], value['baseline'])
        except (baseline.BaselineError, TypeError, KeyError):
            raise RuntimeEvidenceError('runtime-baseline-input-invalid') from None
    comparable = comparison is not None and comparison['status'] != 'incomparable' and not any(
        finding in comparison['findings'] for finding in ('runtime-reference-insufficient-data',
            'runtime-reference-dispersion-exceeded')) and series_valid
    statuses = [bool(valid and normal), bool(valid and pressure), bool(valid and accounting and all(accounting)),
                bool(valid and recovery), series_valid, comparable, False]
    # A local review declaration is not authenticated original approval. The existing maintenance
    # owner must retain its baseline blocker until that separate approval is actually admitted.
    return {'schemaVersion': 1, 'claims': {name: 'observed' if passed else 'not-observed' for name, passed in zip(CLAIMS, statuses)},
            'workloadDigest': workload_digest, 'seriesDigest': baseline.digest(value['series']),
            'evidenceDigest': baseline.digest(value), 'resourceFindings': assessed['findings'],
            'baselineStatus': comparison['status'] if comparison else 'missing-reviewed-runtime-baseline', 'fullAppBudgets': 'not-observed',
            'releaseEligible': False}
