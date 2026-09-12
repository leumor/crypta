"""Constructed native-shaped vectors test derivation, never original runtime authority."""
from __future__ import annotations

import copy
import datetime as dt
import unittest

from cryptad_certification import runtime_pressure_evidence as runtime
from cryptad_certification import cross_version_evidence as journal
from cryptad_certification.tests.test_cross_version_evidence import (
    fixture_plan, fixture_events,
)

STAMP = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
DIGEST = 'sha256:' + 'a' * 64
OWNER = 'native-owner-epoch'


def evidence_fixture():
    """Three executor ticks with real-shaped reserve/charge/release and exact source samples."""
    metric_units = {'rssBytes': 'bytes', 'heapUsedBytes': 'bytes', 'heapCommittedBytes': 'bytes',
                    'heapMaxBytes': 'bytes', 'nonHeapUsedBytes': 'bytes', 'platformThreads': 'threads',
                    'osThreads': 'threads', 'fileDescriptors': 'descriptors', 'cpuNanos': 'nanoseconds',
                    'gcCount': 'collections', 'gcMillis': 'milliseconds', 'inFlight': 'operations',
                    'oldestActiveMillis': 'milliseconds'}
    policy = {'schemaVersion': 1, 'kind': 'cryptad-runtime-baseline-policy', 'metricUnits': metric_units,
              'requiredMetrics': ['rssBytes'], 'cadenceMillis': 1000, 'maxGapMillis': 1500,
              'minimumSamples': 3, 'minimumWindowMillis': 2000, 'minimumRepetitions': 2,
              'phases': ['reference', 'recovery', 'sustained'], 'minimumSuccessRatio': 1,
              'maximumOutstanding': 0, 'maximumDispersionRatio': .1,
              'recoveryMetric': 'rssBytes', 'recoveryAllowance': .1,
              'bounds': {'rssBytes': {'absolutePeak': 1000, 'relativeMedian': .1, 'relativeP95': .1,
                                     'relativePeak': .1, 'maximumSlopePerSecond': 0}}}
    samples = []
    for index in range(12):
        samples.append({'sequence': index, 'epoch': 'daemon-process-epoch',
                        'phase': ('warmup', 'reference', 'recovery', 'sustained')[index // 3],
                        'elapsedMillis': (index + 1) * 1000, 'intervalMillis': 1000, 'valid': True,
                        'metrics': {**dict.fromkeys(metric_units), 'rssBytes': 100},
                        'work': {'offered': 1, 'successful': 1, 'failed': 0, 'cancelled': 0,
                                 'timedOut': 0, 'outstanding': 0, 'latencyMillis': [20]}})
    series = {'schemaVersion': 1, 'kind': 'cryptad-runtime-series', 'runId': 'constructed-unit-vector',
              'evidenceClass': 'synthetic-local', 'startedAt': STAMP.isoformat(),
              'finishedAt': (STAMP + dt.timedelta(seconds=12)).isoformat(),
              'selection': {'baselineDigest': None, 'policyDigest': runtime.baseline.digest(policy), 'selectedAt': STAMP.isoformat()},
              'fingerprint': {key: DIGEST for key in ('productDigest', 'appCohortDigest', 'workloadDigest',
                            'corpusDigest', 'configurationDigest', 'environmentDigest', 'collectorDigest')},
              'samples': samples, 'droppedSamples': 0}
    series['fingerprint']['sourceCommit'] = 'a' * 40
    events, fetch_samples = [], []

    def add(kind, operation=None, operation_id=0, scope=0, value=0, window=0, source=None):
        sequence = len(events) + 1
        time = STAMP + dt.timedelta(milliseconds=sequence * 100)
        event = {'sequence': sequence, 'observedAt': time.isoformat(), 'elapsedNanos': sequence * 100000000,
                 'kind': kind, 'operation': operation, 'operationId': operation_id, 'scope': scope,
                 'value': value, 'windowStartEpochSecond': window, 'sourceEpoch': None,
                 'sourceSequence': 0, 'sourceSampledAtEpochMillis': 0}
        if source is not None:
            transition, in_flight, starts, successes, failures = source
            event.update(sourceEpoch=OWNER, sourceSequence=transition,
                         sourceSampledAtEpochMillis=int(time.timestamp() * 1000), value=in_flight)
            fetch_samples.append({'known': True, 'family': 'bounded-content-fetch-operations', 'unit': 'port-calls',
                                  'epoch': OWNER, 'sequence': transition, 'sampledAtEpochMillis': int(time.timestamp() * 1000),
                                  'inFlightOperations': in_flight, 'oldestActiveAgeMillis': 100 if in_flight else 0,
                                  'startedOperations': starts, 'successfulOperations': successes, 'failedOperations': failures,
                                  'truncated': False, 'pendingKeys': None, 'oldestPendingKeyAgeMillis': None})
        events.append(event)

    def useful_tick(operation_id, charge, source):
        add('EXECUTOR_TICK')
        add('TICK_ENTERED')
        add('PRESSURE_KNOWN_CLEAR', source=source)
        add('DUE')
        add('BUDGET_RESERVE', 'subscription_poll', operation_id)
        families = [('subscription_poll', 2), ('subscription_poll', 1), ('content_fetch_global', 1)]
        for family, scope in families:
            add('RATE_RESERVED', family, operation_id, scope, 1, int(STAMP.timestamp()))
            add('CONCURRENCY_HELD', family, operation_id, scope, 1)
        add('BUDGET_RESERVED', 'subscription_poll', operation_id)
        for family, scope in families:
            add('RATE_OBSERVED', family, operation_id, scope, charge - 1, int(STAMP.timestamp()))
            add('RATE_CHARGED', family, operation_id, scope, charge, int(STAMP.timestamp()))
        add('BUDGET_COMMITTED', 'subscription_poll', operation_id)
        for family, scope in families:
            add('RATE_RESERVATION_RELEASED', family, operation_id, scope, 0, int(STAMP.timestamp()))
        add('FETCH_INVOKED', 'subscription_poll', operation_id)
        add('FETCH_SUCCEEDED', 'subscription_poll', operation_id)
        for family, scope in families:
            add('CONCURRENCY_RELEASED', family, operation_id, scope, 0)
        add('BUDGET_RELEASED', operation_id=operation_id)
        add('NEXT_DUE')
        add('TICK_COMPLETED')

    useful_tick(1, 1, (0, 0, 0, 0, 0))
    add('EXECUTOR_TICK')
    add('TICK_ENTERED')
    add('PRESSURE_CONTENTION_BLOCKED', source=(3, 1, 2, 1, 0))
    add('DUE')
    add('PRESSURE_SKIP')
    add('RETRY_SCHEDULED')
    add('TICK_COMPLETED')
    useful_tick(2, 2, (4, 0, 2, 1, 1))
    return {'schemaVersion': 1, 'workloadDigest': DIGEST, 'collectorDigest': DIGEST,
            'configurationDigest': DIGEST, 'series': series, 'policy': policy,
            'workEvents': events, 'contentFetchSamples': fetch_samples,
            'budgetValid': True, 'droppedEvents': 0}


def derive(value):
    return runtime.derive(value, workload_digest=DIGEST, observation_time='2026-01-01T00:01:00Z')


class RuntimePressureEvidenceTest(unittest.TestCase):
    def test_measured_safety_exceedance_is_not_missing_runtime_series(self):
        value = evidence_fixture()
        for sample in value['series']['samples']:
            sample['metrics']['rssBytes'] = 1001
        result = derive(value)
        self.assertEqual('observed', result['claims']['runtime-series-valid'])
        self.assertIn('runtime-hard-safety-exceeded', result['resourceFindings'])
        self.assertEqual('not-observed', result['claims']['runtime-within-reviewed-bounds'])
        self.assertFalse(result['releaseEligible'])

    def test_original_baseline_inputs_recompute_comparability_without_approval(self):
        value = evidence_fixture()
        references = [copy.deepcopy(value['series']) for _ in range(2)]
        for index, reference in enumerate(references):
            reference['runId'] = 'reference-' + str(index)
            for field in ('startedAt', 'finishedAt'):
                reference[field] = (runtime.baseline._time(reference[field]) - dt.timedelta(days=1)).isoformat()
            reference['selection']['selectedAt'] = reference['startedAt']
        value['baseline'] = runtime.baseline.collect(references, value['policy'])
        value['series']['selection']['baselineDigest'] = runtime.baseline.digest(value['baseline'])
        result = derive(value)
        self.assertEqual('observed', result['claims']['runtime-baseline-comparable'])
        self.assertEqual('not-observed', result['claims']['runtime-within-reviewed-bounds'])
        self.assertEqual('measured-but-uncompared', result['baselineStatus'])
        self.assertFalse(result['releaseEligible'])
        value['baseline']['review'] = {'status': 'reviewed',
            'reviewedAt': (STAMP - dt.timedelta(hours=1)).isoformat(),
            'originDigest': DIGEST, 'approvalDigest': DIGEST,
            'candidateDigest': runtime.baseline.digest(value['baseline']), 'evidenceClass': 'synthetic-local'}
        value['series']['selection']['baselineDigest'] = runtime.baseline.digest(value['baseline'])
        declared_review = derive(value)
        self.assertEqual('within-reviewed-local-bounds', declared_review['baselineStatus'])
        self.assertEqual('not-observed', declared_review['claims']['runtime-within-reviewed-bounds'])
        value['baseline']['referenceSeries'][0]['fingerprint']['environmentDigest'] = 'sha256:' + 'b' * 64
        value['series']['selection']['baselineDigest'] = runtime.baseline.digest(value['baseline'])
        self.assert_unobserved(value, 'runtime-baseline-comparable')

    def test_baseline_summary_cannot_replace_original_numeric_reference(self):
        value = evidence_fixture()
        value['baseline'] = {'status': 'within-reviewed-local-bounds'}
        with self.assertRaises(runtime.RuntimeEvidenceError):
            derive(value)

    def assert_unobserved(self, value, claim):
        try:
            result = derive(value)
        except runtime.RuntimeEvidenceError:
            return
        self.assertEqual('not-observed', result['claims'][claim])

    def test_complete_native_shaped_sequence_grants_only_narrow_components(self):
        result = derive(evidence_fixture())
        for claim in ('scheduler-executor-observed', 'pressure-before-budget-observed',
                      'budget-family-accounting-verified', 'background-recovery-observed', 'runtime-series-valid'):
            self.assertEqual('observed', result['claims'][claim], claim)
        self.assertEqual('not-observed', result['claims']['runtime-baseline-comparable'])
        self.assertEqual('not-observed', result['claims']['runtime-within-reviewed-bounds'])
        self.assertEqual('not-observed', result['fullAppBudgets'])
        self.assertFalse(result['releaseEligible'])

    def test_empty_ticks_manual_ticks_unknown_and_missing_sources_are_not_scheduler_pressure(self):
        for removed in ('DUE', 'EXECUTOR_TICK', 'source', 'unknown'):
            with self.subTest(removed=removed):
                value = evidence_fixture()
                for event in value['workEvents']:
                    if event['kind'] == removed:
                        event['kind'] = 'NOT_DUE' if removed == 'DUE' else 'TICK_ALREADY_RUNNING'
                    if removed == 'source':
                        event['sourceEpoch'] = None
                    if removed == 'unknown' and event['kind'] == 'PRESSURE_CONTENTION_BLOCKED':
                        event['kind'] = 'PRESSURE_UNKNOWN'
                self.assert_unobserved(value, 'pressure-before-budget-observed')

    def test_unknown_truncated_missing_and_different_owner_samples_cannot_prove_pressure(self):
        for change in ('unknown', 'truncated', 'missing', 'epoch'):
            with self.subTest(change=change):
                value = evidence_fixture()
                if change == 'missing':
                    value['contentFetchSamples'] = []
                else:
                    for sample in value['contentFetchSamples']:
                        sample[{'unknown': 'known', 'truncated': 'truncated', 'epoch': 'epoch'}[change]] = {
                            'unknown': False, 'truncated': True, 'epoch': 'different-owner'}[change]
                self.assert_unobserved(value, 'pressure-before-budget-observed')

    def test_recovery_requires_same_owner_and_actual_clear_signal(self):
        for change in ('epoch', 'still-active'):
            with self.subTest(change=change):
                value = evidence_fixture()
                clear = [event for event in value['workEvents'] if event['kind'] == 'PRESSURE_KNOWN_CLEAR'][-1]
                clear['sourceEpoch' if change == 'epoch' else 'value'] = 'another-owner' if change == 'epoch' else 1
                self.assert_unobserved(value, 'background-recovery-observed')

    def test_foreground_success_cannot_be_substituted_for_scheduled_poll(self):
        value = evidence_fixture()
        for event in value['workEvents']:
            if event['kind'] in {'FETCH_INVOKED', 'FETCH_SUCCEEDED'}:
                event['operation'] = 'foreground_content_fetch'
        self.assert_unobserved(value, 'scheduler-executor-observed')

    def test_missing_composed_charge_wrong_scope_and_reordered_commit_cannot_verify_accounting(self):
        for change in ('charge', 'scope', 'commit', 'release'):
            with self.subTest(change=change):
                value = evidence_fixture()
                for event in value['workEvents']:
                    if change == 'charge' and event['kind'] == 'RATE_CHARGED' and event['operation'] == 'content_fetch_global':
                        event['kind'] = 'BUDGET_CHECK'
                    elif change == 'scope' and event['kind'] == 'RATE_CHARGED':
                        event['scope'] = 1
                    elif change == 'commit' and event['kind'] == 'BUDGET_COMMITTED':
                        event['kind'] = 'BUDGET_CHECK'
                    elif change == 'release' and event['kind'] == 'CONCURRENCY_RELEASED':
                        event['kind'] = 'BUDGET_CHECK'
                self.assert_unobserved(value, 'budget-family-accounting-verified')

    def test_fetch_success_before_invocation_cannot_prove_executor_progress(self):
        value = evidence_fixture()
        for event in value['workEvents']:
            if event['kind'] == 'FETCH_INVOKED':
                event['kind'] = 'FETCH_SUCCEEDED'
            elif event['kind'] == 'FETCH_SUCCEEDED':
                event['kind'] = 'FETCH_INVOKED'
        self.assert_unobserved(value, 'scheduler-executor-observed')

    def test_counter_window_first_charge_and_source_sequence_cannot_be_forged(self):
        for change in ('first-charge', 'window', 'source-sequence'):
            with self.subTest(change=change):
                value = evidence_fixture()
                event = next(row for row in value['workEvents'] if row['kind'] == 'RATE_CHARGED')
                if change == 'first-charge':
                    event['value'] = 99
                elif change == 'window':
                    event['windowStartEpochSecond'] += 60
                else:
                    event = next(row for row in value['workEvents'] if row['kind'] == 'PRESSURE_CONTENTION_BLOCKED')
                    event['sourceSequence'] = 999999
                self.assert_unobserved(value, 'pressure-before-budget-observed' if change == 'source-sequence'
                                       else 'budget-family-accounting-verified')

    def test_illegal_native_owner_totals_and_rollback_are_rejected(self):
        for change in ('inconsistent', 'rollback', 'missing-known-count'):
            with self.subTest(change=change):
                value = evidence_fixture()
                sample = value['contentFetchSamples'][-1]
                if change == 'inconsistent':
                    sample['successfulOperations'] = sample['startedOperations'] + 1
                elif change == 'rollback':
                    sample['sequence'] = 1
                else:
                    sample['inFlightOperations'] = None
                with self.assertRaises(runtime.RuntimeEvidenceError):
                    derive(value)

    def test_dropped_records_or_failed_store_observation_prevent_native_claims(self):
        for key, replacement in (('droppedEvents', 1), ('budgetValid', False)):
            value = evidence_fixture()
            value[key] = replacement
            self.assert_unobserved(value, 'pressure-before-budget-observed')
            self.assert_unobserved(value, 'budget-family-accounting-verified')

    def test_future_samples_event_replay_and_wrong_binding_are_rejected(self):
        for change in ('source-future', 'sample-future', 'duplicate-sequence', 'workload', 'fingerprint'):
            with self.subTest(change=change):
                value = evidence_fixture()
                if change == 'source-future':
                    value['workEvents'][2]['sourceSampledAtEpochMillis'] += 1000
                elif change == 'sample-future':
                    value['contentFetchSamples'][0]['sampledAtEpochMillis'] += 60000
                elif change == 'duplicate-sequence':
                    value['workEvents'][4]['sequence'] = value['workEvents'][3]['sequence']
                elif change == 'workload':
                    value['workloadDigest'] = 'sha256:' + 'b' * 64
                else:
                    value['series']['fingerprint']['collectorDigest'] = 'sha256:' + 'b' * 64
                with self.assertRaises(runtime.RuntimeEvidenceError):
                    derive(value)

    def test_future_rate_window_cannot_be_made_valid_by_changing_every_related_record(self):
        value = evidence_fixture()
        for event in value['workEvents']:
            if event['windowStartEpochSecond']:
                event['windowStartEpochSecond'] += 86400
        with self.assertRaises(runtime.RuntimeEvidenceError):
            derive(value)

    def test_attachment_after_assessment_and_wrong_journal_kind_are_rejected(self):
        with self.assertRaises(runtime.RuntimeEvidenceError):
            runtime.validate(evidence_fixture(), workload_digest=DIGEST,
                             observation_time='2026-01-01T00:00:01Z')
        plan = fixture_plan()
        plan['workloadInputs'] = {'scheduler': DIGEST}
        events, _ = fixture_events(plan)
        event = copy.deepcopy(events[0])
        event['runtimeEvidence'] = evidence_fixture()
        with self.assertRaises(journal.EvidenceError):
            journal._validate_event(event, plan)

    def test_caller_authored_claims_and_raw_inventory_fields_are_rejected(self):
        for key in ('claims', 'rawQueue', 'processToken'):
            value = evidence_fixture()
            value[key] = 'not-admitted'
            with self.assertRaises(runtime.RuntimeEvidenceError):
                derive(value)

    def test_historical_journal_without_extension_keeps_original_integrity_and_blockers(self):
        plan = fixture_plan()
        events, checkpoint = fixture_events(plan)
        result = journal.verify(plan, events, checkpoint, now=dt.datetime(2026, 2, 1, tzinfo=dt.timezone.utc))
        self.assertEqual('verified-local-integrity', result['status'])
        self.assertFalse(result['releaseEligible'])
        self.assertEqual('not-authenticated', result['protectedAuthentication'])
        self.assertTrue(all('runtimeEvidence' not in event for event in events))

    def test_journal_extension_binds_exact_source_product_cohort_and_class(self):
        plan = fixture_plan()
        plan['workloadInputs'] = {'scheduler': DIGEST}
        events, _ = fixture_events(plan)
        event = next(copy.deepcopy(row) for row in events if row['kind'] == 'operation')
        event.update(role='candidate-sender', scenario='app-budgets', outcome='partial', peerRole='',
                     nodeEpoch='1' * 32, wallTime='2026-01-01T00:01:00Z')
        event.pop('peerNodeEpoch', None)
        value = evidence_fixture()
        value['series']['fingerprint']['appCohortDigest'] = journal.digest(plan['nodes'][0]['appDigests'])
        event['runtimeEvidence'] = value
        journal._validate_event(event, plan)
        for key in ('sourceCommit', 'productDigest', 'appCohortDigest'):
            with self.subTest(key=key):
                changed = copy.deepcopy(event)
                changed['runtimeEvidence']['series']['fingerprint'][key] = 'b' * 40 if key == 'sourceCommit' else 'sha256:' + 'b' * 64
                with self.assertRaises(journal.EvidenceError):
                    journal._validate_event(changed, plan)
        changed = copy.deepcopy(event)
        changed['runtimeEvidence']['series']['evidenceClass'] = 'operational'
        with self.assertRaises(journal.EvidenceError):
            journal._validate_event(changed, plan)
