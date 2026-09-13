"""Independent fixed vectors for the runtime comparator; synthetic, never reviewed production data."""
import copy
import datetime as dt
import unittest

import runtime_baseline as runtime


def policy():
    return {'schemaVersion': 1, 'kind': 'cryptad-runtime-baseline-policy', 'metricUnits': runtime.METRICS,
            'requiredMetrics': ['rssBytes', 'osThreads', 'fileDescriptors', 'inFlight', 'cpuNanos'],
            'cadenceMillis': 1000, 'maxGapMillis': 2000, 'minimumSamples': 3,
            'minimumWindowMillis': 2000, 'minimumRepetitions': 2,
            'phases': ['reference', 'recovery', 'sustained'], 'minimumSuccessRatio': .9,
            'maximumOutstanding': 0, 'maximumDispersionRatio': .2,
            'recoveryMetric': 'rssBytes', 'recoveryAllowance': .1,
            'bounds': {key: {'absolutePeak': 1000, 'relativeMedian': .2, 'relativeP95': .2,
                            'relativePeak': .2, 'maximumSlopePerSecond': 10}
                       for key in ['rssBytes', 'osThreads', 'fileDescriptors', 'inFlight']}}


def series(run='reference-a', date='2026-09-12'):
    samples = []
    for index in range(12):
        phase = ['warmup', 'reference', 'recovery', 'sustained'][index // 3]
        samples.append({'sequence': index, 'epoch': 'daemon-a', 'phase': phase,
                        'elapsedMillis': (index + 1) * 1000, 'intervalMillis': 1000, 'valid': True,
                        'metrics': {**dict.fromkeys(runtime.METRICS, None), 'rssBytes': 100,
                                    'osThreads': 10, 'fileDescriptors': 20, 'inFlight': 0, 'cpuNanos': index * 100},
                        'work': {'offered': 1, 'successful': 1, 'failed': 0, 'cancelled': 0,
                                 'timedOut': 0, 'outstanding': 0, 'latencyMillis': [10]}})
    return {'schemaVersion': 1, 'kind': 'cryptad-runtime-series', 'runId': run,
            'evidenceClass': 'synthetic-local', 'startedAt': date + 'T00:00:00Z',
            'finishedAt': date + 'T00:00:12Z',
            'selection': {'baselineDigest': None, 'policyDigest': runtime.digest(policy()), 'selectedAt': date + 'T00:00:00Z'},
            'fingerprint': {key: 'a' * 40 if key == 'sourceCommit' else 'sha256:' + 'a' * 64 for key in runtime.FINGERPRINT},
            'samples': samples, 'droppedSamples': 0}


def reviewed():
    baseline = runtime.collect([series(), series('reference-b')], policy())
    baseline['review'] = {'status': 'reviewed', 'reviewedAt': '2026-09-12T01:00:00Z',
                          'originDigest': 'sha256:' + 'b' * 64, 'approvalDigest': 'sha256:' + 'c' * 64,
                          'candidateDigest': runtime.digest(baseline), 'evidenceClass': 'synthetic-local'}
    candidate = series('candidate', '2026-09-13')
    candidate['selection']['baselineDigest'] = runtime.digest(baseline)
    return baseline, candidate


class RuntimeBaselineTest(unittest.TestCase):
    def test_unreviewed_reference_must_exist_before_candidate_selection(self):
        reference, candidate = reviewed()
        reference['review'] = None
        candidate['selection']['selectedAt'] = '2026-09-12T00:00:00Z'
        candidate['selection']['baselineDigest'] = runtime.digest(reference)
        result = runtime.compare(candidate, reference)
        self.assertEqual('incomparable', result['status'])
        self.assertIn('runtime-baseline-selected-before-reference-existed', result['findings'])

    def test_fixed_statistics_include_nearest_rank_peak_and_slope(self):
        samples = [{'elapsedMillis': 1000 * index, 'metrics': {'rssBytes': value}}
                   for index, value in enumerate([2, 4, 6, 8, 10])]
        self.assertEqual({'median': 6, 'p95': 10, 'peak': 10, 'floor': 2, 'slopePerSecond': 2},
                         runtime._summary(samples, 'rssBytes'))
        self.assertEqual(19, runtime._p95(list(range(1, 21))))

    def test_collect_is_unreviewed_and_retains_failed_attempt(self):
        failed = series('failed')
        failed['samples'][4]['valid'] = False
        baseline = runtime.collect([series(), failed], policy())
        self.assertIsNone(baseline['review'])
        self.assertEqual('insufficient-data', baseline['assessments'][1]['status'])
        self.assertEqual(failed, baseline['referenceSeries'][1])

    def test_comparable_local_review_never_grants_original_authority(self):
        baseline, candidate = reviewed()
        result = runtime.compare(candidate, baseline)
        self.assertEqual('within-reviewed-local-bounds', result['status'])
        self.assertFalse(result['releaseEligible'])
        self.assertEqual('external-original-authentication-required', result['reviewAuthentication'])

    def test_missing_review_never_passes(self):
        baseline, candidate = reviewed()
        baseline['review'] = None
        candidate['selection']['baselineDigest'] = runtime.digest(baseline)
        self.assertEqual('measured-but-uncompared', runtime.compare(candidate, baseline)['status'])

    def test_preselected_bytes_environment_and_self_comparison_are_required(self):
        for change in ('selection', 'environment', 'cohort', 'self'):
            with self.subTest(change=change):
                baseline, candidate = reviewed()
                if change == 'selection':
                    candidate['selection']['baselineDigest'] = None
                elif change in {'environment', 'cohort'}:
                    candidate['fingerprint']['environmentDigest' if change == 'environment' else 'appCohortDigest'] = 'sha256:' + 'd' * 64
                else:
                    candidate['runId'] = 'reference-a'
                self.assertEqual('incomparable', runtime.compare(candidate, baseline)['status'])

    def test_review_cannot_be_promoted_by_flag_or_after_execution(self):
        for change in ('late', 'bytes', 'class', 'extra'):
            with self.subTest(change=change):
                baseline, candidate = reviewed()
                review = baseline['review']
                if change == 'late':
                    review['reviewedAt'] = '2026-09-14T00:00:00Z'
                elif change == 'bytes':
                    review['candidateDigest'] = 'sha256:' + 'f' * 64
                elif change == 'class':
                    review['evidenceClass'] = 'operational'
                else:
                    review['authenticated'] = True
                with self.assertRaises(runtime.BaselineError):
                    runtime.compare(candidate, baseline)

    def test_illegal_metrics_units_counter_rollback_and_clock_are_rejected(self):
        changes = [lambda s: s['samples'][4]['metrics'].update(rssBytes=float('nan')),
                   lambda s: s['samples'][4]['metrics'].update(rssBytes=float('inf')),
                   lambda s: s['samples'][4]['metrics'].update(fileDescriptors=-1),
                   lambda s: s['samples'][4]['metrics'].update(rssKiB=1),
                   lambda s: s['samples'][4]['metrics'].update(cpuNanos=0),
                   lambda s: s['samples'][4].update(elapsedMillis=1000),
                   lambda s: s['samples'][4].update(sequence=1),
                   lambda s: s['samples'][4]['metrics'].update(rssBytes=2**53),
                   lambda s: s['samples'][4]['metrics'].update(heapUsedBytes=5, heapCommittedBytes=4, heapMaxBytes=3),
                   lambda s: s['selection'].update(selectedAt='2026-09-14T00:00:00Z')]
        for change in changes:
            with self.subTest(change=change):
                sample = series()
                change(sample)
                with self.assertRaises(runtime.BaselineError):
                    runtime.validate_series(sample)

    def test_missing_invalid_dropped_short_or_restarted_samples_cannot_pass(self):
        for change in ('missing', 'invalid', 'dropped', 'short', 'restart', 'gap'):
            with self.subTest(change=change):
                sample = series()
                if change == 'missing':
                    sample['samples'][4]['metrics']['rssBytes'] = None
                elif change == 'invalid':
                    sample['samples'][4]['valid'] = False
                elif change == 'dropped':
                    sample['droppedSamples'] = 1
                elif change == 'short':
                    sample['samples'] = sample['samples'][:7]
                elif change == 'restart':
                    for item in sample['samples'][6:]:
                        item['epoch'] = 'daemon-b'
                else:
                    sample['samples'][4]['intervalMillis'] = 3000
                self.assertEqual('insufficient-data', runtime.assess(sample, policy())['status'])

    def test_no_work_and_accumulating_outstanding_are_not_stability(self):
        for accumulating in (False, True):
            sample = series()
            for index, item in enumerate(sample['samples']):
                item['work'].update(offered=1 if accumulating else 0, successful=0,
                                    outstanding=index + 1 if accumulating else 0, latencyMillis=[])
            result = runtime.assess(sample, policy())
            self.assertIn('runtime-useful-progress-insufficient', result['findings'])
            if accumulating:
                self.assertIn('runtime-outstanding-work-exceeded', result['findings'])

    def test_timeout_latency_is_retained_and_cannot_be_omitted(self):
        sample = series()
        sample['samples'][4]['work'].update(successful=0, timedOut=1, latencyMillis=[90000])
        result = runtime.assess(sample, policy())
        self.assertEqual(90000, result['phases']['reference']['work']['terminalLatencyP95Millis'])
        self.assertIn('runtime-useful-progress-insufficient', result['findings'])
        sample['samples'][4]['work']['latencyMillis'] = []
        with self.assertRaises(runtime.BaselineError):
            runtime.validate_series(sample)

    def test_hard_safety_warmup_regression_recovery_and_trend(self):
        for change, expected in [('hard', 'runtime-hard-safety-exceeded'), ('regression', 'runtime-regression-exceeded'),
                                 ('recovery', 'runtime-recovery-floor-exceeded')]:
            with self.subTest(change=change):
                baseline, candidate = reviewed()
                if change == 'hard':
                    candidate['samples'][0]['metrics']['rssBytes'] = 1001
                elif change == 'regression':
                    for index, sample in enumerate(candidate['samples'][9:]):
                        sample['metrics']['rssBytes'] = 100 + 50 * index
                else:
                    for sample in candidate['samples'][6:9]:
                        sample['metrics']['rssBytes'] = 115
                self.assertIn(expected, runtime.compare(candidate, baseline)['findings'])

    def test_collector_tail_gap_and_interleaved_phases_fail(self):
        sample = series()
        sample['finishedAt'] = '2026-09-12T01:00:00Z'
        self.assertIn('runtime-sample-tail-gap', runtime.assess(sample, policy())['findings'])
        sample = series()
        sample['samples'][4]['phase'] = 'pressure'
        self.assertIn('runtime-phase-not-contiguous', runtime.assess(sample, policy())['findings'])

    def test_unavailable_sample_cannot_hide_counter_rollback(self):
        sample = series()
        sample['samples'][4]['metrics']['cpuNanos'] = None
        sample['samples'][5]['metrics']['cpuNanos'] = 1
        with self.assertRaisesRegex(runtime.BaselineError, 'runtime-counter-rollback'):
            runtime.validate_series(sample)

    def test_sampling_interval_cannot_invent_covered_wall_time(self):
        sample = series()
        for row in sample['samples']:
            row['intervalMillis'] = 1
        self.assertIn('runtime-sample-gap', runtime.assess(sample, policy())['findings'])

    def test_unhashable_policy_values_have_fixed_diagnostics(self):
        for key in ('requiredMetrics', 'phases'):
            selected = policy()
            selected[key] = [{}]
            with self.assertRaises(runtime.BaselineError):
                runtime.validate_policy(selected)

    def test_cpu_gc_deltas_have_explicit_single_core_denominator(self):
        sample = series()
        for index, row in enumerate(sample['samples']):
            row['metrics'].update(cpuNanos=index * 500000000, gcCount=index, gcMillis=index * 5)
        observed = runtime.assess(sample, policy())['phases']['reference']
        self.assertEqual(2000, observed['windowMillis'])
        self.assertEqual(2000, observed['qualifiedMillis'])
        self.assertEqual({'cpuNanos': 1000000000, 'gcCount': 2, 'gcMillis': 10}, observed['counterDeltas'])
        self.assertEqual(.5, observed['cpuOneCoreRatio'])
        self.assertEqual(1, observed['work']['successfulOperationsPerSecond'])

    def test_policy_cannot_change_after_series_collection(self):
        selected = policy()
        selected['minimumSamples'] = 4
        with self.assertRaisesRegex(runtime.BaselineError, 'runtime-policy-not-preselected'):
            runtime.assess(series(), selected)

    def test_reference_dispersion_and_repetition_are_not_silently_filtered(self):
        baseline, candidate = reviewed()
        baseline = runtime.collect([series()], policy())
        candidate['selection']['baselineDigest'] = runtime.digest(baseline)
        self.assertIn('runtime-reference-insufficient-data', runtime.compare(candidate, baseline)['findings'])
        second = series('reference-b')
        for sample in second['samples']:
            sample['metrics']['rssBytes'] = 150
        baseline = runtime.collect([series(), second], policy())
        candidate['selection']['baselineDigest'] = runtime.digest(baseline)
        self.assertIn('runtime-reference-dispersion-exceeded', runtime.compare(candidate, baseline)['findings'])


if __name__ == '__main__':
    unittest.main()
