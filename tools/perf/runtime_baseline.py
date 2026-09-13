#!/usr/bin/env python3
"""Bounded, pure runtime series collection and deterministic local baseline comparison.

Collection consumes exact-process observations produced by the owned runtime workload. It does
not start nodes or grant original producer/reviewer authority. Units and statistical definitions
are fixed here; baseline selection must precede the candidate execution.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

MAX_BYTES = 16 * 1024 * 1024
MAX_SAMPLES = 4096
MAX_NUMBER = 2**53 - 1
METRICS = {
    'rssBytes': 'bytes', 'heapUsedBytes': 'bytes', 'heapCommittedBytes': 'bytes',
    'heapMaxBytes': 'bytes', 'nonHeapUsedBytes': 'bytes', 'platformThreads': 'threads',
    'osThreads': 'threads', 'fileDescriptors': 'descriptors', 'cpuNanos': 'nanoseconds',
    'gcCount': 'collections', 'gcMillis': 'milliseconds', 'inFlight': 'operations',
    'oldestActiveMillis': 'milliseconds',
}
COUNTERS = {'cpuNanos', 'gcCount', 'gcMillis'}
PHASES = {'warmup', 'reference', 'budget', 'pressure', 'recovery', 'sustained', 'restart'}
FINGERPRINT = {'productDigest', 'sourceCommit', 'appCohortDigest', 'workloadDigest',
               'corpusDigest', 'configurationDigest', 'environmentDigest', 'collectorDigest'}
COMPARABLE = FINGERPRINT - {'productDigest', 'sourceCommit'}
WORK = {'offered', 'successful', 'failed', 'cancelled', 'timedOut', 'outstanding', 'latencyMillis'}
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')


class BaselineError(ValueError):
    """Fixed diagnostic code; never includes private input text."""


def digest(value):
    return 'sha256:' + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _closed(value, keys, code):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise BaselineError(code)


def _integer(value, maximum=MAX_NUMBER):
    return type(value) is int and 0 <= value <= maximum


def _time(value):
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError()
        return result
    except (AttributeError, ValueError, TypeError):
        raise BaselineError('runtime-timestamp-invalid') from None


def validate_series(value):
    """Reject malformed values and preserve unavailable samples and epoch boundaries."""
    _closed(value, {'schemaVersion', 'kind', 'runId', 'evidenceClass', 'startedAt', 'finishedAt',
                    'selection', 'fingerprint', 'samples', 'droppedSamples'}, 'runtime-series-fields-invalid')
    if (type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['kind'] != 'cryptad-runtime-series'
            or not isinstance(value['runId'], str) or not LABEL.fullmatch(value['runId'])
            or value['evidenceClass'] not in {'synthetic-local', 'operational'}):
        raise BaselineError('runtime-series-identity-invalid')
    start, finish = _time(value['startedAt']), _time(value['finishedAt'])
    if not 0 < (finish - start).total_seconds() <= 432000:
        raise BaselineError('runtime-series-duration-invalid')
    _closed(value['selection'], {'baselineDigest', 'policyDigest', 'selectedAt'}, 'runtime-selection-fields-invalid')
    selection = value['selection']
    if (not DIGEST.fullmatch(str(selection['policyDigest'])) or selection['baselineDigest'] is not None and not DIGEST.fullmatch(str(selection['baselineDigest']))
            or _time(selection['selectedAt']) > start):
        raise BaselineError('runtime-baseline-not-preselected')
    _closed(value['fingerprint'], FINGERPRINT, 'runtime-fingerprint-fields-invalid')
    for key, item in value['fingerprint'].items():
        pattern = r'[a-f0-9]{40}' if key == 'sourceCommit' else r'sha256:[a-f0-9]{64}'
        if not isinstance(item, str) or re.fullmatch(pattern, item) is None:
            raise BaselineError('runtime-fingerprint-invalid')
    samples = value['samples']
    if (not isinstance(samples, list) or not 1 <= len(samples) <= MAX_SAMPLES
            or not _integer(value['droppedSamples'])):
        raise BaselineError('runtime-series-cap-invalid')
    previous, epoch, seen, outstanding = None, None, set(), 0
    counter_values = {}
    for index, sample in enumerate(samples):
        _closed(sample, {'sequence', 'epoch', 'phase', 'elapsedMillis', 'intervalMillis', 'valid', 'metrics', 'work'},
                'runtime-sample-fields-invalid')
        if (sample['sequence'] != index or type(sample['sequence']) is not int
                or not isinstance(sample['epoch'], str) or not LABEL.fullmatch(sample['epoch'])
                or sample['phase'] not in PHASES or type(sample['valid']) is not bool
                or not _integer(sample['elapsedMillis'], 432000000)
                or not _integer(sample['intervalMillis'], 600000) or sample['intervalMillis'] == 0
                or sample['elapsedMillis'] > (finish - start).total_seconds() * 1000 + 1):
            raise BaselineError('runtime-sample-clock-or-label-invalid')
        if previous and sample['elapsedMillis'] <= previous['elapsedMillis']:
            raise BaselineError('runtime-sample-order-invalid')
        if epoch != sample['epoch']:
            if sample['epoch'] in seen:
                raise BaselineError('runtime-epoch-reused')
            if outstanding:
                raise BaselineError('runtime-restart-hides-outstanding-work')
            seen.add(sample['epoch'])
            epoch = sample['epoch']
            counter_values = {}
        _closed(sample['metrics'], METRICS, 'runtime-metric-units-or-roster-invalid')
        for key, item in sample['metrics'].items():
            if item is not None and not _integer(item):
                raise BaselineError('runtime-metric-value-invalid')
            if key in COUNTERS and item is not None:
                if key in counter_values and item < counter_values[key]:
                    raise BaselineError('runtime-counter-rollback')
                counter_values[key] = item
        metrics = sample['metrics']
        if all(metrics[key] is not None for key in ('heapUsedBytes', 'heapCommittedBytes', 'heapMaxBytes')):
            if not metrics['heapUsedBytes'] <= metrics['heapCommittedBytes'] <= metrics['heapMaxBytes']:
                raise BaselineError('runtime-heap-order-invalid')
        _closed(sample['work'], WORK, 'runtime-work-fields-invalid')
        work = sample['work']
        if (any(not _integer(work[key], 1000000) for key in WORK - {'latencyMillis'})
                or not isinstance(work['latencyMillis'], list) or len(work['latencyMillis']) > 10000
                or any(not _integer(item, 432000000) for item in work['latencyMillis'])
                or len(work['latencyMillis']) != sum(work[key] for key in ('successful', 'failed', 'cancelled', 'timedOut'))
                or outstanding + work['offered'] != work['outstanding'] + len(work['latencyMillis'])):
            raise BaselineError('runtime-work-accounting-invalid')
        outstanding = work['outstanding']
        previous = sample
    return value


def validate_policy(policy):
    _closed(policy, {'schemaVersion', 'kind', 'metricUnits', 'requiredMetrics', 'cadenceMillis',
                     'maxGapMillis', 'minimumSamples', 'minimumWindowMillis', 'minimumRepetitions',
                     'phases', 'minimumSuccessRatio', 'maximumOutstanding', 'maximumDispersionRatio',
                     'recoveryMetric', 'recoveryAllowance', 'bounds'}, 'runtime-policy-fields-invalid')
    if (type(policy['schemaVersion']) is not int or policy['schemaVersion'] != 1
            or policy['kind'] != 'cryptad-runtime-baseline-policy' or policy['metricUnits'] != METRICS
            or not isinstance(policy['requiredMetrics'], list) or not policy['requiredMetrics']
            or any(not isinstance(item, str) for item in policy['requiredMetrics'])
            or len(set(policy['requiredMetrics'])) != len(policy['requiredMetrics'])
            or not set(policy['requiredMetrics']) <= set(METRICS)
            or not isinstance(policy['phases'], list) or not policy['phases']
            or any(not isinstance(item, str) for item in policy['phases'])
            or len(set(policy['phases'])) != len(policy['phases'])
            or not set(policy['phases']) <= PHASES - {'warmup', 'restart'}):
        raise BaselineError('runtime-policy-metrics-invalid')
    for key in ('cadenceMillis', 'maxGapMillis', 'minimumSamples', 'minimumWindowMillis', 'minimumRepetitions', 'maximumOutstanding'):
        if not _integer(policy[key], 432000000):
            raise BaselineError('runtime-policy-number-invalid')
    if (not 1 <= policy['cadenceMillis'] <= policy['maxGapMillis'] <= 600000
            or not 3 <= policy['minimumSamples'] <= MAX_SAMPLES or policy['minimumWindowMillis'] < 1
            or not 1 <= policy['minimumRepetitions'] <= 16):
        raise BaselineError('runtime-policy-window-invalid')
    for key in ('minimumSuccessRatio', 'maximumDispersionRatio', 'recoveryAllowance'):
        if type(policy[key]) not in {int, float} or not math.isfinite(policy[key]) or not 0 <= policy[key] <= 1:
            raise BaselineError('runtime-policy-ratio-invalid')
    if policy['recoveryMetric'] not in policy['requiredMetrics'] or policy['recoveryMetric'] in COUNTERS:
        raise BaselineError('runtime-policy-recovery-invalid')
    if not isinstance(policy['bounds'], dict) or set(policy['bounds']) != set(policy['requiredMetrics']) - COUNTERS:
        raise BaselineError('runtime-policy-bounds-invalid')
    for limits in policy['bounds'].values():
        _closed(limits, {'absolutePeak', 'relativeMedian', 'relativeP95', 'relativePeak', 'maximumSlopePerSecond'},
                'runtime-policy-bound-fields-invalid')
        for key, number in limits.items():
            if type(number) not in {int, float} or not math.isfinite(number) or number < 0 or number > MAX_NUMBER:
                raise BaselineError('runtime-policy-bound-invalid')
    return policy


def _p95(values):
    """Nearest-rank p95, retaining all terminal outcomes including timeout latency."""
    return sorted(values)[math.ceil(.95 * len(values)) - 1]


def _summary(samples, metric):
    values = [sample['metrics'][metric] for sample in samples]
    times = [sample['elapsedMillis'] / 1000 for sample in samples]
    # Fixed ordinary least squares over the predeclared phase, not selected favorable windows.
    tx, vy = statistics.mean(times), statistics.mean(values)
    slope = sum((x - tx) * (y - vy) for x, y in zip(times, values)) / sum((x - tx)**2 for x in times)
    return {'median': statistics.median(values), 'p95': _p95(values), 'peak': max(values),
            'floor': min(values), 'slopePerSecond': slope}


def assess(series, policy):
    """Produce per-phase numeric summaries; gaps and missing work remain findings."""
    validate_series(series)
    validate_policy(policy)
    if series['selection']['policyDigest'] != digest(policy):
        raise BaselineError('runtime-policy-not-preselected')
    findings, summaries = set(), {}
    if series['droppedSamples']:
        findings.add('runtime-samples-dropped')
    if len({sample['epoch'] for sample in series['samples']}) != 1:
        findings.add('runtime-epoch-segment-required')
    previous = 0
    completed_phases, last_phase = set(), None
    for sample in series['samples']:
        if sample['phase'] != last_phase:
            if sample['phase'] in completed_phases:
                findings.add('runtime-phase-not-contiguous')
            if last_phase is not None:
                completed_phases.add(last_phase)
            last_phase = sample['phase']
        gap = sample['elapsedMillis'] - previous
        if (gap > policy['maxGapMillis'] or sample['intervalMillis'] > policy['maxGapMillis']
                or abs(sample['intervalMillis'] - gap) > 1
                or (previous and gap < policy['cadenceMillis'])):
            findings.add('runtime-sample-gap')
        previous = sample['elapsedMillis']
        if not sample['valid']:
            findings.add('runtime-invalid-sample')
        if any(sample['metrics'][key] is None for key in policy['requiredMetrics']):
            findings.add('runtime-mandatory-metric-unavailable')
    if (_time(series['finishedAt']) - _time(series['startedAt'])).total_seconds() * 1000 - previous > policy['maxGapMillis']:
        findings.add('runtime-sample-tail-gap')
    for phase in policy['phases']:
        selected = [sample for sample in series['samples'] if sample['phase'] == phase]
        if (len(selected) < policy['minimumSamples']
                or selected[-1]['elapsedMillis'] - selected[0]['elapsedMillis'] < policy['minimumWindowMillis']):
            findings.add('runtime-insufficient-phase-window')
            continue
        if any(not sample['valid'] or any(sample['metrics'][key] is None for key in policy['requiredMetrics']) for sample in selected):
            continue
        counts = {key: sum(sample['work'][key] for sample in selected) for key in ('offered', 'successful', 'failed', 'cancelled', 'timedOut')}
        terminal = sum(counts[key] for key in ('successful', 'failed', 'cancelled', 'timedOut'))
        denominator = terminal + selected[-1]['work']['outstanding']
        success_ratio = counts['successful'] / denominator if denominator else 0
        if not counts['successful'] or success_ratio < policy['minimumSuccessRatio']:
            findings.add('runtime-useful-progress-insufficient')
        if max(sample['work']['outstanding'] for sample in selected) > policy['maximumOutstanding']:
            findings.add('runtime-outstanding-work-exceeded')
        latencies = [latency for sample in selected for latency in sample['work']['latencyMillis']]
        window_millis = selected[-1]['elapsedMillis'] - selected[0]['elapsedMillis']
        deltas = {key: (selected[-1]['metrics'][key] - selected[0]['metrics'][key]
                       if selected[-1]['metrics'][key] is not None and selected[0]['metrics'][key] is not None else None)
                  for key in COUNTERS}
        summaries[phase] = {'metrics': {key: _summary(selected, key) for key in policy['bounds']},
                            'windowMillis': window_millis,
                            'qualifiedMillis': sum(sample['intervalMillis'] for sample in selected[1:]),
                            'counterDeltas': deltas,
                            'cpuOneCoreRatio': deltas['cpuNanos'] / (window_millis * 1000000) if deltas['cpuNanos'] is not None else None,
                            'cpuDenominator': 'one-logical-cpu-times-window-nanoseconds',
                            'work': {**counts, 'terminal': terminal, 'outstanding': selected[-1]['work']['outstanding'],
                                     'successfulOperationsPerSecond': counts['successful'] * 1000 / sum(sample['intervalMillis'] for sample in selected),
                                     'successRatio': success_ratio, 'terminalLatencyP95Millis': _p95(latencies) if latencies else None}}
    hard = []
    for sample in series['samples']:
        for key, limits in policy['bounds'].items():
            if sample['metrics'][key] is not None and sample['metrics'][key] > limits['absolutePeak']:
                hard.append(key)
    if hard:
        findings.add('runtime-hard-safety-exceeded')
    if 'reference' in summaries and 'recovery' in summaries:
        key = policy['recoveryMetric']
        reference, recovery = (summaries[phase]['metrics'][key] for phase in ('reference', 'recovery'))
        if recovery['median'] > reference['median'] * (1 + policy['recoveryAllowance']):
            findings.add('runtime-recovery-floor-exceeded')
    return {'status': 'valid' if not findings else 'insufficient-data', 'findings': sorted(findings),
            'hardSafetyExceededMetrics': sorted(set(hard)), 'phases': summaries,
            'seriesDigest': digest(series), 'policyDigest': digest(policy)}


def collect(series_list, policy):
    """Create an unreviewed candidate, preserving every selected attempt and raw series."""
    validate_policy(policy)
    if not isinstance(series_list, list) or not 1 <= len(series_list) <= 16:
        raise BaselineError('runtime-reference-repetitions-invalid')
    assessments = [assess(series, policy) for series in series_list]
    if len({series['runId'] for series in series_list}) != len(series_list):
        raise BaselineError('runtime-reference-repetition-duplicated')
    if any(series['fingerprint'] != series_list[0]['fingerprint'] or series['evidenceClass'] != series_list[0]['evidenceClass'] for series in series_list):
        raise BaselineError('runtime-reference-repetitions-incomparable')
    return {'schemaVersion': 1, 'kind': 'cryptad-runtime-baseline', 'review': None,
            'policy': policy, 'referenceSeries': series_list, 'assessments': assessments}


def compare(series, baseline):
    """Compare exact preselected local review bytes; this result is never release authority."""
    validate_series(series)
    _closed(baseline, {'schemaVersion', 'kind', 'review', 'policy', 'referenceSeries', 'assessments'}, 'runtime-baseline-fields-invalid')
    rebuilt = collect(baseline['referenceSeries'], baseline['policy'])
    if any(baseline[key] != rebuilt[key] for key in ('schemaVersion', 'kind', 'assessments')):
        raise BaselineError('runtime-baseline-recomputed-content-mismatch')
    policy = baseline['policy']
    candidate = assess(series, policy)
    findings = set(candidate['findings'])
    reference = baseline['referenceSeries']
    review = baseline['review']
    if review is None:
        findings.add('reviewed-runtime-baseline-missing')
    else:
        _closed(review, {'status', 'reviewedAt', 'originDigest', 'approvalDigest', 'candidateDigest', 'evidenceClass'}, 'runtime-review-fields-invalid')
        if (review['status'] != 'reviewed' or review['evidenceClass'] != reference[0]['evidenceClass']
                or not all(DIGEST.fullmatch(str(review[key])) for key in ('originDigest', 'approvalDigest', 'candidateDigest'))
                or review['candidateDigest'] != digest(rebuilt)
                or _time(review['reviewedAt']) > _time(series['selection']['selectedAt'])
                or any(_time(item['finishedAt']) > _time(review['reviewedAt']) for item in reference)):
            raise BaselineError('runtime-review-invalid')
    if series['selection']['baselineDigest'] != digest(baseline):
        findings.add('runtime-baseline-selection-mismatch')
    if any(_time(item['finishedAt']) > _time(series['selection']['selectedAt']) for item in reference):
        findings.add('runtime-baseline-selected-before-reference-existed')
    if any(series['runId'] == item['runId'] or digest(series) == digest(item) for item in reference):
        findings.add('runtime-baseline-self-comparison')
    if any(any(series['fingerprint'][key] != item['fingerprint'][key] for key in COMPARABLE)
           or series['evidenceClass'] != item['evidenceClass'] for item in reference):
        findings.add('runtime-environment-incomparable')
    if len(reference) < policy['minimumRepetitions'] or any(item['status'] != 'valid' for item in baseline['assessments']):
        findings.add('runtime-reference-insufficient-data')
    regressions = []
    for phase, summary in candidate['phases'].items():
        if any(phase not in result['phases'] for result in baseline['assessments']):
            continue
        for key, limits in policy['bounds'].items():
            current = summary['metrics'][key]
            references = [result['phases'][phase]['metrics'][key] for result in baseline['assessments']]
            medians = [item['median'] for item in references]
            center = statistics.median(medians)
            if max(medians) - min(medians) > center * policy['maximumDispersionRatio']:
                findings.add('runtime-reference-dispersion-exceeded')
            for statistic in ('median', 'p95', 'peak'):
                expected = statistics.median(item[statistic] for item in references)
                if current[statistic] > expected * (1 + limits['relative' + statistic[0].upper() + statistic[1:]]):
                    regressions.append(phase + '.' + key + '.' + statistic)
            if current['slopePerSecond'] > limits['maximumSlopePerSecond']:
                regressions.append(phase + '.' + key + '.slope')
    if regressions:
        findings.add('runtime-regression-exceeded')
    incomparable = {'runtime-environment-incomparable', 'runtime-baseline-selection-mismatch', 'runtime-baseline-self-comparison',
                    'runtime-baseline-selected-before-reference-existed'}
    status = ('incomparable' if findings & incomparable else 'measured-but-uncompared' if 'reviewed-runtime-baseline-missing' in findings
              else 'fail' if findings & {'runtime-hard-safety-exceeded', 'runtime-regression-exceeded', 'runtime-recovery-floor-exceeded'}
              else 'insufficient-data' if findings else 'within-reviewed-local-bounds')
    return {'schemaVersion': 1, 'status': status, 'findings': sorted(findings), 'regressions': sorted(regressions),
            'candidate': candidate, 'baselineDigest': digest(baseline), 'evidenceClass': series['evidenceClass'],
            'reviewAuthentication': 'external-original-authentication-required', 'releaseEligible': False}


def _read(path):
    if path.stat().st_size > MAX_BYTES:
        raise BaselineError('runtime-input-byte-budget-exceeded')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BaselineError('runtime-input-duplicate-key')
            result[key] = value
        return result
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError):
        raise BaselineError('runtime-input-json-invalid') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    collect_parser = sub.add_parser('collect')
    collect_parser.add_argument('--series', type=Path, action='append', required=True)
    collect_parser.add_argument('--policy', type=Path, required=True)
    compare_parser = sub.add_parser('compare')
    compare_parser.add_argument('--series', type=Path, required=True)
    compare_parser.add_argument('--baseline', type=Path, required=True)
    for command in (collect_parser, compare_parser):
        command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = (collect([_read(path) for path in args.series], _read(args.policy)) if args.command == 'collect'
                  else compare(_read(args.series), _read(args.baseline)))
        content = json.dumps(result, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'
        if len(content) > MAX_BYTES:
            raise BaselineError('runtime-output-byte-budget-exceeded')
        # Raw numeric series remains private; never overwrite a reviewed reference or old run.
        import os
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
        print(json.dumps({'status': 'unreviewed-candidate' if args.command == 'collect' else result['status'], 'releaseEligible': False}))
        return 0 if args.command == 'collect' or result['status'] == 'within-reviewed-local-bounds' else 2
    except (OSError, BaselineError) as error:
        print(json.dumps({'status': 'failed', 'code': str(error) if isinstance(error, BaselineError) else 'runtime-file-operation-failed'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
