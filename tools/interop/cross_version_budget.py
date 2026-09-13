"""Bounded own-app budget and exact-process resource observations.

The caller is the approved supervisor. It reserves up to38requests, provides its actual
synthetic CHK/bytes and a freshly bootstrapped Feed Reader handle, and pins this helper,
its fixed Node driver and Node executable. This does not prove scheduler pressure or
steady-state resource limits; absent reviewed runtime baselines remain unobserved.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.parse

HERE = Path(__file__).resolve().parent
PROTECTED = HERE.parent / 'release-certification/protected'
sys.path.insert(0, str(PROTECTED))
from bounded_process import run

CATEGORIES = {'success', 'concurrency-limited', 'rate-limited', 'forbidden', 'body-mismatch', 'unexpected', 'transport-failed'}


class BudgetObservationError(ValueError):
    """Closed diagnostic, excluding request/response/session/process contents."""


def file_digest(path):
    with path.open('rb') as stream:
        return 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()


def target(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', '::1'}
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {'', '/'} or not parsed.port):
        raise BudgetObservationError('budget-own-app-target-invalid')
    return value.rstrip('/')


def summarize(report):
    if (not isinstance(report, dict) or set(report) != {'schemaVersion', 'requests', 'counts', 'recovery', 'backoffMillis'}
            or report['schemaVersion'] != 1 or type(report['requests']) is not int or not 18 <= report['requests'] <= 38
            or not isinstance(report['counts'], dict) or set(report['counts']) != CATEGORIES
            or any(type(value) is not int or not 0 <= value <= 38 for value in report['counts'].values())
            or sum(report['counts'].values()) != report['requests'] or report['recovery'] not in CATEGORIES
            or report['counts'][report['recovery']] < 1 or report['backoffMillis'] not in {100, 61000}):
        raise BudgetObservationError('budget-observer-output-invalid')
    counts = report['counts']
    failed = bool(counts['forbidden'] or counts['body-mismatch'])
    return {'schemaVersion': 1, 'status': 'fail' if failed else 'partial',
            'requestCount': report['requests'], 'successfulFetches': counts['success'],
            'concurrencyDenials': counts['concurrency-limited'], 'rateDenials': counts['rate-limited'],
            'otherFailures': sum(counts[key] for key in ('forbidden', 'body-mismatch', 'unexpected', 'transport-failed')),
            'cases': {'foreground-concurrency': 'observed' if counts['concurrency-limited'] else 'not-observed',
                      'foreground-rate': 'observed' if counts['rate-limited'] else 'not-observed',
                      'foreground-recovery': 'observed' if report['recovery'] == 'success' else 'not-observed',
                      'scheduler-queue-pressure-precedence': 'not-observed'},
            'fullAppBudgets': 'not-observed'}


def observe_budget(app, synthetic_uri, expected_bytes, node_executable, node_digest,
                   remaining_seconds, *, activation_digest=None):
    """Execute only the fixed driver; real target/session authority belongs to its supervisor."""
    if app.app_id != 'feed-reader' or not isinstance(expected_bytes, bytes) or not 1 <= len(expected_bytes) <= 8192:
        raise BudgetObservationError('budget-selected-app-or-content-invalid')
    if not isinstance(synthetic_uri, str) or not re.fullmatch(r'CHK@[A-Za-z0-9~,._/\-]{1,2048}', synthetic_uri):
        raise BudgetObservationError('budget-synthetic-reference-invalid')
    base, origin = target(app.base), target(app.origin)
    if base == origin or not isinstance(app.session, str) or not app.session or len(app.session) > 4096 or '\n' in app.session or '\r' in app.session:
        raise BudgetObservationError('budget-own-app-session-invalid')
    executable = Path(node_executable)
    if (not executable.is_absolute() or executable.is_symlink() or not executable.is_file()
            or any(parent.is_symlink() for parent in executable.parents) or file_digest(executable) != node_digest):
        raise BudgetObservationError('budget-node-executable-not-selected')
    supervisor = getattr(app, 'supervisor', None)
    if supervisor is not None and supervisor.plan.get('profile') == 'protected-long-live' and activation_digest is None:
        raise BudgetObservationError('budget-protected-activation-required')
    if activation_digest is not None and not re.fullmatch(r'sha256:[a-f0-9]{64}', activation_digest):
        raise BudgetObservationError('budget-activation-digest-invalid')
    remaining = remaining_seconds() if callable(remaining_seconds) else remaining_seconds
    if not isinstance(remaining, (int, float)) or isinstance(remaining, bool) or not 185 <= remaining <= 432000:
        raise BudgetObservationError('budget-observation-time-unavailable')
    driver = HERE / 'cross_version_budget_driver.cjs'
    payload = {'base': base, 'origin': origin, 'session': app.session, 'uri': synthetic_uri,
               'expected': base64.b64encode(expected_bytes).decode(), 'deadlineMillis': 184000,
               'deadlineMonotonicNs': str(time.monotonic_ns() + 184000000000),
               'activationDigest': activation_digest}
    try:
        output = run([str(executable), str(driver)], environment={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                     payload=json.dumps(payload, separators=(',', ':')).encode(), timeout=185, output_limit=4096)
        return summarize(json.loads(output))
    except (ValueError, OSError, UnicodeError):
        raise BudgetObservationError('budget-observation-failed-private-reconciliation-required') from None


def _epoch(pid, proc):
    fields = (proc / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'startTicks': int(fields[19]), 'bootId': (proc / 'sys/kernel/random/boot_id').read_text().strip()}


def measure_resources(identity, app=None, *, jvm_executable_digest, proc_root=Path('/proc')):
    """Read exact daemon JVM epoch and own-app counters; export numbers, never inventories."""
    if not isinstance(identity, dict) or type(identity.get('pid')) is not int or identity['pid'] <= 1:
        raise BudgetObservationError('resource-process-identity-invalid')
    pid = identity['pid']
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', str(jvm_executable_digest)) or file_digest(proc_root / str(pid) / 'exe') != jvm_executable_digest:
        raise BudgetObservationError('resource-selected-jvm-not-observed')
    expected = {key: identity[key] for key in ('pid', 'startTicks', 'bootId')}
    if _epoch(pid, proc_root) != expected:
        raise BudgetObservationError('resource-process-epoch-substituted')
    metrics = {name: None for name in ('memoryBytes', 'threads', 'fileDescriptors', 'queueDepth', 'subscriptions')}
    unavailable = []
    try:
        values = dict(line.split(':', 1) for line in (proc_root / str(pid) / 'status').read_text().splitlines() if ':' in line)
        rss = re.fullmatch(r'\s*(\d+)\s+kB\s*', values.get('VmRSS', ''))
        if rss:
            metrics['memoryBytes'] = int(rss[1]) * 1024
        threads = values.get('Threads', '').strip()
        if threads.isdigit():
            metrics['threads'] = int(threads)
    except OSError:
        pass
    try:
        with os.scandir(proc_root / str(pid) / 'fd') as entries:
            count = 0
            for _ in entries:
                count += 1
                if count > 65536:
                    raise BudgetObservationError('resource-fd-observation-budget-exceeded')
            metrics['fileDescriptors'] = count
    except OSError:
        pass
    if app is not None:
        for field, route, key in (('subscriptions', '/api/v1/content/subscriptions', 'subscriptions'),):
            try:
                status, value = app.request('GET', route, principal='app')
                rows = value.get(key)
                if status == 200 and isinstance(rows, list) and len(rows) <= 10000:
                    metrics[field] = len(rows)
            except (ValueError, OSError):
                pass
    if _epoch(pid, proc_root) != expected or file_digest(proc_root / str(pid) / 'exe') != jvm_executable_digest:
        raise BudgetObservationError('resource-process-epoch-changed-during-sample')
    unavailable = sorted(key for key, value in metrics.items() if value is None)
    return {'schemaVersion': 1, 'status': 'measured-but-uncompared', 'metrics': metrics,
            'unavailable': unavailable, 'queueSource': 'legacy-html-count-not-admitted', 'baseline': 'missing-reviewed-runtime-baseline',
            'baselineApplicability': 'existing-performance-smoke-startup-and-assets-do-not-cover-runtime-growth'}


RUNTIME_METRICS = ('rssBytes', 'heapUsedBytes', 'heapCommittedBytes', 'heapMaxBytes',
                   'nonHeapUsedBytes', 'platformThreads', 'osThreads', 'fileDescriptors',
                   'cpuNanos', 'gcCount', 'gcMillis', 'inFlight', 'oldestActiveMillis')


def measure_runtime_sample(identity, *, executable_digest, proc_root=Path('/proc'), runtime_snapshot=None):
    """Fixed numeric process reads; callers retain each epoch separately and never export identity.

    RSS is Linux resident process memory, OS threads count /proc task threads (not Java virtual
    threads), FDs are counted without reading targets. CPU is cumulative user+system process time
    converted using this host's SC_CLK_TCK, not a percentage. JVM values come only from the fixed
    operator snapshot. Missing reads remain None; every sample brackets all reads by exact identity.
    """
    started = time.monotonic_ns()
    try:
        old = measure_resources(identity, jvm_executable_digest=executable_digest, proc_root=proc_root)
    except (OSError, KeyError, IndexError):
        raise BudgetObservationError('resource-exact-process-read-unavailable') from None
    metrics = dict.fromkeys(RUNTIME_METRICS)
    metrics.update(rssBytes=old['metrics']['memoryBytes'], osThreads=old['metrics']['threads'],
                   fileDescriptors=old['metrics']['fileDescriptors'])
    pid = identity['pid']
    expected = {key: identity[key] for key in ('pid', 'startTicks', 'bootId')}
    try:
        fields = (proc_root / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
        user, system = int(fields[11]), int(fields[12])
        ticks = os.sysconf('SC_CLK_TCK')
        if user >= 0 and system >= 0 and ticks > 0:
            metrics['cpuNanos'] = (user + system) * 1000000000 // ticks
    except (OSError, ValueError, IndexError):
        pass
    snapshot = runtime_snapshot() if callable(runtime_snapshot) else runtime_snapshot
    if snapshot is not None:
        if not isinstance(snapshot, dict):
            raise BudgetObservationError('resource-runtime-snapshot-invalid')
        # This shape is the fixed operator collector contract, not arbitrary management reads.
        for key in RUNTIME_METRICS:
            if key in {'rssBytes', 'osThreads', 'fileDescriptors', 'cpuNanos'}:
                continue
            value = snapshot.get('jvm', {}).get('metrics', {}).get('gcTimeMillis' if key == 'gcMillis' else key)
            if key in {'inFlight', 'oldestActiveMillis'}:
                fetch = snapshot.get('contentFetch', {})
                value = (fetch.get('inFlightOperations' if key == 'inFlight' else 'oldestActiveAgeMillis')
                         if fetch.get('known') is True and fetch.get('truncated') is False else None)
            if value is not None and (type(value) is not int or not 0 <= value <= 2**63 - 1):
                raise BudgetObservationError('resource-runtime-metric-invalid')
            metrics[key] = value
    if (_epoch(pid, proc_root) != expected
            or file_digest(proc_root / str(pid) / 'exe') != executable_digest):
        raise BudgetObservationError('resource-process-epoch-changed-during-sample')
    if any(value is not None and (type(value) is not int or not 0 <= value <= 2**63 - 1)
           for value in metrics.values()):
        raise BudgetObservationError('resource-process-metric-invalid')
    return {'metrics': metrics, 'startedMonotonicNs': started, 'finishedMonotonicNs': time.monotonic_ns(),
            'unavailable': sorted(key for key, value in metrics.items() if value is None)}
