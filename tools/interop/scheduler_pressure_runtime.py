#!/usr/bin/env python3
"""Finite private scheduler experiment using the packaged supervisor and its fixed HTTP driver.

No protected authority, public network or baseline approval is created. The signed synthetic
Feed Reader identity is an experiment subject, not the shipped first-party bundle. Every fetch
uses freshly generated owned USK material and all outputs remain in the fresh private root.
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time

import cross_version_runtime as runtime
import cross_version_budget as budget
from cryptad_certification import cross_version_evidence as evidence
from cryptad_certification import runtime_pressure_evidence as pressure_evidence

HERE = Path(__file__).resolve().parent
PHASES = ('warmup', 'reference', 'budget', 'pressure', 'recovery', 'sustained', 'restart')
MAX_SECONDS = 480
MAX_OPERATIONS = 1000
MAX_SAMPLES = 240
CADENCE_MILLIS = 1000
WARMUP_SAMPLES = 20
SYNTHETIC_PAYLOAD = b'PUBLIC SYNTHETIC SCHEDULER CONTENT'
ENVIRONMENT = {
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_INITIAL_DELAY_SECONDS': '1',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_POLL_INTERVAL_SECONDS': '1',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_MINIMUM_POLL_INTERVAL_SECONDS': '2',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_JITTER_SECONDS': '0',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_FAILURE_BACKOFF_SECONDS': '2',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_MAXIMUM_FAILURE_BACKOFF_SECONDS': '2',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_PRESSURE_MAX_IN_FLIGHT': '1',
    'CRYPTAD_CONTENT_SUBSCRIPTIONS_PRESSURE_RESUME_AT_OR_BELOW': '0',
    'CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_CONCURRENT_GLOBAL': '2',
}


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def port():
    with socket.socket() as selected:
        selected.bind(('127.0.0.1', 0))
        return selected.getsockname()[1]


def private_json(path, value):
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(payload) > 16 * 1024**2:
        raise runtime.RuntimeFailure('scheduler-private-output-budget-exceeded')
    temporary = path.with_suffix('.tmp')
    with temporary.open('wb') as output:
        output.write(payload)
    temporary.chmod(0o600)
    temporary.replace(path)


class SchedulerLane(runtime.Supervisor):
    """One finite local cohort; launch, FCP client, identity and HTTP stay supervisor-owned."""
    scheduler_lane = True

    def __init__(self, root, distribution, java, fixture, source_commit, node_executable, baseline_path=None, policy_path=None):
        self.root = root
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.started = time.monotonic()
        self.started_at = utcnow()
        self.policy_path = policy_path or HERE.parent / 'perf/baselines/runtime-synthetic-policy.json'
        self.policy = json.loads(Path(self.policy_path).read_bytes())
        pressure_evidence.baseline.validate_policy(self.policy)
        self.selection = {'baselineDigest': None, 'selectedAt': self.started_at,
                          'policyDigest': pressure_evidence.baseline.digest(self.policy)}
        if baseline_path is not None:
            if Path(baseline_path).stat().st_size > 1024 * 1024:
                raise runtime.RuntimeFailure('scheduler-baseline-byte-budget-exceeded')
            self.selected_baseline = json.loads(Path(baseline_path).read_bytes())
            self.selection['baselineDigest'] = pressure_evidence.baseline.digest(self.selected_baseline)
            private_json(self.root / 'baseline-selection.json', {
                'canonicalDigest': self.selection['baselineDigest'], 'fileDigest': runtime.digest_file(baseline_path),
                'selectedAt': self.started_at})
        self.deadline = self.started + MAX_SECONDS
        self.operations = 0
        self.nodes = {}
        self.catalog_prepared = None
        self.events = []
        self.samples = []
        self.worker_samples = []
        self.sample_wall_times = []
        self.collector_costs = []
        self.last_work_sequence = {}
        self.series_started = None
        self.series_started_at = None
        self.observations = []
        self.phase = 'warmup'
        self.work = dict(offered=0, successful=0, failed=0, cancelled=0, timedOut=0, outstanding=0, latencyMillis=[])
        self.last_sample = self.started
        self.previous_fetch = None
        self.node_executable = Path(node_executable).resolve(strict=True)
        self.driver_digest = runtime.digest_file(HERE / 'cross_version_budget_driver.cjs')
        self.node_digest = runtime.digest_file(self.node_executable)
        self.driver_process = None
        self.driver_processes = []
        self.driver_started = None
        self.epochs = []
        self.fixture = fixture
        self.source_commit = source_commit
        self.java = java
        self.distribution = distribution
        self.package_target = {'x86_64': 'linux-x64', 'aarch64': 'linux-arm64'}.get(os.uname().machine)
        runtime.require_native_target(distribution, self.package_target, java)
        runtime.packaged_daemon_identity(distribution, source_commit)
        self.product_digest = runtime.tree_digest(distribution, require_java=False)
        self.trust_paths = {'candidate-sender': fixture / 'publisher-keys.properties'}
        node_root = root / 'node'
        ports = runtime.interop.Ports(port(), port(), 0, 0)
        http_port = port()
        config = runtime.make_runtime_config(node_root, ports, http_port)
        config.write_text(config.read_text().replace('End\n', 'fproxy.hasCompletedWizard=true\nEnd\n'))
        self.private = {'nodes': {'candidate-sender': {'httpPort': http_port, 'apps': [
            {'appId': 'feed-reader', 'bundleDigest': runtime.digest_file(fixture / 'feed-reader.zip')}]}}}
        staged = self.root / 'staged-feed-reader'
        runtime.extract_app_bundle(fixture / 'feed-reader.zip', staged, runtime.digest_file(fixture / 'feed-reader.zip'))
        self.app_staging = {('candidate-sender', 'feed-reader'): staged}
        self.app_staging_identities = {'candidate-sender/feed-reader': runtime.tree_digest(staged, require_java=False)}
        self.prepared = {'candidate-sender': (distribution, node_root, ports, java, runtime.digest_file(config))}
        self.apps = {}
        self.fingerprint = {
            'productDigest': self.product_digest, 'sourceCommit': source_commit,
            'appCohortDigest': runtime.canonical_digest([runtime.digest_file(fixture / 'feed-reader.zip')]),
            'workloadDigest': runtime.digest_file(Path(__file__)),
            'corpusDigest': runtime.canonical_digest({'producer': 'fresh-synthetic-usk', 'payload': SYNTHETIC_PAYLOAD.decode('ascii'), 'bytes': len(SYNTHETIC_PAYLOAD)}),
            'configurationDigest': runtime.canonical_digest({'operatorEnvironment': ENVIRONMENT, 'nodeConfig': runtime.digest_file(config)}),
            'environmentDigest': self.environment_digest(),
            'collectorDigest': runtime.canonical_digest({'helper': runtime.digest_file(HERE / 'cross_version_budget.py'),
                'scheduler': runtime.digest_file(HERE / 'scheduler_pressure_runtime.py'),
                'supervisor': runtime.digest_file(HERE / 'cross_version_runtime.py'),
                'metricPolicy': runtime.digest_file(HERE.parent / 'perf/runtime_baseline.py'),
                'driver': runtime.digest_file(HERE / 'cross_version_budget_driver.cjs'),
                'node': runtime.digest_file(self.node_executable), 'cadenceMillis': CADENCE_MILLIS,
                'maxSamples': MAX_SAMPLES, 'metrics': budget.RUNTIME_METRICS}),
        }

    def prepare_journal(self):
        exported = subprocess.run([str(self.java / 'bin/java'), '-cp', str(self.distribution / 'lib/*'),
            'network.crypta.platform.api.PackagedApiExport'], check=True, capture_output=True,
            timeout=30, env={'PATH': str(self.java / 'bin') + ':/usr/bin:/bin', 'JAVA_HOME': str(self.java),
                            'HOME': str(self.root), 'LANG': 'C.UTF-8'})
        contract = json.loads(json.loads(exported.stdout)['contractSnapshot'])
        self.plan = {'schemaVersion': 1, 'kind': evidence.KIND, 'experimentId': 'pr306-scheduler',
            'profile': 'bounded-scheduler-integration', 'topologyClass': 'single-host-independent-processes',
            'provenanceClass': 'source-build-comparison', 'requestedSeconds': MAX_SECONDS,
            'probeIntervalSeconds': 1,
            'policy': {'id': 'cross-version-observed-v1', 'minimumObservedSeconds': 0,
                       'maxGapSeconds': 60, 'maxEvents': 4096}, 'requiredScenarios': ['app-budgets'],
            'producer': {'sourceCommit': self.source_commit, 'runnerDigest': runtime.runner_identity()['runnerDigest'],
                         'adapterDigest': runtime.digest_file(Path(__file__))},
            'nodes': [{'role': 'candidate-sender', 'product': 'cryptad', 'sourceCommit': self.source_commit,
                'artifactDigest': self.product_digest,
                'artifactSize': sum(path.stat().st_size for path in self.distribution.rglob('*') if path.is_file()),
                'packageTarget': self.package_target, 'runtimeDigest': runtime.tree_digest(self.java),
                'contractVersion': contract['contract']['contractVersion'],
                'configDigest': self.prepared['candidate-sender'][4],
                'appDigests': [runtime.digest_file(self.fixture / 'feed-reader.zip')]}],
            'workloadInputs': {'scheduler': self.fingerprint['workloadDigest']}}
        self.journal = evidence.Journal(self.root / 'journal', self.plan)
        private_json(self.root / 'plan.json', self.plan)
        self.journal.append('start')
        self.journal.checkpoint()

    def environment_digest(self):
        limits = {}
        for key, path in (('memoryMax', '/sys/fs/cgroup/memory.max'), ('cpuMax', '/sys/fs/cgroup/cpu.max'),
                          ('cpuSetEffective', '/sys/fs/cgroup/cpuset.cpus.effective')):
            try:
                raw = Path(path).read_bytes()
                if len(raw) > 4096:
                    raise runtime.RuntimeFailure('scheduler-environment-read-budget-exceeded')
                limits[key] = {'known': True, 'value': raw.decode().strip()}
            except OSError:
                limits[key] = {'known': False, 'value': None}
        cpu_fields = {'vendor_id', 'model name', 'cpu family', 'model', 'flags', 'CPU implementer', 'CPU part', 'Features'}
        try:
            with Path('/proc/cpuinfo').open('rb') as source:
                raw = source.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise runtime.RuntimeFailure('scheduler-environment-read-budget-exceeded')
            hardware = sorted({(key.strip(), ' '.join(value.split())) for line in raw.decode().splitlines()
                if ':' in line for key, value in [line.split(':', 1)] if key.strip() in cpu_fields})
            cpu = {'known': bool(hardware), 'descriptorDigest': runtime.canonical_digest(hardware) if hardware else None}
        except OSError:
            cpu = {'known': False, 'descriptorDigest': None}
        version = subprocess.run([str(self.java / 'bin/java'), '-version'], capture_output=True, check=True,
                                 timeout=15, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        try:
            filesystem = os.statvfs(self.root)
            storage = {'known': True, 'class': 'private-owned-workload-directory',
                       'blockSizeBytes': filesystem.f_bsize, 'fragmentSizeBytes': filesystem.f_frsize,
                       'filesystemIdentityDigest': runtime.canonical_digest(filesystem.f_fsid)}
        except (OSError, AttributeError):
            storage = {'known': False, 'class': 'private-owned-workload-directory'}
        environment = {'javaExecutable': runtime.digest_file(self.java / 'bin/java'),
            'javaVersion': version.stderr.decode(), 'os': os.uname().sysname, 'arch': os.uname().machine,
            'kernel': os.uname().release, 'cpuCount': os.cpu_count(), 'container': limits, 'hardware': cpu,
            'network': getattr(self, 'network_class', {'class': 'single-node-isolated-loopback'}), 'storage': storage}
        private_json(self.root / 'environment.json', environment)
        self.environment_known = cpu['known'] and storage['known'] and all(value['known'] for value in limits.values())
        return runtime.canonical_digest(environment)

    def remaining(self, seconds):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise runtime.RuntimeFailure('scheduler-owned-deadline-exhausted')
        return min(seconds, remaining)

    def next_operation(self):
        self.remaining(1)
        self.operations += 1
        if self.operations > MAX_OPERATIONS:
            raise runtime.RuntimeFailure('scheduler-owned-operation-budget-exhausted')
        return 'scheduler-operation-' + str(self.operations)

    def scheduler_process_environment(self, role):
        return dict(ENVIRONMENT)

    def emit(self, kind, role='', **fields):
        event = self.journal.append(kind, role=role, **fields)
        self.events.append(event)
        return event

    def save_state(self):
        private_json(self.root / 'progress.json', {'events': self.events, 'operations': self.operations,
                                                  'phase': self.phase})

    def start_app(self, install):
        handle = runtime.AppHandle(self, 'candidate-sender', 'feed-reader')
        for _ in range(60):
            try:
                handle.host_bootstrap()
                break
            except runtime.RuntimeFailure:
                self.remaining(1)
                time.sleep(0.25)
        else:
            raise runtime.RuntimeFailure('scheduler-owned-host-bootstrap-unavailable')
        if install:
            status, value = handle.request('POST', '/api/v1/apps/install', {'stagedDir': str(self.app_staging[('candidate-sender', 'feed-reader')])})
            if status != 201 or value.get('app', {}).get('appId') != 'feed-reader':
                raise runtime.RuntimeFailure('scheduler-signed-app-install-not-admitted')
        status, _ = handle.request('POST', '/api/v1/apps/feed-reader/start')
        if status not in (200, 201):
            raise runtime.RuntimeFailure('scheduler-signed-app-start-failed')
        handle.observe_worker()
        handle.refresh_session()
        self.handle = handle
        self.apps[('candidate-sender', 'feed-reader')] = handle
        identity = json.loads((self.nodes['candidate-sender'].runtime.base_dir / 'run/process-identity.json').read_bytes())
        self.identity = identity['jvm']
        self.epochs.append(runtime.node_epoch(self.identity))
        self.previous_fetch = None
        observed = self.observe()
        if (observed.get('pressureConfiguration', {}).get('maximumInFlight') != 1
                or observed.get('budgetConfiguration', {}).get('foregroundContentFetchConcurrentGlobal') != 2):
            raise runtime.RuntimeFailure('scheduler-pressure-configuration-not-effective')
        effective = {key: observed.get(key) for key in ('schedulerConfiguration', 'budgetConfiguration', 'pressureConfiguration')}
        if self.samples and runtime.canonical_digest(effective) != self.effective_configuration_digest:
            raise runtime.RuntimeFailure('scheduler-effective-configuration-changed')
        self.effective_configuration_digest = runtime.canonical_digest(effective)
        self.fingerprint['environmentDigest'] = runtime.canonical_digest({
            'osAndToolchain': self.environment_digest(),
            'jvmConfiguration': observed.get('jvm', {}).get('configuration'),
            'configurationKnown': isinstance(observed.get('jvm', {}).get('configuration'), dict)})
        self.environment_known = self.environment_known and known_jvm_configuration(observed.get('jvm', {}).get('configuration'))
        self.fingerprint['configurationDigest'] = self.effective_configuration_digest
        private_json(self.root / 'configuration.json', {'requestedEnvironment': ENVIRONMENT, 'effective': effective})

    def observe(self):
        status, value = self.handle.request('GET', '/api/v1/operator/runtime-observation')
        if status != 200 or value.get('schemaVersion') != 1:
            raise runtime.RuntimeFailure('scheduler-runtime-observation-unavailable')
        return value

    def sample(self):
        if self.samples:
            remaining_cadence = self.last_sample + CADENCE_MILLIS / 1000 - time.monotonic()
            if remaining_cadence > 0:
                time.sleep(min(remaining_cadence, self.remaining(remaining_cadence)))
        sampling_started, sampling_cpu_started = time.monotonic_ns(), time.process_time_ns()
        paths = list((self.nodes['candidate-sender'].runtime.base_dir / 'logs').rglob('*'))
        if len(paths) > 1024 or sum(path.stat().st_size for path in paths if path.is_file()) > runtime.MAX_LOG_BYTES:
            raise runtime.RuntimeFailure('scheduler-private-log-budget-exceeded')
        if self.series_started is None:
            self.series_started = time.monotonic()
            self.series_started_at = utcnow()
            self.last_sample = self.series_started
        if len(self.samples) >= MAX_SAMPLES:
            raise runtime.RuntimeFailure('scheduler-runtime-sample-budget-exhausted')
        captured = []
        def observe_once():
            captured.append(self.observe())
            return captured[0]
        sampled = budget.measure_runtime_sample(self.identity, executable_digest=runtime.digest_file(self.java / 'bin/java'),
                                                runtime_snapshot=observe_once)
        now = time.monotonic()
        snapshot = captured[0]
        previous_sequence = self.last_work_sequence.get(self.epochs[-1], 0)
        current_work = snapshot.get('work', {})
        delta = [event for event in current_work.get('events', []) if event['sequence'] > previous_sequence]
        self.last_work_sequence[self.epochs[-1]] = current_work.get('lastSequence', previous_sequence)
        retained_snapshot = {**snapshot, 'work': {**current_work, 'events': delta}}
        self.observations.append({'sequence': len(self.observations) + 1, 'phase': self.phase,
                                  'epoch': self.epochs[-1], 'runtime': retained_snapshot})
        work = dict(self.work)
        work['latencyMillis'] = list(self.work['latencyMillis'])
        self.work = dict(offered=0, successful=0, failed=0, cancelled=0, timedOut=0,
                         outstanding=work['outstanding'], latencyMillis=[])
        self.samples.append({'sequence': len(self.samples), 'epoch': self.epochs[-1], 'phase': self.phase,
            'elapsedMillis': int((now - self.series_started) * 1000), 'intervalMillis': max(1, int((now - self.last_sample) * 1000)),
            'valid': self.environment_known, 'metrics': sampled['metrics'], 'work': work})
        self.last_sample = now
        self.sample_wall_times.append(utcnow())
        self.journal.append('sample', role='candidate-sender', scenario='app-budgets', counters={
            'memoryBytes': sampled['metrics']['rssBytes'], 'threads': sampled['metrics']['osThreads'],
            'fileDescriptors': sampled['metrics']['fileDescriptors']})
        self.journal.checkpoint()
        if self.handle.worker_identity is not None:
            worker = budget.measure_runtime_sample(self.handle.worker_identity,
                executable_digest=self.handle.worker_identity['executableDigest'])
            self.worker_samples.append({'sequence': len(self.worker_samples) + 1, 'epoch': runtime.node_epoch(self.handle.worker_identity),
                'phase': self.phase, 'elapsedMillis': self.samples[-1]['elapsedMillis'], 'metrics': worker['metrics'],
                'unavailable': worker['unavailable']})
        self.collector_costs.append({'sequence': len(self.samples) - 1,
            'wallNanos': time.monotonic_ns() - sampling_started,
            'collectorProcessCpuNanos': time.process_time_ns() - sampling_cpu_started})
        self.retain()
        return snapshot

    def retain(self):
        private_json(self.root / 'collector-cost.json', {'schemaVersion': 1,
            'definition': 'sample-including-journal-checkpoint-excluding-private-series-rewrite',
            'costs': self.collector_costs})
        private_json(self.root / 'runtime-series.json', {'schemaVersion': 1, 'kind': 'cryptad-runtime-series',
            'runId': 'scheduler-local', 'evidenceClass': getattr(self, 'evidence_class', 'synthetic-local'), 'startedAt': self.series_started_at or self.started_at,
            'finishedAt': utcnow(), 'selection': dict(self.selection),
            'fingerprint': self.fingerprint, 'samples': self.samples, 'droppedSamples': 0})
        for epoch in sorted({sample['epoch'] for sample in self.samples}):
            private_json(self.root / ('runtime-series-' + epoch + '.json'), self.epoch_series(epoch))
        private_json(self.root / 'scheduler-observations.json', {'schemaVersion': 1, 'observations': self.observations,
            'fingerprint': self.fingerprint, 'evidenceClass': getattr(self, 'evidence_class', 'synthetic-local')})
        private_json(self.root / 'worker-series.json', {'schemaVersion': 1, 'processRole': 'selected-app-worker',
            'samples': self.worker_samples, 'status': 'measured-separately-not-summed'})

    def epoch_series(self, epoch):
        indices = [i for i, sample in enumerate(self.samples) if sample['epoch'] == epoch]
        selected = [dict(self.samples[i]) for i in indices]
        offset = selected[0]['elapsedMillis'] - selected[0]['intervalMillis']
        start = dt.datetime.fromisoformat(self.sample_wall_times[indices[0]].replace('Z', '+00:00')) - dt.timedelta(milliseconds=selected[0]['intervalMillis'])
        for sequence, sample in enumerate(selected):
            sample['sequence'] = sequence
            sample['elapsedMillis'] -= offset
        return {'schemaVersion': 1, 'kind': 'cryptad-runtime-series', 'runId': 'scheduler-local-' + epoch,
            'evidenceClass': getattr(self, 'evidence_class', 'synthetic-local'), 'startedAt': start.isoformat(),
            'finishedAt': self.sample_wall_times[indices[-1]],
            'selection': dict(self.selection),
            'fingerprint': self.fingerprint, 'samples': selected, 'droppedSamples': 0}

    def runtime_evidence(self):
        epoch = self.epochs[0]
        observations = [row['runtime'] for row in self.observations if row['epoch'] == epoch]
        events = {}
        for observation in observations:
            for event in observation['work']['events']:
                prior = events.setdefault(event['sequence'], event)
                if prior != event:
                    raise runtime.RuntimeFailure('scheduler-event-sequence-substituted')
        return {'schemaVersion': 1, 'workloadDigest': self.fingerprint['workloadDigest'],
            'collectorDigest': self.fingerprint['collectorDigest'], 'configurationDigest': self.fingerprint['configurationDigest'],
            'series': self.epoch_series(epoch),
            'policy': self.policy,
            'workEvents': [events[key] for key in sorted(events)],
            'contentFetchSamples': [row['contentFetch'] for row in observations],
            'budgetValid': all(row.get('budget', {}).get('valid') is True and row.get('work', {}).get('known') is True for row in observations),
            'droppedEvents': max(row['work']['dropped'] for row in observations),
            **({'baseline': self.selected_baseline} if hasattr(self, 'selected_baseline') else {})}

    def wait_for(self, predicate, seconds, code):
        deadline = time.monotonic() + self.remaining(seconds)
        while time.monotonic() < deadline:
            snapshot = self.sample()
            if predicate(snapshot):
                return snapshot
            time.sleep(min(CADENCE_MILLIS / 1000, max(0, deadline - time.monotonic())))
        raise runtime.RuntimeFailure(code)

    def subscriptions(self):
        status, value = self.handle.request('GET', '/api/v1/content/subscriptions', principal='app')
        if status != 200 or not isinstance(value.get('subscriptions'), list):
            raise runtime.RuntimeFailure('scheduler-owned-subscriptions-unavailable')
        return value['subscriptions']

    def owned_subscription(self):
        selected = [row for row in self.subscriptions() if row.get('subscriptionId') == self.subscription_id]
        if len(selected) != 1:
            raise runtime.RuntimeFailure('scheduler-owned-subscription-identity-missing')
        return selected[0]

    def create_corpus(self):
        with self.client('candidate-sender') as client:
            insert, request = runtime.interop.generate_ssk(client, self.next_operation())
            self.useful_uri = runtime.interop.usk_from_ssk(request, 'scheduler-synthetic', 0)
            insert_uri = runtime.interop.usk_from_ssk(insert, 'scheduler-synthetic', 0)
            self.insert_uri = insert_uri
            self.payload = SYNTHETIC_PAYLOAD
            runtime.interop.put_and_wait_for_success(client, self.next_operation(), insert_uri, self.payload,
                'text/plain', local_request_only=True, uri_fallback=self.useful_uri)
            _, missing = runtime.interop.generate_ssk(client, self.next_operation())
            self.missing_uri = runtime.interop.usk_from_ssk(missing, 'scheduler-owned-unpublished', 0)

    def create_subscription(self):
        status, value = self.handle.request('POST', '/api/v1/content/subscriptions', {
            'label': 'Public synthetic scheduler control', 'uri': self.useful_uri,
            'pollIntervalSeconds': '2', 'maxBytes': '8192', 'timeoutMillis': '3000'}, principal='app')
        if status != 201 or not value.get('subscription', {}).get('subscriptionId'):
            raise runtime.RuntimeFailure('scheduler-owned-subscription-not-created')
        self.subscription_id = value['subscription']['subscriptionId']

    def foreground(self):
        start = time.monotonic()
        self.work['offered'] += 1
        status, value = self.handle.request('POST', '/api/v1/content/fetch', {'uri': self.useful_uri,
            'maxBytes': '8192', 'timeoutMillis': '3000', 'format': 'base64', 'purpose': 'scheduler-synthetic-control'}, principal='app')
        elapsed = int((time.monotonic() - start) * 1000)
        self.work['latencyMillis'].append(elapsed)
        if status == 200 and value.get('contentBase64') == budget.base64.b64encode(self.payload).decode():
            self.work['successful'] += 1
        else:
            self.work['failed'] += 1
        return status, value

    def activation_digest(self):
        if self.plan['profile'] != 'protected-long-live':
            return None
        self.remaining(20)
        return runtime.digest_file(Path('/var/lib/cryptad-cross-version-authority/activation.json'))

    def start_pressure_request(self):
        if (runtime.digest_file(HERE / 'cross_version_budget_driver.cjs') != self.driver_digest
                or runtime.digest_file(self.node_executable) != self.node_digest):
            raise runtime.RuntimeFailure('scheduler-fixed-driver-identity-changed')
        self.work['offered'] += 1
        self.work['outstanding'] += 1
        self.next_operation()
        payload = {'mode': 'pressure', 'base': self.handle.base, 'origin': self.handle.origin,
            'session': self.handle.session, 'uri': self.missing_uri, 'expected': '', 'deadlineMillis': 20000,
            'deadlineMonotonicNs': str(time.monotonic_ns() + 20000000000), 'activationDigest': self.activation_digest()}
        self.driver_started = time.monotonic()
        self.driver_process = subprocess.Popen([str(self.node_executable), str(HERE / 'cross_version_budget_driver.cjs')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, start_new_session=True)
        self.driver_process.stdin.write(json.dumps(payload).encode())
        self.driver_process.stdin.close()
        self.driver_processes.append((self.driver_process, self.driver_started))

    def start_pressure(self):
        self.start_pressure_request()
        self.start_pressure_request()

    def finish_pressure(self):
        reports = []
        for child, started in self.driver_processes:
            try:
                deadline = time.monotonic() + self.remaining(25)
                while child.poll() is None:
                    if time.monotonic() >= deadline:
                        raise runtime.RuntimeFailure('scheduler-pressure-driver-time-budget-exceeded')
                    self.sample()
                    time.sleep(min(CADENCE_MILLIS / 1000, max(0, deadline - time.monotonic())))
                raw = child.stdout.read(4097)
                if child.returncode != 0 or len(raw) > 4096:
                    raise runtime.RuntimeFailure('scheduler-pressure-driver-failed')
                report = json.loads(raw)
                latency = report.get('latencyMillis')
                if (report.get('category') not in budget.CATEGORIES
                        or type(latency) is not int or not 0 <= latency <= 480000):
                    raise runtime.RuntimeFailure('scheduler-pressure-driver-output-invalid')
                self.work['outstanding'] -= 1
                self.work['timedOut' if report.get('httpStatus') == 504 and report.get('errorCode') == 'content_fetch_timeout' else 'failed'] += 1
                self.work['latencyMillis'].append(latency)
                reports.append(report)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
                child.stdout.close()
                child.stderr.close()
        self.driver_processes = []
        self.driver_process = None
        if runtime.digest_file(HERE / 'cross_version_budget_driver.cjs') != self.driver_digest:
            raise runtime.RuntimeFailure('scheduler-fixed-driver-identity-changed')
        return reports

    def stop_owned(self):
        for child, _ in self.driver_processes:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
        self.driver_processes = []
        self.driver_process = None
        node = self.nodes.get('candidate-sender')
        if node is not None and node.runtime.process.poll() is None:
            runtime.interop.terminate_node(node.runtime)
            self.journal.append('node-stop', role='candidate-sender')

    def execute_phases(self, result):
        self.create_corpus()
        self.create_subscription()
        self.wait_for(lambda _: bool(self.owned_subscription().get('lastSuccessAt')), 90,
                      'scheduler-normal-progress-unobserved')
        for _ in range(WARMUP_SAMPLES):
            self.sample()
            time.sleep(CADENCE_MILLIS / 1000)
        self.phase = 'reference'
        for _ in range(5):
            self.foreground()
            self.sample()
            time.sleep(1)
        self.phase = 'budget'
        self.start_pressure()
        self.wait_for(lambda value: value.get('contentFetch', {}).get('inFlightOperations', 0) == 2,
                      10, 'scheduler-real-pressure-source-unobserved')
        held = self.observe()
        global_transitions = [event for event in held.get('work', {}).get('events', [])
            if event.get('operation') == 'content_fetch_global' and event.get('scope') == 1
            and event.get('kind') in ('CONCURRENCY_HELD', 'CONCURRENCY_RELEASED')]
        if (held.get('budget', {}).get('valid') is not True
                or not global_transitions or global_transitions[-1].get('value') != 2
                or held.get('budgetConfiguration', {}).get('foregroundContentFetchConcurrentGlobal') != 2):
            raise runtime.RuntimeFailure('scheduler-shared-global-capacity-not-exhausted')
        before_denial = held['contentFetch']['startedOperations']
        status, denial = self.foreground()
        after_denial = self.observe()['contentFetch']['startedOperations']
        if (status != 429 or denial.get('error', {}).get('code') != 'network_budget_concurrency_limited'
                or after_denial != before_denial):
            raise runtime.RuntimeFailure('scheduler-foreground-concurrency-denial-unobserved')
        result['budgetDenial'] = {'httpStatus': status, 'code': 'network_budget_concurrency_limited',
                                 'contentPortNotInvoked': True, 'sharedGlobalCapacity': 2, 'heldGlobalContentCalls': 2,
                                 'heldConcurrencyFamilySum': held['budget']['activeFamilyLeases']}
        self.phase = 'pressure'
        # Admission predicates use the actual scheduler event sink, filled by its owning code.
        before = self.observe()
        self.wait_for(lambda value: scheduler_count(value, 'PRESSURE_SKIP') > scheduler_count(before, 'PRESSURE_SKIP'),
                      18, 'scheduler-due-pressure-skip-unobserved')
        result['pressureDriver'] = self.finish_pressure()
        self.phase = 'recovery'
        self.wait_for(lambda value: value.get('contentFetch', {}).get('inFlightOperations') == 0,
                      15, 'scheduler-real-pressure-clear-unobserved')
        success_before = self.owned_subscription().get('lastSuccessAt')
        self.wait_for(lambda _: self.owned_subscription().get('lastSuccessAt') != success_before,
                      90, 'scheduler-background-recovery-unobserved')
        for _ in range(3):
            self.foreground()
            self.sample()
            time.sleep(1)
        self.phase = 'sustained'
        for _ in range(10):
            self.foreground()
            self.sample()
            time.sleep(1)
        status, _ = self.handle.request('POST', '/api/v1/content/subscriptions/' + self.subscription_id + '/pause', principal='app')
        if status != 200:
            raise runtime.RuntimeFailure('scheduler-owned-rate-control-pause-failed')
        self.wait_for(lambda value: value['contentFetch']['inFlightOperations'] == 0, 15,
                      'scheduler-owned-rate-control-not-quiescent')
        # Fixed-window rates remain at their defaults. A bounded cached burst observes the
        # real stable denial; no quota reset or counter/window edit is involved.
        for attempt in range(42):
            before_rate = self.observe()
            before_sequence = before_rate['work']['lastSequence']
            status, denial = self.foreground()
            snapshot = self.sample()
            if status == 429 and denial.get('error', {}).get('code') == 'content_fetch_budget_exhausted':
                events = [event for event in snapshot['work']['events'] if event['sequence'] > before_sequence]
                denied = [event for event in events if event['kind'] == 'BUDGET_RATE_DENIED']
                if (snapshot['contentFetch']['startedOperations'] != before_rate['contentFetch']['startedOperations']
                        or not denied or any(event['kind'] in ('FETCH_INVOKED', 'RATE_CHARGED')
                    and event['operationId'] == denied[-1]['operationId'] for event in events)):
                    raise runtime.RuntimeFailure('scheduler-rate-denial-native-accounting-unobserved')
                result['rateDenial'] = {'httpStatus': status, 'code': 'content_fetch_budget_exhausted',
                    'boundedAttempts': attempt + 1, 'deniedOperationUncharged': True, 'contentPortNotInvoked': True}
                break
            if status != 200:
                raise runtime.RuntimeFailure('scheduler-rate-burst-unexpected-result')
        else:
            raise runtime.RuntimeFailure('scheduler-app-rate-denial-unobserved')
        success_before = self.owned_subscription().get('lastSuccessAt')
        status, _ = self.handle.request('POST', '/api/v1/content/subscriptions/' + self.subscription_id + '/resume', principal='app')
        if status != 200:
            raise runtime.RuntimeFailure('scheduler-owned-rate-control-resume-failed')
        self.wait_for(lambda _: self.owned_subscription().get('lastSuccessAt') != success_before, 30,
                      'scheduler-post-rate-useful-progress-unobserved')
        attachment = self.runtime_evidence()
        if hasattr(self, 'selected_baseline'):
            comparison = pressure_evidence.baseline.compare(attachment['series'], self.selected_baseline)
            private_json(self.root / 'runtime-baseline-comparison.json', comparison)
            result['runtimeBaselineComparison'] = comparison
        self.journal.append('operation', role='candidate-sender', scenario='app-budgets',
            operation=self.next_operation(), outcome='partial', runtime_evidence=attachment)
        self.journal.checkpoint()
        result['runtimeComponents'] = pressure_evidence.derive(attachment, workload_digest=self.fingerprint['workloadDigest'])

    def execute(self):
        result = {'schemaVersion': 1, 'evidenceClass': 'synthetic-local', 'releaseEligibility': 'blocked',
                  'fullAppBudgets': 'not-observed', 'runtimeBaseline': 'missing-reviewed-runtime-baseline'}
        self.prepare_journal()
        try:
            self.start('candidate-sender')
            self.start_app(True)
            self.execute_phases(result)
            self.phase = 'restart'
            persisted = self.subscriptions()
            before_restart = self.observe()
            if (before_restart.get('budget', {}).get('valid') is not True
                    or before_restart['budget'].get('activeFamilyLeases') != 0
                    or before_restart['budget'].get('reservedFamilyRates') != 0):
                raise runtime.RuntimeFailure('scheduler-pre-restart-reservations-not-released')
            self.stop_owned()
            self.start('candidate-sender')
            self.start_app(False)
            with self.client('candidate-sender') as client:
                runtime.interop.put_and_wait_for_success(client, self.next_operation(), self.insert_uri, self.payload,
                    'text/plain', local_request_only=True, uri_fallback=self.useful_uri)
            after = self.subscriptions()
            restart_snapshot = self.observe()
            result['restartObservation'] = {'newDaemonEpoch': self.epochs[-1] != self.epochs[-2],
                'subscriptionStateRetained': [row['subscriptionId'] for row in after] == [row['subscriptionId'] for row in persisted],
                'beforeStopReservationsReleased': True,
                'newBudgetObservationValid': restart_snapshot.get('budget', {}).get('valid') is True,
                'ratePersistence': 'native-window-accounting-required'}
            if [row['subscriptionId'] for row in after] != [row['subscriptionId'] for row in persisted]:
                raise runtime.RuntimeFailure('scheduler-restart-subscription-state-mismatch')
            self.wait_for(lambda _: any(row.get('lastSuccessAt') != persisted[0].get('lastSuccessAt') for row in self.subscriptions()),
                          90, 'scheduler-restart-useful-progress-unobserved')
            status, _ = self.handle.request('DELETE', '/api/v1/content/subscriptions/' + self.subscription_id, principal='app')
            if status not in (200, 204):
                raise runtime.RuntimeFailure('scheduler-owned-subscription-cleanup-failed')
            result.update(status='partial', schedulerExecutor='observed', backgroundRecovery='observed',
                          pressure='actual-bounded-content-fetch-operations', sampleCount=len(self.samples))
        except Exception as error:
            fixed = isinstance(error, (runtime.RuntimeFailure, budget.BudgetObservationError, evidence.EvidenceError,
                                       pressure_evidence.RuntimeEvidenceError))
            result.update(status='fail', diagnostic=str(error) if fixed else 'scheduler-runtime-collection-failed')
            raise
        finally:
            self.stop_owned()
            self.retain()
            result['cleanup'] = 'owned-processes-stopped-private-state-retained'
            private_json(self.root / 'result.json', result)
            self.journal.append('cleanup', outcome='pass')
            self.journal.append('finish', outcome='partial' if result.get('status') != 'fail' else 'fail')
            self.journal.checkpoint('complete' if result.get('status') != 'fail' else 'failed')
            self.journal.__exit__(None, None, None)
        return result


class BorrowedSchedulerLane(SchedulerLane):
    """Run the same finite phases on an already authenticated supervisor-owned app and JVM.

    This adapter never launches, stops, restarts, configures or resets the borrowed daemon. The
    enclosing original supervisor retains activation, daemon cleanup and process ownership.
    """
    def __init__(self, supervisor, selection):
        self.parent = supervisor
        self.root = supervisor.root / 'scheduler-observation'
        self.root.mkdir(mode=0o700, exist_ok=False)
        self.started = time.monotonic()
        self.started_at = utcnow()
        self.deadline = self.started + MAX_SECONDS
        self.operations = 0
        self.events, self.samples, self.worker_samples, self.sample_wall_times, self.observations = [], [], [], [], []
        self.collector_costs = []
        self.last_work_sequence = {}
        self.series_started = self.series_started_at = None
        self.phase = 'warmup'
        self.work = dict(offered=0, successful=0, failed=0, cancelled=0, timedOut=0, outstanding=0, latencyMillis=[])
        self.last_sample = self.started
        self.previous_fetch = None
        self.driver_process = self.driver_started = None
        self.driver_processes = []
        self.node_executable = Path(selection['nodeExecutable'])
        self.node_digest = selection['nodeDigest']
        self.driver_digest = runtime.digest_file(HERE / 'cross_version_budget_driver.cjs')
        self.private, self.nodes, self.journal, self.plan = supervisor.private, supervisor.nodes, supervisor.journal, supervisor.plan
        self.evidence_class = 'operational' if self.plan['profile'] == 'protected-long-live' else 'synthetic-local'
        self.network_class = {'class': 'owned-supervisor-loopback-peers',
            'cohortTopologyDigest': runtime.canonical_digest([{key: row[key] for key in
                ('role', 'artifactDigest', 'runtimeDigest')} for row in self.plan['nodes']])}
        selected_node = next(row for row in self.plan['nodes'] if row['role'] == 'candidate-sender')
        node = self.nodes['candidate-sender']
        self.java, self.distribution, self.source_commit = node.java_home, node.distribution, selected_node['sourceCommit']
        supervisor.app_subject('candidate-sender', 'feed-reader')
        existing = supervisor.apps[('candidate-sender', 'feed-reader')]
        self.handle = runtime.AppHandle(self, 'candidate-sender', 'feed-reader')
        self.handle.password = existing.password
        self.handle.observe_worker()
        self.handle.refresh_session()
        identity_path = node.runtime.base_dir / 'run/process-identity.json'
        if identity_path.is_symlink() or identity_path.stat().st_mode & 0o077:
            raise runtime.RuntimeFailure('scheduler-private-process-identity-invalid')
        identity = json.loads(identity_path.read_bytes())
        if identity['supervisor'] != node.identity:
            raise runtime.RuntimeFailure('scheduler-parent-process-identity-substituted')
        self.identity = identity['jvm']
        self.epochs = [runtime.node_epoch(self.identity)]
        self.policy = json.loads((HERE.parent / 'perf/baselines/runtime-synthetic-policy.json').read_bytes())
        self.selection = {'baselineDigest': None, 'selectedAt': self.started_at,
                          'policyDigest': pressure_evidence.baseline.digest(self.policy)}
        observed = self.observe()
        effective = {key: observed.get(key) for key in ('schedulerConfiguration', 'budgetConfiguration', 'pressureConfiguration')}
        scheduler = effective['schedulerConfiguration'] or {}
        pressure = effective['pressureConfiguration'] or {}
        if (pressure.get('maximumInFlight') != 1 or pressure.get('resumeAtOrBelow') != 0
                or (effective['budgetConfiguration'] or {}).get('foregroundContentFetchConcurrentGlobal') != 2
                or scheduler.get('schedulerPollIntervalMillis') != 1000 or scheduler.get('jitterMillis') != 0
                or scheduler.get('minimumPollIntervalMillis') != 2000 or scheduler.get('failureBackoffMillis') != 2000
                or scheduler.get('maximumFailureBackoffMillis') != 2000 or scheduler.get('initialDelayMillis') != 1000):
            raise runtime.RuntimeFailure('scheduler-selected-short-configuration-not-effective')
        self.fingerprint = {'productDigest': selected_node['artifactDigest'], 'sourceCommit': selected_node['sourceCommit'],
            'appCohortDigest': runtime.canonical_digest(selected_node['appDigests']),
            'workloadDigest': self.plan['workloadInputs']['scheduler'],
            'corpusDigest': runtime.canonical_digest({'producer': 'fresh-synthetic-usk', 'payload': SYNTHETIC_PAYLOAD.decode('ascii'), 'bytes': len(SYNTHETIC_PAYLOAD)}),
            'configurationDigest': runtime.canonical_digest(effective),
            'environmentDigest': runtime.canonical_digest({'osAndToolchain': self.environment_digest(),
                                                         'jvmConfiguration': observed.get('jvm', {}).get('configuration')}),
            'collectorDigest': runtime.canonical_digest({'helper': runtime.digest_file(HERE / 'cross_version_budget.py'),
                'scheduler': runtime.digest_file(HERE / 'scheduler_pressure_runtime.py'),
                'supervisor': runtime.digest_file(HERE / 'cross_version_runtime.py'),
                'metricPolicy': runtime.digest_file(HERE.parent / 'perf/runtime_baseline.py'),
                'driver': self.driver_digest, 'node': self.node_digest, 'cadenceMillis': CADENCE_MILLIS,
                'maxSamples': MAX_SAMPLES, 'metrics': budget.RUNTIME_METRICS})}
        self.environment_known = self.environment_known and known_jvm_configuration(observed.get('jvm', {}).get('configuration'))
        private_json(self.root / 'configuration.json', {'requestedEnvironment': ENVIRONMENT, 'effective': effective})

    def remaining(self, seconds):
        remaining = min(self.deadline - time.monotonic(), self.parent.remaining(seconds))
        if remaining <= 0:
            raise runtime.RuntimeFailure('scheduler-owned-deadline-exhausted')
        return min(seconds, remaining)

    def next_operation(self):
        self.remaining(1)
        self.operations += 1
        if self.operations > MAX_OPERATIONS:
            raise runtime.RuntimeFailure('scheduler-owned-operation-budget-exhausted')
        return self.parent.next_operation()

    def client(self, role, **kwargs):
        return self.parent.client(role, **kwargs)

    def execute(self):
        result = {'schemaVersion': 1, 'evidenceClass': self.evidence_class, 'status': 'partial',
            'releaseEligibility': 'blocked', 'fullAppBudgets': 'not-observed',
            'runtimeBaseline': 'missing-reviewed-runtime-baseline'}
        try:
            self.execute_phases(result)
            result.update(schedulerExecutor='observed', backgroundRecovery='observed', sampleCount=len(self.samples))
            return result
        except Exception:
            result['status'] = 'fail'
            raise
        finally:
            private_json(self.root / 'result.json', result)
            for child, _ in self.driver_processes:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
            self.driver_processes = []
            try:
                if hasattr(self, 'subscription_id'):
                    status, _ = self.handle.request('DELETE', '/api/v1/content/subscriptions/' + self.subscription_id, principal='app')
                    if status not in (200, 204):
                        raise runtime.RuntimeFailure('scheduler-owned-subscription-cleanup-failed')
            finally:
                self.retain()
                self.journal.checkpoint()


def observe_existing(supervisor, selection):
    """Called only after the original supervisor validates selection and activation authority."""
    return BorrowedSchedulerLane(supervisor, selection).execute()


def known_jvm_configuration(value):
    if not isinstance(value, dict):
        return False
    required = ('javaVendor', 'javaVersion', 'vmName', 'vmVersion', 'garbageCollectors',
                'availableProcessors', 'heapInitialBytes', 'heapMaxBytes')
    return all(value.get(key) is not None for key in required) and bool(value['garbageCollectors'])


def scheduler_count(snapshot, kind):
    return sum(1 for row in snapshot.get('work', {}).get('events', []) if row.get('kind') == kind)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('private-root', 'distribution', 'java-home', 'fixture-root', 'node-executable'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--policy', type=Path)
    args = parser.parse_args()
    try:
        result = SchedulerLane(args.private_root, args.distribution, args.java_home, args.fixture_root,
                               args.source_commit, args.node_executable, args.baseline, args.policy).execute()
    except Exception:
        print('scheduler-owned-runtime-failed')
        return 2
    print('scheduler-owned-synthetic-observation-complete')
    return 0 if result.get('schedulerExecutor') == 'observed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
