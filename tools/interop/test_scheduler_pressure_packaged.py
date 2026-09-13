"""Real signed app, distributed JVM, elapsed scheduler and exact-process private measurements."""
import json
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import scheduler_pressure_runtime as adapter

ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def retained_on_failure():
    retained = os.environ.get('CRYPTAD_SCHEDULER_RETAIN_TEST_OUTPUT') == '1'
    storage = ROOT / 'build/pr306-private-runs' if retained else None
    if storage is not None:
        storage.mkdir(mode=0o700, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='pr306-packaged-', dir=storage))
    marker = ROOT / 'build/pr306-packaged-private-root.txt'
    marker.write_text(str(root))
    marker.chmod(0o600)
    if retained:
        inventory = ROOT / 'build/pr306-packaged-private-roots.json'
        roots = json.loads(inventory.read_bytes()) if inventory.exists() else []
        roots.append(str(root))
        inventory.write_text(json.dumps(roots))
        inventory.chmod(0o600)
    try:
        yield str(root)
    except BaseException:
        # Retain the owned partial run for private reconciliation; never upload it in CI.
        raise
    else:
        if not retained:
            shutil.rmtree(root)
            marker.unlink(missing_ok=True)


class PackagedSchedulerPressureTest(unittest.TestCase):
    def test_packaged_executor_contention_recovery_and_resource_series(self):
        self.run_case(False)

    def test_existing_supervisor_borrows_native_process_and_original_journal(self):
        self.run_case(True)

    def run_case(self, borrowed):
        try:
            self.execute_case(borrowed)
        except (unittest.SkipTest, AssertionError):
            raise
        except (adapter.runtime.RuntimeFailure, adapter.budget.BudgetObservationError,
                adapter.evidence.EvidenceError, adapter.pressure_evidence.RuntimeEvidenceError) as error:
            raise AssertionError(str(error)) from None
        except Exception:
            raise AssertionError('scheduler-packaged-integration-failed') from None

    def execute_case(self, borrowed):
        tool = ROOT / 'platform-devtools/build/install/crypta-app'
        distribution = ROOT / 'build/cryptad-dist'
        if (not (tool / 'bin/crypta-app').is_file() or not (distribution / 'bin/cryptad').is_file()
                or not shutil.which('javac') or not shutil.which('node')):
            self.skipTest('requires Java 25, Node, :platform-devtools:installDist and assembleCryptadDist')
        with retained_on_failure() as temporary:
            private = Path(temporary)
            private.chmod(0o700)
            packaged = private / 'distribution'
            shutil.copytree(distribution, packaged, symlinks=True)
            java = private / 'jdk'
            shutil.copytree(Path(shutil.which('javac')).resolve().parents[1], java,
                            symlinks=False, ignore_dangling_symlinks=True)
            fixture = private / 'fixture'
            classes = private / 'classes'
            classes.mkdir()
            source = ROOT / 'platform-devtools/src/test/java/network/crypta/platform/devtools/fixtures/Pr306SignedSchedulerFixture.java'
            environment = {'PATH': str(java / 'bin') + ':/usr/bin:/bin', 'JAVA_HOME': str(java),
                           'HOME': str(private), 'LANG': 'C.UTF-8'}
            subprocess.run([str(java / 'bin/javac'), '-cp', str(tool / 'lib/*'), '-d', str(classes), str(source)],
                           check=True, capture_output=True, timeout=60, env=environment)
            subprocess.run([str(java / 'bin/java'), '-cp', str(classes) + os.pathsep + str(tool / 'lib/*'),
                            'network.crypta.platform.devtools.fixtures.Pr306SignedSchedulerFixture', str(fixture)],
                           check=True, capture_output=True, timeout=60, env=environment)
            source_commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                                           capture_output=True, text=True).stdout.strip()
            lane = adapter.SchedulerLane(private / 'runtime', packaged, java, fixture,
                                         source_commit, Path(shutil.which('node')).resolve())
            try:
                if borrowed:
                    result, lane = self.execute_borrowed(lane)
                else:
                    result = lane.execute()
            except adapter.runtime.RuntimeFailure as error:
                # All runtime failure messages are fixed codes; raw daemon logs stay private.
                raise AssertionError(str(error)) from None
            self.assertEqual('observed', result['schedulerExecutor'])
            self.assertEqual('observed', result['backgroundRecovery'])
            self.assertEqual('blocked', result['releaseEligibility'])
            self.assertEqual('not-observed', result['fullAppBudgets'])
            claims = result['runtimeComponents']['claims']
            for name in adapter.pressure_evidence.CLAIMS[:5]:
                self.assertEqual('observed', claims[name],
                                 f"{name}: {result['runtimeComponents']['resourceFindings']}")
            for name in adapter.pressure_evidence.CLAIMS[5:]:
                self.assertEqual('not-observed', claims[name], name)
            self.assertGreaterEqual(len(lane.samples), 20)
            self.assertEqual(1 if borrowed else 2, len(set(lane.epochs)))
            self.assertTrue(all(sample['metrics']['rssBytes'] > 0 for sample in lane.samples))
            self.assertTrue(all(sample['metrics']['heapUsedBytes'] is not None for sample in lane.samples))
            self.assertTrue(lane.worker_samples)
            self.assertTrue(any(adapter.scheduler_count(row['runtime'], 'PRESSURE_SKIP') for row in lane.observations))
            public = json.dumps({'result': result, 'samples': lane.samples})
            for secret in (lane.useful_uri, lane.missing_uri, str(private), lane.handle.session):
                self.assertNotIn(secret, public)

    def execute_borrowed(self, host):
        selection = {'role': 'candidate-sender', 'profile': 'bounded-contention-v1',
            'nodeExecutable': str(host.node_executable), 'nodeDigest': host.node_digest,
            'configurationDigest': adapter.runtime.canonical_digest(adapter.ENVIRONMENT)}
        binding = adapter.runtime.canonical_digest({'schemaVersion': 1, **{key: selection[key] for key in
            ('role', 'profile', 'nodeDigest', 'configurationDigest')}})
        host.private['scheduler'] = selection
        host.authorization = {'schedulerInputsDigest': binding, 'syntheticContent': True,
                              'maxOperations': 1000, 'maxSeconds': adapter.MAX_SECONDS}
        host.fingerprint['workloadDigest'] = binding
        host.prepare_journal()
        try:
            host.start('candidate-sender')
            host.start_app(True)
            adapter.runtime.validate_scheduler_selection(host.plan, host.private, host.authorization)
            before = dict(host.identity)
            borrowed = adapter.BorrowedSchedulerLane(host, selection)
            result = borrowed.execute()
            self.assertEqual(before, adapter.runtime.process_identity(before['pid']))
            self.assertEqual(1, sum(event['kind'] == 'node-start' for event in host.journal.events))
            self.assertEqual(1, sum('runtimeEvidence' in event for event in host.journal.events))
            self.assertFalse(any(event['kind'] == 'node-stop' for event in host.journal.events))
            return result, borrowed
        finally:
            host.stop_owned()
            host.journal.append('cleanup')
            host.journal.append('finish', outcome='partial')
            host.journal.checkpoint('complete')
            host.journal.__exit__(None, None, None)


if __name__ == '__main__':
    unittest.main()
