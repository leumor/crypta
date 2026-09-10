"""Offline fake-clock regression tests for actual recurring workload scheduling."""
import contextlib
import datetime as dt
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch
import unittest

import cross_version_runtime as runtime


class MeasurementDurationTest(unittest.TestCase):
    def supervisor(self, setup=100, deadline=400):
        instance = runtime.Supervisor.__new__(runtime.Supervisor)
        instance.started = 0
        instance.deadline = deadline
        instance._check_resources = Mock()
        instance.runner_admission = None
        instance.plan = {'requestedSeconds': 10, 'probeIntervalSeconds': 6,
                         'policy': {'minimumObservedSeconds': 10, 'maxGapSeconds': 15}}
        instance.observed_operations = 0
        instance.journal = Mock()
        instance.save_state = Mock()
        instance.sample_app_lifecycle = Mock()
        instance.observe_mail_expiry = Mock()
        instance.sample_resources = Mock()
        instance.scan_mail_surfaces = Mock()
        instance.client = lambda role: contextlib.nullcontext(Mock())
        clock = {'now': float(setup), 'probes': [], 'sleeps': [], 'actions': []}
        def content(*args):
            clock['now'] += 1
            clock['actions'].append('content')
            instance.observed_operations += 1
        def emit(kind, **kwargs):
            self.assertEqual('probe', kind)
            clock['actions'].append('probe')
            clock['probes'].append(clock['now'])
            return {'monotonicNs': int(clock['now'] * 10**9)}
        def sleep(seconds):
            clock['actions'].append('sleep')
            clock['sleeps'].append(seconds)
            clock['now'] += seconds
        instance.content = Mock(side_effect=content)
        instance.emit = Mock(side_effect=emit)
        return instance, clock, sleep

    def execute(self, instance, clock, sleep):
        with patch.object(runtime.time, 'monotonic', side_effect=lambda: clock['now']), patch.object(runtime.time, 'sleep', side_effect=sleep), patch.object(runtime, 'absolute_deadline', side_effect=lambda _seconds: contextlib.nullcontext()), patch.object(runtime.interop, 'get_node_reference'):
            instance.measured_workloads()

    def test_nonzero_setup_does_not_consume_requested_minimum_and_final_sleep_has_workload(self):
        instance, clock, sleep = self.supervisor()
        self.execute(instance, clock, sleep)
        self.assertEqual([100, 108, 112], clock['probes'])
        self.assertEqual([6, 2], clock['sleeps'])
        self.assertGreaterEqual(clock['probes'][-1] - clock['probes'][0], instance.plan['policy']['minimumObservedSeconds'])
        self.assertLessEqual(clock['probes'][-1] - clock['probes'][0], 25)
        self.assertEqual(['sleep', 'content', 'content', 'probe'], clock['actions'][-4:])
        self.assertEqual(2, instance.journal.checkpoint.call_count)
        self.assertIsNone(instance.measurement_window_deadline)

    def test_real_journal_verifier_counts_full_requested_coverage_after_offline_setup(self):
        with runtime.fixed_helper_imports():
            from cryptad_certification import cross_version_evidence as evidence
            from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
        instance, clock, sleep = self.supervisor()
        plan = fixture_plan()
        plan.update(requestedSeconds=10, probeIntervalSeconds=6)
        plan['policy'].update(minimumObservedSeconds=10, maxGapSeconds=15)
        instance.plan = plan
        origin = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc).timestamp()
        class OfflineDateTime(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls.fromtimestamp(origin + clock['now'], tz or dt.timezone.utc)
        with tempfile.TemporaryDirectory() as directory, patch.object(evidence.dt, 'datetime', OfflineDateTime), patch.object(evidence.time, 'monotonic_ns', side_effect=lambda: int(clock['now'] * 10**9)):
            clock['now'] = 0
            with evidence.Journal(Path(directory) / 'journal', plan) as journal:
                instance.journal = journal
                del instance.emit
                instance.emit('start')
                for node in plan['nodes']:
                    instance.emit('node-start', node['role'])
                # Offline setup produces only observed idle control probes, never eligible time.
                for moment in range(10, 101, 10):
                    clock['now'] = moment
                    instance.emit('probe', counters={'operations': 0})
                def content(source, recipient):
                    clock['now'] += 1
                    instance.emit('operation', source, 'network-chk', 'offline-' + str(len(journal.events)),
                                  counters={'operations': 1}, peer_role=recipient)
                def lifecycle():
                    for node in plan['nodes']:
                        if node['appDigests']:
                            instance.emit('sample', node['role'], 'app-lifecycle', counters={'operations': len(node['appDigests'])})
                def resources():
                    for node in plan['nodes']:
                        instance.emit('sample', node['role'], 'app-budgets', counters={'memoryBytes': 1024, 'threads': 2, 'fileDescriptors': 4})
                instance.content.side_effect = content
                instance.sample_app_lifecycle.side_effect = lifecycle
                instance.sample_resources.side_effect = resources
                self.execute(instance, clock, sleep)
                for node in plan['nodes']:
                    instance.emit('node-stop', node['role'])
                instance.emit('cleanup')
                instance.emit('finish')
                checkpoint = journal.checkpoint('complete')
                result = evidence.verify(plan, journal.events, checkpoint)
                self.assertEqual(12, result['observedEligibleSeconds'])
                self.assertGreaterEqual(result['observedEligibleSeconds'], plan['policy']['minimumObservedSeconds'])
                self.assertEqual('partial', result['status'])
                self.assertIn('required-scenarios-not-observed', result['findings'])
                self.assertNotIn('observed-duration-insufficient', result['findings'])
                self.assertFalse(result['releaseEligible'])

    def test_remaining_after_setup_must_cover_duration_gap_and_cleanup_before_first_probe(self):
        instance, clock, sleep = self.supervisor(deadline=350)
        with self.assertRaisesRegex(runtime.RuntimeFailure, 'headroom-insufficient'):
            self.execute(instance, clock, sleep)
        instance.emit.assert_not_called()
        instance.content.assert_not_called()
        self.assertEqual([], clock['sleeps'])

    def test_current_protected_authority_headroom_wins_over_local_controller_deadline(self):
        instance, clock, sleep = self.supervisor(deadline=10000)
        instance.runner_admission = Mock()
        instance.runner_admission.public_identity.return_value = {'origin': 'selected'}
        current = Mock()
        current.public_identity.return_value = {'origin': 'selected'}
        current.remaining_seconds.return_value = 200
        with patch.object(runtime, 'authenticate_runner_selection', return_value=current):
            instance.private, instance.authorization = {}, {}
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'headroom-insufficient'):
                self.execute(instance, clock, sleep)
        instance.emit.assert_not_called()

    def test_workload_overrun_does_not_emit_a_qualifying_closing_probe(self):
        instance, clock, sleep = self.supervisor()
        def overrun(*args):
            clock['now'] += 20
        instance.content.side_effect = overrun
        with self.assertRaisesRegex(runtime.RuntimeFailure, 'deadline-exceeded'):
            self.execute(instance, clock, sleep)
        self.assertEqual([100], clock['probes'])
        self.assertIsNone(instance.measurement_window_deadline)

    def test_initial_validation_rejects_provably_short_authorization_before_node_work(self):
        instance = runtime.Supervisor.__new__(runtime.Supervisor)
        instance.plan = {'profile': 'bounded-live', 'provenanceClass': 'source-build-comparison',
                         'experimentId': 'synthetic', 'requestedSeconds': 60, 'probeIntervalSeconds': 10,
                         'policy': {'maxGapSeconds': 20}}
        instance.private = {'root': '/never-used', 'nodes': {}}
        instance.authorization = {'experimentId': 'synthetic', 'planDigest': runtime.canonical_digest(instance.plan),
                                  'root': '/never-used', 'maxSeconds': 100, 'maxOperations': 1000, 'syntheticContent': True}
        with patch.object(runtime.subprocess, 'Popen') as start:
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'headroom-insufficient'):
                instance._validate()
            start.assert_not_called()

    def test_probe_interval_must_leave_time_for_real_work(self):
        instance, clock, sleep = self.supervisor()
        instance.plan['probeIntervalSeconds'] = 15
        with self.assertRaisesRegex(runtime.RuntimeFailure, 'headroom-insufficient'):
            self.execute(instance, clock, sleep)
        instance.emit.assert_not_called()


class OperationReservationTest(unittest.TestCase):
    def test_reservation_prechecks_capacity_then_persists_before_return(self):
        instance = runtime.Supervisor.__new__(runtime.Supervisor)
        instance.operations = 3
        instance.authorization = {'maxOperations': 10}
        instance.remaining = Mock(return_value=1)
        instance.save_state = Mock(side_effect=lambda: self.assertEqual(8, instance.operations))
        instance.reserve_operations(5)
        instance.remaining.assert_called_once_with(1)
        instance.save_state.assert_called_once()
        for invalid in (0, -1, True, 1.5, 3):
            with self.assertRaises(runtime.RuntimeFailure):
                instance.reserve_operations(invalid)
        self.assertEqual(8, instance.operations)
        self.assertEqual(1, instance.save_state.call_count)

    def test_failed_persistence_never_refunds_an_unknown_child_allowance(self):
        instance = runtime.Supervisor.__new__(runtime.Supervisor)
        instance.operations = 0
        instance.authorization = {'maxOperations': 64}
        instance.remaining = Mock(return_value=1)
        instance.save_state = Mock(side_effect=OSError('offline interrupted checkpoint'))
        with self.assertRaises(OSError):
            instance.reserve_operations(64)
        self.assertEqual(64, instance.operations)


if __name__ == '__main__':
    unittest.main()
