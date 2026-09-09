"""Offline recurring observations: no node, sandbox, HTTP or FCP execution."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import cross_version_runtime as runtime


class PeriodicObservationTest(unittest.TestCase):
    def supervisor(self):
        supervisor = runtime.Supervisor.__new__(runtime.Supervisor)
        supervisor.private = {'nodes': {
            'candidate-sender': {'apps': [{'appId': 'site-publisher'}, {'appId': 'feed-reader'}]},
            'candidate-recipient': {'apps': []}, 'previous': {'apps': []}, 'relay-no-apps': {'apps': []}}}
        supervisor.plan = {'nodes': [{'role': role, 'appDigests': ['selected'] * len(node['apps'])}
                                     for role, node in supervisor.private['nodes'].items()]}
        supervisor.apps = {(role, app['appId']): Mock(app_id=app['appId'])
                           for role, node in supervisor.private['nodes'].items() for app in node['apps']}
        supervisor.app_subject = Mock()
        supervisor.remaining = Mock(return_value=30)
        supervisor.emit = Mock()
        supervisor.observed_operations = 7
        supervisor.operations = 0
        supervisor.authorization = {'maxOperations': 100}
        supervisor.resource_observations = {'sampleCount': 0, 'initial': {}, 'latest': {}}
        return supervisor

    def test_complete_role_sample_follows_every_actual_subject_worker_and_session_check(self):
        supervisor = self.supervisor()
        completed = []
        for (role, app_id), handle in supervisor.apps.items():
            handle.refresh_session.side_effect = lambda selected=app_id: completed.append(selected)
        supervisor.emit.side_effect = lambda *args, **kwargs: self.assertEqual(2, len(completed))
        supervisor.sample_app_lifecycle()
        self.assertEqual(2, supervisor.app_subject.call_count)
        for handle in supervisor.apps.values():
            handle.observe_worker.assert_called_once()
            handle.refresh_session.assert_called_once()
        supervisor.emit.assert_called_once_with('sample', 'candidate-sender', 'app-lifecycle', counters={'operations': 2})
        self.assertEqual(7, supervisor.observed_operations)

    def test_omitted_or_extra_app_prevents_all_lifecycle_samples(self):
        for extra in (False, True):
            supervisor = self.supervisor()
            if extra:
                supervisor.apps[('previous', 'unselected-app')] = Mock()
            else:
                supervisor.apps.pop(('candidate-sender', 'feed-reader'))
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'periodic-app-roster'):
                supervisor.sample_app_lifecycle()
            supervisor.emit.assert_not_called()
            supervisor.app_subject.assert_not_called()

    def test_last_failed_worker_prevents_early_role_sample(self):
        supervisor = self.supervisor()
        supervisor.apps[('candidate-sender', 'site-publisher')].observe_worker.side_effect = runtime.RuntimeFailure('worker-failed')
        with self.assertRaises(runtime.RuntimeFailure):
            supervisor.sample_app_lifecycle()
        supervisor.emit.assert_not_called()

    def test_paused_mail_is_not_a_successful_continuing_lifecycle_sample(self):
        supervisor = self.supervisor()
        supervisor.private['nodes']['candidate-recipient']['apps'] = [{'appId': 'mail-prototype'}]
        supervisor.plan['nodes'][1]['appDigests'] = ['selected-mail']
        supervisor.apps[('candidate-recipient', 'mail-prototype')] = Mock(app_id='mail-prototype')
        with patch.object(runtime, 'ObservedMailClient') as client:
            client.return_value.command.return_value = {'status': 'ready', 'recovery': 'paused'}
            with self.assertRaisesRegex(runtime.RuntimeFailure, 'mail-continuing-health'):
                supervisor.sample_app_lifecycle()
        supervisor.emit.assert_not_called()

    def resource_fixture(self, directory):
        supervisor = self.supervisor()
        supervisor.apps = {}
        supervisor.plan = {'nodes': [{'role': 'candidate-sender', 'appDigests': []}]}
        supervisor.private = {'nodes': {'candidate-sender': {'apps': []}}}
        root = Path(directory)
        (root / 'node/run').mkdir(parents=True)
        (root / 'java/bin').mkdir(parents=True)
        (root / 'java/bin/java').write_bytes(b'selected java')
        identity = {'supervisor': {'pid': 7}, 'jvm': {'pid': 8}}
        path = root / 'node/run/process-identity.json'
        path.write_text(json.dumps(identity))
        path.chmod(0o600)
        node = SimpleNamespace(runtime=SimpleNamespace(config_file=root / 'node/config/cryptad.ini'),
                               identity=identity['supervisor'], java_home=root / 'java')
        supervisor.nodes = {'candidate-sender': node}
        return supervisor

    def test_resource_sample_is_collected_without_optional_budget_stress_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            supervisor = self.resource_fixture(directory)
            adapter = Mock()
            adapter.measure_resources.return_value = {'metrics': {'memoryBytes': 1024, 'threads': 2, 'fileDescriptors': 4, 'queueDepth': None}, 'status': 'measured-but-uncompared'}
            with patch.object(runtime, 'fixed_helper', return_value=adapter):
                supervisor.sample_resources()
            supervisor.emit.assert_called_once_with('sample', 'candidate-sender', 'app-budgets', counters={'memoryBytes': 1024, 'threads': 2, 'fileDescriptors': 4})
            self.assertEqual(1, supervisor.resource_observations['sampleCount'])
            self.assertEqual(7, supervisor.observed_operations)

    def test_missing_or_zero_required_metric_stays_partial_without_eligible_sample(self):
        for missing in (None, 0):
            with tempfile.TemporaryDirectory() as directory:
                supervisor = self.resource_fixture(directory)
                adapter = Mock()
                adapter.measure_resources.return_value = {'metrics': {'memoryBytes': missing, 'threads': 2, 'fileDescriptors': 4}, 'status': 'measured-but-uncompared'}
                with patch.object(runtime, 'fixed_helper', return_value=adapter):
                    supervisor.sample_resources()
                self.assertEqual('operation', supervisor.emit.call_args.args[0])
                self.assertEqual('partial', supervisor.emit.call_args.kwargs['outcome'])


if __name__ == '__main__':
    unittest.main()
