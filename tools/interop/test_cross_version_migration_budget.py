"""Offline migration subprocess admission using the production operation reservation."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import cross_version_runtime as runtime

with runtime.fixed_helper_imports():
    import sharesite_observation as migration


class MigrationBudgetTest(unittest.TestCase):
    def supervisor(self, maximum, used=3):
        supervisor = runtime.Supervisor.__new__(runtime.Supervisor)
        supervisor.authorization = {'maxOperations': maximum}
        supervisor.operations = used
        supervisor.remaining = Mock(return_value=180)
        supervisor.save_state = Mock()
        return supervisor

    def run_stage(self, supervisor, stage):
        inputs = SimpleNamespace(node_executable=Path('/selected/node'), java_home=Path('/selected/java'))
        return migration._run_stage(supervisor, inputs, stage, {'stage': stage, 'maximumRequests': 9999},
                                    Path('/selected/driver'), Path('/private'))

    def test_insufficient_capacity_prevents_subprocess_for_every_stage(self):
        for stage, limit in migration.STAGE_REQUEST_LIMITS.items():
            with self.subTest(stage=stage):
                supervisor = self.supervisor(limit + 2)
                with patch.object(migration, '_execute') as execute:
                    with self.assertRaises(runtime.RuntimeFailure):
                        self.run_stage(supervisor, stage)
                execute.assert_not_called()
                supervisor.save_state.assert_not_called()
                self.assertEqual(3, supervisor.operations)

    def test_full_allowance_is_durable_before_launch_and_passed_to_driver(self):
        for stage, limit in migration.STAGE_REQUEST_LIMITS.items():
            with self.subTest(stage=stage):
                supervisor = self.supervisor(limit + 3)
                saved = []
                supervisor.save_state.side_effect = lambda: saved.append(supervisor.operations)
                expected = {'schemaVersion': 1, 'kind': 'sharesite-runtime-stage', 'stage': stage,
                            'selectedCount': 1, 'checks': dict.fromkeys(migration.STAGE_CHECKS[stage], 'pass')}
                def execute(_arguments, config, **_kwargs):
                    self.assertEqual([limit + 3], saved)
                    self.assertEqual(limit, config['maximumRequests'])
                    return json.dumps(expected).encode()
                with patch.object(migration, '_execute', side_effect=execute):
                    self.assertEqual(expected, self.run_stage(supervisor, stage))
                self.assertEqual(limit + 3, supervisor.operations)

    def test_unknown_child_outcome_retains_the_complete_reservation(self):
        limit = migration.STAGE_REQUEST_LIMITS['restore']
        supervisor = self.supervisor(limit + 3)
        with patch.object(migration, '_execute', side_effect=migration.MigrationFailure('unknown-child-outcome')):
            with self.assertRaises(migration.MigrationFailure):
                self.run_stage(supervisor, 'restore')
        self.assertEqual(limit + 3, supervisor.operations)
        supervisor.save_state.assert_called_once()

    def test_failed_checkpoint_prevents_launch(self):
        supervisor = self.supervisor(1000)
        supervisor.save_state.side_effect = OSError('offline-checkpoint-failure')
        with patch.object(migration, '_execute') as execute:
            with self.assertRaises(OSError):
                self.run_stage(supervisor, 'import')
        execute.assert_not_called()
