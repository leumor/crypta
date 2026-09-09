"""Command admission checks must finish before any network or process mutation."""
import json
import contextlib
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptad_certification.cli import build_parser, main
from cryptad_certification.cross_version_command import adapter, publish, read, run, runtime_subcases
from cryptad_certification.tests.test_cross_version_evidence import fixture_plan


class CrossVersionCommandTest(unittest.TestCase):
    def test_runtime_export_uses_fixed_cases_and_never_private_comparison_values(self):
        value = runtime_subcases({'mailOriginObservations': {'candidate-sender:wrongApp': 'observed'},
                                  'privateRuntimeState': 'private-canary-value'})
        self.assertNotIn('private-canary', json.dumps(value))
        self.assertFalse(value['releaseEligible'])
        for source in ({'privateCase': 'observed'}, {'candidate-sender:wrongApp': 'private-canary-value'}):
            with self.assertRaises(ValueError):
                runtime_subcases({'mailOriginObservations': source})

    def test_unexpected_collector_error_cannot_export_private_exception_text(self):
        output = io.StringIO()
        with patch('cryptad_certification.cross_version_command.run',
                   side_effect=RuntimeError('private-canary-and-selected-path')), contextlib.redirect_stderr(output):
            self.assertEqual(2, main(['cross-version-soak', 'plan']))
        self.assertNotIn('private-canary', output.getvalue())
        self.assertNotIn('Traceback', output.getvalue())
        self.assertIn('no complete soak evidence', output.getvalue())

    def test_live_without_explicit_execution_cannot_create_private_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / 'plan.json'
            plan.write_text(json.dumps(fixture_plan()))
            args = build_parser().parse_args(['cross-version-soak', 'run', '--plan', str(plan),
                                             '--journal-root', str(root / 'private'),
                                             '--out-dir', str(root / 'public')])
            with self.assertRaisesRegex(ValueError, 'explicit-execution'):
                run(args)
            self.assertFalse((root / 'private').exists())

    def test_duplicate_input_and_public_private_config_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_text('{"root":1,"root":2}')
            with self.assertRaisesRegex(ValueError, 'duplicate-json'):
                read(path)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'private-input-permissions'):
                read(path, private=True)

    def test_export_cannot_overwrite_old_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'public'
            publish(root, {'status': 'partial'})
            with self.assertRaisesRegex(ValueError, 'output-must-be-new'):
                publish(root, {'status': 'pass'})
            self.assertEqual({'status': 'partial'}, read(root / 'summary.json'))

    def test_migration_export_rejects_private_comparison_field_before_creating_output(self):
        module = adapter('sharesite_observation', protected=True)
        value = {'schemaVersion': 2, 'kind': 'sharesite-runtime-observation',
                 'classification': 'upstream-writer-synthetic', 'status': 'partial',
                 'selectedCount': 1, 'outcomes': dict.fromkeys(module.CHECKS, 'not-observed'),
                 'publication': 'not-observed', 'realDataMigration': 'not-observed',
                 'releaseEligibility': 'blocked', 'planDigest': 'sha256:' + '1' * 64,
                 'bundleDigest': 'sha256:' + '2' * 64,
                 'producerTools': dict.fromkeys(('toolTreeDigest', 'javaTreeDigest',
                    'controllerDigest', 'driverDigest', 'nodeDigest'), 'sha256:' + '3' * 64)}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'public'
            with self.assertRaises(ValueError):
                publish(root, {'status': 'partial'}, migration={**value, 'privateBodyHash': '0' * 64})
            self.assertFalse(root.exists())
            publish(root, {'status': 'partial'}, migration=value)
            self.assertEqual({'summary.json', 'sharesite-runtime-observation.json'},
                             {path.name for path in root.iterdir()})
            self.assertNotIn('producer', read(root / 'sharesite-runtime-observation.json'))

    @unittest.skipUnless(os.name == 'posix' and Path('/proc').is_dir(), 'Linux owned journal')
    def test_interrupted_runtime_preserves_partial_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / 'private'
            inputs = {'plan': fixture_plan(), 'private-config': {'root': str(private)}, 'authorization': {}}
            for name, value in inputs.items():
                path = root / (name + '.json')
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            args = build_parser().parse_args(['cross-version-soak', 'run', '--execute',
                '--plan', str(root / 'plan.json'), '--private-config', str(root / 'private-config.json'),
                '--authorization', str(root / 'authorization.json'), '--journal-root', str(private),
                '--out-dir', str(root / 'public')])
            def interrupted(plan, config, authorization, journal):
                journal.append('fault', outcome='partial')
                return {'failureCode': 'controller-interrupted'}
            with patch('cryptad_certification.cross_version_command.adapter',
                       return_value=SimpleNamespace(run=interrupted, RuntimeFailure=RuntimeError)):
                self.assertEqual(2, run(args))
            self.assertEqual('partial', read(private / 'checkpoint.json')['status'])
            self.assertNotIn('"kind":"finish"', (private / 'journal.jsonl').read_text())
