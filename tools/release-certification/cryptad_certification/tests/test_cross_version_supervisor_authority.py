"""Offline protected-control substitutions; no service, network or privileged changes."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from cryptad_certification.cross_version_evidence import digest, Journal
from cryptad_certification.tests.test_cross_version_evidence import fixture_plan

MODULE = Path(__file__).resolve().parents[2] / 'protected/cross_version_supervisor_authority.py'
SPEC = importlib.util.spec_from_file_location('cross_version_supervisor_authority', MODULE)
authority = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = authority
SPEC.loader.exec_module(authority)


@unittest.skipUnless(os.name == 'posix', 'Linux installed service authority')
class SupervisorAuthorityTest(unittest.TestCase):
    def selection(self):
        plan = fixture_plan()
        plan.update(profile='protected-long-live', requestedSeconds=72 * 3600)
        plan['policy']['minimumObservedSeconds'] = 72 * 3600
        private = {'root': '/selected/disposable'}
        auth = {'maxSeconds': 73 * 3600, 'maxOperations': 10000, 'syntheticContent': True}
        return plan, private, auth

    def activation(self, plan, private, auth):
        return {'schemaVersion': 1, 'planDigest': digest(plan), 'privateConfigDigest': digest(private),
                'authorizationDigest': digest(auth), 'producer': plan['producer'], 'ownerUid': os.getuid(),
                'bootId': 'selected-boot', 'startedMonotonicNs': 100, 'deadlineMonotonicNs': 1000,
                'approvalOrigin': {'artifactId': 3}, 'approvalReportDigest': 'sha256:' + 'e' * 64}

    def test_tokenless_admission_requires_root_activation_exact_inputs_cgroup_and_time(self):
        plan, private, auth = self.selection()
        activation = self.activation(plan, private, auth)
        with patch.object(authority, 'secured', side_effect=lambda p: p), patch.object(authority, 'read_json', return_value=activation), patch.object(authority, 'boot_id', return_value='selected-boot'), patch.object(authority, 'owned_cgroup', return_value=True), patch.object(authority.time, 'monotonic_ns', return_value=500):
            admitted = authority.authenticate_runner(plan, private, auth)
            self.assertIsInstance(admitted, authority.AuthenticatedRunner)
            self.assertGreater(admitted.remaining_seconds(), 0)
            for changed in ({'maxSeconds': 10}, {**auth, 'syntheticContent': False}):
                with self.assertRaisesRegex(authority.AuthorityError, 'binding-or-lifetime'):
                    authority.authenticate_runner(plan, private, changed)
            with patch.object(authority, 'owned_cgroup', return_value=False):
                with self.assertRaisesRegex(authority.AuthorityError, 'outside-owned-service'):
                    authority.authenticate_runner(plan, private, auth)
            with patch.object(authority.time, 'monotonic_ns', return_value=1001):
                with self.assertRaisesRegex(authority.AuthorityError, 'binding-or-lifetime'):
                    authority.authenticate_runner(plan, private, auth)
            with patch.object(authority, 'boot_id', return_value='another-boot'):
                with self.assertRaisesRegex(authority.AuthorityError, 'binding-or-lifetime'):
                    authority.authenticate_runner(plan, private, auth)

    def test_activated_products_rebind_exact_bytes_without_retaining_github_credentials(self):
        import hashlib
        import cross_version_product_admission as products
        plan, private, auth = self.selection()
        private['nodes'] = {}
        rows = []
        with tempfile.TemporaryDirectory() as directory:
            for node in plan['nodes']:
                path = Path(directory).resolve() / (node['role'] + '.tar.gz')
                payload = b'selected candidate' if node['role'].startswith('candidate') else node['role'].encode()
                path.write_bytes(payload)
                node['artifactDigest'] = 'sha256:' + hashlib.sha256(payload).hexdigest()
                node['artifactSize'] = len(payload)
                private['nodes'][node['role']] = {'archivePath': str(path)}
                rows.append({'role': node['role'], 'artifactDigest': node['artifactDigest'],
                             'artifactSize': node['artifactSize'], 'appMatrix': [{'screening': 'fixture'}]})
            activation = {**self.activation(plan, private, auth), 'products': rows}
            runner = authority.AuthenticatedRunner(authority._SEAL, activation)
            with patch.object(products, 'authenticate_original') as network:
                admitted = runner.product_admission(plan, private)
                self.assertIsInstance(admitted, products.AuthenticatedProducts)
                network.assert_not_called()
                Path(private['nodes']['candidate-sender']['archivePath']).write_bytes(b'substituted')
                with self.assertRaisesRegex(products.ProductAdmissionError, 'package-substituted'):
                    runner.product_admission(plan, private)
                network.assert_not_called()

    def test_caller_cannot_construct_runner_object(self):
        with self.assertRaises(authority.AuthorityError):
            authority.AuthenticatedRunner(None, {})

    def test_selected_files_use_single_descriptor_bytes_and_reject_symlink_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            selected = state / 'selected'
            selected.mkdir(mode=0o700)
            for name in ('plan', 'private-config', 'authorization', 'service-selection'):
                path = selected / (name + '.json')
                path.write_bytes(b'{"selected":true}')
                path.chmod(0o600)
            values, hashes = authority.read_selected(state, os.getuid())
            self.assertEqual({'selected': True}, values['plan'])
            import hashlib
            self.assertEqual('sha256:' + hashlib.sha256(b'{"selected":true}').hexdigest(), hashes['plan'])
            real_open = os.open
            def switched(path, flags, *args, **kwargs):
                if path == 'plan.json':
                    target = selected / 'plan.json'
                    target.unlink()
                    target.symlink_to(selected / 'private-config.json')
                return real_open(path, flags, *args, **kwargs)
            with patch.object(authority.os, 'open', side_effect=switched):
                with self.assertRaises(OSError):
                    authority.read_selected(state, os.getuid())

    def test_selected_state_with_symlinked_ancestor_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            actual = root / 'actual'
            actual.mkdir()
            state = actual / 'state'
            state.mkdir(mode=0o700)
            link = root / 'linked'
            link.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(OSError):
                authority.read_selected(link / 'state', os.getuid())

    def test_selected_directory_link_and_hardlinked_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            actual = state / 'actual'
            actual.mkdir(mode=0o700)
            (state / 'selected').symlink_to(actual, target_is_directory=True)
            with self.assertRaises(OSError):
                authority.read_selected(state, os.getuid())
            (state / 'selected').unlink()
            (state / 'selected').mkdir(mode=0o700)
            original = state / 'original.json'
            original.write_text('{}')
            original.chmod(0o600)
            os.link(original, state / 'selected/plan.json')
            with self.assertRaisesRegex(authority.AuthorityError, 'input-not-private'):
                authority.read_selected(state, os.getuid())

    def test_secured_input_rejects_group_writable_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / 'input.json'
            target.write_text('{}')
            target.chmod(0o666)
            with self.assertRaises(authority.AuthorityError):
                authority.secured(target, owner=os.getuid())
            link = Path(directory).resolve() / 'link.json'
            link.symlink_to(target)
            with self.assertRaises(authority.AuthorityError):
                authority.secured(link, owner=os.getuid())

    def original(self, report, name='cross-version-supervisor.json'):
        content = io.BytesIO()
        with zipfile.ZipFile(content, 'w') as archive:
            archive.writestr(name, json.dumps(report))
        coordinates = {'sourceFamily': 'cross-version-supervisor', 'sourceCommit': 'a' * 40, 'runId': 9, 'runAttempt': 2, 'artifactName': 'cross-version-supervisor-9-2'}
        return SimpleNamespace(content=content.getvalue(), coordinates=coordinates)

    def test_original_attestation_requires_exact_attempt_and_member_job(self):
        plan, _, _ = self.selection()
        report = {'schemaVersion': 1, 'kind': 'cryptad-cross-version-supervisor', 'operation': 'authorize',
                  'experimentId': plan['experimentId'], 'planDigest': digest(plan), 'producer': plan['producer'],
                  'job': {'sourceCommit': 'a' * 40, 'runId': 9, 'runAttempt': 2}, 'purpose': 'nonrelease-observed-experiment',
                  'releaseEligible': False, 'selectionDigest': 'sha256:' + 'b' * 64,
                  'approvedBounds': {}, 'plan': plan, 'serviceDigest': 'sha256:' + 'c' * 64}
        original = self.original(report)
        invocation = 'https://github.com/crypta-network/cryptad/actions/runs/9/attempts/2'
        verified = [{'verificationResult': {'signature': {'certificate': {'runInvocationURI': invocation}}}}]
        with tempfile.TemporaryDirectory() as directory, patch.object(authority, 'authenticate_original', return_value=original), patch.object(authority, '_environment', return_value={}), patch.object(authority, '_gh', return_value=verified) as gh:
            observed, _ = authority.authenticate_report(original.coordinates, Path(directory).resolve())
            self.assertEqual(report, observed)
            self.assertIn('--signer-digest', gh.call_args.args[0])
            gh.return_value = [{'verificationResult': {'signature': {'certificate': {'runInvocationURI': invocation[:-1] + '1'}}}}]
            with self.assertRaisesRegex(authority.AuthorityError, 'attested-attempt'):
                authority.authenticate_report(original.coordinates, Path(directory).resolve())
            gh.return_value = verified
            changed = self.original({'job': {**report['job'], 'runAttempt': 1}})
            with patch.object(authority, 'authenticate_original', return_value=changed):
                with self.assertRaisesRegex(authority.AuthorityError, 'original-job'):
                    authority.authenticate_report(original.coordinates, Path(directory).resolve())

    def test_zip_substitution_rejected_before_attestation(self):
        original = self.original({}, '../cross-version-supervisor.json')
        with tempfile.TemporaryDirectory() as directory, patch.object(authority, 'authenticate_original', return_value=original), patch.object(authority, '_gh') as gh:
            with self.assertRaisesRegex(authority.AuthorityError, 'artifact-shape'):
                authority.authenticate_report(original.coordinates, Path(directory).resolve())
            gh.assert_not_called()

    def test_authorize_is_non_mutating_and_start_requires_completed_original_authorization(self):
        plan, private, auth = self.selection()
        job = {'sourceCommit': plan['producer']['sourceCommit'], 'runId': 1, 'runAttempt': 1}
        bindings = {'serviceDigest': 'sha256:' + 'b' * 64}
        with tempfile.TemporaryDirectory() as directory:
            private['root'] = str(Path(directory).resolve() / 'not-created')
            with patch.object(authority.os, 'geteuid', return_value=0), patch.object(authority, 'selected_inputs', return_value=(plan, private, auth, os.getuid(), bindings)), patch.object(authority, 'run_identity', return_value=job), patch.object(authority, '_service_state', return_value='stopped'), patch.object(authority.subprocess, 'run') as run:
                report = authority.control('authorize')
                self.assertEqual('authorize', report['operation'])
                self.assertFalse(report['releaseEligible'])
                self.assertEqual([], authority.scan_value(report))
                run.assert_not_called()
                previous = {**report, 'operation': 'checkpoint'}
                with patch.object(authority, 'secured', side_effect=lambda p, **kw: p), patch.object(authority, 'read_json', return_value={}), patch.object(authority, 'authenticate_report', return_value=(previous, {'artifactId': 1})):
                    with self.assertRaisesRegex(authority.AuthorityError, 'requires-original-authorization'):
                        authority.control('start')
                run.assert_not_called()

    @patch.object(authority, 'boot_id', return_value='selected-boot')
    def test_fixed_start_records_authority_before_start_and_rejects_reuse(self, boot):
        plan, private, auth = self.selection()
        bindings = {'serviceDigest': 'sha256:' + 'b' * 64}
        job = {'sourceCommit': plan['producer']['sourceCommit'], 'runId': 2, 'runAttempt': 1}
        previous = {'schemaVersion': 1, 'operation': 'authorize', 'experimentId': plan['experimentId'],
                    'planDigest': digest(plan), 'producer': plan['producer'], 'selectionDigest': digest(bindings), 'plan': plan}
        with tempfile.TemporaryDirectory() as directory:
            private['root'] = str(Path(directory).resolve() / 'never-created')
            protected = Path(directory).resolve() / 'authority'
            with patch.object(authority.os, 'geteuid', return_value=0), patch.object(authority, 'AUTHORITY', protected), patch.object(authority, 'authority_directory', side_effect=lambda: protected.mkdir(exist_ok=True)), patch.object(authority, 'selected_inputs', return_value=(plan, private, auth, os.getuid(), bindings)), patch.object(authority, 'run_identity', return_value=job), patch.object(authority, 'secured', side_effect=lambda p, **kw: p), patch.object(authority, 'read_json', return_value={}), patch.object(authority, 'authenticate_report', return_value=(previous, {'artifactId': 1})), patch.object(authority, '_service_state', side_effect=['stopped', 'running', 'stopped']), patch.object(authority.subprocess, 'run') as run:
                report = authority.control('start')
                self.assertEqual('running', report['serviceState'])
                self.assertEqual([], authority.scan_value(report))
                activation = json.loads((protected / 'activation.json').read_text())
                self.assertEqual(digest(private), activation['privateConfigDigest'])
                self.assertEqual(boot.return_value, activation['bootId'])
                self.assertEqual(['/usr/bin/systemctl', 'start', authority.UNIT], run.call_args.args[0])
                self.assertNotIn('GH_TOKEN', run.call_args.kwargs['env'])
                with self.assertRaisesRegex(authority.AuthorityError, 'reuse'):
                    authority.control('start')
                self.assertEqual(1, run.call_count)

    @patch('cryptad_certification.cross_version_evidence.boot_identity',
           return_value='00000000-0000-0000-0000-000000000001')
    def test_checkpoint_reads_atomic_prefix_and_rejects_prior_tail_substitution(self, boot):
        plan = fixture_plan()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'journal'
            with Journal(root, plan) as journal:
                boot.assert_called_once_with()
                journal.append('start')
                journal.append('probe', counters={'operations': 0})
                checkpoint = journal.checkpoint('partial')
                # A writer may have appended beyond the selected checkpoint.
                journal.append('probe', counters={'operations': 0})
                report = authority.snapshot(plan, root, expected_uid=os.getuid())
                measured = authority.snapshot(plan, root, expected_uid=os.getuid(),
                    activation={'planDigest': digest(plan), 'producer': plan['producer'], 'products': None})
                self.assertEqual(report['checkpoint'], measured['checkpoint'])
                self.assertEqual(report['checkpoint']['digest'], measured['maintenanceMeasurements']['checkpointDigest'])
                self.assertEqual('blocked', measured['maintenanceMeasurements']['maintenanceEligibility'])
                self.assertEqual([], authority.scan_value(measured))
                with self.assertRaisesRegex(authority.AuthorityError, 'activation-substituted'):
                    authority.snapshot(plan, root, expected_uid=os.getuid(), activation={'planDigest': 'wrong'})
                self.assertEqual(checkpoint['sequence'], report['checkpoint']['sequence'])
                substituted = {'checkpoint': {**report['checkpoint'], 'tailDigest': 'sha256:' + 'a' * 64}}
                with self.assertRaisesRegex(authority.AuthorityError, 'tail-substitution'):
                    authority.snapshot(plan, root, substituted, expected_uid=os.getuid())

    @patch('cryptad_certification.cross_version_evidence.boot_identity',
           return_value='00000000-0000-0000-0000-000000000001')
    def test_checkpoint_rejects_unbounded_sequence_and_completed_trailing_bytes(self, boot):
        plan = fixture_plan()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'journal'
            with Journal(root, plan) as journal:
                boot.assert_called_once_with()
                journal.append('start')
                journal.append('finish')
                checkpoint = journal.checkpoint('complete')
            path = root / 'checkpoint.json'
            path.write_text(json.dumps({**checkpoint, 'sequence': plan['policy']['maxEvents'] + 1}))
            with self.assertRaisesRegex(authority.AuthorityError, 'sequence-budget'):
                authority.snapshot(plan, root, expected_uid=os.getuid())
            path.write_text(json.dumps(checkpoint))
            with (root / 'journal.jsonl').open('ab') as stream:
                stream.write(b'{}\n')
            with self.assertRaisesRegex(authority.AuthorityError, 'trailing-journal'):
                authority.snapshot(plan, root, expected_uid=os.getuid())
            with self.assertRaisesRegex(authority.AuthorityError, 'path-not-owned'):
                authority.snapshot(plan, root, expected_uid=os.getuid() + 1)

    def test_main_never_prints_report_rejected_by_shared_redaction(self):
        with patch.object(authority.sys, 'argv', ['control', 'authorize']), patch.object(authority, 'control', return_value={'private': 'private-canary'}), patch.object(authority, 'scan_value', return_value=[{'category': 'secret'}]), patch('builtins.print') as output:
            self.assertEqual(2, authority.main())
            self.assertEqual(1, output.call_count)
            self.assertNotIn('private-canary', output.call_args.args[0])
            self.assertIs(authority.sys.stderr, output.call_args.kwargs['file'])

    def test_public_privacy_failure_stops_only_just_started_owned_service(self):
        with patch.object(authority.sys, 'argv', ['control', 'start']), patch.object(authority, 'control', return_value={'operation': 'start', 'serviceState': 'running'}), patch.object(authority, 'scan_value', return_value=[{'category': 'secret'}]), patch.object(authority.subprocess, 'run') as command, patch('builtins.print'):
            self.assertEqual(2, authority.main())
            self.assertEqual(['/usr/bin/systemctl', 'stop', authority.UNIT], command.call_args.args[0])
            self.assertNotIn('GH_TOKEN', command.call_args.kwargs['env'])

    def test_finish_does_not_stop_running_service(self):
        plan, private, auth = self.selection()
        bindings = {'serviceDigest': 'sha256:' + 'b' * 64}
        job = {'sourceCommit': plan['producer']['sourceCommit'], 'runId': 3, 'runAttempt': 1}
        activation = self.activation(plan, private, auth)
        previous = {'operation': 'start', 'experimentId': plan['experimentId'], 'planDigest': digest(plan),
                    'producer': plan['producer'], 'selectionDigest': digest(bindings), 'approvalOrigin': activation['approvalOrigin']}
        with patch.object(authority.os, 'geteuid', return_value=0), patch.object(authority, 'selected_inputs', return_value=(plan, private, auth, os.getuid(), bindings)), patch.object(authority, 'run_identity', return_value=job), patch.object(authority, 'secured', side_effect=lambda p, **kw: p), patch.object(authority, 'read_json', return_value=activation), patch.object(authority, 'authenticate_report', return_value=(previous, {'artifactId': 1})), patch.object(authority, '_service_state', return_value='running'), patch.object(authority.subprocess, 'run') as run:
            with self.assertRaisesRegex(authority.AuthorityError, 'still-running'):
                authority.control('finish')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
