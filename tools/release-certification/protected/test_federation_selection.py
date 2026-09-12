"""Original transport seams supplement real CMS confidentiality and native Java scope tests."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import federation_selection as selection
import app_subject_projection as projection
from original_artifact_authentication import OriginalArtifact
import test_app_subject_projection as legacy_tests


class SelectionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.coordinates = {'repository': 'crypta-network/cryptad', 'sourceFamily': 'federation-selection',
            'sourceCommit': 'a' * 40, 'runId': 12, 'runAttempt': 3, 'jobId': 14,
            'jobName': 'produce-federation-selection', 'artifactId': 15, 'artifactName': 'original-selection',
            'artifactDigest': 'sha256:' + 'b' * 64, 'artifactSize': 100}
        self.content_origin = {**self.coordinates, 'sourceFamily': 'third-party-pilot'}
        context = {'appId': 'external-app', 'generation': 3,
            'candidates': [{'catalog': {'path': 'catalog', 'digest': selection.digest(b'catalog')},
                            'signature': {'path': 'signature', 'digest': selection.digest(b'signature')},
                            'bundle': {'path': 'bundle', 'digest': selection.digest(b'bundle')}}],
            'catalogBindings': [{'path': 'catalog.properties', 'digest': selection.digest(b'catalog-scope')}],
            'publisherBindings': [{'path': 'publisher.properties', 'digest': selection.digest(b'publisher-scope')}],
            'reviewerScopes': [{'path': 'reviewer.properties', 'digest': selection.digest(b'reviewer-scope')}],
            'bundleDigest': selection.digest(b'bundle'), 'catalogDigest': selection.digest(b'catalog'),
            'catalogSignatureDigest': selection.digest(b'signature')}
        self.files = {'context.json': selection._bytes(context), 'catalog': b'catalog', 'signature': b'signature',
                      'bundle': b'bundle', 'catalog.properties': b'catalog-scope',
                      'publisher.properties': b'publisher-scope', 'reviewer.properties': b'reviewer-scope'}
        self.handoff = {'schemaVersion': 1, 'kind': 'private-federation-selection',
            'producer': {'workflowPath': selection.WORKFLOW, 'sourceCommit': 'a' * 40, 'runId': 12, 'runAttempt': 3},
            'generatedAt': '2026-09-11T17:15:00+00:00',
            'contexts': [{'id': 'initial', 'appId': 'external-app', 'member': 'context.json',
                          'digest': selection.digest(self.files['context.json']), 'generation': 3}],
            'members': [{'name': name, 'digest': selection.digest(raw), 'size': len(raw),
                         'original': {'coordinates': self.content_origin, 'member': name}
                         if name in {'catalog', 'signature', 'bundle'} else None}
                        for name, raw in self.files.items()]}
        self.files['selection-handoff.json'] = selection._bytes(self.handoff)
        self.now = dt.datetime(2026, 9, 11, 18, tzinfo=dt.timezone.utc)

    def test_complete_candidate_and_scope_roster_is_required(self):
        selection._validate_handoff(self.handoff, self.files, now=self.now)
        for missing in ('bundle', 'catalog.properties', 'publisher.properties', 'reviewer.properties'):
            with self.subTest(missing=missing), self.assertRaises(selection.SelectionFailure):
                selection._validate_handoff(self.handoff, {key: raw for key, raw in self.files.items() if key != missing}, now=self.now)

    def test_local_selection_cannot_claim_original_bundle_build(self):
        handoff = copy.deepcopy(self.handoff)
        next(row for row in handoff['members'] if row['name'] == 'bundle')['original'] = None
        with self.assertRaisesRegex(selection.SelectionFailure, 'candidate-original-missing'):
            selection._validate_handoff(handoff, self.files, now=self.now)

    def test_archive_rejects_extra_traversal_link_and_case_alias_before_use(self):
        import io
        import zipfile
        for name, mode in (('../escape', 0o100600), ('context.json', 0o120777), ('CONTEXT.JSON', 0o100600)):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                archive.writestr('context.json', b'original')
                entry = zipfile.ZipInfo(name)
                entry.external_attr = mode << 16
                archive.writestr(entry, b'canary')
            with self.subTest(name=name), self.assertRaises(selection.SelectionFailure):
                selection.archive_members(output.getvalue())

    def test_wrong_original_attempt_is_rejected_before_private_decryption(self):
        raw = selection._archive({selection.MEMBER: b'ciphertext'})
        proof = [{'verificationResult': {'signature': {'certificate': {'runInvocationURI':
            'https://github.com/crypta-network/cryptad/actions/runs/12/attempts/2'}}}}]
        with patch.object(selection, 'authenticate_original', return_value=OriginalArtifact(raw, self.coordinates)), \
                patch.object(selection, '_gh', return_value=proof), patch.object(selection, '_environment', return_value={}), \
                patch.object(selection, '_cms') as decrypt:
            with self.assertRaisesRegex(selection.SelectionFailure, 'attested-attempt-mismatch'):
                selection.authenticate_selection(self.coordinates, self.root)
            decrypt.assert_not_called()

    def test_authenticated_private_bytes_retain_external_source_and_generation(self):
        raw = selection._archive({selection.MEMBER: b'ciphertext'})
        proof = [{'verificationResult': {'signature': {'certificate': {'runInvocationURI':
            'https://github.com/crypta-network/cryptad/actions/runs/12/attempts/3'}}}}]
        with patch.object(selection, 'authenticate_original', return_value=OriginalArtifact(raw, self.coordinates)), \
                patch.object(selection, '_gh', return_value=proof), patch.object(selection, '_environment', return_value={}), \
                patch.object(selection, '_cms', return_value=selection._archive(self.files)):
            authenticated = selection.authenticate_selection(self.coordinates, self.root)
        source = {'appId': 'external-app', 'original': self.content_origin, 'members': {'bundle': 'bundle', 'catalog': 'catalog', 'catalogSignature': 'signature'}}
        authenticated.require_source('initial', source)
        self.assertEqual(3, authenticated.context('initial')['generation'])
        source['original'] = self.coordinates
        with self.assertRaisesRegex(selection.SelectionFailure, 'content-origin-substituted'):
            authenticated.require_source('initial', source)
        authenticated.materialize(self.root / 'materialized')
        self.assertEqual(self.files['bundle'], (self.root / 'materialized/bundle').read_bytes())
        with self.assertRaises(selection.SelectionFailure):
            authenticated.materialize(self.root / 'materialized')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'protected CMS handoff uses the Linux runner openssl')
    def test_real_envelope_roundtrip_is_randomized_and_has_no_private_canary(self):
        certificate, key = self.root / 'certificate.pem', self.root / 'key.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(certificate), '-days', '1', '-subj', '/CN=synthetic-pr305'],
                       check=True, capture_output=True, timeout=30)
        original_regular = selection._regular
        # OS-owner seam only: the test runner is unprivileged, unlike protected root provisioning.
        def regular(path, maximum=1024*1024, **kwargs):
            return original_regular(path, maximum)
        canary = b'private-subscription-canary-and-local-selection' * 10
        with patch.object(selection, 'RECIPIENT', certificate), patch.object(selection, 'RECIPIENT_KEY', key), \
                patch.object(selection, '_regular', side_effect=regular):
            first = selection._cms(canary, self.root)
            second = selection._cms(canary, self.root)
            self.assertNotEqual(first, second)
            self.assertNotIn(canary[:20], first)
            self.assertEqual(canary, selection._cms(first, self.root, decrypt=True))
            damaged = first[:-1] + bytes([first[-1] ^ 1])
            with self.assertRaises(selection.SelectionFailure):
                selection._cms(damaged, self.root, decrypt=True)

    def test_v4_companion_keeps_legacy_content_and_runtime_authority_separate(self):
        inventory, contract, policy = legacy_tests.ProjectionBoundaryTest().inventory()
        original = next(row['signedProjection'] for row in inventory['subjects'] if row['appId'] == 'external-app')
        native = {**original, 'schemaVersion': 3, 'contractSnapshotDigest': selection.digest(b'contract'),
                  'baselineRegistryDigest': selection.digest(b'registry'), 'nativeAdmission': 'accepted', 'catalogChannel': 'stable',
                  'federationSelection': {key: selection.digest(key.encode()) for key in
                     ('selectionDigest', 'selectedSubjectDigest', 'conflictSetDigest', 'catalogBindingDigest',
                      'publisherPolicyDigest', 'publisherBindingDigest', 'catalogRevisionDigest', 'reviewerPolicyDigest')}}
        native['federationSelection']['generation'] = 3
        inventory.update(schemaVersion=4, baseInventoryVersion=2, privacy='private-local-selection',
            selectedFederation=[{'appId': 'external-app', 'original': self.coordinates, 'contextId': 'initial',
                'contextDigest': native['federationSelection']['selectionDigest'], 'generation': 3, 'nativeProjection': native}])
        inventory['cohortProjection'] = {'federationSelections': [{key: value for key, value in inventory['selectedFederation'][0].items() if key != 'nativeProjection'}]}
        inventory['cohortProjection']['admissionContract'] = {'snapshotDigest': native['contractSnapshotDigest'],
                                                           'registryDigest': native['baselineRegistryDigest']}
        inventory['cohortDigest'] = projection._canonical_digest(inventory['cohortProjection'])
        inventory['inventoryDigest'] = projection._canonical_digest({**inventory, 'inventoryDigest': 'sha256:' + '0'*64})
        projection.validate_federation_inventory(inventory)
        capability = projection.AuthenticatedProjection(inventory, selection.digest(b'inventory'), projection._VERIFIED)
        from cryptad_certification.engines import stable_platform_api_1x as api
        self.assertEqual([], api._app_subject_inventory_errors(inventory, False, contract, policy, capability))
        inventory['baseInventoryVersion'] = 3
        self.assertTrue(any('runtime-only' in error for error in api._app_subject_inventory_errors(inventory, False, contract, policy, capability)))
        inventory['selectedFederation'][0]['generation'] = 4
        with self.assertRaises(projection.ProjectionFailure):
            projection.validate_federation_inventory(inventory)
