"""Offline original-transport seams plus real Ed25519 signing; no protected operation is run."""
import base64
import copy
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import federated_catalog_runtime_observer as observer
import federation_selection as selection
import test_app_subject_projection as fixtures
from original_artifact_authentication import OriginalArtifact


class CatalogObserverTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.now = dt.datetime(2026, 9, 11, 20, tzinfo=dt.timezone.utc)
        self.pin = 'sha256:' + 'a' * 64
        self.producer = {'repository': observer.REPOSITORY, 'workflowPath': observer.WORKFLOW,
            'sourceCommit': 'b' * 40, 'runId': 41, 'runAttempt': 2, 'environment': observer.ENVIRONMENT}
        self.coordinates = {'repository': observer.REPOSITORY, 'sourceFamily': 'catalog-origin-observation',
            'sourceCommit': 'b' * 40, 'runId': 41, 'runAttempt': 2, 'jobId': 42, 'jobName': observer.JOB,
            'artifactId': 44, 'artifactName': 'catalog-origin-observer-receipt-41-2',
            'artifactDigest': self.pin, 'artifactSize': 100}
        inventory, _, _ = fixtures.ProjectionBoundaryTest().inventory()
        declaration = next(row['signedProjection'] for row in inventory['subjects'] if row['appId'] == 'external-app')
        contexts = {}
        for number, label in enumerate(observer.LABELS, 1):
            native = copy.deepcopy(declaration)
            native.update(schemaVersion=3, appVersion=str(number), catalogId='catalog-b' if label in {'switch', 'originUpdate'} else 'catalog-a',
                          bundleDigest='sha256:' + str(number) * 64, contractSnapshotDigest=self.pin,
                          baselineRegistryDigest=self.pin, nativeAdmission='accepted', catalogChannel='stable',
                          federationSelection={'generation': 7, **{field: self.pin for field in
                              ('selectionDigest', 'selectedSubjectDigest', 'conflictSetDigest', 'catalogBindingDigest', 'publisherPolicyDigest', 'publisherBindingDigest', 'reviewerPolicyDigest')}})
            native['federationSelection']['catalogRevisionDigest'] = 'sha256:' + 'd' * 64 if label == 'originUpdate' else self.pin
            native['federationSelection']['publisherBindingDigest'] = 'sha256:' + 'e' * 64
            native['federationSelection']['selectedSubjectDigest'] = observer._selected_subject_commitment(native, 'sha256:' + 'd' * 64 if label == 'originUpdate' else self.pin, self.pin)
            contexts[label] = native
        operations, prior = [], None
        names = {'appId': 'app_id', 'appVersion': 'version', 'catalogId': 'catalog_id', 'bundleDigest': 'bundle_digest',
                 'publisherFingerprint': 'publisher_fingerprint', 'signedContentDigest': 'signed_content_digest'}
        for operation, label in (('install', 'initial'), ('update', 'update'), ('switch', 'switch'), ('rollback', 'update')):
            native = contexts[label]
            state = {field: native[field] for field in names}
            state.update(installedTreeDigest=self.pin, originSchemaVersion=2,
                         originDigest=native['bundleDigest'], originFileDigest=native['bundleDigest'])
            state.update(catalogContentDigest=native['catalogDigest'],
                         retainedCatalogRevision={'revisionDigest': self.pin, 'signatureKeyId': native['catalogKeyId']},
                         catalogRevisionDigest=self.pin, catalogSignerFingerprint=self.pin, catalogKeyId=native['catalogKeyId'],
                         reviewDigest=native['reviewDigest'], publisherBindingDigest='sha256:' + 'e' * 64, reviewerPolicyDigest=self.pin,
                         catalogTrustBindingDigest=self.pin)
            target = {target: native[field] for field, target in names.items()}
            target['installed_tree_digest'] = self.pin
            operations.append({'operation': operation, 'target': target, 'before': prior, 'status': 'complete',
                               'observed': state, 'reconciled': False})
            prior = state
        self.value = {'schemaVersion': 2, 'kind': 'catalog-origin-scoped-observation', 'sourceCommit': 'b' * 40,
            'executionId': 'synthetic-catalog', 'planDigest': self.pin, 'selectionOriginal': {'synthetic': 'selection'},
            'projectionOriginal': {'synthetic': 'projection'}, 'projectionInventoryDigest': self.pin,
            **{field: self.pin for field in ('daemonDigest', 'daemonExecutableDigest', 'toolTreeDigest', 'javaTreeDigest', 'fixtureTreeDigest', 'implementationDigest')},
            'contexts': contexts, 'startedAt': '2026-09-10T19:55:00+00:00', 'completedAt': '2026-09-10T19:59:00+00:00',
            'producer': self.producer, 'evidenceClass': 'synthetic-local', 'releaseEligibility': 'blocked',
            'observation': {'schemaVersion': 2, 'kind': 'catalog-origin-local-observation', 'evidenceClass': 'synthetic-local',
                'releaseEligibility': 'blocked', 'dataRollback': 'not-claimed', 'nativeProjections': contexts,
                'cleanup': 'owned-process-stopped-private-state-retained', 'operations': operations,
                'daemonEpochs': [{'pid': pid, 'startTicks': pid * 100, 'bootId': 'a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12,
                                  'executableDigest': self.pin} for pid in (10, 11)],
                'requestCounts': {source + '/' + member: 2 for source in ('primary', 'mirror') for member in ('catalog', 'signature')}}}

        observed = self.value['observation']
        observed['terminalOrigin'] = operations[3]['observed']
        observed['daemonEpochs'] = [{'supervisor': process, 'jvm': {**process, 'pid': process['pid'] + 100}}
                                    for process in observed['daemonEpochs']]
        observed['sourceSwitchDenials'] = [{'case': case, 'httpStatus': 409,
            'errorCode': 'catalog_source_switch_consent_required', 'beforeOrigin': operations[1]['observed'],
            'afterOrigin': operations[1]['observed']} for case in ('missing-consent', 'stale-consent')]
        observed['mirror'] = {}
        for name, available, mode, status in (('exactFallback', False, 'exact', 200),
                ('mismatchedSignature', False, 'mismatch', 409), ('staleCatalog', False, 'stale', 409),
                ('primaryRecovery', True, 'exact', 200)):
            catalog = {'catalogDigest': self.pin, 'signatureKeyId': contexts['update']['catalogKeyId']}
            observed['mirror'][name] = {'beforeRequests': {key: 1 for key in observed['requestCounts']},
                'afterRequests': observed['requestCounts'], 'beforeOrigin': operations[1]['observed'],
                'afterOrigin': operations[1]['observed'], 'beforeCatalog': catalog, 'afterCatalog': catalog,
                'primaryAvailable': available, 'mirrorMode': mode, 'httpStatus': status, 'errorCode': None}
        observed['originalPreauthorizationDigest'] = observer._hash(contexts)
        observed['roleActivationBindings'] = [{'role': 'catalog-origin', 'sequence': number,
            'daemonEpochDigest': observer._hash(observed['daemonEpochs'][0]),
            'authorityScope': 'fresh-role-local-operator-activation', 'binding': {
                'bindingId': label, 'catalogId': contexts[label]['catalogId'], 'status': 'active',
                'signerKeyIds': [contexts[label]['catalogKeyId']], 'signerFingerprints': ['a' * 64],
                'channels': ['stable'], 'localPriority': 1, 'reviewerPolicyDigest': 'a' * 64,
                'publisherPolicyDigest': 'a' * 64, 'selfDigest': 'a' * 64}}
                for number, label in enumerate(('initial', 'switch'), 1)]

        observed['rolePlanDigest'] = self.pin
        observed['totalOperations'] = 350
        observed['rollbackAuthority'] = {'exactEquivalentSource': {'candidate': {'status': 'none', 'catalogId': contexts['update']['catalogId']},
            'equivalentBundleDigest': contexts['update']['bundleDigest'], 'beforeOrigin': operations[1]['observed'], 'afterOrigin': operations[1]['observed']}}
        conflict = {'subjectSetDigestSha256': 'a' * 64}
        observed['sourceSecurity'] = {'untrustedSource': {'httpStatus': 400, 'errorCode': 'invalid_catalog_signature',
            'beforeConflict': conflict, 'afterConflict': conflict, 'beforeOrigin': operations[1]['observed'], 'afterOrigin': operations[1]['observed']},
            'denylistPreference': {'httpStatus': 200, 'errorCode': None, 'conflict': {'hard': True, 'types': ['security_policy_disagreement']},
                'candidate': {'status': 'blocked'}, 'beforeOrigin': operations[1]['observed'], 'afterOrigin': operations[1]['observed']}}
        observed['secondaryRoles'] = []
        for number, role in enumerate(('catalog-origin-update', 'catalog-origin-staged-negative',
                'catalog-origin-publisher-scope-negative', 'catalog-origin-reviewer-scope-negative'), 1):
            child = {'schemaVersion': 2, 'role': role, 'rolePlanDigest': self.pin, 'cleanup': observed['cleanup'],
                     'operations': copy.deepcopy(operations), 'terminalOrigin': operations[3]['observed'],
                     'daemonEpochs': copy.deepcopy(observed['daemonEpochs']),
                     'roleActivationBindings': copy.deepcopy(observed['roleActivationBindings']),
                     'requestCounts': copy.deepcopy(observed['requestCounts'])}
            for epoch in child['daemonEpochs']:
                for process in epoch.values():
                    process['pid'] += number * 1000
            for binding in child['roleActivationBindings']:
                binding.update(role=role, daemonEpochDigest=observer._hash(child['daemonEpochs'][0]))
            if role.endswith('staged-negative'):
                child['operations'] = []
                child['roleActivationBindings'] = child['roleActivationBindings'][:1]
                child['stagedRegistration'] = {'httpStatus': 404, 'errorCode': 'catalog_origin_missing',
                    'beforeInstalledTreeDigest': self.pin, 'afterInstalledTreeDigest': self.pin,
                    'bundleDigest': contexts['initial']['bundleDigest'], 'originPresent': False}
            elif role.endswith('-update'):
                native = contexts['originUpdate']
                state = {**operations[2]['observed'], **{field: native[field] for field in names}}
                state.update(originDigest=native['bundleDigest'], originFileDigest=native['bundleDigest'],
                             catalogRevisionDigest='sha256:' + 'd' * 64, catalogContentDigest=native['catalogDigest'],
                             retainedCatalogRevision={'revisionDigest': 'sha256:' + 'd' * 64, 'signatureKeyId': native['catalogKeyId']})
                child['operations'][3] = {'operation': 'origin-update', 'before': operations[2]['observed'],
                    'target': {**{target: native[field] for field, target in names.items()}, 'installed_tree_digest': self.pin},
                    'status': 'complete', 'observed': state, 'reconciled': False}
                child['terminalOrigin'] = state
                child['eligibleOriginUpdate'] = {'beforeOrigin': operations[2]['observed'], 'afterOrigin': state,
                    'candidate': {'status': 'available', 'catalogId': native['catalogId'],
                                  'bundle': {'sha256': native['bundleDigest'].removeprefix('sha256:')}}}
                child['currentOriginTrustRemoval'] = {'beforeOrigin': state, 'cases': []}
                for index, action in enumerate(('remove', 'revoke')):
                    binding = copy.deepcopy(child['roleActivationBindings'][1]['binding'])
                    binding.update(status='removed' if action == 'remove' else 'revoked', selfDigest=str(index + 5) * 64)
                    child['currentOriginTrustRemoval']['cases'].append({'action': action, 'binding': binding,
                        'beforeOrigin': state, 'afterOrigin': state, 'refreshHttpStatus': 200,
                        'beforeRequests': {'primary/catalog': index, 'primary/signature': index},
                        'afterRequests': {'primary/catalog': index + 1, 'primary/signature': index + 1},
                        'unrelatedCatalog': {'catalogId': contexts['update']['catalogId'],
                            'catalogDigest': contexts['update']['federationSelection']['catalogRevisionDigest'],
                            'signatureKeyId': contexts['update']['catalogKeyId']}})
            else:
                kind = 'publisher' if 'publisher' in role else 'reviewer'
                child['scopeRevocation'] = {'scopeKind': kind, 'retainedTarget': operations[2]['observed'],
                    'binding': {'scopeKind': kind, 'status': 'revoked', 'catalogId': contexts['switch']['catalogId'],
                                'previousDigestSha256': ('e' if kind == 'publisher' else 'a') * 64, 'selfDigestSha256': 'b' * 64},
                    'rollbackHttpStatus': 409, 'rollbackErrorCode': 'catalog_rollback_trust_blocked',
                    'switchHttpStatus': 409, 'switchErrorCode': 'catalog_publisher_scope_rejected' if kind == 'publisher' else 'catalog_reviewer_scope_required',
                    'beforeOrigin': operations[3]['observed'], 'afterOrigin': operations[3]['observed']}
                child['scopeRevocation']['revisionInvalidation'] = None
                if kind == 'publisher':
                    child['scopeRevocation']['revisionInvalidation'] = {
                        'httpStatus': 409, 'errorCode': 'catalog_source_switch_consent_required',
                        'beforeOrigin': operations[3]['observed'], 'afterOrigin': operations[3]['observed'],
                        'beforeCatalogRevisionDigest': self.pin, 'afterCatalogRevisionDigest': 'sha256:' + 'd' * 64,
                        'oldConsentDigest': 'a' * 64, 'newConsentDigest': 'b' * 64,
                        'targetBundleDigest': contexts['originUpdate']['bundleDigest']}
            observed['secondaryRoles'].append(child)

    def test_schema_one_and_missing_secondary_cases_cannot_be_upgraded(self):
        for mutate in (
                lambda value: value.update(schemaVersion=1),
                lambda value: value['observation'].update(schemaVersion=1),
                lambda value: value['observation']['secondaryRoles'].pop(),
                lambda value: value['observation']['secondaryRoles'][0]['eligibleOriginUpdate']['candidate'].update(status='blocked'),
                lambda value: value['observation']['secondaryRoles'][1]['stagedRegistration'].update(originPresent=True),
                lambda value: value['observation']['secondaryRoles'][2]['scopeRevocation'].update(retainedTarget=None),
                lambda value: value['observation']['secondaryRoles'][2]['scopeRevocation']['binding'].update(previousDigestSha256='f' * 64),
                lambda value: value['observation']['secondaryRoles'][3]['scopeRevocation']['binding'].update(status='active'),
                lambda value: value['observation']['sourceSecurity']['denylistPreference']['candidate'].update(status='available'),
                lambda value: value['observation']['sourceSecurity']['untrustedSource'].update(httpStatus=200),
                lambda value: value['observation']['secondaryRoles'][2]['scopeRevocation'].update(revisionInvalidation=None),
                lambda value: value['observation']['secondaryRoles'][2]['scopeRevocation']['revisionInvalidation'].update(afterCatalogRevisionDigest='sha256:' + 'e' * 64),
                lambda value: value['observation']['secondaryRoles'][2]['scopeRevocation']['revisionInvalidation'].update(newConsentDigest='a' * 64),
                lambda value: value['observation']['secondaryRoles'][0].pop('currentOriginTrustRemoval'),
                lambda value: value['observation']['secondaryRoles'][0]['currentOriginTrustRemoval']['cases'][0].update(afterOrigin=None),
                lambda value: value['observation']['secondaryRoles'][0]['currentOriginTrustRemoval']['cases'][1]['binding'].update(status='active'),
                lambda value: value['observation']['secondaryRoles'][0]['currentOriginTrustRemoval']['cases'][1]['afterRequests'].update({'primary/signature': 1}),
                lambda value: value['observation'].update(totalOperations=601)):
            value = copy.deepcopy(self.value)
            mutate(value)
            with self.assertRaises(observer.ObserverFailure):
                observer.validate_observation(value, self.pin, now=self.now)

    def test_run_and_seal_preserve_distinct_authenticated_product_domains(self):
        # Synthetic original-input/daemon/CMS seams exercise the real producer envelope and signer.
        # The separate packaged integration executes native original inputs and every daemon role.
        from types import SimpleNamespace
        key, identity = self.keys()
        policy = {**identity, 'privateRoot': str(self.root), 'maximumSeconds': 900,
            'sourceCommit': self.value['sourceCommit'], 'executionId': self.value['executionId'],
            'selectionOriginal': self.value['selectionOriginal'], 'projectionOriginal': self.value['projectionOriginal'],
            'nativeProjections': self.value['contexts'], 'publicCohortId': 'synthetic-observer-test',
            'packageDigest': 'sha256:' + 'c' * 64, 'daemonExecutableDigest': 'sha256:' + 'd' * 64,
            'projectionInventoryDigest': 'sha256:' + 'e' * 64,
            **{field: self.value[field] for field in ('toolTreeDigest', 'javaTreeDigest', 'fixtureTreeDigest', 'implementationDigest')},
            'javaHome': str(self.root / 'java'), 'toolRoot': str(self.root / 'tool'), 'fixtureRoot': str(self.root / 'fixture')}
        execution = self.root / 'execution.json'
        execution.write_bytes(observer._bytes({'schemaVersion': 1, 'kind': 'catalog-origin-synthetic-execution',
            'sourceCommit': policy['sourceCommit'], 'executionId': policy['executionId'], 'evidenceClass': 'synthetic-local'}))
        def cipher(raw, _root, *, decrypt=False):
            return raw.removeprefix(b'synthetic-cms:') if decrypt else b'synthetic-cms:' + raw
        with patch.object(observer, '_plan', return_value=(policy, self.pin)), \
                patch.object(observer, '_identity', return_value=self.producer), \
                patch.object(observer, '_check_trees'), \
                patch.object(observer, '_authenticated_inputs', return_value=(SimpleNamespace(digest=policy['projectionInventoryDigest']), self.root / 'distribution')), \
                patch('federated_catalog_runtime.execute', return_value=copy.deepcopy(self.value['observation'])), \
                patch.object(selection, '_cms', side_effect=cipher):
            result = observer.run(execution, self.root / 'upload')
        self.assertEqual(policy['packageDigest'], result['daemonDigest'])
        self.assertEqual(policy['daemonExecutableDigest'], result['daemonExecutableDigest'])
        self.assertEqual(policy['projectionInventoryDigest'], result['projectionInventoryDigest'])
        uploaded = {name: (self.root / 'upload' / name).read_bytes() for name in (observer.CIPHERTEXT, observer.PUBLIC)}
        original_archive = selection._archive(uploaded)
        name = 'catalog-origin-observation-41-2'
        metadata = {'id': 43, 'name': name, 'workflow_run': {'id': 41}, 'expired': False,
                    'digest': observer._digest(original_archive)}
        # Environment construction can consult operator credentials before the mocked GitHub call.
        with patch.object(observer, '_plan', return_value=(policy, self.pin)), \
                patch.object(observer, '_identity', return_value=self.producer), \
                patch.object(observer, '_environment', return_value={}), \
                patch.object(observer, '_gh', side_effect=[original_archive, metadata]), \
                patch.dict(os.environ, {'CRYPTAD_FEDERATION_OBSERVER_PRIVATE_KEY': base64.b64encode(key).decode()}):
            observer.seal(execution, self.root / 'upload', self.root / 'sealed', artifact_id=43,
                          artifact_name=name, artifact_digest=metadata['digest'])
        receipt_archive = selection._archive({path.name: path.read_bytes() for path in (self.root / 'sealed').iterdir()})
        completed = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)).isoformat()
        with patch.object(observer, '_plan', return_value=(policy, self.pin)), \
                patch.object(observer, 'authenticate_original', return_value=OriginalArtifact(receipt_archive, self.coordinates, completed)), \
                patch.object(selection, '_cms', side_effect=cipher):
            authority = observer.authenticate_observation(self.coordinates, self.root, self.pin)
        self.assertTrue(authority.matches(result))
        self.assertEqual(observer._digest(observer._bytes(result)), authority.digest)

    def test_exact_transitions_derive_narrow_cases_without_release_claim(self):
        cases = observer.validate_observation(self.value, self.pin, now=self.now)
        self.assertIn('exact-bundle-origin-rollback', cases)
        self.assertNotIn('72-hour-operation', cases)
        self.assertEqual('blocked', self.value['releaseEligibility'])

    def test_missing_operation_or_caller_pass_cannot_replace_observed_bytes(self):
        for change in ('missing', 'before', 'target', 'rollback', 'epoch', 'future', 'long', 'traffic', 'live'):
            value = copy.deepcopy(self.value)
            if change == 'missing':
                value['observation']['operations'].pop()
                value['observation']['verdict'] = 'pass'
            elif change == 'before':
                value['observation']['operations'][1]['before'] = None
            elif change == 'target':
                value['observation']['operations'][2]['target']['bundle_digest'] = self.pin
            elif change == 'rollback':
                value['observation']['operations'][3]['observed']['originFileDigest'] = self.pin
            elif change == 'epoch':
                value['observation']['daemonEpochs'][1] = value['observation']['daemonEpochs'][0]
            elif change == 'future':
                value['completedAt'] = '2026-09-12T00:00:00+00:00'
            elif change == 'long':
                value['startedAt'] = '2026-09-08T19:59:00+00:00'
            elif change == 'traffic':
                value['observation']['requestCounts']['mirror/signature'] = 0
            else:
                value['evidenceClass'] = 'protected-public-live'
            with self.subTest(change=change), self.assertRaises(observer.ObserverFailure):
                observer.validate_observation(value, self.pin, now=self.now)

    def test_cached_mirror_and_wrong_activation_cannot_claim_measured_cases(self):
        for mutate in (
                lambda v: v.pop('terminalOrigin'),
                lambda v: v['operations'][0]['observed'].update(catalogRevisionDigest='sha256:' + 'f' * 64),
                lambda v: v['operations'][0]['observed'].update(catalogContentDigest='sha256:' + 'f' * 64),
                lambda v: v['operations'][0]['observed'].pop('retainedCatalogRevision'),
                lambda v: v['operations'][0]['observed']['retainedCatalogRevision'].update(signatureKeyId='wrong-key'),
                lambda v: v['operations'][0]['observed'].update(catalogSignerFingerprint='sha256:' + 'f' * 64),
                lambda v: v['operations'][0]['observed'].update(reviewDigest='sha256:' + 'f' * 64),
                lambda v: v['operations'][0]['observed'].update(publisherBindingDigest='sha256:' + 'f' * 64),
                lambda v: v['operations'][0]['observed'].update(catalogTrustBindingDigest='sha256:' + 'f' * 64),
                lambda v: v['mirror']['exactFallback'].update(afterRequests=v['mirror']['exactFallback']['beforeRequests']),
                lambda v: v['mirror']['mismatchedSignature'].update(httpStatus=200),
                lambda v: v['mirror']['staleCatalog'].update(afterOrigin=None),
                lambda v: v['mirror']['exactFallback']['beforeCatalog'].update(catalogDigest=self.value['contexts']['update']['catalogDigest']),
                lambda v: v['sourceSwitchDenials'][0].update(httpStatus=200),
                lambda v: v['roleActivationBindings'][0]['binding'].update(signerKeyIds=['wrong']),
                lambda v: v['roleActivationBindings'][0]['binding'].update(channels=['beta']),
                lambda v: v['roleActivationBindings'][0]['binding'].update(publisherPolicyDigest='f' * 64),
                lambda v: v['roleActivationBindings'][0]['binding'].update(reviewerPolicyDigest='f' * 64),
                lambda v: v['roleActivationBindings'][0].update(daemonEpochDigest='sha256:' + 'f' * 64),
                lambda v: v.update(originalPreauthorizationDigest='sha256:' + 'f' * 64)):
            value = copy.deepcopy(self.value)
            mutate(value['observation'])
            with self.assertRaises(observer.ObserverFailure):
                observer.validate_observation(value, self.pin, now=self.now)

    def test_wrong_plan_and_json_capability_are_rejected(self):
        with self.assertRaises(observer.ObserverFailure):
            observer.validate_observation(self.value, 'sha256:' + 'f' * 64, now=self.now)
        with self.assertRaises(observer.ObserverFailure):
            observer.AuthenticatedCatalogObservation(self.value)

    def keys(self):
        # Protected Linux execution pins /usr/bin/openssl. The offline macOS suite
        # uses Homebrew OpenSSL because the system tool lacks Ed25519 support.
        candidates = dict.fromkeys(filter(None, (
            '/usr/bin/openssl', shutil.which('openssl'),
            '/opt/homebrew/opt/openssl@3/bin/openssl',
            '/usr/local/opt/openssl@3/bin/openssl',
        )))
        key = self.root / 'observer.der'
        for executable in candidates:
            if not Path(executable).is_file():
                continue
            result = subprocess.run(
                [executable, 'genpkey', '-algorithm', 'ED25519', '-outform', 'DER', '-out', str(key)],
                capture_output=True, timeout=30)
            if result.returncode == 0:
                break
        else:
            self.fail('observer tests require OpenSSL with Ed25519 support')

        original_run = observer.bounded_run

        def run_with_test_openssl(command, **kwargs):
            self.assertEqual(command[0], '/usr/bin/openssl')
            return original_run([executable, *command[1:]], **kwargs)

        transport = patch.object(observer, 'bounded_run', side_effect=run_with_test_openssl)
        transport.start()
        self.addCleanup(transport.stop)
        public = subprocess.run([executable, 'pkey', '-inform', 'DER', '-in', str(key), '-pubout', '-outform', 'DER'],
                                check=True, capture_output=True).stdout
        return key.read_bytes(), {'observerKeyId': 'synthetic-observer', 'observerFingerprint': observer._digest(public),
                                 'observerPublicKeySpkiBase64': base64.b64encode(public).decode()}

    def receipt(self, public, encrypted):
        return {'schemaVersion': 1, 'kind': 'catalog-origin-observer-receipt', 'producer': self.producer,
                'ciphertextDigest': observer._digest(encrypted), 'publicDigest': observer._digest(public),
                'originalObservation': {'artifactId': 43, 'artifactName': 'catalog-origin-observation-41-2', 'artifactDigest': self.pin},
                'signatureBase64': ''}

    def test_real_ed25519_signs_ciphertext_commitment_without_private_selection_hashes(self):
        key, policy = self.keys()
        receipt = {**self.receipt(b'public', b'ciphertext'), **policy}
        with patch.dict(os.environ, {'CRYPTAD_FEDERATION_OBSERVER_PRIVATE_KEY': base64.b64encode(key).decode()}):
            receipt['signatureBase64'] = observer._sign(receipt, policy, self.root)
        self.assertEqual([], observer.pilot._verify(policy['observerPublicKeySpkiBase64'], observer._signature_subject(receipt), receipt['signatureBase64'], 'observer'))
        self.assertNotIn('planDigest', receipt)
        self.assertNotIn('observationDigest', receipt)
        changed = copy.deepcopy(receipt)
        changed['ciphertextDigest'] = self.pin
        self.assertTrue(observer.pilot._verify(policy['observerPublicKeySpkiBase64'], observer._signature_subject(changed), changed['signatureBase64'], 'observer'))

    def test_authenticated_original_ciphertext_reaches_typed_consumer(self):
        key, identity = self.keys()
        policy = {**identity, 'sourceCommit': self.value['sourceCommit'], 'selectionOriginal': self.value['selectionOriginal'],
                  'projectionOriginal': self.value['projectionOriginal'], 'nativeProjections': self.value['contexts'],
                  'packageDigest': self.value['daemonDigest'], **{field: self.value[field] for field in
                    ('daemonExecutableDigest', 'projectionInventoryDigest', 'executionId', 'toolTreeDigest',
                     'javaTreeDigest', 'fixtureTreeDigest', 'implementationDigest')}}
        public, encrypted = b'{"synthetic":true}', b'private-ciphertext'
        receipt = {**self.receipt(public, encrypted), **identity}
        with patch.dict(os.environ, {'CRYPTAD_FEDERATION_OBSERVER_PRIVATE_KEY': base64.b64encode(key).decode()}):
            receipt['signatureBase64'] = observer._sign(receipt, policy, self.root)
        raw = selection._archive({observer.RECEIPT: observer._bytes(receipt), observer.PUBLIC: public, observer.CIPHERTEXT: encrypted})
        original = OriginalArtifact(raw, self.coordinates, '2026-09-11T20:00:00Z')
        with patch.object(observer, '_plan', return_value=(policy, self.pin)), \
                patch.object(observer, 'authenticate_original', return_value=original), \
                patch.object(selection, '_cms', return_value=observer._bytes(self.value)):
            authority = observer.authenticate_observation(self.coordinates, self.root, self.pin)
        self.assertTrue(authority.matches(self.value))
        altered = authority.observation()
        altered['contexts']['initial']['appVersion'] = '99'
        self.assertFalse(authority.matches(altered))
        self.assertTrue(authority.matches(self.value))

    def test_signed_observer_with_wrong_product_or_inventory_pin_is_rejected(self):
        key, identity = self.keys()
        policy = {**identity, 'sourceCommit': self.value['sourceCommit'],
            'selectionOriginal': self.value['selectionOriginal'], 'projectionOriginal': self.value['projectionOriginal'],
            'nativeProjections': self.value['contexts'], 'packageDigest': self.value['daemonDigest'],
            **{field: self.value[field] for field in ('daemonExecutableDigest', 'projectionInventoryDigest', 'executionId',
                'toolTreeDigest', 'javaTreeDigest', 'fixtureTreeDigest', 'implementationDigest')}}
        for field in ('daemonDigest', 'daemonExecutableDigest', 'projectionInventoryDigest',
                      'toolTreeDigest', 'javaTreeDigest', 'fixtureTreeDigest', 'implementationDigest'):
            value = copy.deepcopy(self.value)
            value[field] = 'sha256:' + 'f' * 64
            encrypted, public = observer._bytes(value), b'{"synthetic":true}'
            receipt = {**self.receipt(public, encrypted), **identity}
            with patch.dict(os.environ, {'CRYPTAD_FEDERATION_OBSERVER_PRIVATE_KEY': base64.b64encode(key).decode()}):
                receipt['signatureBase64'] = observer._sign(receipt, policy, self.root)
            raw = selection._archive({observer.RECEIPT: observer._bytes(receipt), observer.PUBLIC: public, observer.CIPHERTEXT: encrypted})
            with self.subTest(field=field), patch.object(observer, '_plan', return_value=(policy, self.pin)), \
                    patch.object(observer, 'authenticate_original', return_value=OriginalArtifact(raw, self.coordinates, '2026-09-11T20:00:00Z')), \
                    patch.object(selection, '_cms', return_value=encrypted), self.assertRaises(observer.ObserverFailure):
                observer.authenticate_observation(self.coordinates, self.root, self.pin)

    def test_wrong_original_attempt_rejected_before_decryption(self):
        key, policy = self.keys()
        public, encrypted = b'public', b'ciphertext'
        receipt = {**self.receipt(public, encrypted), **policy}
        receipt['producer'] = {**self.producer, 'runAttempt': 1}
        with patch.dict(os.environ, {'CRYPTAD_FEDERATION_OBSERVER_PRIVATE_KEY': base64.b64encode(key).decode()}):
            receipt['signatureBase64'] = observer._sign(receipt, policy, self.root)
        raw = selection._archive({observer.RECEIPT: observer._bytes(receipt), observer.PUBLIC: public, observer.CIPHERTEXT: encrypted})
        with patch.object(observer, '_plan', return_value=(policy, self.pin)), \
                patch.object(observer, 'authenticate_original', return_value=OriginalArtifact(raw, self.coordinates)), \
                patch.object(selection, '_cms') as decrypt:
            with self.assertRaises(observer.ObserverFailure):
                observer.authenticate_observation(self.coordinates, self.root, self.pin)
            decrypt.assert_not_called()

    def test_original_authentication_failure_never_launches_daemon(self):
        policy = {'sourceCommit': 'b' * 40, 'executionId': 'synthetic-catalog', 'privateRoot': str(self.root)}
        execution = self.root / 'execution.json'
        execution.write_bytes(observer._bytes({'schemaVersion': 1, 'kind': 'catalog-origin-synthetic-execution',
            'sourceCommit': 'b' * 40, 'executionId': 'synthetic-catalog', 'evidenceClass': 'synthetic-local'}))
        with patch.object(observer, '_identity', return_value=self.producer), patch.object(observer, '_plan', return_value=(policy, self.pin)), \
                patch.object(observer, '_check_trees'), patch.object(observer, '_authenticated_inputs', side_effect=observer.ObserverFailure('original-rejected')), \
                patch('federated_catalog_runtime.execute') as launch:
            with self.assertRaises(observer.ObserverFailure):
                observer.run(execution, self.root / 'upload')
            launch.assert_not_called()
        self.assertFalse((self.root / 'upload').exists())


if __name__ == '__main__':
    unittest.main()

class CatalogPhaseAdapterTest(unittest.TestCase):
    def setUp(self):
        CatalogObserverTest.setUp(self)

    def payloads(self):
        plan = {field: self.pin for field in observer.PLAN_FIELDS}
        plan.update(schemaVersion=2, kind='protected-synthetic-catalog-origin-plan', maximumSeconds=900,
            sourceCommit=self.value['sourceCommit'], executionId=self.value['executionId'],
            selectionOriginal=self.value['selectionOriginal'], projectionOriginal=self.value['projectionOriginal'],
            nativeProjections=self.value['contexts'], packageDigest=self.value['daemonDigest'],
            contexts={label: {'id': label.lower(), 'digest': self.pin, 'generation': 7} for label in observer.LABELS})
        raw = observer._bytes(plan)
        self.value['planDigest'] = observer._digest(raw)
        return {'plan.json': raw, 'observation.json': observer._bytes(self.value)}

    def test_scoped_adapter_authentication_keeps_parent_rows_blocked(self):
        from cryptad_certification import phase_12_runtime_adapters as adapters
        payloads = self.payloads()
        authority = observer.AuthenticatedCatalogObservation(self.value, observer.AUTHORITY)
        result = adapters.verify_authenticated('catalog-origin-observation', payloads, self.now.isoformat(), self.root, authority)
        self.assertEqual('authenticated', result['dimensions']['originalProvenance'])
        self.assertEqual('partial', result['dimensions']['runtimeExecution'])
        self.assertIn('synthetic-local-cannot-close-parent-requirement', result['blockers'])
        self.assertEqual('synthetic-local', result['evidenceClass'])
        self.assertEqual(self.value['completedAt'], result['observedAt'])
        self.assertEqual(self.producer['runAttempt'], result['producerCoordinates']['runAttempt'])
        self.assertIn('exact-bundle-origin-rollback', result['coverage']['observed'])
        with self.assertRaises(ValueError):
            adapters.verify_authenticated('catalog-origin-observation',
                {**payloads, 'observation.json': payloads['observation.json'] + b'\n'},
                self.now.isoformat(), self.root, authority)

    def test_product_cohort_epoch_producer_cutoff_and_raw_plan_substitution_fail(self):
        from cryptad_certification import phase_12_runtime_adapters as adapters
        payloads = self.payloads()
        for mutate in (
                lambda v: v.update(daemonDigest='sha256:' + 'f' * 64),
                lambda v: v['producer'].update(runAttempt=0),
                lambda v: v['producer'].update(workflowPath='.github/workflows/other.yml'),
                lambda v: v['contexts'].pop('switch'),
                lambda v: v['observation']['daemonEpochs'].append(v['observation']['daemonEpochs'][0]),
                lambda v: v.update(completedAt='2026-09-12T00:00:00+00:00')):
            value = copy.deepcopy(self.value)
            mutate(value)
            with self.assertRaises(ValueError):
                adapters.verify('catalog-origin-observation', {**payloads, 'observation.json': observer._bytes(value)}, self.now.isoformat(), self.root)
        with self.assertRaises(ValueError):
            adapters.verify('catalog-origin-observation', {**payloads, 'plan.json': payloads['plan.json'] + b'\n'}, self.now.isoformat(), self.root)
        with self.assertRaises(ValueError):
            adapters.verify_authenticated('catalog-origin-observation', payloads, self.now.isoformat(), self.root, {'authenticated': True})
