"""Original protected observer for the bounded synthetic catalog-origin driver.

The root-owned plan authorizes a finite, disposable loopback experiment. Original selection,
projection, package and tool bytes authenticate before Java or node execution. The observer signs
only the immutable ciphertext uploaded by this original run. Its prospective receipt never
satisfies the legacy broad federation observation or claims public-network/72-hour execution.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
INTEROP = ROOT / 'tools/interop'
CERTIFICATION = ROOT / 'tools/release-certification'
sys.path.insert(0, str(INTEROP))
sys.path.insert(0, str(CERTIFICATION))

import app_subject_projection as projection
import federation_selection as selection
from bounded_process import run as bounded_run
from original_artifact_authentication import authenticate_original, validate_coordinates, _gh, _environment, REPOSITORY
from cryptad_certification.engines import stable_1_0_third_party_pilot as pilot

WORKFLOW = '.github/workflows/stable-1.0-federated-catalog-runtime.yml'
ENVIRONMENT = 'stable-1-0-federated-catalog-runtime-observation'
JOB = 'Observe authenticated synthetic catalog-origin cohort'
POLICY = Path('/etc/cryptad-certification/catalog-origin-runtime.json')
CIPHERTEXT = 'catalog-origin-observation.cms'
RECEIPT = 'catalog-origin-observer-receipt.json'
PUBLIC = 'catalog-origin-synthetic-summary.json'
DOMAIN = b'cryptad-catalog-origin-observer-v1\x00'
AUTHORITY = object()
LABELS = {'initial': 'A1', 'update': 'A2', 'switch': 'B3', 'originUpdate': 'B4'}
ORIGIN_SELECTION_FIELDS = {'catalogContentDigest', 'catalogRevisionDigest', 'catalogSignerFingerprint', 'catalogKeyId', 'reviewDigest',
                           'publisherBindingDigest', 'reviewerPolicyDigest', 'catalogTrustBindingDigest'}
PLAN_FIELDS = {'schemaVersion', 'kind', 'sourceCommit', 'executionId', 'publicCohortId', 'privateRoot',
               'selectionOriginal', 'projectionOriginal', 'projectionCohortDigest', 'contexts',
               'nativeProjections', 'toolRoot', 'toolTreeDigest', 'toolOriginal', 'toolMember',
               'javaHome', 'javaTreeDigest', 'fixtureRoot', 'fixtureTreeDigest', 'packageOriginal',
               'packageMember', 'packageDigest', 'daemonExecutableDigest', 'projectionInventoryDigest', 'packageSize', 'distributionTreeDigest', 'maximumSeconds',
               'observerKeyId', 'observerFingerprint', 'observerPublicKeySpkiBase64', 'implementationDigest'}
ENVELOPE_FIELDS = {'schemaVersion', 'kind', 'sourceCommit', 'executionId', 'planDigest',
                   'selectionOriginal', 'projectionOriginal', 'projectionInventoryDigest',
                   'daemonDigest', 'daemonExecutableDigest', 'toolTreeDigest', 'javaTreeDigest', 'fixtureTreeDigest',
                   'implementationDigest', 'contexts', 'startedAt', 'completedAt', 'producer',
                   'observation', 'evidenceClass', 'releaseEligibility'}


class ObserverFailure(ValueError):
    """A fixed, path-free protected observer failure."""


def _fail():
    raise ObserverFailure('catalog-observer-admission-rejected')


def _json(raw):
    return selection._json(raw)


def _bytes(value):
    return selection._bytes(value)


def _digest(raw):
    return selection.digest(raw)


def _hash(value):
    return _digest(_bytes(value))


def _write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def implementation_digest():
    """Bind every imported repository Python module, not just the PATH launcher."""
    rows = []
    for root in (INTEROP, CERTIFICATION / 'protected', CERTIFICATION / 'cryptad_certification'):
        for path in sorted(root.rglob('*.py')):
            if path.is_symlink():
                _fail()
            rows.append([path.relative_to(ROOT).as_posix(), _digest(path.read_bytes())])
    return _hash(rows)


def _identity():
    if (os.environ.get('GITHUB_REPOSITORY') != REPOSITORY
            or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or os.environ.get('GITHUB_ACTOR') != 'leumor'
            or os.environ.get('GITHUB_TRIGGERING_ACTOR') != 'leumor'
            or os.environ.get('GITHUB_REF') != 'refs/heads/develop'
            or os.environ.get('GITHUB_WORKFLOW_REF') != f'{REPOSITORY}/{WORKFLOW}@refs/heads/develop'):
        _fail()
    commit = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        _fail()
    try:
        run_id, attempt = int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])
    except (KeyError, ValueError):
        _fail()
    if run_id < 1 or attempt < 1:
        _fail()
    return {'repository': REPOSITORY, 'workflowPath': WORKFLOW, 'sourceCommit': commit,
            'runId': run_id, 'runAttempt': attempt, 'environment': ENVIRONMENT}


def _private_directory(path):
    path = Path(path)
    if (not path.is_dir() or path.stat().st_mode & 0o077
            or any(parent.is_symlink() for parent in (path, *path.parents))):
        _fail()
    return path


def _plan():
    raw = selection._regular(POLICY, protected=True, private=True)
    value = _json(raw)
    if (not isinstance(value, dict) or set(value) != PLAN_FIELDS
            or value['schemaVersion'] != 2 or type(value['schemaVersion']) is not int
            or value['kind'] != 'protected-synthetic-catalog-origin-plan'
            or set(value['contexts']) != set(LABELS) or set(value['nativeProjections']) != set(LABELS)
            or not re.fullmatch(r'synthetic-[a-z0-9][a-z0-9-]{1,62}', value['publicCohortId'])
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', value['executionId'])
            or type(value['maximumSeconds']) is not int or not 30 <= value['maximumSeconds'] <= 1800
            or type(value['packageSize']) is not int or not 1 <= value['packageSize'] <= selection.MAX_BYTES):
        _fail()
    for field in ('selectionOriginal', 'projectionOriginal', 'toolOriginal', 'packageOriginal'):
        validate_coordinates(value[field])
    if (value['selectionOriginal']['sourceFamily'] != 'federation-selection'
            or value['projectionOriginal']['sourceFamily'] != 'app-subject-projection'
            or value['toolOriginal']['sourceFamily'] != 'projection-tools'
            or value['packageOriginal']['sourceFamily'] not in {'first-party-release', 'stable-rc-product', 'stable-maintenance-freeze'}):
        _fail()
    for field in PLAN_FIELDS:
        if field.endswith('Digest') or field == 'observerFingerprint':
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', str(value[field])):
                _fail()
    if _digest(base64.b64decode(value['observerPublicKeySpkiBase64'], validate=True)) != value['observerFingerprint']:
        _fail()
    for label, context in value['contexts'].items():
        if (set(context) != {'id', 'digest', 'generation'} or type(context['generation']) is not int
                or not 1 <= context['generation'] <= 2**53-1):
            _fail()
        native = projection.validate_declaration(value['nativeProjections'][label])
        if (native['schemaVersion'] != 3 or native['federationSelection']['selectionDigest'] != context['digest']
                or native['federationSelection']['generation'] != context['generation']):
            _fail()
    _private_directory(value['privateRoot'])
    return value, _digest(raw)


def _execution(path, policy, producer):
    value = _json(selection._regular(path))
    if value != {'schemaVersion': 1, 'kind': 'catalog-origin-synthetic-execution',
                 'executionId': policy['executionId'], 'sourceCommit': policy['sourceCommit'],
                 'evidenceClass': 'synthetic-local'} or policy['sourceCommit'] != producer['sourceCommit']:
        raise ObserverFailure('catalog-observer-legacy-or-unselected-execution')


def _check_trees(policy):
    for root, field in (('toolRoot', 'toolTreeDigest'), ('javaHome', 'javaTreeDigest'), ('fixtureRoot', 'fixtureTreeDigest')):
        if projection.tree_digest(Path(policy[root])) != policy[field]:
            _fail()
    if implementation_digest() != policy['implementationDigest']:
        _fail()
    # Observer keys cannot double as node, app publisher, catalog signer or reviewer keys.
    for name in ('publisher', 'catalog', 'reviewer'):
        raw = selection._regular(Path(policy['fixtureRoot']) / (name + '-keys.properties'))
        for encoded in re.findall(rb'(?m)^.*\.public\.key\.base64=([^\r\n]+)$', raw):
            if _digest(base64.b64decode(encoded, validate=True)) == policy['observerFingerprint']:
                _fail()


def _authenticated_inputs(policy, scratch):
    """Authenticate all original inputs and exact private contexts before executable extraction."""
    original_selection = selection.authenticate_selection(policy['selectionOriginal'], scratch)
    inventory = projection.authenticate_inventory(policy['projectionOriginal'], scratch,
                                                  expected_cohort_digest=policy['projectionCohortDigest'], expected_inventory_version=4)
    if not isinstance(original_selection, selection.AuthenticatedSelection) or not isinstance(inventory, projection.AuthenticatedProjection):
        _fail()
    if inventory.digest != policy['projectionInventoryDigest']:
        _fail()
    value = inventory.inventory()
    projection.validate_federation_inventory(value)
    initial = policy['nativeProjections']['initial']
    selected = [row for row in value.get('selectedFederation', []) if row['appId'] == initial['appId']]
    if (len(selected) != 1 or selected[0]['nativeProjection'] != initial
            or selected[0]['original'] != policy['selectionOriginal']):
        _fail()
    original_selection.materialize(scratch / 'selection')
    for label, context in policy['contexts'].items():
        actual = original_selection.context(context['id'])
        native = policy['nativeProjections'][label]
        if (actual['digest'] != context['digest'] or actual['generation'] != context['generation']
                or actual['appId'] != native['appId']):
            _fail()
        expected_context = selection._regular(scratch / 'selection' / actual['member'])
        fixture_context = selection._regular(Path(policy['fixtureRoot']) / 'selections' / LABELS[label] / 'selection.json')
        if expected_context != fixture_context:
            _fail()
    projection.authenticate_tool_tree(policy, Path(policy['toolRoot']), scratch)
    package_origin = authenticate_original(policy['packageOriginal'], scratch)
    package = projection.selected_members(package_origin, {'bundle': policy['packageMember']})['bundle']
    if _digest(package) != policy['packageDigest'] or len(package) != policy['packageSize']:
        _fail()
    package_path = scratch / 'product.tar.gz'
    _write(package_path, package)
    import cross_version_runtime as runtime
    distribution = runtime.extract_package(package_path, scratch / 'distribution', policy['packageDigest'], policy['packageSize'])
    if (projection.tree_digest(distribution) != policy['distributionTreeDigest']
            or runtime.digest_file(distribution / 'lib/cryptad.jar') != policy['daemonExecutableDigest']):
        _fail()
    _check_trees(policy)
    return inventory, Path(distribution)


def _selected_subject_commitment(native, revision, signer_fingerprint):
    """Rebuild the existing native v3 identity preimage, keeping raw and revision digests distinct."""
    identity = {field: native[field] for field in ('catalogId', 'appId', 'catalogDigest',
        'catalogSignatureDigest', 'bundleDigest', 'bundleSize', 'signedContentDigest',
        'publisherFingerprint', 'reviewDigest', 'appVersion')}
    identity.update(channel=native['catalogChannel'], generation=native['federationSelection']['generation'],
                    catalogRevisionDigest=revision, catalogSignerFingerprint=signer_fingerprint)
    identity.update({field: native['federationSelection'][field] for field in
                     ('catalogBindingDigest', 'publisherPolicyDigest', 'publisherBindingDigest', 'reviewerPolicyDigest')})
    return _hash(identity)


def _origin_selection(actual, native):
    retained = actual.get('retainedCatalogRevision')
    if (not isinstance(retained, dict) or set(retained) != {'revisionDigest', 'signatureKeyId'}
            or retained['revisionDigest'] != actual['catalogRevisionDigest']
            or retained['signatureKeyId'] != native['catalogKeyId']
            or actual['catalogContentDigest'] != native['catalogDigest']
            or actual['catalogRevisionDigest'] != native['federationSelection']['catalogRevisionDigest']
            or actual['catalogKeyId'] != native['catalogKeyId'] or actual['reviewDigest'] != native['reviewDigest']
            or any(actual[field] != native['federationSelection'][field]
                   for field in ('publisherBindingDigest', 'reviewerPolicyDigest'))
            or any(not re.fullmatch(r'sha256:[0-9a-f]{64}', str(actual[field]))
                   for field in ORIGIN_SELECTION_FIELDS - {'catalogKeyId'})
            or _selected_subject_commitment(native, actual['catalogRevisionDigest'], actual['catalogSignerFingerprint'])
               != native['federationSelection']['selectedSubjectDigest']):
        _fail()


def _origin_activation(actual, activations):
    if not any(row.get('binding', {}).get('catalogId') == actual['catalogId']
               and 'sha256:' + str(row['binding'].get('selfDigest')) == actual['catalogTrustBindingDigest']
               and row['binding'].get('signerKeyIds') == [actual['catalogKeyId']]
               and row['binding'].get('signerFingerprints') == [actual['catalogSignerFingerprint'].removeprefix('sha256:')]
               for row in activations):
        _fail()


def _role_operations(rows, contexts, labels):
    if not isinstance(rows, list) or [row.get('operation') for row in rows] != [name for name, _ in labels]:
        _fail()
    prior = None
    names = {'appId': 'app_id', 'appVersion': 'version', 'catalogId': 'catalog_id',
             'bundleDigest': 'bundle_digest', 'publisherFingerprint': 'publisher_fingerprint',
             'signedContentDigest': 'signed_content_digest', 'installedTreeDigest': 'installed_tree_digest'}
    for row, (_, label) in zip(rows, labels):
        if (set(row) != {'operation', 'target', 'before', 'status', 'observed', 'reconciled'}
                or row['status'] != 'complete' or type(row['reconciled']) is not bool or row['before'] != prior):
            _fail()
        actual, native = row['observed'], contexts[label]
        projection.validate_declaration(native)
        if (set(actual) != set(names) | {'originSchemaVersion', 'originDigest', 'originFileDigest', 'retainedCatalogRevision'} | ORIGIN_SELECTION_FIELDS
                or actual['originSchemaVersion'] != 2 or set(row['target']) != set(names.values())
                or any(actual[field] != row['target'][target] for field, target in names.items())
                or any(actual[field] != native[field] for field in names if field != 'installedTreeDigest')
                or any(not re.fullmatch(r'sha256:[0-9a-f]{64}', str(actual[field]))
                       for field in ('originDigest', 'originFileDigest', 'installedTreeDigest'))):
            _fail()
        _origin_selection(actual, native)
        prior = actual
    return prior



def _current_origin_removal(child, contexts, terminal):
    removal = child.get('currentOriginTrustRemoval')
    if (not isinstance(removal, dict) or set(removal) != {'beforeOrigin', 'cases'}
            or removal['beforeOrigin'] != terminal or not isinstance(removal['cases'], list)
            or len(removal['cases']) != 2):
        _fail()
    target, unrelated = contexts['originUpdate'], contexts['update']
    previous = terminal['catalogTrustBindingDigest']
    for row, action, status in zip(removal['cases'], ('remove', 'revoke'), ('removed', 'revoked')):
        fields = {'action', 'binding', 'beforeOrigin', 'afterOrigin', 'refreshHttpStatus',
                  'beforeRequests', 'afterRequests', 'unrelatedCatalog'}
        if (not isinstance(row, dict) or set(row) != fields or row['action'] != action
                or row['beforeOrigin'] != terminal or row['afterOrigin'] != terminal
                or row['refreshHttpStatus'] != 200):
            _fail()
        binding, catalog = row['binding'], row['unrelatedCatalog']
        if (binding.get('catalogId') != target['catalogId'] or binding.get('status') != status
                or binding.get('signerKeyIds') != [target['catalogKeyId']]
                or binding.get('signerFingerprints') != [terminal['catalogSignerFingerprint'].removeprefix('sha256:')]
                or any('sha256:' + str(binding.get(field)) != target['federationSelection'][field]
                       for field in ('publisherPolicyDigest', 'reviewerPolicyDigest'))
                or not re.fullmatch(r'[0-9a-f]{64}', str(binding.get('selfDigest')))
                or 'sha256:' + binding['selfDigest'] == previous
                or set(catalog) != {'catalogId', 'catalogDigest', 'signatureKeyId'}
                or catalog['catalogId'] != unrelated['catalogId']
                or catalog['signatureKeyId'] != unrelated['catalogKeyId']
                or 'sha256:' + str(catalog['catalogDigest']).removeprefix('sha256:')
                   != unrelated['federationSelection']['catalogRevisionDigest']):
            _fail()
        previous = 'sha256:' + binding['selfDigest']
        for counts in (row['beforeRequests'], row['afterRequests']):
            if not isinstance(counts, dict) or any(type(value) is not int or value < 0 for value in counts.values()):
                _fail()
        for member in ('catalog', 'signature'):
            key = 'primary/' + member
            if row['afterRequests'].get(key, 0) <= row['beforeRequests'].get(key, 0):
                _fail()


def _secondary_roles(observed, contexts):
    roles = ('catalog-origin-update', 'catalog-origin-staged-negative',
             'catalog-origin-publisher-scope-negative', 'catalog-origin-reviewer-scope-negative')
    children = observed.get('secondaryRoles')
    plan = observed.get('rolePlanDigest')
    if (not re.fullmatch(r'sha256:[0-9a-f]{64}', str(plan))
            or type(observed.get('totalOperations')) is not int or not 1 <= observed['totalOperations'] <= 600
            or not isinstance(children, list) or [row.get('role') for row in children] != list(roles)):
        _fail()
    process_ids = {(process['pid'], process['startTicks'], process['bootId'])
                   for epoch in observed['daemonEpochs'] for process in epoch.values()}
    for child in children:
        role = child['role']
        if (type(child.get('schemaVersion')) is not int or child['schemaVersion'] != 2
                or child.get('rolePlanDigest') != plan
                or child.get('cleanup') != 'owned-process-stopped-private-state-retained'):
            _fail()
        epochs = child.get('daemonEpochs')
        minimum = 1 if role.endswith('staged-negative') else 2
        if not isinstance(epochs, list) or not minimum <= len(epochs) <= 16:
            _fail()
        for epoch in epochs:
            if set(epoch) != {'supervisor', 'jvm'}:
                _fail()
            for process in epoch.values():
                if (set(process) != {'pid', 'startTicks', 'bootId', 'executableDigest'}
                        or type(process['pid']) is not int or process['pid'] < 1
                        or type(process['startTicks']) is not int or process['startTicks'] < 1
                        or not re.fullmatch(r'[0-9a-f-]{36}', str(process['bootId']))
                        or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(process['executableDigest']))):
                    _fail()
                identity = (process['pid'], process['startTicks'], process['bootId'])
                if identity in process_ids:
                    _fail()
                process_ids.add(identity)
        labels = [('install', 'initial'), ('update', 'update'), ('switch', 'switch')]
        if role.endswith('staged-negative'):
            if child.get('operations') != []:
                _fail()
            row = child.get('stagedRegistration', {})
            if (set(row) != {'httpStatus', 'errorCode', 'beforeInstalledTreeDigest', 'afterInstalledTreeDigest', 'bundleDigest', 'originPresent'}
                    or row['httpStatus'] != 404 or row['originPresent'] is not False
                    or row['bundleDigest'] != contexts['initial']['bundleDigest']
                    or row['beforeInstalledTreeDigest'] != row['afterInstalledTreeDigest']
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(row['beforeInstalledTreeDigest']))):
                _fail()
        else:
            labels.append(('origin-update', 'originUpdate') if role.endswith('-update') else ('rollback', 'update'))
            terminal = _role_operations(child.get('operations'), contexts, labels)
            if child.get('terminalOrigin') != terminal:
                _fail()
            if role.endswith('-update'):
                row = child.get('eligibleOriginUpdate', {})
                target = contexts['originUpdate']
                if (row.get('beforeOrigin') != child['operations'][2]['observed'] or row.get('afterOrigin') != terminal
                        or row.get('candidate', {}).get('status') != 'available'
                        or row['candidate'].get('catalogId') != target['catalogId']
                        or row['candidate'].get('bundle', {}).get('sha256') != target['bundleDigest'].removeprefix('sha256:')
                        or target['catalogId'] != contexts['switch']['catalogId']
                        or target['publisherFingerprint'] != contexts['switch']['publisherFingerprint']
                        or target['bundleDigest'] in {contexts[key]['bundleDigest'] for key in ('initial', 'update', 'switch')}):
                    _fail()
                _current_origin_removal(child, contexts, terminal)
            else:
                row = child.get('scopeRevocation', {})
                kind = 'publisher' if 'publisher-scope' in role else 'reviewer'
                binding = row.get('binding', {})
                if (row.get('scopeKind') != kind or row.get('beforeOrigin') != terminal or row.get('afterOrigin') != terminal
                        or row.get('retainedTarget') != child['operations'][2]['observed']
                        or row.get('rollbackHttpStatus') != 409 or row.get('rollbackErrorCode') != 'catalog_rollback_trust_blocked'
                        or row.get('switchHttpStatus') != 409
                        or row.get('switchErrorCode') not in ({'catalog_publisher_scope_rejected'} if kind == 'publisher'
                                                            else {'catalog_reviewer_scope_required', 'app_review_untrusted'})
                        or binding.get('status') != 'revoked' or binding.get('scopeKind') != kind
                        or binding.get('catalogId') != contexts['switch']['catalogId']
                        or kind == 'publisher' and 'sha256:' + str(binding.get('previousDigestSha256'))
                           != contexts['switch']['federationSelection']['publisherBindingDigest']
                        or binding.get('previousDigestSha256') == binding.get('selfDigestSha256')
                        or any(not re.fullmatch(r'[0-9a-f]{64}', str(binding.get(field)))
                               for field in ('previousDigestSha256', 'selfDigestSha256'))):
                    _fail()
                revision = row.get('revisionInvalidation')
                if kind == 'publisher':
                    fields = {'httpStatus', 'errorCode', 'beforeOrigin', 'afterOrigin',
                              'beforeCatalogRevisionDigest', 'afterCatalogRevisionDigest',
                              'oldConsentDigest', 'newConsentDigest', 'targetBundleDigest'}
                    if (not isinstance(revision, dict) or set(revision) != fields
                            or revision['httpStatus'] != 409 or revision['errorCode'] != 'catalog_source_switch_consent_required'
                            or revision['beforeOrigin'] != terminal or revision['afterOrigin'] != terminal
                            or revision['targetBundleDigest'] != contexts['originUpdate']['bundleDigest']
                            or revision['beforeCatalogRevisionDigest'] == revision['afterCatalogRevisionDigest']
                            or revision['oldConsentDigest'] == revision['newConsentDigest']
                            or any(not re.fullmatch(r'[0-9a-f]{64}', str(revision[field]))
                                   for field in ('oldConsentDigest', 'newConsentDigest'))):
                        _fail()
                    signer = row['retainedTarget']['catalogSignerFingerprint']
                    for field, label in (('beforeCatalogRevisionDigest', 'switch'), ('afterCatalogRevisionDigest', 'originUpdate')):
                        if (not re.fullmatch(r'sha256:[0-9a-f]{64}', str(revision[field]))
                                or _selected_subject_commitment(contexts[label], revision[field], signer)
                                != contexts[label]['federationSelection']['selectedSubjectDigest']):
                            _fail()
                elif revision is not None:
                    _fail()
        expected_catalogs = {contexts[label]['catalogId'] for _, label in labels}
        if role.endswith('staged-negative'):
            expected_catalogs = {contexts['initial']['catalogId']}
        bindings = child.get('roleActivationBindings')
        if not isinstance(bindings, list) or not 1 <= len(bindings) <= 16:
            _fail()
        actual_catalogs = set()
        for number, row in enumerate(bindings, 1):
            binding = row.get('binding', {})
            if (row.get('role') != role or type(row.get('sequence')) is not int or row['sequence'] != number
                    or row.get('authorityScope') != 'fresh-role-local-operator-activation'
                    or row.get('daemonEpochDigest') not in {_hash(epoch) for epoch in epochs}
                    or binding.get('status') != 'active' or binding.get('channels') != ['stable']):
                _fail()
            actual_catalogs.add(binding.get('catalogId'))
            native = next((native for native in contexts.values() if native['catalogId'] == binding.get('catalogId')), None)
            if (native is None or binding.get('signerKeyIds') != [native['catalogKeyId']]
                    or any('sha256:' + str(binding.get(field)) != native['federationSelection'][field]
                           for field in ('publisherPolicyDigest', 'reviewerPolicyDigest'))):
                _fail()
        if actual_catalogs != expected_catalogs:
            _fail()
        for operation in child['operations']:
            _origin_activation(operation['observed'], bindings)
    return {'eligible-origin-pinned-update', 'staged-registration-origin-remains-absent',
            'local-publisher-scope-revocation-denied', 'local-reviewer-scope-revocation-denied',
            'catalog-revision-invalidates-source-switch-consent',
            'current-origin-trust-removal-preserves-app-and-unrelated-catalog'}


def _source_security(observed, contexts):
    expected = observed['operations'][1]['observed']
    equivalent = observed.get('rollbackAuthority', {}).get('exactEquivalentSource', {})
    if (equivalent.get('equivalentBundleDigest') != contexts['update']['bundleDigest']
            or equivalent.get('beforeOrigin') != expected or equivalent.get('afterOrigin') != expected
            or equivalent.get('candidate', {}).get('status') != 'none'
            or equivalent['candidate'].get('catalogId') != contexts['update']['catalogId']):
        _fail()
    source = observed.get('sourceSecurity', {})
    if set(source) != {'untrustedSource', 'denylistPreference'}:
        _fail()
    untrusted, denied = source['untrustedSource'], source['denylistPreference']
    if (untrusted.get('httpStatus') != 400 or untrusted.get('errorCode') != 'invalid_catalog_signature'
            or untrusted.get('beforeOrigin') != expected or untrusted.get('afterOrigin') != expected
            or not re.fullmatch(r'[0-9a-f]{64}', str(untrusted.get('beforeConflict', {}).get('subjectSetDigestSha256')))
            or untrusted['beforeConflict']['subjectSetDigestSha256'] != untrusted.get('afterConflict', {}).get('subjectSetDigestSha256')
            or denied.get('httpStatus') not in {200, 201, 400, 409}
            or denied.get('conflict', {}).get('hard') is not True
            or 'security_policy_disagreement' not in denied['conflict'].get('types', [])
            or denied.get('candidate', {}).get('status') != 'blocked'
            or denied.get('beforeOrigin') != expected or denied.get('afterOrigin') != expected):
        _fail()
    return {'exact-equivalent-source-origin-preserved', 'untrusted-source-isolated', 'denylist-preference-no-mutation'}


def validate_observation(value, expected_plan_digest, *, now):
    """Recompute narrow measured cases; JSON consistency alone is never original authority."""
    if (not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS or type(value['schemaVersion']) is not int
            or value['schemaVersion'] != 2 or value['kind'] != 'catalog-origin-scoped-observation'
            or value['evidenceClass'] != 'synthetic-local' or value['releaseEligibility'] != 'blocked'
            or value['planDigest'] != expected_plan_digest or set(value['contexts']) != set(LABELS)):
        _fail()
    for field in ENVELOPE_FIELDS:
        if field.endswith('Digest') and not re.fullmatch(r'sha256:[0-9a-f]{64}', str(value[field])):
            _fail()
    began = dt.datetime.fromisoformat(value['startedAt'])
    ended = dt.datetime.fromisoformat(value['completedAt'])
    if (began.tzinfo is None or ended.tzinfo is None or now.tzinfo is None or ended < began
            or ended > now or (ended - began).total_seconds() > 1800):
        _fail()
    observed = value['observation']
    if (type(observed.get('schemaVersion')) is not int or observed['schemaVersion'] != 2
            or observed.get('kind') != 'catalog-origin-local-observation'
            or observed.get('evidenceClass') != 'synthetic-local' or observed.get('releaseEligibility') != 'blocked'
            or observed.get('nativeProjections') != value['contexts'] or observed.get('dataRollback') != 'not-claimed'
            or observed.get('cleanup') != 'owned-process-stopped-private-state-retained'):
        _fail()
    epochs = observed.get('daemonEpochs')
    if not isinstance(epochs, list) or not 2 <= len(epochs) <= 16:
        _fail()
    identities = set()
    for epoch in epochs:
        if set(epoch) != {'supervisor', 'jvm'}:
            _fail()
        for process in epoch.values():
            if (set(process) != {'pid', 'startTicks', 'bootId', 'executableDigest'}
                    or type(process['pid']) is not int or process['pid'] < 1
                    or type(process['startTicks']) is not int or process['startTicks'] < 1
                    or not re.fullmatch(r'[0-9a-f-]{36}', process['bootId'])
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', process['executableDigest'])):
                _fail()
            identity = (process['pid'], process['startTicks'], process['bootId'])
            if identity in identities:
                _fail()
            identities.add(identity)
    operations = observed.get('operations')
    ordered = [('install', 'initial'), ('update', 'update'), ('switch', 'switch'), ('rollback', 'update')]
    if not isinstance(operations, list) or [row.get('operation') for row in operations] != [name for name, _ in ordered]:
        _fail()
    prior = None
    for row, (_, label) in zip(operations, ordered):
        if (set(row) != {'operation', 'target', 'before', 'status', 'observed', 'reconciled'}
                or row['status'] != 'complete' or type(row['reconciled']) is not bool or row['before'] != prior):
            _fail()
        native = projection.validate_declaration(value['contexts'][label])
        if native['schemaVersion'] != 3:
            _fail()
        actual = row['observed']
        names = {'appId': 'app_id', 'appVersion': 'version', 'catalogId': 'catalog_id',
                 'bundleDigest': 'bundle_digest', 'publisherFingerprint': 'publisher_fingerprint',
                 'signedContentDigest': 'signed_content_digest', 'installedTreeDigest': 'installed_tree_digest'}
        if (not isinstance(actual, dict) or set(actual) != set(names) | {'originSchemaVersion', 'originDigest', 'originFileDigest', 'retainedCatalogRevision'} | ORIGIN_SELECTION_FIELDS
                or actual['originSchemaVersion'] != 2 or set(row['target']) != set(names.values())
                or any(actual[field] != row['target'][target] for field, target in names.items())
                or any(actual[field] != native[field] for field in names if field != 'installedTreeDigest')):
            _fail()
        if any(not re.fullmatch(r'sha256:[0-9a-f]{64}', actual[field])
               for field in ('originDigest', 'originFileDigest', 'installedTreeDigest')):
            _fail()
        _origin_selection(actual, native)
        prior = actual
    if operations[3]['observed'] != operations[1]['observed']:
        _fail()
    initial, update, switch = (value['contexts'][label] for label in ('initial', 'update', 'switch'))
    if (initial['catalogId'] != update['catalogId'] or initial['catalogId'] == switch['catalogId']
            or len({entry['publisherFingerprint'] for entry in (initial, update, switch)}) != 1
            or len({entry['bundleDigest'] for entry in (initial, update, switch)}) != 3):
        _fail()
    counts = observed.get('requestCounts')
    if (not isinstance(counts, dict) or any(type(count) is not int or not 0 <= count <= 4096 for count in counts.values())
            or any(counts.get(source + '/' + member, 0) < 1 for source in ('primary', 'mirror') for member in ('catalog', 'signature'))):
        _fail()
    cases = {'catalog-install-origin-v2', 'same-origin-update', 'explicit-source-switch',
             'exact-bundle-origin-rollback', 'daemon-restart-origin-persistence', 'owned-process-cleanup'}
    if observed.get('terminalOrigin') != prior:
        _fail()
    mirrors = observed.get('mirror')
    if mirrors is None:
        _fail()
    if mirrors is not None:
        expected = {'exactFallback': (False, 'exact', 'mirror', True),
                    'mismatchedSignature': (False, 'mismatch', 'mirror', False),
                    'staleCatalog': (False, 'stale', 'mirror', False),
                    'primaryRecovery': (True, 'exact', 'primary', True)}
        if set(mirrors) != set(expected):
            _fail()
        for name, (available, mode, source, success) in expected.items():
            row = mirrors[name]
            if (set(row) != {'beforeRequests', 'afterRequests', 'httpStatus', 'errorCode', 'beforeOrigin',
                             'afterOrigin', 'beforeCatalog', 'afterCatalog', 'primaryAvailable', 'mirrorMode'}
                    or row['primaryAvailable'] is not available or row['mirrorMode'] != mode
                    or type(row['httpStatus']) is not int or (row['httpStatus'] in {200, 201}) != success
                    or (not success and not 400 <= row['httpStatus'] <= 599)
                    or row['beforeOrigin'] != operations[1]['observed'] or row['afterOrigin'] != row['beforeOrigin']
                    or set(row['beforeCatalog']) != {'catalogDigest', 'signatureKeyId'}
                    or row['beforeCatalog'] != row['afterCatalog']
                    or row['beforeCatalog']['signatureKeyId'] != update['catalogKeyId']):
                _fail()
            revision = 'sha256:' + str(row['beforeCatalog']['catalogDigest']).removeprefix('sha256:')
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', revision):
                _fail()
            signers = {fingerprint for activation in observed.get('roleActivationBindings', [])
                       if activation.get('binding', {}).get('catalogId') == update['catalogId']
                       for fingerprint in activation['binding'].get('signerFingerprints', [])}
            if (len(signers) != 1 or _selected_subject_commitment(update, revision, 'sha256:' + next(iter(signers)))
                    != update['federationSelection']['selectedSubjectDigest']):
                _fail()
            for counts_row in (row['beforeRequests'], row['afterRequests']):
                if (not isinstance(counts_row, dict) or any(type(n) is not int or not 0 <= n <= 4096 for n in counts_row.values())):
                    _fail()
            if (any(row['afterRequests'].get(key, 0) < n for key, n in row['beforeRequests'].items())
                    or any(row['afterRequests'].get(source + '/' + member, 0) <= row['beforeRequests'].get(source + '/' + member, 0)
                           for member in ('catalog', 'signature'))):
                _fail()
        cases.update({'loopback-primary-mirror-fallback', 'mismatched-mirror-signature-denied',
                      'stale-mirror-denied', 'loopback-primary-recovery'})
    denials = observed.get('sourceSwitchDenials')
    if denials is None:
        _fail()
    if denials is not None:
        if (not isinstance(denials, list) or len(denials) != 2
                or {row.get('case') for row in denials} != {'missing-consent', 'stale-consent'}):
            _fail()
        for row in denials:
            if (set(row) != {'case', 'httpStatus', 'errorCode', 'beforeOrigin', 'afterOrigin'}
                    or row['httpStatus'] != 409 or row['errorCode'] != 'catalog_source_switch_consent_required'
                    or row['beforeOrigin'] != operations[1]['observed'] or row['afterOrigin'] != row['beforeOrigin']):
                _fail()
        cases.update({'source-switch-missing-consent-denied', 'source-switch-stale-consent-denied'})
    activations = observed.get('roleActivationBindings')
    if (not isinstance(activations, list) or not 2 <= len(activations) <= 16
            or observed.get('originalPreauthorizationDigest') != _hash(value['contexts'])):
        _fail()
    catalog_keys = {entry['catalogId']: entry['catalogKeyId'] for entry in value['contexts'].values()}
    activated = set()
    for number, row in enumerate(activations, 1):
        if (set(row) != {'role', 'sequence', 'daemonEpochDigest', 'authorityScope', 'binding'}
                or row['role'] != 'catalog-origin' or type(row['sequence']) is not int or row['sequence'] != number
                or row['daemonEpochDigest'] not in {_hash(epoch) for epoch in epochs}
                or row['authorityScope'] != 'fresh-role-local-operator-activation'):
            _fail()
        binding = row['binding']
        if (set(binding) != {'bindingId', 'catalogId', 'status', 'signerKeyIds', 'signerFingerprints', 'channels',
                             'localPriority', 'reviewerPolicyDigest', 'publisherPolicyDigest', 'selfDigest'}
                or binding['status'] != 'active' or binding['channels'] != ['stable']
                or len(binding['signerKeyIds']) != 1 or len(binding['signerFingerprints']) != 1
                or any(not re.fullmatch(r'[0-9a-f]{64}', str(binding[field]))
                       for field in ('reviewerPolicyDigest', 'publisherPolicyDigest', 'selfDigest'))
                or not re.fullmatch(r'[0-9a-f]{64}', str(binding['signerFingerprints'][0]))):
            _fail()
        if binding['catalogId'] in catalog_keys:
            if binding['signerKeyIds'] != [catalog_keys[binding['catalogId']]]:
                _fail()
            for native in value['contexts'].values():
                if native['catalogId'] == binding['catalogId'] and any(
                        'sha256:' + binding[field] != native['federationSelection'][field]
                        for field in ('publisherPolicyDigest', 'reviewerPolicyDigest')):
                    _fail()
            activated.add(binding['catalogId'])
    if activated != set(catalog_keys):
        _fail()
    for operation in operations:
        _origin_activation(operation['observed'], activations)
    cases.add('role-local-scoped-catalog-activation')
    cases.update(_secondary_roles(observed, value['contexts']))
    cases.update(_source_security(observed, value['contexts']))
    return frozenset(cases)


def run(execution_contract, observation_dir):
    producer = _identity()
    policy, plan_digest = _plan()
    _execution(execution_contract, policy, producer)
    _check_trees(policy)
    output = Path(observation_dir)
    if output.exists() or output.is_symlink():
        _fail()
    # Retained activation fences replay. A retry must reconcile this exact owned journal manually;
    # the adapter never silently creates another daemon or changes the admitted cohort.
    activation = Path(policy['privateRoot']) / f"catalog-{producer['runId']}-{producer['runAttempt']}"
    activation.mkdir(mode=0o700)
    _write(activation / 'intent.json', _bytes({'producer': producer, 'planDigest': plan_digest, 'status': 'admitting'}))
    inventory, distribution = _authenticated_inputs(policy, activation)
    started = dt.datetime.now(dt.timezone.utc)
    from federated_catalog_runtime import execute
    observation = execute(activation / 'runtime', distribution, Path(policy['javaHome']), Path(policy['toolRoot']),
                          Path(policy['fixtureRoot']), source_commit=policy['sourceCommit'],
                          maximum_seconds=policy['maximumSeconds'], expected_projections=policy['nativeProjections'])
    ended = dt.datetime.now(dt.timezone.utc)
    import cross_version_runtime as runtime
    envelope = {'schemaVersion': 2, 'kind': 'catalog-origin-scoped-observation',
                'sourceCommit': policy['sourceCommit'], 'executionId': policy['executionId'], 'planDigest': plan_digest,
                'selectionOriginal': policy['selectionOriginal'], 'projectionOriginal': policy['projectionOriginal'],
                'projectionInventoryDigest': inventory.digest, 'daemonDigest': policy['packageDigest'],
                'daemonExecutableDigest': policy['daemonExecutableDigest'],
                **{field: policy[field] for field in ('toolTreeDigest', 'javaTreeDigest', 'fixtureTreeDigest', 'implementationDigest')},
                'contexts': policy['nativeProjections'], 'startedAt': started.isoformat(), 'completedAt': ended.isoformat(),
                'producer': producer, 'observation': observation, 'evidenceClass': 'synthetic-local', 'releaseEligibility': 'blocked'}
    validate_observation(envelope, plan_digest, now=ended)
    _check_trees(policy)
    if (ended - started).total_seconds() > policy['maximumSeconds']:
        _fail()
    encrypted = selection._cms(_bytes(envelope), activation)
    public = {'schemaVersion': 2, 'kind': 'catalog-origin-synthetic-summary', 'cohortId': policy['publicCohortId'],
              'evidenceClass': 'synthetic-local', 'releaseEligibility': 'blocked', 'sourceCommit': policy['sourceCommit'],
              'daemonDigest': envelope['daemonDigest'], 'toolTreeDigest': policy['toolTreeDigest'],
              'operationCount': observation['totalOperations'], 'reasonCodes': ['synthetic-loopback-only', 'full-phase-12-incomplete']}
    output.mkdir(mode=0o700)
    _write(output / CIPHERTEXT, encrypted)
    _write(output / PUBLIC, _bytes(public))
    _write(activation / 'observation-pin.json', _bytes({'producer': producer, 'planDigest': plan_digest,
        'ciphertextDigest': _digest(encrypted), 'publicDigest': _hash(public), 'observationDigest': _hash(envelope)}))
    return envelope


def _signature_subject(receipt):
    return DOMAIN + _bytes({key: value for key, value in receipt.items() if key != 'signatureBase64'})


def _sign(receipt, policy, scratch):
    encoded = os.environ.get('CRYPTAD_FEDERATION_OBSERVER_PRIVATE_KEY', '')
    try:
        private = base64.b64decode(encoded, validate=True)
    except ValueError:
        _fail()
    if not 1 <= len(private) <= 16384:
        _fail()
    with tempfile.TemporaryDirectory(prefix='observer-key-', dir=scratch) as temporary:
        root = Path(temporary)
        _write(root / 'key.der', private)
        _write(root / 'subject', _signature_subject(receipt))
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'OPENSSL_CONF': '/dev/null'}
        bounded_run(['/usr/bin/openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(root / 'key.der'),
                     '-keyform', 'DER', '-in', str(root / 'subject'), '-out', str(root / 'signature')],
                    environment=environment, timeout=30, output_limit=4096)
        signature = base64.b64encode(selection._regular(root / 'signature', 64)).decode()
        if pilot._verify(policy['observerPublicKeySpkiBase64'], _signature_subject(receipt), signature, 'observer'):
            _fail()
        return signature


def seal(execution_contract, observation_dir, receipt_dir, *, artifact_id, artifact_name, artifact_digest):
    producer = _identity()
    policy, plan_digest = _plan()
    _execution(execution_contract, policy, producer)
    source = Path(observation_dir)
    if {path.name for path in source.iterdir()} != {CIPHERTEXT, PUBLIC}:
        _fail()
    encrypted = selection._regular(source / CIPHERTEXT, selection.MAX_BYTES)
    public = selection._regular(source / PUBLIC)
    activation = _private_directory(Path(policy['privateRoot']) / f"catalog-{producer['runId']}-{producer['runAttempt']}")
    pin = _json(selection._regular(activation / 'observation-pin.json'))
    if (pin['producer'] != producer or pin['planDigest'] != plan_digest
            or pin['ciphertextDigest'] != _digest(encrypted) or pin['publicDigest'] != _digest(public)):
        _fail()
    if (type(artifact_id) is not int or artifact_id < 1
            or artifact_name != f"catalog-origin-observation-{producer['runId']}-{producer['runAttempt']}"
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(artifact_digest))):
        _fail()
    # Authenticate the exact just-uploaded immutable bytes, not a path supplied to the seal step.
    archive = _gh(['api', f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip'], _environment(), json_result=False)
    metadata = _gh(['api', f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}'], _environment())
    if (metadata.get('id') != artifact_id or metadata.get('name') != artifact_name
            or metadata.get('workflow_run', {}).get('id') != producer['runId'] or metadata.get('expired') is not False
            or metadata.get('digest') != artifact_digest or _digest(archive) != artifact_digest
            or selection.archive_members(archive) != {CIPHERTEXT: encrypted, PUBLIC: public}):
        _fail()
    receipt = {'schemaVersion': 1, 'kind': 'catalog-origin-observer-receipt', 'producer': producer,
               'ciphertextDigest': _digest(encrypted), 'publicDigest': _digest(public),
               'originalObservation': {'artifactId': artifact_id, 'artifactName': artifact_name, 'artifactDigest': artifact_digest},
               'observerKeyId': policy['observerKeyId'], 'observerFingerprint': policy['observerFingerprint'],
               'observerPublicKeySpkiBase64': policy['observerPublicKeySpkiBase64'], 'signatureBase64': ''}
    receipt['signatureBase64'] = _sign(receipt, policy, activation)
    destination = Path(receipt_dir)
    destination.mkdir(mode=0o700)
    _write(destination / CIPHERTEXT, encrypted)
    _write(destination / PUBLIC, public)
    _write(destination / RECEIPT, _bytes(receipt))
    return receipt


class AuthenticatedCatalogObservation:
    """Typed capability for exact original observed bytes; ordinary JSON cannot construct it."""
    def __init__(self, value, authority=None, *, original_bytes=None):
        if authority is not AUTHORITY:
            _fail()
        self.__raw = _bytes(value)
        original = self.__raw if original_bytes is None else original_bytes
        if _json(original) != value:
            _fail()
        self.digest = _digest(original)

    def observation(self):
        return _json(self.__raw)

    def matches(self, value):
        return _bytes(value) == self.__raw


def authenticate_observation(coordinates, private_root, expected_plan_digest):
    if coordinates.get('sourceFamily') != 'catalog-origin-observation':
        _fail()
    policy, plan_digest = _plan()
    if plan_digest != expected_plan_digest:
        _fail()
    artifact = authenticate_original(coordinates, private_root)
    files = selection.archive_members(artifact.content)
    if set(files) != {CIPHERTEXT, PUBLIC, RECEIPT}:
        _fail()
    receipt = _json(files[RECEIPT])
    fields = {'schemaVersion', 'kind', 'producer', 'ciphertextDigest', 'publicDigest',
              'originalObservation', 'observerKeyId', 'observerFingerprint',
              'observerPublicKeySpkiBase64', 'signatureBase64'}
    expected_producer = {'repository': REPOSITORY, 'workflowPath': WORKFLOW, 'sourceCommit': coordinates['sourceCommit'],
                         'runId': coordinates['runId'], 'runAttempt': coordinates['runAttempt'], 'environment': ENVIRONMENT}
    if (set(receipt) != fields or receipt['schemaVersion'] != 1 or receipt['kind'] != 'catalog-origin-observer-receipt'
            or receipt['producer'] != expected_producer
            or receipt['ciphertextDigest'] != _digest(files[CIPHERTEXT]) or receipt['publicDigest'] != _digest(files[PUBLIC])
            or any(receipt[field] != policy[field] for field in ('observerKeyId', 'observerFingerprint', 'observerPublicKeySpkiBase64'))
            or pilot._verify(receipt['observerPublicKeySpkiBase64'], _signature_subject(receipt), receipt['signatureBase64'], 'observer')):
        _fail()
    unsigned = receipt['originalObservation']
    if (not isinstance(unsigned, dict) or set(unsigned) != {'artifactId', 'artifactName', 'artifactDigest'}
            or type(unsigned['artifactId']) is not int or unsigned['artifactId'] < 1
            or unsigned['artifactId'] == coordinates['artifactId']
            or unsigned['artifactName'] != f"catalog-origin-observation-{coordinates['runId']}-{coordinates['runAttempt']}"
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(unsigned['artifactDigest']))):
        _fail()
    original_bytes = selection._cms(files[CIPHERTEXT], private_root, decrypt=True)
    value = _json(original_bytes)
    validate_observation(value, expected_plan_digest, now=dt.datetime.now(dt.timezone.utc))
    if (value['producer'] != expected_producer or value['planDigest'] != expected_plan_digest
            or value['sourceCommit'] != policy['sourceCommit']
            or value['selectionOriginal'] != policy['selectionOriginal'] or value['projectionOriginal'] != policy['projectionOriginal']
            or value['contexts'] != policy['nativeProjections']):
        _fail()
    bindings = {'daemonDigest': 'packageDigest', 'daemonExecutableDigest': 'daemonExecutableDigest',
                'projectionInventoryDigest': 'projectionInventoryDigest', 'executionId': 'executionId',
                'toolTreeDigest': 'toolTreeDigest', 'javaTreeDigest': 'javaTreeDigest',
                'fixtureTreeDigest': 'fixtureTreeDigest', 'implementationDigest': 'implementationDigest'}
    if any(value[field] != policy[selected] for field, selected in bindings.items()):
        _fail()
    completed = dt.datetime.fromisoformat(value['completedAt'])
    if artifact.job_completed_at is None or completed > dt.datetime.fromisoformat(artifact.job_completed_at.replace('Z', '+00:00')):
        _fail()
    return AuthenticatedCatalogObservation(value, AUTHORITY, original_bytes=original_bytes)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['run', 'seal'])
    parser.add_argument('--execution-contract', type=Path, required=True)
    parser.add_argument('--observation-dir', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path)
    parser.add_argument('--require-managed-daemon', action='store_true')
    parser.add_argument('--receipt-dir', type=Path)
    parser.add_argument('--artifact-id', type=int)
    parser.add_argument('--artifact-name')
    parser.add_argument('--artifact-digest')
    # Legacy identity flags are assertions only; the protected environment remains authoritative.
    for name in ('observer-key-id', 'observer-key-fingerprint', 'repository', 'workflow-path', 'workflow-commit', 'run-id', 'run-attempt', 'environment'):
        parser.add_argument('--' + name)
    args = parser.parse_args(argv)
    try:
        supplied = {name: getattr(args, name) for name in ('observer_key_id', 'observer_key_fingerprint',
                    'repository', 'workflow_path', 'workflow_commit', 'run_id', 'run_attempt', 'environment')}
        if any(value is not None for value in supplied.values()):
            policy, _ = _plan()
            producer = _identity()
            expected = {'observer_key_id': policy['observerKeyId'], 'observer_key_fingerprint': policy['observerFingerprint'],
                'repository': REPOSITORY, 'workflow_path': WORKFLOW, 'workflow_commit': producer['sourceCommit'],
                'run_id': str(producer['runId']), 'run_attempt': str(producer['runAttempt']), 'environment': ENVIRONMENT}
            if any(value is not None and value != expected[name] for name, value in supplied.items()):
                _fail()
        if args.evidence_dir is not None:
            _fail()  # Legacy broad evidence never selects this finite original-input producer.
        if args.command == 'run':
            if not args.require_managed_daemon:
                _fail()
            run(args.execution_contract, args.observation_dir)
        else:
            if args.receipt_dir is None or args.artifact_id is None or args.artifact_name is None or args.artifact_digest is None:
                _fail()
            seal(args.execution_contract, args.observation_dir, args.receipt_dir, artifact_id=args.artifact_id,
                 artifact_name=args.artifact_name, artifact_digest=args.artifact_digest)
    except Exception:
        print('catalog-observer-operation-failed')
        return 2
    print('catalog-observer-private-operation-complete')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
