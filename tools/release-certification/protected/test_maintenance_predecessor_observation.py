"""Pre-freeze observation reuses the complete native published maintenance authority graph."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

import maintenance_runtime_metadata as metadata
from cryptad_certification.tests.test_stable_maintenance import _published_ga_maintenance_context
from cryptad_certification.engines import stable_1_0_maintenance_core as core
from cryptad_certification.tests.support import workspace_root
from cryptad_certification.tests import test_stable_maintenance as fixtures
from cryptad_certification.engines import stable_1_0_maintenance as engine


class PredecessorObservationTests(unittest.TestCase):
    def context(self, root):
        context, output = _published_ga_maintenance_context(root)
        baseline = json.loads((output / 'stable-1.0-maintenance-baseline.json').read_text())
        release = baseline['release']
        context.manifest.inputs.update({
            'predecessorBaseline': context.manifest.inputs['stableGaMaintenanceBaseline'],
            'predecessorPublicationReceipt': context.manifest.inputs['stableGaPublicationReceipt'],
        })
        context.manifest.policies.update({
            'expectedPredecessorBuild': release['buildVersion'],
            'expectedPredecessorReleaseId': release['releaseId'],
            'expectedPredecessorProductDigest': release['rcProductDigest'],
            'releaseClass': 'maintenance',
        })
        return context, output, release

    def test_complete_published_ga_graph_derives_exact_observation(self):
        workspace = workspace_root()
        with tempfile.TemporaryDirectory(dir=workspace / 'build') as directory:
            context, output, release = self.context(Path(directory))
            result = metadata.authenticate_predecessor_observation(context, '2026-09-11T12:00:00Z')
            self.assertEqual(result, {
                'releaseId': release['releaseId'], 'buildVersion': release['buildVersion'],
                'sourceCommit': release['sourceCommit'], 'productDigest': release['rcProductDigest'],
                'baselineDigest': core.file_digest(output / 'stable-1.0-maintenance-baseline.json'),
                'publicationReceiptDigest': core.file_digest(output / 'stable-1.0-ga-publication-receipt.json'),
                'latestPublishedPointerDigest': None, 'observedAt': '2026-09-11T12:00:00Z',
                'status': 'latest-published',
            })

    def test_substituted_receipt_baseline_and_ga_pointer_reject_before_freeze(self):
        workspace = workspace_root()
        with tempfile.TemporaryDirectory(dir=workspace / 'build') as directory:
            context, output, _ = self.context(Path(directory))
            original_inputs = dict(context.manifest.inputs)
            for key in ('predecessorBaseline', 'predecessorPublicationReceipt', 'latestPublishedMaintenancePointer'):
                with self.subTest(key=key):
                    context.manifest.inputs.clear()
                    context.manifest.inputs.update(original_inputs)
                    selected = Path(directory) / (key + '.json')
                    if key == 'latestPublishedMaintenancePointer':
                        selected.write_text('{}')
                    else:
                        value = json.loads((workspace / original_inputs[key]).read_text())
                        value['unboundModification'] = 'synthetic substitution'
                        selected.write_text(json.dumps(value))
                    context.manifest.inputs[key] = selected.relative_to(workspace).as_posix()
                    with self.assertRaisesRegex(metadata.RuntimeMetadataError, 'published-graph-rejected'):
                        metadata.authenticate_predecessor_observation(context, '2026-09-11T12:00:00Z')

    def test_changed_original_ga_root_rejects_even_with_matching_predecessor_path(self):
        workspace = workspace_root()
        with tempfile.TemporaryDirectory(dir=workspace / 'build') as directory:
            context, output, _ = self.context(Path(directory))
            receipt = output / 'stable-1.0-ga-publication-receipt.json'
            value = json.loads(receipt.read_text())
            value['publicationState'] = 'prepared'
            receipt.write_text(json.dumps(value))
            with self.assertRaisesRegex(metadata.RuntimeMetadataError, 'ga-root-rejected'):
                metadata.authenticate_predecessor_observation(context, '2026-09-11T12:00:00Z')

    def successor_context(self, root):
        context, _, _ = self.context(root)
        state = core.ValidationState()
        ga = core.authenticate_ga_root(context, state)
        predecessor = core.authenticate_predecessor(context, ga, state)
        self.assertEqual(state.blockers, [])
        candidate = fixtures._candidate(root)
        _, receipt = fixtures.StableMaintenanceAuthorizationAndPublicationTest()._publication_fixture(root, 'created')
        successor = engine._successor(
            fixtures._context(root), ga, predecessor, candidate, fixtures._digest('1'),
            fixtures._evidence(), fixtures._digest('2'), receipt, fixtures._digest('3'),
            fixtures._digest('4'), None, None,
        )
        baseline_path = root / 'published-successor.json'
        fixtures.write_json(baseline_path, successor)
        receipt['successorBaselineDigest'] = core.file_digest(baseline_path)
        receipt_path = root / 'published-maintenance-receipt.json'
        fixtures.write_json(receipt_path, receipt)
        pointer = {
            'kind': 'stable-1.0-maintenance-latest-published',
            'releaseId': successor['release']['releaseId'],
            'buildVersion': successor['release']['buildVersion'],
            'baselineDigest': core.file_digest(baseline_path),
            'publicationReceiptDigest': core.file_digest(receipt_path),
            'lineageDigest': successor['lineage']['lineageDigest'],
            'backportReleaseTrainDigest': successor['releaseTrain']['validationDigest'],
            'status': 'active',
        }
        pointer_path = root / 'activated-pointer.json'
        fixtures.write_json(pointer_path, pointer)
        context.manifest.inputs.update({
            'predecessorBaseline': baseline_path.relative_to(workspace_root()).as_posix(),
            'predecessorPublicationReceipt': receipt_path.relative_to(workspace_root()).as_posix(),
            'latestPublishedMaintenancePointer': pointer_path.relative_to(workspace_root()).as_posix(),
        })
        context.manifest.policies.update({
            'expectedPredecessorBuild': successor['release']['buildVersion'],
            'expectedPredecessorReleaseId': successor['release']['releaseId'],
            'expectedPredecessorProductDigest': successor['release']['productDigest'],
        })
        context = replace(context, manifest=replace(context.manifest, release=replace(
            context.manifest.release, version=str(int(successor['release']['buildVersion']) + 1))))
        return context, successor, baseline_path, receipt_path, pointer_path

    def test_actual_maintenance_successor_graph_derives_original_source_and_pointer(self):
        with tempfile.TemporaryDirectory(dir=workspace_root() / 'build') as directory:
            context, successor, baseline, receipt, pointer = self.successor_context(Path(directory))
            result = metadata.authenticate_predecessor_observation(context, '2026-09-11T12:00:00Z')
            self.assertEqual(result['sourceCommit'], fixtures.COMMIT)
            self.assertEqual(result['productDigest'], successor['release']['productDigest'])
            self.assertEqual(result['baselineDigest'], core.file_digest(baseline))
            self.assertEqual(result['publicationReceiptDigest'], core.file_digest(receipt))
            self.assertEqual(result['latestPublishedPointerDigest'], core.file_digest(pointer))

    def test_maintenance_pointer_receipt_and_lineage_substitutions_reject(self):
        with tempfile.TemporaryDirectory(dir=workspace_root() / 'build') as directory:
            context, _, baseline, receipt, pointer = self.successor_context(Path(directory))
            cases = (
                (pointer, lambda value: value.update({'baselineDigest': fixtures._digest('e')})),
                (receipt, lambda value: value.update({'sourceCommit': 'f' * 40})),
                (baseline, lambda value: value['lineage']['history'][0].update({'sourceCommit': 'e' * 40})),
            )
            for path, mutate in cases:
                with self.subTest(member=path.name):
                    original = path.read_bytes()
                    value = json.loads(original)
                    mutate(value)
                    fixtures.write_json(path, value)
                    try:
                        with self.assertRaisesRegex(metadata.RuntimeMetadataError, 'published-graph-rejected'):
                            metadata.authenticate_predecessor_observation(context, '2026-09-11T12:00:00Z')
                    finally:
                        path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
