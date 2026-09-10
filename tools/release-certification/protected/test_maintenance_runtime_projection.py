"""Deterministic projection tests; synthetic journal duration is never live elapsed time."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import maintenance_runtime_projection as projection
from cryptad_certification.tests.test_cross_version_evidence import fixture_plan, fixture_events, checkpoint_for
from cryptad_certification.cross_version_evidence import digest


class MaintenanceRuntimeProjectionTest(unittest.TestCase):
    def fixture(self):
        plan = fixture_plan()
        plan['provenanceClass'] = 'production-artifact-comparison'
        events, checkpoint = fixture_events(plan)
        products = [{**{key: node[key] for key in ('role', 'sourceCommit', 'artifactDigest', 'artifactSize', 'packageTarget')},
                     'maintenanceFreezeDigest': 'sha256:' + 'a' * 64,
                     'freezeCompletedAt': '2025-12-31T00:00:00Z',
                     'frozenPortableBinding': 'existing-maintenance-freeze-exact-product-v1'} for node in plan['nodes']]
        return plan, events, checkpoint, products

    def project(self, fixture=None, **kwargs):
        return projection.project(*(fixture or self.fixture()), now=dt.datetime(2026, 1, 1, 0, 10, tzinfo=dt.timezone.utc), **kwargs)

    def test_real_verifier_counts_each_direction_and_keeps_missing_adapters_blocked(self):
        result = self.project()
        self.assertIs(result, projection.validate(result))
        row = next(row for row in result['rows'] if row['id'].endswith('live-network-interoperability'))
        self.assertEqual(1, row['caseSamples']['network-chk/previous/candidate-recipient'])
        self.assertEqual([], row['missingCases'])
        self.assertIn('hyphanet-required-matrix-adapter-missing', row['blockers'])
        self.assertTrue(all(row['status'] == 'blocked' for row in result['rows']))
        self.assertEqual('blocked', result['maintenanceEligibility'])
        self.assertEqual(8, result['observedNetworkOperations'])
        self.assertEqual('sha256:' + hashlib.sha256(projection.POLICY.read_bytes()).hexdigest(), result['policyByteDigest'])

    def test_replayed_segment_cannot_supply_maintenance_readiness(self):
        plan, events, checkpoint, products = self.fixture()
        events.insert(-1, copy.deepcopy(events[6]))
        result = self.project((plan, events, checkpoint_for(plan, events), products))
        self.assertTrue(all('journal-required-coverage-or-integrity-incomplete' in row['blockers'] for row in result['rows']))

    def test_before_freeze_wrong_bytes_and_rc_app_only_binding_are_distinct_denials(self):
        for change, expected in (({'freezeCompletedAt': '2026-01-02T00:00:00Z'}, 'journal-start-precedes-freeze-completion'),
                                 ({'artifactDigest': 'sha256:' + '9' * 64}, 'candidate-or-predecessor-portable-freeze-unbound'),
                                 ({'frozenPortableBinding': 'not-established'}, 'candidate-or-predecessor-portable-freeze-unbound')):
            with self.subTest(change=change):
                fixture = self.fixture()
                fixture[3][0].update(change)
                result = self.project(fixture)
                self.assertTrue(all(expected in row['blockers'] for row in result['rows']))

    def test_policy_windows_are_read_from_exact_bytes_and_staleness_is_rechecked(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'policy.json'
            policy = json.loads(projection.POLICY.read_bytes())
            policy['evidenceWindows']['maximumAgeDays'] = 0
            path.write_text(json.dumps(policy))
            result = self.project(policy_path=path)
            self.assertNotEqual(self.project()['policyByteDigest'], result['policyByteDigest'])
            self.assertTrue(all('maintenance-observation-stale-or-future' in row['blockers'] for row in result['rows']))

    def test_missing_direction_and_unknown_or_promoted_row_are_rejected(self):
        fixture = self.fixture()
        event = next(event for event in fixture[1] if event['scenario'] == 'network-chk' and event['kind'] == 'operation')
        event['outcome'] = 'not-observed'
        result = self.project(fixture)
        row = next(row for row in result['rows'] if row['id'].endswith('live-network-interoperability'))
        self.assertIn('network-chk/candidate-sender/previous', row['missingCases'])
        row['status'] = 'pass'
        with self.assertRaises(projection.ProjectionError):
            projection.validate(result)

    def test_malformed_nested_json_values_fail_with_closed_projection_errors(self):
        valid = self.project()
        mutations = (
            ('row scalar', lambda value: value['rows'].__setitem__(0, None)),
            ('row list', lambda value: value['rows'].__setitem__(0, [])),
            ('row identifier list', lambda value: value['rows'][0].update(id=[])),
            ('row identifier object', lambda value: value['rows'][0].update(id={})),
            ('row missing field', lambda value: value['rows'][0].pop('caseSamples')),
            ('samples null', lambda value: value['rows'][0].update(caseSamples=None)),
            ('samples list', lambda value: value['rows'][0].update(caseSamples=[])),
            ('samples nonempty list', lambda value: value['rows'][0].update(caseSamples=list(value['rows'][0]['caseSamples']))),
            ('sample count object', lambda value: value['rows'][0]['caseSamples'].update({next(iter(value['rows'][0]['caseSamples'])): {}})),
            ('missing cases object', lambda value: value['rows'][0].update(missingCases={})),
            ('missing case list', lambda value: value['rows'][0].update(missingCases=[[]])),
            ('blocker list', lambda value: value['rows'][0].update(blockers=[[]])),
            ('blocker object', lambda value: value['rows'][0].update(blockers=[{}])),
            ('blocker mixed type', lambda value: value['rows'][0].update(blockers=['known', 1])),
            ('product scalar', lambda value: value['products'].__setitem__(0, None)),
            ('product role list', lambda value: value['products'][0].update(role=[])),
            ('product role object', lambda value: value['products'][0].update(role={})),
            ('product binding list', lambda value: value['products'][0].update(binding=[])),
            ('product binding object', lambda value: value['products'][0].update(binding={})),
            ('product missing field', lambda value: value['products'][0].pop('binding')),
            ('producer list', lambda value: value.update(producer=[])),
            ('huge elapsed integer', lambda value: value.update(observedEligibleSeconds=10 ** 1000)),
            ('elapsed object', lambda value: value.update(observedEligibleSeconds={})),
        )
        for name, mutate in mutations:
            with self.subTest(case=name):
                value = copy.deepcopy(valid)
                mutate(value)
                with self.assertRaisesRegex(projection.ProjectionError, r'^maintenance-measurements-[a-z-]+$'):
                    projection.validate(value)
        self.assertEqual('blocked', projection.validate(valid)['maintenanceEligibility'])

    def test_original_finish_authentication_is_required_and_binding_cannot_be_substituted(self):
        import cross_version_supervisor_authority as supervisor
        measured = self.project()
        report = {'schemaVersion': 2, 'operation': 'finish', 'maintenanceMeasurements': measured,
                  'planDigest': measured['planDigest'], 'producer': measured['producer'],
                  'checkpoint': {'digest': measured['checkpointDigest']}}
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(supervisor, 'authenticate_report', return_value=(report, {'runId': 123})) as authenticate:
                result = projection.authenticate({}, Path(temporary), expected_plan_digest=measured['planDigest'],
                                                 expected_policy_digest=measured['policyByteDigest'],
                                                 now=dt.datetime(2026, 1, 1, 0, 10, tzinfo=dt.timezone.utc))
                authenticate.assert_called_once()
                self.assertEqual({'runId': 123}, result.original_coordinates())
                returned = result.measurements()
                returned['rows'].clear()
                self.assertTrue(result.measurements()['rows'])
                with self.assertRaises(projection.ProjectionError):
                    projection.authenticate({}, Path(temporary), expected_plan_digest=measured['planDigest'],
                                            expected_policy_digest='sha256:' + '9' * 64)
                with self.assertRaisesRegex(projection.ProjectionError, 'observation-expired'):
                    projection.authenticate({}, Path(temporary), expected_plan_digest=measured['planDigest'],
                                            expected_policy_digest=measured['policyByteDigest'],
                                            now=dt.datetime(2026, 2, 1, tzinfo=dt.timezone.utc))
                report['schemaVersion'] = 1
                with self.assertRaises(projection.ProjectionError):
                    projection.authenticate({}, Path(temporary), expected_plan_digest=measured['planDigest'],
                                            expected_policy_digest=measured['policyByteDigest'])
        with self.assertRaises(projection.ProjectionError):
            projection.AuthenticatedMeasurements(measured, {'runId': 123}, True)

    def test_supervisor_v2_keeps_v1_observation_and_binds_measurements_to_checkpoint(self):
        import cross_version_supervisor_authority as supervisor
        plan, events, checkpoint, _products = self.fixture()
        measured = self.project()
        report = {'schemaVersion': 2, 'kind': 'cryptad-cross-version-supervisor', 'operation': 'finish',
                  'experimentId': plan['experimentId'], 'planDigest': digest(plan), 'producer': plan['producer'],
                  'job': {'sourceCommit': plan['producer']['sourceCommit'], 'runId': 123, 'runAttempt': 1},
                  'purpose': 'nonrelease-observed-experiment', 'releaseEligible': False,
                  'selectionDigest': 'sha256:' + '1' * 64, 'previousReportDigest': 'sha256:' + '2' * 64,
                  'previousOrigin': {}, 'serviceState': 'stopped', 'approvalOrigin': {},
                  'approvalReportDigest': 'sha256:' + '3' * 64,
                  'checkpoint': {'digest': digest(checkpoint)},
                  'observation': projection.verify(plan, events, checkpoint), 'maintenanceMeasurements': measured}
        self.assertIs(report, supervisor.validate_report(report))
        self.assertEqual([], supervisor.scan_value(report))
        legacy = {key: value for key, value in report.items() if key != 'maintenanceMeasurements'}
        legacy['schemaVersion'] = 1
        self.assertIs(legacy, supervisor.validate_report(legacy))
        report['maintenanceMeasurements']['checkpointDigest'] = 'sha256:' + '4' * 64
        with self.assertRaisesRegex(supervisor.AuthorityError, 'measurements-binding-invalid'):
            supervisor.validate_report(report)


if __name__ == '__main__':
    unittest.main()
