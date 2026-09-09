"""Offline catalog admission and durable continuation tests; no node launch or source fetch."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import cross_version_runtime as runtime
import cross_version_catalog as catalog


class CatalogRuntimeTest(unittest.TestCase):
    def subject(self):
        value = object.__new__(runtime.Supervisor)
        value.private = {}
        value.plan = {}
        value.authorization = {}
        value.catalog_prepared = None
        value.catalog_observation = None
        value.private_work = {}
        value.outcomes = {}
        return value

    def test_missing_and_wrong_private_authority_refused_before_preflight(self):
        supervisor = self.subject()
        supervisor.plan = {"workloadInputs": {"catalog": "sha256:" + "a" * 64}}
        with self.assertRaisesRegex(runtime.RuntimeFailure, "without-private-selection"):
            supervisor.prepare_catalog_selection()
        supervisor.private = {"catalog": {"role": "candidate-sender"}}
        supervisor.authorization = {"catalogInputsDigest": "sha256:" + "b" * 64}
        with self.assertRaisesRegex(runtime.RuntimeFailure, "not-authorized"):
            supervisor.prepare_catalog_selection()
        self.assertIsNone(supervisor.catalog_prepared)

    def test_unicode_selected_paths_have_same_canonical_binding(self):
        value = {"localRoot": "/private/synthetic-α", "role": "candidate-sender"}
        self.assertEqual(runtime.canonical_digest(value), catalog.selection_digest(value))

    def test_host_routes_are_confined_to_selected_role_app_and_catalog(self):
        supervisor = self.subject()
        supervisor.catalog_prepared = SimpleNamespace(role="candidate-sender", baseline=SimpleNamespace(app_id="site-publisher", catalog_id="soak-catalog"), other_catalog=None)
        self.assertTrue(supervisor.catalog_route_allowed("candidate-sender", "site-publisher", "POST", "/api/v1/app-catalogs/add"))
        self.assertTrue(supervisor.catalog_route_allowed("candidate-sender", "site-publisher", "GET", "/api/v1/app-catalogs/soak-catalog/operations/health"))
        self.assertFalse(supervisor.catalog_route_allowed("candidate-recipient", "site-publisher", "POST", "/api/v1/app-catalogs/add"))
        self.assertFalse(supervisor.catalog_route_allowed("candidate-sender", "mail-prototype", "POST", "/api/v1/app-catalogs/add"))
        self.assertFalse(supervisor.catalog_route_allowed("candidate-sender", "site-publisher", "DELETE", "/api/v1/app-catalogs/personal-catalog"))

    def test_interrupted_catalog_operation_never_automatically_replayed(self):
        supervisor = self.subject()
        runner = Mock()
        supervisor.catalog_prepared = SimpleNamespace(role="candidate-sender", run=runner)
        supervisor.private_work = {"catalogStarted": "durable-original-operation"}
        with self.assertRaisesRegex(runtime.RuntimeFailure, "reconciliation-required"):
            supervisor.catalog_scenarios()
        runner.assert_not_called()

    def test_durable_start_precedes_actual_adapter_and_partial_remains_partial(self):
        supervisor = self.subject()
        order = []
        result = {"status": "partial", "outcomes": {"signedCatalogAdmission": "pass", "bundleRollback": "not-observed"}, "cleanup": "complete"}
        supervisor.catalog_prepared = SimpleNamespace(role="candidate-sender", run=lambda owned: order.append("run") or result)
        supervisor.next_operation = lambda: "durable-operation"
        supervisor.save_state = lambda: order.append("save")
        supervisor.emit = lambda *args, **kwargs: order.append(kwargs["outcome"])
        supervisor.catalog_scenarios()
        self.assertEqual(["save", "run", "save", "partial"], order)
        self.assertEqual("durable-operation", supervisor.private_work["catalogStarted"])
        self.assertEqual("partial", supervisor.outcomes["catalog-provenance"])
        self.assertIs(supervisor.catalog_observation, result)


if __name__ == "__main__": unittest.main()
