"""Offline fault injection into the production own-app scenario adapter; no node execution."""
import copy
import unittest

import cross_version_app_scenarios as scenarios


class Store:
    def __init__(self):
        self.record = None
        self.calls = []
        self.existing = False
        self.mutate_denied = False
        self.deny_cleanup = False

    def refresh_session(self):
        pass

    def request(self, method, path, parameters=None, *, principal):
        self.calls.append((method, path, copy.deepcopy(parameters), principal))
        if path.endswith("/status"):
            return 200, {"status": {"recordCount": int(self.record is not None)}}
        if path.endswith("/queue"):
            return 200, {"queue": {}}
        if "/namespaces/" in path:
            if method == "DELETE":
                if self.deny_cleanup:
                    return 503, {}
                self.record = None
                return 200, {}
            return (200 if self.existing or self.record else 404), {}
        if method == "POST":
            if "ifMatchSha256" in parameters:
                if self.mutate_denied:
                    self.record = parameters.copy()
                return 409, {"error": {"code": "app_data_write_conflict"}}
            self.record = parameters.copy()
            return 201, {"record": {}}
        return 200, {"record": self.record}


class Supervisor:
    def __init__(self):
        self.store = Store()
        self.apps = {("previous", "site-publisher"): self.store}
        self.restarts = []
        self.forget = False
        self.operations = 0

    def next_operation(self):
        self.operations += 1

    def restart_node(self, role):
        self.restarts.append(role)
        if self.forget:
            self.store.record = None


class StableApiTest(unittest.TestCase):
    def test_selected_own_app_round_trip_and_restart_preserve_private_value(self):
        supervisor = Supervisor()
        result = scenarios.stable_api(supervisor, "previous")
        self.assertEqual("observed", result["status"])
        self.assertEqual("observed", result["cleanup"])
        self.assertEqual(["previous"], supervisor.restarts)
        self.assertEqual(supervisor.operations, result["operations"])
        self.assertTrue(all(call[3] == "app" for call in supervisor.store.calls))
        self.assertIsNone(supervisor.store.record)
        self.assertEqual({"status", "cleanup", "operations"}, set(result))

    def test_response_denial_with_storage_side_effect_fails(self):
        supervisor = Supervisor()
        supervisor.store.mutate_denied = True
        self.assertEqual("failed", scenarios.stable_api(supervisor, "previous")["status"])
        self.assertEqual([], supervisor.restarts)

    def test_restart_that_loses_committed_state_fails(self):
        supervisor = Supervisor()
        supervisor.forget = True
        self.assertEqual("failed", scenarios.stable_api(supervisor, "previous")["status"])

    def test_existing_namespace_is_never_mutation_or_cleanup_input(self):
        supervisor = Supervisor()
        supervisor.store.existing = True
        self.assertEqual("failed", scenarios.stable_api(supervisor, "previous")["status"])
        self.assertTrue(all(call[0] == "GET" for call in supervisor.store.calls))

    def test_cleanup_failure_cannot_leave_successful_scenario(self):
        supervisor = Supervisor()
        supervisor.store.deny_cleanup = True
        result = scenarios.stable_api(supervisor, "previous")
        self.assertEqual("failed", result["status"])
        self.assertEqual("cleanup-incomplete", result["cleanup"])

    def test_missing_previous_app_is_not_replaced_with_host_credentials(self):
        supervisor = Supervisor()
        result = scenarios.stable_api(supervisor, "candidate-sender")
        self.assertEqual("not-observed", result["status"])
        self.assertEqual([], supervisor.store.calls)


if __name__ == "__main__":
    unittest.main()
