"""Deterministic journal recovery checks supplement the packaged-node integration."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from catalog_origin_lifecycle import Driver, Journal, LifecycleFailure, Subject


class JournalTest(unittest.TestCase):
    def subject(self, catalog="catalog-a", version="1"):
        return Subject("synthetic-app", catalog, "sha256:" + "a" * 64,
                       "sha256:" + "b" * 64, "sha256:" + "c" * 64,
                       "sha256:" + "d" * 64, version)

    def observed(self, subject):
        return {"appId": subject.app_id, "catalogId": subject.catalog_id,
                "bundleDigest": subject.bundle_digest, "installedTreeDigest": subject.installed_tree_digest,
                "signedContentDigest": subject.signed_content_digest,
                "publisherFingerprint": subject.publisher_fingerprint,
                "appVersion": subject.version, "originSchemaVersion": 2, "originDigest": "exact-original"}

    def test_lost_successful_response_reconciles_without_repeating_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = self.subject()
            current = None
            path = Path(temporary) / "journal.json"
            journal = Journal(path, "approved-selection")
            def install():
                nonlocal current
                self.assertIn('"status": "started"', path.read_text())
                current = self.observed(target)
                raise OSError("synthetic lost response")
            result = journal.transition("install", None, target, lambda: current, install)
            self.assertEqual(current, result)
            resumed = Journal(path, "approved-selection")
            result = resumed.transition("install", None, target, lambda: current,
                                        lambda: self.fail("must not replay install"))
            self.assertEqual(current, result)
            self.assertTrue(resumed.value["operations"][0]["reconciled"])

    def test_incomplete_state_requires_recovery_and_different_cohort_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = self.subject()
            path = Path(temporary) / "journal.json"
            journal = Journal(path, "approved-selection")
            def fail():
                raise OSError("synthetic interruption")
            with self.assertRaises(OSError):
                journal.transition("install", None, target, lambda: None, fail)
            with self.assertRaisesRegex(LifecycleFailure, "recovery-required"):
                Journal(path, "approved-selection").transition("install", None, target, lambda: None,
                    lambda: self.fail("must not replay incomplete mutation"))
            with self.assertRaisesRegex(LifecycleFailure, "selection-mismatch"):
                Journal(path, "changed-selection")

    def test_staged_install_or_substituted_bytes_cannot_satisfy_origin(self):
        target = self.subject()
        observed = self.observed(target)
        self.assertTrue(target.matches(observed))
        for key, replacement in (("originSchemaVersion", 1), ("catalogId", "catalog-b"),
                                 ("installedTreeDigest", "substituted"), ("signedContentDigest", "substituted")):
            with self.subTest(key=key):
                self.assertFalse(target.matches(dict(observed, **{key: replacement})))
        self.assertFalse(target.matches(None))

    def test_transition_cohort_requires_distinct_bundles_and_same_publisher(self):
        with self.assertRaisesRegex(LifecycleFailure, "cohort-invalid"):
            Driver(None, {"initial": self.subject(), "update": self.subject(version="2"),
                          "switch": self.subject(catalog="catalog-b", version="3")}, None)

    def test_completed_journal_does_not_accept_replaced_current_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = self.subject()
            current = None
            journal = Journal(Path(temporary) / "journal.json", "approved-selection")
            def install():
                nonlocal current
                current = self.observed(target)
            journal.transition("install", None, target, lambda: current, install)
            current = dict(current, originDigest="substituted-origin")
            with self.assertRaisesRegex(LifecycleFailure, "resume-current-subject"):
                journal.transition("install", None, target, lambda: current,
                                   lambda: self.fail("must not mutate substituted state"))


class OwnedCleanupTest(unittest.TestCase):
    def test_preflight_and_native_timeouts_share_the_remaining_authorized_budget(self):
        import federated_catalog_runtime as runtime
        budget = {"operations": 0, "deadline": 100}
        with patch.object(runtime.time, "monotonic", return_value=95):
            self.assertEqual(5, runtime.remaining_budget(budget, 180))
            self.assertEqual(5, runtime.remaining_budget(budget, 60))
            self.assertEqual(2, runtime.remaining_budget(budget, 2))
        for now in (100, 101):
            with patch.object(runtime.time, "monotonic", return_value=now):
                with self.assertRaisesRegex(LifecycleFailure, "budget-exhausted"):
                    runtime.remaining_budget(budget, 60)

    def test_expired_secondary_role_does_not_prepare_state_or_launch_native_bootstrap(self):
        import federated_catalog_runtime as runtime
        with patch.object(runtime.time, "monotonic", return_value=100), \
                patch.object(runtime.runtime, "make_runtime_config") as configure, \
                patch.object(runtime.subprocess, "run") as native:
            with self.assertRaisesRegex(LifecycleFailure, "budget-exhausted"):
                runtime.execute_secondary_role(None, None, None, None, None, None, None, None,
                                               None, None, {"deadline": 100}, 900, None, None, None)
        configure.assert_not_called()
        native.assert_not_called()

    def test_retained_origin_uses_recorded_signed_revision_after_current_catalog_advances(self):
        import federated_catalog_runtime as runtime
        host = runtime.OwnedHost.__new__(runtime.OwnedHost)
        host.observed_revisions = {}
        origin = {"catalogId": "catalog-a", "selfDigestSha256": "exact-origin",
                  "catalogSignerKeyId": "catalog-key"}
        revision = {"revisionDigest": "sha256:" + "a" * 64, "signatureKeyId": "catalog-key"}
        history = {"revisions": {"catalogId": "catalog-a", "revisions": [{"revision": revision}]}}
        host.ok = Mock(side_effect=[{"health": {"catalogDigest": "a" * 64,
                                                "signatureKeyId": "catalog-key"}}, history, history])
        self.assertEqual(revision, host.retained_revision(origin))
        self.assertEqual(revision, host.retained_revision(origin))
        self.assertEqual(1, sum(call.args[1].endswith("/health") for call in host.ok.call_args_list))
        host.ok = Mock(return_value={"revisions": {"catalogId": "catalog-a", "revisions": [
            {"revision": dict(revision, revisionDigest="sha256:" + "b" * 64)}]}})
        with self.assertRaisesRegex(LifecycleFailure, "retained-revision-not-observed"):
            host.retained_revision(origin)

    def test_role_transition_does_not_reset_shared_operation_or_time_budget(self):
        import federated_catalog_runtime as runtime
        budget = {"operations": 599, "deadline": 20}
        hosts = [runtime.OwnedHost.__new__(runtime.OwnedHost) for _ in range(2)]
        for host in hosts:
            host.budget, host.deadline, host.operations = budget, budget["deadline"], 0
        with patch.object(runtime.time, "monotonic", return_value=10):
            hosts[0].next_operation()
            with self.assertRaisesRegex(LifecycleFailure, "operation-budget-exhausted"):
                hosts[1].next_operation()
        with patch.object(runtime.time, "monotonic", return_value=21):
            with self.assertRaisesRegex(LifecycleFailure, "budget-exhausted"):
                hosts[1].remaining(1)

    def test_unrecorded_start_and_failed_stop_journal_still_terminate_owned_process(self):
        import federated_catalog_runtime as runtime
        host = runtime.OwnedHost.__new__(runtime.OwnedHost)
        node = Mock()
        host.node, host.epochs = node, []
        host.transport = Mock(value={"operations": []})
        host.transport.save.side_effect = OSError("synthetic-journal-unavailable")
        with patch.object(runtime.runtime.interop, "terminate_node") as terminate:
            with self.assertRaises(OSError):
                host.stop()
        terminate.assert_called_once_with(node)
        self.assertIsNone(host.node)
        self.assertEqual("started", host.transport.value["operations"][0]["status"])


if __name__ == "__main__":
    unittest.main()
