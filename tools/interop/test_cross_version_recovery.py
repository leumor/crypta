"""Offline recovery driver checks; fixtures are never operational evidence."""
import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import cross_version_recovery as recovery


class RecoveryTest(unittest.TestCase):
    def cohort(self, directory):
        value = recovery.OwnedRecoveryCohort.__new__(recovery.OwnedRecoveryCohort)
        value.root = Path(directory)
        value.subjects = {"previous": {"artifactDigest": "sha256:" + "a" * 64},
                          "candidate-sender": {"artifactDigest": "sha256:" + "b" * 64}}
        value.app = {"bundleDigest": "sha256:" + "c" * 64}
        value.emit = Mock()
        value.next_operation = Mock(side_effect=("operation-" + str(index) for index in range(20)))
        value.close = Mock(return_value="observed")
        value.stop_current = Mock()
        return value

    def test_constructed_cohort_reaches_inherited_spawn_without_catalog_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = recovery.runtime.Supervisor.__new__(recovery.runtime.Supervisor)
            parent.root = Path(directory)
            (parent.root / "runtime").mkdir()
            selection = {"cohortId": recovery.COHORT, "fnpPort": 11001, "fcpPort": 11002, "httpPort": 11003}
            binding = recovery.runtime.canonical_digest(selection)
            parent.authorization = {"recoveryInputsDigest": binding}
            parent.plan = {"cohorts": [{"id": recovery.COHORT, "sourceRole": "previous",
                                       "targetRole": "candidate-sender", "configDigest": binding}],
                           "nodes": [{"role": role, "artifactDigest": role, "runtimeDigest": "tree"}
                                     for role in recovery.SUBJECTS]}
            parent.private = {"nodes": {"previous": {"fnpPort": 12001, "fcpPort": 12002,
                              "httpPort": 12003, "apps": [{"appId": "site-publisher"}]}}}
            parent.remaining = Mock(return_value=10)
            # A selected main catalog must not be inherited by the recovery process.
            parent.catalog_prepared = Mock()
            parent.catalog_environment = {"CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE": "main-only"}

            def prepare(cohort):
                node_root = cohort.root / "node"
                (node_root / "logs").mkdir(parents=True)
                cohort.prepared["previous"] = (cohort.root / "package", node_root,
                    recovery.runtime.interop.Ports(11001, 11002, 0, 0), cohort.root / "jdk", "config")
                cohort.package_identities["previous"] = "tree"
                cohort.private["nodes"]["previous"] = parent.private["nodes"]["previous"]
                cohort.trust_paths["previous"] = cohort.root / "publisher.keys"
                cohort.phase = "prepared"

            with patch.object(recovery.OwnedRecoveryCohort, "_prepare", prepare):
                cohort = recovery.OwnedRecoveryCohort(parent, selection, Mock())
            # Only the process boundary is stopped: launch() and inherited start() run normally.
            with patch.object(recovery.runtime, "tree_digest", return_value="tree"), patch.object(
                    recovery.runtime.subprocess, "Popen", side_effect=RuntimeError("offline-spawn-boundary")) as spawn:
                with self.assertRaisesRegex(RuntimeError, "offline-spawn-boundary"):
                    cohort.launch("previous")
            environment = spawn.call_args.kwargs["env"]
            self.assertEqual("bubblewrap", environment["CRYPTAD_APPHOST_SANDBOX_PROVIDER"])
            self.assertIn("CRYPTAD_APPHOST_TRUSTED_KEYS_FILE", environment)
            self.assertNotIn("CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE", environment)
            self.assertNotIn("CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_KEYS_FILE", environment)
            self.assertTrue(spawn.call_args.kwargs["stdout"].closed)
            self.assertTrue(spawn.call_args.kwargs["stderr"].closed)

    def test_previous_and_current_apis_compare_actual_values_and_keep_backup_private(self):
        with tempfile.TemporaryDirectory() as directory:
            cohort = self.cohort(directory)
            payload = base64.b64encode(b"private-value").decode()
            previous, current, restarted = Mock(), Mock(), Mock()
            previous.request.side_effect = [(404, {}), (201, {}), (200, {"record": {"valueBase64": payload}}),
                                            (200, {"payloadBase64": "private-backup"})]
            current.request.side_effect = [(200, {"record": {"valueBase64": payload}}), (201, {})]
            changed = base64.b64encode(b"private-valuechanged").decode()
            current_value = base64.b64encode(b"private-valuecurrent-write").decode()
            restarted.request.side_effect = [(200, {"record": {"valueBase64": current_value}}), (201, {}),
                                             (200, {"record": {"valueBase64": changed}}),
                                             (200, {"restorePlan": {"status": "ready"}}),
                                             (200, {"restoreResult": {"restored": True, "status": "restored"}}), (200, {"record": {"valueBase64": payload}})]
            cohort.launch = Mock(side_effect=[previous, restarted])
            cohort.transition = Mock(return_value=current)
            with patch.object(recovery.secrets, "token_bytes", return_value=b"private-value"):
                result = recovery.observe_upgrade(cohort)
            self.assertEqual("previous", cohort.launch.call_args_list[0].args[0])
            self.assertEqual("candidate-sender", cohort.launch.call_args_list[1].args[0])
            self.assertEqual("app", previous.request.call_args_list[1].kwargs["principal"])
            self.assertNotIn("principal", previous.request.call_args_list[-1].kwargs)
            self.assertEqual("observed", result["daemonUpgrade"])
            self.assertEqual("observed", result["privateRestore"])
            self.assertEqual("not-observed", result["unsafeDowngrade"])
            self.assertEqual("not-observed", result["mailRestore"])
            self.assertNotIn("private-value", str(result))
            self.assertNotIn("private-backup", str(result))
            self.assertEqual(0o600, (cohort.root / "private-app-backup.json").stat().st_mode & 0o777)
            with recovery.runtime.fixed_helper_imports():
                from cryptad_certification.cross_version_evidence import Journal, verify
                from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
            plan = fixture_plan()
            plan["cohorts"] = [{"id": recovery.COHORT, "sourceRole": "previous", "targetRole": "candidate-sender", "configDigest": "sha256:" + "d" * 64}]
            with Journal(cohort.root / "journal-test", plan) as journal:
                journal.append("start")
                role = "previous"
                journal.append("node-start", role=role, cohort=recovery.COHORT)
                for call in cohort.emit.call_args_list:
                    self.assertEqual("operation", call.args[0])
                    self.assertEqual("partial", call.kwargs["outcome"])
                    if call.kwargs["role"] != role:
                        journal.append("node-stop", role=role, cohort=recovery.COHORT)
                        role = call.kwargs["role"]
                        journal.append("node-start", role=role, cohort=recovery.COHORT)
                    journal.append(call.args[0], cohort=recovery.COHORT, **call.kwargs)
                journal.append("node-stop", role=role, cohort=recovery.COHORT)
                journal.append("cleanup", role=role, cohort=recovery.COHORT)
                journal.append("finish")
                checked = verify(plan, journal.events, journal.checkpoint("complete"))
            self.assertNotIn("fault-recovery-lineage-invalid", checked["findings"])
            self.assertEqual(3, checked["recoveryCohortSamples"][recovery.COHORT])

    def test_current_read_mismatch_fails_and_still_cleans_owned_cohort(self):
        with tempfile.TemporaryDirectory() as directory:
            cohort = self.cohort(directory)
            previous, current = Mock(), Mock()
            payload = base64.b64encode(b"expected").decode()
            previous.request.side_effect = [(404, {}), (201, {}), (200, {"record": {"valueBase64": payload}}),
                                            (200, {"payloadBase64": "private-backup"})]
            current.request.return_value = (200, {"record": {"valueBase64": "substituted"}})
            cohort.launch = Mock(return_value=previous)
            cohort.transition = Mock(return_value=current)
            with patch.object(recovery.secrets, "token_bytes", return_value=b"expected"):
                result = recovery.observe_upgrade(cohort)
            self.assertEqual("failed", result["status"])
            self.assertEqual("not-observed", result["daemonUpgrade"])
            cohort.close.assert_called_once()

    def test_downgrade_is_rejected_before_starting_old_bytes(self):
        cohort = recovery.OwnedRecoveryCohort.__new__(recovery.OwnedRecoveryCohort)
        cohort.current_role = None
        cohort.phase = "running-candidate-sender"
        cohort.start = Mock()
        with self.assertRaisesRegex(recovery.RecoveryFailure, "downgrade-storage-compatibility-unestablished"):
            cohort.launch("previous")
        cohort.start.assert_not_called()

    def test_caller_written_result_is_not_an_owned_cohort(self):
        with self.assertRaisesRegex(recovery.RecoveryFailure, "owned-recovery-cohort-required"):
            recovery.observe_upgrade({"daemonUpgrade": "observed"})

    def test_selected_recovery_ports_cannot_alias_main_nodes(self):
        supervisor = recovery.runtime.Supervisor.__new__(recovery.runtime.Supervisor)
        selected = {"cohortId": recovery.COHORT, "fnpPort": 11001, "fcpPort": 11002, "httpPort": 11003}
        supervisor.authorization = {"recoveryInputsDigest": recovery.runtime.canonical_digest(selected)}
        supervisor.plan = {"cohorts": [{"id": recovery.COHORT, "sourceRole": "previous", "targetRole": "candidate-sender",
                                        "configDigest": recovery.runtime.canonical_digest(selected)}]}
        supervisor.private = {"nodes": {"previous": {"fnpPort": 11001, "fcpPort": 12002, "httpPort": 12003}}}
        with self.assertRaisesRegex(recovery.RecoveryFailure, "port-binding"):
            recovery.validate_selection(supervisor, selected)

    def test_missing_separate_recovery_authority_denies_before_root_creation(self):
        supervisor = recovery.runtime.Supervisor.__new__(recovery.runtime.Supervisor)
        supervisor.authorization = {}
        selected = {"cohortId": recovery.COHORT, "fnpPort": 11001, "fcpPort": 11002, "httpPort": 11003}
        with self.assertRaisesRegex(recovery.RecoveryFailure, "selection-not-authorized"):
            recovery.OwnedRecoveryCohort(supervisor, selected, Mock())


if __name__ == "__main__":
    unittest.main()
