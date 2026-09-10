"""Offline fixtures establish integrity rejection, never live observations."""
from __future__ import annotations

import copy
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptad_certification.cross_version_evidence import (
    CASES, EvidenceError, Journal, KIND, SCENARIOS, ZERO, boot_identity, digest, validate_plan, verify,
)


def fixture_plan():
    nodes = []
    for i, role in enumerate(("candidate-sender", "candidate-recipient", "previous", "relay-no-apps")):
        nodes.append({"role": role, "product": "cryptad", "sourceCommit": ("b" if role == "previous" else "a") * 40,
                      "artifactDigest": "sha256:" + ("b" if role == "previous" else "a") * 64,
                      "artifactSize": 100, "packageTarget": "linux-x64", "runtimeDigest": "sha256:" + "c" * 64,
                      "contractVersion": 25, "configDigest": "sha256:" + str(i + 1) * 64,
                      "appDigests": [] if role == "relay-no-apps" else ["sha256:" + "d" * 64]})
    return {"schemaVersion": 1, "kind": KIND, "experimentId": "offline-integrity-test", "profile": "offline-self-test",
            "topologyClass": "single-host-independent-processes", "provenanceClass": "source-build-comparison",
            "requestedSeconds": 100, "probeIntervalSeconds": 1,
            "policy": {"id": "cross-version-observed-v1", "minimumObservedSeconds": 2, "maxGapSeconds": 30, "maxEvents": 1000},
            "requiredScenarios": sorted(SCENARIOS), "producer": {"sourceCommit": "a" * 40, "runnerDigest": "sha256:" + "e" * 64, "adapterDigest": "sha256:" + "f" * 64},
            "nodes": nodes}


def fixture_events(plan=None):
    plan = plan or fixture_plan()
    events = []
    stamp = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    def add(kind, role="", scenario="", operation="", outcome="pass", counters=None, peer_role=""):
        n = len(events)
        clock = sum(e["kind"] != "sample" for e in events)
        events.append({"sequence": n + 1, "previousDigest": digest(events[-1]) if events else ZERO,
                       "planDigest": digest(plan), "epoch": "a" * 32, "wallTime": (stamp + dt.timedelta(seconds=clock)).isoformat(),
                       "monotonicNs": clock * 1000000000, "kind": kind, "role": role, "scenario": scenario,
                       "operation": operation, "outcome": outcome, "counters": counters or {},
                       "nodeEpoch": str(sorted(n["role"] for n in plan["nodes"]).index(role) + 1) * 32 if role else "", "peerRole": peer_role})
        if peer_role:
            events[-1]["peerNodeEpoch"] = str(sorted(row["role"] for row in plan["nodes"]).index(peer_role) + 1) * 32
    add("start")
    for node in plan["nodes"]:
        add("node-start", node["role"])
    add("probe", counters={"operations": 0})
    i = 0
    for scenario in sorted(SCENARIOS):
        for role, peer in CASES[scenario]:
            add("operation", role, scenario, "case-" + str(i), peer_role=peer)
            i += 1
            for node in plan["nodes"]:
                add("sample", node["role"], "app-budgets", counters={"memoryBytes": 100, "threads": 2, "fileDescriptors": 3})
                if node["appDigests"]:
                    add("sample", node["role"], "app-lifecycle", counters={"operations": len(node["appDigests"])})
            add("probe", counters={"operations": i})
    for node in plan["nodes"]:
        add("node-stop", node["role"])
    add("cleanup")
    add("finish")
    return events, checkpoint_for(plan, events)


def checkpoint_for(plan, events, status="complete"):
    return {"schemaVersion": 1, "planDigest": digest(plan), "sequence": len(events),
            "tailDigest": digest(events[-1]) if events else ZERO, "epoch": events[0]["epoch"] if events else "a" * 32, "status": status}


def rechain(events):
    for i, event in enumerate(events):
        event["sequence"] = i + 1
        event["previousDigest"] = digest(events[i - 1]) if i else ZERO


class CrossVersionEvidenceTest(unittest.TestCase):
    def verify_fixture(self, plan=None, events=None, checkpoint=None):
        plan = plan or fixture_plan()
        if events is None:
            events, checkpoint = fixture_events(plan)
        return verify(plan, events, checkpoint or checkpoint_for(plan, events), now=dt.datetime(2026, 2, 1, tzinfo=dt.timezone.utc))

    def test_complete_fixture_is_integrity_only_and_never_release(self):
        result = self.verify_fixture()
        self.assertEqual("verified-local-integrity", result["status"])
        self.assertEqual(2 * sum(map(len, CASES.values())), result["observedEligibleSeconds"])
        self.assertFalse(result["releaseEligible"])
        self.assertEqual("not-authenticated", result["protectedAuthentication"])

    def test_stopped_required_node_cannot_supply_operations_or_coverage(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        stop = copy.deepcopy(events[4])
        stop["kind"] = "node-stop"
        events.insert(5, stop)
        rechain(events)
        result = self.verify_fixture(plan, events, checkpoint_for(plan, events))
        self.assertEqual(0, result["observedEligibleSeconds"])
        self.assertIn("operation-on-stopped-node", result["findings"])

    def test_isolated_recovery_epochs_do_not_replace_main_roles_or_add_coverage(self):
        plan = fixture_plan()
        plan["cohorts"] = [{"id": "previous-to-candidate", "sourceRole": "previous",
                            "targetRole": "candidate-sender", "configDigest": "sha256:" + "5" * 64}]
        events, _ = fixture_events(plan)
        expected = self.verify_fixture(plan, events)["observedEligibleSeconds"]
        # Extra cohort activity occurs at an existing observation time and cannot
        # alter either main participant epoch or fulfill a main required case.
        start = copy.deepcopy(events[3])
        start.update(cohort="previous-to-candidate", nodeEpoch="9" * 32)
        operation = copy.deepcopy(start)
        operation.update(kind="operation", scenario="daemon-upgrade", operation="isolated-check", outcome="partial")
        stop = copy.deepcopy(start)
        stop["kind"] = "node-stop"
        events[4:4] = [start, operation, stop]
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertEqual(expected, result["observedEligibleSeconds"])
        self.assertEqual({"previous-to-candidate": 1}, result["recoveryCohortSamples"])
        self.assertNotIn("runtime-epoch-mismatch", result["findings"])

    def test_cleanup_before_restarted_process_does_not_establish_final_cleanup(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        event = copy.deepcopy(events[-1])
        event.update(kind="node-start", role="previous", nodeEpoch="8" * 32)
        events.insert(-1, event)
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertEqual("not-observed", result["cleanup"])
        self.assertIn("cleanup-not-observed", result["findings"])

    def test_wrong_recipient_epoch_cannot_satisfy_direction(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        event = next(e for e in events if e["kind"] == "operation" and e["peerRole"])
        event["peerNodeEpoch"] = "9" * 32
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertEqual(0, result["observedEligibleSeconds"])
        self.assertIn("peer-runtime-epoch-mismatch", result["findings"])

    def test_one_operation_cannot_be_relabelled_as_different_scenarios(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        operations = [e for e in events if e["kind"] == "operation"]
        operations[1]["operation"] = operations[0]["operation"]
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertIn("operation-replayed", result["findings"])
        self.assertEqual(0, result["observedEligibleSeconds"])

    def test_content_only_intervals_cannot_be_counted_as_complete_experiment_coverage(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        events = [e for e in events if e["kind"] != "sample" or e["scenario"] != "app-lifecycle"]
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertEqual(0, result["observedEligibleSeconds"])
        self.assertIn("observed-duration-insufficient", result["findings"])

    def test_unselected_recovery_cohort_is_rejected(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        events[2]["cohort"] = "previous-to-candidate"
        with self.assertRaisesRegex(EvidenceError, "cohort-binding"):
            self.verify_fixture(plan, events)

    def test_malformed_plan_types_fail_with_closed_error(self):
        for field, value in (("profile", []), ("provenanceClass", {}), ("requiredScenarios", [{}]), ("schemaVersion", True), ("experimentId", 42)):
            plan = fixture_plan()
            plan[field] = value
            with self.assertRaises(EvidenceError):
                validate_plan(plan)

    def test_malformed_event_enum_types_fail_with_closed_error(self):
        plan = fixture_plan()
        for field in ("kind", "outcome", "role", "scenario", "peerRole"):
            events, checkpoint = fixture_events(plan)
            events[6][field] = []
            with self.assertRaises(EvidenceError):
                self.verify_fixture(plan, events, checkpoint)

    def test_current_bytes_cannot_be_relabeled_previous(self):
        plan = fixture_plan()
        plan["nodes"][2]["artifactDigest"] = plan["nodes"][0]["artifactDigest"]
        with self.assertRaisesRegex(EvidenceError, "previous-relabels"):
            validate_plan(plan)

    def test_source_relabel_is_rejected_even_with_different_archive(self):
        plan = fixture_plan()
        plan["nodes"][2]["sourceCommit"] = plan["nodes"][0]["sourceCommit"]
        with self.assertRaises(EvidenceError):
            validate_plan(plan)

    def test_missing_or_duplicate_required_scenario_rejected(self):
        for changed in (sorted(SCENARIOS)[1:], sorted(SCENARIOS) + ["network-chk"], sorted(SCENARIOS) + ["unknown"]):
            plan = fixture_plan()
            plan["requiredScenarios"] = changed
            with self.assertRaises(EvidenceError):
                validate_plan(plan)

    def test_alias_config_and_duplicate_role_rejected(self):
        for field in ("configDigest", "role"):
            plan = fixture_plan()
            plan["nodes"][1][field] = plan["nodes"][0][field]
            with self.assertRaises(EvidenceError):
                validate_plan(plan)

    def test_incompatible_mail_and_installed_relay_rejected(self):
        for role, field, value in ((0, "contractVersion", 24), (3, "appDigests", ["sha256:" + "a" * 64])):
            plan = fixture_plan()
            plan["nodes"][role][field] = value
            with self.assertRaises(EvidenceError):
                validate_plan(plan)

    def test_short_protected_policy_rejected(self):
        plan = fixture_plan()
        plan["profile"] = "protected-long-live"
        with self.assertRaises(EvidenceError):
            validate_plan(plan)

    def test_journal_fork_and_checkpoint_tail_substitution(self):
        plan = fixture_plan()
        events, checkpoint = fixture_events(plan)
        events[6]["previousDigest"] = ZERO
        result = self.verify_fixture(plan, events, checkpoint)
        self.assertIn("journal-lineage-invalid", result["findings"])
        events, checkpoint = fixture_events(plan)
        self.assertIn("checkpoint-substitution-or-truncation", self.verify_fixture(plan, events[:-1], checkpoint)["findings"])

    def test_duplicate_operation_does_not_gain_coverage(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        first, second = [e for e in events if e["kind"] == "operation"][:2]
        second.update({key: first[key] for key in ("scenario", "role", "operation")})
        rechain(events)
        self.assertIn("operation-replayed", self.verify_fixture(plan, events)["findings"])

    def test_clock_discontinuity_and_epoch_change_zero_duration(self):
        for field, value in (("monotonicNs", 0), ("epoch", "b" * 32)):
            plan = fixture_plan()
            events, _ = fixture_events(plan)
            events[8][field] = value
            rechain(events)
            self.assertEqual(0, self.verify_fixture(plan, events)["observedEligibleSeconds"])

    def test_future_time_is_rejected(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        events[-1]["wallTime"] = "2099-01-01T00:00:00+00:00"
        rechain(events)
        self.assertIn("journal-wall-clock-invalid", self.verify_fixture(plan, events)["findings"])

    def test_naive_malformed_and_wrong_type_wall_clock_fail_closed(self):
        for value in ("2026-01-01", "not-a-time", None, 1):
            plan = fixture_plan()
            events, _ = fixture_events(plan)
            events[8]["wallTime"] = value
            rechain(events)
            result = self.verify_fixture(plan, events)
            self.assertIn("journal-wall-clock-invalid", result["findings"])
            self.assertEqual(0, result["observedEligibleSeconds"])

    def test_network_direction_cannot_be_substituted_by_sender_only(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        event = next(e for e in events if e["scenario"] == "network-chk" and e["role"] == "previous")
        event["peerRole"] = ""
        event.pop("peerNodeEpoch", None)
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertIn("network-chk/previous/candidate-recipient", result["missingCases"])
        self.assertIn("operation-outside-required-case", result["findings"])

    def test_runtime_epoch_cannot_be_substituted(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        next(e for e in events if e["kind"] == "operation")["nodeEpoch"] = "e" * 32
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertIn("runtime-epoch-mismatch", result["findings"])
        self.assertEqual(0, result["observedEligibleSeconds"])

    def test_fork_has_no_eligible_duration(self):
        plan = fixture_plan()
        events, checkpoint = fixture_events(plan)
        events[6]["previousDigest"] = ZERO
        self.assertEqual(0, self.verify_fixture(plan, events, checkpoint)["observedEligibleSeconds"])

    def test_idle_probes_do_not_count_duration(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        events = [e for e in events if e["kind"] != "operation"]
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertEqual(0, result["observedEligibleSeconds"])
        self.assertIn("idle-only-run", result["findings"])

    def test_heartbeats_after_one_operation_do_not_count(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        operation_events = [e for e in events if e["kind"] == "operation"]
        events = [e for e in events if e["kind"] != "operation" or e is operation_events[0]]
        rechain(events)
        self.assertEqual(2, self.verify_fixture(plan, events)["observedEligibleSeconds"])

    def test_observation_gap_excluded(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        for event in events[8:]:
            event["monotonicNs"] += 100000000000
            event["wallTime"] = (dt.datetime.fromisoformat(event["wallTime"]) + dt.timedelta(seconds=100)).isoformat()
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertGreater(result["unexplainedGapSeconds"], 100)
        self.assertIn("unexplained-observation-gap", result["findings"])
        self.assertLess(result["observedEligibleSeconds"], 2 * sum(map(len, CASES.values())))

    def test_planned_fault_interval_is_separate_from_eligible_coverage(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        for stamp, kind in ((6, "fault"), (8, "recovery")):
            event = next(e for e in events if e["monotonicNs"] == stamp * 1000000000)
            event.pop("peerNodeEpoch", None)
            event.update({"kind": kind, "role": "candidate-sender", "nodeEpoch": "2" * 32,
                                  "operation": "approved-fault", "scenario": "", "peerRole": "", "counters": {}})
        rechain(events)
        result = self.verify_fixture(plan, events)
        self.assertEqual(2, result["plannedFaultSeconds"])
        self.assertLess(result["observedEligibleSeconds"], 2 * sum(map(len, CASES.values())))
        self.assertNotIn("fault-recovery-lineage-invalid", result["findings"])

    def test_recovery_without_arranged_fault_is_invalid(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        events[7].update({"kind": "recovery", "role": "candidate-sender", "nodeEpoch": "2" * 32,
                          "operation": "unarranged-recovery", "scenario": "", "peerRole": "", "counters": {}})
        rechain(events)
        self.assertIn("fault-recovery-lineage-invalid", self.verify_fixture(plan, events)["findings"])

    def test_failure_dominates_later_success(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        events[6]["outcome"] = "fail"
        rechain(events)
        self.assertEqual("fail", self.verify_fixture(plan, events)["status"])

    def test_canary_fields_cannot_enter_event_or_public_output(self):
        plan = fixture_plan()
        events, checkpoint = fixture_events(plan)
        events[6]["body"] = "private-canary"
        with self.assertRaises(EvidenceError):
            self.verify_fixture(plan, events, checkpoint)
        result = self.verify_fixture()
        self.assertNotIn("operation", result)
        self.assertNotIn("epoch", result)
        self.assertNotIn("wallTime", result)

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_exclusive_lease_rejects_second_controller(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "journal"
            with Journal(root, fixture_plan()) as first:
                first.append("start")
                with self.assertRaises((EvidenceError, BlockingIOError)):
                    Journal(root, fixture_plan())
            with self.assertRaisesRegex(EvidenceError, "authenticated-continuation"):
                Journal(root, fixture_plan())

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_interrupted_run_preserves_partial_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "journal"
            with self.assertRaises(RuntimeError):
                with Journal(root, fixture_plan()) as journal:
                    journal.append("start")
                    raise RuntimeError("interrupted")
            checkpoint = json.loads((root / "checkpoint.json").read_text())
            self.assertEqual("partial", checkpoint["status"])
            self.assertEqual(1, checkpoint["sequence"])
            self.assertEqual(0, root.stat().st_mode & 0o077)

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_failed_checkpoint_cannot_be_overwritten_by_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            with Journal(Path(directory).resolve() / "journal", fixture_plan()) as journal:
                journal.append("start", outcome="fail")
                self.assertEqual("failed", journal.checkpoint("complete")["status"])

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_atomic_checkpoint_failure_keeps_old_complete_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            with Journal(Path(directory).resolve() / "journal", fixture_plan()) as journal:
                journal.append("start")
                journal.checkpoint()
                before = (journal.root / "checkpoint.json").read_bytes()
                with patch("cryptad_certification.cross_version_evidence.os.replace", side_effect=OSError("interrupted")):
                    with self.assertRaises(OSError):
                        journal.checkpoint()
                self.assertEqual(before, (journal.root / "checkpoint.json").read_bytes())
                self.assertFalse((journal.root / "checkpoint.json.new").exists())

    def continuation_fixture(self, directory, failed=False):
        plan = fixture_plan()
        plan["profile"] = "bounded-live"
        root = Path(directory).resolve() / "journal"
        with Journal(root, plan) as journal:
            journal.append("start", outcome="fail" if failed else "pass")
        checkpoint = json.loads((root / "checkpoint.json").read_text())
        import os
        authorization = {"experimentId": plan["experimentId"], "planDigest": digest(plan),
                         "checkpointDigest": digest(checkpoint), "root": str(root),
                         "ownerUid": os.getuid(), "bootId": boot_identity()}
        return plan, root, authorization

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_explicit_same_owner_continuation_starts_distinct_epoch(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, root, authorization = self.continuation_fixture(directory)
            original = json.loads((root / "journal.jsonl").read_text())
            with Journal(root, plan, authorization) as journal:
                self.assertTrue(journal.resumed)
                self.assertEqual("continuation", journal.events[-1]["kind"])
                self.assertNotEqual(original["epoch"], journal.events[-1]["epoch"])
                checkpoint = journal.checkpoint()
                result = verify(plan, journal.events, checkpoint)
                self.assertEqual(1, result["controllerRestarts"])
                self.assertIn("controller-restarted-uninterrupted-soak-unproven", result["findings"])

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_continuation_rejects_wrong_checkpoint_owner_boot_root_or_plan(self):
        for field, value in (("checkpointDigest", ZERO), ("ownerUid", -1), ("bootId", "other"),
                             ("root", "/other"), ("planDigest", ZERO)):
            with tempfile.TemporaryDirectory() as directory:
                plan, root, authorization = self.continuation_fixture(directory)
                authorization[field] = value
                before = (root / "journal.jsonl").read_bytes()
                with self.assertRaises(EvidenceError):
                    Journal(root, plan, authorization)
                self.assertEqual(before, (root / "journal.jsonl").read_bytes())

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_failed_finding_survives_continuation(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, root, authorization = self.continuation_fixture(directory, failed=True)
            with Journal(root, plan, authorization) as journal:
                journal.append("finish")
                checkpoint = journal.checkpoint("complete")
                self.assertEqual("failed", checkpoint["status"])
                self.assertEqual("fail", verify(plan, journal.events, checkpoint)["status"])

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_continuation_rejects_tail_extended_without_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, root, authorization = self.continuation_fixture(directory)
            with (root / "journal.jsonl").open("a") as stream:
                stream.write((root / "journal.jsonl").read_text())
            with self.assertRaises(EvidenceError):
                Journal(root, plan, authorization)

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_continuation_rejects_copied_root_identity(self):
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            plan, root, authorization = self.continuation_fixture(directory)
            clone = Path(directory).resolve() / "clone"
            shutil.copytree(root, clone)
            authorization["root"] = str(clone)
            with self.assertRaisesRegex(EvidenceError, "root-owner-boot-substituted"):
                Journal(clone, plan, authorization)

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_continuation_rejects_finished_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, root, authorization = self.continuation_fixture(directory)
            with Journal(root, plan, authorization) as journal:
                journal.append("finish")
                checkpoint = journal.checkpoint("complete")
            authorization["checkpointDigest"] = digest(checkpoint)
            with self.assertRaises(EvidenceError):
                Journal(root, plan, authorization)

    def test_separate_epochs_are_never_added(self):
        plan = fixture_plan()
        plan["profile"] = "bounded-live"
        events, checkpoint = fixture_events(plan)
        first_seconds = self.verify_fixture(plan, events, checkpoint)["observedEligibleSeconds"]
        # A closed partial checkpoint authenticates the prefix structurally. The local
        # fixture still cannot establish operational authenticity or a continuous soak.
        events.pop()
        prior = checkpoint_for(plan, events, "partial")
        last = events[-1]
        continuation = {**copy.deepcopy(last), "kind": "continuation", "epoch": "b" * 32,
                        "priorCheckpoint": prior, "monotonicNs": last["monotonicNs"] + 1000000000,
                        "wallTime": (dt.datetime.fromisoformat(last["wallTime"]) + dt.timedelta(seconds=1)).isoformat()}
        events.append(continuation)
        second, _ = fixture_events(plan)
        base = dt.datetime.fromisoformat(continuation["wallTime"]) + dt.timedelta(seconds=10)
        for i, event in enumerate(second[1:]):
            event["epoch"] = "b" * 32
            event["monotonicNs"] = continuation["monotonicNs"] + (event["monotonicNs"] + 10 * 1000000000)
            event["wallTime"] = (base + dt.timedelta(seconds=event["monotonicNs"] / 1e9 - continuation["monotonicNs"] / 1e9 - 10)).isoformat()
            if event["operation"]:
                event["operation"] += "-continued"
            events.append(event)
        rechain(events)
        current_checkpoint = checkpoint_for(plan, events)
        current_checkpoint["epoch"] = "b" * 32
        result = self.verify_fixture(plan, events, current_checkpoint)
        self.assertEqual(first_seconds, result["observedEligibleSeconds"])
        self.assertEqual([first_seconds, first_seconds], result["measuredEpochSeconds"])

    @unittest.skipUnless(os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").exists(), "Linux owned-journal integration")
    def test_symlink_root_and_public_permissions_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory).resolve() / "public"
            public.mkdir(mode=0o755)
            link = Path(directory).resolve() / "link"
            link.symlink_to(public)
            for path in (public, link):
                with self.assertRaises(EvidenceError):
                    Journal(path, fixture_plan())


if __name__ == "__main__":
    unittest.main()
