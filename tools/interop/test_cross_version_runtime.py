"""Offline tests of production archive/admission/HTTP adapters; never launch a node."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

import cross_version_runtime as runtime


class RuntimeSubjectBindingTest(unittest.TestCase):
    def test_contract_identity_is_checked_before_any_app_install(self):
        supervisor = runtime.Supervisor.__new__(runtime.Supervisor)
        supervisor.private = {'nodes': {role: {'apps': []} for role in runtime.ROLES}}
        supervisor.plan = {'nodes': [{'role': role, 'contractVersion': 25} for role in runtime.ROLES]}
        supervisor.product_admission = Mock()
        supervisor.product_admission.verify_runtime_contract.side_effect = ValueError('exact-contract-substituted')
        payload = {'contract': {'contractVersion': 25, 'capabilities': []}}
        with patch.object(runtime, 'AppHandle') as handle:
            handle.return_value.request.return_value = (200, payload)
            with self.assertRaisesRegex(ValueError, 'exact-contract-substituted'):
                supervisor.provision_apps()
        supervisor.product_admission.verify_runtime_contract.assert_called_once_with(runtime.ROLES[0], payload)
        handle.return_value.request.assert_called_once_with('GET', '/api/v1/platform/contract')


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, entries):
        path = self.root / "package.tar"
        with tarfile.open(path, "w") as archive:
            for name, kind, body in entries:
                info = tarfile.TarInfo(name)
                info.mode = 0o755
                if kind == "link":
                    info.type = tarfile.SYMTYPE
                    info.linkname = body
                    archive.addfile(info)
                else:
                    info.size = len(body)
                    archive.addfile(info, io.BytesIO(body))
        return path

    def extract(self, path):
        return runtime.extract_package(path, self.root / "out", runtime.digest_file(path), path.stat().st_size)

    def test_exact_package_preserves_executable_and_confines_tree(self):
        path = self.archive([("bin/cryptad", "file", b"#!/bin/sh\nexit 0\n"), ("lib/a.jar", "file", b"fixture")])
        result = self.extract(path)
        self.assertEqual(self.root / "out", result)
        self.assertEqual(b"fixture", (result / "lib/a.jar").read_bytes())
        self.assertTrue(os.access(result / "bin/cryptad", os.X_OK))
        self.assertEqual(0, result.stat().st_mode & 0o077)

    def test_digest_mismatch_precedes_extraction(self):
        path = self.archive([("bin/cryptad", "file", b"fixture")])
        with self.assertRaisesRegex(runtime.RuntimeFailure, "artifact-digest-mismatch"):
            runtime.extract_package(path, self.root / "out", "sha256:" + "0" * 64, path.stat().st_size)
        self.assertFalse((self.root / "out").exists())

    def test_wrong_size_precedes_extraction(self):
        path = self.archive([("bin/cryptad", "file", b"fixture")])
        with self.assertRaisesRegex(runtime.RuntimeFailure, "artifact-size-mismatch"):
            runtime.extract_package(path, self.root / "out", runtime.digest_file(path), path.stat().st_size + 1)

    def test_traversal_link_and_case_collision_rejected(self):
        cases = [[("../escape", "file", b"x")], [("/escape", "file", b"x")],
                 [("escape", "link", "/tmp/private")], [("a", "file", b"x"), ("A", "file", b"y")],
                 [("parent", "file", b"x"), ("parent/child", "file", b"x")]]
        for entries in cases:
            with self.subTest(entries=entries):
                path = self.archive(entries)
                with self.assertRaises(runtime.RuntimeFailure):
                    self.extract(path)
                self.assertFalse((self.root / "out").exists())

    def test_existing_destination_is_never_deleted(self):
        destination = self.root / "out"
        destination.mkdir()
        (destination / "personal").write_text("retain")
        path = self.archive([("bin/cryptad", "file", b"fixture")])
        with self.assertRaisesRegex(runtime.RuntimeFailure, "extraction-target-exists"):
            self.extract(path)
        self.assertEqual("retain", (destination / "personal").read_text())

    def test_archive_byte_and_count_budgets(self):
        path = self.archive([("bin/cryptad", "file", b"fixture")])
        with patch.object(runtime, "MAX_FILES", 0), self.assertRaisesRegex(runtime.RuntimeFailure, "member-budget"):
            self.extract(path)
        with patch.object(runtime, "MAX_EXPANDED", 1), self.assertRaisesRegex(runtime.RuntimeFailure, "expanded-budget"):
            self.extract(path)

    def test_runtime_digest_changes_for_loaded_library_bytes(self):
        home = self.root / "jdk"
        (home / "bin").mkdir(parents=True)
        (home / "bin/java").write_bytes(b"fixture java")
        (home / "lib").mkdir()
        library = home / "lib/runtime.so"
        library.write_bytes(b"first")
        first = runtime.tree_digest(home)
        library.write_bytes(b"second")
        self.assertNotEqual(first, runtime.tree_digest(home))

    def test_runtime_total_byte_budget_is_checked_before_hashing(self):
        home = self.root / "jdk"
        (home / "bin").mkdir(parents=True)
        (home / "bin/java").write_bytes(b"large fixture")
        with patch.object(runtime, "MAX_EXPANDED", 1), patch.object(runtime, "digest_file") as digest:
            with self.assertRaisesRegex(runtime.RuntimeFailure, "runtime-byte-budget"):
                runtime.tree_digest(home)
            digest.assert_not_called()

    def test_runtime_link_cannot_import_unselected_host_libraries(self):
        home = self.root / "jdk"
        (home / "bin").mkdir(parents=True)
        (home / "bin/java").write_bytes(b"fixture java")
        outside = self.root / "unselected"
        outside.write_bytes(b"private")
        (home / "linked").symlink_to(outside)
        with self.assertRaisesRegex(runtime.RuntimeFailure, "outside-selected-tree"):
            runtime.tree_digest(home)

    def test_signed_app_zip_is_confined_without_interpreting_declarations(self):
        archive = self.root / "app.zip"
        with zipfile.ZipFile(archive, "w") as writer:
            writer.writestr("cryptad-app.properties", "app.id=mail-prototype")
            writer.writestr("static/app.js", "fixture")
        runtime.extract_app_bundle(archive, self.root / "app", runtime.digest_file(archive))
        self.assertEqual("app.id=mail-prototype", (self.root / "app/cryptad-app.properties").read_text())

    def test_app_zip_traversal_and_link_rejected(self):
        for name in ("../private", "/private", "a\\private"):
            archive = self.root / "app.zip"
            with zipfile.ZipFile(archive, "w") as writer:
                writer.writestr(name, "never")
            with self.assertRaises(runtime.RuntimeFailure):
                runtime.extract_app_bundle(archive, self.root / "app", runtime.digest_file(archive))
            self.assertFalse((self.root / "app").exists())

    def test_packaged_source_marker_cannot_be_relabelled_as_previous(self):
        distribution = self.root / "distribution"
        (distribution / "lib").mkdir(parents=True)
        jar = distribution / "lib/cryptad.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nImplementation-Version: 200 abcdef123\r\n\r\n")
        self.assertEqual(runtime.digest_file(jar), runtime.packaged_daemon_identity(distribution, "abcdef123" + "0" * 31))
        with self.assertRaisesRegex(runtime.RuntimeFailure, "embedded-source-mismatch"):
            runtime.packaged_daemon_identity(distribution, "1" * 40)

    def test_packaged_authenticated_build_marker_cannot_be_changed(self):
        distribution = self.root / "distribution"
        (distribution / "lib").mkdir(parents=True)
        with zipfile.ZipFile(distribution / "lib/cryptad.jar", "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Version: 200 abcdef123\n\n")
        with self.assertRaisesRegex(runtime.RuntimeFailure, "embedded-build-mismatch"):
            runtime.packaged_daemon_identity(distribution, "abcdef123" + "0" * 31, "199")

    def test_native_target_checks_actual_elf_and_selected_host(self):
        distribution = self.root / "distribution"
        (distribution / "bin").mkdir(parents=True)
        java_home = self.root / "jdk"
        (java_home / "bin").mkdir(parents=True)
        header = bytearray(20)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (62).to_bytes(2, "little")
        wrapper = distribution / "bin/wrapper-linux-x86-64"
        wrapper.write_bytes(header)
        (java_home / "bin/java").write_bytes(header)
        with patch.object(runtime.os, "uname", return_value=Mock(machine="x86_64")):
            runtime.require_native_target(distribution, "linux-x64", java_home)
            header[18:20] = (183).to_bytes(2, "little")
            wrapper.write_bytes(header)
            with self.assertRaisesRegex(runtime.RuntimeFailure, "native-architecture-mismatch"):
                runtime.require_native_target(distribution, "linux-x64", java_home)

    def test_generated_configuration_binds_role_and_opaque_ports(self):
        values = []
        for role, port in (("candidate-sender", 20000), ("candidate-recipient", 21000)):
            node_root = self.root / role / "node"
            config = runtime.interop.make_cryptad_config(node_root, runtime.interop.Ports(port, port + 1, 0, 0))
            values.append(runtime.config_identity(config, node_root, port, port + 1))
        self.assertNotEqual(*values)


class DeadlineTest(unittest.TestCase):
    def test_whole_operation_deadline_interrupts_slow_progress(self):
        with self.assertRaisesRegex(runtime.RuntimeFailure, "operation-deadline-exceeded"):
            with runtime.absolute_deadline(.01):
                signal.pause()
        self.assertEqual((0.0, 0.0), signal.getitimer(signal.ITIMER_REAL))

    def test_nested_timer_cannot_silently_override_supervisor_deadline(self):
        with runtime.absolute_deadline(1):
            with self.assertRaisesRegex(runtime.RuntimeFailure, "nested-process-timer-rejected"):
                with runtime.absolute_deadline(.01):
                    self.fail("nested scope entered")


class HttpAdapterTest(unittest.TestCase):
    def setUp(self):
        self.supervisor = Mock()
        self.supervisor.private = {"nodes": {"candidate-sender": {"httpPort": 8888}}}
        self.supervisor.remaining.return_value = 1
        self.handle = runtime.AppHandle(self.supervisor, "candidate-sender", "mail-prototype")

    def test_unselected_host_route_rejected_before_http(self):
        with patch.object(self.handle.opener, "open") as opened:
            with self.assertRaisesRegex(runtime.RuntimeFailure, "route-not-approved"):
                self.handle.request("POST", "/api/v1/arbitrary-exec", {"script": "never"})
            opened.assert_not_called()

    def test_host_password_cannot_substitute_for_missing_app_session(self):
        self.handle.password = "private-host-token"
        with patch.object(self.handle.opener, "open") as opened:
            with self.assertRaisesRegex(runtime.RuntimeFailure, "own-app-session-unavailable"):
                self.handle.request("POST", "/api/v1/mail/command", {}, principal="app")
            opened.assert_not_called()

    def test_fresh_bootstrap_replaces_expired_session_without_host_credentials(self):
        self.handle.session = "expired"
        with patch.object(self.handle, "request", return_value=(200, {"uiOrigin": "http://127.0.0.1:9001", "browserSessionToken": "fresh"})) as request:
            self.handle.refresh_session()
        self.assertEqual("fresh", self.handle.session)
        self.assertEqual(("GET", "/apps/mail-prototype/.well-known/cryptad-bootstrap.json"), request.call_args.args)

    def test_remote_or_shared_origin_never_becomes_app_principal(self):
        for origin in ("http://example.org:9001", "http://127.0.0.1:8888"):
            with patch.object(self.handle, "request", return_value=(200, {"uiOrigin": origin, "browserSessionToken": "fresh"})):
                with self.assertRaises((runtime.RuntimeFailure, runtime.mail_demo.DemoFailure)):
                    self.handle.refresh_session()

    def test_real_sandbox_required_even_with_running_status(self):
        response = {"runtime": {"running": True, "pid": os.getpid(), "sandbox": {"provider": "best-effort", "active": True}}}
        with patch.object(self.handle, "request", return_value=(200, response)):
            with self.assertRaisesRegex(runtime.RuntimeFailure, "real-app-sandbox"):
                self.handle.observe_worker()

    def test_empty_successful_delete_response_does_not_hide_cleanup_success(self):
        self.handle.session = "private-session"
        self.handle.origin = "http://127.0.0.1:9001"
        response = io.BytesIO(b"")
        response.status = 204
        with patch.object(self.handle.opener, "open", return_value=response):
            self.assertEqual((204, {}), self.handle.request("DELETE", "/api/v1/app-data/namespaces/synthetic", principal="app"))

    def test_host_bootstrap_uses_actual_embedded_json_and_rejects_duplicate(self):
        html = b'<script type="application/json" id="web-shell-bootstrap">{"formPassword":"private"}</script>'
        with patch.object(self.handle, "request", return_value=(200, html)):
            self.handle.host_bootstrap()
        self.assertEqual("private", self.handle.password)
        with patch.object(self.handle, "request", return_value=(200, html + html)):
            with self.assertRaisesRegex(runtime.RuntimeFailure, "bootstrap-unavailable"):
                self.handle.host_bootstrap()



class SupervisorBehaviorTest(unittest.TestCase):
    def supervisor(self):
        instance = runtime.Supervisor.__new__(runtime.Supervisor)
        instance.nodes = {}
        instance.resume_pending_roles = set()
        instance.orphaned_spawn = False
        instance.operations = 0
        instance.observed_operations = 0
        instance.authorization = {"maxOperations": 10}
        instance.outcomes = {}
        instance.journal = Mock()
        instance.remaining = Mock(return_value=1)
        return instance

    def test_content_compares_actual_opposite_fetch_and_forces_remote_path(self):
        instance = self.supervisor()
        sender, receiver = Mock(), Mock()
        @contextlib.contextmanager
        def client(role):
            yield sender if role == "candidate-sender" else receiver
        instance.client = client
        captured = {}
        def inserted(_client, _operation, _uri, payload, _type, **kwargs):
            captured["payload"] = payload
            self.assertTrue(kwargs["local_request_only"])
            return "CHK@private-test-reference"
        def fetched(_client, _operation, _reference, _timeout, **kwargs):
            self.assertIs(receiver, _client)
            self.assertTrue(kwargs["ignore_ds"])
            return captured["payload"]
        with patch.object(runtime.interop, "put_and_wait_for_success", side_effect=inserted), patch.object(runtime.interop, "fetch_direct", side_effect=fetched):
            instance.content("candidate-sender", "previous")
        event = instance.journal.append.call_args.kwargs
        self.assertEqual("previous", event["peer_role"])
        self.assertEqual("network-chk", event["scenario"])
        self.assertNotIn("CHK@", json.dumps(event))
        self.assertEqual(1, instance.observed_operations)

    def test_wrong_remote_bytes_never_emit_passing_operation(self):
        instance = self.supervisor()
        @contextlib.contextmanager
        def client(_role):
            yield Mock()
        instance.client = client
        with patch.object(runtime.interop, "put_and_wait_for_success", return_value="CHK@private"), patch.object(runtime.interop, "fetch_direct", return_value=b"wrong"):
            with self.assertRaisesRegex(runtime.RuntimeFailure, "content-mismatch"):
                instance.content("candidate-sender", "previous")
        instance.journal.append.assert_not_called()
        self.assertEqual({}, instance.outcomes)

    def test_action_budget_denies_before_network(self):
        instance = self.supervisor()
        instance.authorization["maxOperations"] = 0
        instance.client = Mock()
        with self.assertRaisesRegex(runtime.RuntimeFailure, "operation-budget"):
            instance.content("candidate-sender", "previous")
        instance.client.assert_not_called()

    def test_pid_reuse_blocks_process_group_signal(self):
        instance = self.supervisor()
        node = Mock()
        node.runtime.process.poll.return_value = None
        node.runtime.process.pid = 12345
        node.identity = {"pid": 12345, "startTicks": 100, "bootId": "old"}
        instance.nodes["previous"] = node
        with patch.object(runtime, "process_identity", return_value={"pid": 12345, "startTicks": 200, "bootId": "old"}), patch.object(runtime.interop, "terminate_node") as stop:
            with self.assertRaisesRegex(runtime.RuntimeFailure, "identity-changed"):
                instance.stop("previous")
            stop.assert_not_called()

    def test_exited_leader_records_stop_only_after_owned_group_disappeared(self):
        for gone in (True, False):
            instance = self.supervisor()
            node = Mock()
            node.runtime.process.poll.return_value = 0
            node.runtime.process.pid = 12345
            instance.nodes["previous"] = node
            with patch.object(runtime.os, "killpg", side_effect=ProcessLookupError if gone else None) as check, patch.object(runtime.interop, "terminate_node") as terminate:
                if gone:
                    instance.stop("previous")
                    self.assertEqual("node-stop", instance.journal.append.call_args.args[0])
                else:
                    with self.assertRaisesRegex(runtime.RuntimeFailure, "group-remains"):
                        instance.stop("previous")
                    instance.journal.append.assert_not_called()
                check.assert_called_once_with(12345, 0)
                terminate.assert_not_called()
                node.runtime.stdout_handle.close.assert_called_once()
                node.runtime.stderr_handle.close.assert_called_once()

    def test_cleanup_continues_after_one_owned_process_failure(self):
        instance = self.supervisor()
        instance.prepared = {}
        instance.stop = Mock(side_effect=[runtime.RuntimeFailure("cleanup-blocked"), None, None, None])
        self.assertEqual("cleanup-incomplete", instance.cleanup())
        self.assertEqual(4, instance.stop.call_count)
        self.assertEqual("fail", instance.journal.append.call_args.kwargs["outcome"])

    def test_partial_resume_keeps_reconciliation_state_and_cannot_claim_cleanup(self):
        instance = self.supervisor()
        instance.resume_pending_roles = {"previous"}
        instance.prepared = {"candidate-sender": ()}
        instance.stop = Mock()
        with tempfile.TemporaryDirectory() as directory:
            instance.root = Path(directory)
            (instance.root / "runtime").mkdir()
            state = instance.root / "runtime/runtime-state.json"
            state.write_text("original-private-reconciliation-record")
            self.assertEqual("cleanup-incomplete", instance.cleanup())
            self.assertEqual("original-private-reconciliation-record", state.read_text())

    def test_unauthenticated_or_replaced_private_state_never_attaches(self):
        instance = self.supervisor()
        with tempfile.TemporaryDirectory() as directory:
            instance.root = Path(directory)
            (instance.root / "runtime").mkdir()
            (instance.root / "runtime/runtime-state.json").write_text('{"nodes":{"previous":{"pid":123}}}')
            instance.authorization = {"runtimeStateDigest": "sha256:" + "0" * 64}
            with patch.object(runtime, "_ContinuedProcess") as process:
                with self.assertRaisesRegex(runtime.RuntimeFailure, "continuation-state-mismatch"):
                    instance.resume_owned()
                process.assert_not_called()


class RecoveryProtocolTest(unittest.TestCase):
    def test_persistent_request_must_retain_exact_identifier_uri_and_scope(self):
        original = {"name": "PersistentGet", "fields": {"Identifier": "original", "URI": "USK@private/site/0", "Persistence": "forever", "Global": "false"}}
        self.assertEqual(original, runtime.require_persistent_identity([original], "original", "USK@private/site/0"))
        for requests in ([], [original, original], [{"name": "PersistentGet", "fields": {**original["fields"], "URI": "USK@substituted/site/0"}}],
                         [{"name": "PersistentGet", "fields": {**original["fields"], "Persistence": "connection"}}]):
            with self.assertRaises(runtime.RuntimeFailure):
                runtime.require_persistent_identity(requests, "original", "USK@private/site/0")

    def test_list_persistent_original_identity_is_admitted_without_allowing_another(self):
        client = runtime.BoundedFcpClient.__new__(runtime.BoundedFcpClient)
        client.sock = Mock()
        client.expected_identifier = "listing"
        client.allowed_identifiers = {"original"}
        client._log_message = Mock()
        client.file = io.BytesIO(b"PersistentGet\nIdentifier=original\nURI=USK@private/site/0\nEndMessage\n")
        self.assertEqual("PersistentGet", client.read_message(1).name)
        client.file = io.BytesIO(b"PersistentGet\nIdentifier=unrelated\nEndMessage\n")
        with self.assertRaisesRegex(runtime.RuntimeFailure, "operation-binding"):
            client.read_message(1)

    def subscription(self, notification):
        supervisor = runtime.Supervisor.__new__(runtime.Supervisor)
        supervisor.next_operation = Mock(return_value="original")
        supervisor.remaining = Mock(return_value=120)
        supervisor.plan = {"probeIntervalSeconds": 1}
        supervisor.outcomes = {}
        supervisor.emit = Mock()
        wire = Mock()
        wire.read_until.return_value = runtime.interop.FcpFrame("SubscribedUSK", {"Identifier": "original"})
        @contextlib.contextmanager
        def client(_role):
            yield wire
        supervisor.client = client
        payloads = []
        def put(_client, _identifier, _uri, payload, _type, **_kwargs):
            payloads.append(payload)
            return "USK@private/site/0"
        def fetch(*_args, **_kwargs):
            return payloads[-1]
        with patch.object(runtime.interop, "generate_ssk", return_value=("SSK@insert", "SSK@request")), patch.object(runtime.interop, "put_and_wait_for_success", side_effect=put), patch.object(runtime.interop, "fetch_direct", side_effect=fetch), patch.object(runtime.interop, "wait_for_subscription_update", return_value=(1 if notification else None, {"SubscribedUSKUpdate": 1} if notification else {}, [])), patch.object(runtime.time, "monotonic", side_effect=[0, 100]):
            supervisor.subscribe("candidate-sender", "previous")
        return supervisor, wire

    def test_fetch_fallback_cannot_pass_subscription_notification(self):
        supervisor, wire = self.subscription(False)
        self.assertEqual("not-observed", supervisor.emit.call_args.kwargs["outcome"])
        self.assertEqual("UnsubscribeUSK", wire.send.call_args.args[0])
        self.assertIn("fetch-observed-not-notification", supervisor.outcomes.values())

    def test_later_notification_and_exact_fetched_content_produce_directional_observation(self):
        supervisor, wire = self.subscription(True)
        self.assertEqual("network-subscription", supervisor.emit.call_args.args[2])
        self.assertEqual("previous", supervisor.emit.call_args.kwargs["peer_role"])
        self.assertIn("notification-observed", supervisor.outcomes.values())


class AdmissionTest(unittest.TestCase):
    def test_runner_identity_binds_actual_python_bytes_without_exporting_host_path(self):
        identity = runtime.runner_python_identity()
        self.assertEqual(runtime.digest_file(Path("/proc/self/exe")), identity["executableDigest"])
        self.assertEqual(runtime.sys.version, identity["version"])
        self.assertNotIn(str(Path(runtime.sys.executable).resolve()), json.dumps(identity))
        self.assertEqual("not-established", identity["osImageAuthentication"])

    def test_selected_python_cannot_lie_about_actual_running_executable(self):
        with tempfile.NamedTemporaryFile() as selected:
            selected.write(b"unrelated executable")
            selected.flush()
            with patch.object(runtime.sys, "executable", selected.name):
                with self.assertRaisesRegex(runtime.RuntimeFailure, "python-executable-mismatch"):
                    runtime.runner_python_identity()

    def test_protected_and_offline_inputs_cannot_reach_process_start(self):
        for profile, provenance in (("protected-long-live", "source-build-comparison"),
                                    ("offline-self-test", "source-build-comparison")):
            with patch.object(runtime.subprocess, "Popen") as start:
                with self.assertRaises(runtime.RuntimeFailure):
                    runtime.Supervisor({"profile": profile, "provenanceClass": provenance}, {"root": "/unused"}, {}, Mock())
                start.assert_not_called()

    def test_protected_missing_original_activation_cannot_admit_runner(self):
        with self.assertRaisesRegex(runtime.RuntimeFailure, "protected-runner-authority-unavailable"):
            runtime.authenticate_runner_selection({"profile": "protected-long-live"}, {}, {})

    def test_protected_remaining_uses_current_authority_deadline_and_rejects_substitution(self):
        supervisor = runtime.Supervisor.__new__(runtime.Supervisor)
        supervisor._check_resources = Mock()
        supervisor.deadline = 1000
        supervisor.plan, supervisor.private, supervisor.authorization = {}, {}, {}
        supervisor.runner_admission = Mock()
        supervisor.runner_admission.public_identity.return_value = {"original": "selected"}
        current = Mock()
        current.public_identity.return_value = {"original": "selected"}
        current.remaining_seconds.return_value = 2
        with patch.object(runtime.time, "monotonic", return_value=100), patch.object(runtime, "authenticate_runner_selection", return_value=current):
            self.assertEqual(2, supervisor.remaining(30))
            current.public_identity.return_value = {"original": "substituted"}
            with self.assertRaisesRegex(runtime.RuntimeFailure, "authority-substitution"):
                supervisor.remaining(30)

    def test_production_package_labels_without_original_coordinates_cannot_admit(self):
        with self.assertRaisesRegex(runtime.RuntimeFailure, "original-product-selection-required"):
            runtime.authenticate_product_selection({"provenanceClass": "production-artifact-comparison"}, {})

    def test_missing_explicit_target_authority_denies_before_artifact_execution(self):
        with patch.object(runtime.subprocess, "Popen") as start:
            with self.assertRaisesRegex(runtime.RuntimeFailure, "exact-topology-authorization"):
                runtime.Supervisor({"profile": "bounded-live", "provenanceClass": "source-build-comparison"},
                                   {"root": "/unused", "nodes": {}}, {}, Mock())
            start.assert_not_called()


class PartitionTest(unittest.TestCase):
    def test_get_failed_for_the_original_request_proves_bounded_denial(self):
        receiver = Mock()
        receiver.read_until.return_value = runtime.interop.FcpFrame("GetFailed", {"Identifier": "original", "Code": "14"})
        self.assertTrue(runtime.observe_partition_denial(receiver, "original", "CHK@private"))
        self.assertEqual("true", receiver.send.call_args.args[1]["IgnoreDS"])

    def test_protocol_error_is_not_accepted_as_network_denial(self):
        receiver = Mock()
        receiver.read_until.side_effect = runtime.interop.InteropFailure("ProtocolError")
        with self.assertRaises(runtime.interop.InteropFailure):
            runtime.observe_partition_denial(receiver, "original", "CHK@private")

    def test_unrelated_failure_and_invalid_uri_code_do_not_pass_partition(self):
        receiver = Mock()
        receiver.read_until.return_value = runtime.interop.FcpFrame("GetFailed", {"Identifier": "unrelated", "Code": "14"})
        with self.assertRaisesRegex(runtime.RuntimeFailure, "operation-binding"):
            runtime.observe_partition_denial(receiver, "original", "CHK@private")
        receiver.read_until.return_value = runtime.interop.FcpFrame("GetFailed", {"Identifier": "original", "Code": "20"})
        self.assertFalse(runtime.observe_partition_denial(receiver, "original", "CHK@private"))


class WireBudgetTest(unittest.TestCase):
    def test_actual_parser_rejects_oversized_frame_before_payload_read(self):
        stream = io.BytesIO(b"AllData\nDataLength=1073741824\nData\n")
        with self.assertRaisesRegex(runtime.RuntimeFailure, "fcp-payload-budget"):
            runtime.interop.read_fcp_frame_from_file(runtime._BoundedWireFile(stream))

    def test_actual_parser_rejects_duplicate_length_and_long_header(self):
        for body in (b"AllData\nDataLength=1\nDataLength=2\nData\n", b"X" * 8193):
            with self.assertRaises(runtime.RuntimeFailure):
                runtime.interop.read_fcp_frame_from_file(runtime._BoundedWireFile(io.BytesIO(body)))

    def test_unrelated_fcp_data_cannot_satisfy_pending_operation(self):
        client = runtime.BoundedFcpClient.__new__(runtime.BoundedFcpClient)
        client.sock = Mock()
        client.file = io.BytesIO(b"AllData\nIdentifier=other\nDataLength=3\nData\nabc")
        client.expected_identifier = "original"
        client._log_message = Mock()
        with self.assertRaisesRegex(runtime.RuntimeFailure, "fcp-operation-binding"):
            client.read_message(1)
        client._log_message.assert_not_called()

    def test_actual_parser_retains_bounded_payload(self):
        frame = runtime.interop.read_fcp_frame_from_file(runtime._BoundedWireFile(io.BytesIO(b"AllData\nDataLength=3\nData\nabc")))
        self.assertEqual(b"abc", frame.payload)


class MailPrivacyTest(unittest.TestCase):
    def supervisor(self):
        value = runtime.Supervisor.__new__(runtime.Supervisor)
        value.canaries = ["synthetic-private-body"]
        value.mail_canary_observations = {}
        value.mail_origin_observations = {}
        value.outcomes = {}
        value.next_operation = Mock(return_value="operation")
        value.remaining = lambda seconds: seconds
        return value

    def test_mail_request_budget_exhaustion_precedes_any_transport(self):
        supervisor = Mock()
        supervisor.next_operation.side_effect = runtime.RuntimeFailure("operation-budget-exceeded")
        client = runtime.ObservedMailClient(supervisor, "http://127.0.0.1:8888/api/v1", "http://127.0.0.1:9999", "session")
        client.opener = Mock()
        with self.assertRaisesRegex(runtime.RuntimeFailure, "operation-budget-exceeded"):
            client.post("/mail/command", {"command": "status"})
        client.opener.open.assert_not_called()

    def test_canary_in_base64_failure_surface_fails_without_exporting_body(self):
        supervisor = self.supervisor()
        with self.assertRaisesRegex(runtime.RuntimeFailure, "private-canary-exposure") as error:
            supervisor._scan_canaries(runtime.base64.b64encode(b"synthetic-private-body"))
        self.assertNotIn("synthetic-private-body", str(error.exception))
        self.assertEqual({"privacy": "failed"}, supervisor.mail_canary_observations)

    def test_log_scan_detects_canary_crossing_chunk_boundary_before_restart(self):
        supervisor = self.supervisor()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "run/apps/mail-prototype/process.log"
            log.parent.mkdir(parents=True)
            log.write_bytes(b"x" * 65530 + b"synthetic-private-body")
            supervisor.nodes = {"sender": Mock(runtime=Mock(base_dir=root))}
            with self.assertRaisesRegex(runtime.RuntimeFailure, "private-canary-exposure"):
                supervisor.scan_private_process_logs()

    def test_wrong_app_uses_genuine_sibling_session_without_inventing_launch_token(self):
        supervisor = self.supervisor()
        mail = Mock(origin="http://127.0.0.1:1", session="mail-session")
        mail.request.return_value = (403, b'{}')
        sibling = Mock(origin="http://127.0.0.1:2", session="site-session")
        supervisor.apps = {("candidate-sender", "mail-prototype"): mail,
                           ("candidate-sender", "site-publisher"): sibling}
        supervisor.mail_origin_checks()
        self.assertEqual({"Origin": sibling.origin}, mail.request.call_args_list[0].kwargs["headers_override"])
        self.assertEqual(sibling.session, mail.request.call_args_list[1].kwargs["headers_override"]["X-Crypta-App-Session"])
        self.assertEqual("not-observed", supervisor.mail_origin_observations["candidate-sender:staleProcessLaunchToken"])
        self.assertEqual("partial", supervisor.outcomes["mail-origin"])

    def test_real_expiry_requires_monotonic_elapsed_and_recent_accepted_session(self):
        supervisor = self.supervisor()
        handle = Mock(role="candidate-recipient")
        handle.request.return_value = (403, b'{}')
        supervisor.apps = {("candidate-recipient", "mail-prototype"): handle}
        supervisor.nodes = {"candidate-recipient": Mock(identity={"epoch": "original"})}
        supervisor.plan = {"policy": {"maxGapSeconds": 10}}
        supervisor.expiry_probe = {"session": "original-session", "origin": "http://127.0.0.1:2",
                                   "identity": {"epoch": "original"}, "expires": 100,
                                   "remaining": 50, "started": 40, "lastGood": 94}
        with patch.object(runtime.time, "time", return_value=101), patch.object(runtime.time, "monotonic", return_value=101):
            supervisor.observe_mail_expiry()
        self.assertEqual("observed", supervisor.mail_origin_observations["candidate-recipient:expiredBrowserSession"])
        self.assertEqual("original-session", handle.request.call_args.kwargs["headers_override"]["X-Crypta-App-Session"])

    def test_future_wall_clock_cannot_manufacture_expired_session_observation(self):
        supervisor = self.supervisor()
        handle = Mock(role="candidate-recipient")
        supervisor.apps = {("candidate-recipient", "mail-prototype"): handle}
        supervisor.nodes = {"candidate-recipient": Mock(identity={})}
        supervisor.expiry_probe = {"identity": {}, "expires": 100, "remaining": 50, "started": 99}
        with patch.object(runtime.time, "time", return_value=101), patch.object(runtime.time, "monotonic", return_value=101):
            with self.assertRaisesRegex(runtime.RuntimeFailure, "clock-discontinuity"):
                supervisor.observe_mail_expiry()
        handle.request.assert_not_called()


class RecoveryIntegrationTest(unittest.TestCase):
    def inputs(self):
        selection = {"cohortId": "previous-to-candidate", "fnpPort": 12001, "fcpPort": 12002, "httpPort": 12003}
        binding = runtime.canonical_digest(selection)
        plan = {"cohorts": [{"id": "previous-to-candidate", "sourceRole": "previous", "targetRole": "candidate-sender", "configDigest": binding}]}
        private = {"recovery": selection, "nodes": {"previous": {"fnpPort": 13001, "fcpPort": 13002, "httpPort": 13003,
                                                                        "apps": [{"appId": "site-publisher"}]}}}
        return plan, private, {"recoveryInputsDigest": binding}

    def test_private_selection_requires_both_plan_and_authorization_binding(self):
        plan, private, authorization = self.inputs()
        runtime.validate_recovery_selection(plan, private, authorization)
        with self.assertRaisesRegex(runtime.RuntimeFailure, "recovery-selection-not-authorized"):
            runtime.validate_recovery_selection({}, private, authorization)
        with self.assertRaisesRegex(runtime.RuntimeFailure, "recovery-selection-not-authorized"):
            runtime.validate_recovery_selection(plan, private, {})

    def test_recovery_cannot_reuse_main_port_even_with_matching_authority(self):
        plan, private, authorization = self.inputs()
        private["nodes"]["previous"]["httpPort"] = 12003
        with self.assertRaisesRegex(runtime.RuntimeFailure, "recovery-port-alias"):
            runtime.validate_recovery_selection(plan, private, authorization)

    def test_scoped_operation_does_not_inflate_main_coverage_counter(self):
        supervisor = runtime.Supervisor.__new__(runtime.Supervisor)
        supervisor.observed_operations = 4
        supervisor.journal = Mock()
        supervisor.emit("operation", role="previous", scenario="daemon-upgrade", outcome="pass", cohort="previous-to-candidate")
        self.assertEqual(4, supervisor.observed_operations)
        self.assertEqual("previous-to-candidate", supervisor.journal.append.call_args.kwargs["cohort"])

    def test_interrupted_recovery_requires_reconciliation_without_reinitializing(self):
        supervisor = runtime.Supervisor.__new__(runtime.Supervisor)
        supervisor.private = {"recovery": {}}
        supervisor.recovery_observation = None
        supervisor.private_work = {"recoveryStarted": "old-operation"}
        with patch.object(runtime, "fixed_helper") as helper:
            with self.assertRaisesRegex(runtime.RuntimeFailure, "recovery-interrupted-reconciliation-required"):
                supervisor.recovery_scenarios()
        self.assertTrue(supervisor.recovery_incomplete)
        helper.assert_not_called()


class BudgetIntegrationTest(unittest.TestCase):
    def test_node_and_feed_selection_require_plan_and_authorization_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            node = Path(directory) / "node"
            node.write_bytes(b"selected executable fixture")
            selection = {"role": "candidate-sender", "nodeExecutable": str(node), "nodeDigest": runtime.digest_file(node)}
            binding = runtime.canonical_digest(selection)
            private = {"budget": selection, "nodes": {"candidate-sender": {"apps": [{"appId": "feed-reader"}]}}}
            plan, auth = {"workloadInputs": {"budget": binding}}, {"budgetInputsDigest": binding}
            runtime.validate_budget_selection(plan, private, auth)
            for changed_plan, changed_auth in (({}, auth), (plan, {})):
                with self.assertRaisesRegex(runtime.RuntimeFailure, "not-authorized"):
                    runtime.validate_budget_selection(changed_plan, private, changed_auth)
            node.write_bytes(b"substituted executable fixture")
            with self.assertRaisesRegex(runtime.RuntimeFailure, "node-executable-not-selected"):
                runtime.validate_budget_selection(plan, private, auth)

    def test_orphan_budget_binding_and_interrupted_attempt_never_relaunch(self):
        with self.assertRaisesRegex(runtime.RuntimeFailure, "without-private"):
            runtime.validate_budget_selection({"workloadInputs": {"budget": "selected"}}, {}, {})
        supervisor = runtime.Supervisor.__new__(runtime.Supervisor)
        supervisor.private = {"budget": {}}
        supervisor.budget_observation = None
        supervisor.private_work = {"budgetStarted": "durable-original-attempt"}
        with patch.object(runtime, "fixed_helper") as helper:
            with self.assertRaisesRegex(runtime.RuntimeFailure, "interrupted-reconciliation"):
                supervisor.budget_scenarios()
            helper.assert_not_called()

    def supervisor(self):
        supervisor = runtime.Supervisor.__new__(runtime.Supervisor)
        supervisor.private = {"budget": {"role": "candidate-sender", "nodeExecutable": "/selected/node", "nodeDigest": "selected"}}
        supervisor.plan = {"profile": "bounded-live"}
        supervisor.authorization = {"maxOperations": 200}
        supervisor.operations = 0
        supervisor.budget_observation = None
        supervisor.private_work = {}
        supervisor.outcomes = {}
        supervisor.apps = {("candidate-sender", "feed-reader"): Mock()}
        supervisor.remaining = Mock(return_value=400)
        supervisor.save_state = Mock()
        supervisor.sample_resources = Mock()
        supervisor.emit = Mock()
        supervisor.client = lambda _role: contextlib.nullcontext(Mock())
        return supervisor

    def test_capacity_rejection_precedes_app_bootstrap_and_fcp_insert(self):
        supervisor = self.supervisor()
        supervisor.authorization["maxOperations"] = 63
        with patch.object(runtime, "validate_budget_selection"), patch.object(runtime.interop, "put_and_wait_for_success") as insert:
            with self.assertRaisesRegex(runtime.RuntimeFailure, "capacity-unavailable"):
                supervisor.budget_scenarios()
            insert.assert_not_called()
            supervisor.apps[("candidate-sender", "feed-reader")].refresh_session.assert_not_called()
            supervisor.save_state.assert_not_called()

    def test_actual_inserted_private_fixture_reaches_fixed_driver_with_reserved_requests(self):
        supervisor = self.supervisor()
        adapter = Mock()
        adapter.observe_budget.return_value = {"status": "partial", "requestCount": 38, "cases": {"scheduler-queue-pressure-precedence": "not-observed"}}
        with patch.object(runtime, "validate_budget_selection"), patch.object(runtime, "fixed_helper", return_value=adapter), patch.object(runtime.interop, "put_and_wait_for_success", return_value="CHK@fresh-synthetic") as inserted:
            supervisor.budget_scenarios()
        self.assertEqual(inserted.call_args.args[3], adapter.observe_budget.call_args.args[2])
        self.assertEqual("CHK@fresh-synthetic", adapter.observe_budget.call_args.args[1])
        self.assertTrue(inserted.call_args.kwargs["local_request_only"])
        self.assertEqual(39, supervisor.operations)
        self.assertEqual("partial", supervisor.outcomes["app-budgets"])
        self.assertEqual("partial", supervisor.emit.call_args.kwargs["outcome"])
        self.assertEqual(38, supervisor.emit.call_args.kwargs["counters"]["operations"])
        self.assertEqual(2, supervisor.sample_resources.call_count)

    def test_resource_sample_records_only_partial_numeric_counters_from_selected_jvm(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "node/run").mkdir(parents=True)
            (root / "java/bin").mkdir(parents=True)
            (root / "java/bin/java").write_bytes(b"selected java")
            identity = {"supervisor": {"pid": 7}, "jvm": {"pid": 8}}
            path = root / "node/run/process-identity.json"
            path.write_text(json.dumps(identity))
            path.chmod(0o600)
            supervisor = self.supervisor()
            del supervisor.sample_resources
            supervisor.resource_observations = {"sampleCount": 0, "initial": {}, "latest": {}}
            node = Mock()
            node.runtime.config_file = root / "node/config/cryptad.ini"
            node.java_home = root / "java"
            node.identity = identity["supervisor"]
            supervisor.nodes = {"candidate-sender": node}
            supervisor.plan["nodes"] = [{"role": "candidate-sender", "appDigests": []}]
            adapter = Mock()
            adapter.measure_resources.return_value = {"metrics": {"memoryBytes": 1024, "threads": 2, "queueDepth": None}, "status": "measured-but-uncompared"}
            with patch.object(runtime, "fixed_helper", return_value=adapter):
                supervisor.sample_resources()
            self.assertEqual(identity["jvm"], adapter.measure_resources.call_args.args[0])
            self.assertEqual(runtime.digest_file(root / "java/bin/java"), adapter.measure_resources.call_args.kwargs["jvm_executable_digest"])
            self.assertEqual({"memoryBytes": 1024, "threads": 2}, supervisor.emit.call_args.kwargs["counters"])
            self.assertEqual("partial", supervisor.emit.call_args.kwargs["outcome"])


if __name__ == "__main__":
    unittest.main()
