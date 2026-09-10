"""Offline tests for fixed persistent deployment admission; never start a service or node."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cross_version_service as service


@unittest.skipUnless(os.name == "posix", "Linux persistent supervisor")
class PersistentSourceSupervisorTest(unittest.TestCase):
    def selection(self, directory):
        root = Path(directory)
        checkout = root / "checkout"
        executable = checkout / "tools/interop/cross_version_service.py"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"public pinned service fixture")
        state = root / "state"
        state.mkdir(mode=0o700)
        for name in ("selected", "experiments", "public"):
            (state / name).mkdir(mode=0o700)
        selected = state / "selected"
        target = state / "experiments" / "synthetic-test"
        self.write(selected / "plan.json", {"experimentId": "synthetic-test", "profile": "bounded-live", "provenanceClass": "source-build-comparison"})
        self.write(selected / "private-config.json", {"root": str(target)})
        self.write(selected / "authorization.json", {"root": str(target), "maxSeconds": 72 * 3600, "syntheticContent": True})
        manifest = {"schemaVersion": 1, "serviceDigest": service._digest(executable)}
        for name, field in (("plan.json", "planDigest"), ("private-config.json", "privateConfigDigest"), ("authorization.json", "authorizationDigest")):
            manifest[field] = service._digest(selected / name)
        self.write(selected / "service-selection.json", manifest)
        return checkout, state

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def test_persistent_duration_admission_is_local_source_class(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout, state = self.selection(directory)
            selected, root, output, maximum = service.load_selection(checkout, state)
            self.assertEqual(72 * 3600, maximum)
            self.assertFalse(root.exists())
            self.assertFalse(output.exists())

    def test_modified_input_fails_before_process_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout, state = self.selection(directory)
            self.write(state / "selected/authorization.json", {"maxSeconds": 1})
            with patch.object(service.subprocess, "Popen") as spawn:
                with self.assertRaises(service.ServiceError):
                    service.supervise(checkout, state)
                spawn.assert_not_called()

    def test_existing_root_requires_reconciliation_without_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout, state = self.selection(directory)
            (state / "experiments/synthetic-test").mkdir(mode=0o700)
            with self.assertRaisesRegex(service.ServiceError, "reconciliation"):
                service.load_selection(checkout, state)

    def test_protected_profile_is_not_admitted_by_local_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout, state = self.selection(directory)
            selected = state / "selected"
            plan = json.loads((selected / "plan.json").read_text())
            plan["profile"] = "protected-long-live"
            self.write(selected / "plan.json", plan)
            manifest = json.loads((selected / "service-selection.json").read_text())
            manifest["planDigest"] = service._digest(selected / "plan.json")
            self.write(selected / "service-selection.json", manifest)
            with self.assertRaisesRegex(service.ServiceError, "protected-authority"):
                service.load_selection(checkout, state)

    def test_environment_does_not_retain_github_or_runtime_secrets(self):
        with patch.dict(os.environ, {"GH_TOKEN": "private-canary", "GITHUB_TOKEN": "private-canary", "HTTPS_PROXY": "private-canary", "JAVA_OPTS": "private-canary"}):
            environment = service.child_environment(Path("/private"))
        self.assertEqual({"PATH", "LANG", "HOME", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE"}, set(environment))
        self.assertNotIn("private-canary", json.dumps(environment))

    def test_maximum_five_day_duration(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout, state = self.selection(directory)
            selected = state / "selected"
            auth = json.loads((selected / "authorization.json").read_text())
            auth["maxSeconds"] = service.MAX_SECONDS + 1
            self.write(selected / "authorization.json", auth)
            manifest = json.loads((selected / "service-selection.json").read_text())
            manifest["authorizationDigest"] = service._digest(selected / "authorization.json")
            self.write(selected / "service-selection.json", manifest)
            with self.assertRaisesRegex(service.ServiceError, "duration"):
                service.load_selection(checkout, state)

    def test_deadline_cancels_only_owned_controller_then_returns_partial(self):
        class Child:
            returncode = 2
            def __init__(self):
                self.signals = []
            def poll(self):
                return 2 if self.signals else None
            def send_signal(self, value):
                self.signals.append(value)
        child = Child()
        with tempfile.TemporaryDirectory() as directory:
            checkout, state = self.selection(directory)
            with patch.object(service.subprocess, "Popen", return_value=child) as spawn, \
                    patch.object(service.signal, "signal"), \
                    patch.object(service.time, "monotonic", side_effect=[0, 72 * 3600 + 181, 72 * 3600 + 182, 72 * 3600 + 183]), \
                    patch.object(service.time, "sleep"):
                self.assertEqual(2, service.supervise(checkout, state))
            self.assertEqual([service.signal.SIGINT], child.signals)
            self.assertEqual("/usr/bin/python3", spawn.call_args.args[0][0])
            self.assertEqual(service.child_environment(state), spawn.call_args.kwargs["env"])

    def test_service_digest_substitution_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout, state = self.selection(directory)
            (checkout / "tools/interop/cross_version_service.py").write_text("different executable")
            with self.assertRaisesRegex(service.ServiceError, "executable-binding"):
                service.load_selection(checkout, state)


if __name__ == "__main__":
    unittest.main()
