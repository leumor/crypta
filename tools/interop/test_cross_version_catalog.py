"""Offline stateful adapter negatives; no operational evidence or live node."""
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import cross_version_catalog as catalog


class Supervisor:
    def __init__(self):
        self.catalogs = set()
        self.calls = []
        self.digest = "sha256:" + "a" * 64
        self.bad_health = False
    def remaining(self, seconds): return seconds
    def catalog_request(self, role, method, path, form=None):
        self.calls.append((method, path, form))
        if method == "GET" and path == "/api/v1/app-catalogs":
            return 200, {"catalogs": [{"catalogId": item} for item in sorted(self.catalogs)]}
        if method == "POST" and path.endswith("/add"):
            if form.get("source", "").endswith("bad.properties"):
                return 400, {"error": {"code": "invalid_catalog_signature"}}
            self.catalogs.add(form["expectedCatalogId"])
            return 201, {"catalog": {"catalogId": form["expectedCatalogId"]}}
        if path.endswith("/operations/health"):
            return 200, {"health": {"catalogDigest": "sha256:" + ("c" if self.bad_health else "a") * 64,
                                   "signatureKeyId": "test-key"}}
        if method == "DELETE":
            self.catalogs.discard(path.split("/")[-1])
            return 200, {"catalog": {"removed": True}}
        raise AssertionError((method, path))


class CatalogCasesTest(unittest.TestCase):
    def fixture(self, root):
        return catalog.Fixture(root / "catalog.properties", root / "cryptad-app-catalog.signature", root / "app.zip",
            root / "catalog.keys", root / "publisher.keys", root / "reviewer.keys", "test-key", "site-publisher", "soak-catalog",
            *(["sha256:" + "a" * 64] * 6))
    def tool(self, root):
        return catalog.Tool(root, "sha256:" + "a" * 64, root, "sha256:" + "b" * 64, root)

    def test_real_route_actions_and_exact_postcondition_required(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(catalog, "verify_fixture", return_value={}):
            supervisor = Supervisor()
            result = catalog.run_catalog_cases(supervisor, "candidate-sender", self.tool(Path(directory)), self.fixture(Path(directory)))
            self.assertEqual("pass", result["outcomes"]["signedCatalogAdmission"])
            self.assertEqual("not-observed", result["outcomes"]["stableBetaIsolation"])
            self.assertEqual("partial", result["status"])
            self.assertEqual("complete", result["cleanup"])
            self.assertIn(("POST", "/api/v1/app-catalogs/add"), [(m,p) for m,p,_ in supervisor.calls])
            self.assertFalse(supervisor.catalogs)
            supervisor.bad_health = True
            result = catalog.run_catalog_cases(supervisor, "candidate-sender", self.tool(Path(directory)), self.fixture(Path(directory)))
            self.assertEqual("failed", result["status"])
            self.assertNotEqual("pass", result["outcomes"]["signedCatalogAdmission"])
            self.assertFalse(supervisor.catalogs)

    def test_source_switch_without_catalog_origin_never_attempts_mutating_update(self):
        class SourceSupervisor(Supervisor):
            def __init__(self):
                super().__init__()
                self.running = True
                self.lifecycle_calls = []
            def app_subject(self, role, app_id):
                return {"bundleDigest": self.digest}
            def stop_app(self, role, app_id):
                self.lifecycle_calls.append("stop")
                self.running = False
            def start_app(self, role, app_id):
                self.lifecycle_calls.append("start")
                self.running = True
            def catalog_request(self, role, method, path, form=None):
                if path.endswith("/update"):
                    # A staged install has no catalog origin: the real consent gate skips it.
                    # Model a compatible alternate being accepted, rather than inventing a 409.
                    self.calls.append((method, path, form))
                    self.digest = "sha256:" + "f" * 64
                    return 200, {"app": {"appId": "site-publisher"}}
                return super().catalog_request(role, method, path, form)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = self.fixture(root)
            other = replace(base, catalog_id="other-catalog", catalog=root / "other.properties")
            supervisor = SourceSupervisor()
            with patch.object(catalog, "verify_fixture", side_effect=[{"appId": "site-publisher", "appVersion": "1"},
                                                                       {"appId": "site-publisher", "appVersion": "2"}]) as verifier:
                result = catalog.run_catalog_cases(supervisor, "candidate-sender", self.tool(root), base, other_catalog=other)
            self.assertEqual(2, verifier.call_count)
            self.assertEqual("partial", result["status"])
            self.assertEqual("pass", result["outcomes"]["signedCatalogAdmission"])
            self.assertEqual("not-observed", result["outcomes"]["sourceSwitchConsent"])
            self.assertEqual("blocked", result["releaseEligibility"])
            self.assertEqual("complete", result["cleanup"])
            self.assertEqual(base.bundle_digest, supervisor.digest)
            self.assertTrue(supervisor.running)
            self.assertEqual([], supervisor.lifecycle_calls)
            self.assertFalse(any(path.endswith("/update") for _, path, _ in supervisor.calls))
            self.assertFalse(any(form and form.get("expectedCatalogId") == other.catalog_id
                                 for _, _, form in supervisor.calls))
            self.assertFalse(supervisor.catalogs)

    def test_preexisting_catalog_never_deleted(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(catalog, "verify_fixture", return_value={}):
            supervisor = Supervisor()
            supervisor.catalogs.add("soak-catalog")
            result = catalog.run_catalog_cases(supervisor, "candidate-sender", self.tool(Path(directory)), self.fixture(Path(directory)))
            self.assertEqual("failed", result["status"])
            self.assertEqual({"soak-catalog"}, supervisor.catalogs)
            self.assertFalse(any(method == "DELETE" for method, _, _ in supervisor.calls))

    def test_untrusted_case_requires_actual_signature_denial_and_keeps_sources_private(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(catalog, "verify_fixture", return_value={}):
            root = Path(directory)
            bad = root / "bad.properties"
            bad.write_bytes(b"public synthetic invalid catalog")
            signature = root / "cryptad-app-catalog.signature"
            signature.write_bytes(b"public synthetic invalid signature")
            digest = lambda p: "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
            result = catalog.run_catalog_cases(Supervisor(), "candidate-sender", self.tool(root), self.fixture(root),
                untrusted_catalog=bad, untrusted_digest=digest(bad), untrusted_signature_digest=digest(signature))
            self.assertEqual("pass", result["outcomes"]["untrustedCatalogBlocking"])
            self.assertNotIn(directory, str(result))

    def test_untrusted_tool_fails_before_any_api_action(self):
        with tempfile.TemporaryDirectory() as directory:
            supervisor = Supervisor()
            result = catalog.run_catalog_cases(supervisor, "candidate-sender", self.tool(Path(directory)), self.fixture(Path(directory)))
            self.assertEqual("failed", result["status"])
            self.assertEqual([], supervisor.calls)




class CatalogSelectionTest(unittest.TestCase):
    def selection(self, root):
        fixture = {"catalogPath": str(root / "catalog.properties"), "signaturePath": str(root / "cryptad-app-catalog.signature"),
                   "bundlePath": str(root / "app.zip"), "catalogKeysPath": str(root / "catalog.keys"),
                   "publisherKeysPath": str(root / "publisher.keys"), "reviewerKeysPath": str(root / "reviewer.keys"),
                   "catalogKeyId": "test-key", "appId": "site-publisher", "catalogId": "soak-catalog"}
        fixture.update({key: "sha256:" + "a" * 64 for key in ("catalogDigest", "signatureDigest", "bundleDigest",
                       "catalogKeysDigest", "publisherKeysDigest", "reviewerKeysDigest")})
        return {"schemaVersion": 1, "role": "candidate-sender", "localRoot": str(root),
                "tool": {"root": str(root), "treeDigest": "sha256:" + "b" * 64,
                         "javaHome": str(root), "javaTreeDigest": "sha256:" + "c" * 64},
                "baseline": fixture, "mirror": None, "otherCatalog": None, "untrusted": None}

    def test_preflight_invokes_java_verifier_before_returning_daemon_environment(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(catalog, "verify_fixture", return_value={}) as verifier:
            root = Path(directory)
            value = self.selection(root)
            prepared = catalog.preflight_selection(value, expected_digest=catalog.selection_digest(value), private_root=root, remaining=lambda seconds: seconds)
            self.assertEqual(1, verifier.call_count)
            self.assertEqual(root / "catalog.properties", prepared.baseline.catalog)
            self.assertEqual({"CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE": str(root / "catalog.keys"),
                              "CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_KEYS_FILE": str(root / "reviewer.keys")}, prepared.daemon_environment())

    def test_wrong_authority_and_outside_root_fail_before_executable(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(catalog, "verify_fixture") as verifier:
            root = Path(directory)
            value = self.selection(root)
            with self.assertRaises(catalog.CatalogFailure):
                catalog.preflight_selection(value, expected_digest="sha256:" + "d" * 64, private_root=root, remaining=lambda seconds: seconds)
            value["baseline"]["bundlePath"] = str(root.parent / "other.zip")
            with self.assertRaisesRegex(catalog.CatalogFailure, "root-escape"):
                catalog.preflight_selection(value, expected_digest=catalog.selection_digest(value), private_root=root, remaining=lambda seconds: seconds)
            verifier.assert_not_called()

    def test_modified_tool_tree_rejected_during_prelaunch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = self.selection(root)
            with self.assertRaisesRegex(catalog.CatalogFailure, "tool-substituted"):
                catalog.preflight_selection(value, expected_digest=catalog.selection_digest(value), private_root=root, remaining=lambda seconds: seconds)

if __name__ == "__main__": unittest.main()
