"""Real packaged daemon, Java-signed fixtures, normal HTTP mutations and durable provenance.

Run after ./gradlew :platform-devtools:installDist assembleCryptadDist. This is a short local
synthetic integration, never original protected provenance or public-network availability proof.
"""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import federated_catalog_runtime as adapter

ROOT = Path(__file__).resolve().parents[2]


class PackagedCatalogOriginTest(unittest.TestCase):
    def test_native_catalog_install_update_switch_rollback_and_mirror(self):
        try:
            self._execute_native_catalog_lifecycle()
        except unittest.SkipTest:
            raise
        except Exception as error:
            public_codes = {
                "catalog-owned-equivalent-origin-changed", "catalog-owned-untrusted-source-poisoned-selection",
                "catalog-owned-security-conflict-not-classified", "catalog-owned-preference-bypassed-denylist",
                "catalog-owned-origin-update-not-eligible", "catalog-owned-staged-install-gained-origin",
                "catalog-owned-scope-roster-invalid", "catalog-owned-scope-revocation-mismatch",
                "catalog-owned-local-scope-not-revalidated", "catalog-owned-original-projection-substitution",
                "catalog-owned-fixture-cohort-invalid", "catalog-owned-native-declaration-mismatch",
                "catalog-owned-source-snapshot-substituted",
                "catalog-owned-revoked-key-rollback-not-denied", "catalog-owned-revoked-key-preview-not-denied",
                "catalog-owned-revoked-rollback-not-denied", "catalog-owned-revoked-preview-not-denied",
                "catalog-owned-retained-rollback-substituted", "catalog-owned-suspension-mutated-app",
                "catalog-owned-suspended-rollback-origin-substituted", "catalog-owned-native-request-denied",
                "catalog-owned-registry-restoration-failed", "catalog-owned-revocation-disabled-unrelated-origin",
                "catalog-owned-stable-channel-escape", "catalog-owned-app-principal-not-denied",
            }
            code = str(error) if isinstance(error, adapter.LifecycleFailure) and str(error) in public_codes else "catalog-origin-packaged-integration-failed"
            raise AssertionError(code) from None

    def _execute_native_catalog_lifecycle(self):
        tool = ROOT / "platform-devtools/build/install/crypta-app"
        distribution = ROOT / "build/cryptad-dist"
        if (not (tool / "bin/crypta-app").is_file() or not (distribution / "bin/cryptad").is_file()
                or not shutil.which("javac")):
            self.skipTest("requires Java 25, :platform-devtools:installDist and assembleCryptadDist")
        with tempfile.TemporaryDirectory(prefix="pr305-packaged-") as temporary:
            private = Path(temporary)
            packaged = private / "distribution"
            shutil.copytree(distribution, packaged, symlinks=True)
            distribution = packaged
            installed_java = Path(shutil.which("javac")).resolve().parents[1]
            java = private / "jdk"
            shutil.copytree(installed_java, java, symlinks=False, ignore_dangling_symlinks=True)
            execution_env = {"PATH": str(java / "bin") + ":/usr/bin:/bin", "JAVA_HOME": str(java),
                             "HOME": str(private), "LANG": "C.UTF-8"}
            classes = private / "classes"
            classes.mkdir()
            fixture = private / "fixture"
            source = ROOT / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/Pr305SignedCatalogFixture.java"
            subprocess.run([str(java / "bin/javac"), "-cp", str(tool / "lib/*"), "-d", str(classes), str(source)],
                           check=True, capture_output=True, timeout=60, env=execution_env)
            subprocess.run([str(java / "bin/java"), "-cp", str(classes) + os.pathsep + str(tool / "lib/*"),
                            "network.crypta.platform.appcatalog.Pr305SignedCatalogFixture", str(fixture)],
                           check=True, capture_output=True, timeout=60, env=execution_env)
            source_commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                                           capture_output=True, text=True).stdout.strip()
            exported = subprocess.run([str(java / "bin/java"), "-cp", str(distribution / "lib/*"),
                "network.crypta.platform.api.PackagedApiExport"], check=True, capture_output=True, timeout=60, env=execution_env)
            envelope = json.loads(exported.stdout)
            snapshot, registry = private / "contract.json", private / "registry.json"
            snapshot.write_text(envelope["contractSnapshot"])
            registry.write_text(envelope["baselineRegistry"])
            sys.path.insert(0, str(ROOT / "tools/release-certification/protected"))
            try:
                from test_pr305_native_projection import verify_original_fixture
                original = verify_original_fixture(fixture, tool, java, private / "original-projection", snapshot, registry)
            finally:
                sys.path.pop(0)
            selected = {label: original[key] for label, key in (("initial", "A1"), ("update", "A2"), ("switch", "B3"), ("originUpdate", "B4"))}
            observed = adapter.execute(private / "runtime", distribution, java, tool, fixture,
                                       source_commit=source_commit, expected_projections=selected)
            self.assertEqual(["install", "update", "switch", "rollback"],
                             [row["operation"] for row in observed["operations"]])
            self.assertTrue(all(row["status"] == "complete" for row in observed["operations"]))
            self.assertTrue(observed["operations"][0]["reconciled"])
            self.assertEqual(observed["operations"][1]["observed"], observed["operations"][3]["observed"])
            self.assertGreaterEqual(len(observed["daemonEpochs"]), 2)
            self.assertGreaterEqual(observed["mirror"]["mismatchedSignature"]["httpStatus"], 400)
            self.assertEqual("synthetic-local", observed["evidenceClass"])
            self.assertEqual("blocked", observed["releaseEligibility"])
            roles = {row["role"]: row for row in observed["secondaryRoles"]}
            self.assertEqual({"catalog-origin-update", "catalog-origin-staged-negative",
                              "catalog-origin-publisher-scope-negative", "catalog-origin-reviewer-scope-negative"}, set(roles))
            self.assertEqual(selected["originUpdate"]["bundleDigest"],
                             roles["catalog-origin-update"]["terminalOrigin"]["bundleDigest"])
            removal = roles["catalog-origin-update"]["currentOriginTrustRemoval"]
            self.assertEqual(["remove", "revoke"], [row["action"] for row in removal["cases"]])
            for row in removal["cases"]:
                self.assertEqual(removal["beforeOrigin"], row["afterOrigin"])
                self.assertEqual(200, row["refreshHttpStatus"])
                self.assertEqual(selected["update"]["federationSelection"]["catalogRevisionDigest"],
                                 row["unrelatedCatalog"]["catalogDigest"])
            self.assertFalse(roles["catalog-origin-staged-negative"]["stagedRegistration"]["originPresent"])
            self.assertLessEqual(observed["totalOperations"], 600)


if __name__ == "__main__":
    unittest.main()
