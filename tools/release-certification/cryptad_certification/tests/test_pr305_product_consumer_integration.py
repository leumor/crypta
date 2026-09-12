"""Private v4 projection and bounded runtime beside ordinary maintenance product admission.

Only original transport, CMS transport and protected file ownership are synthetic seams.
The dedicated catalog role starts absent; legacy startup roles retain their exact app subset.
No result of this local test attests protected execution or original observer authority.
"""
import hashlib
import copy
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import unittest
from unittest.mock import patch

from cryptad_certification.tests import test_pr304_product_consumer_integration as legacy
import federation_selection as selection
import test_pr305_native_projection as fixtures


class FederationProductConsumerIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (legacy.ROOT / "build/cryptad-dist/lib/cryptad.jar").is_file():
            raise unittest.SkipTest("requires assembleCryptadDist")
        try:
            legacy.ProductConsumerIntegrationTest.setUpClass()
        except unittest.SkipTest:
            raise
        except Exception:
            raise AssertionError("pr305-product-integration-prerequisite-failed") from None
        cls.addClassCleanup(legacy.ProductConsumerIntegrationTest.tearDownClass)

    def test_private_v4_rejects_publication_and_runs_beside_admitted_legacy_product(self):
        self._stage = "setup"
        harness = legacy.ProductConsumerIntegrationTest(methodName="runTest")
        try:
            harness.setUp()
            self.addCleanup(harness.tearDown)
            self._execute(harness)
        except Exception:
            raise AssertionError("pr305-product-consumer-integration-failed:" + self._stage) from None

    def _execute(self, h):
        self._stage = "fixture-preparation"
        distribution = h.work / "packaged-daemon"
        shutil.copytree(legacy.ROOT / "build/cryptad-dist", distribution, symlinks=True)
        # The prospective package embeds the exact executable later launched by the dedicated
        # catalog role, not the API-only stand-in used by the older compatibility fixture.
        h.api_jars = [distribution / "lib/cryptad.jar"]
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=legacy.ROOT, check=True,
                                capture_output=True, text=True).stdout.strip()
        fixture = h.work / "federated-fixture"
        classes = h.work / "fixture-classes"
        classes.mkdir()
        cp = str(h.tool / "lib/*")
        subprocess.run([str(h.java / "bin/javac"), "-cp", cp, "-d", str(classes), str(
            legacy.ROOT / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/Pr305SignedCatalogFixture.java")],
            check=True, capture_output=True, timeout=60)
        subprocess.run([str(h.java / "bin/java"), "-cp", str(classes) + os.pathsep + cp,
            "network.crypta.platform.appcatalog.Pr305SignedCatalogFixture", str(fixture)],
            check=True, capture_output=True, timeout=60)
        exported = subprocess.run([str(h.java / "bin/java"), "-cp", cp,
            "network.crypta.platform.api.PackagedApiExport"], check=True, capture_output=True, timeout=60)
        contract = json.loads(exported.stdout)
        snapshot, registry = h.work / "contract.json", h.work / "registry.json"
        snapshot.write_text(contract["contractSnapshot"])
        registry.write_text(contract["baselineRegistry"])

        class Transport:
            def add(self, family, files):
                return h.artifact(family, files)

        self._stage = "original-selection"
        source, upstream, authority, evidence = fixtures._source_artifacts(fixture, Transport())
        policy = fixtures._selection_policy(fixture, source)
        for member in policy["members"]:
            if member["original"] is None:
                Path(member["path"]).chmod(0o600)
        policy_path = h.work / "selection-policy.json"
        policy_path.write_bytes(fixtures._json(policy))
        policy_path.chmod(0o600)
        envelopes = {}

        def cms(raw, _root, *, decrypt=False):
            if decrypt:
                if raw not in envelopes:
                    raise selection.SelectionFailure("synthetic-envelope-substituted")
                return envelopes[raw]
            encrypted = b"synthetic-cms:" + hashlib.sha256(raw).digest()
            envelopes[encrypted] = raw
            return encrypted

        for name, value in (("authenticate_original", h.fetch), ("POLICY", policy_path),
                            ("Path", fixtures._SyntheticRootOwnedPath), ("_cms", cms),
                            ("_gh", legacy.projection._gh), ("_environment", lambda: {})):
            h.stack.enter_context(patch.object(selection, name, value))
        with patch.dict(os.environ, {"GITHUB_WORKFLOW_REF": selection.REPOSITORY + "/" + selection.WORKFLOW + "@refs/heads/develop"}):
            selection.produce_selection(h.work, h.work / "selection.cms")
        selection_original = h.artifact("federation-selection", {selection.MEMBER: (h.work / "selection.cms").read_bytes()})
        authenticated = selection.authenticate_selection(selection_original, h.work)
        # Freeze only the ordinary cohort that the maintenance publication format supports.
        self._stage = "ordinary-maintenance-product"
        base_inputs = h.cohort("stable-1.0-maintenance-302", commit)
        with patch.object(h, "cohort", return_value=base_inputs):
            freeze, package, _legacy_inventory, selected = h.freeze(302, commit)

        def cohort():
            base_value, path, _inventory, _origin, product_root = base_inputs
            value = copy.deepcopy(base_value)
            members = {"catalog": "A1/catalog.properties", "catalogSignature": "A1/cryptad-app-catalog.signature",
                       "bundle": "A1/bundle.zip", "submission": "A1/submission.zip"}
            row = {"appId": "pr305-fixture", "original": source, "originalInventory": upstream,
                   "catalogOriginal": None, "members": members, "catalogKeyId": "catalog-a",
                   "sourceAuthorityRoot": authority, "sourceEvidenceDigest": evidence, "requiredForRelease": True}
            for field, filename in (("catalogKeys", "catalog-keys.properties"),
                                    ("publisherKeys", "publisher-keys.properties"), ("reviewerKeys", "reviewer-keys.properties")):
                row[field] = str(fixture / filename)
                row[field + "Digest"] = legacy.products.file_digest(fixture / filename)
            # This prospective cohort selects the reviewed synthetic federation pilot as its
            # external member. The historical cohort and its original projection stay intact.
            value["sources"] = [member for member in value["sources"]
                                if member["original"]["sourceFamily"] != "third-party-pilot"] + [row]
            value["authorityRoots"]["thirdPartyPilot"] = authority
            value["schemaVersion"] = 2
            value["federationSelections"] = [{"appId": "pr305-fixture", "original": selection_original,
                "contextId": "a1", "contextDigest": authenticated.context("a1")["digest"], "generation": 7}]
            value["admissionContract"] = {"snapshotPath": str(snapshot), "registryPath": str(registry),
                "snapshotDigest": legacy.products.file_digest(snapshot), "registryDigest": legacy.products.file_digest(registry)}
            path.chmod(0o600)
            path.write_bytes(fixtures._json(value))
            output = h.work / "selected-v4.json"
            with patch.object(legacy.projection, "COHORT_FILE", path):
                inventory = legacy.projection.produce_cohort(h.work, output)
            origin = h.artifact("app-subject-projection", {"platform-api-1.x-app-subject-inventory.cms": cms(output.read_bytes(), h.work)})
            original = legacy.projection.authenticate_inventory(origin, h.work,
                expected_cohort_digest=inventory["cohortDigest"], expected_inventory_version=4)
            self.assertTrue(original.matches(inventory))
            return value, path, inventory, origin, product_root

        self._stage = "private-projection"
        _cohort, policy_path, inventory, projection_origin, _products = cohort()
        private_projection = {"coordinates": projection_origin, "cohortDigest": inventory["cohortDigest"]}
        self._stage = "publication-boundary"
        rejected_output = h.work / "rejected-publication-runtime"
        with patch.object(legacy.projection, "COHORT_FILE", policy_path):
            with self.assertRaisesRegex(legacy.metadata.RuntimeMetadataError,
                                       "^runtime-metadata-private-companion-unsupported$"):
                legacy.metadata.produce_runtime_metadata(freeze, package, rejected_output,
                    projection_origin=projection_origin, private_root=h.work)
        self.assertFalse(rejected_output.exists())
        self.assertEqual(4, inventory["schemaVersion"])
        self.assertEqual(3, inventory["baseInventoryVersion"])
        self.assertIn("pr305-fixture", inventory["requiredAppIds"])
        self.assertEqual(sorted(legacy.metadata.FIRST_PARTY | {"mail-prototype", "pr305-fixture"}),
                         inventory["requiredAppIds"])
        subject = next(row for row in inventory["subjects"] if row["appId"] == "pr305-fixture")
        self.assertEqual("third-party-pilot", subject["sourceAuthority"])
        root = package.parent / "runtime"
        metadata = legacy.metadata.read_json((root / "runtime-subjects.json").read_bytes())
        self.assertTrue(metadata["executable"]["digest"] == legacy.products.file_digest(h.api_jars[0]))
        self.assertNotIn("pr305-fixture", metadata["shippedAppIds"])
        native = legacy.metadata.read_json((root / "native-admissions.json").read_bytes())
        self.assertNotIn("pr305-fixture", {row["appId"] for row in native})
        self.assertNotIn(b"federationSelection", (root / "native-admissions.json").read_bytes())
        scoped = inventory["selectedFederation"][0]["nativeProjection"]
        self.assertEqual(3, scoped["schemaVersion"])
        self.assertEqual("accepted", scoped["nativeAdmission"])
        node = next(row for row in legacy.fixture_plan()["nodes"] if row["role"] == "candidate-sender")
        by_id = {row["appId"]: row for row in native}
        node.update(artifactDigest=legacy.products.file_digest(package), artifactSize=package.stat().st_size,
            sourceCommit=commit, contractVersion=metadata["contractVersion"],
            appDigests=sorted(by_id[app]["bundleDigest"] for app in metadata["rolePolicy"]["candidate-sender"]))
        self._stage = "product-admission"
        admitted = legacy.products.authenticate_maintenance_product(selected["maintenanceProduct"], node, h.work / "admitted")
        legacy.products.authenticate_runtime_projection(admitted, selected["appProjection"], h.work)
        self.assertTrue(admitted["appMatrix"])
        self.assertTrue(all(row["nativeAdmission"] == "accepted" for row in admitted["appMatrix"]))
        with self.assertRaisesRegex(legacy.products.ProductAdmissionError,
                                   "maintenance-runtime-projection-selection-mismatch"):
            legacy.products.authenticate_runtime_projection(admitted, private_projection, h.work)
        changed = {**node, "appDigests": sorted(node["appDigests"] + [scoped["bundleDigest"]])}
        with self.assertRaisesRegex(legacy.products.ProductAdmissionError, "maintenance-runtime-required-app-roster-mismatch"):
            legacy.products.authenticate_maintenance_product(selected["maintenanceProduct"], changed, h.work / "unplanned-role")
        wrong = {**selected["appProjection"], "cohortDigest": "sha256:" + "0" * 64}
        with self.assertRaisesRegex(legacy.products.ProductAdmissionError, "maintenance-runtime-projection-selection-mismatch"):
            legacy.products.authenticate_runtime_projection(admitted, wrong, h.work)
        self._stage = "catalog-runtime"
        self._runtime(h, fixture, source, upstream, authority, evidence, authenticated,
                      selection_original, private_projection, inventory, scoped, snapshot, registry,
                      package, selected["maintenanceProduct"]["coordinates"])

    def _runtime(self, h, fixture, source, upstream, authority, evidence, authenticated,
                 selection_original, projection_original, inventory, initial, snapshot, registry,
                 package, package_original):
        interop = str(legacy.ROOT / "tools/interop")
        sys.path.insert(0, interop)
        self.addCleanup(sys.path.remove, interop)
        import federated_catalog_runtime as adapter
        import federated_catalog_runtime_observer as observer
        distribution = h.work / "packaged-daemon"
        contexts = {"initial": initial}
        for label, name in (("update", "A2"), ("switch", "B3"), ("originUpdate", "B4")):
            members = {"catalog": name + "/catalog.properties", "catalogSignature": name + "/cryptad-app-catalog.signature",
                       "bundle": name + "/bundle.zip", "submission": name + "/submission.zip"}
            source_row = {"appId": "pr305-fixture", "original": source, "originalInventory": upstream,
                          "catalogOriginal": None, "members": members, "sourceAuthorityRoot": authority,
                          "sourceEvidenceDigest": evidence}
            contexts[label] = legacy.projection.produce(h.fetch(source, h.work), members,
                exporter=h.tool / "bin/crypta-app", exporter_digest=legacy.products.file_digest(h.tool / "bin/crypta-app"),
                app_id="pr305-fixture", catalog_key_id="catalog-a" if name == "A2" else "catalog-b",
                catalog_keys=fixture / "catalog-keys.properties", publisher_keys=fixture / "publisher-keys.properties",
                reviewer_keys=fixture / "reviewer-keys.properties", private_root=h.work, java_home=h.java,
                contract_path=snapshot, baseline_registry_path=registry, federation_selection=authenticated,
                selection_id=name.lower(), source=source_row)["declaration"]
            legacy.projection.verify_upstream_subject(source_row, contexts[label], h.fetch(source, h.work), h.work)
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=legacy.ROOT, check=True,
                                capture_output=True, text=True).stdout.strip()
        inventory_capability = legacy.projection.authenticate_inventory(projection_original["coordinates"], h.work,
            expected_cohort_digest=inventory["cohortDigest"], expected_inventory_version=4)
        executable_digest = legacy.products.file_digest(distribution / "lib/cryptad.jar")
        immutable = {"daemonDigest": legacy.products.file_digest(package),
            "daemonExecutableDigest": executable_digest,
            "toolTreeDigest": legacy.projection.tree_digest(h.tool), "javaTreeDigest": legacy.projection.tree_digest(h.java),
            "fixtureTreeDigest": legacy.projection.tree_digest(fixture), "implementationDigest": observer.implementation_digest()}
        selected_plan = {"sourceCommit": commit, "contexts": contexts,
                         "selectionOriginal": selection_original, "projectionOriginal": projection_original,
                         "projectionInventoryDigest": inventory_capability.digest,
                         "packageOriginal": package_original, "packageMember": "freeze/assets/" + package.name,
                         "packageDigest": immutable["daemonDigest"],
                         **immutable}
        plan_digest = fixtures._digest(fixtures._json(selected_plan))
        began = dt.datetime.now(dt.timezone.utc)
        observed = adapter.execute(h.work / "catalog-runtime", distribution, h.java, h.tool, fixture,
                                   source_commit=commit, expected_projections=contexts)
        ended = dt.datetime.now(dt.timezone.utc)
        for field, path in (("toolTreeDigest", h.tool), ("javaTreeDigest", h.java), ("fixtureTreeDigest", fixture)):
            self.assertTrue(legacy.projection.tree_digest(path) == immutable[field])
        self.assertTrue(legacy.products.file_digest(distribution / "lib/cryptad.jar") == executable_digest)
        self.assertTrue(legacy.products.file_digest(package) == immutable["daemonDigest"])
        envelope = {"schemaVersion": 2, "kind": "catalog-origin-scoped-observation", "sourceCommit": commit,
            "executionId": "synthetic-pr305-product-chain", "planDigest": plan_digest,
            "selectionOriginal": selection_original, "projectionOriginal": projection_original["coordinates"],
            "projectionInventoryDigest": inventory_capability.digest,
            **immutable,
            "contexts": contexts, "startedAt": began.isoformat(), "completedAt": ended.isoformat(),
            "producer": {"repository": observer.REPOSITORY, "workflowPath": observer.WORKFLOW,
                "sourceCommit": commit, "runId": 1, "runAttempt": 1, "environment": observer.ENVIRONMENT},
            "observation": observed, "evidenceClass": "synthetic-local", "releaseEligibility": "blocked"}
        # This is the native observer's local consistency reader, not an authenticated observer
        # capability. The synthetic workflow identity above carries no operational authority.
        cases = observer.validate_observation(envelope, plan_digest, now=dt.datetime.now(dt.timezone.utc))
        self.assertIn("catalog-install-origin-v2", cases)
        self.assertIn("exact-bundle-origin-rollback", cases)
        self.assertTrue({"eligible-origin-pinned-update", "staged-registration-origin-remains-absent",
                         "local-publisher-scope-revocation-denied", "local-reviewer-scope-revocation-denied",
                         "exact-equivalent-source-origin-preserved", "untrusted-source-isolated",
                         "denylist-preference-no-mutation"} <= cases)
        self.assertEqual("blocked", envelope["releaseEligibility"])
        changed = {**envelope, "contexts": {**contexts, "initial": contexts["update"]}}
        with self.assertRaises(observer.ObserverFailure):
            observer.validate_observation(changed, plan_digest, now=dt.datetime.now(dt.timezone.utc))
