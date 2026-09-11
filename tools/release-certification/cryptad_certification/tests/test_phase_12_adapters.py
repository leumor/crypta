"""Behavioral owner-adapter checks using isolated, existing synthetic authorities."""
import base64
import copy
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptad_certification import phase_12_adapters as audit
from cryptad_certification import transparency_bundle as bundle
from cryptad_certification import transparency_sources as sources


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class Phase12OwnerAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(strict=True)
        self.number = 0

    def verify(self, adapter, values, when="2026-09-10T00:00:00Z"):
        self.number += 1
        scratch = self.root / str(self.number)
        scratch.mkdir()
        with patch("socket.socket", side_effect=AssertionError("offline-network-denied")), \
             patch("subprocess.run", side_effect=AssertionError("offline-execution-denied")):
            return audit.verify(adapter, values, when, scratch)

    def test_catalog_checks_real_signatures_without_promoting_synthetic_authority(self):
        from .test_stable_catalog_authority import _manifest
        manifest = _manifest()
        result = self.verify("catalog-keyset", {"authority.json": encoded(manifest)})
        self.assertEqual("executed-pass", result["dimensions"]["localVerification"])
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
        self.assertEqual("synthetic-rehearsal", result["evidenceClass"])
        self.assertEqual(["p12-293-keyset"], result["claims"])
        manifest["keyset"]["keys"][0]["proofOfPossession"]["signatureBase64"] = base64.b64encode(b"x" * 64).decode()
        with self.assertRaises(audit.AdapterError):
            self.verify("catalog-keyset", {"authority.json": encoded(manifest)})

    def test_signature_on_unrelated_keyset_cannot_authenticate_changed_role(self):
        from .test_stable_catalog_authority import _manifest
        manifest = _manifest()
        manifest["keyset"]["keys"][0]["role"] = "offline-recovery"
        with self.assertRaises(audit.AdapterError):
            self.verify("catalog-keyset", {"authority.json": encoded(manifest)})

    def test_pilot_signed_review_cohort_is_separate_from_runtime(self):
        from .third_party_pilot_fixtures import PilotFixture
        fixture = PilotFixture(self.root / "pilot")
        payloads = {"execution.json": fixture.contract_path.read_bytes()}
        for name, key in (("handoff", "externalHandoff"), ("review", "reviewCohort"), ("approval", "publisherApproval")):
            payloads[name + ".json"] = (fixture.evidence / fixture.contract["evidence"][key]["fileName"]).read_bytes()
        result = self.verify("pilot-review", payloads, fixture.contract["evaluationTime"])
        self.assertIn("p12-294-review", result["claims"])
        self.assertIn("pilot-runtime-not-observed", result["blockers"])
        changed = json.loads(payloads["review.json"])
        changed["appId"] = "unrelated-external-app"
        payloads["review.json"] = encoded(changed)
        with self.assertRaises(audit.AdapterError):
            self.verify("pilot-review", payloads, fixture.contract["evaluationTime"])

    def federation(self):
        from .test_stable_federated_catalog import FederationFixture
        (self.root / "federation").mkdir()
        fixture = FederationFixture(self.root / "federation")
        payloads = {"execution.json": fixture.contract_path.read_bytes(),
                    "descriptor.json": (fixture.evidence / "descriptor.json").read_bytes(),
                    "runtime.json": (fixture.evidence / "runtime.json").read_bytes(),
                    "endorsements.json": encoded([base64.b64encode((fixture.evidence / "endorsement.json").read_bytes()).decode()])}
        return fixture, payloads

    def test_federation_signature_subject_and_original_observer_remain_distinct(self):
        fixture, payloads = self.federation()
        result = self.verify("federation-trust", payloads, "2026-08-25T12:00:00Z")
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
        self.assertIn("p12-295-origin", result["claims"])
        self.assertIn("original-federation-observer-authority-required", result["blockers"])
        with self.assertRaises(audit.AdapterError):
            self.verify("federation-trust", payloads, "2026-09-10T00:00:00Z")
        with self.assertRaises(audit.AdapterError):
            self.verify("federation-trust", payloads, "2026-08-24T12:00:00Z")

    def test_federation_attempt_replay_and_semantic_for_byte_digest_fail(self):
        fixture, payloads = self.federation()
        contract = copy.deepcopy(fixture.contract)
        contract["evidence"]["runtimeObservation"]["receiptProvenance"]["runAttempt"] += 1
        payloads["execution.json"] = encoded(contract)
        with self.assertRaises(audit.AdapterError):
            self.verify("federation-trust", payloads, "2026-08-25T12:00:00Z")
        contract = copy.deepcopy(fixture.contract)
        contract["evidence"]["descriptor"]["digest"] = "sha256:" + fixture.descriptor["selfDigestSha256"]
        payloads["execution.json"] = encoded(contract)
        with self.assertRaises(audit.AdapterError):
            self.verify("federation-trust", payloads, "2026-08-25T12:00:00Z")

    def package(self):
        return sources.collect({"schemaVersion": 1, "mode": "production", "asOf": "2026-09-10T00:00:00Z", "sources": []}, self.root)

    def zip(self, files):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name, raw in sorted(files.items()):
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, raw)
        return stream.getvalue()

    def test_empty_production_admission_does_not_establish_inventory_or_deployment(self):
        result = self.verify("transparency-sources", {"source-package.json": encoded(self.package())})
        self.assertEqual(["empty-source-selection-verified"], result["coverage"]["observed"])
        self.assertIn("site-deployment-not-observed", result["blockers"])
        self.assertNotIn("publication", result["dimensions"])

    def test_exact_bundle_verification_rejects_resealed_presentation_and_sidecars(self):
        files = bundle.render_files(self.package())
        result = self.verify("transparency-bundle", {"bundle.zip": self.zip(files)})
        self.assertEqual(["deterministic-site-bundle"], result["coverage"]["observed"])
        for name, raw in (("index.html", b"phase complete"), ("private-contact-canary.json", b"private-contact-canary"), ("../escape", b"private-canary")):
            changed = {**files, name: raw}
            with self.subTest(name=name), self.assertRaises(audit.AdapterError) as caught:
                self.verify("transparency-bundle", {"bundle.zip": self.zip(changed)})
            self.assertNotIn("canary", str(caught.exception))

    def test_site_archive_rejects_appended_payload_comments_and_member_extras(self):
        files = bundle.render_files(self.package())
        attacks = [self.zip(files) + b"private-contact-canary"]
        for kind in ("archive-comment", "member-comment", "member-extra"):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                for number, (name, raw) in enumerate(sorted(files.items())):
                    info = zipfile.ZipInfo(name)
                    if number == 0 and kind == "member-comment":
                        info.comment = b"private-contact-canary"
                    if number == 0 and kind == "member-extra":
                        info.extra = b"\xff\xff\x00\x00"
                    archive.writestr(info, raw)
                if kind == "archive-comment":
                    archive.comment = b"private-contact-canary"
            attacks.append(output.getvalue())
        for raw in attacks:
            with self.assertRaises(audit.AdapterError) as caught:
                self.verify("transparency-bundle", {"bundle.zip": raw})
            self.assertNotIn("canary", str(caught.exception))

    def test_core_merges_actual_bundle_claim_with_executed_verifier_without_operational_upgrade(self):
        from cryptad_certification import phase_12_closeout as closeout
        files = bundle.render_files(self.package())
        raw = self.zip(files)
        selected = closeout.repository_selection()
        identity = closeout.checkout()
        selected["artifacts"] = [{
            "id": "checked-site", "adapter": "transparency-bundle",
            "files": [{"name": "bundle.zip", "digest": sources.digest(raw), "size": len(raw)}],
            "subject": {"kind": "public-site", "commit": identity["commit"], "tree": identity["tree"],
                        "build": None, "digest": sources.digest(files[bundle.MANIFEST])},
            "predecessors": [], "proof": None, "observedAt": None, "expiresAt": None}]
        inputs = self.root / "inputs"
        (inputs / "checked-site").mkdir(parents=True)
        (inputs / "checked-site" / "bundle.zip").write_bytes(raw)
        # The real core executes the real deterministic bundle verifier. No adapter or
        # producer verdict is mocked; the empty source package has no operational authority.
        with patch("socket.socket", side_effect=AssertionError("offline-network-denied")):
            assessed = closeout.evaluate(selected, inputs, "2026-09-10T00:00:00Z")
        rows = {row["id"]: row for row in assessed["requirements"]}
        self.assertEqual("executed-pass", rows["p12-302-bundle"]["dimensions"]["localVerification"])
        self.assertEqual("complete", rows["p12-302-bundle"]["dimensions"]["coverage"])
        self.assertEqual("not-observed", rows["p12-302-deployment"]["dimensions"]["publication"])
        self.assertEqual("not-observed", rows["p12-302-observation"]["dimensions"]["publicObservation"])
        self.assertFalse(assessed["phaseComplete"])

    def test_historical_checkpoint_preserves_old_tool_without_claiming_rerender(self):
        with patch.object(bundle, "tool_identity", return_value="sha256:" + "a" * 64):
            files = bundle.render_files(self.package())
        payloads = {"bundle.zip": self.zip(files),
                    "checkpoint.json": encoded({"manifestDigest": sources.digest(files[bundle.MANIFEST])})}
        result = self.verify("historical-transparency-bundle", payloads)
        self.assertEqual(["historical-exact-site-checkpoint"], result["coverage"]["observed"])
        self.assertIn("original-historical-site-tool-proof-required", result["blockers"])
        with self.assertRaises(audit.AdapterError):
            self.verify("transparency-bundle", {"bundle.zip": payloads["bundle.zip"]})
        payloads["checkpoint.json"] = encoded({"manifestDigest": "sha256:" + "0" * 64})
        with self.assertRaises(audit.AdapterError):
            self.verify("historical-transparency-bundle", payloads)

    def test_duplicate_extra_unknown_and_deep_inputs_fail_with_fixed_private_safe_error(self):
        attacks = [("catalog-keyset", {"authority.json": b'{"kind":1,"kind":2}'}),
                   ("transparency-sources", {"source-package.json": encoded(self.package()), "private.json": b"canary"}),
                   ("caller.module.execute", {"payload.json": b"{}"}),
                   ("catalog-keyset", {"authority.json": b"[" * 40 + b"0" + b"]" * 40})]
        for adapter, payloads in attacks:
            with self.subTest(adapter=adapter), self.assertRaisesRegex(audit.AdapterError, "^phase12-owner-evidence-invalid$"):
                self.verify(adapter, payloads)

    def test_ga_receipt_reruns_original_freeze_plan_and_publication_checks(self):
        from . import test_stable_protected_release as fixture
        root = self.root / "ga"
        root.mkdir()
        contract = fixture._contract(root)
        fixture._configure_publication_receipt(root, contract)
        names = {"freeze.json": "stable-1.0-rc-freeze.json", "authorization.json": "exact-authorization.json",
                 "plan.json": "stable-1.0-ga-publication-plan.json", "receipt.json": "ga-publication-receipt.json",
                 "identity.json": "stable-1.0-ga-validation-authorization-identity.json"}
        payloads = {name: (root / source).read_bytes() for name, source in names.items()}
        payloads["contract.json"] = encoded(contract)
        result = self.verify("protected-ga-receipt", payloads)
        self.assertIn("p12-291-publication", result["claims"])
        self.assertIn("exact-frozen-product-bytes-required", result["blockers"])
        self.assertNotIn("publication", result["dimensions"])
        receipt = json.loads(payloads["receipt.json"])
        receipt["workflow"]["runAttempt"] += 1
        payloads["receipt.json"] = encoded(receipt)
        with self.assertRaises(audit.AdapterError):
            self.verify("protected-ga-receipt", payloads)

    def test_independent_actual_archive_comparison_preserves_unproven_provider(self):
        from . import test_stable_protected_release as ga
        from .stable_independent_protected_fixture import _independent_reproducibility_evidence
        from .test_stable_supply_chain import SupplyChainFixture
        from cryptad_certification.engines import stable_1_0_independent_reproducibility as owner
        root = self.root / "independent"
        root.mkdir()
        ga_contract = ga._contract(root)
        ga._configure_publication_receipt(root, ga_contract)
        protected_policy = json.loads((audit.POLICIES / "stable-1.0-protected-release-policy.json").read_bytes())
        members = _independent_reproducibility_evidence(root, ga_contract, protected_policy, fixture=True)
        primary = json.loads(members["stable-1.0-primary-builder-receipt.json"].read_bytes())
        external = json.loads(members["stable-1.0-independent-builder-receipt.json"].read_bytes())
        manifest = json.loads(members["stable-1.0-independent-output-manifest.json"].read_bytes())
        products = SupplyChainFixture(root / "products")
        inventory = copy.deepcopy(products.subjects)
        inventory.update(releaseId=primary["releaseId"], buildVersion=primary["buildVersion"], sourceCommit=primary["sourceCommit"])
        inventory["subjectInventoryDigest"] = owner._strict_digest(inventory, "subjectInventoryDigest")
        contract = json.loads((audit.POLICIES / "manifests/stable-1.0-independent-reproducibility.example.json").read_bytes())
        contract["repository"].update(sourceCommit=primary["sourceCommit"], sourceRef=primary["sourceRef"], sourceTreeDigest=primary["source"]["treeDigest"])
        contract["release"].update(id=primary["releaseId"], integerBuild=primary["buildVersion"], tag=primary["tag"])
        contract["authenticatedInputs"].update(subjectInventoryDigest=inventory["subjectInventoryDigest"], buildMaterialsDigest=primary["materialsDigest"], resolutionSnapshotDigest=primary["resolutionSnapshotDigest"])
        contract["expectedVerifierAuthority"]["profileDigest"] = external["providerProfileDigest"]
        contract["buildRecipe"]["expectedOutputs"] = [{key: row[key] for key in ("subjectKey", "fileName", "reproducibilityClass", "normalizationRuleId")} for row in manifest["subjects"]]
        contract["evidenceClassification"]["selfTest"] = "passed"
        contract["executionContractDigest"] = owner.execution_contract_digest(contract)
        external["executionContractDigest"] = contract["executionContractDigest"]
        normalized = {row["subjectKey"] for row in manifest["subjects"] if row["reproducibilityClass"] == "normalized-payload-identical"}
        for row in external["subjects"]:
            if row["subjectKey"] not in normalized:
                row["payloadManifestDigest"] = None
        for row in manifest["subjects"]:
            if row["subjectKey"] not in normalized:
                row["payloadManifestDigest"] = None
        manifest["subjectSetDigest"] = sources.digest(encoded(manifest["subjects"]))
        for execution in external["builderExecutions"]:
            if execution["handoffDigest"] is not None:
                execution["handoffDigest"] = sources.digest(("independent-" + execution["executionId"]).encode())
        external["receiptDigest"] = owner._strict_digest(external, "receiptDigest")
        manifest["executionContractDigest"] = contract["executionContractDigest"]
        manifest["builderReceiptDigest"] = external["receiptDigest"]
        for row in manifest["payloadManifests"]:
            raw = (products.payload_root / (row["subjectKey"] + ".json")).read_bytes()
            row.update(sha256=sources.digest(raw), size=len(raw))
        manifest["manifestDigest"] = owner._strict_digest(manifest, "manifestDigest")
        payloads = {"contract.json": encoded(contract), "inventory.json": encoded(inventory),
                    "primary.json": encoded(primary), "external.json": encoded(external), "output-manifest.json": encoded(manifest)}
        archives = {}
        for name, receipt, output in (("primary.zip", primary, None), ("external.zip", external, manifest)):
            files = {path: (products.root / path).read_bytes() for path in owner._bundle_paths(receipt, output)}
            archives[name] = files
            payloads[name] = self.zip(files)
        result = self.verify("independent-comparison", payloads)
        self.assertEqual("synthetic-rehearsal", result["evidenceClass"])
        self.assertIn("owner-exact-and-normalized-byte-comparison", result["coverage"]["observed"])
        self.assertIn("original-builder-and-kit-proofs-required", result["blockers"])
        changed = dict(archives["external.zip"])
        target = next(name for name in sorted(changed) if name.startswith("subjects/"))
        changed[target] += b"changed-after-builder-receipt"
        payloads["external.zip"] = self.zip(changed)
        with self.assertRaises(audit.AdapterError):
            self.verify("independent-comparison", payloads)


if __name__ == "__main__":
    unittest.main()
