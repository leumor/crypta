"""Offline original-artifact substitution tests; no GitHub or node execution."""
from __future__ import annotations

import hashlib
import gzip
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from cryptad_certification.tests.test_stable_ga import _write_exact_rc_fixture

_MODULE = Path(__file__).resolve().parents[2] / "protected/cross_version_product_admission.py"
_SPEC = importlib.util.spec_from_file_location("cross_version_product_admission", _MODULE)
products = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = products
_SPEC.loader.exec_module(products)


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as source:
        for name, content in files.items():
            source.writestr(name, content)
    return output.getvalue()


class CrossVersionProductAdmissionTest(unittest.TestCase):
    def test_prospective_capability_rechecks_exact_native_roster_and_runtime_surface(self):
        from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
        plan = fixture_plan()
        contract = {"contractVersion": plan["nodes"][0]["contractVersion"], "capabilities": []}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows, private = {}, {"nodes": {}}
            for node in plan["nodes"]:
                role = node["role"]
                package = root / (role + ".tar.gz")
                package.write_bytes(role.encode())
                node.update(artifactDigest=products.file_digest(package), artifactSize=package.stat().st_size)
                bundle = root / (role + ".app")
                bundle.write_bytes(b"exact app " + role.encode())
                app_digest = products.file_digest(bundle)
                node["appDigests"] = [] if role == "relay-no-apps" else [app_digest]
                matrix = [] if not node["appDigests"] else [{"appId": "site-publisher", "bundleDigest": app_digest,
                    "bundleSize": bundle.stat().st_size, "nativeAdmission": "accepted", "contractVerifier": "executed"}]
                rows[role] = {**node, "path": package, "runtimeRoot": root,
                    "runtimeBinding": {"contractSemanticDigest": products.digest(contract)},
                    "requiredAppIds": [app["appId"] for app in matrix], "appMatrix": matrix}
                private["nodes"][role] = {"archivePath": str(package), "apps": [
                    {"appId": "site-publisher", "bundlePath": str(bundle), "bundleDigest": app_digest}] if matrix else []}
            authority = products.AuthenticatedProducts(products._SEAL, products.digest(plan), rows)
            self.assertTrue(authority.bind(plan, private))
            self.assertTrue(authority.bind_apps(plan))
            role = plan["nodes"][0]["role"]
            self.assertTrue(authority.verify_runtime_contract(role, {"contract": contract}))
            with self.assertRaisesRegex(products.ProductAdmissionError, "exact-subject-mismatch"):
                authority.verify_runtime_contract(role, {"contract": {**contract, "capabilities": ["substituted"]}})
            self.assertFalse(any("runtimeRoot" in row or "path" in row for row in authority.public_identities()))
            selected = Path(private["nodes"][role]["apps"][0]["bundlePath"])
            selected.write_bytes(b"changed")
            with self.assertRaisesRegex(products.ProductAdmissionError, "app-substituted"):
                authority.bind(plan, private)

    def maintenance_fixture(self, mutate=None):
        from cryptad_certification.tests.test_stable_maintenance_workflows import _activation_candidate_freeze
        freeze = _activation_candidate_freeze("2026-09-10T00:00:00Z")
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode="w") as tar:
            member = tarfile.TarInfo("cryptad-dist/README.txt")
            member.size, member.mode = 7, 0o644
            member.uname = member.gname = "root"
            tar.addfile(member, io.BytesIO(b"fixture"))
        payload = gzip.compress(tar_bytes.getvalue(), mtime=0)
        files = {"cryptad-v301.tar.gz": payload, "stable-catalog.json": b"synthetic catalog",
                 "stable-catalog.json.sig": b"synthetic signature"}
        for row in freeze["assets"]:
            if row["role"] == "product":
                row["fileName"] = "cryptad-v301.tar.gz"
            value = files[row["fileName"]]
            row.update(digest="sha256:" + hashlib.sha256(value).hexdigest(), sizeBytes=len(value))
        freeze["assets"].sort(key=lambda row: row["fileName"])
        checksums = "".join(row["digest"][7:] + "  " + row["fileName"] + "\n" for row in freeze["assets"]).encode()
        freeze["checksumsDigest"] = "sha256:" + hashlib.sha256(checksums).hexdigest()
        freeze["assetSetDigest"] = products.maintenance.semantic_digest(freeze["assets"])
        if mutate:
            mutate(freeze)
        freeze_bytes = json.dumps(freeze).encode()
        content = archive({"freeze/" + products.maintenance.CANDIDATE_FREEZE_FILE: freeze_bytes,
                           "freeze/checksums.txt": checksums,
                           **{"freeze/assets/" + name: value for name, value in files.items()}})
        coordinates = {"sourceFamily": "stable-maintenance-freeze", "sourceCommit": "b" * 40,
                       "runId": 1, "runAttempt": 1,
                       "artifactName": "stable-1-0-maintenance-frozen-stable-1.0-maintenance-301-301-1-1"}
        node = {"role": "previous", "sourceCommit": "b" * 40, "product": "cryptad",
                "artifactDigest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "artifactSize": len(payload), "packageTarget": "linux-x64", "appDigests": []}
        return SimpleNamespace(content=content, coordinates=coordinates), node, "sha256:" + hashlib.sha256(freeze_bytes).hexdigest()

    def test_maintenance_original_freeze_selects_exact_portable_and_all_asset_checksums(self):
        original, node, freeze_digest = self.maintenance_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            row = products.verify_maintenance_artifact(original, node, freeze_digest, Path(temporary).resolve() / "selected")
            self.assertEqual(node["artifactDigest"], products.file_digest(row["path"]))
            self.assertEqual(freeze_digest, row["maintenanceFreezeDigest"])
            self.assertEqual("existing-maintenance-freeze-exact-product-v1", row["frozenPortableBinding"])
            self.assertEqual("not-established-runtime-observation-required", row["runtimeContractAuthentication"])
            self.assertNotIn("contractVersion", row)
            self.assertNotIn("releaseEligible", row)

    def test_maintenance_app_only_freeze_and_original_producer_or_time_substitution_are_denied(self):
        mutations = (
            lambda value: value.update(kind="stable-1.0-rc-freeze"),
            lambda value: value["producer"].update(runAttempt=2),
            lambda value: value["producer"].update(workflowCommit="c" * 40),
            lambda value: value.update(generatedAt="2026-09-09T00:00:00Z"),
            lambda value: value["predecessorObservation"].update(observedAt="2026-09-11T00:00:00Z"),
            lambda value: value["assets"].pop(0),
        )
        for index, mutation in enumerate(mutations):
            original, node, freeze_digest = self.maintenance_fixture(mutation)
            with self.subTest(case=index), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(products.ProductAdmissionError):
                    products.verify_maintenance_artifact(original, node, freeze_digest, Path(temporary).resolve() / "selected")

    def test_maintenance_exact_byte_digest_is_not_semantic_digest_or_other_package(self):
        original, node, freeze_digest = self.maintenance_fixture()
        with zipfile.ZipFile(io.BytesIO(original.content)) as source:
            freeze = json.loads(source.read("freeze/" + products.maintenance.CANDIDATE_FREEZE_FILE))
        cases = ((products.maintenance.semantic_digest(freeze), node),
                 (freeze_digest, {**node, "artifactDigest": "sha256:" + "c" * 64}))
        for selected_digest, selected_node in cases:
            with self.subTest(digest=selected_digest), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(products.ProductAdmissionError):
                    products.verify_maintenance_artifact(original, selected_node, selected_digest, Path(temporary).resolve() / "selected")

    def test_maintenance_checks_every_frozen_asset_not_only_portable(self):
        original, node, freeze_digest = self.maintenance_fixture()
        with zipfile.ZipFile(io.BytesIO(original.content)) as source:
            files = {name: source.read(name) for name in source.namelist()}
        files["freeze/assets/stable-catalog.json"] += b"substitution"
        original.content = archive(files)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(products.ProductAdmissionError, "asset-byte-mismatch"):
                products.verify_maintenance_artifact(original, node, freeze_digest, Path(temporary).resolve() / "selected")

    def test_maintenance_authentication_checks_three_exact_original_member_attestations(self):
        original, node, freeze_digest = self.maintenance_fixture()
        invocation = "https://github.com/crypta-network/cryptad/actions/runs/1/attempts/1"
        result = [{"verificationResult": {"signature": {"certificate": {"runInvocationURI": invocation}}}}]
        for accepted in (True, False):
            with self.subTest(accepted=accepted), tempfile.TemporaryDirectory() as temporary:
                with patch.object(products, "authenticate_original", return_value=original), \
                        patch.object(products, "_environment", return_value={}), \
                        patch.object(products, "_gh", return_value=result if accepted else []) as gh:
                    selection = {"coordinates": original.coordinates, "freezeDigest": freeze_digest}
                    if accepted:
                        row = products.authenticate_maintenance_product(selection, node, Path(temporary).resolve() / "private")
                        self.assertEqual(3, gh.call_count)
                        self.assertEqual(node["artifactDigest"], products.file_digest(row["path"]))
                    else:
                        with self.assertRaisesRegex(products.ProductAdmissionError, "attested-attempt-mismatch"):
                            products.authenticate_maintenance_product(selection, node, Path(temporary).resolve() / "private")

    def test_maintenance_app_bearing_runtime_intake_fails_before_original_fetch(self):
        from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
        plan = fixture_plan()
        plan.update(profile="bounded-live", provenanceClass="production-artifact-comparison")
        selection = {"schemaVersion": 1, "roles": {node["role"]: {"maintenanceProduct": {}}
                     for node in plan["nodes"]}}
        with tempfile.TemporaryDirectory() as temporary, patch.object(products, "authenticate_original") as authenticate:
            with self.assertRaisesRegex(products.ProductAdmissionError, "app-contract-projection-not-established"):
                products.authenticate_products(plan, selection, Path(temporary).resolve() / "private")
            authenticate.assert_not_called()

    def test_maintenance_path_rejects_symlink_parent_without_authentication(self):
        original, node, freeze_digest = self.maintenance_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "link").symlink_to(root, target_is_directory=True)
            with patch.object(products, "authenticate_original") as authenticate:
                with self.assertRaisesRegex(products.ProductAdmissionError, "root-must-be-new"):
                    products.authenticate_maintenance_product(
                        {"coordinates": original.coordinates, "freezeDigest": freeze_digest}, node, root / "link" / "private")
                authenticate.assert_not_called()

    def rc(self, root):
        _context, paths = _write_exact_rc_fixture(root / "fixture")
        artifact_root = paths["selectedStableRcFreeze"].parent
        files = {p.relative_to(artifact_root).as_posix(): p.read_bytes() for p in artifact_root.rglob("*") if p.is_file()}
        coordinates = {"sourceCommit": "a" * 40, "runId": 42, "runAttempt": 3,
                       "artifactName": "stable-1-0-rc-stable-1-0-rc-284-284-42-3"}
        return SimpleNamespace(content=archive(files), coordinates=coordinates)

    def portable(self, selected):
        payload = b"selected old portable archive bytes"
        checksum = hashlib.sha256(payload).hexdigest()
        coordinates = {"sourceCommit": "a" * 40, "runId": 84, "runAttempt": 2}
        checksum_bytes = (checksum + "  ./distributions/cryptad-v284.tar.gz\n").encode()
        handoff = {"schemaVersion": 1, "kind": "cryptad-stable-supply-chain-builder-handoff",
                   "builderRole": "candidate-producer", "executionId": "portable-apps",
                   "jobName": "candidate-producer-portable-apps", "runnerOs": "linux", "runnerArchitecture": "amd64",
                   "releaseId": "stable-1-0-rc-284", "buildVersion": 284, "sourceCommit": "a" * 40,
                   "workflowSha": "a" * 40, "runId": 84, "runAttempt": 2,
                   "workflow": "github.com/crypta-network/cryptad/.github/workflows/stable-1.0-supply-chain.yml@" + "a" * 40,
                   "fileSetDigest": "sha256:" + hashlib.sha256(checksum_bytes).hexdigest()}
        raw = archive({"handoff.json": json.dumps(handoff), "subject-files.sha256": checksum_bytes,
                       "subjects/distributions/cryptad-v284.tar.gz": payload})
        node = {"role": "previous", "artifactDigest": "sha256:" + checksum, "artifactSize": len(payload),
                "sourceCommit": "a" * 40, "product": "cryptad", "packageTarget": "linux-x64",
                "contractVersion": selected.freeze["platformApi"]["currentContractVersion"]}
        return SimpleNamespace(content=raw, coordinates=coordinates), node, payload

    def selected(self, root):
        original = self.rc(root)
        result = products.verify_rc_artifact(original, root / "selected")
        return SimpleNamespace(**result.__dict__, _original_coordinates=original.coordinates)

    def test_rc_uses_existing_freeze_product_checksums_and_archive_consumer(self):
        with tempfile.TemporaryDirectory() as temporary:
            selected = self.selected(Path(temporary).resolve())
            self.assertEqual("a" * 40, selected.freeze["candidate"]["sourceCommit"])
            self.assertEqual(selected.product_digest, selected.freeze["candidate"]["productionDistributionDigest"])

    def test_portable_subject_reopens_exact_original_member_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            selected = self.selected(root)
            original, node, payload = self.portable(selected)
            row = products.verify_portable_artifact(original, selected, node, root / "portable.tar.gz")
            self.assertEqual(payload, row["path"].read_bytes())
            self.assertEqual("not-established", row["frozenPortableBinding"])
            self.assertEqual("284", row["buildVersion"])
            self.assertEqual(84, row["portableOrigin"]["runId"])

    def test_portable_wrong_role_digest_source_contract_and_target_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            selected = self.selected(root)
            original, node, _payload = self.portable(selected)
            for field, value in (("artifactDigest", "sha256:" + "f" * 64), ("sourceCommit", "b" * 40),
                                 ("contractVersion", 999), ("packageTarget", "windows-x64")):
                with self.subTest(field=field):
                    with self.assertRaises(products.ProductAdmissionError):
                        products.verify_portable_artifact(original, selected, {**node, field: value}, root / "never")

    def test_rc_source_cannot_be_rebound_to_current_producer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            original = self.rc(root)
            original.coordinates["sourceCommit"] = "b" * 40
            with self.assertRaisesRegex(products.ProductAdmissionError, "source-mismatch"):
                products.verify_rc_artifact(original, root / "selected")

    def test_archive_links_traversal_case_collision_and_duplicates_rejected(self):
        for names in (("../outside",), ("/outside",), ("a", "A")):
            with self.subTest(names=names), self.assertRaises(products.ProductAdmissionError):
                products._members(archive({name: b"x" for name in names}))
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as source:
            member = zipfile.ZipInfo("link")
            member.external_attr = 0o120777 << 16
            source.writestr(member, b"outside")
        with self.assertRaises(products.ProductAdmissionError):
            products._members(output.getvalue())

    def test_rc_checksum_corruption_is_rejected_by_existing_consumer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            original = self.rc(root)
            with zipfile.ZipFile(io.BytesIO(original.content)) as source:
                files = {name: source.read(name) for name in source.namelist()}
            files["crypta-stable-1.0-rc-284-product.tar.gz"] += b"changed"
            original.content = archive(files)
            with self.assertRaises(products.ProductAdmissionError):
                products.verify_rc_artifact(original, root / "selected")

    def test_portable_attestation_requires_original_attempt_for_both_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            selected = self.selected(root)
            original, node, _payload = self.portable(selected)
            package = root / "portable.tar.gz"
            products.verify_portable_artifact(original, selected, node, package)
            invocation = "https://github.com/crypta-network/cryptad/actions/runs/84/attempts/2"
            result = [{"verificationResult": {"signature": {"certificate": {"runInvocationURI": invocation}}}}]
            with patch.object(products, "_environment", return_value={}), patch.object(products, "_gh", return_value=result) as gh:
                products.verify_portable_attestations(original, package, root)
                self.assertEqual(2, gh.call_count)
                self.assertIn("--source-digest", gh.call_args.args[0])

    def test_portable_reuploaded_attestation_attempt_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            selected = self.selected(root)
            original, node, _payload = self.portable(selected)
            package = root / "portable.tar.gz"
            products.verify_portable_artifact(original, selected, node, package)
            invocation = "https://github.com/crypta-network/cryptad/actions/runs/84/attempts/99"
            result = [{"verificationResult": {"signature": {"certificate": {"runInvocationURI": invocation}}}}]
            with patch.object(products, "_environment", return_value={}), patch.object(products, "_gh", return_value=result):
                with self.assertRaisesRegex(products.ProductAdmissionError, "attested-attempt"):
                    products.verify_portable_attestations(original, package, root)

    def test_required_roster_omission_stops_before_any_network_authentication(self):
        from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
        plan = fixture_plan()
        plan["profile"] = "bounded-live"
        plan["provenanceClass"] = "production-artifact-comparison"
        with tempfile.TemporaryDirectory() as temporary, patch.object(products, "authenticate_original") as authenticate:
            with self.assertRaisesRegex(products.ProductAdmissionError, "required-roster"):
                products.authenticate_products(plan, {"schemaVersion": 1, "roles": {}}, Path(temporary).resolve() / "private")
            authenticate.assert_not_called()

    def test_protected_long_product_selection_still_requires_original_roster(self):
        from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
        plan = fixture_plan()
        plan.update({"profile": "protected-long-live", "provenanceClass": "production-artifact-comparison", "requestedSeconds": 72 * 3600})
        plan["policy"]["minimumObservedSeconds"] = 72 * 3600
        with tempfile.TemporaryDirectory() as temporary, patch.object(products, "authenticate_original") as authenticate:
            with self.assertRaisesRegex(products.ProductAdmissionError, "required-roster"):
                products.authenticate_products(plan, {}, Path(temporary).resolve() / "private")
            authenticate.assert_not_called()

    def test_full_original_rc_and_portable_pipeline_binds_four_roles(self):
        from cryptad_certification.tests import test_stable_ga as fixtures
        from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
        from cryptad_certification.tests.test_stable_rc import _freeze
        plan = fixture_plan()
        plan.update({"profile": "bounded-live", "provenanceClass": "production-artifact-comparison"})
        originals = {}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for source_commit, build in (("a" * 40, "284"), ("b" * 40, "283")):
                release_id = "stable-1-0-rc-" + build
                def current_freeze():
                    freeze = _freeze()
                    freeze["platformApi"]["currentContractVersion"] = 25
                    return freeze
                with patch.multiple(fixtures, SOURCE_COMMIT=source_commit, SOURCE_REF="commit:" + source_commit,
                                    BUILD_VERSION=build, RELEASE_ID=release_id, _complete_rc_freeze=current_freeze):
                    _context, paths = fixtures._write_exact_rc_fixture(root / ("fixture-" + build))
                artifact_root = paths["selectedStableRcFreeze"].parent
                files = {p.relative_to(artifact_root).as_posix(): p.read_bytes() for p in artifact_root.rglob("*") if p.is_file()}
                coordinates = {"sourceFamily": "stable-rc-product", "sourceCommit": source_commit, "runId": int(build), "runAttempt": 1,
                               "artifactName": f"stable-1-0-rc-{release_id}-{build}-{build}-1"}
                originals[("stable-rc-product", source_commit)] = SimpleNamespace(content=archive(files), coordinates=coordinates)
                payload = ("actual selected portable fixture " + source_commit).encode()
                checksum = hashlib.sha256(payload).hexdigest()
                checksum_bytes = (checksum + f"  ./distributions/cryptad-v{build}.tar.gz\n").encode()
                portable_coordinates = {"sourceFamily": "first-party-release", "sourceCommit": source_commit,
                                        "runId": int(build) + 1000, "runAttempt": 2}
                handoff = {"schemaVersion": 1, "kind": "cryptad-stable-supply-chain-builder-handoff", "builderRole": "candidate-producer",
                           "executionId": "portable-apps", "jobName": "candidate-producer-portable-apps", "runnerOs": "linux", "runnerArchitecture": "amd64",
                           "releaseId": release_id, "buildVersion": int(build), "sourceCommit": source_commit, "workflowSha": source_commit,
                           "runId": int(build) + 1000, "runAttempt": 2,
                           "workflow": "github.com/crypta-network/cryptad/.github/workflows/stable-1.0-supply-chain.yml@" + source_commit,
                           "fileSetDigest": "sha256:" + hashlib.sha256(checksum_bytes).hexdigest()}
                originals[("first-party-release", source_commit)] = SimpleNamespace(
                    content=archive({"handoff.json": json.dumps(handoff), "subject-files.sha256": checksum_bytes,
                                     f"subjects/distributions/cryptad-v{build}.tar.gz": payload}), coordinates=portable_coordinates)
                for node in plan["nodes"]:
                    if node["sourceCommit"] == source_commit:
                        node.update({"artifactDigest": "sha256:" + checksum, "artifactSize": len(payload), "contractVersion": 25})
            selection = {"schemaVersion": 1, "roles": {node["role"]: {
                "rcCoordinates": originals[("stable-rc-product", node["sourceCommit"])].coordinates,
                "portableCoordinates": originals[("first-party-release", node["sourceCommit"])].coordinates}
                for node in plan["nodes"]}}
            def authenticate(coordinates, _root):
                return originals[(coordinates["sourceFamily"], coordinates["sourceCommit"])]
            def attest(arguments, _environment):
                source = arguments[arguments.index("--source-digest") + 1]
                run = originals[("first-party-release", source)].coordinates["runId"]
                return [{"verificationResult": {"signature": {"certificate": {"runInvocationURI":
                    f"https://github.com/crypta-network/cryptad/actions/runs/{run}/attempts/2"}}}}]
            with patch.object(products, "authenticate_original", side_effect=authenticate), \
                    patch.object(products, "_environment", return_value={}), patch.object(products, "_gh", side_effect=attest):
                admitted = products.authenticate_products(plan, selection, root / "authenticated")
            private = {"nodes": {role: {"archivePath": path} for role, path in admitted.package_paths().items()}}
            self.assertTrue(admitted.bind(plan, private))
            identities = admitted.public_identities()
            self.assertEqual(4, len(identities))
            previous = next(row for row in identities if row["role"] == "previous")
            self.assertEqual("b" * 40, previous["sourceCommit"])
            self.assertEqual("283", previous["buildVersion"])
            # An explicitly selected byte-identical local copy retains its original authority.
            copy = root / "selected-copy.tar.gz"
            copy.write_bytes(Path(private["nodes"]["previous"]["archivePath"]).read_bytes())
            private["nodes"]["previous"]["archivePath"] = str(copy)
            self.assertTrue(admitted.bind(plan, private))
            copy.write_bytes(b"substituted")
            with self.assertRaises(products.ProductAdmissionError):
                admitted.bind(plan, private)

            # The existing roster can mix original RC/supply-chain subjects with an app-free
            # maintenance subject. Each keeps its own producer; no current-SHA relabeling.
            maintenance_original, maintenance_node, freeze_digest = self.maintenance_fixture()
            relay = next(node for node in plan["nodes"] if node["role"] == "relay-no-apps")
            relay.update({key: value for key, value in maintenance_node.items() if key != "role"})
            originals[("stable-maintenance-freeze", maintenance_node["sourceCommit"])] = maintenance_original
            selection["roles"]["relay-no-apps"] = {"maintenanceProduct": {
                "coordinates": maintenance_original.coordinates, "freezeDigest": freeze_digest}}
            def mixed_attest(arguments, environment):
                if "stable-1.0-maintenance-release.yml" in " ".join(arguments):
                    return [{"verificationResult": {"signature": {"certificate": {
                        "runInvocationURI": "https://github.com/crypta-network/cryptad/actions/runs/1/attempts/1"}}}}]
                return attest(arguments, environment)
            with patch.object(products, "authenticate_original", side_effect=authenticate), \
                    patch.object(products, "_environment", return_value={}), patch.object(products, "_gh", side_effect=mixed_attest):
                mixed = products.authenticate_products(plan, selection, root / "mixed-authenticated")
            mixed_private = {"nodes": {role: {"archivePath": path} for role, path in mixed.package_paths().items()}}
            self.assertTrue(mixed.bind(plan, mixed_private))
            selected_relay = next(row for row in mixed.public_identities() if row["role"] == "relay-no-apps")
            self.assertEqual(freeze_digest, selected_relay["maintenanceFreezeDigest"])

    def app_projection_fixture(self, root, required=None, optional=None):
        import app_subject_projection as projection
        from test_app_subject_projection import ProjectionBoundaryTest
        inventory, _contract, _policy = ProjectionBoundaryTest().inventory()
        declaration = inventory["subjects"][0]["signedProjection"]
        declaration.update({"appId": "mail-prototype", "targetStability": "experimental", "targetBaseline": None,
                            "minimumContractVersion": 25, "maximumTestedContractVersion": 25,
                            "experimentalCapabilitiesAccepted": True,
                            "requiredCapabilities": required or ["content.fetch"], "optionalCapabilities": optional or []})
        inventory["subjects"] = [{"signedProjection": declaration}]
        authenticated = projection.AuthenticatedProjection(inventory, "sha256:" + "c" * 64, projection._VERIFIED)
        snapshot = {"contract": {"contractVersion": 25, "stableBaseline": {"name": "1.0", "contractVersion": 19,
                                 "capabilities": ["content.fetch"]},
                                 "capabilities": [{"name": "content.fetch", "stability": "stable", "audience": "app"}]}}
        contract_path = root / "platform-api-current-contract.json"
        contract_path.write_text(json.dumps(snapshot))
        selected = SimpleNamespace(freeze_path=root / "freeze.json", freeze={"platformApi": {"currentContractDigest": products.file_digest(contract_path)}})
        node = {"role": "candidate-sender", "sourceCommit": "a" * 40, "contractVersion": 25,
                "appDigests": [declaration["bundleDigest"]]}
        selection = {"coordinates": {}, "cohortDigest": "sha256:" + "d" * 64}
        return projection, authenticated, selected, node, selection

    def test_app_projection_checks_real_signed_declarations_against_frozen_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            projection, authenticated, selected, node, selection = self.app_projection_fixture(root, optional=["future.optional"])
            with patch.object(projection, "authenticate_inventory", return_value=authenticated):
                rows = products.verify_app_projection(selected, node, selection, root)
            self.assertEqual(["future.optional"], rows[0]["optionalUnavailable"])
            self.assertEqual("mail-prototype", rows[0]["appId"])
            self.assertEqual(["content.fetch"], rows[0]["requiredCapabilities"])

    def test_unknown_required_app_capability_blocks_before_node_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            projection, authenticated, selected, node, selection = self.app_projection_fixture(root, required=["unknown.required"])
            with patch.object(projection, "authenticate_inventory", return_value=authenticated):
                with self.assertRaisesRegex(products.ProductAdmissionError, "required-capability-unknown"):
                    products.verify_app_projection(selected, node, selection, root)

    def test_genuine_projection_cannot_substitute_different_selected_bundle_or_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            projection, authenticated, selected, node, selection = self.app_projection_fixture(root)
            with patch.object(projection, "authenticate_inventory", return_value=authenticated):
                with self.assertRaisesRegex(products.ProductAdmissionError, "selected-bundle-missing"):
                    products.verify_app_projection(selected, {**node, "appDigests": ["sha256:" + "e" * 64]}, selection, root)
                (root / "platform-api-current-contract.json").write_text("{}")
                with self.assertRaisesRegex(products.ProductAdmissionError, "snapshot-freeze-binding"):
                    products.verify_app_projection(selected, node, selection, root)

    def test_json_boolean_cannot_construct_authority_object(self):
        with self.assertRaises(products.ProductAdmissionError):
            products.AuthenticatedProducts(True, "sha256:" + "a" * 64, {})


if __name__ == "__main__":
    unittest.main()
