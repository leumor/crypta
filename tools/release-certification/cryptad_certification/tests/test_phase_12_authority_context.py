"""Behavioral native-context adapter checks using original owner fixture builders."""
from __future__ import annotations

import io
import json
import contextlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from urllib.parse import urlsplit
import zipfile

from cryptad_certification import phase_12_authority_context as audit
from cryptad_certification.tests import test_stable_catalog_authority as catalog
from cryptad_certification.tests import test_stable_protected_release as release
from cryptad_certification.tests.third_party_pilot_fixtures import PilotFixture, NOW as PILOT_NOW


def encoded(value):
    return json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"


def archive(members):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as target:
        for name, raw in members.items():
            entry = zipfile.ZipInfo(name)
            entry.external_attr = (stat.S_IFREG | 0o600) << 16
            target.writestr(entry, raw)
    return output.getvalue()


class Phase12AuthorityContextTest(unittest.TestCase):
    def call(self, name, payloads, now):
        with tempfile.TemporaryDirectory() as tmp:
            # Real signature/schema/subject validators execute; any network attempt is a failure.
            with patch("socket.socket", side_effect=AssertionError("network forbidden")):
                return audit.verify(name, payloads, now, Path(tmp).resolve(strict=True))

    def test_catalog_complete_fixture_revalidates_six_drills_without_original_authority(self):
        payloads = {"authority.json": encoded(catalog._manifest()), "evidence.zip": archive({})}
        result = self.call("catalog-closeout", payloads, "2026-08-22T05:00:00Z")
        self.assertEqual("synthetic-test-only", result["evidenceClass"])
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
        self.assertEqual("complete", result["claimResults"]["p12-293-drills"]["dimensions"]["coverage"])
        self.assertNotIn("publication", result["claimResults"]["p12-293-transparency"]["dimensions"])

    def test_catalog_receipt_scope_and_real_recovery_signature_mutations_fail(self):
        for change in ("signature", "cohort", "mirror"):
            value = catalog._manifest()
            if change == "signature":
                value["transparency"]["signatureBase64"] = "A" * 86 + "=="
            elif change == "cohort":
                value["drills"].pop()
            else:
                value["publication"]["observations"][0]["catalogDigest"] = "sha256:" + "0" * 64
            with self.subTest(change=change), self.assertRaises(audit.AuthorityContextError):
                self.call("catalog-closeout", {"authority.json": encoded(value), "evidence.zip": archive({})}, "2026-08-22T05:00:00Z")

    def test_catalog_fixture_flag_removal_cannot_supply_missing_original_receipts(self):
        value = catalog._manifest()
        value["fixtureOnly"] = False
        with self.assertRaises(audit.AuthorityContextError):
            self.call("catalog-closeout", {"authority.json": encoded(value), "evidence.zip": archive({})}, "2026-08-22T05:00:00Z")

    def test_catalog_and_pilot_reject_unbound_safe_named_sidecars(self):
        with self.assertRaises(audit.AuthorityContextError):
            self.call("catalog-closeout", {"authority.json": encoded(catalog._manifest()),
                "evidence.zip": archive({"harmless.json": b"{}"})}, "2026-08-22T05:00:00Z")
        with tempfile.TemporaryDirectory() as root:
            fixture, payloads = self.pilot_payloads(Path(root).resolve(strict=True))
            members = {p.name: p.read_bytes() for p in fixture.evidence.iterdir() if p.is_file()}
            members["harmless.json"] = b"{}"
            payloads["evidence.zip"] = archive(members)
            with self.assertRaises(audit.AuthorityContextError):
                self.call("pilot-runtime", payloads, PILOT_NOW)

    def pilot_payloads(self, root):
        fixture = PilotFixture(root)
        return fixture, {"execution.json": fixture.contract_path.read_bytes(),
            "evidence.zip": archive({p.name: p.read_bytes() for p in fixture.evidence.iterdir() if p.is_file()})}

    def test_pilot_runtime_executes_actual_bundle_review_and_node_receipt_verifiers(self):
        with tempfile.TemporaryDirectory() as root:
            _, payloads = self.pilot_payloads(Path(root).resolve(strict=True))
            result = self.call("pilot-runtime", payloads, PILOT_NOW)
        self.assertEqual(["p12-294-runtime"], result["claims"])
        self.assertEqual("synthetic-test-only", result["evidenceClass"])
        self.assertEqual("complete", result["dimensions"]["cleanup"])
        self.assertIn("corrected-v2-rollback", result["coverage"]["observed"])

    def test_pilot_signed_runtime_cannot_replace_missing_caution_consent_or_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            fixture, payloads = self.pilot_payloads(Path(root).resolve(strict=True))
            runtime = fixture.load_evidence("runtimeDrill")
            runtime["cleanStateRestored"] = False
            fixture.replace_evidence("runtimeDrill", runtime)
            payloads = {"execution.json": fixture.contract_path.read_bytes(),
                "evidence.zip": archive({p.name: p.read_bytes() for p in fixture.evidence.iterdir() if p.is_file()})}
            with self.assertRaises(audit.AuthorityContextError):
                self.call("pilot-runtime", payloads, PILOT_NOW)

    def lifecycle_payloads(self, root):
        from cryptad_certification.tests import test_stable_lifecycle_publication as fixtures
        from cryptad_certification.engines import stable_1_0_lifecycle as owner
        from cryptad_certification.engines import stable_1_0_lifecycle_core as core
        fixture = fixtures.BundleFixture(root)
        with patch.object(fixtures.publication, "_now", return_value=fixtures.NOW):
            fixture.published_bundle()
        # The publication fixture intentionally uses its own 14-day descriptor window. This
        # audit instead reuses the currently selected native 7-day policy and rebuilds its inputs.
        policy = json.loads((audit.BASE / owner.POLICY_FILE).read_bytes())
        fixture.descriptor, errors = core.build_descriptor(fixture.ledger, policy,
            fixtures.GENERATED_AT, None, policy["descriptor"]["updateKeyIdentityDigest"])
        self.assertEqual([], errors)
        authorization, _, _ = owner._validate_authorization(None, policy, fixture.descriptor,
            fixture.ledger, fixture.transition_set, fixtures.PUBLIC_URI,
            fixtures.MAINTENANCE_POINTER_URI, None, fixtures.NOW)
        authorization.update(authorizationId="lifecycle-authorization-1", generatedAt=fixtures.GENERATED_AT,
                             expiresAt=fixtures.EXPIRES_AT, decision="approved")
        fixture.authorization = authorization
        fixture.plan = owner._publication_plan(fixture.descriptor, fixture.ledger, authorization, True,
            fixtures.PUBLIC_URI, fixtures.MAINTENANCE_POINTER_URI, None, fixture.transition_set["transitionSetDigest"])
        receipt = json.loads((root / fixtures.publication.RECEIPT_FILE).read_bytes())
        receipt.update(descriptorDigest=fixture.descriptor["descriptorDigest"],
                       descriptorBytesDigest=core.canonical_file_digest(fixture.descriptor),
                       publicationPlanDigest=fixture.plan["publicationPlanDigest"],
                       authorizationDigest=core.canonical_file_digest(authorization))
        return {"ledger.json": encoded(fixture.ledger), "descriptor.json": encoded(fixture.descriptor),
            "previous-descriptor.json": encoded(None), "transition.json": encoded(fixture.transition_set),
            "authorization.json": encoded(fixture.authorization), "plan.json": encoded(fixture.plan),
            "receipt.json": encoded(receipt)}

    def test_lifecycle_rederives_descriptor_plan_authorization_and_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            payloads = self.lifecycle_payloads(Path(root).resolve(strict=True))
            result = self.call("lifecycle-receipt", payloads, "2026-07-21T13:00:00Z")
        self.assertNotIn("activation", result["dimensions"])
        self.assertEqual(["p12-301-support-lifecycle"], result["claims"])
        self.assertIn("original-lifecycle-public-observation-required", result["blockers"])
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
        self.assertNotIn("publicObservation", result["dimensions"])

    def test_lifecycle_unrelated_descriptor_wrong_plan_and_stale_observation_fail(self):
        with tempfile.TemporaryDirectory() as root:
            payloads = self.lifecycle_payloads(Path(root).resolve(strict=True))
        for name in ("descriptor.json", "receipt.json", "plan.json"):
            changed = dict(payloads)
            value = json.loads(changed[name])
            value["descriptorDigest"] = "sha256:" + "f" * 64
            changed[name] = encoded(value)
            with self.subTest(name=name), self.assertRaises(audit.AuthorityContextError):
                self.call("lifecycle-receipt", changed, "2026-07-21T13:00:00Z")
        with self.assertRaises(audit.AuthorityContextError):
            self.call("lifecycle-receipt", payloads, "2026-08-21T13:00:00Z")

    def observation_payloads(self, root):
        contract = release._contract(root)
        release._configure_publish(root, contract)
        receipt, path = release._configure_publication_receipt(root, contract)
        value = release._public_observation(contract, receipt, audit._digest(path.read_bytes()))
        release._bind_observation_coordinate(contract, value)
        raw = encoded(value)
        bundle = archive({"stable-1.0-public-observation.json": raw})
        contract["workflowCoordinates"]["publicObservation"]["artifactDigest"] = audit._digest(bundle)
        return {"contract.json": encoded(contract), "publication.json": path.read_bytes(),
                "observation.json": raw, "observation.zip": bundle}

    def test_release_observation_binds_exact_original_artifact_and_every_public_target(self):
        with tempfile.TemporaryDirectory() as root:
            payloads = self.observation_payloads(Path(root).resolve(strict=True))
            result = self.call("protected-public-observation", payloads, "2026-08-16T03:00:00Z")
        self.assertEqual("observed", result["dimensions"]["publicObservation"])
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])

    def test_resealed_observation_omission_wrong_attempt_and_before_publication_fail(self):
        with tempfile.TemporaryDirectory() as root:
            payloads = self.observation_payloads(Path(root).resolve(strict=True))
        for case in ("target", "attempt", "time"):
            changed = dict(payloads)
            value = json.loads(changed["observation.json"])
            if case == "target":
                value["targets"].pop()
            elif case == "attempt":
                value["observer"]["runAttempt"] = "2"
            else:
                value["observedAt"] = "2026-08-15T01:00:00Z"
            changed["observation.json"] = encoded(value)
            changed["observation.zip"] = archive({"stable-1.0-public-observation.json": changed["observation.json"]})
            contract = json.loads(changed["contract.json"])
            contract["workflowCoordinates"]["publicObservation"]["artifactDigest"] = audit._digest(changed["observation.zip"])
            changed["contract.json"] = encoded(contract)
            with self.subTest(case=case), self.assertRaises(audit.AuthorityContextError):
                self.call("protected-public-observation", changed, "2026-08-16T03:00:00Z")

    def maintenance_payloads(self):
        from cryptad_certification.tests import test_stable_maintenance as fixtures
        native = fixtures._context(Path("unused-private-context")).manifest
        inputs = fixtures._required_inputs()
        inputs.update(maintenancePolicy="policy.json", maintenanceCandidate="candidate.json",
                      maintenanceCandidateAssets="assets",
                      stableMaintenanceAuthorization="authorization.json",
                      stableMaintenancePublicationReceipt="receipt.json", coreUpdatePublicationReceipt="core-receipt.json")
        candidate = fixtures._candidate_input()
        candidate["packages"] = fixtures._packages()
        members = {value: b"{}" for key, value in inputs.items() if key != "maintenanceCandidateAssets"}
        members["policy.json"] = (audit.BASE / "stable-1.0-maintenance-policy.json").read_bytes()
        members["candidate.json"] = encoded(candidate)
        for name in [candidate["product"]["fileName"], candidate["stableCatalog"]["fileName"],
                     candidate["stableCatalog"]["signatureFileName"], *(p["fileName"] for p in candidate["packages"])]:
            members["assets/" + name] = b"{}" if name.endswith(".json") else b"original-product-absent"
        manifest = {"schemaVersion": 1,
            "release": {"id": native.release.release_id, "version": native.release.version,
                        "profile": native.release.profile},
            "output": {"root": "private-output", "reset": False},
            "requirements": native.requirements,
            "inputs": inputs,
            "policies": native.policies, "execution": {"skipGradle": True, "skipFullBuild": True},
            "commands": {"stable-maintenance": {"mode": "validate-only", "args": []}}}
        return {"manifest.json": encoded(manifest), "evidence.zip": archive(members)}

    def test_maintenance_full_native_verifier_rejects_missing_candidate_and_original_ga(self):
        from cryptad_certification.engines import stable_1_0_maintenance as owner
        payloads = self.maintenance_payloads()
        # This observes the actual full owner call; no Candidate, receipt, or successful result
        # is supplied by a test double. A self-resealed summary cannot manufacture its inputs.
        with patch.object(owner, "run", wraps=owner.run) as run:
            with self.assertRaises(audit.AuthorityContextError):
                self.call("maintenance-publication", payloads, "2026-09-10T20:00:00Z")
        self.assertEqual(1, run.call_count)

    def test_maintenance_unavailable_dns_is_an_explicit_unexecuted_prerequisite(self):
        payloads = self.maintenance_payloads()
        manifest = json.loads(payloads["manifest.json"])
        manifest["policies"]["artifactBaseUri"] = "https://downloads.crypta.network/stable"
        payloads["manifest.json"] = encoded(manifest)
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
            result = self.call("maintenance-publication", payloads, "2026-09-10T20:00:00Z")
        claim = result["claimResults"]["p12-301-publication"]
        self.assertEqual("not-run", claim["dimensions"]["localVerification"])
        self.assertNotIn("publication", claim["dimensions"])
        self.assertIn("native-maintenance-public-address-verification-unavailable", claim["blockers"])

    def test_maintenance_transport_denies_commands_sidecars_paths_and_weakening(self):
        original = self.maintenance_payloads()
        for case in ("command", "argument", "path", "fixture", "sidecar", "cohort", "governance"):
            payloads = dict(original)
            manifest = json.loads(payloads["manifest.json"])
            if case == "command":
                manifest["commands"]["stable-maintenance"]["mode"] = "prepare-authorization"
            elif case == "argument":
                manifest["commands"]["stable-maintenance"]["args"] = ["private-command-canary"]
            elif case == "path":
                manifest["inputs"]["maintenancePolicy"] = "../outside.json"
            elif case == "fixture":
                manifest["execution"]["fixtureEvidence"] = True
            elif case == "cohort":
                del manifest["inputs"]["maintenanceCandidateFreeze"]
            elif case == "governance":
                manifest["requirements"]["stableSupplyChain"] = False
            else:
                with zipfile.ZipFile(io.BytesIO(payloads["evidence.zip"])) as original_archive:
                    members = {name: original_archive.read(name) for name in original_archive.namelist()}
                members["unbound.json"] = b'{"private":"private-contact-canary"}'
                payloads["evidence.zip"] = archive(members)
            payloads["manifest.json"] = encoded(manifest)
            with self.subTest(case=case), self.assertRaisesRegex(audit.AuthorityContextError,
                    "^phase12-native-authority-context-invalid$"):
                self.call("maintenance-publication", payloads, "2026-09-10T20:00:00Z")

    def test_maintenance_source_owned_positive_receipt_scope_remains_separate(self):
        from cryptad_certification import transparency_public_projection as public
        from cryptad_certification.tests import test_stable_maintenance as fixtures
        # The existing PR302 fixture owns its Candidate context. This proves the receipt export
        # verifier's reachable scoped positive path, not original Candidate authentication.
        with tempfile.TemporaryDirectory() as root:
            args, receipt = fixtures.StableMaintenanceAuthorizationAndPublicationTest()._publication_fixture(Path(root).resolve(strict=True), "created")
            context, *remaining = args
            inputs = public.MaintenancePublicationContext(*remaining)
            value = public.validate_public_projection(public.export_verified("maintenance", context, inputs=inputs))
            self.assertEqual("301", value["fields"]["buildVersion"])
            self.assertEqual("not-exported-private-context", value["originalProducerProof"])
            receipt["assets"][0]["digest"] = "sha256:" + "0" * 64
            with self.assertRaises(public.PublicProjectionError):
                public.export_verified("maintenance", context, inputs=inputs)

    def activation_payloads(self):
        from cryptad_certification.tests import test_stable_maintenance_publication as fixtures
        case = fixtures.StableMaintenancePublicationTest()
        case.setUp()
        outcomes = []
        original = fixtures.publication.activate_latest_baseline

        def capture(*args, **kwargs):
            result = original(*args, **kwargs)
            outcomes.extend(result.artifacts.values())
            return result

        try:
            # Execute the actual owner's synthetic provider test. The audit adapter below never
            # receives that provider, invokes activation, or treats it as an original producer.
            with patch.object(fixtures.publication, "activate_latest_baseline", side_effect=capture):
                case.test_activation_is_compare_and_swap_and_idempotent()
            payloads = {"successor.json": (case.root / "successor.json").read_bytes(),
                "history.json": (case.root / "history.json").read_bytes(),
                "publication.json": (case.root / "receipt.json").read_bytes(),
                "authorization.json": case.fixture.authorization_path.read_bytes(),
                "activation-authorization.json": (case.root / "receipt-activation-authorization.json").read_bytes(),
                "activation.json": encoded(outcomes[0])}
            request = fixtures.publication._load_activation_request(case.root / "successor.json",
                case.root / "history.json", case.root / "receipt.json", case.fixture.authorization_path,
                case.root / "receipt-activation-authorization.json", fixtures.POINTER)
            payloads["current-pointer.json"] = request.activated_pointer_bytes
            return payloads, outcomes[1]
        finally:
            case.doCleanups()

    def test_maintenance_activation_native_created_and_idempotent_receipts(self):
        payloads, idempotent = self.activation_payloads()
        owner = audit._maintenance_activation_owner()
        with patch.object(owner, "activate_latest_baseline", side_effect=AssertionError("activation forbidden")), \
                patch.object(owner, "_load_backend", side_effect=AssertionError("backend forbidden")):
            for receipt in (json.loads(payloads["activation.json"]), idempotent):
                payloads["activation.json"] = encoded(receipt)
                result = self.call("maintenance-activation", payloads, "2026-07-18T13:00:00Z")
                self.assertEqual("activated", result["dimensions"]["activation"])
                self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
                self.assertEqual("2026-07-18T12:00:00Z", result["observedAt"])
                self.assertEqual("1", result["producerCoordinates"]["runAttempt"])

    def test_activation_wrong_pointer_attempt_expired_grant_and_publication_substitution_fail(self):
        original, _ = self.activation_payloads()
        for case in ("pointer-bytes", "pointer-subject", "receipt", "attempt", "expired", "future", "publication"):
            payloads = dict(original)
            if case == "pointer-bytes":
                payloads["current-pointer.json"] += b"\n"
            elif case == "pointer-subject":
                value = json.loads(payloads["current-pointer.json"])
                value["baselineDigest"] = "sha256:" + "f" * 64
                payloads["current-pointer.json"] = encoded(value)
            elif case == "publication":
                payloads["activation.json"] = payloads["publication.json"]
            else:
                name = "activation-authorization.json" if case in {"attempt", "expired"} else "activation.json"
                value = json.loads(payloads[name])
                if case == "attempt":
                    value["workflowRunAttempt"] = 2
                elif case == "expired":
                    value["expiresAt"] = "2026-07-18T11:59:59Z"
                elif case == "future":
                    value["generatedAt"] = "2026-07-19T12:00:00Z"
                else:
                    value["expectedPreviousPointerDigest"] = "sha256:" + "f" * 64
                payloads[name] = encoded(value)
            with self.subTest(case=case), self.assertRaisesRegex(audit.AuthorityContextError,
                    "^phase12-native-authority-context-invalid$"):
                self.call("maintenance-activation", payloads, "2026-07-18T13:00:00Z")

    def ga_payloads(self, root):
        contract = release._contract(root)
        receipt, receipt_path = release._configure_publication_receipt(root, contract)
        observation = release._public_observation(contract, receipt, audit._digest(receipt_path.read_bytes()))
        release._bind_observation_coordinate(contract, observation)
        path = root / "observation.json"
        path.write_bytes(encoded(observation))
        contract["operationEvidence"]["publicObservation"] = {
            **release._binding(root, Path("observation.json")), "schema": release.protected.OBSERVATION_SCHEMA}
        release._bind_observation_artifact(root, contract, path)
        contract["lifecycleState"] = "publicly-observed"
        contract["evidenceClassification"]["publicObservation"] = "completed"
        paths, pending = set(), [contract]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                if "path" in value:
                    paths.add(value["path"])
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        policy = root / "tools/release-certification" / release.protected.POLICY_FILE
        policy.parent.mkdir(parents=True, exist_ok=True)
        policy.write_bytes((audit.BASE / release.protected.POLICY_FILE).read_bytes())
        return contract, {"contract.json": encoded(contract),
            "evidence.zip": archive({name: (root / name).read_bytes() for name in sorted(paths)})}

    def ga_api(self, contract, wrong_attempt=False):
        coordinates = [c for c in contract["workflowCoordinates"].values() if c is not None]
        def respond(path, _token):
            if path == "/user":
                return {"login": "leumor"}
            run_id = path.split("/runs/")[1].split("/")[0]
            rows = [c for c in coordinates if c["runId"] == run_id]
            coordinate = rows[0]
            if path.endswith("/jobs?per_page=100"):
                catalog_job = coordinate["workflowPath"] == release.protected.CATALOG_AUTHORITY_WORKFLOW
                job = "Close out only authenticated catalog-authority evidence" if catalog_job else "Attest protected Stable GA evidence bytes"
                steps = ("Derive truthful closeout from exact protected receipts",) if catalog_job else (
                    "Verify the exact protected attestation subjects",
                    "Attest exact validation, authorization, and publication-target identity")
                return {"total_count": 1, "jobs": [{"name": job,
                    "run_id": int(run_id), "head_sha": coordinate["workflowCommit"],
                    "status": "completed", "conclusion": "success", "steps": [
                        {"name": name, "status": "completed", "conclusion": "success"} for name in steps]}]}
            if "/attempts/" in path:
                return {"id": int(run_id), "run_attempt": 99 if wrong_attempt else int(coordinate["runAttempt"]),
                    "head_sha": coordinate["workflowCommit"], "path": coordinate["workflowPath"],
                    "event": "workflow_dispatch", "conclusion": "success", "repository": {"full_name": coordinate["repository"]},
                    "actor": {"login": "leumor"}, "triggering_actor": {"login": "leumor"}}
            unique = {(c["artifactName"], c["artifactDigest"]) for c in rows}
            return {"total_count": len(unique), "artifacts": [
                {"name": name, "digest": digest, "expired": False} for name, digest in sorted(unique)]}
        return respond

    def ga_opener(self, contract, wrong_attempt=False):
        response = self.ga_api(contract, wrong_attempt)
        def open_response(request, timeout):
            parsed = urlsplit(request.full_url)
            return io.BytesIO(encoded(response(parsed.path + ("?" + parsed.query if parsed.query else ""), "unused")))
        return SimpleNamespace(open=open_response)

    def test_native_ga_closeout_keeps_offline_semantics_separate_from_original_gets(self):
        owner = release.protected
        with tempfile.TemporaryDirectory() as root:
            contract, payloads = self.ga_payloads(Path(root).resolve(strict=True))
            # Isolated source authority supplies the owner fixture's original candidate. All
            # receipt/lineage/authorization/archive checks and the GET metadata validator run.
            with patch.object(audit, "_ga_workspace", side_effect=lambda *_args: contextlib.nullcontext(Path(root).resolve(strict=True))), \
                    patch.object(owner, "_source_errors", return_value=[]), \
                    patch.object(owner, "_policy_errors", return_value=[]), \
                    patch("urllib.request.build_opener", return_value=self.ga_opener(contract)), \
                    patch.object(owner, "_github_api_json", wraps=owner._github_api_json) as api:
                offline = self.call("protected-ga-closeout", payloads, "2026-08-16T03:00:00Z")
                self.assertEqual("unverified", offline["originalProof"]["state"])
                self.assertEqual(0, api.call_count)
                self.assertNotIn("publication", offline["claimResults"]["p12-291-publication"]["dimensions"])
                with tempfile.TemporaryDirectory() as scratch, patch.dict(os.environ, {"GH_TOKEN": "isolated-test-token", "GITHUB_ACTIONS": "true"}):
                    verified = audit.collect_and_verify("protected-ga-closeout", payloads, "2026-08-16T03:00:00Z", Path(scratch).resolve(strict=True))
                self.assertGreater(api.call_count, 0)
                self.assertEqual("authenticated", verified["originalProof"]["state"])
                self.assertEqual("published", verified["claimResults"]["p12-291-publication"]["dimensions"]["publication"])
                self.assertEqual("observed", verified["claimResults"]["p12-291-observation"]["dimensions"]["publicObservation"])

    def test_native_ga_collection_rejects_swapped_original_attempt_and_unbound_sidecar(self):
        owner = release.protected
        with tempfile.TemporaryDirectory() as root:
            contract, payloads = self.ga_payloads(Path(root).resolve(strict=True))
            with patch.object(audit, "_ga_workspace", side_effect=lambda *_args: contextlib.nullcontext(Path(root).resolve(strict=True))), \
                    patch.object(owner, "_source_errors", return_value=[]), patch.object(owner, "_policy_errors", return_value=[]), \
                    patch("urllib.request.build_opener", return_value=self.ga_opener(contract, wrong_attempt=True)), \
                    patch.dict(os.environ, {"GH_TOKEN": "isolated-test-token", "GITHUB_ACTIONS": "true"}), tempfile.TemporaryDirectory() as scratch:
                with self.assertRaises(audit.AuthorityContextError):
                    audit.collect_and_verify("protected-ga-closeout", payloads, "2026-08-16T03:00:00Z", Path(scratch).resolve(strict=True))
            with zipfile.ZipFile(io.BytesIO(payloads["evidence.zip"])) as original:
                members = {name: original.read(name) for name in original.namelist()}
            members["sidecar.json"] = b"{}"
            payloads["evidence.zip"] = archive(members)
            with self.assertRaises(audit.AuthorityContextError):
                self.call("protected-ga-closeout", payloads, "2026-08-16T03:00:00Z")

    def test_native_ga_original_token_and_actual_candidate_unavailable_are_gaps(self):
        owner = release.protected
        with tempfile.TemporaryDirectory() as root:
            _, payloads = self.ga_payloads(Path(root).resolve(strict=True))
            result = self.call("protected-ga-closeout", payloads, "2026-08-16T03:00:00Z")
            self.assertIn("original-candidate-checkout-and-release-ref-required", result["blockers"])
            with patch.object(audit, "_ga_workspace", side_effect=lambda *_args: contextlib.nullcontext(Path(root).resolve(strict=True))), \
                    patch.object(owner, "_source_errors", return_value=[]), patch.object(owner, "_policy_errors", return_value=[]), \
                    patch.dict(os.environ, {"GH_TOKEN": "", "GITHUB_ACTIONS": "true"}), tempfile.TemporaryDirectory() as scratch:
                result = audit.collect_and_verify("protected-ga-closeout", payloads, "2026-08-16T03:00:00Z", Path(scratch).resolve(strict=True))
                self.assertEqual("unverified", result["originalProof"]["state"])
                self.assertIn("native-protected-closeout-github-token-unavailable", result["originalProof"]["blockers"])

    def test_native_ga_get_access_denial_is_unverified_and_transport_is_get_only(self):
        from urllib.error import HTTPError, URLError
        from urllib.request import Request
        owner = release.protected
        with tempfile.TemporaryDirectory() as root:
            _, payloads = self.ga_payloads(Path(root).resolve(strict=True))
            def denied(_request, timeout):
                raise HTTPError("https://api.github.com/user", 403, "private-denial-canary", {}, None)
            with patch.object(audit, "_ga_workspace", side_effect=lambda *_args: contextlib.nullcontext(Path(root).resolve(strict=True))), \
                    patch.object(owner, "_source_errors", return_value=[]), patch.object(owner, "_policy_errors", return_value=[]), \
                    patch("urllib.request.build_opener", return_value=SimpleNamespace(open=denied)), \
                    patch.dict(os.environ, {"GH_TOKEN": "isolated-test-token", "GITHUB_ACTIONS": "true"}), tempfile.TemporaryDirectory() as scratch:
                result = audit.collect_and_verify("protected-ga-closeout", payloads, "2026-08-16T03:00:00Z", Path(scratch).resolve(strict=True))
                self.assertEqual("unverified", result["originalProof"]["state"])
                self.assertIn("native-protected-closeout-original-access-unavailable", result["originalProof"]["blockers"])
                self.assertNotIn("private-denial-canary", json.dumps(result))
        with audit._ga_bounded_transport(owner):
            for request in (Request("https://api.github.com/user", method="POST"),
                            Request("https://private.invalid/user"),
                            Request("https://api.github.com/repos/other/project/actions/runs/1/attempts/1")):
                with self.subTest(url=request.full_url), self.assertRaises(URLError):
                    owner.urlopen(request)

    def test_native_ga_zero_original_requests_never_authenticate_absent_operations(self):
        owner = release.protected
        with tempfile.TemporaryDirectory() as root:
            root = Path(root).resolve(strict=True)
            _, payloads = self.ga_payloads(root)
            contract = json.loads(payloads["contract.json"])
            contract["workflowCoordinates"] = {key: None for key in contract["workflowCoordinates"]}
            contract["operationEvidence"] = {key: None for key in contract["operationEvidence"]}
            contract["ga"] = release._contract(root)["ga"]
            contract["lifecycleState"] = "planned"
            contract["evidenceClassification"] = {"repositoryImplementation": "present", "offlineVerification": "pending",
                "protectedOperation": "not-performed", "publicObservation": "not-performed"}
            payloads["contract.json"] = encoded(contract)
            names = {row["file"]["path"] for row in contract["upstreamEvidence"]}
            names.update(row["path"] for row in contract["rcInputs"].values() if row is not None)
            payloads["evidence.zip"] = archive({name: (root / name).read_bytes() for name in sorted(names)})
            with patch.object(audit, "_ga_workspace", side_effect=lambda *_args: contextlib.nullcontext(root)), \
                    patch.object(owner, "_source_errors", return_value=[]), patch.object(owner, "_policy_errors", return_value=[]), \
                    patch.dict(os.environ, {"GH_TOKEN": "isolated-test-token", "GITHUB_ACTIONS": "true"}), \
                    patch("socket.socket", side_effect=AssertionError("no original request expected")), tempfile.TemporaryDirectory() as scratch:
                result = audit.collect_and_verify("protected-ga-closeout", payloads, "2026-08-16T03:00:00Z", Path(scratch).resolve(strict=True))
                self.assertEqual("unverified", result["originalProof"]["state"])
                self.assertIn("native-original-stages-not-observed", result["originalProof"]["blockers"])

    def test_native_catalog_producer_verifies_original_archive_without_transparency_publication(self):
        from cryptad_certification.tests import test_stable_protected_catalog_authority as fixtures
        owner = release.protected
        independent = {"summaryDigest": "sha256:" + "9" * 64, "resultDigest": "sha256:" + "a" * 64,
                       "subjectInventoryDigest": "sha256:" + "c" * 64}
        with tempfile.TemporaryDirectory() as root:
            root = Path(root).resolve(strict=True)
            contract, payloads = self.ga_payloads(root)
            freeze = json.loads((root / contract["operationEvidence"]["rcFreezeRecord"]["path"]).read_bytes())
            summary = fixtures._summary(contract, freeze, independent)
            binding = fixtures._archive(root, Path("catalog-original.zip"), summary)
            contract["workflowCoordinates"]["catalogAuthority"] = release._coordinate(owner.CATALOG_AUTHORITY_WORKFLOW,
                owner.CATALOG_AUTHORITY_ENVIRONMENT, run_id="70",
                artifact_name=f"stable-1-0-catalog-authority-closeout-{release.RELEASE_ID}-3-70-1",
                artifact_digest=binding["sha256"])
            contract["operationEvidence"]["catalogAuthority"] = binding
            (root / "isolated-independent-authority.json").write_bytes(encoded({"kind": "isolated-test-authority"}))
            contract["operationEvidence"]["independentReproducibility"] = {
                **release._binding(root, Path("isolated-independent-authority.json")), "schema": owner.INDEPENDENT_SUMMARY_SCHEMA}
            with zipfile.ZipFile(io.BytesIO(payloads["evidence.zip"])) as original:
                members = {name: original.read(name) for name in original.namelist()}
            members.update({"catalog-original.zip": (root / "catalog-original.zip").read_bytes(),
                            "isolated-independent-authority.json": (root / "isolated-independent-authority.json").read_bytes()})
            payloads = {"contract.json": encoded(contract), "evidence.zip": archive(members)}
            # PR292 is an isolated test authority here: its provider adapter remains unavailable
            # in production. The actual catalog verifier, exact original ZIP and GET checks run.
            with patch.object(audit, "_ga_workspace", side_effect=lambda *_args: contextlib.nullcontext(root)), \
                    patch.object(owner, "_source_errors", return_value=[]), patch.object(owner, "_policy_errors", return_value=[]), \
                    patch.object(owner, "_independent_reproducibility_errors", return_value=[]), \
                    patch.object(owner, "_independent_summary_digests", return_value=(independent, [])), \
                    patch("urllib.request.build_opener", return_value=self.ga_opener(contract)), \
                    patch.dict(os.environ, {"GH_TOKEN": "isolated-test-token", "GITHUB_ACTIONS": "true"}), tempfile.TemporaryDirectory() as scratch:
                result = audit.collect_and_verify("protected-ga-closeout", payloads, "2026-08-16T03:00:00Z", Path(scratch).resolve(strict=True))
            for claim in ("p12-293-keyset", "p12-293-publication", "p12-293-drills"):
                self.assertIn(claim, result["claims"])
            self.assertNotIn("p12-293-transparency", result["claims"])
            self.assertNotIn("cleanup", result["claimResults"]["p12-293-drills"]["dimensions"])
            summary["catalogSubject"]["signatureDigest"] = "sha256:" + "f" * 64
            summary["summaryDigest"] = fixtures.base.DIGEST_ZERO
            summary["summaryDigest"] = owner._semantic_digest(summary)
            changed = fixtures._archive(root, Path("changed-catalog.zip"), summary)
            contract["operationEvidence"]["catalogAuthority"] = changed
            contract["workflowCoordinates"]["catalogAuthority"]["artifactDigest"] = changed["sha256"]
            with patch.object(owner, "_github_actions_coordinate_errors", return_value=[]), \
                    patch.object(owner, "_independent_summary_digests", return_value=(independent, [])):
                state, failures = owner._catalog_authority_closeout(root, contract, freeze, "independently-reproduced")
            self.assertEqual("blocked", state)
            self.assertTrue(failures)

    def test_pilot_closeout_missing_original_roots_preserves_actual_verified_runtime_scope(self):
        with tempfile.TemporaryDirectory() as root:
            _, payloads = self.pilot_payloads(Path(root).resolve(strict=True))
            result = self.call("pilot-closeout", payloads, PILOT_NOW)
            self.assertEqual("synthetic-test-only", result["evidenceClass"])
            self.assertEqual({"p12-294-externality", "p12-294-review", "p12-294-runtime"}, set(result["claims"]))
            self.assertEqual("unverified", result["originalProof"]["state"])
            self.assertIn("native-pilot-original-roots-not-supplied", result["originalProof"]["blockers"])
            self.assertNotIn("independentReview", result["claimResults"]["p12-294-review"]["dimensions"])
            with tempfile.TemporaryDirectory() as scratch, self.assertRaises(audit.AuthorityContextError):
                audit.collect_and_verify("pilot-closeout", payloads, PILOT_NOW, Path(scratch).resolve(strict=True))

    def test_pilot_closeout_supplied_invalid_root_is_not_hidden_by_other_missing_roots(self):
        from cryptad_certification.tests.third_party_pilot_fixtures import provenance
        with tempfile.TemporaryDirectory() as root:
            fixture, payloads = self.pilot_payloads(Path(root).resolve(strict=True))
            raw = archive({"stable-1.0-protected-release-execution-summary.json": b"{}"})
            source = provenance(fixture.contract["repository"]["identity"],
                ".github/workflows/stable-1.0-protected-release-closeout.yml", 71, "original-protected-root")
            source["artifactDigest"] = audit._digest(raw)
            fixture.contract["evidence"]["protectedRelease"] = {"fileName": "root.zip", "digest": audit._digest(raw),
                "size": len(raw), "provenance": source}
            with zipfile.ZipFile(io.BytesIO(payloads["evidence.zip"])) as original:
                members = {name: original.read(name) for name in original.namelist()}
            members["root.zip"] = raw
            payloads = {"execution.json": encoded(fixture.contract), "evidence.zip": archive(members)}
            with self.assertRaises(audit.AuthorityContextError):
                self.call("pilot-closeout", payloads, PILOT_NOW)

    def test_pilot_partial_roots_reject_schema_valid_wrong_subject_and_producer(self):
        from cryptad_certification.tests.third_party_pilot_fixtures import provenance
        with tempfile.TemporaryDirectory() as root:
            fixture, payloads = self.pilot_payloads(Path(root).resolve(strict=True))
            summary = {"schemaVersion": 1, "kind": "stable-1.0-protected-release-execution-summary",
                "executionId": "isolated-pilot-original", "mode": "closeout", "status": "pass",
                "promotionReady": True, "lifecycleState": "publicly-observed",
                "contractDigest": fixture.contract["authorities"]["protectedReleaseRootDigest"],
                "candidateCommit": fixture.contract["repository"]["sourceCommit"],
                "releaseId": fixture.contract["release"]["releaseId"],
                "buildVersion": str(fixture.contract["release"]["buildVersion"]),
                "evidenceClassification": {"repositoryImplementation": "present", "offlineVerification": "passed",
                    "protectedRcOperation": "completed", "gaValidation": "completed", "gaPublication": "completed",
                    "publicObservation": "completed", "independentReproducibility": "pending"},
                "dispatchPackage": None, "findings": [], "redaction": {"status": "pass", "findingCount": 0, "findings": []}}
            audit._json(encoded(summary), "stable-1.0-protected-release-execution-summary-v1.schema.json")
            original_members = {p.name: p.read_bytes() for p in fixture.evidence.iterdir() if p.is_file()}
            source = provenance(fixture.contract["repository"]["identity"],
                ".github/workflows/stable-1.0-protected-release-closeout.yml", 71, "original-protected-root",
                workflow_commit=fixture.contract["repository"]["sourceCommit"],
                environment="stable-1-0-protected-release-closeout")
            def selected():
                raw = archive({"stable-1.0-protected-release-execution-summary.json": encoded(summary)})
                source["artifactDigest"] = audit._digest(raw)
                fixture.contract["evidence"]["protectedRelease"] = {"fileName": "root.zip", "digest": audit._digest(raw),
                    "size": len(raw), "schema": None, "provenance": source}
                return {"execution.json": encoded(fixture.contract), "evidence.zip": archive({**original_members, "root.zip": raw})}
            self.assertEqual("unverified", self.call("pilot-closeout", selected(), PILOT_NOW)["originalProof"]["state"])
            summary["candidateCommit"] = "f" * 40
            with self.assertRaises(audit.AuthorityContextError):
                self.call("pilot-closeout", selected(), PILOT_NOW)
            summary["candidateCommit"] = fixture.contract["repository"]["sourceCommit"]
            source["workflowPath"] = ".github/workflows/stable-1.0-wrong-producer.yml"
            with self.assertRaises(audit.AuthorityContextError):
                self.call("pilot-closeout", selected(), PILOT_NOW)

    def test_pilot_partial_freeze_keeps_original_schema_and_rejects_wrong_product(self):
        from cryptad_certification.engines import stable_1_0_third_party_pilot as owner
        from cryptad_certification.tests.third_party_pilot_fixtures import provenance
        with tempfile.TemporaryDirectory() as root:
            fixture, _ = self.pilot_payloads(Path(root).resolve(strict=True))
            freeze = release._rc_freeze_record(release._selected_rc())
            freeze["candidate"].update({"releaseId": fixture.contract["release"]["releaseId"],
                "buildVersion": str(fixture.contract["release"]["buildVersion"]),
                "sourceRef": f"refs/heads/release/{fixture.contract['release']['buildVersion']}",
                "productionDistributionDigest": fixture.contract["release"]["productDistributionDigest"]})
            source = provenance(fixture.contract["repository"]["identity"], owner.SELECTED_RC_WORKFLOW, 71,
                "original-rc-freeze", environment=owner.SELECTED_RC_ENVIRONMENT)
            def selected():
                freeze["contentDigest"] = owner.rc_freeze.freeze_content_digest(freeze)
                raw = encoded(freeze)
                fixture.contract["evidence"]["selectedRcFreeze"] = {"fileName": "freeze.json", "digest": audit._digest(raw),
                    "size": len(raw), "schema": owner.RC_FREEZE_SCHEMA, "provenance": source}
                return {"execution.json": encoded(fixture.contract), "evidence.zip": archive({
                    **{p.name: p.read_bytes() for p in fixture.evidence.iterdir() if p.is_file()}, "freeze.json": raw})}
            self.assertEqual("unverified", self.call("pilot-closeout", selected(), PILOT_NOW)["originalProof"]["state"])
            freeze["candidate"]["productionDistributionDigest"] = "sha256:" + "f" * 64
            with self.assertRaises(audit.AuthorityContextError):
                self.call("pilot-closeout", selected(), PILOT_NOW)

    def test_pilot_partial_catalog_invokes_native_archive_subject_verifier(self):
        from cryptad_certification.engines import stable_1_0_third_party_pilot as owner
        from cryptad_certification.tests import test_stable_protected_catalog_authority as fixtures
        from cryptad_certification.tests.third_party_pilot_fixtures import provenance
        with tempfile.TemporaryDirectory() as root:
            fixture, _ = self.pilot_payloads(Path(root).resolve(strict=True) / "pilot")
            contract = release._contract(Path(root).resolve(strict=True) / "ga")
            freeze = release._rc_freeze_record(release._selected_rc())
            summary = fixtures._summary(contract, freeze, {"summaryDigest": "sha256:" + "9" * 64,
                "resultDigest": "sha256:" + "a" * 64, "subjectInventoryDigest": "sha256:" + "b" * 64})
            fixtures._archive(Path(root).resolve(strict=True), Path("catalog.zip"), summary)
            raw = (Path(root).resolve(strict=True) / "catalog.zip").read_bytes()
            source = provenance(fixture.contract["repository"]["identity"], owner.catalog_authority_closeout.WORKFLOW,
                71, "original-catalog", environment=owner.catalog_authority_closeout.ENVIRONMENT)
            source["artifactDigest"] = audit._digest(raw)
            fixture.contract["evidence"]["catalogAuthority"] = {"fileName": "catalog.zip", "digest": audit._digest(raw),
                "size": len(raw), "schema": None, "provenance": source}
            payloads = {"execution.json": encoded(fixture.contract), "evidence.zip": archive({
                **{p.name: p.read_bytes() for p in fixture.evidence.iterdir() if p.is_file()}, "catalog.zip": raw})}
            with patch.object(owner.catalog_authority_closeout, "verify_artifact",
                    wraps=owner.catalog_authority_closeout.verify_artifact) as original:
                with self.assertRaises(audit.AuthorityContextError):
                    self.call("pilot-closeout", payloads, PILOT_NOW)
                original.assert_called_once()

    def test_closed_inputs_duplicate_keys_private_errors_and_unsafe_archives(self):
        for raw in (b'{"private":"contact-canary","private":"path-canary"}',
                    encoded({"private": "secret-canary"})):
            with self.assertRaisesRegex(audit.AuthorityContextError, "^phase12-native-authority-context-invalid$"):
                self.call("catalog-closeout", {"authority.json": raw, "evidence.zip": archive({})}, "2026-08-22T05:00:00Z")
        for members in ({"../escape.json": b"{}"}, {"A": b"x", "a": b"y"}, {"._metadata": b"x"}):
            with self.subTest(members=members), tempfile.TemporaryDirectory() as tmp, self.assertRaises(audit.AuthorityContextError):
                audit._archive(archive(members), Path(tmp).resolve(strict=True) / "evidence")
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(audit.AuthorityContextError):
            audit._archive(archive({"receipt.json": b"{}"}) + b"unbound-private-sidecar", Path(tmp).resolve(strict=True) / "evidence")
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(audit.AuthorityContextError):
            audit._archive(archive({"receipt.json": b'{"id":1,"id":2}'}), Path(tmp).resolve(strict=True) / "evidence")
        for extra in ("entry-comment", "archive-comment", "extra-field"):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as target:
                entry = zipfile.ZipInfo("member")
                entry.external_attr = (stat.S_IFREG | 0o600) << 16
                if extra == "entry-comment":
                    entry.comment = b"private-comment"
                elif extra == "archive-comment":
                    target.comment = b"private-comment"
                else:
                    entry.extra = b"\x00\x00\x00\x00"
                target.writestr(entry, b"x")
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as tmp, self.assertRaises(audit.AuthorityContextError):
                audit._archive(output.getvalue(), Path(tmp).resolve(strict=True) / "evidence")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as target:
            link = zipfile.ZipInfo("link")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            target.writestr(link, "private-target")
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(audit.AuthorityContextError):
            audit._archive(output.getvalue(), Path(tmp).resolve(strict=True) / "evidence")


if __name__ == "__main__":
    unittest.main()
