"""Synthetic original transport with real signed fixtures and production native projection.

The seam is confined to this test module. No production manifest can select it. These records
model source authentication for executable regression tests and are never protected/live evidence.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app_subject_projection as projection
import federation_selection as selection
import original_artifact_authentication as original


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class _OriginalFixtureTransport:
    """Exact in-memory artifact transport; wrong coordinates fail before native execution."""
    def __init__(self):
        self.artifacts = {}

    def add(self, family, files):
        raw = selection._archive(files)
        identifier = len(self.artifacts) + 1
        coordinates = {
            "repository": original.REPOSITORY, "sourceFamily": family,
            "sourceCommit": "a" * 40, "runId": 305, "runAttempt": 2,
            "jobId": identifier, "jobName": original.PRODUCERS[family][2],
            "artifactId": identifier, "artifactName": "synthetic-original-" + str(identifier),
            "artifactDigest": _digest(raw), "artifactSize": len(raw),
        }
        original.validate_coordinates(coordinates)
        self.artifacts[identifier] = original.OriginalArtifact(raw, coordinates)
        return coordinates

    def fetch(self, coordinates, _private_root):
        artifact = self.artifacts.get(coordinates.get("artifactId"))
        if artifact is None or artifact.coordinates != coordinates:
            raise original.AuthenticationError("synthetic-original-coordinate-substitution")
        if _digest(artifact.content) != coordinates["artifactDigest"]:
            raise original.AuthenticationError("synthetic-original-byte-substitution")
        return artifact

    @staticmethod
    def proof(*_args, **_kwargs):
        return [{"verificationResult": {"signature": {"certificate": {
            "runInvocationURI": "https://github.com/crypta-network/cryptad/actions/runs/305/attempts/2"
        }}}}]


class _SyntheticRootOwnedPath(type(Path())):
    """OS-owner seam only: ordinary CI does not need root to model protected input ownership."""
    def lstat(self):
        fields = list(super().lstat())
        fields[4] = 0
        return os.stat_result(fields)


def _positive_names(fixture):
    """Keep old three-subject fixtures distinct from the finite B4 successor cohort."""
    metadata = json.loads((fixture / "fixture.json").read_bytes())
    version = metadata.get("schemaVersion")
    if type(version) is not int or version not in {1, 2}:
        raise ValueError("synthetic-fixture-version-invalid")
    expected = ("A1", "A2", "B3") if version == 1 else ("A1", "A2", "B3", "B4")
    if set(metadata.get("subjects", {})) != set(expected):
        raise ValueError("synthetic-fixture-transition-cohort-invalid")
    return expected


def _source_artifacts(fixture, transport):
    metadata = json.loads((fixture / "fixture.json").read_bytes())
    files, cohort = {}, []
    for name in _positive_names(fixture):
        for filename in ("catalog.properties", "cryptad-app-catalog.signature", "bundle.zip", "submission.zip"):
            files[name + "/" + filename] = (fixture / name / filename).read_bytes()
        cohort.append({
            "bundleDigest": metadata["subjects"][name]["bundleDigest"],
            "appVersion": metadata["subjects"][name]["appVersion"],
            "submissionDigest": _digest(files[name + "/submission.zip"]),
            "bundleSignatureDigest": _digest((fixture / name / "app/cryptad-app.signature").read_bytes()),
            "expectedDecision": "reviewed",
        })
    files["execution.json"] = _json({"externalApp": {"appId": metadata["appId"]}, "cohort": cohort})
    source = transport.add("third-party-pilot", files)
    evidence = _digest(b"synthetic-original-external-review")
    authority = _digest(b"synthetic-original-pilot-summary")
    inventory = transport.add("third-party-inventory", {
        "stable-1.0-third-party-app-pilot-summary.json": _json({
            "summaryDigest": authority,
            "evidence": [{"id": "third-party-pilot.external-developer", "digest": evidence, "status": "pass"}],
            "externalApp": {"appId": metadata["appId"], "publisherKeyId": "publisher",
                            "publisherFingerprint": "sha256:" + metadata["subjects"]["A1"]["publisherFingerprint"]},
        })
    })
    return source, inventory, authority, evidence


def _selection_policy(fixture, source):
    contexts, members = [], {}
    for name in _positive_names(fixture):
        root = fixture / "selections" / name
        context_file = root / "selection.json"
        context = json.loads(context_file.read_bytes())
        member_name = "selections/" + name + "/selection.json"
        contexts.append({"id": name.lower(), "appId": context["appId"], "member": member_name,
                         "digest": _digest(context_file.read_bytes()), "generation": context["generation"]})
        members[member_name] = {"name": member_name, "path": str(context_file),
                               "digest": _digest(context_file.read_bytes()), "size": context_file.stat().st_size,
                               "original": None}
        for category in ("catalogBindings", "publisherBindings", "reviewerScopes"):
            for reference in context[category]:
                path = root / reference["path"]
                relative = "selections/" + name + "/" + reference["path"]
                members[relative] = {"name": relative, "path": str(path), "digest": reference["digest"],
                                     "size": path.stat().st_size, "original": None}
        for candidate in context["candidates"]:
            for reference in candidate.values():
                path = root / reference["path"]
                relative = "selections/" + name + "/" + reference["path"]
                members[relative] = {"name": relative, "path": str(path), "digest": reference["digest"],
                                     "size": path.stat().st_size,
                                     "original": {"coordinates": source, "member": reference["path"]}}
    return {"schemaVersion": 1, "contexts": contexts, "members": list(members.values())}


def verify_original_fixture(fixture_root, tool, java, private_root, snapshot, registry):
    """Return real native declarations after original selection/source authentication.

    No daemon freeze, runtime observation, prospective verdict, or caller manifest declaration is
    consumed. The caller supplies the exact packaged native contract and full registry paths.
    """
    fixture, tool, java, private = map(Path, (fixture_root, tool, java, private_root))
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    transport = _OriginalFixtureTransport()
    source_original, inventory_original, authority, evidence = _source_artifacts(fixture, transport)
    policy = _selection_policy(fixture, source_original)
    for member in policy["members"]:
        if member["original"] is None:
            Path(member["path"]).chmod(0o600)
    policy_file = private / "synthetic-selection-policy.json"
    policy_file.write_bytes(_json(policy))
    policy_file.chmod(0o600)
    envelopes = {}

    def cms(raw, _root, *, decrypt=False):
        if decrypt:
            if raw not in envelopes:
                raise selection.SelectionFailure("synthetic-envelope-substituted")
            return envelopes[raw]
        cipher = b"synthetic-cms-transport:" + hashlib.sha256(raw).digest()
        envelopes[cipher] = raw
        return cipher

    test = unittest.TestCase()
    results = {}
    with ExitStack() as stack:
        for module in (projection, selection):
            stack.enter_context(patch.object(module, "authenticate_original", side_effect=transport.fetch))
        stack.enter_context(patch.object(selection, "POLICY", policy_file))
        stack.enter_context(patch.object(selection, "Path", _SyntheticRootOwnedPath))
        stack.enter_context(patch.object(selection, "_cms", side_effect=cms))
        stack.enter_context(patch.object(selection, "_gh", side_effect=transport.proof))
        stack.enter_context(patch.object(selection, "_environment", return_value={}))
        stack.enter_context(patch.dict(os.environ, {
            "GITHUB_WORKFLOW_REF": original.REPOSITORY + "/" + selection.WORKFLOW + "@refs/heads/develop",
            "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "305", "GITHUB_RUN_ATTEMPT": "2",
        }))
        # The producer authenticates all catalog/signature/bundle originals before the encrypted
        # handoff is constructed. The transport is a test seam, not a production verification flag.
        encrypted = private / "selection.cms"
        selection.produce_selection(private, encrypted)
        selected_original = transport.add("federation-selection", {selection.MEMBER: encrypted.read_bytes()})
        authenticated = selection.authenticate_selection(selected_original, private)

        bad_attempt = {**selected_original, "runAttempt": 3}
        with patch.object(selection, "_cms") as decrypt:
            with test.assertRaises(original.AuthenticationError):
                selection.authenticate_selection(bad_attempt, private)
            decrypt.assert_not_called()
        with patch.object(selection, "_gh", return_value=[]) as proof, patch.object(selection, "_cms") as decrypt:
            with test.assertRaises(selection.SelectionFailure):
                selection.authenticate_selection(selected_original, private)
            test.assertTrue(proof.called)
            decrypt.assert_not_called()

        for name in _positive_names(fixture):
            members = {"catalog": name + "/catalog.properties",
                       "catalogSignature": name + "/cryptad-app-catalog.signature",
                       "bundle": name + "/bundle.zip", "submission": name + "/submission.zip"}
            source = {"appId": "pr305-fixture", "original": source_original,
                      "originalInventory": inventory_original, "catalogOriginal": None,
                      "members": members, "sourceAuthorityRoot": authority, "sourceEvidenceDigest": evidence}
            args = dict(exporter=tool / "bin/crypta-app", exporter_digest=_digest((tool / "bin/crypta-app").read_bytes()),
                        app_id="pr305-fixture", catalog_key_id="catalog-a" if name.startswith("A") else "catalog-b",
                        catalog_keys=fixture / "catalog-keys.properties", publisher_keys=fixture / "publisher-keys.properties",
                        reviewer_keys=fixture / "reviewer-keys.properties", private_root=private, java_home=java,
                        contract_path=Path(snapshot), baseline_registry_path=Path(registry),
                        federation_selection=authenticated, selection_id=name.lower(), source=source)
            artifact = transport.fetch(source_original, private)
            # Source/member/selection mismatches must stop before the native executable starts.
            for changed in ({**source, "original": selected_original},
                            {**source, "members": {**members, "bundle": "unapproved.zip"}}):
                with patch("bounded_process.run") as execute:
                    with test.assertRaises(selection.SelectionFailure):
                        projection.produce(artifact, members, **{**args, "source": changed})
                    execute.assert_not_called()
            with patch("bounded_process.run") as execute:
                with test.assertRaises(projection.ProjectionFailure):
                    projection.produce(artifact, members, **{**args, "federation_selection": None})
                execute.assert_not_called()
            with patch("bounded_process.run") as execute:
                with test.assertRaises(selection.SelectionFailure):
                    projection.produce(artifact, members, **{**args, "selection_id": "unplanned"})
                execute.assert_not_called()
            declaration = projection.produce(artifact, members, **args)["declaration"]
            projection.verify_upstream_subject(source, declaration, artifact, private)
            test.assertEqual(3, declaration["schemaVersion"])
            test.assertEqual("accepted", declaration["nativeAdmission"])
            test.assertEqual(authenticated.context(name.lower())["digest"],
                             declaration["federationSelection"]["selectionDigest"])
            test.assertIsNotNone(declaration["submissionDigest"])
            results[name] = declaration
    return results


class OriginalFixtureTransportTest(unittest.TestCase):
    def test_prospective_transition_roster_cannot_drop_or_add_an_authorized_version(self):
        with tempfile.TemporaryDirectory(prefix="pr305-roster-") as directory:
            root = Path(directory)
            for names in (("A1", "A2", "B3"), ("A1", "A2", "B3", "B4", "B5")):
                (root / "fixture.json").write_bytes(_json({"schemaVersion": 2, "subjects": dict.fromkeys(names, {})}))
                transport = _OriginalFixtureTransport()
                with self.subTest(names=names), self.assertRaisesRegex(ValueError, "synthetic-fixture-transition-cohort-invalid"):
                    _source_artifacts(root, transport)
                self.assertFalse(transport.artifacts)
            (root / "fixture.json").write_bytes(_json({"schemaVersion": 1,
                "subjects": dict.fromkeys(("A1", "A2", "B3"), {})}))
            self.assertEqual(("A1", "A2", "B3"), _positive_names(root))

    def test_transport_rejects_wrong_original_run_attempt_family_and_member_bytes(self):
        transport = _OriginalFixtureTransport()
        coordinates = transport.add("third-party-pilot", {"bundle.zip": b"synthetic"})
        for field, value in (("runId", 306), ("runAttempt", 1), ("sourceFamily", "federation-selection"),
                             ("artifactDigest", "sha256:" + "0" * 64)):
            with self.subTest(field=field), self.assertRaises(original.AuthenticationError):
                transport.fetch({**coordinates, field: value}, None)

    def test_transport_does_not_promote_unknown_artifact_to_original(self):
        with self.assertRaises(original.AuthenticationError):
            _OriginalFixtureTransport().fetch({"artifactId": 999}, None)


if __name__ == "__main__":
    unittest.main()
