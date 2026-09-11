"""Native site records checked with isolated transports; fixtures never authenticate deployment."""
from __future__ import annotations

import datetime as dt
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from cryptad_certification import phase_12_site_evidence as site
from cryptad_certification import phase_12_closeout as closeout
from cryptad_certification import transparency_bundle as bundle
from cryptad_certification import transparency_sources as sources

AS_OF = "2026-09-10T01:00:00Z"
COMMIT = "a" * 40


def zip_bytes(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, raw in sorted(files.items()):
            archive.writestr(name, raw)
    return output.getvalue()


def pages_bytes(files, *, link=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, raw in sorted(files.items()):
            member = tarfile.TarInfo("./" + name)
            member.size = len(raw)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(raw))
        if link:
            member = tarfile.TarInfo("./private-link")
            member.type, member.linkname = tarfile.LNKTYPE, "index.html"
            archive.addfile(member)
    return zip_bytes({"artifact.tar": output.getvalue()})


def fixture(root, *, previous=False):
    """Build genuine native file formats under visibly synthetic transport/hosted records."""
    def package(stamp):
        return sources.collect({"schemaVersion": 1, "mode": "production", "asOf": stamp, "sources": []}, root)
    prior = b""
    prior_digest = None
    if previous:
        bundle.build(package("2026-09-09T00:00:00Z"), root / "prior")
        previous_files = bundle.inventory(root / "prior")
        prior_digest = bundle.digest(previous_files[bundle.MANIFEST])
        prior = zip_bytes(previous_files)
    bundle.build(package("2026-09-10T00:00:00Z"), root / "site")
    files = bundle.inventory(root / "site")
    manifest = bundle.digest(files[bundle.MANIFEST])
    selected = {"schemaVersion": 1, "sourceCommit": COMMIT, "runId": 123, "runAttempt": 2,
                "manifestDigest": manifest, "previousManifestDigest": prior_digest,
                "bootstrapManifestDigest": None if previous else manifest,
                "siteUrl": "https://example.org/synthetic-site/"}
    checkpoint = {"status": "checkpoint-verified" if previous else "bootstrap-authorized",
                  "manifestDigest": prior_digest or manifest}
    run = {"id": 123, "run_attempt": 2, "path": site.WORKFLOW, "head_sha": COMMIT,
           "head_branch": "develop", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
           "repository": {"full_name": site.REPOSITORY}}
    jobs = []
    for i, name in enumerate(site.JOBS):
        jobs.append({"id": i + 10, "name": name, "run_id": 123, "head_sha": COMMIT, "status": "completed",
                     "conclusion": "success", "steps": [{"number": 1, "name": "synthetic-record", "conclusion": "success"}],
                     "started_at": f"2026-09-10T00:0{i}:00Z", "completed_at": f"2026-09-10T00:0{i}:59Z"})
    def artifact(name, data, job, identity):
        return {"id": identity, "name": name, "digest": bundle.digest(data), "size_in_bytes": len(data),
                "workflow_run": {"id": 123, "head_sha": COMMIT},
                "created_at": job["started_at"], "updated_at": job["completed_at"], "expired": False}
    raw_bundle, pages = zip_bytes(files), pages_bytes(files)
    deployment = {"id": 7, "sha": COMMIT, "environment": "github-pages",
                  "creator": {"login": "github-actions[bot]"}, "repository_url": site.API,
                  "url": site.API + "/deployments/7", "created_at": jobs[3]["started_at"]}
    status = {"id": 8, "environment": "github-pages", "state": "success",
              "deployment_url": deployment["url"], "environment_url": selected["siteUrl"],
              "log_url": site.WEB + "/actions/runs/123/job/13", "created_at": jobs[3]["completed_at"]}
    stamp = "2026-09-10T00:04:30Z"
    native = bundle.observe(root / "site", selected["siteUrl"], stamp, expected_manifest=manifest,
               clock=lambda: dt.datetime.fromisoformat(stamp),
               fetcher=lambda url, _limit: files[url.removeprefix(selected["siteUrl"])])
    observation = bundle.canonical(native)
    observation_archive = zip_bytes({"public-observation.json": observation})
    return {"selection.json": bundle.canonical(selected), "bundle.zip": raw_bundle, "previous.zip": prior,
            "checkpoint.json": bundle.canonical(checkpoint), "run.json": bundle.canonical(run),
            "jobs.json": bundle.canonical({"total_count": len(jobs), "jobs": jobs}),
            "artifact.json": bundle.canonical(artifact("verified-public-site", raw_bundle, jobs[1], 100)),
            "pages-artifact.json": bundle.canonical(artifact("github-pages", pages, jobs[2], 101)),
            "pages-artifact.zip": pages, "deployment.json": bundle.canonical(deployment),
            "deployment-status.json": bundle.canonical(status), "observation.json": observation,
            "observation-artifact.json": bundle.canonical(artifact("public-site-observation", observation_archive, jobs[4], 102)),
            "observation.zip": observation_archive}


class SiteEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.inputs = fixture(self.root)

    def evaluate(self, inputs=None, adapter="site-observation"):
        selected = inputs or self.inputs
        selected = {key: selected[key] for key in site.REQUIRED_INPUTS[adapter]}
        with tempfile.TemporaryDirectory() as temporary, mock.patch("socket.create_connection", side_effect=AssertionError("network denied")):
            return site.verify(adapter, selected, AS_OF, Path(temporary).resolve())

    def change(self, name, change, inputs=None):
        result = dict(inputs or self.inputs)
        value = bundle.parse(result[name])
        change(value)
        result[name] = bundle.canonical(value)
        return result

    def evaluate_closeout(self, adapter, inputs):
        selected = closeout.repository_selection()
        identity = bundle.parse(inputs["selection.json"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            directory = root / "site"
            directory.mkdir()
            members = []
            for name in site.REQUIRED_INPUTS[adapter]:
                raw = inputs[name]
                (directory / name).write_bytes(raw)
                members.append({"name": name, "digest": bundle.digest(raw), "size": len(raw)})
            selected["artifacts"] = [{"id": "site", "adapter": adapter, "files": members,
                "subject": {"kind": "public-site", "commit": identity["sourceCommit"],
                            "tree": closeout.checkout()["tree"], "build": None,
                            "digest": identity["manifestDigest"]},
                "predecessors": [], "proof": None, "expiresAt": None,
                "observedAt": bundle.parse(inputs["observation.json"])["observedAt"]
                    if adapter == "site-observation" else None}]
            with mock.patch("socket.socket", side_effect=AssertionError("offline network denied")):
                return closeout.evaluate(selected, root, AS_OF)

    def test_closeout_admits_bootstrap_empty_predecessor_without_authenticating_operations(self):
        self.assertEqual(b"", self.inputs["previous.zip"])
        for adapter in site.REQUIRED_INPUTS:
            with self.subTest(adapter=adapter):
                result = self.evaluate_closeout(adapter, self.inputs)
                self.assertEqual("executed-pass", result["subjects"][0]["verification"])
                row = next(row for row in result["requirements"]
                           if row["id"] == "p12-302-" + adapter.removeprefix("site-"))
                self.assertEqual("executed-pass", row["dimensions"]["localVerification"])
                self.assertNotEqual("authenticated", row["dimensions"]["originalProvenance"])
                self.assertEqual("incomplete", result["phaseDecision"])
                self.assertFalse(result["phaseComplete"])

    def test_closeout_owner_still_rejects_wrong_bootstrap_and_nonbootstrap_markers(self):
        root = self.root / "successor"
        root.mkdir()
        successor = fixture(root, previous=True)
        for adapter in site.REQUIRED_INPUTS:
            with self.subTest(adapter=adapter):
                self.assertEqual("executed-pass", self.evaluate_closeout(adapter, successor)["subjects"][0]["verification"])
                for inputs in ({**successor, "previous.zip": b""},
                               {**self.inputs, "previous.zip": zip_bytes({})}):
                    result = self.evaluate_closeout(adapter, inputs)
                    self.assertEqual("failed", result["subjects"][0]["verification"])
                    self.assertEqual("blocked", result["phaseDecision"])

    def test_closeout_rejects_empty_other_site_members(self):
        for adapter in site.REQUIRED_INPUTS:
            for name in site.REQUIRED_INPUTS[adapter]:
                if name in {"previous.zip", "selection.json", "observation.json"}:
                    continue
                with self.subTest(adapter=adapter, member=name), self.assertRaisesRegex(ValueError, "artifact-byte-contract"):
                    self.evaluate_closeout(adapter, {**self.inputs, name: b""})

    def reseal_observation(self, value):
        result = dict(self.inputs)
        result["observation.json"] = bundle.canonical(value)
        result["observation.zip"] = zip_bytes({"public-observation.json": result["observation.json"]})
        artifact = bundle.parse(result["observation-artifact.json"])
        artifact.update(digest=bundle.digest(result["observation.zip"]), size_in_bytes=len(result["observation.zip"]))
        result["observation-artifact.json"] = bundle.canonical(artifact)
        return result

    def test_native_empty_site_observation_is_semantically_verified_without_inventing_deployment(self):
        result = self.evaluate()
        self.assertEqual("native-exact-match-reported", result["retainedRecordClassification"])
        self.assertEqual("executed-pass", result["dimensions"]["localVerification"])
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
        self.assertEqual("not-observed", result["dimensions"]["publication"])
        self.assertEqual("not-observed", result["dimensions"]["publicObservation"])
        self.assertEqual(["p12-302-observation"], result["claims"])
        self.assertNotIn("p12-291-publication", result["claims"])

    def test_deployment_verification_reuses_exact_pages_and_build_exports(self):
        result = self.evaluate(adapter="site-deployment")
        self.assertEqual(["p12-302-deployment"], result["claims"])
        self.assertEqual("deployment-records-consistent", result["retainedRecordClassification"])
        wrong = dict(self.inputs)
        files = site._zip(wrong["bundle.zip"])
        files["index.html"] += b"tampered"
        wrong["pages-artifact.zip"] = pages_bytes(files)
        with self.assertRaises(ValueError):
            self.evaluate(wrong)

    def test_existing_prior_checkpoint_history_is_verified_with_exact_old_bytes(self):
        alternate = self.root / "successor"
        alternate.mkdir()
        inputs = fixture(alternate, previous=True)
        self.assertEqual("executed-pass", self.evaluate(inputs)["dimensions"]["localVerification"])
        changed = self.change("selection.json", lambda row: row.update(previousManifestDigest="sha256:" + "f" * 64), inputs)
        with self.assertRaises(ValueError):
            self.evaluate(changed)

    def test_wrong_attempt_source_repository_environment_or_job_link_rejected(self):
        mutations = (("run.json", lambda row: row.update(run_attempt=1)),
                     ("run.json", lambda row: row.update(head_sha="b" * 40)),
                     ("run.json", lambda row: row["repository"].update(full_name="attacker/site")),
                     ("run.json", lambda row: row.update(event="pull_request")),
                     ("deployment.json", lambda row: row.update(environment="unprotected")),
                     ("deployment-status.json", lambda row: row.update(log_url=site.WEB + "/actions/runs/123/job/14")))
        for name, mutation in mutations:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.evaluate(self.change(name, mutation))

    def test_artifact_reupload_different_job_time_or_swapped_id_reject(self):
        for name, mutation in (("artifact.json", lambda row: row["workflow_run"].update(id=124)),
                               ("pages-artifact.json", lambda row: row.update(id=100)),
                               ("observation-artifact.json", lambda row: row.update(created_at="2026-09-10T00:03:01Z"))):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.evaluate(self.change(name, mutation))

    def test_native_conflict_counts_derive_conflict_but_cannot_be_flipped_to_exact(self):
        observation = bundle.parse(self.inputs["observation.json"])
        observation["exactFiles"] -= 1
        observation["conflictingFiles"] = 1
        observation["status"] = "conflict"
        result = self.evaluate(self.reseal_observation(observation))
        self.assertIn("site-public-byte-observation-not-exact", result["blockers"])
        observation["status"] = "exact-match"
        with self.assertRaises(ValueError):
            self.evaluate(self.reseal_observation(observation))

    def test_future_outside_job_and_forged_count_observations_reject(self):
        for change in (lambda row: row.update(observedAt="2026-09-11T00:00:00Z"),
                       lambda row: row.update(observedAt="2026-09-10T00:03:45Z"),
                       lambda row: row.update(exactFiles=row["exactFiles"] + 1),
                       lambda row: row.update(exactFiles=True)):
            value = bundle.parse(self.inputs["observation.json"])
            change(value)
            with self.assertRaises(ValueError):
                self.evaluate(self.reseal_observation(value))

    def test_skipped_deployment_job_is_not_publication_evidence(self):
        inputs = self.change("jobs.json", lambda row: row["jobs"][3].update(conclusion="skipped"))
        result = self.evaluate(inputs, adapter="site-deployment")
        self.assertIn("site-required-deployment-jobs-not-successful", result["blockers"])
        self.assertEqual("not-observed", result["dimensions"]["publication"])

    def test_skipped_observe_job_does_not_erase_native_deployment_records(self):
        inputs = self.change("jobs.json", lambda row: row["jobs"][4].update(
            conclusion="skipped", steps=[], started_at=None, completed_at=None))
        result = self.evaluate(inputs, adapter="site-deployment")
        self.assertEqual("deployment-records-consistent", result["retainedRecordClassification"])
        with self.assertRaises(ValueError):
            self.evaluate(inputs)

    def test_environment_approval_wait_and_delayed_status_are_native_timing(self):
        inputs = self.change("deployment.json", lambda row: row.update(created_at="2026-09-10T00:00:00Z"))
        inputs = self.change("deployment-status.json", lambda row: row.update(created_at="2026-09-10T00:04:00Z"), inputs)
        self.assertEqual("deployment-records-consistent", self.evaluate(inputs, adapter="site-deployment")["retainedRecordClassification"])

    def test_checkpoint_selection_cannot_smuggle_empty_or_unbound_bootstrap_pin(self):
        for mutation in (lambda row: row.update(previousManifestDigest=""),
                         lambda row: row.update(bootstrapManifestDigest="sha256:" + "f" * 64)):
            with self.assertRaises(ValueError):
                self.evaluate(self.change("selection.json", mutation))

    def test_pages_tar_hardlinks_reject(self):
        inputs = dict(self.inputs)
        inputs["pages-artifact.zip"] = pages_bytes(site._zip(inputs["bundle.zip"]), link=True)
        with self.assertRaises(ValueError):
            self.evaluate(inputs)

    def test_archive_comments_extra_metadata_empty_directory_and_appended_sidecars_reject(self):
        files = site._zip(self.inputs["bundle.zip"])
        for kind in ("comment", "extra", "entry-comment", "empty-directory", "appended"):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                if kind == "comment":
                    archive.comment = b"PRIVATE_COMMENT"
                for name, raw in files.items():
                    member = zipfile.ZipInfo(name)
                    if kind == "extra":
                        member.extra = b"\x01\x00\x00\x00"
                    if kind == "entry-comment":
                        member.comment = b"PRIVATE_COMMENT"
                    archive.writestr(member, raw)
                if kind == "empty-directory":
                    archive.writestr("private-sidecar/", b"")
            inputs = dict(self.inputs)
            inputs["bundle.zip"] = output.getvalue() + (b"PRIVATE_SIDECAR" if kind == "appended" else b"")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.evaluate(inputs)

    def test_pages_pax_metadata_is_not_the_pinned_ubuntu_gnu_export(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, raw in site._zip(self.inputs["bundle.zip"]).items():
                member = tarfile.TarInfo("./" + name)
                member.size = len(raw)
                member.pax_headers = {"private-note": "PRIVATE_METADATA"}
                archive.addfile(member, io.BytesIO(raw))
        inputs = dict(self.inputs)
        inputs["pages-artifact.zip"] = zip_bytes({"artifact.tar": output.getvalue()})
        with self.assertRaises(ValueError):
            self.evaluate(inputs)

    def test_traversal_and_case_collision_archives_reject(self):
        for names in (("../private.json",), ("index.html", "INDEX.html")):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                for name in names:
                    archive.writestr(name, b"{}")
            inputs = dict(self.inputs)
            inputs["bundle.zip"] = output.getvalue()
            with self.subTest(names=names), self.assertRaises(ValueError):
                self.evaluate(inputs)

    def test_private_native_details_and_errors_never_escape(self):
        inputs = self.change("deployment.json", lambda row: row.update(description="PRIVATE_CONTACT /home/private-user"))
        result = self.evaluate(inputs)
        self.assertNotIn("PRIVATE_CONTACT", str(result))
        self.assertNotIn("private-user", str(result))
        invalid = self.change("selection.json", lambda row: row.update(siteUrl="https://secret-user:secret-key@example.org/private/"))
        with self.assertRaisesRegex(ValueError, "^phase12-site-native-evidence-rejected$"):
            self.evaluate(invalid)

    def test_deterministic_independent_scratch_roots(self):
        self.assertEqual(self.evaluate(), self.evaluate())


if __name__ == "__main__":
    unittest.main()
