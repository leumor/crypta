"""Synthetic original transport, real compiled exports/signatures and native consumers.

Requires the locally built Java 25 crypta-app distribution. No fixture receipts are exported,
no node is launched, and the injected provider transport is unavailable in production.
"""
from contextlib import ExitStack
import copy
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[4]
PROTECTED = ROOT / "tools/release-certification/protected"
sys.path.insert(0, str(PROTECTED))
import app_subject_projection as projection
import cross_version_product_admission as products
import cross_version_supervisor_authority as supervisor
import maintenance_runtime_metadata as metadata
import maintenance_app_products as app_products
import historical_runtime_subjects as historical
import maintenance_runtime_projection as measurements
import original_artifact_authentication as original
from cryptad_certification.cross_version_evidence import EvidenceError, digest, validate_plan, verify
from cryptad_certification.tests.test_cross_version_evidence import fixture_plan, fixture_events, checkpoint_for
from cryptad_certification.tests.test_stable_maintenance_workflows import _activation_candidate_freeze


def packed(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(files.items()):
            archive.writestr(name, payload)
    return output.getvalue()


class SelectedRootPolicy(type(Path())):
    """Test OS owner seam only; production cohort parsing and roster checks still execute."""
    def lstat(self):
        fields = list(super().lstat())
        fields[4] = 0
        return os.stat_result(fields)


class FixedClock(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 9, 11, 10, tzinfo=dt.timezone.utc)


class ProductConsumerIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = ROOT / "platform-devtools/build/install/crypta-app"
        cls.api_jars = sorted((ROOT / "platform-api/build/libs").glob("platform-api-*.jar"))
        if not (cls.tool / "bin/crypta-app").is_file() or not cls.api_jars or not shutil.which("javac"):
            raise unittest.SkipTest("requires Java 25 and ./gradlew :platform-devtools:installDist")
        if not Path("/usr/bin/bwrap").is_file():
            raise unittest.SkipTest("requires the production bubblewrap package-export sandbox")
        cls.temporary = tempfile.TemporaryDirectory(prefix="pr304-synthetic-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        installed_java = Path(shutil.which("javac")).resolve().parents[1]
        cls.java = cls.root / "jdk"
        # Normalize the distro-specific local test JDK, then model Temurin's internal legal
        # links. The production stage must restore the independently approved materialized tree.
        linked_java = cls.root / "installed-jdk"
        shutil.copytree(installed_java, linked_java, symlinks=False, ignore_dangling_symlinks=True)
        notice = linked_java / "legal/pr304-test-notice"
        notice.parent.mkdir(exist_ok=True)
        notice.write_bytes(b"synthetic shared legal notice\n")
        duplicate = linked_java / "legal/pr304-linked-notice"
        duplicate.write_bytes(notice.read_bytes())
        approved_jdk = projection.tree_digest(linked_java)
        duplicate.unlink()
        duplicate.symlink_to(notice.name)
        metadata.stage_jdk(linked_java, cls.java, approved_jdk)
        cp = str(cls.tool / "lib/*")
        source = ROOT / "platform-devtools/src/test/java/network/crypta/platform/devtools/fixtures/Pr304SignedFixture.java"
        subprocess.run([str(cls.java / "bin/javac"), "-cp", cp, "-d", str(cls.root), str(source)],
                       check=True, capture_output=True, timeout=60)
        subprocess.run([str(cls.java / "bin/java"), "-cp", str(cls.root) + os.pathsep + cp,
                        "network.crypta.platform.devtools.fixtures.Pr304SignedFixture", str(cls.root)],
                       check=True, capture_output=True, timeout=60)
        # Compile a genuinely different implementation with the same integer label. The original
        # package's API JAR remains the only compilation dependency, and only produced class bytes
        # replace corresponding original members. This is synthetic package creation, not a
        # reconstruction of any historical release binary.
        variant = cls.root / "variant"
        variant.mkdir()
        contract_source = ROOT / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
        text = contract_source.read_text()
        if "/mail/" not in text:
            raise AssertionError("compiled contract substitution fixture must select actual Mail endpoints")
        source_copy = variant / "PlatformApiContract.java"
        source_copy.write_text(text.replace("/mail/", "/synthetic-mail/"))
        subprocess.run([str(cls.java / "bin/javac"), "-cp", str(cls.api_jars[0]), "-d", str(variant), str(source_copy)],
                       check=True, capture_output=True, timeout=60)
        output = io.BytesIO()
        with zipfile.ZipFile(cls.api_jars[0]) as source_jar, zipfile.ZipFile(output, "w") as target:
            for entry in source_jar.infolist():
                replacement = variant / entry.filename
                target.writestr(entry, replacement.read_bytes() if replacement.is_file() else source_jar.read(entry))
        cls.previous_api = output.getvalue()
        if cls.previous_api == cls.api_jars[0].read_bytes():
            raise AssertionError("compiled contract implementation did not change")
        cls.tool_digest = projection.tree_digest(cls.tool)
        cls.java_digest = projection.tree_digest(cls.java)
        tool_bytes = io.BytesIO()
        with zipfile.ZipFile(tool_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(cls.tool.rglob("*")):
                if path.is_file():
                    archive.write(path, "crypta-app/" + path.relative_to(cls.tool).as_posix())
        cls.tool_bytes = tool_bytes.getvalue()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="case-", dir=self.root))
        self.artifacts = {}
        self.counter = 0
        self.stack = ExitStack()
        invocation = "https://github.com/crypta-network/cryptad/actions/runs/1/attempts/1"
        attestation = [{"verificationResult": {"signature": {"certificate": {"runInvocationURI": invocation}}}}]
        for module in (projection, products, original, supervisor, historical):
            self.stack.enter_context(patch.object(module, "authenticate_original", side_effect=self.fetch))
            if hasattr(module, "_gh"):
                self.stack.enter_context(patch.object(module, "_gh", return_value=attestation))
                self.stack.enter_context(patch.object(module, "_environment", return_value={}))
        self.stack.enter_context(patch.dict(os.environ, {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW_REF":
            "crypta-network/cryptad/.github/workflows/stable-1.0-app-subject-projection.yml@refs/heads/develop"}))
        self.stack.enter_context(patch.object(metadata, "datetime", FixedClock))
        self.stack.enter_context(patch.object(app_products, "datetime", FixedClock))
        self.stack.enter_context(patch.object(historical, "datetime", FixedClock))

    def tearDown(self):
        self.stack.close()
        shutil.rmtree(self.work)

    def artifact(self, family, files, source="a" * 40, name="synthetic-original"):
        self.counter += 1
        raw = packed(files)
        coordinates = {"repository": "crypta-network/cryptad", "sourceFamily": family, "sourceCommit": source,
            "runId": 1, "runAttempt": 1, "jobId": self.counter, "jobName": original.PRODUCERS[family][2],
            "artifactId": self.counter, "artifactName": name, "artifactDigest": metadata.digest_bytes(raw),
            "artifactSize": len(raw)}
        original.validate_coordinates(coordinates)
        artifact = original.OriginalArtifact(raw, coordinates)
        self.artifacts[self.counter] = artifact
        return coordinates

    def fetch(self, coordinates, _root):
        artifact = self.artifacts[coordinates["artifactId"]]
        self.assertEqual(artifact.coordinates, coordinates)
        self.assertEqual(metadata.digest_bytes(artifact.content), coordinates["artifactDigest"])
        return artifact

    def cohort(self, release, source, handoff_overrides=None):
        roots = {key: "sha256:" + "8" * 64 for key in ("maintenanceAppProducts", "thirdPartyPilot")}
        tool_origin = self.artifact("projection-tools", {"tools.zip": self.tool_bytes}, source="c" * 40)
        cohort = {"schemaVersion": 1, "cohortPolicy": "current-eight-experimental-mail", "releaseId": release,
            "sourceCommit": source, "authorityRoots": roots, "toolRoot": str(self.tool), "toolTreeDigest": self.tool_digest,
            "toolOriginal": tool_origin, "toolMember": "tools.zip", "exporterRelativePath": "bin/crypta-app",
            "javaHome": str(self.java), "javaTreeDigest": self.java_digest, "sources": []}
        build = release.rsplit("-", 1)[-1]
        workspace = self.work / (release + "-workspace")
        for app in sorted(metadata.FIRST_PARTY | {"mail-prototype"}):
            built = workspace / "apps" / app / "build"
            (built / "cryptad-app-bundle").mkdir(parents=True)
            app_version = "3.1" if app == "site-publisher" else "1"
            shutil.copyfile(self.root / (app + ".zip"), built / "cryptad-app-bundle" / (app + "-" + app_version + ".zip"))
            shutil.copytree(self.root / app, built / "cryptad-app" / app)
        product_root = self.work / (release + "-app-products")
        signing = json.loads((self.root / "producer-env.json").read_bytes())
        with patch.dict(os.environ, {**signing, "GITHUB_SHA": source}):
            handoff = app_products.produce_app_products(workspace, product_root, release_id=release,
                build_version=build, source_commit=source, include_mail=True,
                artifact_base="https://example.invalid/synthetic-artifacts", exporter=self.tool / "bin/crypta-app", java_home=self.java)
        site = next(row for row in handoff["subjects"] if row["appId"] == "site-publisher")
        self.assertEqual("3.1", site["signedProjection"]["appVersion"])
        self.assertEqual(build, handoff["buildVersion"])
        if handoff_overrides:
            # Synthetic original authority seam: retain real signed app/catalog bytes while the
            # authenticated handoff identifies a different product. No production fixture switch.
            handoff.update(handoff_overrides)
            (product_root / app_products.HANDOFF_FILE).write_bytes(metadata.canonical_bytes(handoff))
        handoff_digest = products.file_digest(product_root / app_products.HANDOFF_FILE)
        maintenance_origin = self.artifact("maintenance-app-products", {
            path.relative_to(product_root).as_posix(): path.read_bytes() for path in product_root.rglob("*") if path.is_file()}, source)
        roots["maintenanceAppProducts"] = handoff_digest
        for subject in handoff["subjects"]:
            cohort["sources"].append({"appId": subject["appId"], "original": maintenance_origin,
                "originalInventory": maintenance_origin, "catalogOriginal": None, "members": subject["members"],
                "catalogKeyId": "catalog", "sourceAuthorityRoot": handoff_digest,
                "sourceEvidenceDigest": handoff_digest, "requiredForRelease": True})
        files = {"catalog": (self.root / "external.properties").read_bytes(),
                 "signature": (self.root / "external.signature").read_bytes(),
                 "bundle": (self.root / "external-app.zip").read_bytes(),
                 "submission": (self.root / "submission.zip").read_bytes()}
        names = {"catalog": "catalog", "catalogSignature": "signature", "bundle": "bundle", "submission": "submission"}
        coordinate = self.artifact("third-party-pilot", files)
        declaration = projection.produce(self.fetch(coordinate, self.work), names, exporter=self.tool / "bin/crypta-app",
            exporter_digest=products.file_digest(self.tool / "bin/crypta-app"), app_id="external-app", catalog_key_id="catalog",
            catalog_keys=self.root / "catalog-keys.properties", publisher_keys=self.root / "publisher-keys.properties",
            reviewer_keys=self.root / "reviewer-keys.properties", private_root=self.work, java_home=self.java)["declaration"]
        evidence = "sha256:" + "9" * 64
        files["execution.json"] = json.dumps({"externalApp": {"appId": "external-app"}, "cohort": [{
            "bundleDigest": declaration["bundleDigest"], "appVersion": "1", "submissionDigest": declaration["submissionDigest"],
            "bundleSignatureDigest": declaration["signatureDigest"], "expectedDecision": "reviewed"}]}).encode()
        coordinate = self.artifact("third-party-pilot", files)
        upstream = self.artifact("third-party-inventory", {"stable-1.0-third-party-app-pilot-summary.json": json.dumps({
            "summaryDigest": roots["thirdPartyPilot"], "evidence": [{"id": "third-party-pilot.external-developer", "digest": evidence, "status": "pass"}],
            "externalApp": {"appId": "external-app", "publisherKeyId": "publisher", "publisherFingerprint": declaration["publisherFingerprint"]}}).encode()})
        cohort["sources"].append({"appId": "external-app", "original": coordinate, "originalInventory": upstream,
            "catalogOriginal": None, "members": names, "catalogKeyId": "catalog", "sourceAuthorityRoot": roots["thirdPartyPilot"],
            "sourceEvidenceDigest": evidence, "requiredForRelease": True})
        for selected in cohort["sources"]:
            for field, filename in (("catalogKeys", "catalog-keys.properties"), ("publisherKeys", "publisher-keys.properties"), ("reviewerKeys", "reviewer-keys.properties")):
                selected[field] = str(self.root / filename)
                selected[field + "Digest"] = products.file_digest(self.root / filename)
        path = self.work / (release + "-cohort.json")
        path.write_text(json.dumps(cohort))
        path.chmod(0o600)
        with patch.object(projection, "COHORT_FILE", SelectedRootPolicy(path)):
            output = self.work / (release + "-projection.json")
            inventory = projection.produce_cohort(self.work, output)
        origin = self.artifact("app-subject-projection", {"platform-api-1.x-app-subject-inventory.json": output.read_bytes()})
        return cohort, SelectedRootPolicy(path), inventory, origin, product_root

    def freeze(self, build, source, predecessor=None, *, handoff_overrides=None):
        release = "stable-1.0-maintenance-" + str(build)
        cohort, policy_path, inventory, projection_origin, app_root = self.cohort(release, source, handoff_overrides)
        root = self.work / str(build)
        root.mkdir()
        package = root / ("cryptad-v" + str(build) + ".tar.gz")
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
            for name, payload in sorted((("lib/cryptad.jar", self.previous_api if build == 301 else self.api_jars[0].read_bytes()),
                                         ("README.txt", ("Synthetic build " + str(build)).encode()))):
                member = tarfile.TarInfo(name)
                member.mode, member.size = 0o644, len(payload)
                member.uname = member.gname = "root"
                archive.addfile(member, io.BytesIO(payload))
        package.write_bytes(gzip.compress(tar_bytes.getvalue(), mtime=0))
        freeze = _activation_candidate_freeze("2026-09-10T00:00:00Z")
        freeze.update(releaseId=release, buildVersion=str(build))
        freeze["source"]["commit"] = source
        freeze["producer"]["workflowCommit"] = source
        freeze["predecessorObservation"]["buildVersion"] = str(build - 1)
        freeze["predecessorObservation"]["sourceCommit"] = "b" * 40
        if predecessor is not None:
            freeze["predecessorObservation"].update(predecessor)
        files = {package.name: package.read_bytes(), "stable-catalog.json": (app_root / "catalogs/stable/catalog.properties").read_bytes(),
                 "stable-catalog.json.sig": (app_root / "catalogs/stable/cryptad-app-catalog.signature").read_bytes()}
        for row in freeze["assets"]:
            if row["role"] == "product":
                row["fileName"] = package.name
            raw = files[row["fileName"]]
            row.update(digest=metadata.digest_bytes(raw), sizeBytes=len(raw))
        freeze["assets"].sort(key=lambda row: row["fileName"])
        checksums = "".join(row["digest"][7:] + "  " + row["fileName"] + "\n" for row in freeze["assets"]).encode()
        freeze["checksumsDigest"], freeze["assetSetDigest"] = metadata.digest_bytes(checksums), metadata.semantic_digest(freeze["assets"])
        with patch.object(projection, "COHORT_FILE", policy_path):
            sealed = metadata.seal_prospective_freeze(freeze, package, root / "runtime", projection_origin=projection_origin, private_root=self.work)
        freeze_bytes = metadata.canonical_bytes(sealed)
        members = {"freeze/" + products.maintenance.CANDIDATE_FREEZE_FILE: freeze_bytes, "freeze/checksums.txt": checksums,
                   **{"freeze/assets/" + name: raw for name, raw in files.items()},
                   **{"freeze/runtime/" + path.name: path.read_bytes() for path in (root / "runtime").iterdir()}}
        origin = self.artifact("stable-maintenance-freeze", members, source,
                               "stable-1-0-maintenance-frozen-" + release + "-" + str(build) + "-1-1")
        return sealed, package, inventory, {"maintenanceProduct": {"coordinates": origin, "freezeDigest": metadata.digest_bytes(freeze_bytes)},
            "appProjection": {"coordinates": projection_origin, "cohortDigest": inventory["cohortDigest"]}}

    def phase12(self, plan, events, checkpoint, rows, measured, now):
        from cryptad_certification import phase_12_runtime_adapters as consumer
        common = {"kind": "cryptad-cross-version-supervisor", "experimentId": plan["experimentId"],
            "planDigest": digest(plan), "producer": plan["producer"],
            "job": {"sourceCommit": "a" * 40, "runId": 1, "runAttempt": 1},
            "purpose": "nonrelease-observed-experiment", "releaseEligible": False, "selectionDigest": "sha256:" + "6" * 64}
        approval = {**common, "schemaVersion": 1, "operation": "authorize", "approvedBounds": {
            "maxSeconds": 100, "maxOperations": 1000, "syntheticContent": True}, "plan": plan, "serviceDigest": "sha256:" + "7" * 64}
        def report_origin(report):
            supervisor.validate_report(report)
            return self.artifact("cross-version-supervisor", {"cross-version-supervisor.json": metadata.canonical_bytes(report)},
                                 name="cross-version-supervisor-1-1")
        approval_origin = report_origin(approval)
        start = {**common, "schemaVersion": 3, "operation": "start", "previousOrigin": approval_origin,
            "previousReportDigest": digest(approval), "serviceState": "running", "approvalOrigin": approval_origin,
            "approvalReportDigest": digest(approval), "admittedProductsDigest": digest(rows)}
        start_origin = report_origin(start)
        finish = {**start, "operation": "finish", "previousOrigin": start_origin,
            "previousReportDigest": digest(start), "serviceState": "stopped", "maintenanceMeasurements": measured,
            "checkpoint": {"sequence": checkpoint["sequence"], "tailDigest": checkpoint["tailDigest"],
                           "digest": digest(checkpoint), "status": checkpoint["status"]},
            "observation": verify(plan, events, checkpoint, now=now)}
        finish_origin = report_origin(finish)
        payloads = {name: metadata.canonical_bytes(value) for name, value in {
            "plan.json": plan, "events.json": events, "checkpoint.json": checkpoint, "products.json": rows}.items()}
        proof = {"coordinates": finish_origin, "members": consumer.ORIGINAL_MEMBERS["maintenance-measurements"]}
        result = consumer.collect_and_verify("maintenance-measurements", payloads, now.isoformat(), self.work, proof)
        self.assertEqual("authenticated", result["dimensions"]["originalProvenance"])
        self.assertEqual("partial", result["dimensions"]["coverage"])
        self.assertEqual("pass", result["components"]["subjectAdmission"])
        self.assertEqual("pass", result["components"]["measurementDerivation"])
        self.assertIn("maintenance-required-consumer-adapters-incomplete", result["blockers"])
        substituted = copy.deepcopy(rows)
        substituted[0]["runtimeBinding"]["contractSemanticDigest"] = "sha256:" + "f" * 64
        payloads["products.json"] = metadata.canonical_bytes(substituted)
        with self.assertRaises(ValueError):
            consumer.collect_and_verify("maintenance-measurements", payloads, now.isoformat(), self.work, proof)

    def historical_selection(self, contract_version, observation, *, unsupported=False):
        """Use the existing exact RC fixture authority and a separately authenticated portable.

        RC fixture records are synthetic old authority inputs. Their frozen shipped inventory is
        retained unchanged; the later experiment cohort is independently signed and selected.
        No GA publication receipt or future maintenance freeze is invented for that old authority.
        """
        from cryptad_certification.tests import test_stable_ga as ga_fixture
        suffix = "unsupported" if unsupported else "supported"
        rc_freeze = ga_fixture._complete_rc_freeze()
        rc_freeze["platformApi"]["currentContractVersion"] = contract_version
        rc_freeze["platformApi"]["baselineContractVersion"] = 19
        with patch.object(ga_fixture, "BUILD_VERSION", "301"), \
                patch.object(ga_fixture, "RELEASE_ID", "stable-1-0-rc-301"), \
                patch.object(ga_fixture, "SOURCE_COMMIT", "b" * 40), \
                patch.object(ga_fixture, "SOURCE_REF", "commit:" + "b" * 40), \
                patch.object(ga_fixture, "_complete_rc_freeze", return_value=rc_freeze):
            _, paths = ga_fixture._write_exact_rc_fixture(self.work / ("original-rc-" + suffix))
        rc_root = paths["selectedStableRcFreeze"].parent
        rc_origin = self.artifact("stable-rc-product", {
            path.relative_to(rc_root).as_posix(): path.read_bytes() for path in rc_root.rglob("*") if path.is_file()},
            "b" * 40, "stable-1-0-rc-stable-1-0-rc-301-301-1-1")
        # This package predates the new fixed main. The reviewed bridge must load every API
        # definition from its original bytes; the current tool's own API classes cannot fill gaps.
        jar_bytes = io.BytesIO()
        excluded = {"network/crypta/platform/api/PackagedApiExport.class"}
        if unsupported:
            excluded.add("network/crypta/platform/api/PlatformApiBaselineRegistry.class")
        with zipfile.ZipFile(io.BytesIO(self.previous_api)) as source, zipfile.ZipFile(jar_bytes, "w") as target:
            for entry in source.infolist():
                if entry.filename not in excluded:
                    target.writestr(entry, source.read(entry))
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
            member = tarfile.TarInfo("lib/cryptad.jar")
            member.mode, member.size = 0o644, len(jar_bytes.getvalue())
            member.uname = member.gname = "root"
            archive.addfile(member, io.BytesIO(jar_bytes.getvalue()))
        package = self.work / ("original-301-" + suffix + ".tar.gz")
        package.write_bytes(gzip.compress(tar_bytes.getvalue(), mtime=0))
        checksum = products.file_digest(package)
        checksum_bytes = (checksum[7:] + "  ./distributions/cryptad-v301.tar.gz\n").encode()
        handoff = {"schemaVersion": 1, "kind": "cryptad-stable-supply-chain-builder-handoff",
            "builderRole": "candidate-producer", "executionId": "portable-apps", "jobName": "candidate-producer-portable-apps",
            "runnerOs": "linux", "runnerArchitecture": "amd64", "releaseId": "stable-1-0-rc-301", "buildVersion": 301,
            "sourceCommit": "b" * 40, "workflowSha": "b" * 40, "runId": 1, "runAttempt": 1,
            "workflow": "github.com/crypta-network/cryptad/.github/workflows/stable-1.0-supply-chain.yml@" + "b" * 40,
            "fileSetDigest": metadata.digest_bytes(checksum_bytes)}
        portable_origin = self.artifact("first-party-release", {"handoff.json": metadata.canonical_bytes(handoff),
            "subject-files.sha256": checksum_bytes, "subjects/distributions/cryptad-v301.tar.gz": package.read_bytes()}, "b" * 40)
        selected = products.verify_rc_artifact(self.fetch(rc_origin, self.work), self.work / ("selected-rc-" + suffix))
        predecessor = {"releaseId": selected.freeze["candidate"]["releaseId"],
                       "buildVersion": selected.freeze["candidate"]["buildVersion"], "productDigest": selected.product_digest,
                       "sourceCommit": selected.freeze["candidate"]["sourceCommit"]}
        return package, {"rcCoordinates": rc_origin, "portableCoordinates": portable_origin, "runtimeObservation": observation}, predecessor

    def test_original_app_handoff_cannot_be_relabelled_for_another_candidate(self):
        for build, field, value in ((401, "releaseId", "stable-1.0-maintenance-299"),
                                     (402, "buildVersion", "299"), (403, "sourceCommit", "b" * 40)):
            with self.subTest(field=field):
                with self.assertRaises((projection.ProjectionFailure, metadata.RuntimeMetadataError)) as caught:
                    self.freeze(build, "a" * 40, handoff_overrides={field: value})
                causes = []
                error = caught.exception
                while error is not None:
                    causes.append(str(error))
                    error = error.__context__
                self.assertIn("app-subject-maintenance-candidate-identity-mismatch", causes)
                self.assertFalse((self.work / str(build) / "runtime").exists())
                self.assertFalse(any(artifact.coordinates["sourceFamily"] == "stable-maintenance-freeze"
                                     for artifact in self.artifacts.values()))

    def test_real_producer_app_admission_and_journal_have_positive_narrow_path(self):
        predecessor = self.freeze(301, "b" * 40)
        candidate = self.freeze(302, "a" * 40, {"releaseId": predecessor[0]["releaseId"], "buildVersion": "301",
            "productDigest": products.file_digest(predecessor[1]), "sourceCommit": predecessor[0]["source"]["commit"]})
        self.assertEqual(3, candidate[2]["schemaVersion"])
        self.assertEqual(sorted(metadata.FIRST_PARTY | {"mail-prototype", "external-app"}), candidate[2]["requiredAppIds"])
        manifest = metadata.read_json((candidate[1].parent / "runtime/runtime-subjects.json").read_bytes())
        self.assertEqual(sorted(metadata.FIRST_PARTY), manifest["shippedAppIds"])
        self.assertNotIn("mail-prototype", manifest["shippedAppIds"])
        current_snapshot = metadata.read_json((candidate[1].parent / "runtime/snapshot.json").read_bytes())
        previous_snapshot = metadata.read_json((predecessor[1].parent / "runtime/snapshot.json").read_bytes())
        self.assertEqual(current_snapshot["contract"]["contractVersion"], previous_snapshot["contract"]["contractVersion"])
        self.assertNotEqual(digest(current_snapshot["contract"]), digest(previous_snapshot["contract"]))
        plan = fixture_plan()
        plan.update(profile="bounded-live", provenanceClass="production-artifact-comparison")
        selection, private = {"schemaVersion": 1, "roles": {}}, {"nodes": {}}
        for node in plan["nodes"]:
            freeze, package, inventory, selected = predecessor if node["role"] == "previous" else candidate
            apps = [] if node["role"] == "relay-no-apps" else ["feed-reader", "site-publisher"] + ([] if node["role"] == "previous" else ["mail-prototype"])
            node.update(artifactDigest=products.file_digest(package), artifactSize=package.stat().st_size,
                        contractVersion=metadata.read_json((package.parent / "runtime/snapshot.json").read_bytes())["contract"]["contractVersion"])
            by_id = {row["appId"]: row["signedProjection"] for row in inventory["subjects"]}
            node["appDigests"] = sorted(by_id[app]["bundleDigest"] for app in apps)
            selection["roles"][node["role"]] = selected
            private["nodes"][node["role"]] = {"archivePath": str(package), "apps": [{"appId": app,
                "bundlePath": str(self.root / (app + ".zip")), "bundleDigest": by_id[app]["bundleDigest"]} for app in apps]}
        admitted = products.authenticate_products(plan, selection, self.work / "admission")
        self.assertTrue(admitted.bind(plan, private))
        self.assertTrue(admitted.bind_apps(plan))
        rows = admitted.public_identities()
        self.assertTrue(all(row["runtimeBinding"]["provenance"] == "frozen-with-original-release" for row in rows))
        previous_row = next(row for row in rows if row["role"] == "previous")
        release_binding = previous_row["predecessorReleaseBinding"]
        self.assertEqual("candidate-freeze-observed-published-predecessor", release_binding["provenance"])
        self.assertEqual(candidate[3]["maintenanceProduct"]["freezeDigest"], release_binding["candidateFreezeDigest"])
        for field in ("baselineDigest", "publicationReceiptDigest", "latestPublishedPointerDigest", "observedAt"):
            self.assertEqual(candidate[0]["predecessorObservation"][field], release_binding[field])
        # Each independently authenticated authority field participates in the exact relationship.
        # Repack the synthetic original transport without replacing its package or metadata bytes.
        original_candidate = self.fetch(candidate[3]["maintenanceProduct"]["coordinates"], self.work)
        with zipfile.ZipFile(io.BytesIO(original_candidate.content)) as archive:
            candidate_members = {name: archive.read(name) for name in archive.namelist()}
        for field, value in (("releaseId", "stable-1.0-maintenance-299"), ("buildVersion", "299"),
                             ("productDigest", "sha256:" + "4" * 64), ("sourceCommit", "c" * 40)):
            changed_freeze = copy.deepcopy(candidate[0])
            changed_freeze["predecessorObservation"][field] = value
            raw_freeze = metadata.canonical_bytes(changed_freeze)
            changed_members = dict(candidate_members)
            changed_members["freeze/" + products.maintenance.CANDIDATE_FREEZE_FILE] = raw_freeze
            changed_origin = self.artifact("stable-maintenance-freeze", changed_members,
                name=original_candidate.coordinates["artifactName"])
            changed_selection = copy.deepcopy(selection)
            for role in ("candidate-sender", "candidate-recipient", "relay-no-apps"):
                changed_selection["roles"][role]["maintenanceProduct"] = {
                    "coordinates": changed_origin, "freezeDigest": metadata.digest_bytes(raw_freeze)}
            with self.assertRaisesRegex(products.ProductAdmissionError, "authenticated-actual-predecessor-mismatch"):
                products.authenticate_products(plan, changed_selection, self.work / ("predecessor-mismatch-" + field))
        aliased_plan = copy.deepcopy(plan)
        alias = next(node for node in aliased_plan["nodes"] if node["role"] == "previous")
        alias["artifactDigest"] = products.file_digest(candidate[1])
        alias["artifactSize"] = candidate[1].stat().st_size
        with self.assertRaisesRegex(EvidenceError, "previous-relabels-current"):
            validate_plan(aliased_plan)
        events, checkpoint = fixture_events(plan)
        offset = dt.timedelta(days=253, hours=11)
        for event in events:
            event["wallTime"] = (dt.datetime.fromisoformat(event["wallTime"]) + offset).isoformat()
            event["previousDigest"] = digest(events[event["sequence"] - 2]) if event["sequence"] > 1 else "sha256:" + "0" * 64
        checkpoint = checkpoint_for(plan, events)
        now = dt.datetime(2026, 9, 11, 12, tzinfo=dt.timezone.utc)
        result = measurements.project(plan, events, checkpoint, rows, now=now)
        measurements.validate(result)
        self.assertEqual([], verify(plan, events, checkpoint, now=now)["findings"])
        self.assertEqual("pass", result["subjectAdmission"]["status"])
        self.assertEqual("pass", result["measurementDerivation"]["status"])
        self.assertEqual("blocked", result["maintenanceEligibility"])
        self.assertTrue(all(row["status"] == "blocked" for row in result["rows"]))
        self.phase12(plan, events, checkpoint, rows, result, now)
        # The original RC/pre-maintenance authority reaches the real production selection branch.
        # It has no prospective freeze and must retain a separate historical observation class.
        historical_plan, historical_inputs = copy.deepcopy(plan), copy.deepcopy(selection)
        historical_node = next(row for row in historical_plan["nodes"] if row["role"] == "previous")
        old_package, old_selection, old_subject = self.historical_selection(historical_node["contractVersion"], None)
        # GA promotion preserves the original RC product while assigning its own publication ID.
        # The candidate owning freeze records that published ID; package admission retains RC ID.
        old_subject["releaseId"] = "stable-1.0-ga-301"
        historical_candidate = self.freeze(303, "a" * 40, old_subject)
        old_selection["runtimeObservation"] = historical_candidate[3]["appProjection"]
        for node in historical_plan["nodes"]:
            if node["role"] != "previous":
                node.update(artifactDigest=products.file_digest(historical_candidate[1]), artifactSize=historical_candidate[1].stat().st_size)
                historical_inputs["roles"][node["role"]] = historical_candidate[3]
        historical_node.update(artifactDigest=products.file_digest(old_package), artifactSize=old_package.stat().st_size)
        historical_inputs["roles"]["previous"] = old_selection
        policy_path = SelectedRootPolicy(self.work / (historical_candidate[0]["releaseId"] + "-cohort.json"))
        with patch.object(projection, "COHORT_FILE", policy_path):
            observed = products.authenticate_products(historical_plan, historical_inputs, self.work / "historical-admission")
        observed_rows = observed.public_identities()
        old_row = next(row for row in observed_rows if row["role"] == "previous")
        self.assertEqual("observed-from-original-package", old_row["runtimeBinding"]["provenance"])
        self.assertEqual("not-established", old_row["frozenPortableBinding"])
        self.assertEqual("stable-1.0-ga-301", old_row["predecessorReleaseBinding"]["publishedReleaseId"])
        self.assertEqual("stable-1-0-rc-301", old_row["releaseId"])
        self.assertNotEqual(old_row["releaseId"], old_row["predecessorReleaseBinding"]["publishedReleaseId"])
        self.assertNotIn("maintenanceFreezeDigest", old_row)
        self.assertEqual(digest(previous_snapshot["contract"]), old_row["runtimeBinding"]["contractSemanticDigest"])
        self.assertTrue(observed.verify_runtime_contract("previous", previous_snapshot))
        with self.assertRaises(products.ProductAdmissionError):
            observed.verify_runtime_contract("previous", current_snapshot)
        historical_events = copy.deepcopy(events)
        for event in historical_events:
            event["planDigest"] = digest(historical_plan)
            event["previousDigest"] = digest(historical_events[event["sequence"] - 2]) if event["sequence"] > 1 else "sha256:" + "0" * 64
        historical_checkpoint = checkpoint_for(historical_plan, historical_events)
        historical_result = measurements.project(historical_plan, historical_events, historical_checkpoint, observed_rows, now=now)
        self.assertEqual("pass", historical_result["subjectAdmission"]["status"])
        self.assertEqual("pass", historical_result["measurementDerivation"]["status"])
        self.assertTrue(all("candidate-or-predecessor-portable-freeze-unbound" in row["blockers"] for row in historical_result["rows"]))
        self.phase12(historical_plan, historical_events, historical_checkpoint, observed_rows, historical_result, now)
        wrong_plan, wrong_selection = copy.deepcopy(plan), copy.deepcopy(selection)
        wrong_previous = next(row for row in wrong_plan["nodes"] if row["role"] == "previous")
        wrong_previous.update(artifactDigest=products.file_digest(old_package), artifactSize=old_package.stat().st_size)
        wrong_selection["roles"]["previous"] = old_selection
        with patch.object(projection, "COHORT_FILE", policy_path):
            with self.assertRaisesRegex(products.ProductAdmissionError, "authenticated-actual-predecessor-mismatch"):
                products.authenticate_products(wrong_plan, wrong_selection, self.work / "wrong-actual-predecessor")
        bad_package, bad_selection, _ = self.historical_selection(historical_node["contractVersion"], historical_candidate[3]["appProjection"], unsupported=True)
        historical_node.update(artifactDigest=products.file_digest(bad_package), artifactSize=bad_package.stat().st_size)
        historical_inputs["roles"]["previous"] = bad_selection
        with patch.object(projection, "COHORT_FILE", policy_path):
            with self.assertRaisesRegex(products.ProductAdmissionError, "historical-original-package-exporter-unsupported"):
                products.authenticate_products(historical_plan, historical_inputs, self.work / "unsupported-admission")
        payload = metadata.read_json((candidate[1].parent / "runtime/snapshot.json").read_bytes())
        self.assertTrue(admitted.verify_runtime_contract("candidate-sender", payload))
        with self.assertRaises(products.ProductAdmissionError):
            admitted.verify_runtime_contract("candidate-sender", previous_snapshot)
        changed = copy.deepcopy(payload)
        changed["contract"]["capabilities"].pop()
        with self.assertRaises(products.ProductAdmissionError):
            admitted.verify_runtime_contract("candidate-sender", changed)
        altered = copy.deepcopy(plan)
        altered["nodes"][0]["appDigests"].pop()
        with self.assertRaises(products.ProductAdmissionError):
            products.authenticate_products(altered, selection, self.work / "omitted-app")
        candidate[1].write_bytes(candidate[1].read_bytes() + b"x")
        with self.assertRaises(products.ProductAdmissionError):
            admitted.bind(plan, private)
