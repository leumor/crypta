"""Executable exact-package observation and historical format isolation regressions."""
from __future__ import annotations
import io
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import maintenance_runtime_metadata as metadata


class PackagedObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        java = shutil.which("java")
        javac = shutil.which("javac")
        if not java or not javac or not Path("/usr/bin/bwrap").exists():
            raise unittest.SkipTest("Java compiler or bounded export sandbox unavailable")
        cls.java_home = Path(java).resolve().parents[1]
        cls.javac = javac

    def package(self, root, surface, *, manifest=None):
        source = root / "source/network/crypta/platform/api/PackagedApiExport.java"
        source.parent.mkdir(parents=True)
        envelope = {"schemaVersion": 1, "kind": "packaged-platform-api-export",
                    "contractSnapshot": json.dumps({"contract": {"contractVersion": 26, "surface": surface}}),
                    "baselineRegistry": json.dumps({"baselineRegistry": {"surface": surface}})}
        literal = json.dumps(json.dumps(envelope))
        source.write_text("package network.crypta.platform.api; public final class PackagedApiExport {"
                          "public static void main(String[] args) {System.out.print(" + literal + ");}}")
        classes = root / "classes"
        subprocess.run([self.javac, "-d", str(classes), str(source)], check=True, capture_output=True)
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as jar:
            for path in classes.rglob("*.class"):
                jar.write(path, path.relative_to(classes).as_posix())
            if manifest:
                jar.writestr("META-INF/MANIFEST.MF", manifest)
        package = root / "cryptad-v999.tar.gz"
        with package.open("wb") as destination, gzip.GzipFile(fileobj=destination, mode="wb", filename="", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w") as archive:
            entry = tarfile.TarInfo("lib/cryptad.jar")
            entry.mode = 0o644
            entry.uname = entry.gname = "root"
            entry.size = len(raw.getvalue())
            archive.addfile(entry, io.BytesIO(raw.getvalue()))
        return package

    def test_two_compiled_surfaces_with_same_integer_export_distinct_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first = self.package(root / "first", "first")
            second = self.package(root / "second", "second")
            first_snapshot, _, first_executable = metadata.observe_package(first, self.java_home, root)
            second_snapshot, _, second_executable = metadata.observe_package(second, self.java_home, root)
            self.assertEqual(json.loads(first_snapshot)["contract"]["contractVersion"], 26)
            self.assertEqual(json.loads(second_snapshot)["contract"]["contractVersion"], 26)
            self.assertEqual(json.loads(first_snapshot)["contract"]["surface"], "first")
            self.assertEqual(json.loads(second_snapshot)["contract"]["surface"], "second")
            self.assertNotEqual(first_snapshot, second_snapshot)
            self.assertNotEqual(first_executable["digest"], second_executable["digest"])
            metadata.verify_package_identity(first, {"portable": metadata.identity(first), "executable": first_executable})
            with self.assertRaisesRegex(metadata.RuntimeMetadataError, "executable-substituted"):
                metadata.verify_package_identity(second, {"portable": metadata.identity(second), "executable": first_executable})

    def test_manifest_cannot_escape_fixed_package_classpath(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package = self.package(root / "package", "first", manifest="Manifest-Version: 1.0\nClass-Path: foreign.jar\n")
            with self.assertRaisesRegex(metadata.RuntimeMetadataError, "external-classpath"):
                metadata.observe_package(package, self.java_home, root)

    def test_portable_case_collision_rejects_before_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package = root / "cryptad-v999.tar.gz"
            with package.open("wb") as destination, gzip.GzipFile(fileobj=destination, mode="wb", filename="", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w") as archive:
                for name in ("lib/cryptad.jar", "LIB/CRYPTAD.JAR"):
                    entry = tarfile.TarInfo(name)
                    entry.size = 1
                    entry.mode = 0o644
                    entry.uname = entry.gname = "root"
                    archive.addfile(entry, io.BytesIO(b"x"))
            with self.assertRaisesRegex(metadata.RuntimeMetadataError, "case-collision"):
                metadata.observe_package(package, self.java_home, root)

    def test_archive_without_fixed_exporter_is_specific_blocker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package = root / "cryptad-v999.tar.gz"
            with package.open("wb") as destination, gzip.GzipFile(fileobj=destination, mode="wb", filename="", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w"):
                pass
            with self.assertRaisesRegex(metadata.RuntimeMetadataError, "packaged-exporter-unavailable"):
                metadata.observe_package(package, self.java_home, root)


class MetadataBoundaryTests(unittest.TestCase):
    def test_version_dispatch_preserves_v1_and_requires_v2_metadata_identity(self):
        from cryptad_certification.tests.test_stable_maintenance_workflows import _activation_candidate_freeze
        freeze = _activation_candidate_freeze("2026-09-10T00:00:00Z")
        original = metadata.canonical_bytes(freeze)
        self.assertEqual(metadata.validate_schema(freeze, metadata.maintenance.CANDIDATE_FREEZE_SCHEMA), [])
        prospective = dict(freeze, schemaVersion=2)
        prospective["predecessorObservation"] = dict(freeze["predecessorObservation"], sourceCommit="b" * 40)
        self.assertTrue(metadata.validate_schema(prospective, metadata.maintenance.CANDIDATE_FREEZE_SCHEMA))
        prospective["runtimeMetadata"] = {"fileName": "runtime-subjects.json", "digest": "sha256:" + "a" * 64, "sizeBytes": 2}
        self.assertEqual(metadata.validate_schema(prospective, metadata.maintenance.CANDIDATE_FREEZE_SCHEMA), [])
        self.assertTrue(metadata.validate_schema(prospective, "stable-1.0-maintenance-candidate-freeze-v1.schema.json"))
        prospective["runtimeMetadata"]["publicAsset"] = True
        self.assertTrue(metadata.validate_schema(prospective, metadata.maintenance.CANDIDATE_FREEZE_SCHEMA))
        self.assertEqual(metadata.canonical_bytes(freeze), original)

    def test_v1_is_not_reinterpreted_as_runtime_admission(self):
        with self.assertRaisesRegex(metadata.RuntimeMetadataError, "absent-historical"):
            metadata.validate_runtime_metadata({"schemaVersion": 1}, Path("unused"))

    def test_app_producer_rejects_shared_catalog_and_publisher_key_material(self):
        import maintenance_app_products as app_products
        environment = {"CRYPTAD_APP_SIGNING_KEY_ID": "publisher", "STABLE_CATALOG_SIGNING_KEY_ID": "catalog",
            "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64": "c3ludGhldGlj", "STABLE_CATALOG_SIGNING_PUBLIC_KEY_BASE64": "c3ludGhldGlj",
            "STABLE_CATALOG_SIGNING_PRIVATE_KEY_BASE64": "synthetic-unused"}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, environment):
            root = Path(directory).resolve()
            with self.assertRaisesRegex(metadata.RuntimeMetadataError, "signing-roles-overlap"):
                app_products.produce_app_products(root, root / "output", release_id="synthetic", build_version="999",
                    source_commit="a" * 40, include_mail=True, artifact_base="https://example.invalid/apps",
                    exporter=root / "unused", java_home=root / "unused-jdk")
            self.assertFalse((root / "output").exists())

    def test_private_acquisition_failure_has_only_fixed_diagnostic(self):
        with patch.object(metadata, "_produce_runtime_metadata", side_effect=FileNotFoundError("/private/secret-subject")):
            with self.assertRaises(metadata.RuntimeMetadataError) as failure:
                metadata.produce_runtime_metadata({}, Path("package"), Path("output"),
                    projection_origin={}, private_root=Path("scratch"))
            self.assertEqual(str(failure.exception), "runtime-metadata-production-failed")
            self.assertTrue(failure.exception.__suppress_context__)

    def test_duplicate_json_keys_reject(self):
        with self.assertRaises(metadata.RuntimeMetadataError):
            metadata.read_json(b'{"contractVersion":26,"contractVersion":26}')

    def test_symlinked_parent_rejects_even_when_subject_bytes_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original"
            original.mkdir()
            subject = original / "subject"
            subject.write_bytes(b"exact synthetic subject")
            alias = root / "alias"
            alias.symlink_to(original, target_is_directory=True)
            self.assertEqual(metadata.digest_bytes(b"exact synthetic subject"), metadata.identity(subject)["digest"])
            with self.assertRaisesRegex(metadata.RuntimeMetadataError, "input-link"):
                metadata.identity(alias / "subject")

    def test_member_hard_links_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original"
            original.write_bytes(b"subject")
            os.link(original, root / "alias")
            with self.assertRaisesRegex(metadata.RuntimeMetadataError, "input-unsafe"):
                metadata.identity(original)

    def test_role_cohorts_preserve_shipped_mail_distinction(self):
        self.assertNotIn("mail-prototype", metadata.FIRST_PARTY)
        roles = metadata.role_policy("current-eight-experimental-mail")
        self.assertEqual(roles["relay-no-apps"], [])
        self.assertEqual(roles["previous"], ["feed-reader", "site-publisher"])
        self.assertEqual(roles["candidate-sender"], ["feed-reader", "mail-prototype", "site-publisher"])
        self.assertNotIn("mail-prototype", metadata.role_policy("historical-seven")["candidate-sender"])


if __name__ == "__main__":
    unittest.main()
