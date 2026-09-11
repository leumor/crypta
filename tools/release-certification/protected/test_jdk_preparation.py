"""Production preparation materializes approved JDK bytes without admitting linked trees."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

import app_subject_projection as projection
import maintenance_runtime_metadata as metadata


class JdkPreparationTest(unittest.TestCase):
    def installed_jdk(self, root):
        source = root / "installed"
        (source / "bin").mkdir(parents=True)
        (source / "legal/java.base").mkdir(parents=True)
        (source / "legal/java.compiler").mkdir()
        (source / "bin/java").write_bytes(b"synthetic executable\n")
        (source / "bin/java").chmod(0o755)
        (source / "legal/java.base/LICENSE").write_bytes(b"synthetic shared license\n")
        (source / "legal/java.compiler/LICENSE").symlink_to("../java.base/LICENSE")
        # Independently define the materialized identity, including both copies of the notice.
        rows = [[name, len(raw), executable, hashlib.sha256(raw).hexdigest()] for name, raw, executable in (
            ("bin/java", b"synthetic executable\n", True),
            ("legal/java.base/LICENSE", b"synthetic shared license\n", False),
            ("legal/java.compiler/LICENSE", b"synthetic shared license\n", False))]
        return source, "sha256:" + hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()

    def inputs(self, root, jdk_digest):
        tools = io.BytesIO()
        with zipfile.ZipFile(tools, "w") as archive:
            member = zipfile.ZipInfo("tool/bin/crypta-app")
            member.external_attr = 0o100755 << 16
            archive.writestr(member, b"synthetic tool")
        cohort = {"cohortPolicy": "historical-seven", "releaseId": "synthetic-preparation",
                  "sourceCommit": "a" * 40, "authorityRoots": {}, "sources": [],
                  "javaHome": "/selected/installation", "javaTreeDigest": jdk_digest,
                  "toolRoot": "/selected/tools", "toolTreeDigest": projection.tool_archive_digest(tools.getvalue()),
                  "toolOriginal": {"sourceFamily": "projection-tools"}, "toolMember": "tools.zip"}
        inputs = root / "inputs"
        inputs.mkdir()
        (inputs / "cohort.json").write_text(json.dumps(cohort))
        original = io.BytesIO()
        with zipfile.ZipFile(original, "w") as archive:
            archive.writestr("tools.zip", tools.getvalue())
        return inputs, cohort, SimpleNamespace(content=original.getvalue())

    def test_materialized_tree_matches_independent_identity_and_keeps_link_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, expected = self.installed_jdk(root)
            with self.assertRaisesRegex(projection.ProjectionFailure, "tree-link-invalid"):
                projection.tree_digest(source)
            staged = metadata.stage_jdk(source, root / "staged", expected)
            self.assertEqual(expected, projection.tree_digest(staged))
            self.assertTrue((source / "legal/java.compiler/LICENSE").is_symlink())
            self.assertFalse(any(p.is_symlink() for p in staged.rglob("*")))
            self.assertTrue(all(p.stat().st_nlink == 1 for p in staged.rglob("*") if p.is_file()))

    def test_actual_preparation_uses_staged_path_without_changing_approved_cohort(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, expected = self.installed_jdk(root)
            inputs, cohort, original = self.inputs(root, expected)
            with patch("original_artifact_authentication.authenticate_original", return_value=original), \
                    patch.object(projection, "authenticate_tool_tree") as attestation:
                metadata.prepare_environment(inputs, root / "prepared.json", source, root / "tools", root / "jdk")
            prepared = json.loads((root / "prepared.json").read_bytes())
            self.assertEqual(str(root / "jdk"), prepared["javaHome"])
            self.assertEqual(expected, projection.tree_digest(Path(prepared["javaHome"])))
            self.assertEqual(projection._public_cohort(cohort), projection._public_cohort(prepared))
            self.assertEqual(prepared, attestation.call_args.args[0])

    def test_unapproved_bytes_reject_before_online_authentication_and_remove_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, expected = self.installed_jdk(root)
            inputs, _, _ = self.inputs(root, expected)
            (source / "bin/java").write_bytes(b"changed executable")
            with patch("original_artifact_authentication.authenticate_original") as online:
                with self.assertRaisesRegex(metadata.RuntimeMetadataError, "approved-jdk-mismatch"):
                    metadata.prepare_environment(inputs, root / "prepared.json", source, root / "tools", root / "jdk")
                online.assert_not_called()
            self.assertFalse((root / "jdk").exists())
            self.assertFalse((root / "prepared.json").exists())

    def test_invalid_links_and_special_files_reject_without_partial_stage(self):
        for kind in ("dangling", "cycle", "external", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, expected = self.installed_jdk(root)
                extra = source / "extra"
                if kind == "fifo":
                    os.mkfifo(extra)
                else:
                    (root / "outside").write_text("not an installed JDK member")
                    extra.symlink_to({"dangling": "absent", "cycle": ".", "external": "../outside"}[kind])
                with self.assertRaises(metadata.RuntimeMetadataError):
                    metadata.stage_jdk(source, root / "staged", expected)
                self.assertFalse((root / "staged").exists())

    def test_existing_or_overlapping_stage_is_never_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, expected = self.installed_jdk(root)
            for destination in (source, source / "stage", root):
                with self.assertRaises(metadata.RuntimeMetadataError):
                    metadata.stage_jdk(source, destination, expected)
                self.assertTrue((source / "bin/java").is_file())
