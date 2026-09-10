"""Real local Git rehearsals for the bounded synthetic maintenance train driver."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from cryptad_certification import maintenance_drill_train as train


class MaintenanceDrillTrainTest(unittest.TestCase):
    def test_real_cherry_pick_conflict_resolution_and_accounting_execute_and_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            calls = []
            actual_run = subprocess.run
            def observed_run(arguments, **kwargs):
                calls.append(tuple(arguments))
                return actual_run(arguments, **kwargs)
            with mock.patch.object(train.subprocess, "run", side_effect=observed_run):
                result = train.execute(root)
            self.assertEqual(list(train.CASES), result)
            self.assertEqual([], list(root.iterdir()))
            self.assertTrue(any("cherry-pick" in call and "--continue" in call for call in calls))
            self.assertEqual(3, sum(call[0] == "python3" for call in calls))
            self.assertFalse(any("push" in call or "fetch" in call or "config" in call for call in calls))

    def test_ambient_git_repository_and_configuration_cannot_redirect_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.dict(os.environ, {
                "GIT_DIR": str(root / "absent-object-database"),
                "GIT_WORK_TREE": str(root / "absent-worktree"),
                "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath",
                "GIT_CONFIG_VALUE_0": str(root / "absent-hooks"),
            }):
                self.assertEqual(list(train.CASES), train.execute(root))
            self.assertEqual([], list(root.iterdir()))

    def test_failed_regression_removes_only_owned_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            unrelated = root / "keep.txt"
            unrelated.write_bytes(b"existing-owned-parent-file")
            with mock.patch.object(train.ScratchGit, "regression", side_effect=ValueError("synthetic-regression")):
                with self.assertRaisesRegex(ValueError, "synthetic-regression"):
                    train.execute(root)
            self.assertEqual([unrelated], list(root.iterdir()))
            self.assertEqual(b"existing-owned-parent-file", unrelated.read_bytes())

    def test_symlink_backed_parent_denied_and_mutation_command_budget_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "root-invalid"):
                train.execute(alias)
            repository = root / "scratch"
            repository.mkdir()
            git = train.ScratchGit(repository)
            with self.assertRaisesRegex(ValueError, "scratch-root-must-be-empty"):
                train.ScratchGit(repository)
            with self.assertRaisesRegex(ValueError, "operation-denied"):
                git.run("fetch", "https://unapproved.invalid")
            git.calls = 64
            with self.assertRaisesRegex(ValueError, "budget"):
                git.run("status", "--porcelain")


if __name__ == "__main__":
    unittest.main()
