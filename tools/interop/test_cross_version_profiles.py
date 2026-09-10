"""Offline checks for exact-source profile execution; no release or network authority."""
import importlib.util
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('cross_version_profiles', Path(__file__).with_name('cross_version_profiles.py'))
profiles = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profiles)
ROOT = Path(__file__).resolve().parents[2]


class ProfileComparisonTest(unittest.TestCase):
    def test_source_requires_exact_commit_and_distinct_predecessor(self):
        for value in ('HEAD', 'develop', 'a' * 39, 'A' * 40, '../source'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                profiles.exact_commit(ROOT, value)
        head = profiles.git(ROOT, 'rev-parse', 'HEAD').decode().strip()
        with self.assertRaisesRegex(ValueError, 'source-alias'):
            profiles.compare(ROOT, head, head)

    def test_materialized_source_is_reopened_from_git_not_worktree(self):
        head = profiles.git(ROOT, 'rev-parse', 'HEAD').decode().strip()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'selected'
            identity = profiles.materialize(ROOT, head, destination)
            self.assertEqual(head, identity['commit'])
            self.assertEqual('local-git-source-comparison', identity['identityClass'])
            for short, source in profiles.SOURCES.items():
                data = profiles.git(ROOT, 'show', head + ':' + source)
                self.assertEqual(data, (destination / short).read_bytes())

    def test_real_adapter_observes_changed_selected_producer(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node is required for actual JavaScript adapter execution')
        head = profiles.git(ROOT, 'rev-parse', 'HEAD').decode().strip()
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            # Two current copies are an offline adapter test, never an historical comparison.
            profiles.materialize(ROOT, head, private / 'one')
            profiles.materialize(ROOT, head, private / 'two')
            command = [node, str(Path(__file__).with_name('cross_version_profiles.cjs')),
                       str(private / 'one'), str(private / 'two'), str(ROOT / profiles.CORPUS)]
            env = {'PATH': os.defpath, 'LANG': 'C.UTF-8'}
            passed = subprocess.run(command, capture_output=True, timeout=120, env=env)
            self.assertEqual(0, passed.returncode, passed.stderr.decode())
            selected = private / 'one' / 'feed.js'
            original = selected.read_text()
            marker = 'function buildPublishedSnapshot(form, entry) {'
            self.assertIn(marker, original)
            selected.write_text(original.replace(marker, marker + '\n throw new Error("synthetic producer failure");', 1))
            failed = subprocess.run(command, capture_output=True, timeout=120, env=env)
            self.assertEqual(1, failed.returncode)
            self.assertEqual(b'', failed.stdout)
            self.assertEqual(b'profile-comparison-failed\n', failed.stderr)


if __name__ == '__main__':
    unittest.main()
