"""Exercise the service Git identity lookup across real filesystem ownership boundaries."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import cross_version_runtime as runtime
import cross_version_service as service


class GitOwnershipTest(unittest.TestCase):
    def test_service_reads_only_the_selected_root_owned_checkout(self):
        if os.name != 'posix' or os.geteuid() == 0 or not shutil.which('sudo'):
            self.skipTest('requires an unprivileged test user with passwordless sudo for temporary ownership')
        available = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=10)
        if available.returncode:
            self.skipTest('passwordless sudo unavailable for the temporary root-owned checkout')
        source = Path(runtime.__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout, sibling, home = (root / name for name in ('checkout', 'sibling', 'service-home'))
            home.mkdir()
            environment = service.child_environment(home)
            environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
            # Local object sharing creates no network traffic and executes no checked-out hooks.
            subprocess.run(['git', 'clone', '--shared', '--no-checkout', str(source), str(checkout)],
                           env=environment, capture_output=True, check=True, timeout=30)
            subprocess.run(['git', 'init', str(sibling)], env=environment,
                           capture_output=True, check=True, timeout=10)
            expected = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout,
                                               env=environment, text=True, timeout=10).strip()
            try:
                subprocess.run(['sudo', '-n', 'chown', '-R', '0:0', str(checkout), str(sibling)],
                               check=True, capture_output=True, timeout=10)
                self.assertEqual(0, checkout.stat().st_uid)
                self.assertNotEqual(os.geteuid(), checkout.stat().st_uid)
                denied = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=checkout,
                                        env=environment, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(0, denied.returncode)
                self.assertIn('dubious ownership', denied.stderr)
                environment.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.directory", GIT_CONFIG_VALUE_0="*")
                execute = subprocess.check_output
                # Hashing helpers is unrelated to Git ownership; retain the actual identity
                # function and actual Git subprocess, selecting the temporary executing tree.
                with patch.dict(os.environ, environment, clear=True), patch.object(
                        runtime, '__file__', str(checkout / 'tools/interop/cross_version_runtime.py')), patch.object(
                        runtime, 'digest_file', return_value='sha256:' + 'a' * 64), patch.object(
                        runtime, 'runner_python_identity', return_value={}), patch.object(
                        runtime.subprocess, 'check_output', wraps=execute) as git:
                    identity = runtime.runner_identity()
                self.assertEqual(expected, identity['sourceCommit'])
                command = git.call_args.args[0]
                # Reusing the same command against a sibling must not trust that repository.
                other = subprocess.run(command, cwd=sibling, env=environment,
                                       capture_output=True, text=True, timeout=10)
                self.assertNotEqual(0, other.returncode)
                self.assertIn('dubious ownership', other.stderr)
                self.assertFalse((home / '.gitconfig').exists())
                self.assertEqual(0, checkout.stat().st_uid)
            finally:
                subprocess.run(['sudo', '-n', 'chown', '-R', f'{os.geteuid()}:{os.getegid()}',
                                str(checkout), str(sibling)], check=True, capture_output=True, timeout=10)
