"""Exercise the hosted freeze installation permissions without changing /etc."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import app_subject_projection as projection


class CohortInstallPermissionsTest(unittest.TestCase):
    def test_runner_can_read_root_owned_cohort_but_cannot_change_it(self):
        if sys.platform != "linux" or os.geteuid() == 0 or not shutil.which("sudo"):
            self.skipTest("requires a Linux unprivileged runner with passwordless sudo")
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode:
            self.skipTest("passwordless sudo unavailable")
        workflow = Path(__file__).resolve().parents[3] / ".github/workflows/stable-1.0-maintenance-release.yml"
        # Execute the real installation commands, changing only their destination to a test root.
        commands = [line.strip() for line in workflow.read_text().splitlines()
                    if line.strip().startswith("sudo install ")
                    and "/etc/cryptad-certification" in line]
        self.assertEqual(2, len(commands))
        fields = ("schemaVersion cohortPolicy releaseId sourceCommit authorityRoots toolRoot toolTreeDigest "
                  "toolOriginal toolMember exporterRelativePath javaHome javaTreeDigest sources").split()
        cohort = dict.fromkeys(fields, None)
        cohort.update(schemaVersion=1, cohortPolicy="historical-seven", releaseId="synthetic-permission-test")
        source_fields = ("appId original originalInventory catalogOriginal members catalogKeyId catalogKeys "
                         "catalogKeysDigest publisherKeys publisherKeysDigest reviewerKeys reviewerKeysDigest "
                         "sourceAuthorityRoot sourceEvidenceDigest requiredForRelease").split()
        cohort["sources"] = []
        for app in sorted(projection.FIRST_PARTY | {"synthetic-external"}):
            source = dict.fromkeys(source_fields, None)
            source.update(appId=app, requiredForRelease=True, original={"sourceFamily":
                "third-party-pilot" if app == "synthetic-external" else "first-party-release"})
            cohort["sources"].append(source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            prepared = root / "prepared.json"
            prepared.write_text(json.dumps(cohort))
            protected = root / "protected"
            installed = protected / "app-subject-cohort.json"
            script = "set -euo pipefail\n" + "\n".join(commands).replace(
                "/etc/cryptad-certification", '"$TEST_PROTECTED_ROOT"')
            try:
                subprocess.run(["bash", "-c", script], check=True, capture_output=True,
                               env={**os.environ, "prepared_cohort": str(prepared),
                                    "TEST_PROTECTED_ROOT": str(protected)})
                info = installed.stat()
                self.assertEqual(0, info.st_uid)
                self.assertEqual(os.getgid(), info.st_gid)
                self.assertEqual(0o640, stat.S_IMODE(info.st_mode))
                self.assertEqual(0, protected.stat().st_uid)
                with patch.object(projection, "COHORT_FILE", installed):
                    self.assertEqual(cohort, projection._cohort())
                with self.assertRaises(PermissionError):
                    installed.write_bytes(b"substitution")
                with self.assertRaises(PermissionError):
                    installed.unlink()
                outsider = subprocess.run(["sudo", "-n", "-u", "nobody", sys.executable, "-c",
                    "from pathlib import Path; import sys; "
                    "p=Path(sys.argv[1]); "
                    "sys.exit(0 if not __import__('os').access(p, __import__('os').R_OK) else 1)",
                    str(installed)], cwd=directory, capture_output=True)
                self.assertEqual(0, outsider.returncode, outsider.stderr.decode())
            finally:
                if installed.exists():
                    subprocess.run(["sudo", "-n", "rm", "--", str(installed)], check=True)
                if protected.exists():
                    subprocess.run(["sudo", "-n", "rmdir", "--", str(protected)], check=True)
