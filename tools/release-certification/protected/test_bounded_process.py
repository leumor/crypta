import os
import sys
import time
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bounded_process import run


class BoundedProcessTest(unittest.TestCase):
    def test_stdout_limit_terminates_only_created_helper(self):
        with self.assertRaisesRegex(ValueError, "output_exceeded"):
            run([sys.executable, "-c", "import os; os.write(1, b'x' * 65536)"],
                environment={"PATH": "/usr/bin:/bin"}, output_limit=1024)

    def test_stdin_not_consumed_cannot_block_deadline(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "deadline_exceeded"):
            run([sys.executable, "-c", "import time; time.sleep(60)"],
                environment={"PATH": "/usr/bin:/bin"}, payload=b"x" * 16384, timeout=0.15)
        self.assertLess(time.monotonic() - started, 3)

    def test_exited_leader_with_descendant_pipes_still_hits_deadline(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "deadline_exceeded"):
            run([sys.executable, "-c", "import os,time; child=os.fork(); time.sleep(60) if child == 0 else os._exit(0)"],
                environment={"PATH": "/usr/bin:/bin"}, timeout=0.15)
        self.assertLess(time.monotonic() - started, 3)

    def test_environment_is_the_closed_selected_environment(self):
        output = run([sys.executable, "-c", "import os; print(sorted(os.environ))"],
                     environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        self.assertNotIn(b"TOKEN", output)
        self.assertNotIn(b"HOME", output)


if __name__ == "__main__": unittest.main()
