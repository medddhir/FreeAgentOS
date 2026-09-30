"""Fixed Git controller utility output and cleanup bounds."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
from roles.controller_git import ControllerGitError, run_git


class ControllerGitTests(unittest.TestCase):
    def test_normal_git_metadata_is_bounded_and_cleaned(self):
        result = run_git(["--version"], cwd=ROOT)
        self.assertEqual(result.returncode, 0)
        self.assertLess(len(result.stdout), result.evidence["output_limit_bytes"])
        self.assertEqual(result.evidence["cleanup_status"], "CONFIRMED")
        self.assertEqual(result.evidence["remaining_processes"], 0)

    def test_large_git_output_blocks_during_stream(self):
        with tempfile.TemporaryDirectory(prefix="controller-git-") as temp:
            repo = Path(temp)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            (repo / "big.txt").write_text("x" * 100000)
            subprocess.run(["git", "add", "big.txt"], cwd=repo, check=True)
            subprocess.run(["git", "-c", "user.name=Fixture", "-c",
                            "user.email=fixture@example.invalid", "commit", "-qm", "fixture"],
                           cwd=repo, check=True)
            with self.assertRaisesRegex(ControllerGitError, "OUTPUT_LIMIT"):
                run_git(["show", "HEAD:big.txt"], cwd=repo, max_output=4096)

    def test_controller_git_request_rejects_non_string_arguments(self):
        with self.assertRaisesRegex(ControllerGitError, "REQUEST_INVALID"):
            run_git(["status", 1], cwd=ROOT)


if __name__ == "__main__":
    unittest.main()
