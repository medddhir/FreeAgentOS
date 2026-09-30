"""The trusted self-runner and copied target runner select their own runtimes."""

import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).parent
RUNNER = ROOT / "bin" / "freeagent-test"


class FreeagentTestRuntimeTests(unittest.TestCase):
    def setUp(self):
        runner = runpy.run_path(str(RUNNER))
        self.bootstrap = runner["bootstrap_controller_runtime"]
        self.detect = runner["detect"]
        self.globals = self.bootstrap.__globals__

    def test_system_python_reexecs_to_controller_venv(self):
        target = str(ROOT / ".venv-orchestrator" / "bin" / "python3")
        with patch.object(sys, "executable", "/usr/bin/python3"), \
                patch.dict(os.environ, {}, clear=False), \
                patch.object(os, "execv") as execv:
            os.environ.pop("FREEAGENT_TEST_BOOTSTRAP_ATTEMPTED", None)
            self.bootstrap()
            execv.assert_called_once_with(target, [target, str(RUNNER), *sys.argv[1:]])
            self.assertEqual(os.environ["FREEAGENT_TEST_BOOTSTRAP_ATTEMPTED"], "1")

    def test_shell_launch_hands_off_from_system_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "orchestrator").mkdir()
            (root / "orchestrator" / "cli.py").write_text("# controller marker\n")
            copied = root / "bin" / "freeagent-test"
            shutil.copyfile(RUNNER, copied)
            interpreter = root / ".venv-orchestrator" / "bin" / "python3"
            interpreter.parent.mkdir(parents=True)
            interpreter.write_text("#!/bin/sh\nprintf 'BOOTSTRAPPED\\n'\n")
            interpreter.chmod(0o755)
            result = subprocess.run(["/usr/bin/python3", str(copied)], cwd=root,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "BOOTSTRAPPED\n")

    def test_symlinked_venv_launch_runs_tests_with_venv_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "orchestrator").mkdir()
            (root / "orchestrator" / "cli.py").write_text("# controller marker\n")
            shutil.copyfile(RUNNER, root / "bin" / "freeagent-test")
            venv = root / ".venv-orchestrator"
            subprocess.run(["/usr/bin/python3", "-m", "venv", "--without-pip", str(venv)],
                           check=True, capture_output=True, timeout=20)
            interpreter = venv / "bin" / "python3"
            self.assertTrue(interpreter.is_symlink())
            (root / "test_runtime.py").write_text(
                "import sys, unittest\n"
                "class RuntimeTest(unittest.TestCase):\n"
                " def test_interpreter(self):\n"
                f"  self.assertEqual(sys.executable, {str(interpreter)!r})\n"
                f"  self.assertEqual(sys.prefix, {str(venv)!r})\n"
            )
            result = subprocess.run(["/usr/bin/python3", str(root / "bin" / "freeagent-test")],
                                    cwd=root, capture_output=True, text=True, timeout=15,
                                    env={key: value for key, value in os.environ.items()
                                         if key != "FREEAGENT_TEST_BOOTSTRAP_ATTEMPTED"})
            self.assertEqual(result.returncode, 0, result.stdout[-500:] + result.stderr[-500:])
            self.assertIn("RESULT=PASS", result.stdout)
            self.assertIn("COMMAND=" + str(interpreter) + " -m unittest discover -v", result.stdout)

    def test_shell_launch_missing_venv_fails_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "orchestrator").mkdir()
            (root / "orchestrator" / "cli.py").write_text("# controller marker\n")
            copied = root / "bin" / "freeagent-test"
            shutil.copyfile(RUNNER, copied)
            result = subprocess.run(["/usr/bin/python3", str(copied)], cwd=root,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 4)
            self.assertIn("ORCHESTRATOR_RUNTIME_UNAVAILABLE", result.stderr)
            self.assertNotIn("COMMAND=", result.stdout)

    def test_shell_launch_unusable_venv_fails_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "orchestrator").mkdir()
            (root / "orchestrator" / "cli.py").write_text("# controller marker\n")
            copied = root / "bin" / "freeagent-test"
            shutil.copyfile(RUNNER, copied)
            interpreter = root / ".venv-orchestrator" / "bin" / "python3"
            interpreter.parent.mkdir(parents=True)
            interpreter.write_text("not executable\n")
            result = subprocess.run(["/usr/bin/python3", str(copied)], cwd=root,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 4)
            self.assertIn("ORCHESTRATOR_RUNTIME_EXEC_FAILED", result.stderr)

    def test_venv_python_does_not_reexec(self):
        with patch.object(sys, "executable", str(self.globals["CONTROLLER_PYTHON"])), \
                patch.object(sys, "prefix", str(self.globals["CONTROLLER_VENV"])), \
                patch.dict(os.environ, {"FREEAGENT_TEST_BOOTSTRAP_ATTEMPTED": "1"}), \
                patch.object(os, "execv") as execv:
            self.bootstrap()
            execv.assert_not_called()
            self.assertNotIn("FREEAGENT_TEST_BOOTSTRAP_ATTEMPTED", os.environ)

    def test_failed_reexec_cannot_loop(self):
        with patch.object(sys, "executable", "/usr/bin/python3"), \
                patch.dict(os.environ, {"FREEAGENT_TEST_BOOTSTRAP_ATTEMPTED": "1"}), \
                patch.object(os, "execv") as execv:
            with self.assertRaisesRegex(RuntimeError, "ORCHESTRATOR_RUNTIME_REEXEC_LOOP"):
                self.bootstrap()
            execv.assert_not_called()

    def test_missing_controller_venv_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(self.globals, {"CONTROLLER_PYTHON": Path(directory) / "missing"}):
                with self.assertRaisesRegex(RuntimeError, "ORCHESTRATOR_RUNTIME_UNAVAILABLE"):
                    self.bootstrap()

    def test_copied_target_runner_does_not_require_controller_venv(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "controller" / "freeagent-test"
            with patch.dict(self.globals, {"SCRIPT": copied,
                                           "CONTROLLER_ROOT": copied.parents[1]}), \
                    patch.object(os, "execv") as execv:
                self.bootstrap()
                execv.assert_not_called()

    def test_unittest_uses_current_interpreter(self):
        self.assertEqual(self.detect(), ([sys.executable, "-m", "unittest", "discover", "-v"],
                                         "python-unittest"))

    def test_pytest_uses_current_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "pytest.ini").write_text("[pytest]\n")
            with patch.dict(self.globals, {"ROOT": repo}):
                self.assertEqual(self.detect(), ([sys.executable, "-m", "pytest", "-q"],
                                                 "pytest"))

    def test_node_runner_is_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text('{"scripts":{"test":"node test.js"}}')
            with patch.dict(self.globals, {"ROOT": repo}), \
                    patch.object(self.globals["shutil"], "which", return_value="/usr/bin/npm"):
                self.assertEqual(self.detect(), (["npm", "test", "--", "--runInBand"], "npm-test"))


if __name__ == "__main__":
    unittest.main()
