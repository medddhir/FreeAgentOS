"""The trusted self-runner and copied target runner select their own runtimes."""

import ast
import contextlib
import io
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import tokenize
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
            self.assertIn("COMMAND=" + str(interpreter) + " -m unittest discover\n", result.stdout)
            self.assertNotIn("test_interpreter (", result.stdout)

    def test_copied_target_reports_executed_names_despite_project_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / 'controller'
            target = root / 'target'
            control.mkdir(); target.mkdir()
            copied = control / 'freeagent-test'
            shutil.copyfile(RUNNER, copied)
            # Project markers cannot impersonate the script's controller layout.
            (target / 'orchestrator').mkdir()
            (target / 'orchestrator' / 'cli.py').write_text('# untrusted marker\n')
            (target / 'pyproject.toml').write_text('unittest_reporting = "compact"\n')
            (target / 'test_named.py').write_text(
                'import unittest\nclass Named(unittest.TestCase):\n'
                ' def test_execution_evidence(self): self.assertTrue(True)\n')
            result = subprocess.run([sys.executable, str(copied)], cwd=target,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout[-500:])
            self.assertIn(' -m unittest discover -v', result.stdout)
            self.assertIn('test_execution_evidence (test_named.Named.test_execution_evidence) ... ok',
                          result.stdout)
            self.assertIn('RESULT=PASS', result.stdout)

    def test_controller_entrypoint_in_target_directory_preserves_names(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'test_named.py').write_text(
                'import unittest\nclass Named(unittest.TestCase):\n'
                ' def test_execution_evidence(self): self.assertTrue(True)\n')
            result = subprocess.run([str(RUNNER)], cwd=target,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout[-500:])
            self.assertIn('COMMAND=' + str(ROOT / '.venv-orchestrator/bin/python3') +
                          ' -m unittest discover -v', result.stdout)
            self.assertIn('test_execution_evidence (test_named.Named.test_execution_evidence) ... ok',
                          result.stdout)


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
        self.assertEqual(self.detect(), ([sys.executable, "-m", "unittest", "discover"],
                                         "python-unittest"))

    def test_pytest_uses_current_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "pytest.ini").write_text("[pytest]\n")
            with patch.dict(self.globals, {"ROOT": repo}):
                self.assertEqual(self.detect(), ([sys.executable, "-m", "pytest", "-vv"],
                                                 "pytest"))

    def test_pytest_markers_cannot_select_controller_reporting(self):
        for marker, content in (("pytest.ini", "[pytest]\naddopts = -q\n"),
                                ("conftest.py", "# pytest configuration\n"),
                                ("pyproject.toml", "[tool.pytest.ini_options]\naddopts = '-q'\n")):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)
                (target / marker).write_text(content)
                (target / "orchestrator").mkdir()
                (target / "orchestrator" / "cli.py").write_text("# misleading controller marker\n")
                (target / "bin").mkdir()
                (target / "bin" / "freeagent-test").write_text("# misleading runner marker\n")
                with patch.dict(self.globals, {"ROOT": target}):
                    self.assertEqual(self.detect(),
                                     ([sys.executable, "-m", "pytest", "-vv"], "pytest"))
                copied = target / "protected" / "freeagent-test"
                with patch.dict(self.globals, {"ROOT": target, "SCRIPT": copied,
                                               "CONTROLLER_ROOT": copied.parents[1]}):
                    self.assertEqual(self.detect(),
                                     ([sys.executable, "-m", "pytest", "-vv"], "pytest"))

    def test_pytest_controller_reporting_remains_compact(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = Path(directory)
            (controller / "pytest.ini").write_text("[pytest]\n")
            (controller / "orchestrator").mkdir()
            (controller / "orchestrator" / "cli.py").write_text("# trusted layout fixture\n")
            with patch.dict(self.globals, {"ROOT": controller, "CONTROLLER_ROOT": controller,
                                           "SCRIPT": controller / "bin" / "freeagent-test"}):
                self.assertEqual(self.detect(),
                                 ([sys.executable, "-m", "pytest", "-q"], "pytest"))

    def test_node_runner_is_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text('{"scripts":{"test":"node test.js"}}')
            with patch.dict(self.globals, {"ROOT": repo}), \
                    patch.object(self.globals["shutil"], "which", return_value="/usr/bin/npm"):
                self.assertEqual(self.detect(), (["npm", "test", "--", "--runInBand"], "npm-test"))

    def test_budget(self):
        self.assertEqual(self.globals["TIMEOUT"], 600)
        self.assertEqual(self.globals["MAX_CAPTURE"], 64 * 1024)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(Path, "cwd", return_value=Path(directory)):
            self.assertEqual(runpy.run_path(str(RUNNER))["TIMEOUT"], 180)

        def constant(filename, name):
            tree = ast.parse((ROOT / "orchestrator" / "roles" / filename).read_text())
            return next(ast.literal_eval(node.value) for node in tree.body
                        if isinstance(node, ast.Assign) and any(
                            isinstance(target, ast.Name) and target.id == name
                            for target in node.targets))

        self.assertEqual(constant("coder.py", "CODER_TIMEOUT"), 180)
        self.assertEqual(constant("fixer.py", "FIXER_TIMEOUT"), 180)
        for name, value in (("BASE_SECONDS", 180), ("GRACE_SECONDS", 60),
                            ("HARD_SECONDS", 240), ("RECENT_SECONDS", 30)):
            self.assertEqual(constant("lease.py", name), value)
        for path in (ROOT / "orchestrator" / "roles").glob("*.py"):
            with self.subTest(production_module=path.name):
                # Octal file mode 0o644 also equals 420 numerically; it is not
                # a reference to the decimal full-suite wall-clock budget.
                tokens = tokenize.generate_tokens(io.StringIO(path.read_text()).readline)
                self.assertFalse(any(token.type == tokenize.NUMBER and token.string == "420"
                                     for token in tokens))

        cases = [("print('SUITE_COMPLETE')", 5, 0, "PASS"),
                 ("raise SystemExit(7)", 5, 7, "FAIL"),
                 ("print('x' * 65537)", 5, 1, "FAIL"),
                 ("import time; time.sleep(10)", 0.02, 124, "TIMEOUT")]
        for code, budget, expected_exit, expected_result in cases:
            with self.subTest(result=expected_result), \
                    patch.dict(self.globals, {"TIMEOUT": budget}), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                result = self.globals["run"]([sys.executable, "-c", code], "fixture")
            self.assertEqual(result, expected_exit)
            text = output.getvalue()
            self.assertIn("RESULT=" + expected_result, text)
            self.assertIn("EXIT_CODE=" + str(expected_exit), text)
            if expected_result == "PASS":
                self.assertLess(text.index("SUITE_COMPLETE"), text.index("RESULT=PASS"))
            else:
                self.assertNotIn("RESULT=PASS", text)
            if '65537' in code:
                self.assertIn("OUTPUT_TRUNCATED=true", text)

    def test_budget_selection_uses_controller_context_not_project_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'orchestrator').mkdir()
            (target / 'orchestrator' / 'cli.py').write_text('# misleading marker\n')
            (target / 'bin').mkdir()
            (target / 'bin' / 'freeagent-test').write_text('# misleading marker\n')
            (target / 'pytest.ini').write_text('[pytest]\n')
            (target / 'pyproject.toml').write_text('controller_timeout = 600\n')
            control = target / 'protected'
            control.mkdir()
            copied = control / 'freeagent-test'
            shutil.copyfile(RUNNER, copied)
            with patch.dict(os.environ, {'FREEAGENT_TEST_TIMEOUT': '600',
                                         'FREEAGENT_CONTROLLER_TIMEOUT': '600'}), \
                    patch.object(sys, 'argv', [str(copied), '--timeout', '600']), \
                    patch.object(Path, 'cwd', return_value=target):
                # A real controller entrypoint used from a target keeps 180s.
                self.assertEqual(runpy.run_path(str(RUNNER))['TIMEOUT'], 180)
                # This copied runner's parent-derived root equals cwd, but its
                # protected location is not the trusted bin/ entrypoint layout.
                self.assertEqual(runpy.run_path(str(copied))['TIMEOUT'], 180)
            with patch.object(Path, 'cwd', return_value=control):
                self.assertEqual(runpy.run_path(str(copied))['TIMEOUT'], 180)
        with patch.object(Path, 'cwd', return_value=ROOT):
            self.assertEqual(runpy.run_path(str(RUNNER))['TIMEOUT'], 600)


if __name__ == "__main__":
    unittest.main()

class ControllerShutdownTimingTests(unittest.TestCase):
    def execute(self, source, limit=2, broken=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            runner = runpy.run_path(str(RUNNER))
            function = runner['run']; values = function.__globals__
            output = io.StringIO()
            with patch.dict(values, {'TIMEOUT': limit}), \
                    patch.dict(os.environ, {'FREEAGENT_CONTROLLER_PROGRESS_DIR': str(root)}), \
                    contextlib.redirect_stdout(output):
                if broken:
                    class Broken:
                        def __init__(self, directory): pass
                        def record(self, *args): raise OSError('not published')
                        def close(self): raise OSError('not published')
                    with patch.object(runpy, 'run_path', return_value={'RunnerTiming': Broken}):
                        code = function([sys.executable, '-c', source], 'synthetic')
                else:
                    code = function([sys.executable, '-c', source], 'synthetic')
            import json
            path = root / 'runner-timing.jsonl'
            rows = [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
            self.assertLessEqual(len(rows), 32)
            if path.exists():
                self.assertLessEqual(path.stat().st_size, 32768)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            return code, output.getvalue(), rows

    def test_normal_exit_and_eof_before_exit(self):
        code, output, rows = self.execute('import os,time; os.close(1); os.close(2); time.sleep(.05)')
        self.assertEqual(code, 0); self.assertIn('RESULT=PASS', output)
        events = [x['event'] for x in rows]
        self.assertLess(events.index('STDOUT_EOF'), events.index('CHILD_EXIT_OBSERVED'))
        self.assertLess(events.index('WAIT_COMPLETE'), events.index('RUNNER_CLASSIFIED'))
        self.assertEqual(events.count('CHILD_EXIT_OBSERVED'), 1)
        self.assertIsInstance(rows[0]['identity'], float)
        self.assertTrue(all(a['monotonic_ns'] <= b['monotonic_ns'] for a,b in zip(rows, rows[1:])))

    def test_exit_after_deadline_still_times_out_and_reaps(self):
        code, output, rows = self.execute('import time; time.sleep(2)', limit=.05)
        self.assertEqual(code, 124); self.assertIn('RESULT=TIMEOUT', output)
        events = [x['event'] for x in rows]
        self.assertLess(events.index('TIMEOUT_DECISION'), events.index('SIGTERM_ATTEMPT'))
        self.assertLess(events.index('SIGTERM_ATTEMPT'), events.index('WAIT_COMPLETE'))
        self.assertEqual(rows[-1]['identity'], 124)

    def test_diagnostic_failure_preserves_failure_classification(self):
        code, output, rows = self.execute('raise SystemExit(7)', broken=True)
        self.assertEqual(code, 7); self.assertIn('RESULT=FAIL', output)
        self.assertNotIn('not published', output)
        self.assertEqual(rows, [])

    def test_termination_escalation_is_observed_without_changing_timeout(self):
        code, output, rows = self.execute(
            'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(3)',
            limit=.2)
        self.assertEqual(code, 124)
        self.assertIn('RESULT=TIMEOUT', output)
        events = [x['event'] for x in rows]
        self.assertLess(events.index('SIGTERM_ATTEMPT'), events.index('SIGKILL_ATTEMPT'))
        self.assertLess(events.index('SIGKILL_ATTEMPT'), events.index('WAIT_COMPLETE'))

    def test_foreign_context_cannot_activate_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            runner = runpy.run_path(str(RUNNER)); function = runner['run']
            with patch.dict(function.__globals__, {'ROOT': root}), \
                    patch.dict(os.environ, {'FREEAGENT_CONTROLLER_PROGRESS_DIR': str(root)}), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(function([sys.executable, '-c', 'pass'], 'synthetic'), 0)
            self.assertFalse((root / 'runner-timing.jsonl').exists())
