"""Real copied-runner tests; require the documented isolated dev fixture."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "orchestrator"))
from roles.workspace import test_discovery_count


class PytestReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get("FREEAGENT_PYTEST_FIXTURE_PYTHON")
        if not value:
            raise RuntimeError("PYTEST_DEVELOPMENT_FIXTURE_REQUIRED: see RPT1_VERIFICATION.md")
        cls.python = Path(value).absolute()
        if cls.python.is_relative_to(ROOT) or not cls.python.is_file():
            raise RuntimeError("PYTEST_FIXTURE_MUST_BE_EXTERNAL")
        result = subprocess.run([str(cls.python), "-c",
            "import sys,json,importlib.metadata as m; "
            "print(json.dumps({'prefix':sys.prefix,'base':sys.base_prefix,"
            "'versions':{n:m.version(n) for n in ['pytest','iniconfig','packaging','pluggy']}}))"],
            capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise RuntimeError("PYTEST_FIXTURE_UNAVAILABLE")
        identity = json.loads(result.stdout)
        if (identity["prefix"] == identity["base"] or
                Path(identity["prefix"]).is_relative_to(ROOT) or
                identity["versions"] != {"pytest":"8.3.5", "iniconfig":"2.0.0",
                                         "packaging":"24.2", "pluggy":"1.5.0"}):
            raise RuntimeError("PYTEST_FIXTURE_IDENTITY_MISMATCH")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-pytest-case-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.target.mkdir()
        self.script = self.root / "protected" / "freeagent-test"
        self.script.parent.mkdir()
        shutil.copyfile(ROOT / "bin/freeagent-test", self.script)
        self.env = {k:v for k,v in os.environ.items()
                    if not k.startswith("PYTEST") and k not in ("PYTHONPATH", "PYTHONHOME")}
        self.env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    def launch(self, budget=None):
        command = [str(self.python), str(self.script)]
        if budget is not None:
            # Existing run() injection seam: shorten this owned test's clock,
            # not production deadlines. detect/main still execute in subprocess.
            command = [str(self.python), "-c",
                "import runpy,sys; m=runpy.run_path(sys.argv[1]); "
                "m['run'].__globals__['TIMEOUT']=float(sys.argv[2]); "
                "sys.exit(m['main']())", str(self.script), str(budget)]
        return subprocess.run(command, cwd=self.target, env=self.env,
                              capture_output=True, text=True, timeout=20)

    def test_target_framework_markers_and_quiet_config(self):
        for marker, contents in (("pytest.ini", "[pytest]\naddopts = -q\n"),
                                ("pyproject.toml", "[tool.pytest.ini_options]\naddopts = '-q'\n"),
                                ("conftest.py", "# real pytest selection\n")):
            with self.subTest(marker=marker):
                for name in ("pytest.ini", "pyproject.toml", "conftest.py"):
                    (self.target / name).unlink(missing_ok=True)
                (self.target / marker).write_text(contents)
                (self.target / "orchestrator").mkdir(exist_ok=True)
                (self.target / "orchestrator/cli.py").write_text("# misleading marker\n")
                (self.target / "bin").mkdir(exist_ok=True)
                (self.target / "bin/freeagent-test").write_text("# misleading marker\n")
                (self.target / "test_named.py").write_text("def test_named_evidence():\n assert True\n")
                result = self.launch()
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn(" -m pytest -vv", result.stdout)
                self.assertIn("test_named.py::test_named_evidence PASSED", result.stdout)
                self.assertEqual(test_discovery_count(result.stdout), (1, "pytest"))
                self.assertIn("RESULT=PASS", result.stdout)

    def test_failure_error_skip_and_counts(self):
        (self.target / "pytest.ini").write_text("[pytest]\n")
        (self.target / "test_outcomes.py").write_text(
            "import pytest\n@pytest.fixture\ndef broken(): raise RuntimeError('SETUP_ERROR')\n"
            "def test_error(broken): pass\ndef test_failure(): assert False, 'FAILURE_DETAIL'\n"
            "def test_skip(): pytest.skip('EXPLICIT_SKIP')\ndef test_pass(): pass\n")
        result = self.launch()
        self.assertEqual(result.returncode, 1, result.stdout)
        for text in ("test_error ERROR", "test_failure FAILED", "test_skip SKIPPED",
                     "test_pass PASSED", "SETUP_ERROR", "FAILURE_DETAIL", "RESULT=FAIL"):
            self.assertIn(text, result.stdout)
        self.assertEqual(test_discovery_count(result.stdout), (4, "pytest"))

    def test_timeout_and_overflow_still_reject(self):
        (self.target / "pytest.ini").write_text("[pytest]\naddopts = -s\n")
        (self.target / "test_output.py").write_text("def test_output(): print('x' * 70000)\n")
        result = self.launch()
        self.assertEqual(result.returncode, 1)
        self.assertIn("OUTPUT_TRUNCATED=true", result.stdout)
        self.assertIn("RESULT=FAIL", result.stdout)
        (self.target / "test_output.py").write_text("def test_output():\n import time\n time.sleep(10)\n")
        result = self.launch(budget=0.5)
        self.assertEqual(result.returncode, 124)
        self.assertIn("RESULT=TIMEOUT", result.stdout)
        self.assertNotIn("RESULT=PASS", result.stdout)

    def test_copied_target_unittest_stays_verbose(self):
        (self.target / "test_named.py").write_text(
            "import unittest\nclass Named(unittest.TestCase):\n def test_named(self): pass\n")
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(" -m unittest discover -v", result.stdout)
        self.assertIn("test_named (test_named.Named.test_named) ... ok", result.stdout)

    def test_trusted_controller_pytest_stays_compact(self):
        self.target = self.root / "controller"
        self.target.mkdir()
        (self.target / "orchestrator").mkdir()
        (self.target / "orchestrator/cli.py").write_text("# owned controller layout fixture\n")
        self.script = self.target / "bin/freeagent-test"
        self.script.parent.mkdir()
        shutil.copyfile(ROOT / "bin/freeagent-test", self.script)
        subprocess.run([str(self.python), "-m", "venv", "--without-pip",
                        str(self.target / ".venv-orchestrator")], check=True,
                       capture_output=True, timeout=20)
        # Only this synthetic controller process receives the isolated packages.
        self.env["PYTHONPATH"] = str(self.python.parent.parent / "lib/python3.12/site-packages")
        (self.target / "pytest.ini").write_text("[pytest]\n")
        (self.target / "test_named.py").write_text("def test_named_evidence(): pass\n")
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(" -m pytest -q", result.stdout)
        self.assertNotIn("::test_named_evidence PASSED", result.stdout)
        self.assertEqual(test_discovery_count(result.stdout), (1, "pytest"))
