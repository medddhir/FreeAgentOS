"""The user CLI must enter the real production graph and preserve its gates."""

import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
import cli
import graph
from roles import workspace


class TrustedEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-cli-test-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("def value():\n    return 1\n")
        (self.repo / "test_app.py").write_text(
            "import unittest\nfrom app import value\n"
            "class TestApp(unittest.TestCase):\n"
            "    def test_value(self):\n        self.assertEqual(value(), 2)\n")
        (self.repo / "note.txt").write_text("original\n")
        for args in (("init", "-q"), ("config", "user.name", "Fixture"),
                     ("config", "user.email", "fixture@example.invalid"), ("add", "."),
                     ("commit", "-qm", "fixture")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    @staticmethod
    def good(repo):
        (repo / "app.py").write_text("def value():\n    return 2\n")

    def invoke(self, coder=None, fixer=None, *, task="Implement value", plan=None,
               research=False, preflight_fail=False, worker_fail=False,
               sandbox_fail=False, flags=()):
        coder = coder or self.good
        plan = plan or {"needs_research": False, "research_type": "none",
                        "research_query": "", "steps": ["Implement value"]}
        review = {"verdict": "PASS", "issues": [], "summary": "Fixture review"}

        def make_code(state):
            coder(Path(state["repo_dir"]))
            return {"trace": ["coder:fixture"]}

        def make_fix(state):
            if fixer:
                fixer(Path(state["repo_dir"]))
            return {"fix_attempts": state.get("fix_attempts", 0) + 1,
                    "fixer_error": "", "trace": ["fixer:fixture"]}

        def fake_research(state):
            return {"research": "bounded fixture", "research_source": "fixture",
                    "research_results": 1, "research_error": "", "trace": ["researcher"]}

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("roles.planner._run_planner", return_value=plan))
            stack.enter_context(patch("roles.reviewer._run_reviewer", return_value=review))
            stack.enter_context(patch.object(graph, "coder_node", make_code))
            stack.enter_context(patch.object(graph, "fixer_node", make_fix))
            if research:
                stack.enter_context(patch.object(graph, "researcher_node", fake_research))
            if preflight_fail:
                stack.enter_context(patch.object(graph, "preflight_node", lambda state: {
                    "preflight_status": "BLOCKED", "preflight_error": "CGROUP_UNAVAILABLE",
                    "status": "BLOCKED", "trace": ["preflight:error"]}))
            if worker_fail:
                stack.enter_context(patch.object(graph, "coder_node", lambda state: {
                    "coder_error": "WORKER_BOUNDARY_UNVERIFIED", "status": "BLOCKED",
                    "trace": ["coder:boundary-error"]}))
            if sandbox_fail:
                stack.enter_context(patch("roles.tester.run_isolated", side_effect=RuntimeError("SANDBOX_UNAVAILABLE")))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = cli.main(["--repo", str(self.repo), "--task", task, "--json", *flags])
        result = json.loads(output.getvalue().strip())
        artifact = result.get("promotion_patch")
        if artifact:
            self.addCleanup(shutil.rmtree, str(Path(artifact).parent), True)
        return code, result

    def test_normal_task_matches_production_trace_and_patch(self):
        code, result = self.invoke()
        self.assertEqual((code, result["status"]), (0, "VERIFIED"))
        self.assertEqual(result["trace"][:6], ["workspace_prepare", "preflight", "baseline",
                                               "test_discovery_baseline", "inspector", "planner"])
        self.assertEqual(result["trace"][-2:], ["finalizer", "workspace_finish"])
        self.assertEqual(result["test_result"], "PASS")
        self.assertEqual(result["review_verdict"], "PASS")
        self.assertTrue(Path(result["promotion_patch"]).is_file())
        self.assertEqual((self.repo / "app.py").read_text(), "def value():\n    return 1\n")

    def test_self_repair_uses_one_fixer_attempt(self):
        code, result = self.invoke(coder=lambda repo: (repo / "app.py").write_text("def value():\n    return 3\n"),
                                   fixer=self.good)
        self.assertEqual((code, result["status"], result["fix_attempts"]), (0, "VERIFIED", 1))
        self.assertIn("fixer:fixture", result["trace"])

    def test_research_routes_through_inspector_and_validator(self):
        task = "Update Open-Meteo current API /v1/forecast with temperature_2m."
        plan = {"needs_research": True, "research_type": "api_reference",
                "research_query": "Open-Meteo current API /v1/forecast temperature_2m",
                "steps": ["Research", "Implement"]}
        code, result = self.invoke(task=task, plan=plan, research=True)
        self.assertEqual((code, result["status"]), (0, "VERIFIED"))
        self.assertIn("research_validation", result["trace"])
        self.assertIn("researcher", result["trace"])

    def test_fake_api_parameter_blocks(self):
        task = "Update Open-Meteo current API /v1/forecast using quantum_weather_mode."
        plan = {"needs_research": True, "research_type": "api_reference",
                "research_query": task, "steps": ["Research", "Implement"]}
        docs = ("API endpoint: https://api.open-meteo.com/v1/forecast\n"
                "| current | temperature_2m |\n| timezone | Set timezone=auto |\n")
        def transport(command):
            if command[0] == "dev-intel":
                return {"apis": [{"name": "Open-Meteo", "https": True,
                                  "url": "https://open-meteo.com/"}]}
            return {"results": [{"title": "Forecast docs", "url": "https://open-meteo.com/en/docs"}]}
        with patch("roles.researcher._run_json", side_effect=transport), \
                patch("roles.researcher._fetch_jina", return_value=docs):
            code, result = self.invoke(task=task, plan=plan)
        self.assertEqual((code, result["status"]), (2, "BLOCKED"))
        self.assertNotIn("coder:fixture", result["trace"])

    def test_hallucinated_provider_blocks(self):
        plan = {"needs_research": True, "research_type": "api_reference",
                "research_query": "Stripe current API docs", "steps": ["Research"]}
        code, result = self.invoke(task="Update the external payments API using current docs.", plan=plan)
        self.assertEqual((code, result["status"]), (2, "BLOCKED"))
        self.assertIn("research_validation:error", result["trace"])

    def test_protected_test_change_cannot_verify(self):
        code, result = self.invoke(coder=lambda repo: (repo / "test_app.py").write_text(
            "import unittest\nclass TestApp(unittest.TestCase):\n    def test_value(self): self.assertTrue(True)\n"))
        self.assertNotEqual(code, 0)
        self.assertNotEqual(result["status"], "VERIFIED")

    def test_unauthorized_new_file_cannot_verify(self):
        code, result = self.invoke(coder=lambda repo: (repo / "scratch.tmp").write_text("unauthorized"))
        self.assertNotEqual(code, 0)
        self.assertNotEqual(result["status"], "VERIFIED")
        self.assertFalse((self.repo / "scratch.tmp").exists())

    def test_unauthorized_delete_cannot_verify(self):
        code, result = self.invoke(coder=lambda repo: (repo / "note.txt").unlink())
        self.assertNotEqual(code, 0)
        self.assertNotEqual(result["status"], "VERIFIED")
        self.assertTrue((self.repo / "note.txt").exists())

    def test_preflight_failure_returns_blocked_exit(self):
        code, result = self.invoke(preflight_fail=True)
        self.assertEqual((code, result["status"]), (2, "BLOCKED"))
        self.assertNotIn("planner", result["trace"])

    def test_worker_boundary_failure_returns_blocked_exit(self):
        code, result = self.invoke(worker_fail=True)
        self.assertEqual((code, result["status"]), (2, "BLOCKED"))
        self.assertNotIn("tester", result["trace"])

    def test_target_sandbox_failure_returns_blocked_exit(self):
        code, result = self.invoke(sandbox_fail=True)
        self.assertEqual((code, result["status"]), (2, "BLOCKED"))
        self.assertIn("tester:isolation-error", result["trace"])

    def test_fixer_remains_bounded_to_two_attempts(self):
        code, result = self.invoke(coder=lambda repo: (repo / "app.py").write_text("def value():\n    return 3\n"))
        self.assertEqual(code, 1)
        self.assertEqual(result["fix_attempts"], 2)

    def test_json_unverified_contract(self):
        code, result = self.invoke(coder=lambda repo: (repo / "app.py").write_text("def value():\n    return 3\n"))
        self.assertEqual((code, result["status"]), (1, "UNVERIFIED"))
        self.assertEqual(result["test_result"], "FAIL")
        self.assertLess(len(json.dumps(result)), cli.MAX_JSON_BYTES)

    def test_invalid_input_and_bypass_flags(self):
        for flag in ("--no-sandbox", "--skip-tests", "--skip-review", "--disable-integrity",
                     "--unlimited", "--raw-shell", "--direct-claude"):
            with self.subTest(flag=flag):
                result = subprocess.run([str(ROOT / "bin/freeagent-run"), "--json", "--repo", str(self.repo),
                                         "--task", "Implement value", flag], capture_output=True, text=True,
                                        timeout=10)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(json.loads(result.stdout)["status"], "INVALID_INPUT")

    def test_help_and_disabled_direct_model_shortcut(self):
        help_result = subprocess.run([str(ROOT / "bin/freeagent-run"), "--help"],
                                     capture_output=True, text=True, timeout=10)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("production graph", help_result.stdout)
        shortcut = subprocess.run([str(ROOT / "bin/freeagent-code"), "-p", "unsafe"],
                                  capture_output=True, text=True, timeout=10)
        self.assertEqual(shortcut.returncode, 3)
        self.assertIn("retired", shortcut.stderr)

    def test_stale_recovery_only_removes_proven_empty_runs(self):
        root = Path(tempfile.gettempdir())
        owned = Path(tempfile.mkdtemp(prefix="freeagentos-run-", dir=root))
        unknown = Path(tempfile.mkdtemp(prefix="freeagentos-run-", dir=root))
        populated = Path(tempfile.mkdtemp(prefix="freeagentos-run-", dir=root))
        extra = Path(tempfile.mkdtemp(prefix="freeagentos-run-", dir=root))
        for path in (owned, unknown, populated, extra):
            self.addCleanup(shutil.rmtree, path, True)
            path.chmod(0o700)
        for path in (owned, populated, extra):
            control = path / "controller"
            control.mkdir(mode=0o700)
            workspace._owner_marker(control, path)
            marker = control / "owner.json"
            data = json.loads(marker.read_text())
            data.update(pid=99999999, process_birth="1")
            marker.write_text(json.dumps(data))
        (populated / "workspace").mkdir()
        (populated / "workspace" / "change.txt").write_text("unpromoted")
        (extra / "unknown.txt").write_text("user data")
        result = workspace.recover_stale_workspaces()
        self.assertGreaterEqual(result["cleaned"], 1)
        self.assertFalse(owned.exists())
        self.assertTrue(unknown.exists())
        self.assertTrue((populated / "workspace" / "change.txt").exists())
        self.assertTrue((extra / "unknown.txt").exists())

    def test_interruption_cleans_active_worker_and_workspace(self):
        harness = r'''
import json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import cli
from roles import workspace
from roles.worker import run_worker
class FixtureGraph:
    def invoke(self, state):
        prepared = workspace.prepare_workspace_node(state)
        Path(sys.argv[3]).write_text(prepared["run_dir"])
        child = "import time; from pathlib import Path; Path(%r).write_text(Path('/proc/self/status').read_text().split('NSpid:')[1].split()[0]); time.sleep(90)" % sys.argv[4]
        run_worker([sys.executable, "-c", child], role="coder", timeout=90)
        raise RuntimeError("fixture unexpectedly completed")
cli.graph.build_graph = lambda: FixtureGraph()
sys.exit(cli.main(["--json", "--repo", sys.argv[2], "--task", "fixture"]))
'''
        for signum, expected in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            with self.subTest(signal=signum):
                run_file = Path(self.temp.name) / f"run-{signum}.txt"
                pid_file = Path(self.temp.name) / f"pid-{signum}.txt"
                process = subprocess.Popen([sys.executable, "-c", harness,
                                            str(ROOT / "orchestrator"), str(self.repo),
                                            str(run_file), str(pid_file)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    initial_scopes = {path.name for path in Path("/sys/fs/cgroup").glob("freeagentos-worker-*")}
                    deadline = time.monotonic() + 15
                    while not pid_file.exists() and time.monotonic() < deadline and process.poll() is None:
                        time.sleep(0.05)
                    self.assertTrue(pid_file.exists(), "worker did not start")
                    target_pid = int(pid_file.read_text())
                    run_dir = Path(run_file.read_text())
                    process.send_signal(signum)
                    out, err = process.communicate(timeout=12)
                    self.assertEqual(process.returncode, expected, err[-1000:])
                    self.assertEqual(json.loads(out)["workspace_cleanup"], "CONFIRMED")
                    self.assertFalse(run_dir.exists())
                    status = Path(f"/proc/{target_pid}/stat")
                    self.assertTrue(not status.exists() or status.read_text().rsplit(")", 1)[1].split()[0] == "Z")
                    self.assertEqual({path.name for path in Path("/sys/fs/cgroup").glob("freeagentos-worker-*")},
                                     initial_scopes)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
