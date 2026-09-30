"""Bounded research scope and strict controller dispatch adversarial tests."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
from roles import researcher
from roles.research_execution import (ResearchExecutionError, run_research_action,
                                      run_research_command)
from roles.worker import RESEARCH_POLICY, WorkerBoundaryError, WorkerResult, run_worker
from roles import workspace


class ResearchExecutionTests(unittest.TestCase):
    def execute(self, code, *, timeout=3, limits=None):
        self._expected_policy = {**RESEARCH_POLICY, **(limits or {})}
        return run_worker([sys.executable, "-c", code], cwd=ROOT, timeout=timeout,
                          role="research:fixture", limits=limits, policy_profile="research")

    def assert_clean(self, result):
        self.assertEqual(result.evidence["cleanup_status"], "CONFIRMED")
        self.assertEqual(result.evidence["remaining_processes"], 0)
        self.assertEqual(result.evidence["cgroup_status"], "ENFORCED")
        expected = getattr(self, "_expected_policy", RESEARCH_POLICY)
        self.assertEqual(result.evidence["policy_sha256"], __import__("hashlib").sha256(
            json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest())

    def test_clean_normal_tool(self):
        result = run_research_action("dev_api", query="weather")
        self.assert_clean(result)
        self.assertEqual(result.returncode, 0)
        self.assertIsInstance(json.loads(result.stdout), dict)

    def test_infinite_research_tool(self):
        result = self.execute("while True: pass", timeout=2)
        self.assert_clean(result)
        self.assertTrue(result.evidence["timeout_triggered"])

    def test_ignored_sigterm(self):
        result = self.execute("import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True:time.sleep(.1)", timeout=2)
        self.assert_clean(result)
        self.assertTrue(result.evidence["forced_kill_used"])

    def test_child_survivor(self):
        code = ("import subprocess,sys,time\n"
                "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n"
                "time.sleep(.2)")
        result = self.execute(code)
        self.assert_clean(result)
        self.assertEqual(result.returncode, 0)

    def test_multilevel_tree(self):
        code = ("import subprocess,sys,time\n"
                "subprocess.Popen([sys.executable,'-c','import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,\"-c\",\"import time;time.sleep(60)\"]);"
                "time.sleep(60)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n"
                "while True:time.sleep(.1)")
        result = self.execute(code, timeout=2)
        self.assert_clean(result)
        self.assertTrue(result.evidence["timeout_triggered"])

    def test_stdout_flood(self):
        result = self.execute("import sys;sys.stdout.write('x'*1048576)",
                              limits={"max_output_bytes": 32768})
        self.assert_clean(result)
        self.assertTrue(result.evidence["output_truncated"])
        self.assertLess(len(result.stdout), 40000)

    def test_stderr_flood(self):
        result = self.execute("import sys;sys.stderr.write('x'*1048576)",
                              limits={"max_output_bytes": 32768})
        self.assert_clean(result)
        self.assertTrue(result.evidence["output_truncated"])
        self.assertLess(len(result.stdout), 40000)

    def test_memory_exhaustion(self):
        result = self.execute("chunks=[]\nwhile True:chunks.append(bytearray(16*1024*1024))",
                              timeout=5, limits={"memory_limit_bytes": 128 * 1024 * 1024})
        self.assert_clean(result)
        self.assertTrue(result.evidence["resource_hits"]["memory"])

    def test_process_explosion(self):
        code = ("import subprocess,sys,time\nchildren=[]\nfor _ in range(50):\n"
                " try:children.append(subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))\n except OSError:break\n")
        result = self.execute(code, limits={"max_processes": 8})
        self.assert_clean(result)
        self.assertTrue(result.evidence["resource_hits"]["process_count"])

    def test_network_namespace_is_inherited(self):
        before = Path("/proc/self/ns/net").readlink()
        result = self.execute("from pathlib import Path;print(Path('/proc/self/ns/net').readlink())")
        self.assert_clean(result)
        self.assertIn(str(before), result.stdout)

    def test_malformed_json_blocks_graph_role(self):
        fake = WorkerResult(0, "{bad", {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
        with patch.object(researcher, "run_research_command", return_value=fake):
            result = researcher.researcher_node({"needs_research": True, "research_type": "current_web",
                                                 "research_query": "weather", "task": "weather"})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["research_failure_kind"], "EXECUTION")

    def test_truncated_json_blocks_graph_role(self):
        fake = WorkerResult(1, '{"results":[]', {"cleanup_status": "CONFIRMED",
                             "remaining_processes": 0, "output_truncated": True})
        with patch.object(researcher, "run_research_command", return_value=fake):
            result = researcher.researcher_node({"needs_research": True, "research_type": "current_web",
                                                 "research_query": "weather", "task": "weather"})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["research_failure_kind"], "EXECUTION")

    def test_truncated_jina_document_blocks(self):
        fake = WorkerResult(1, "partial page", {"cleanup_status": "CONFIRMED",
                             "remaining_processes": 0, "output_truncated": True})
        with patch.object(researcher, "run_research_action", return_value=fake):
            with self.assertRaisesRegex(ResearchExecutionError, "RESEARCH_OUTPUT_TRUNCATED"):
                researcher._fetch_jina("https://example.com/docs")

    def test_cleanup_failure_blocks(self):
        failure = WorkerBoundaryError("WORKER_BOUNDARY_UNVERIFIED",
                                      {"cleanup_status": "UNPROVEN", "remaining_processes": 1})
        with patch("roles.research_execution.run_worker", side_effect=failure):
            result = researcher.researcher_node({"needs_research": True, "research_type": "current_web",
                                                 "research_query": "weather", "task": "weather"})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["research_failure_kind"], "EXECUTION")
        self.assertEqual(result["research_execution_history"][0]["evidence"]["remaining_processes"], 1)

    def test_arbitrary_executable_rejected(self):
        for command in (["/bin/sh", "-c", "true"], ["exa-intel", "q", "--limit", "99", "--json"],
                        ["curl", "https://example.com"]):
            with self.subTest(command=command), self.assertRaises(ResearchExecutionError):
                run_research_command(command)
        with self.assertRaises(ResearchExecutionError):
            run_research_action("shell", query="anything")

    def test_jina_dispatch_accepts_only_public_https(self):
        for url in ("file:///etc/passwd", "http://example.com", "https://localhost/a",
                    "https://127.0.0.1/a", "https://user:pass@example.com/a"):
            with self.subTest(url=url), self.assertRaises(ResearchExecutionError):
                run_research_action("jina", url=url)

    def test_research_budget_cannot_be_increased(self):
        with self.assertRaises(WorkerBoundaryError):
            self.execute("print('never')", limits={"memory_limit_bytes": RESEARCH_POLICY["memory_limit_bytes"] + 1})

    def test_exa_helper_nested_output_is_bounded(self):
        with tempfile.TemporaryDirectory(prefix="fake-mcporter-") as temp:
            fake = Path(temp) / "mcporter"
            fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdout.write('x'*3145728)\n")
            fake.chmod(0o700)
            env = {**os.environ, "PATH": temp + os.pathsep + os.environ.get("PATH", "")}
            result = subprocess.run([sys.executable, str(ROOT / "bin/exa-intel"), "weather", "--json"],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("EXA_OUTPUT_LIMIT", result.stderr)
            self.assertLess(len(result.stdout) + len(result.stderr), 1000)

    def test_exa_helper_normal_fixture(self):
        with tempfile.TemporaryDirectory(prefix="fake-mcporter-") as temp:
            fake = Path(temp) / "mcporter"
            fake.write_text("#!/usr/bin/env python3\nprint('Title: Weather docs')\n"
                            "print('URL: https://example.com/docs')\n"
                            "print('Published: 2026-01-01')\n"
                            "print('Highlights:')\n"
                            "print('Official weather reference details for integration.')\n")
            fake.chmod(0o700)
            env = {**os.environ, "PATH": temp + os.pathsep + os.environ.get("PATH", "")}
            result = subprocess.run([sys.executable, str(ROOT / "bin/exa-intel"), "weather", "--json"],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["count"], 1)

    def test_external_manifest_binds_research_policy(self):
        with tempfile.TemporaryDirectory(prefix="research-manifest-") as temp:
            repo = Path(temp) / "source"
            repo.mkdir()
            (repo / "app.py").write_text("value = 1\n")
            for args in (("init", "-q"), ("config", "user.name", "Fixture"),
                         ("config", "user.email", "fixture@example.invalid"), ("add", "."),
                         ("commit", "-qm", "fixture")):
                subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
            state = workspace.prepare_workspace_node({"repo_dir": str(repo)})
            self.addCleanup(__import__("shutil").rmtree, state["run_dir"], True)
            with patch.object(workspace, "RESEARCH_POLICY", {**RESEARCH_POLICY, "max_processes": 100}):
                with self.assertRaisesRegex(RuntimeError, "RESEARCH_RESOURCE_POLICY_CHANGED"):
                    workspace._load_verified_manifest(state)


if __name__ == "__main__":
    unittest.main()
