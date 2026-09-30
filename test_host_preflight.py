"""Deterministic capability and production graph preflight checks."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
import graph
from roles import preflight
from roles.workspace import _load_verified_manifest, prepare_workspace_node


class HostPreflightTests(unittest.TestCase):
    def supported(self):
        return {name: "SUPPORTED" for name in preflight.REQUIRED} | {"pidfd_optional": "SUPPORTED"}

    @staticmethod
    def good_probe():
        return {"isolated": True, "result": "PASS", "evidence": {
            "cleanup_status": "CONFIRMED", "remaining_processes": 0, "cgroup_status": "ENFORCED",
            "controls": {name: "ENFORCED" for name in preflight.REQUIRED_CONTROLS}}}

    def evaluate(self, overrides=None, probe=None, worker_probe=None):
        capabilities = self.supported()
        capabilities.update(overrides or {})
        worker_probe = worker_probe or type("Worker", (), {"returncode": 0,
            "evidence": {"cleanup_status": "CONFIRMED", "remaining_processes": 0,
                         "cgroup_status": "ENFORCED"}})()
        with patch.object(preflight, "_static_capabilities", return_value=capabilities), \
                patch.object(preflight, "_probe_sandbox", return_value=self.good_probe() if probe is None else probe), \
                patch.object(preflight, "_probe_worker", return_value=worker_probe):
            return preflight.check_host()

    def test_missing_cgroup_v2_blocks(self):
        self.assertIn("cgroup_v2", self.evaluate({"cgroup_v2": "UNSUPPORTED"})["required_failures"])

    def test_missing_memory_controller_blocks(self):
        self.assertIn("memory_controller", self.evaluate({"memory_controller": "UNSUPPORTED"})["required_failures"])

    def test_missing_pids_controller_blocks(self):
        self.assertIn("pids_controller", self.evaluate({"pids_controller": "UNSUPPORTED"})["required_failures"])

    def test_missing_network_namespace_blocks(self):
        result = self.evaluate(probe={**self.good_probe(), "isolated": False})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("sandbox_boundary", result["required_failures"])

    def test_missing_cgroup_kill_blocks(self):
        result = self.evaluate(probe={**self.good_probe(), "evidence": {
            **self.good_probe()["evidence"], "cgroup_status": "UNAVAILABLE"}})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("cgroup_kill", result["required_failures"])

    def test_failed_probe_cleanup_blocks(self):
        evidence = {**self.good_probe()["evidence"], "cleanup_status": "UNPROVEN", "remaining_processes": 1}
        result = self.evaluate(probe={**self.good_probe(), "evidence": evidence})
        self.assertEqual(result["status"], "BLOCKED")

    def test_worker_scope_unavailable_blocks(self):
        failed = type("Worker", (), {"returncode": 125, "evidence": {"cleanup_status": "UNPROVEN"}})()
        result = self.evaluate(worker_probe=failed)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("worker_scope", result["required_failures"])

    def test_required_supported_passes(self):
        self.assertEqual(self.evaluate()["status"], "PASS")

    def test_optional_missing_is_reported_without_blocking(self):
        result = self.evaluate({"pidfd_optional": "UNSUPPORTED"})
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["optional_failures"], ["pidfd_optional"])

    def test_actual_host_probe_passes(self):
        result = preflight.check_host()
        self.assertEqual(result["status"], "PASS", result)

    def test_graph_blocks_before_model_and_tests_on_failed_preflight(self):
        with tempfile.TemporaryDirectory(prefix="preflight-graph-") as temp:
            repo = Path(temp) / "source"
            repo.mkdir()
            (repo / "app.py").write_text("value = 1\n")
            for args in (("init", "-q"), ("config", "user.name", "Fixture"),
                         ("config", "user.email", "fixture@example.invalid"), ("add", "."),
                         ("commit", "-qm", "fixture")):
                subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
            blocked = {"status": "BLOCKED", "capabilities": {"cgroup_v2": "UNSUPPORTED"},
                       "required_failures": ["cgroup_v2"], "optional_failures": [], "error": "unavailable"}
            with patch.object(preflight, "check_host", return_value=blocked):
                result = graph.build_graph().invoke({"repo_dir": str(repo), "task": "Update app", "trace": []})
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["trace"][:2], ["workspace_prepare", "preflight:error"])
            self.assertNotIn("planner", result["trace"])
            self.assertNotIn("tester", result["trace"])

    def test_external_preflight_evidence_is_attested(self):
        with tempfile.TemporaryDirectory(prefix="preflight-attest-") as temp:
            repo = Path(temp) / "source"
            repo.mkdir()
            (repo / "app.py").write_text("value = 1\n")
            for args in (("init", "-q"), ("config", "user.name", "Fixture"),
                         ("config", "user.email", "fixture@example.invalid"), ("add", "."),
                         ("commit", "-qm", "fixture")):
                subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
            state = prepare_workspace_node({"repo_dir": str(repo)})
            self.addCleanup(lambda: shutil.rmtree(state["run_dir"], ignore_errors=True))
            with patch.object(preflight, "check_host", return_value={"status": "PASS", "capabilities": self.supported(),
                    "required_failures": [], "optional_failures": [], "error": ""}):
                result = preflight.preflight_node(state)
            self.assertEqual(result["preflight_status"], "PASS")
            combined = {**state, **result}
            self.assertEqual(_load_verified_manifest(combined)["source_repo"], str(repo))
            (Path(state["run_dir"]) / "controller" / "preflight.json").write_text("{}")
            with self.assertRaisesRegex(RuntimeError, "PREFLIGHT_EVIDENCE_CHANGED"):
                _load_verified_manifest(combined)


if __name__ == "__main__":
    unittest.main()
