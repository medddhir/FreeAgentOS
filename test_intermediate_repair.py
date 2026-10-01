"""Stage 1.8: real isolated tests and synthetic model boundaries only."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "orchestrator"))
import graph
from roles import fixer, planner
from roles.coding_units import validate_planner_units
from roles.file_tools import FileTools
from roles.read_policy import ReadDenied, validate_policy
from roles.intermediate_repair import repair_checkpoint, safe_intermediate
from roles.worker import WorkerResult


class IntermediateRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-intermediate-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.write_values(self.repo, 9)
        (self.repo / "api.py").write_text("from domain import values\ndef value(i): return values[i]\n")
        (self.repo / "other.py").write_text("value = 1\n")
        (self.repo / "test_api.py").write_text(
            "import unittest\nfrom api import value\nclass Values(unittest.TestCase):\n" +
            "".join(f"    def test_{i}(self): self.assertEqual(value({i}), 1)\n" for i in range(10)))
        for args in (("init", "-q"), ("add", "."), ("-c", "user.name=Fixture", "-c",
                     "user.email=fixture@example.invalid", "commit", "-qm", "baseline")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    @staticmethod
    def write_values(repo, failures):
        (repo / "domain.py").write_text("values = " + repr([0] * failures + [1] * (10 - failures)) + "\n")

    def invoke(self, coder_failures, repairs=(), repair_hook=None, coder_hook=None, unit_targets=None):
        calls = []
        units = [{"goal": "Implement domain/API behavior together",
                  "target_files": unit_targets[i] if unit_targets else ["domain.py", "api.py"]}
                 for i, _ in enumerate(coder_failures)]
        plan = {"needs_research": False, "research_type": "none", "research_query": "",
                "steps": ["Inspect requirements", "Implement domain and consumers together", "Verify behavior"],
                "coding_units": units}
        counts = iter(coder_failures)
        repair_counts = iter(repairs)
        snapshots = []

        def code(state):
            calls.append("coder")
            self.write_values(Path(state["repo_dir"]), next(counts))
            if coder_hook:
                coder_hook(state)
            return {"trace": ["coder:fixture"]}

        def repair(state):
            calls.append("fixer")
            snapshots.append(dict(state))
            if repair_hook:
                result = repair_hook(state)
                if result is not None:
                    return result
            self.write_values(Path(state["repo_dir"]), next(repair_counts))
            return {"fix_attempts": state.get("fix_attempts", 0) + 1,
                    "fixer_error": "", "trace": ["fixer:fixture"]}

        def review(state):
            calls.append("reviewer")
            self.assertIsNone(graph.machine_verification_error(state))
            return {"review_verdict": "PASS", "review_issues": [], "trace": ["reviewer"]}

        with patch.object(planner, "_run_planner", return_value=plan), \
                patch.object(graph, "coder_node", code), patch.object(graph, "fixer_node", repair), \
                patch.object(graph, "reviewer_node", review):
            result = graph.build_graph().invoke({"repo_dir": str(self.repo), "task": "Complete domain/API behavior",
                                                 "trace": []})
        self.assertEqual((self.repo / "domain.py").read_text(), "values = " + repr([0] * 9 + [1]) + "\n")
        return result, calls, snapshots

    def test_improvement_continues(self):
        result, calls, _ = self.invoke([6, 0])
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(calls, ["coder", "coder", "reviewer"])
        self.assertEqual([r["test_failures_after"] for r in result["unit_history"]], [6, 0])

    def test_equal_continues(self):
        result, calls, _ = self.invoke([9, 0])
        self.assertEqual(result["status"], "VERIFIED")
        self.assertNotIn("fixer", calls)

    def test_regression_repaired_to_improvement(self):
        result, calls, _ = self.invoke([10, 0], [8])
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(calls, ["coder", "fixer", "coder", "reviewer"])
        self.assertEqual([r["test_failures_after"] for r in result["unit_history"]], [10, 8, 0])
        self.assertEqual(result["unit_history"][1]["phase"], "repair")
        self.assertEqual(result["unit_history"][1]["test_failures_before"], 10)
        self.assertEqual(result["intermediate_repair"]["failures_before_unit"], 9)

    def test_regression_repaired_to_equality(self):
        result, calls, _ = self.invoke([10, 0], [9])
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(calls.count("fixer"), 1)

    def test_unrecovered_regression_blocks(self):
        result, calls, _ = self.invoke([10, 0], [10])
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(calls, ["coder", "fixer"])
        self.assertEqual(result["intermediate_repair"]["status"], "FAILED")

    def test_further_regression_blocks(self):
        def broken(state):
            # Eleven errors are structurally simulated in the checkpoint tests;
            # this real test produces import errors instead of a usable summary.
            Path(state["repo_dir"], "domain.py").write_text("raise RuntimeError('invalid implementation')\n")
            return {"fix_attempts": state.get("fix_attempts", 0) + 1, "fixer_error": "", "trace": ["fixer"]}
        result, calls, _ = self.invoke([10, 0], repair_hook=broken)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(calls, ["coder", "fixer"])

    def test_timeout_blocks_without_next_unit(self):
        def timeout(state):
            return {"fix_attempts": state.get("fix_attempts", 0) + 1, "fixer_error": "FIXER_TIMEOUT",
                    "status": "BLOCKED", "trace": ["fixer:fixture"]}
        result, calls, _ = self.invoke([10, 0], repair_hook=timeout)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(calls, ["coder", "fixer"])
        self.assertEqual(result["fixer_error"], "FIXER_TIMEOUT")

    def test_global_budget_shared_with_final_repairs(self):
        result, calls, _ = self.invoke([10, 1], [8, 0])
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(calls, ["coder", "fixer", "coder", "fixer", "reviewer"])
        self.assertEqual(result["fix_attempts"], 2)

    def test_no_third_attempt(self):
        result, calls, _ = self.invoke([10, 1], [8, 1])
        self.assertNotEqual(result["status"], "VERIFIED")
        self.assertEqual(calls.count("fixer"), 2)
        self.assertNotIn("reviewer", calls)

    def test_previous_unit_is_preserved(self):
        def code(state):
            if state["unit_index"] == 0:
                with Path(state["repo_dir"], "api.py").open("a") as stream:
                    stream.write("# earlier verified unit\n")
        def repair(state):
            self.assertIn("# earlier verified unit", Path(state["repo_dir"], "api.py").read_text())
        result, calls, snapshots = self.invoke([6, 10, 0], [5], coder_hook=code, repair_hook=repair,
                                               unit_targets=[["domain.py", "api.py"], ["domain.py"], ["domain.py"]])
        self.assertIn("earlier verified unit", Path(result["verified_patch_path"]).read_text())
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(calls.count("reviewer"), 1)
        self.assertEqual(snapshots[0]["unit_history"][0]["test_failures_after"], 6)
        self.assertEqual([r["test_failures_after"] for r in result["unit_history"]], [6, 10, 5, 0])

    def test_real_fixer_context_and_policy_are_current_and_unit_scoped(self):
        def real_repair(state):
            def worker(command, **kwargs):
                prompt = command[-1]
                self.assertIn("failures_before_unit", prompt)
                self.assertIn("values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]", prompt)
                self.assertIn("CURRENT implementation unit", prompt)
                config = json.loads(command[command.index("--mcp-config") + 1])
                args = config["mcpServers"]["freeagent_files"]["args"]
                self.assertEqual(hashlib.sha256(args[2].encode()).hexdigest(), args[3])
                policy = validate_policy(json.loads(args[2]))
                self.assertEqual(set(policy["write_files"]), {"domain.py", "api.py"})
                tools = FileTools(policy)
                tools.call("read_file", {"path": "test_api.py"})
                with self.assertRaises(ReadDenied):
                    tools.call("write_file", {"path": "other.py", "text": "value = 1\n"})
                with self.assertRaises(ReadDenied):
                    tools.call("write_file", {"path": "test_api.py", "text": "# replaced"})
                for path in (".env", "../private", "orchestrator/state.py", "new.py"):
                    with self.assertRaises(ReadDenied):
                        tools.call("read_file", {"path": path})
                    with self.assertRaises(ReadDenied):
                        tools.call("write_file", {"path": path, "text": "value = 1\n"})
                self.write_values(Path(state["repo_dir"]), 8)
                self.assertEqual(kwargs["timeout"], 180)
                return WorkerResult(0, "MODEL_WORKER_COMPLETED", {})
            with patch.object(fixer, "run_worker", side_effect=worker):
                return fixer.fixer_node(state)
        result, calls, _ = self.invoke([10, 0], repair_hook=real_repair)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(calls.count("fixer"), 1)

    def test_unauthorized_repair_paths_block(self):
        for path in ("test_api.py", "pyproject.toml", "other.py", "new.py"):
            with self.subTest(path=path):
                def unauthorized(state):
                    Path(state["repo_dir"], path).write_text("value = 2\n")
                    return {"fix_attempts": 1, "fixer_error": "", "trace": ["fixer"]}
                result, calls, _ = self.invoke([10, 0], repair_hook=unauthorized)
                self.assertEqual(result["status"], "BLOCKED")
                self.assertEqual(calls, ["coder", "fixer"])

    def test_unauthorized_deletion_blocks(self):
        def deletion(state):
            Path(state["repo_dir"], "api.py").unlink()
            return {"fix_attempts": 1, "fixer_error": "", "trace": ["fixer"]}
        result, calls, _ = self.invoke([10, 0], repair_hook=deletion)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(calls, ["coder", "fixer"])

    def test_direct_fixer_attempt_cap_remains(self):
        with patch.object(fixer, "run_worker") as worker:
            result = fixer.fixer_node({"fix_attempts": 2})
        self.assertEqual(result["status"], "BLOCKED")
        worker.assert_not_called()

    def test_explicit_further_failure_count_blocks(self):
        import test_stage1_hardening as fixture
        holder = fixture.StageOneHardeningTests()
        holder.setUp()
        try:
            before = {**holder.state, "unit_index": 0, "unit_gate_status": "READY",
                      "unit_failure_before": 9, "unit_history": []}
            def tested(count):
                return {"test_result": "FAIL", "test_exit": 1, "diff_check_exit": 0,
                        "test_output": f"Ran 12 tests in 0.1s\nFAILED (failures={count})",
                        "integrity_violations": before["integrity_violations"], "changed_files": [],
                        "workspace_test_attestation": before["workspace_test_attestation"]}
            pending = graph.tested_unit_node(before, lambda _: tested(10))
            self.assertEqual(pending["unit_gate_status"], "REPAIR_REQUIRED")
            repaired = graph.tested_unit_node({**before, **pending, "fix_attempts": 1}, lambda _: tested(11))
            self.assertEqual(repaired["status"], "BLOCKED")
            self.assertEqual(repaired["intermediate_repair"]["failures_after_intermediate_fix"], 11)
            exhausted = graph.tested_unit_node({**before, "fix_attempts": 2}, lambda _: tested(10))
            self.assertEqual(exhausted["status"], "BLOCKED")
        finally:
            holder.doCleanups()

    def test_planner_prompt_requires_test_coherence_without_extra_call(self):
        valid = {"needs_research": False, "research_type": "none", "research_query": "",
                 "steps": ["Implement coupled domain/API behavior"],
                 "coding_units": [{"goal": "Implement coupled domain/API behavior",
                                   "target_files": ["domain.py", "api.py"]}]}
        evidence = {"cleanup_status": "CONFIRMED", "remaining_processes": 0,
                    "timeout_triggered": False, "output_truncated": False}
        with patch.object(planner, "run_worker", return_value=WorkerResult(0, json.dumps(valid), evidence)) as worker:
            planner._run_planner("Implement coupled domain/API behavior", "Python repository")
        self.assertEqual(worker.call_count, 1)
        prompt = worker.call_args.args[0][-1]
        for guidance in ("test-coherent", "not one-file-per-unit", "tightly coupled", "prerequisites before dependents"):
            self.assertIn(guidance, prompt)

    def test_final_verification_rejects_incomplete_repair(self):
        import test_stage1_hardening as fixture
        holder = fixture.StageOneHardeningTests()
        holder.setUp()
        try:
            with patch("roles.reviewer._run_reviewer") as model:
                for value in ({"status": "PENDING"}, {"status": "FAILED"}, {"status": "RECOVERED"}):
                    state = {**holder.state, "intermediate_repair": value}
                    self.assertIsNotNone(graph.machine_verification_error(state))
                    self.assertNotEqual(graph.finalizer_node(state)["status"], "VERIFIED")
                    from roles.reviewer import reviewer_node
                    self.assertEqual(reviewer_node(state)["review_verdict"], "FAIL")
                model.assert_not_called()
        finally:
            holder.doCleanups()

    def test_safe_diagnostics(self):
        result = safe_intermediate({"status": "PENDING", "fix_attempts_before": 0,
                                   "failures_before_unit": 9, "failures_after_coder": 10,
                                   "raw": "fake-secret /host/private"}, 1, True)
        self.assertEqual(result["intermediate_fix_result"], "FAILED")
        self.assertNotIn("fake-secret", json.dumps(result))
        self.assertEqual(result["global_fix_attempts"], 1)

    def test_invalid_checkpoint_fails_closed(self):
        for state in ({}, {"intermediate_repair": {"status": "PENDING"}},
                      {"intermediate_repair": {"status": "PENDING", "raw": "fake-secret"}}):
            with self.assertRaisesRegex(ValueError, "^INTERMEDIATE_REPAIR_STATE_INVALID$"):
                repair_checkpoint(state)

    def test_planner_coherent_fixture_bounds(self):
        steps = ["Inspect current contracts", "Implement domain and consumers", "Verify tests"]
        fixtures = [
            [{"goal": "Fix arithmetic behavior", "target_files": ["domain.py"]}],
            [{"goal": "Implement coupled domain/API behavior", "target_files": ["domain.py", "api.py"]}],
            [{"goal": "Implement coherent domain behavior", "target_files": ["domain.py"]},
             {"goal": "Implement interface output", "target_files": ["api.py"]}],
            [{"goal": "Implement foundation contracts", "target_files": ["domain.py"]},
             {"goal": "Implement core behavior", "target_files": ["domain.py", "api.py"]},
             {"goal": "Implement interface output", "target_files": ["api.py"]}],
        ]
        for units in fixtures:
            self.assertEqual(len(validate_planner_units(steps, units)), len(units))
        # Inspection-only file slices remain invalid, even with valid targets.
        with self.assertRaises(ValueError):
            validate_planner_units(steps, [{"goal": "Read domain.py", "target_files": ["domain.py"]},
                                           {"goal": "Read api.py", "target_files": ["api.py"]}])


if __name__ == "__main__":
    unittest.main()
