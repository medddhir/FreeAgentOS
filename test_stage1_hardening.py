"""Adversarial controller checks for Stage 1 unit routing and final verification."""

import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))

import graph
from roles import fixer, reviewer
from roles.sandbox import REQUIRED_CONTROLS


def clean_violations():
    return {key: [] for key in ("protected", "verification", "untracked", "new", "deleted", "all")}


class StageOneHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-stage1-guard-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.units = [{"id": "unit-1", "goal": "first", "files": []},
                      {"id": "unit-2", "goal": "second", "files": []}]
        self.state = {
            "repo_dir": str(self.repo), "run_workspace": str(self.repo), "preflight_status": "PASS",
            "test_result": "PASS", "test_exit": 0, "diff_check_exit": 0,
            "integrity_violations": clean_violations(),
            "workspace_test_attestation": {"status": "PASS", "baseline_status": "ATTESTED",
                                            "baseline_count": 3, "final_count": 3,
                                            "count_not_reduced": True, "isolated": True,
                                            "framework": "unittest"},
            "sandbox_evidence": {"cleanup_status": "CONFIRMED", "remaining_processes": 0,
                                 "cgroup_status": "ENFORCED", "timeout_triggered": False,
                                 "output_truncated": False, "resource_hits": {},
                                 "controls": {name: "ENFORCED" for name in REQUIRED_CONTROLS}},
            "coding_units": self.units, "unit_index": 2, "unit_gate_status": "FINAL",
            "unit_history": [{"unit_id": "unit-1", "unit_index": 1, "test_result_after": "FAIL"},
                             {"unit_id": "unit-2", "unit_index": 2, "test_result_after": "PASS"}],
            "review_verdict": "PASS", "fix_attempts": 0,
        }

    def invoke_mocked_production_graph(self, test_results, *, rollback_blocks=False):
        """Exercise production edges with deterministic nodes and no host sandbox."""
        events = []
        results = iter(test_results)

        def node(name, values):
            def run(_state):
                events.append(name)
                return {**values, "trace": [name]}
            return run

        def coder(_state):
            events.append("coder")
            return {"trace": ["coder"]}

        def tester(_state):
            events.append("tester")
            return {"test_result": "FAIL", "test_exit": 1, "diff_check_exit": 0,
                    "changed_files": [], "integrity_violations": clean_violations(),
                    "workspace_test_attestation": self.state["workspace_test_attestation"],
                    "sandbox_evidence": self.state["sandbox_evidence"],
                    **next(results), "trace": ["tester"]}

        def repair(state):
            events.append("fixer")
            return {"fix_attempts": state.get("fix_attempts", 0) + 1,
                    "fixer_error": "", "trace": ["fixer"]}

        def rollback(_state):
            events.append("rollback")
            return {**({"status": "BLOCKED"} if rollback_blocks else {}),
                    "trace": ["rollback"]}

        def finish(state):
            events.append("finalizer")
            return {"status": "BLOCKED" if state.get("status") == "BLOCKED" else "UNVERIFIED",
                    "trace": ["finalizer"]}

        replacements = {
            "prepare_workspace_node": node("workspace_prepare", {}),
            "preflight_node": node("preflight", {"preflight_status": "PASS"}),
            "baseline_node": node("baseline", {}),
            "discovery_baseline_node": node("test_discovery_baseline", {}),
            "inspector_node": node("inspector", {}),
            "planner_node": node("planner", {"plan_steps": ["a", "b", "c"], "needs_research": False}),
            "derive_units_node": node("unit_derivation", {"coding_units": self.units,
                                                           "unit_index": 0, "unit_failure_before": 2,
                                                           "unit_gate_status": "READY"}),
            "research_validation_node": node("research_validation", {"research_validation_passed": True}),
            "coder_node": coder, "tester_node": tester,
            "rollback_node": rollback, "fixer_node": repair,
            "reviewer_node": node("reviewer", {"review_verdict": "PASS"}),
            "finalizer_node": finish,
        }
        with ExitStack() as stack:
            for name, replacement in replacements.items():
                stack.enter_context(patch.object(graph, name, replacement))
            result = graph.build_graph().invoke({**self.state, "unit_history": [],
                                                 "fix_attempts": 0, "trace": []})
        return result, events

    def test_clean_final_machine_evidence_can_reach_one_reviewer(self):
        self.assertIsNone(reviewer.machine_verification_error(self.state))
        with patch.object(reviewer, "verify_execution_contract"), \
                patch.object(reviewer, "_run_reviewer", return_value={
                    "verdict": "PASS", "issues": [], "summary": "Fixture review"}) as worker:
            result = reviewer.reviewer_node(self.state)
        self.assertEqual(result["review_verdict"], "PASS")
        self.assertEqual(worker.call_count, 1)

    def test_intermediate_pass_with_integrity_violation_routes_to_rollback(self):
        violation = clean_violations()
        violation["protected"] = ["test_app.py"]
        violation["all"] = ["test_app.py"]
        before = {**self.state, "unit_index": 0, "unit_gate_status": "READY",
                  "unit_failure_before": 2, "unit_history": []}
        result = graph.tested_unit_node(before, lambda _: {
            "test_result": "PASS", "test_exit": 0, "diff_check_exit": 0,
            "integrity_violations": violation, "changed_files": [],
            "workspace_test_attestation": before["workspace_test_attestation"],
            "trace": ["tester"]})
        self.assertEqual(result["unit_gate_status"], "INTEGRITY_OR_SANDBOX_FAILURE")
        self.assertEqual(graph.route_after_tester({**before, **result}), "rollback")
        with patch.object(reviewer, "_run_reviewer") as worker:
            rejected = reviewer.reviewer_node({**before, **result})
        worker.assert_not_called()
        self.assertEqual(rejected["review_verdict"], "FAIL")

    def test_production_graph_never_reviews_or_codes_after_intermediate_integrity_pass(self):
        violation = {**clean_violations(), "protected": ["test_app.py"], "all": ["test_app.py"]}
        result, events = self.invoke_mocked_production_graph(
            [{"test_result": "PASS", "test_exit": 0, "integrity_violations": violation}],
            rollback_blocks=True)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(events.count("coder"), 1)
        self.assertEqual(events.count("reviewer"), 0)
        self.assertEqual(events[-3:], ["tester", "rollback", "finalizer"])

    def test_production_graph_fixer_limit_is_global_across_units(self):
        violation = {**clean_violations(), "protected": ["test_app.py"], "all": ["test_app.py"]}
        failed = lambda count: {"test_output": f"Ran 3 tests in 0.1s\nFAILED (failures={count})"}
        result, events = self.invoke_mocked_production_graph([
            {**failed(2), "integrity_violations": violation}, failed(2), failed(1), failed(1)])
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["fix_attempts"], 2)
        self.assertEqual(events.count("coder"), 2)
        self.assertEqual(events.count("tester"), 4)
        self.assertEqual(events.count("fixer"), 2)
        self.assertEqual(events.count("reviewer"), 0)

    def test_intermediate_failure_gate_decrease_same_increase_and_missing(self):
        before = {**self.state, "unit_index": 0, "unit_gate_status": "READY",
                  "unit_failure_before": 2, "unit_history": []}
        for count, gate, status in ((1, "CONTINUE", None), (2, "CONTINUE", None),
                                    (3, "REPAIR_REQUIRED", None), (None, "BLOCKED", "BLOCKED")):
            output = (f"Ran 3 tests in 0.1s\nFAILED (failures={count})" if count is not None
                      else "no structured test summary")
            result = graph.tested_unit_node(before, lambda _, value=output: {
                "test_result": "FAIL", "test_exit": 1, "test_output": value,
                "diff_check_exit": 0, "integrity_violations": clean_violations(),
                "changed_files": [], "workspace_test_attestation": before["workspace_test_attestation"]})
            self.assertEqual(result["unit_gate_status"], gate)
            self.assertEqual(result.get("status"), status)

    def test_tester_error_exception_exit_125_and_diff_failure_block(self):
        before = {**self.state, "unit_index": 0, "unit_gate_status": "READY",
                  "unit_failure_before": 2, "unit_history": []}
        clean = {"test_result": "FAIL", "test_exit": 1,
                 "test_output": "Ran 3 tests in 0.1s\nFAILED (failures=1)",
                 "diff_check_exit": 0, "integrity_violations": clean_violations(),
                 "changed_files": [], "workspace_test_attestation": before["workspace_test_attestation"]}
        for update in ({"tester_error": "RUNNER_FAILED"}, {"test_exit": 125},
                       {"diff_check_exit": 2}):
            result = graph.tested_unit_node(before, lambda _, change=update: {**clean, **change})
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(graph.route_after_tester({**before, **result}), "finalizer")
        result = graph.tested_unit_node(before, lambda _: (_ for _ in ()).throw(RuntimeError("private detail")))
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["tester_error"], "TESTER_EXCEPTION:RuntimeError")
        self.assertNotIn("private detail", str(result))

    def test_reviewer_rejects_machine_failures_before_model_call(self):
        cases = [
            {"tester_error": "FAIL"}, {"workspace_integrity_error": "FAIL"},
            {"diff_check_exit": 2}, {"test_result": "FAIL"}, {"test_exit": 125},
            {"workspace_test_attestation": {**self.state["workspace_test_attestation"], "status": "FAIL"}},
            {"sandbox_evidence": {**self.state["sandbox_evidence"], "cleanup_status": "UNCERTAIN"}},
            {"repo_dir": "/nonexistent"}, {"protected_files_changed": ["test_app.py"]},
            {"verification_files_changed": ["orchestrator/roles/tester.py"]},
            {"integrity_violations": {**clean_violations(), "new": ["scratch.py"]}},
            {"integrity_violations": {**clean_violations(), "deleted": ["app.py"]}},
        ]
        with patch.object(reviewer, "_run_reviewer") as worker:
            for update in cases:
                with self.subTest(update=update):
                    result = reviewer.reviewer_node({**self.state, **update})
                    self.assertEqual(result["review_verdict"], "FAIL")
        worker.assert_not_called()

    def test_finalizer_rejects_partial_or_forged_unit_state(self):
        cases = [
            {"unit_index": 1}, {"coding_units": [{"id": f"unit-{i}"} for i in range(1, 5)]},
            {"unit_history": self.state["unit_history"][:1]}, {"unit_gate_status": "CONTINUE"},
            {"tester_error": "FAIL"}, {"diff_check_exit": 2},
            {"workspace_test_attestation": {**self.state["workspace_test_attestation"], "status": "FAIL"}},
            {"review_verdict": "FAIL"}, {"test_result": "FAIL"},
            {"sandbox_evidence": {}}, {"integrity_violations": {**clean_violations(), "all": ["x"]}},
            {"coding_units": []}, {"unit_history": []},
        ]
        with patch("roles.workspace.verify_execution_contract"):
            for update in cases:
                with self.subTest(update=update):
                    result = graph.finalizer_node({**self.state, **update})
                    self.assertNotEqual(result["status"], "VERIFIED")
        oversize = graph.finalizer_node({**self.state, "coding_units": [{"id": "x"}] * 4})
        self.assertEqual((oversize["status"], oversize["unit_error"]),
                         ("BLOCKED", "UNIT_LIMIT_EXCEEDED"))

    def test_graph_and_direct_coder_guards_reject_four_units(self):
        state = {**self.state, "coding_units": [{"id": "unit-1"}] * 4}
        with patch.object(graph, "coder_node") as worker:
            result = graph.guarded_coder_node(state, worker)
        worker.assert_not_called()
        self.assertEqual(result["status"], "BLOCKED")

    def test_direct_fixer_guard_blocks_third_attempt_without_model(self):
        with patch.object(fixer, "run_worker") as worker:
            result = fixer.fixer_node({"task": "Repair fixture", "repo_dir": str(self.repo),
                                       "fix_attempts": 2})
        worker.assert_not_called()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["fixer_error"], "FIX_ATTEMPT_LIMIT_OR_STATE_INVALID")


if __name__ == "__main__":
    unittest.main()
