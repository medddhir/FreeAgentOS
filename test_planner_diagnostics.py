"""Planner failure categories contain structure, never raw provider output."""

import json
import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))

import cli
from roles import planner
from roles.worker import WorkerBoundaryError, WorkerResult


VALID = {"needs_research": False, "research_type": "none", "research_query": "",
         "steps": ["Fix the calculator"],
         "coding_units": [{"goal": "Fix the calculator implementation", "target_files": []}]}
EVIDENCE = {"cleanup_status": "CONFIRMED", "remaining_processes": 0,
            "timeout_triggered": False, "output_truncated": False}
SECRET = "Bearer secret_private_token_123456789"


class PlannerDiagnosticTests(unittest.TestCase):
    def check_case(self, output, code, *, exit_code=0, evidence=None, exception=None):
        result = WorkerResult(exit_code, output, evidence or EVIDENCE)
        with patch.object(planner, "verify_execution_contract"), \
                patch.object(planner, "run_worker", side_effect=exception, return_value=result):
            state = planner.planner_node({"task": "Fix calculator", "repo_facts_text": "Python project"})
        self.assertEqual(state["planner_error_code"], code)
        self.assertEqual(state["status"], "BLOCKED")
        self.assertNotIn(SECRET, json.dumps(state))
        self.assertLess(len(json.dumps(state)), 2048)
        projected = cli._projection(state, Path("/tmp/fixture"), "Fix calculator", {})
        self.assertEqual(projected["planner_error_code"], code)
        self.assertEqual(projected["block_stage"], "planner")
        self.assertNotIn(SECRET, json.dumps(projected))
        self.assertLess(len(json.dumps(projected)), cli.MAX_JSON_BYTES)
        return state, projected

    def test_worker_exit_nonzero(self):
        state, _ = self.check_case(SECRET, "PLANNER_WORKER_EXIT_NONZERO", exit_code=1)
        self.assertEqual(state["planner_diagnostic"]["worker_exit"], 1)

    def test_empty_response(self):
        self.check_case("", "PLANNER_EMPTY_RESPONSE")

    def test_invalid_outer_json(self):
        self.check_case("not json " + SECRET, "PLANNER_OUTER_JSON_INVALID")

    def test_multiple_values_and_trailing_prose_fail_closed(self):
        for output in (json.dumps(VALID) + '\n' + json.dumps(VALID),
                       json.dumps(VALID) + ' trailing prose ' + SECRET,
                       '```json\n' + json.dumps(VALID) + '\n```'):
            with self.subTest(output_kind=output[:3]):
                state, _ = self.check_case(output, "PLANNER_OUTER_JSON_INVALID")
                self.assertFalse(state["planner_diagnostic"]["outer_json_valid"])

    def test_direct_object_and_json_whitespace(self):
        for output in (json.dumps(VALID), ' \n' + json.dumps(VALID) + '\t'):
            with self.subTest(whitespace=output.startswith(' ')):
                result = WorkerResult(0, output, EVIDENCE)
                with patch.object(planner, "verify_execution_contract"), \
                        patch.object(planner, "run_worker", return_value=result):
                    state = planner.planner_node({"task": "Fix calculator"})
                self.assertEqual(state["planner_error_code"], "")
                self.assertEqual(state["plan_steps"], VALID["steps"])
                self.assertEqual(state["unit_derivation_source"], "PLANNER_EXPLICIT")
                self.assertEqual(state["planner_diagnostic"]["supported_envelope_detected"],
                                 "DIRECT_STRUCTURED_OBJECT")

    def test_direct_object_schema_stays_strict(self):
        invalid = {**VALID, "steps": [SECRET], "needs_research": "false"}
        self.check_case(json.dumps(invalid), "PLANNER_SCHEMA_VALIDATION_FAILED")

    def test_valid_stdout_with_stderr_evidence(self):
        evidence = {**EVIDENCE, "worker_stderr_bytes_seen": 85,
                    "worker_first_stderr_byte_ms": 5, "worker_first_stdout_byte_ms": 20}
        result = WorkerResult(0, json.dumps({"structured_output": VALID}), evidence)
        with patch.object(planner, "verify_execution_contract"), \
                patch.object(planner, "run_worker", return_value=result):
            state = planner.planner_node({"task": "Fix calculator"})
        self.assertEqual(state["planner_error_code"], "")
        self.assertEqual(state["worker_history"][0]["evidence"]["worker_stderr_bytes_seen"], 85)
        self.assertEqual(state["planner_diagnostic"]["stderr_bytes"], 85)

    def test_structured_output_missing(self):
        self.check_case(json.dumps({"result": "plain answer " + SECRET}),
                        "PLANNER_STRUCTURED_OUTPUT_MISSING")

    def test_malformed_structured_output(self):
        self.check_case(json.dumps({"structured_output": [SECRET]}),
                        "PLANNER_STRUCTURED_OUTPUT_INVALID")

    def test_schema_invalid_structured_output(self):
        invalid = {**VALID, "needs_research": "false", "steps": [SECRET]}
        self.check_case(json.dumps({"structured_output": invalid}),
                        "PLANNER_SCHEMA_VALIDATION_FAILED")

    def test_explicit_model_error(self):
        state, projected = self.check_case(json.dumps({"is_error": True, "error": SECRET}),
                                           "PLANNER_MODEL_ERROR")
        self.assertTrue(projected["planner_diagnostic"]["explicit_error"])

    def test_truncated_response(self):
        self.check_case(SECRET, "PLANNER_RESPONSE_TRUNCATED",
                        evidence={**EVIDENCE, "output_truncated": True})

    def test_worker_timeout(self):
        self.check_case(SECRET, "PLANNER_WORKER_TIMEOUT", exit_code=124,
                        evidence={**EVIDENCE, "timeout_triggered": True})

    def test_cleanup_failure(self):
        self.check_case(SECRET, "PLANNER_CLEANUP_FAILED",
                        exception=WorkerBoundaryError("WORKER_BOUNDARY_UNVERIFIED",
                                                      {"cleanup_status": "UNPROVEN",
                                                       "remaining_processes": 1, "error": SECRET}))

    def test_valid_result_and_fallback(self):
        for envelope in ({"structured_output": VALID},
                         {"structured_output": None, "result": json.dumps(VALID)}):
            with self.subTest(envelope=envelope):
                result = WorkerResult(0, json.dumps(envelope), EVIDENCE)
                with patch.object(planner, "verify_execution_contract"), \
                        patch.object(planner, "run_worker", return_value=result):
                    state = planner.planner_node({"task": "Fix calculator"})
                self.assertEqual(state["planner_error_code"], "")
                self.assertEqual(state["plan_steps"], ["Fix the calculator"])
                self.assertEqual(state["trace"], ["planner"])

    def test_cli_json_and_human_diagnostics_are_bounded(self):
        state = {"status": "BLOCKED", "trace": ["planner:error"],
                 "planner_error": "PLANNER_MODEL_ERROR", "planner_error_code": "PLANNER_MODEL_ERROR",
                 "planner_error_stage": "model",
                 "planner_diagnostic": {"response_bytes": 80, "explicit_error": True,
                                        "known_keys_present": ["error", SECRET], "raw": SECRET}}
        class FakeGraph:
            def invoke(self, _initial):
                return state
        with patch.object(cli, "_repo", return_value=Path("/tmp/fixture")), \
                patch.object(cli, "recover_stale_workspaces", return_value={}), \
                patch.object(cli.graph, "build_graph", return_value=FakeGraph()):
            for json_mode in (False, True):
                with self.subTest(json_mode=json_mode):
                    stream = io.StringIO()
                    with contextlib.redirect_stdout(stream):
                        code = cli.main(["--repo", "/tmp/fixture", "--task", "task"]
                                        + (["--json"] if json_mode else []))
                    self.assertEqual(code, 2)
                    output = stream.getvalue()
                    self.assertNotIn(SECRET, output)
                    self.assertLess(len(output), cli.MAX_JSON_BYTES)
                    if json_mode:
                        self.assertEqual(json.loads(output)["planner_error_code"], "PLANNER_MODEL_ERROR")
                    else:
                        self.assertIn("BLOCK_STAGE=planner", output)
                        self.assertIn("PLANNER_ERROR_CODE=PLANNER_MODEL_ERROR", output)


if __name__ == "__main__":
    unittest.main()
