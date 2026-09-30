"""Strict Planner-provided Coder boundaries, with no additional model call."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))

import cli
from roles import planner
from roles.coding_units import MAX_UNITS, derive_units_node, validate_planner_units
from roles.worker import WorkerResult


EVIDENCE = {"cleanup_status": "CONFIRMED", "remaining_processes": 0,
            "timeout_triggered": False, "output_truncated": False}
STEPS = ["Inspect the current implementation", "Implement data models and CSV parsing",
         "Handle duplicate and unmatched records", "Implement reconciliation and CLI output",
         "Run the existing tests"]


def response(steps=STEPS, units=None):
    selected = (units if units is not None else [
        {"goal": "Implement parsing and duplicate handling"},
        {"goal": "Implement reconciliation and CLI output"}])
    return {"needs_research": False, "research_type": "none", "research_query": "",
            "steps": steps, "coding_units": ([{**unit, "target_files": unit.get("target_files", [])}
                                              if isinstance(unit, dict) else unit for unit in selected]
                                             if isinstance(selected, list) else selected)}


class ExplicitCodingUnitTests(unittest.TestCase):
    def planner_state(self, payload):
        result = WorkerResult(0, json.dumps({"structured_output": payload}), EVIDENCE)
        with patch.object(planner, "verify_execution_contract"), \
                patch.object(planner, "run_worker", return_value=result) as worker:
            state = planner.planner_node({"task": "Implement fixture", "repo_facts_text": "Python"})
        worker.assert_called_once()
        return state

    def test_valid_one_two_and_three_units(self):
        cases = [
            (["Inspect calculator", "Fix add", "Run tests"],
             [{"goal": "Fix calculator add implementation"}]),
            (STEPS, response()["coding_units"]),
            (STEPS, [{"goal": "Implement data model and parser"},
                     {"goal": "Handle duplicate and unmatched records"},
                     {"goal": "Implement reconciliation and CLI output"}]),
        ]
        for steps, units in cases:
            with self.subTest(count=len(units)):
                state = self.planner_state(response(steps, units))
                self.assertNotEqual(state.get("status"), "BLOCKED")
                self.assertEqual(state["unit_derivation_source"], "PLANNER_EXPLICIT")
                derived = derive_units_node({**state, "task": "Implement fixture",
                                             "repo_facts": {},
                                             "workspace_test_attestation": {"baseline_failures": 2}})
                self.assertEqual(len(derived["coding_units"]), len(units))
                for unit in derived["coding_units"]:
                    self.assertEqual(unit["steps"], steps)
                projected = cli._projection({**state, **derived, "status": "BLOCKED", "trace": []},
                                            Path("/tmp/fixture"), "Implement fixture", {})
                self.assertEqual(projected["planner_steps_count"], len(steps))
                self.assertEqual(projected["planner_coding_units_count"], len(units))
                self.assertEqual(projected["unit_derivation_source"], "PLANNER_EXPLICIT")

    def test_schema_requires_bounded_explicit_units(self):
        schema = planner.PLANNER_SCHEMA
        self.assertIn("coding_units", schema["required"])
        self.assertEqual(schema["properties"]["coding_units"]["maxItems"], MAX_UNITS)
        self.assertFalse(schema["properties"]["coding_units"]["items"]["additionalProperties"])
        self.assertIn("target_files", schema["properties"]["coding_units"]["items"]["required"])
        self.assertNotIn("covers_steps", schema["properties"]["coding_units"]["items"]["properties"])

    def test_missing_units_in_actual_worker_response_blocks(self):
        payload = response()
        del payload["coding_units"]
        state = self.planner_state(payload)
        self.assertEqual(state["planner_error_code"], "PLANNER_CODING_UNITS_MISSING")
        self.assertEqual(state["status"], "BLOCKED")
        self.assertNotIn("planner_coding_units", state)

    def test_production_requires_target_files_field(self):
        payload = response()
        del payload["coding_units"][0]["target_files"]
        state = self.planner_state(payload)
        self.assertEqual(state["status"], "BLOCKED")
        self.assertEqual(state["planner_error_code"], "PLANNER_CODING_UNITS_INVALID")
        self.assertEqual(state["planner_diagnostic"]["unit_validation_code"],
                         "UNIT_SCHEMA_INVALID")

    def test_blank_plan_step_remains_invalid(self):
        payload = response(["Implement parser", "   ", "Run tests"],
                           [{"goal": "Implement parser"}])
        state = self.planner_state(payload)
        self.assertEqual(state["status"], "BLOCKED")
        self.assertEqual(state["planner_error_code"], "PLANNER_SCHEMA_VALIDATION_FAILED")

    def test_invalid_units_fail_before_derivation(self):
        first = {"goal": "Implement parser"}
        second = {"goal": "Implement report"}
        cases = {
            "zero": [], "four": [first, second, second, second],
            "count_type": {},
            "blank_goal": [{"goal": "   "}],
            "goal_type": [{"goal": 17}],
            "oversize_goal": [{"goal": "Implement " + "x" * 300}],
            "meta_goal": [{"goal": "Run tests"}],
            "malformed": ["Implement parser"],
            "extra_field": [{"goal": "Implement all", "skip_tests": True}],
            "target_type": [{"goal": "Implement parser", "target_files": "parser.py"}],
            "target_element": [{"goal": "Implement parser", "target_files": [None]}],
            "target_duplicate": [{"goal": "Implement parser", "target_files": ["app.py", "app.py"]}],
            "target_unsafe": [{"goal": "Implement parser", "target_files": ["../app.py"]}],
            "target_count": [{"goal": "Implement parser", "target_files": [f"part{i}.py" for i in range(5)]}],
        }
        for label, units in cases.items():
            with self.subTest(case=label):
                state = self.planner_state(response(units=units))
                self.assertEqual(state["status"], "BLOCKED")
                self.assertEqual(state["planner_error_code"], "PLANNER_CODING_UNITS_INVALID")
                self.assertIn(state["planner_diagnostic"]["unit_validation_code"],
                              {"UNIT_COUNT_INVALID", "UNIT_SCHEMA_INVALID", "UNIT_GOAL_INVALID",
                               "UNIT_TARGET_FILE_INVALID"})
                projected = cli._projection(state, Path("/tmp/fixture"), "Implement fixture", {})
                self.assertEqual(projected["planner_error_code"], "PLANNER_CODING_UNITS_INVALID")
                self.assertNotIn("skip_tests", json.dumps(projected))

    def test_unit_derivation_rechecks_forged_explicit_state(self):
        state = {"plan_steps": STEPS, "unit_derivation_source": "PLANNER_EXPLICIT",
                 "planner_coding_units": [{"goal": "Run tests", "target_files": []}]}
        result = derive_units_node(state)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["unit_error"], "UNIT_GOAL_INVALID")

    def test_legacy_fixture_conversion_remains_explicitly_identified(self):
        payload = response()
        del payload["coding_units"]
        with patch.object(planner, "verify_execution_contract"), \
                patch.object(planner, "_run_planner", return_value=payload):
            state = planner.planner_node({"task": "Implement fixture"})
        self.assertEqual(state["unit_derivation_source"], "LEGACY_COMPACTION")
        self.assertEqual(state["planner_coding_units"], [])
        derived = derive_units_node({**state, "repo_facts": {},
                                     "workspace_test_attestation": {"baseline_failures": 2}})
        self.assertEqual(derived["unit_derivation_source"], "LEGACY_COMPACTION")
        self.assertTrue(derived["coding_units"])

    def test_production_rejects_old_numeric_mapping_as_unknown_field(self):
        for coverage in ([1, 2], [1, 1, 999], "malformed"):
            with self.subTest(coverage=coverage):
                payload = response(units=[{"goal": "Implement parser", "covers_steps": coverage}])
                state = self.planner_state(payload)
                self.assertEqual(state["status"], "BLOCKED")
                self.assertEqual(state["planner_diagnostic"]["unit_validation_code"], "UNIT_SCHEMA_INVALID")

    def test_plan_and_unit_counts_are_independent(self):
        for steps_count in range(1, 6):
            for unit_count in range(1, 4):
                with self.subTest(steps=steps_count, units=unit_count):
                    units = [{"goal": f"Implement objective {i}", "target_files": []}
                             for i in range(unit_count)]
                    self.assertEqual(len(validate_planner_units(STEPS[:steps_count], units)), unit_count)

    def test_unit_schema_diagnostic_never_leaks_unknown_field_values(self):
        secret = "Bearer fake_private_token_should_never_appear"
        state = self.planner_state(response(units=[{"goal": "Implement parser", "secret": secret}]))
        projected = cli._projection(state, Path("/tmp/fixture"), "Implement fixture", {})
        self.assertEqual(projected["planner_diagnostic"]["unit_validation_code"], "UNIT_SCHEMA_INVALID")
        self.assertNotIn(secret, json.dumps(projected))


if __name__ == "__main__":
    unittest.main()
