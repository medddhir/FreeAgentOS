"""Deterministic unit derivation and bounded Coder context fixtures."""

import json
import subprocess
import sys
import tempfile
import unittest
import os
import runpy
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
from roles import coder
from roles.coding_units import (MAX_CONTEXT_BYTES, MAX_CONTEXT_FILE_BYTES, MAX_CONTEXT_FILES,
                                _step_kind, derive_units, derive_units_node, failure_count, local_context)
from roles.worker import WorkerResult
import cli


class CodingUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-unit-test-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / "app.py").write_text("def value():\n    return 1\n")
        (self.repo / "README.md").write_text("Improve value in app.py.\n")
        (self.repo / ".gitignore").write_text(".env\n")
        (self.repo / ".env").write_text("API_KEY=fake_secret_never_include\n")
        for args in (("init", "-q"), ("add", "app.py", "README.md", ".gitignore"),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-qm", "baseline")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        self.state = {"task": "Improve value", "repo_dir": str(self.repo),
                      "integrity_baseline": {"repo": str(self.repo), "head": head},
                      "repo_facts": {"relevant_files": ["app.py"], "test_locations": ["test_app.py"]},
                      "repo_facts_text": '{"languages":["Python"],"relevant_files":["app.py"]}',
                      "plan_steps": ["Improve app.py"]}

    def test_small_medium_large_and_max_cap(self):
        facts = self.state["repo_facts"]
        self.assertEqual(derive_units([], facts), [])
        steps = [f"Implement distinct stage {i} in app.py" for i in range(10)]
        self.assertEqual(len(derive_units(steps[:1], facts)), 1)
        self.assertEqual(len(derive_units(steps[:2], facts)), 1)
        self.assertEqual(len(derive_units(steps[:3], facts)), 2)
        self.assertEqual(len(derive_units(steps[:4], facts)), 2)
        self.assertEqual(len(derive_units(steps[:5], facts)), 3)
        self.assertEqual(len(derive_units(steps, facts)), 3)
        self.assertEqual(derive_units_node({**self.state, "plan_steps": []})["unit_error"],
                         "NO_IMPLEMENTATION_UNITS")
        malformed = derive_units_node({**self.state, "coding_units": [{}] * 4})
        self.assertEqual(malformed["status"], "BLOCKED")
        self.assertEqual(malformed["unit_error"], "UNIT_LIMIT_OR_STATE_INVALID")

    def test_calculator_workflow_steps_compact_to_one_implementation_unit(self):
        steps = ["Read test_calculator.py to understand expected behavior.",
                 "Read calculator.py and identify the discrepancy.",
                 "Correct the add implementation.",
                 "Run the existing tests.",
                 "Verify the smallest implementation change."]
        units = derive_units(steps, {"relevant_files": ["calculator.py", "test_calculator.py"]})
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0]["steps"], steps)
        self.assertIn("Correct the add implementation", units[0]["goal"])
        self.assertIn("Read test_calculator.py", units[0]["goal"])
        self.assertIn("Run the existing tests", units[0]["goal"])

    def test_shipment_like_work_keeps_distinct_implementation_units(self):
        steps = ["Inspect README and existing data models.",
                 "Implement robust CSV/Decimal parsing and validation.",
                 "Implement reconciliation for duplicates, unmatched AWBs, and tolerance.",
                 "Implement deterministic report and CLI output.",
                 "Run the existing test suite and verify behavior."]
        units = derive_units(steps, {})
        self.assertEqual(len(units), 2)
        self.assertEqual([step for unit in units for step in unit["steps"]], steps)
        self.assertIn("reconciliation", units[1]["goal"])

    def test_meta_steps_attach_to_adjacent_work_without_reordering(self):
        cases = [
            (["Inspect app.py", "Fix parsing in app.py", "Run tests"], 1),
            (["Read tests", "Fix parsing", "Inspect output", "Update CLI", "Verify diff"], 1),
            (["Read models", "Implement parser", "Inspect CLI", "Implement report",
              "Add command flags"], 2),
        ]
        for steps, expected in cases:
            with self.subTest(steps=steps):
                units = derive_units(steps, {})
                self.assertEqual(len(units), expected)
                self.assertEqual([step for unit in units for step in unit["steps"]], steps[:5])

    def test_meta_only_plan_falls_back_to_one_bounded_unit(self):
        steps = ["Read README", "Inspect implementation", "Identify discrepancy",
                 "Run tests", "Review diff"]
        units = derive_units(steps, {})
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0]["steps"], steps)
        self.assertLessEqual(len(units[0]["goal"]), 900)

    def test_test_and_verification_code_edits_are_implementation(self):
        for step in ("Add tests for decimal parsing", "Implement validation checks",
                     "Fix test discovery", "Update verification logic", "Add review endpoint"):
            with self.subTest(step=step):
                self.assertEqual(_step_kind(step), "implementation")
        self.assertEqual(_step_kind("Run tests to check the fix"), "verification")

    def test_planner_guidance_requests_outcomes_not_tool_steps(self):
        from roles import planner
        response = {"structured_output": {"needs_research": False, "research_type": "none",
                                           "research_query": "", "steps": ["Fix app.py"],
                                           "coding_units": [{"goal": "Fix app.py", "target_files": []}]}}
        prompts = []
        def fake_worker(cmd, **_kwargs):
            prompts.append(cmd[-1])
            return WorkerResult(0, json.dumps(response),
                                {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
        with patch.object(planner, "run_worker", fake_worker):
            planner._run_planner("Fix app.py")
        self.assertIn("coding_units define the expensive Coder model-call boundaries", prompts[0])
        self.assertIn("never create a read-only or test-only coding unit", prompts[0])

    def test_failure_count_only_recognizes_runner_summaries(self):
        self.assertEqual(failure_count("Ran 3 tests in 0.1s\nFAILED (failures=2, errors=1)", "unittest"), 3)
        self.assertEqual(failure_count("Ran 3 tests in 0.1s\nOK", "unittest"), 0)
        self.assertEqual(failure_count("=== 2 failed, 5 passed in 0.2s ===", "pytest"), 2)
        self.assertIsNone(failure_count("Everything is fine", "unittest"))

    def test_exact_file_ownership_only(self):
        units = derive_units(["Edit app.py", "Complete the change"], self.state["repo_facts"])
        self.assertEqual(units[0]["files"], ["app.py"])
        units = derive_units(["Complete the change"], self.state["repo_facts"])
        self.assertEqual(units[0]["files"], [])
        ordinary = derive_units_node({**self.state, "workspace_test_attestation": {"baseline_failures": 1}})
        self.assertEqual(ordinary["coding_units"][0]["enforced_files"], [])
        restricted = derive_units_node({**self.state, "task": "Only edit app.py for this task",
                                        "workspace_test_attestation": {"baseline_failures": 1}})
        self.assertEqual(restricted["coding_units"][0]["enforced_files"], ["app.py"])

    def test_local_context_excludes_secrets_and_is_bounded(self):
        unit = derive_units(["Edit app.py"], self.state["repo_facts"])[0]
        text = local_context(self.state, unit)
        self.assertIn("def value():", text)
        self.assertNotIn("fake_secret_never_include", text)
        self.assertLessEqual(len(text.encode()), MAX_CONTEXT_BYTES)
        (self.repo / "app.py").write_text("API_KEY=fake_secret_in_regular_source\n")
        text = local_context(self.state, unit)
        self.assertNotIn("fake_secret_in_regular_source", text)

    def test_large_repo_context_hard_cap(self):
        for index in range(12):
            (self.repo / f"module_{index}.py").write_text("# ordinary source\n" * 380)
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "more files"], cwd=self.repo, check=True, capture_output=True)
        self.state["integrity_baseline"]["head"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        self.state["repo_facts"]["relevant_files"] = [f"module_{i}.py" for i in range(12)]
        text = local_context(self.state, {"files": []})
        self.assertLessEqual(len(text.encode()), MAX_CONTEXT_BYTES)
        self.assertLessEqual(text.count("\nFILE "), MAX_CONTEXT_FILES)
        self.assertLessEqual(text.count("# ordinary source"), MAX_CONTEXT_FILES * 380)

    def test_context_excludes_data_fixture_upload_and_generated_sources(self):
        names = ("data/records.py", "fixtures/example.py", "uploads/request.py",
                 "generated/client.py", "generated_client.py", "normal.py")
        for name in names:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"CONTEXT_MARKER_{path.stem.upper()} = 1\n")
        (self.repo / "normal.py").write_text("# AUTO-GENERATED. DO NOT EDIT\nHIDDEN_GENERATED = 1\n")
        subprocess.run(["git", "add", *names], cwd=self.repo, check=True, capture_output=True)
        self.state["repo_facts"]["relevant_files"] = list(names)
        text = local_context(self.state, {"files": list(names)})
        self.assertNotIn("CONTEXT_MARKER", text)
        self.assertNotIn("HIDDEN_GENERATED", text)
        self.assertIn("README.md", text)

    def test_context_rejects_symlink_hardlink_special_and_opaque_content(self):
        (self.repo / "linked.py").symlink_to("app.py")
        subprocess.run(["git", "add", "linked.py"], cwd=self.repo, check=True, capture_output=True)
        with self.assertRaises(RuntimeError):
            local_context(self.state, {"files": ["linked.py"]})
        (self.repo / "linked.py").unlink()
        os.link(self.repo / "app.py", self.repo / "hard.py")
        subprocess.run(["git", "add", "hard.py"], cwd=self.repo, check=True, capture_output=True)
        with self.assertRaises(RuntimeError):
            local_context(self.state, {"files": ["hard.py"]})
        (self.repo / "hard.py").unlink()
        (self.repo / "app.py").write_text("HEADER = 'Bearer short-example'\n")
        self.assertNotIn("Bearer short-example", local_context(self.state, {"files": ["app.py"]}))
        (self.repo / "app.py").write_text("VALUE = '" + "x" * 40 + "'\n")
        self.assertNotIn("x" * 40, local_context(self.state, {"files": ["app.py"]}))
        (self.repo / "app.py").write_text("A = '" + "q" * (MAX_CONTEXT_FILE_BYTES + 100) + "'\n")
        self.assertNotIn("q" * 100, local_context(self.state, {"files": ["app.py"]}))
        (self.repo / "app.py").unlink()
        os.mkfifo(self.repo / "app.py")
        with self.assertRaises(RuntimeError):
            local_context(self.state, {"files": ["app.py"]})

    def test_real_self_suite_discovers_stage_one_tests(self):
        runner = runpy.run_path(str(ROOT / "bin/freeagent-test"))
        self.assertEqual(runner["detect"](), ([sys.executable, "-m", "unittest", "discover"],
                                                "python-unittest"))
        suite = unittest.TestLoader().discover(str(ROOT), pattern="test*.py")
        def test_ids(node):
            if isinstance(node, unittest.TestCase):
                return [node.id()]
            return [item for child in node for item in test_ids(child)]
        ids = test_ids(suite)
        for name in ("test_coding_units", "test_unit_graph", "test_integrity_core"):
            self.assertTrue(any(identifier.startswith(name + ".") for identifier in ids), name)
        self.assertGreaterEqual(len(ids), 204)

    def test_coder_receives_repo_facts_and_context(self):
        prompt = []
        def fake_worker(cmd, **_kwargs):
            prompt.append(cmd[-1])
            return WorkerResult(0, "done", {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
        unit = derive_units(self.state["plan_steps"], self.state["repo_facts"])[0]
        with patch.object(coder, "verify_execution_contract"), patch.object(coder, "run_worker", fake_worker):
            result = coder.coder_node({**self.state, "coding_units": [unit], "unit_index": 0})
        self.assertFalse(result["coder_error"])
        self.assertIn('"languages":["Python"]', prompt[0])
        self.assertIn("def value():", prompt[0])
        self.assertNotIn("fake_secret_never_include", prompt[0])

    def test_second_coder_uses_verified_dirty_workspace_with_fresh_call(self):
        units = derive_units(["Fix first behavior", "Fix second behavior", "Implement third behavior in app.py"],
                             self.state["repo_facts"])
        (self.repo / "app.py").write_text("def value():\n    return 2\n")
        prompts = []
        def fake_worker(cmd, **_kwargs):
            prompts.append(cmd[-1])
            return WorkerResult(0, "done", {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
        state = {**self.state, "coding_units": units, "unit_index": 1,
                 "unit_gate_status": "CONTINUE", "unit_history": [{"unit_id": "unit-1",
                                                                   "changed_files": ["app.py"],
                                                                   "test_failures_after": 1}]}
        with patch.object(coder, "verify_execution_contract"), patch.object(coder, "run_worker", fake_worker):
            result = coder.coder_node(state)
        self.assertFalse(result["coder_error"])
        self.assertEqual(len(prompts), 1)
        self.assertIn("unit-2", prompts[0])
        self.assertIn("return 2", prompts[0])
        with patch.object(coder, "verify_execution_contract"), patch.object(coder, "run_worker", fake_worker):
            blocked = coder.coder_node({**state, "unit_gate_status": "BLOCKED"})
        self.assertEqual(blocked["coder_error"], "PRIOR_UNIT_NOT_VERIFIED")
        self.assertEqual(len(prompts), 1)

    def test_coder_timeout_retains_unit_timing_without_tester(self):
        unit = derive_units(self.state["plan_steps"], self.state["repo_facts"])[0]
        evidence = {"worker_total_ms": 180100, "worker_first_stdout_byte_ms": None,
                    "timeout_triggered": True, "output_truncated": False,
                    "resource_hits": {"memory": False}, "worker_exit_code": 124,
                    "cleanup_status": "CONFIRMED", "remaining_processes": 0}
        with patch.object(coder, "verify_execution_contract"), \
                patch.object(coder, "run_worker", return_value=WorkerResult(124, "", evidence)):
            result = coder.coder_node({**self.state, "coding_units": [unit], "unit_index": 0})
        self.assertEqual(result["coder_error"], "CODER_TIMEOUT")
        self.assertEqual(result["unit_history"][0]["test_result_after"], "NOT_RUN")
        self.assertEqual(result["unit_history"][0]["worker_total_ms"], 180100)

    def test_cli_unit_timing_is_bounded_and_secret_safe(self):
        secret = "Bearer fake_secret_should_not_appear"
        result = cli._projection({"status": "BLOCKED", "trace": ["coder"],
                                  "unit_history": [{"unit_id": "unit-1", "unit_index": 1,
                                                    "goal": secret, "worker_total_ms": 123,
                                                    "first_stdout_byte_ms": 100,
                                                    "changed_files": ["app.py"],
                                                    "test_failures_before": 2,
                                                    "test_failures_after": 1}],
                                  "coding_units": [{"id": "unit-1"}], "unit_index": 1},
                                 self.repo, "task", {})
        self.assertEqual(result["unit_history"][0]["worker_total_ms"], 123)
        self.assertEqual(result["unit_history"][0]["goal"], "[REDACTED]")
        self.assertNotIn(secret, str(result))


if __name__ == "__main__":
    unittest.main()
