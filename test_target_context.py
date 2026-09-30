"""Stage 1.3 target hints and current-workspace Coder context."""

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

import cli
import graph
from roles import coder, planner
from roles.coding_units import (MAX_CONTEXT_BYTES, MAX_CONTEXT_FILE_BYTES,
                                MAX_TARGET_FILES, derive_units_node, local_context_packet)
from roles.worker import WorkerResult


def unit(targets, goal="Implement parser"):
    return {"goal": goal, "target_files": targets}


class TargetContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-target-context-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / "models.py").write_text("MODEL_PRIMARY = 1\n")
        (self.repo / "parser.py").write_text("PARSER_SECONDARY = 1\n")
        (self.repo / "report.py").write_text("REPORT_TERTIARY = 1\n")
        (self.repo / "README.md").write_text("Ordinary application.\n")
        (self.repo / "test_app.py").write_text("import unittest\n")
        (self.repo / ".gitignore").write_text(".env\n")
        (self.repo / ".env").write_text("FAKE_SECRET = 'never show this'\n")
        for args in (("init", "-q"),
                     ("add", "models.py", "parser.py", "report.py", "README.md", "test_app.py", ".gitignore"),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-qm", "baseline")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo,
                                       text=True).strip()
        self.state = {"task": "Implement fixture", "repo_dir": str(self.repo),
                      "integrity_baseline": {"repo": str(self.repo), "head": head},
                      "repo_facts": {"relevant_files": ["parser.py", "report.py", "models.py"],
                                     "test_locations": ["test_app.py"]},
                      "repo_facts_text": '{"languages":["Python"]}',
                      "plan_steps": ["Implement parser"],
                      "unit_derivation_source": "PLANNER_EXPLICIT",
                      "workspace_test_attestation": {"baseline_failures": 1}}

    def derive(self, targets, **state_overrides):
        return derive_units_node({**self.state,
                                  "planner_coding_units": [unit(targets)], **state_overrides})

    def test_calculator_like_existing_target_and_current_contents_first(self):
        result = self.derive(["models.py"])
        self.assertNotIn("status", result)
        self.assertEqual(len(result["coding_units"]), 1)
        selected = result["coding_units"][0]
        self.assertEqual(selected["target_files"], ["models.py"])
        packet = local_context_packet(self.state, selected)
        self.assertLess(packet["text"].index("MODEL_PRIMARY"),
                        packet["text"].index("PARSER_SECONDARY"))
        self.assertEqual(packet["target_files_existing_count"], 1)
        self.assertEqual(packet["target_files_new_count"], 0)
        self.assertLessEqual(len(packet["text"].encode()), MAX_CONTEXT_BYTES)

    def test_calculator_five_plan_steps_one_explicit_unit(self):
        (self.repo / "calculator.py").write_text("def add(a, b): return a - b\n")
        for args in (("add", "calculator.py"),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-qm", "calculator fixture")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        self.state["integrity_baseline"]["head"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        steps = ["Inspect requirements", "Read the existing implementation",
                 "Fix the calculator", "Run tests", "Inspect the final change"]
        payload = {"needs_research": False, "research_type": "none", "research_query": "",
                   "steps": steps, "coding_units": [unit(["calculator.py"],
                                                          "Fix the calculator implementation and verify behavior")]}
        worker = WorkerResult(0, json.dumps({"structured_output": payload}),
                              {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
        with patch.object(planner, "verify_execution_contract"), \
                patch.object(planner, "run_worker", return_value=worker):
            planned = planner.planner_node(self.state)
        derived = derive_units_node({**self.state, **planned})
        projected = cli._projection({**self.state, **planned, **derived,
                                     "status": "BLOCKED", "trace": []}, self.repo, "task", {})
        self.assertEqual(projected["planner_steps_count"], 5)
        self.assertEqual(projected["planner_coding_units_count"], 1)
        self.assertEqual(projected["coding_units_planned"], 1)
        self.assertEqual(projected["unit_derivation_source"], "PLANNER_EXPLICIT")
        self.assertEqual(derived["coding_units"][0]["target_files"], ["calculator.py"])

    def test_shipment_like_two_units_and_current_workspace_contents(self):
        steps = ["Inspect models", "Implement parsing", "Implement core behavior",
                 "Implement report", "Run tests"]
        proposed = [unit(["models.py", "parser.py"], "Implement models and parsing"),
                    unit(["models.py", "report.py"], "Implement report")]
        state = {**self.state, "plan_steps": steps, "planner_coding_units": proposed}
        result = derive_units_node(state)
        self.assertEqual(len(result["coding_units"]), 2)
        first = local_context_packet(state, result["coding_units"][0])
        self.assertLess(first["text"].index("MODEL_PRIMARY"),
                        first["text"].index("REPORT_TERTIARY"))
        (self.repo / "models.py").write_text("MODEL_CHANGED_BY_UNIT_ONE = 2\n")
        second = local_context_packet({**state, "unit_history": [{"changed_files": ["models.py"]}]},
                                      result["coding_units"][1])
        self.assertIn("MODEL_CHANGED_BY_UNIT_ONE", second["text"])
        self.assertNotIn("MODEL_PRIMARY", second["text"])
        self.assertLess(second["text"].index("MODEL_CHANGED_BY_UNIT_ONE"),
                        second["text"].index("PARSER_SECONDARY"))
        self.assertEqual(second["target_files_count"], 2)

    def test_coder_goal_is_authoritative_and_full_plan_is_context(self):
        steps = ["Inspect models", "Implement parsing", "Implement core behavior",
                 "Implement report", "Run tests"]
        state = {**self.state, "plan_steps": steps,
                 "planner_coding_units": [unit(["models.py"], "Implement models"),
                                          unit(["report.py"], "Implement report")]}
        derived = derive_units_node(state)
        selected = derived["coding_units"][1]
        selected["steps"] = ["Unrelated stale unit bookkeeping"]
        prompts = []
        def worker(cmd, **_kwargs):
            prompts.append(cmd[-1])
            return WorkerResult(0, "done", {})
        with patch.object(coder, "verify_execution_contract"), patch.object(coder, "run_worker", worker):
            coded = coder.coder_node({**state, **derived, "unit_index": 1, "unit_gate_status": "CONTINUE"})
        self.assertEqual(coded["coder_error"], "")
        self.assertEqual(len(prompts), 1)
        for index, step in enumerate(steps, 1):
            self.assertIn(f"{index}. {step}", prompts[0])
        self.assertNotIn("Unrelated stale unit bookkeeping", prompts[0])
        self.assertIn('"goal": "Implement report"', prompts[0])
        self.assertIn("current coding-unit goal is authoritative", prompts[0])
        self.assertEqual(coded["worker_history"][0]["context"]["planner_steps_context_count"], 5)

    def test_unsafe_and_protected_paths_fail_before_coder(self):
        rejected = ("/tmp/escape.py", "../escape.py", "a/../escape.py", "./models.py",
                    "models//parser.py", ".git/config.py", ".env", "credentials.py",
                    "private_key.py", "data/records.py", "fixtures/example.py",
                    "uploads/request.py", "generated/client.py", "generated_client.py",
                    "orchestrator/roles/tester.py", "pyproject.toml", "test_app.py",
                    "a\\b.py", "x" * 181 + ".py")
        for name in rejected:
            with self.subTest(path=name):
                result = self.derive([name])
                self.assertEqual(result["status"], "BLOCKED")
                self.assertTrue(result["unit_error"].startswith("UNIT_TARGET_FILE_"))

    def test_duplicate_and_excess_targets_fail(self):
        for targets in (["models.py", "models.py"],
                        [f"module_{index}.py" for index in range(MAX_TARGET_FILES + 1)]):
            with self.subTest(targets=targets):
                self.assertEqual(self.derive(targets)["unit_error"], "UNIT_TARGET_FILE_INVALID")

    def test_new_file_requires_policy_and_existing_claim_must_be_real(self):
        self.assertEqual(self.derive(["new_parser.py"])["unit_error"],
                         "UNIT_TARGET_FILE_POLICY_DENIED")
        allowed = self.derive(["new_parser.py"], allow_new_files=True)
        self.assertEqual(allowed["coding_units"][0]["target_files"], ["new_parser.py"])
        packet = local_context_packet({**self.state, "allow_new_files": True},
                                      allowed["coding_units"][0])
        self.assertEqual(packet["target_files_new_count"], 1)
        self.assertNotIn("FILE new_parser.py", packet["text"])
        bad_facts = {**self.state["repo_facts"],
                     "relevant_files": ["missing_claim.py", "models.py"]}
        self.assertEqual(self.derive(["missing_claim.py"], allow_new_files=True,
                                     repo_facts=bad_facts)["unit_error"],
                         "UNIT_TARGET_FILE_UNTRUSTED")

    def test_new_file_cannot_replace_untracked_file_or_cross_symlink_parent(self):
        (self.repo / "surprise.py").write_text("UNTRACKED = 1\n")
        self.assertEqual(self.derive(["surprise.py"], allow_new_files=True)["unit_error"],
                         "UNIT_TARGET_FILE_UNTRUSTED")
        (self.repo / "linked").symlink_to("/tmp")
        self.assertEqual(self.derive(["linked/new.py"], allow_new_files=True)["unit_error"],
                         "UNIT_TARGET_FILE_UNSAFE")

    def test_test_file_requires_explicit_test_policy(self):
        self.assertEqual(self.derive(["test_app.py"])["unit_error"],
                         "UNIT_TARGET_FILE_POLICY_DENIED")
        self.assertEqual(self.derive(["test_app.py"], allow_test_changes=True)
                         ["coding_units"][0]["target_files"], ["test_app.py"])

    def test_symlink_hardlink_and_special_file_rejected(self):
        (self.repo / "models.py").unlink()
        (self.repo / "models.py").symlink_to("parser.py")
        self.assertEqual(self.derive(["models.py"])["unit_error"], "UNIT_TARGET_FILE_UNSAFE")
        (self.repo / "models.py").unlink()
        (self.repo / "models.py").write_text("MODEL_PRIMARY = 1\n")
        os.link(self.repo / "models.py", self.repo / "hard.py")
        self.assertEqual(self.derive(["models.py"])["unit_error"], "UNIT_TARGET_FILE_UNSAFE")
        (self.repo / "hard.py").unlink()
        (self.repo / "models.py").unlink()
        os.mkfifo(self.repo / "models.py")
        self.assertEqual(self.derive(["models.py"])["unit_error"], "UNIT_TARGET_FILE_UNSAFE")

    def test_oversize_target_is_marked_incomplete_and_context_remains_bounded(self):
        (self.repo / "models.py").write_text("A = 1\n" * 3000)
        result = self.derive(["models.py"])
        packet = local_context_packet(self.state, result["coding_units"][0])
        self.assertGreater(packet["target_context_truncated_count"], 0)
        self.assertLessEqual(len(packet["text"].encode()), MAX_CONTEXT_BYTES)
        self.assertLessEqual(packet["target_context_chars"], MAX_CONTEXT_FILE_BYTES + 200)

    def test_coder_prompt_and_cli_expose_only_bounded_counts(self):
        selected = self.derive(["models.py"])["coding_units"][0]
        captured = []
        def fake_worker(cmd, **_kwargs):
            captured.append(cmd[-1])
            return WorkerResult(124, "", {"worker_total_ms": 180100,
                                          "cleanup_status": "CONFIRMED", "remaining_processes": 0})
        with patch.object(coder, "verify_execution_contract"), \
                patch.object(coder, "run_worker", fake_worker):
            result = coder.coder_node({**self.state, "coding_units": [selected], "unit_index": 0})
        self.assertEqual(result["coder_error"], "CODER_TIMEOUT")
        self.assertIn("MODEL_PRIMARY", captured[0])
        self.assertIn("do not re-read a file marked complete", captured[0])
        self.assertIn("do not run tests", captured[0])
        projected = cli._projection({**self.state, **result, "trace": []}, self.repo, "task", {})
        evidence = projected["unit_history"][0]
        self.assertEqual(evidence["target_files_count"], 1)
        self.assertGreater(evidence["coder_prompt_chars"], evidence["local_context_chars"])
        self.assertNotIn("MODEL_PRIMARY", json.dumps(projected))

    def test_successful_coder_context_counts_reach_tested_unit_history(self):
        selected = self.derive(["models.py"])["coding_units"][0]
        with patch.object(coder, "verify_execution_contract"), \
                patch.object(coder, "run_worker", return_value=WorkerResult(0, "done", {})):
            coded = coder.coder_node({**self.state, "coding_units": [selected], "unit_index": 0})
        tested = graph.tested_unit_node({**self.state, **coded, "coding_units": [selected],
                                        "unit_index": 0, "unit_failure_before": 1},
                                       tester_runner=lambda _: {"test_result": "PASS",
                                                                "changed_files": ["models.py"],
                                                                "diff_check_exit": 0})
        self.assertEqual(tested["unit_history"][0]["target_files_count"], 1)
        self.assertEqual(tested["unit_history"][0]["planner_steps_context_count"], 1)


if __name__ == "__main__":
    unittest.main()
