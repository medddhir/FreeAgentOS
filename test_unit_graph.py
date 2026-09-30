"""Production graph exercises bounded Coder units with real isolated Tester runs."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
import graph


class UnitGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-unit-graph-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.write_values(0, 0, 0)
        (self.repo / "test_app.py").write_text(
            "import unittest\nfrom app import a,b,c\n"
            "class Values(unittest.TestCase):\n"
            "    def test_a(self): self.assertEqual(a(),1)\n"
            "    def test_b(self): self.assertEqual(b(),1)\n"
            "    def test_c(self): self.assertEqual(c(),1)\n")
        (self.repo / "note.txt").write_text("keep\n")
        for args in (("init", "-q"), ("add", "."),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-qm", "baseline")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def write_values(self, a, b, c, repo=None):
        (repo or self.repo).joinpath("app.py").write_text(
            f"def a(): return {a}\ndef b(): return {b}\ndef c(): return {c}\n")

    def invoke(self, edits, *, steps=3, plan_steps=None, explicit_units=None,
               research=False, review=True, fixer=None,
               task="Implement fixture"):
        calls = {"coder": 0, "research": 0, "reviewer": 0, "fixer": 0,
                 "coder_research_packets": []}
        plan = {"needs_research": research, "research_type": "current_web" if research else "none",
                "research_query": "fixture" if research else "",
                "steps": (plan_steps if plan_steps is not None else
                          [f"Implement stage {i + 1} in app.py" for i in range(steps)])}
        if explicit_units is not None:
            plan["coding_units"] = explicit_units

        def code(state):
            index = calls["coder"]
            calls["coder"] += 1
            calls["coder_research_packets"].append(state.get("research", ""))
            edits[index](Path(state["repo_dir"]))
            return {"trace": [f"coder:unit-{index + 1}"],
                    "worker_history": [{"role": "coder", "unit_id": f"unit-{index + 1}",
                                        "evidence": {"worker_total_ms": 123, "worker_exit_code": 0,
                                                     "worker_first_stdout_byte_ms": 100,
                                                     "timeout_triggered": False,
                                                     "output_truncated": False,
                                                     "resource_hits": {"memory": False}}}]}

        def reviewer(_state):
            calls["reviewer"] += 1
            return {"review_verdict": "PASS" if review else "FAIL", "review_issues": [],
                    "trace": ["reviewer"]}

        def researcher(_state):
            calls["research"] += 1
            return {"research": "fixture packet", "research_source": "fixture",
                    "research_results": 1, "research_error": "", "trace": ["researcher"]}

        def repair(state):
            calls["fixer"] += 1
            if fixer:
                fixer(Path(state["repo_dir"]))
            return {"fix_attempts": state.get("fix_attempts", 0) + 1,
                    "fixer_error": "", "trace": ["fixer:fixture"]}

        with patch("roles.planner._run_planner", return_value=plan), \
                patch.object(graph, "coder_node", code), \
                patch.object(graph, "reviewer_node", reviewer), \
                patch.object(graph, "fixer_node", repair):
            if research:
                with patch.object(graph, "research_validation_node", return_value={
                        "research_validation_passed": True, "trace": ["research_validation"]}), \
                        patch.object(graph, "researcher_node", researcher):
                    result = graph.build_graph().invoke({"repo_dir": str(self.repo),
                                                         "task": task, "trace": []})
            else:
                result = graph.build_graph().invoke({"repo_dir": str(self.repo),
                                                     "task": task, "trace": []})
        return result, calls

    def test_meta_heavy_small_plan_uses_one_coder_tester_and_reviewer(self):
        plan = ["Read test_app.py to understand expectations",
                "Inspect app.py and identify the discrepancy",
                "Correct the app.py implementation",
                "Run the existing tests",
                "Verify the smallest diff"]
        result, calls = self.invoke([lambda repo: self.write_values(1, 1, 1, repo)],
                                    plan_steps=plan, task="Fix app values")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual((calls["coder"], calls["reviewer"], result["trace"].count("tester")),
                         (1, 1, 1))
        self.assertEqual(len(result["coding_units"]), 1)

    def test_explicit_calculator_plan_uses_one_coder(self):
        plan = ["Inspect app.py and its tests", "Fix the app.py implementation",
                "Run existing tests"]
        units = [{"goal": "Fix the app.py implementation and verify tests",
                  "target_files": ["app.py"]}]
        result, calls = self.invoke([lambda repo: self.write_values(1, 1, 1, repo)],
                                    plan_steps=plan, explicit_units=units)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["unit_derivation_source"], "PLANNER_EXPLICIT")
        self.assertEqual((calls["coder"], calls["reviewer"], result["trace"].count("tester")),
                         (1, 1, 1))

    def test_explicit_two_units_test_between_and_single_review(self):
        plan = ["Inspect models and tests", "Implement model and parsing fixes",
                "Handle duplicate input", "Implement final report behavior",
                "Run the existing tests"]
        units = [{"goal": "Implement models, parsing, and duplicate handling",
                  "target_files": ["app.py"]},
                 {"goal": "Implement report behavior and verify tests",
                  "target_files": ["app.py"]}]
        result, calls = self.invoke([lambda repo: self.write_values(1, 0, 0, repo),
                                     lambda repo: self.write_values(1, 1, 1, repo)],
                                    plan_steps=plan, explicit_units=units, research=True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["unit_derivation_source"], "PLANNER_EXPLICIT")
        self.assertEqual((calls["coder"], calls["research"], calls["reviewer"]), (2, 1, 1))
        self.assertEqual([event for event in result["trace"] if event.startswith("coder:unit-")
                          or event == "tester"],
                         ["coder:unit-1", "tester", "coder:unit-2", "tester"])
        self.assertEqual(calls["coder_research_packets"], ["fixture packet"] * 2)

    def test_invalid_explicit_units_never_reach_coder(self):
        plan = ["Inspect app.py", "Implement the repair", "Run tests"]
        units = [{"goal": "Implement the repair", "target_files": ["app.py"], "skip_tests": True}]
        result, calls = self.invoke([], plan_steps=plan, explicit_units=units)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["planner_error_code"], "PLANNER_CODING_UNITS_INVALID")
        self.assertEqual(calls["coder"], 0)

    def test_two_units_test_between_and_failure_decreases(self):
        result, calls = self.invoke([lambda repo: self.write_values(1, 0, 0, repo),
                                     lambda repo: self.write_values(1, 1, 1, repo)])
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(calls["coder"], 2)
        self.assertEqual(calls["reviewer"], 1)
        self.assertEqual([x["test_failures_after"] for x in result["unit_history"]], [2, 0])
        self.assertEqual(result["trace"].count("tester"), 2)
        self.assertEqual(result["unit_history"][0]["worker_total_ms"], 123)
        self.assertEqual((self.repo / "app.py").read_text(),
                         "def a(): return 0\ndef b(): return 0\ndef c(): return 0\n")

    def test_same_failure_count_may_continue(self):
        result, calls = self.invoke([lambda repo: (repo / "app.py").write_text(
                                         (repo / "app.py").read_text() + "# intermediate\n"),
                                     lambda repo: self.write_values(1, 1, 1, repo)])
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual([x["test_failures_after"] for x in result["unit_history"]], [3, 0])
        self.assertEqual(calls["coder"], 2)

    def test_failure_increase_blocks_next_unit(self):
        self.write_values(0, 1, 1)
        subprocess.run(["git", "add", "app.py"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "one failure"], cwd=self.repo, check=True, capture_output=True)
        result, calls = self.invoke([lambda repo: self.write_values(0, 0, 1, repo),
                                     lambda repo: self.write_values(1, 1, 1, repo)])
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["unit_error"], "UNIT_TEST_FAILURES_INCREASED")
        self.assertEqual(calls["coder"], 1)

    def test_path_violation_blocks(self):
        result, calls = self.invoke([lambda repo: (repo / "note.txt").write_text("unrelated\n"),
                                     lambda repo: self.write_values(1, 1, 1, repo)],
                                    task="Only edit app.py while implementing fixture")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["unit_error"], "UNIT_PATH_VIOLATION")
        self.assertEqual(calls["coder"], 1)

    def test_three_units_reuse_research_and_one_final_reviewer(self):
        result, calls = self.invoke([lambda repo: self.write_values(1, 0, 0, repo),
                                     lambda repo: self.write_values(1, 1, 0, repo),
                                     lambda repo: self.write_values(1, 1, 1, repo)],
                                    steps=5, research=True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual((calls["coder"], calls["research"], calls["reviewer"]), (3, 1, 1))
        self.assertEqual(result["trace"].count("tester"), 3)
        self.assertEqual([event for event in result["trace"] if event.startswith("coder:unit-") or event == "tester"],
                         ["coder:unit-1", "tester", "coder:unit-2", "tester", "coder:unit-3", "tester"])
        self.assertEqual(calls["coder_research_packets"], ["fixture packet"] * 3)
        self.assertEqual(result["unit_index"], 3)

    def test_fixer_budget_stays_global(self):
        result, calls = self.invoke([lambda repo: self.write_values(1, 0, 0, repo),
                                     lambda repo: self.write_values(1, 0, 0, repo)], fixer=lambda _repo: None)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["fix_attempts"], 2)
        self.assertEqual(calls["fixer"], 2)

    def test_reviewer_is_single_final_call_on_rejection(self):
        result, calls = self.invoke([lambda repo: self.write_values(1, 1, 1, repo)],
                                    steps=2, review=False)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(calls["reviewer"], 1)
        self.assertEqual(calls["fixer"], 0)


if __name__ == "__main__":
    unittest.main()
