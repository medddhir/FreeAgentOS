"""Machine-owned repair context fixtures; no provider calls."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "orchestrator"))
import cli
import graph
from roles import fixer
from roles.repair_context import (MAX_DIFF_BYTES, MAX_FAILURE_EVIDENCE,
                                  MAX_FAILURE_IDENTIFIERS, MAX_SECONDARY_OUTPUT,
                                  failure_evidence, repair_packet)
from roles.coding_units import MAX_CONTEXT_BYTES
from roles.worker import WorkerResult, WorkerBoundaryError


def unittest_output(count):
    return "\n".join(f"FAIL: test_case_{i} (tests.Checks.test_case_{i})\n"
                     "AssertionError: mismatch" for i in range(count)) + \
        f"\nRan 15 tests in 0.01s\nFAILED (failures={count})\n"


class FixerContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-repair-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        for name in ("models.py", "parser.py", "reconcile.py", "cli.py"):
            (self.repo / name).write_text("def value():\n    return 'baseline'\n")
        (self.repo / "test_app.py").write_text("# protected test fixture\n")
        (self.repo / "README.md").write_text("A compact multi-file application.\n")
        for args in (("init", "-q"), ("add", "."),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-qm", "baseline")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        for name in ("models.py", "parser.py", "reconcile.py", "cli.py"):
            (self.repo / name).write_text("def value():\n    return 'current_implemented'\n")
        self.state = {"task": "Complete this application", "repo_dir": str(self.repo),
                      "integrity_baseline": {"repo": str(self.repo), "head": head,
                                             "existing": [p.name for p in self.repo.iterdir()]},
                      "workspace_test_attestation": {"framework": "unittest", "baseline_failures": 9},
                      "test_result": "FAIL", "test_exit": 1, "diff_check_exit": 0,
                      "test_output": unittest_output(6), "unit_index": 2,
                      "coding_units": [{"goal": "Implement core", "target_files": ["reconcile.py"]},
                                       {"goal": "Implement CLI", "target_files": ["cli.py"]}],
                      "unit_history": [{"goal": "Implement core", "test_failures_before": 9,
                                        "test_failures_after": 5,
                                        "changed_files": ["models.py", "parser.py", "reconcile.py"]},
                                       {"goal": "Implement CLI", "test_failures_before": 5,
                                        "test_failures_after": 6, "changed_files": ["cli.py"]}],
                      "repo_facts": {"relevant_files": ["models.py", "parser.py", "reconcile.py", "cli.py"]}}

    def test_multi_file_progress_and_current_workspace(self):
        packet = repair_packet(self.state)
        evidence = json.loads(packet["evidence"])
        self.assertEqual(evidence["baseline_failures"], 9)
        self.assertEqual([(p["before"], p["after"]) for p in evidence["unit_progress"]], [(9, 5), (5, 6)])
        self.assertEqual(len(evidence["failure_evidence"]["failing_test_names"]), 6)
        self.assertEqual(set(evidence["changed_files"]), {"models.py", "parser.py", "reconcile.py", "cli.py"})
        self.assertIn("current_implemented", packet["context"])
        self.assertNotIn("return 'baseline'", packet["context"])
        self.assertIn("-    return 'baseline'", packet["diff"]["text"])
        self.assertIn("+    return 'current_implemented'", packet["diff"]["text"])
        self.assertEqual(packet["metrics"]["fixer_previous_failure_count"], 5)
        self.assertEqual(packet["metrics"]["fixer_current_failure_count"], 6)

    def test_prompt_tools_metrics_and_second_attempt(self):
        result = WorkerResult(0, "repaired", {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
        with patch.object(fixer, "run_worker", return_value=result) as worker:
            update = fixer.fixer_node(self.state)
        command = worker.call_args.args[0]
        prompt = command[-1]
        self.assertIn("do not restart", prompt)
        self.assertIn("deterministic Tester owns verification", prompt)
        self.assertIn("current_implemented", prompt)
        self.assertNotIn("Bash", command)
        self.assertEqual(worker.call_args.kwargs["timeout"], 180)
        metrics = update["worker_history"][0]["context"]
        self.assertEqual(metrics["fixer_prompt_chars"], len(prompt))
        projected = cli._projection({**self.state, **update, "status": "UNVERIFIED"}, str(self.repo), self.state["task"], [])
        self.assertEqual(projected["resource_evidence"]["workers"][0]["context"], metrics)
        again = repair_packet({**self.state, "worker_history": update["worker_history"],
                               "test_output": unittest_output(2)})
        self.assertEqual(again["metrics"]["fixer_previous_failure_count"], 6)
        self.assertEqual(again["metrics"]["fixer_current_failure_count"], 2)

    def test_identifiers_and_secondary_evidence_bounded(self):
        evidence = failure_evidence(unittest_output(1000), "unittest")
        self.assertLessEqual(len(evidence["failing_test_names"]), MAX_FAILURE_IDENTIFIERS)
        self.assertLessEqual(len(evidence["secondary_output"].encode()), MAX_SECONDARY_OUTPUT)
        self.assertFalse(evidence["identifiers_complete"])
        self.state["test_output"] = "Traceback\n" + "x" * 1000000
        packet = repair_packet(self.state)
        self.assertLessEqual(len(packet["evidence"].encode()), MAX_FAILURE_EVIDENCE)
        self.assertEqual(json.loads(packet["evidence"])["failure_evidence"]["format"], "UNKNOWN")

    def test_pytest_identifiers_and_unknown_formats(self):
        output = "FAILED tests/test_app.py::test_value - AssertionError\nERROR tests/test_app.py::test_other\n2 failed in 0.1s"
        evidence = failure_evidence(output, "pytest")
        self.assertEqual(evidence["failure_count"], 2)
        self.assertEqual(len(evidence["failing_test_names"]), 2)
        for framework, malformed in (("unittest", "FAIL: malformed"), ("pytest", "FAILED [broken"),
                                     ("unknown", output)):
            self.assertEqual(failure_evidence(malformed, framework)["format"], "UNKNOWN")

    def test_tail_preserves_tester_summary(self):
        evidence = failure_evidence("... output truncated ...\n" + "x" * 7000 +
                                    "\n" + unittest_output(6), "unittest")
        self.assertEqual(evidence["failure_count"], 6)
        self.assertEqual(len(evidence["failing_test_names"]), 6)

    def test_pending_new_unit_file_does_not_require_existing_contents(self):
        self.state["coding_units"][1]["target_files"] = ["pending.py"]
        packet = repair_packet({**self.state, "allow_new_files": True})
        self.assertNotIn("FILE pending.py", packet["context"])
        self.assertIn("Implement CLI", packet["evidence"])

    def test_failure_text_never_selects_paths(self):
        output = "\n".join(["FAIL: test_bad (../../escape.py)", "FAIL: test_bad (/etc/passwd)",
                             "FAIL: test_bad (tests.\x01bad)", "FAIL: test_bad (tests.api_token)",
                             "FAILED /etc/passwd", "File /tmp/unsafe.py", "File test_app.py",
                             "File orchestrator/graph.py", "Ran 15 tests in 0.01s", "FAILED (failures=6)"])
        packet = repair_packet({**self.state, "test_output": output})
        self.assertEqual(json.loads(packet["evidence"])["failure_evidence"]["failing_test_names"], [])
        self.assertNotIn("test_app.py", json.loads(packet["evidence"])["changed_files"])
        self.assertNotIn("FILE test_app.py", packet["context"])

    def test_secret_evidence_and_source_diff_exclusion(self):
        secret = "sk_test_" + "A" * 40
        self.state["test_output"] += "\nAuthorization: Bearer " + secret + "\npassword=fixture_do_not_leak"
        (self.repo / "parser.py").write_text("API_KEY = '" + secret + "'\n")
        packet = repair_packet(self.state)
        self.assertNotIn(secret, json.dumps(packet))
        self.assertNotIn("fixture_do_not_leak", json.dumps(packet))
        self.assertNotIn("FILE parser.py", packet["context"])
        self.assertNotIn("b/parser.py", packet["diff"]["text"])
        with patch.object(fixer, "run_worker", return_value=WorkerResult(0, "ok", {})):
            update = fixer.fixer_node(self.state)
        self.assertNotIn(secret, json.dumps(cli._projection({**self.state, **update, "status": "UNVERIFIED"}, str(self.repo), self.state["task"], [])))

    def test_unsafe_candidates_fail_before_worker(self):
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                path = self.repo / "parser.py"
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(self.repo / "models.py")
                elif kind == "hardlink":
                    os.link(self.repo / "models.py", path)
                else:
                    os.mkfifo(path)
                with patch.object(fixer, "run_worker") as worker:
                    result = fixer.fixer_node(self.state)
                self.assertEqual(result["status"], "BLOCKED")
                self.assertEqual(result["fixer_error"], "FIXER_INTEGRITY_FAILURE")
                worker.assert_not_called()
                path.unlink()
                path.write_text("# safe again\n")

    def test_new_file_requires_controller_permission(self):
        (self.repo / "helper.py").write_text("def helper():\n    return 2\n")
        with self.assertRaisesRegex(RuntimeError, "POLICY_DENIED"):
            repair_packet(self.state)
        subprocess.run(["git", "add", "helper.py"], cwd=self.repo, check=True)
        with self.assertRaisesRegex(RuntimeError, "POLICY_DENIED"):
            repair_packet(self.state)
        subprocess.run(["git", "reset", "-q", "--", "helper.py"], cwd=self.repo, check=True)
        packet = repair_packet({**self.state, "allow_new_files": True})
        self.assertIn("FILE helper.py", packet["context"])
        self.assertIn("b/helper.py", packet["diff"]["text"])

    def test_protected_and_verification_files_excluded(self):
        (self.repo / "test_app.py").write_text("# changed protected fixture\n")
        (self.repo / "pyproject.toml").write_text("# verifier configuration\n")
        self.state["repo_facts"]["relevant_files"] += ["test_app.py", "pyproject.toml"]
        packet = repair_packet(self.state)
        self.assertNotIn("FILE test_app.py", packet["context"])
        self.assertNotIn("pyproject.toml", packet["context"])
        self.assertNotIn("test_app.py", packet["diff"]["text"])

    def test_context_and_diff_limits(self):
        for name in ("models.py", "parser.py", "reconcile.py", "cli.py"):
            (self.repo / name).write_text("print('bounded')\n" * 3000)
        packet = repair_packet(self.state)
        self.assertLessEqual(len(packet["context"].encode()), MAX_CONTEXT_BYTES)
        self.assertLessEqual(len(packet["diff"]["text"].encode()), MAX_DIFF_BYTES)
        self.assertGreater(packet["diff"]["omitted_or_truncated_files"], 0)

    def test_current_content_after_rollback(self):
        (self.repo / "parser.py").write_text("def value():\n    return 'baseline'\n")
        packet = repair_packet({**self.state, "rollback_evidence": {"restored": ["parser.py"]}})
        self.assertIn("FILE parser.py", packet["context"])
        self.assertNotIn("b/parser.py", packet["diff"]["text"])
        self.assertTrue(json.loads(packet["evidence"])["rollback_completed"])

    def test_global_attempt_cap_and_failure_taxonomy(self):
        for attempt in (2, 3):
            with patch.object(fixer, "run_worker") as worker:
                result = fixer.fixer_node({**self.state, "fix_attempts": attempt})
            worker.assert_not_called()
            self.assertEqual(result["status"], "BLOCKED")
        with patch.object(fixer, "run_worker", return_value=WorkerResult(124, "", {})):
            result = fixer.fixer_node(self.state)
        self.assertEqual(result["fixer_error"], "FIXER_TIMEOUT")
        self.assertEqual(graph.route_after_fixer(result), "finalizer")
        with patch.object(fixer, "run_worker", side_effect=WorkerBoundaryError(
                "WORKER_BOUNDARY_UNVERIFIED", {"cleanup_status": "UNPROVEN"})):
            result = fixer.fixer_node(self.state)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["worker_history"][0]["evidence"]["cleanup_status"], "UNPROVEN")
        self.assertEqual(result["fixer_error"], "FIXER_CLEANUP_FAILED")

    def test_contract_rejection_precedes_context_and_worker(self):
        with patch.object(fixer, "verify_execution_contract", side_effect=RuntimeError("fixture")), \
                patch.object(fixer, "repair_packet") as packet, \
                patch.object(fixer, "run_worker") as worker:
            result = fixer.fixer_node(self.state)
        packet.assert_not_called()
        worker.assert_not_called()
        self.assertEqual(result["fixer_error"], "FIXER_INTEGRITY_FAILURE")
        self.assertEqual(result["status"], "BLOCKED")

    def test_worker_exception_diagnostic_is_sanitized(self):
        secret = "fixture_credential_should_not_appear"
        with patch.object(fixer, "run_worker", side_effect=RuntimeError(secret)):
            result = fixer.fixer_node(self.state)
        self.assertEqual(result["fixer_error"], "FIXER_WORKER_FAILURE")
        self.assertNotIn(secret, json.dumps(result))

    def test_secret_baseline_diff_never_copied(self):
        path = self.repo / "parser.py"
        secret = "ghp_" + "B" * 40
        path.write_text("API_KEY = '" + secret + "'\n")
        subprocess.run(["git", "add", "parser.py"], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "sensitive baseline"], cwd=self.repo, check=True)
        self.state["integrity_baseline"]["head"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        path.write_text("def value():\n    return 'safe_current'\n")
        packet = repair_packet(self.state)
        self.assertIn("safe_current", packet["context"])
        self.assertNotIn(secret, json.dumps(packet))
        self.assertNotIn("b/parser.py", packet["diff"]["text"])


if __name__ == "__main__":
    unittest.main()
