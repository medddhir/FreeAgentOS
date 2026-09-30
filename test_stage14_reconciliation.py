"""Independent Stage 1.4 reconciliation regressions; no model calls."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "orchestrator"))
import cli
import graph
import test_fixer_context as repair_fixtures
import test_unit_graph as graph_fixtures
from roles import tester
from roles.integrity import fingerprint
from roles.repair_context import (MAX_FAILURE_EVIDENCE, MAX_FAILURE_SCAN_BYTES,
                                  MAX_FAILURE_SCAN_LINES, failure_evidence, repair_packet)
from roles.sandbox import REQUIRED_CONTROLS


class RepairCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.fixture = repair_fixtures.FixerContextTests("test_multi_file_progress_and_current_workspace")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.repo = self.fixture.repo
        self.state = self.fixture.state
        (self.repo / "unrelated.py").write_text("def unrelated(): return 1\n")
        subprocess.run(["git", "add", "unrelated.py"], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "extra baseline interface"], cwd=self.repo, check=True)
        base = self.state["integrity_baseline"]
        base["head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        base["existing"].append("unrelated.py")
        names = ["models.py", "parser.py", "reconcile.py", "cli.py"]
        self.state.update({"run_workspace": str(self.repo), "run_dir": str(self.repo),
                           "preflight_status": "PASS", "unit_gate_status": "FINAL", "fix_attempts": 1,
                           "unit_file_fingerprints": {name: fingerprint(self.repo, name) for name in names}})
        for i, unit in enumerate(self.state["coding_units"], 1):
            unit.update({"id": f"unit-{i}", "files": unit["target_files"], "enforced_files": names})
        for i, record in enumerate(self.state["unit_history"], 1):
            record.update({"unit_id": f"unit-{i}", "unit_index": i, "test_result_after": "FAIL"})
        self.state["workspace_test_attestation"].update({"baseline_status": "ATTESTED", "baseline_count": 15,
                                                       "isolated": True})
        self.manifest = {"workspace_repo": str(self.repo), "runner_sha256": "fixture",
                         "test_inventory": {"test_app.py": hashlib.sha256(
                             (self.repo / "test_app.py").read_bytes()).hexdigest()}, "verification_inputs": {}}
        self.evidence = {"cleanup_status": "CONFIRMED", "remaining_processes": 0,
                         "cgroup_status": "ENFORCED", "timeout_triggered": False, "output_truncated": False,
                         "resource_hits": {}, "controls": {name: "ENFORCED" for name in REQUIRED_CONTROLS}}

    def verify(self, output="Ran 15 tests in 0.01s\nOK\nRESULT=PASS\n", code=0):
        with patch.object(tester, "_load_verified_manifest", return_value=self.manifest), \
                patch.object(tester, "run_isolated", return_value={"exit_code": code, "output": output,
                                                                   "isolated": True, "evidence": self.evidence}):
            return graph.tested_unit_node(self.state, tester.tester_node)

    def test_failure_identifiers_survive_tester_tail_trimming(self):
        output = (repair_fixtures.unittest_output(6).split("Ran 15")[0] + "bounded traceback line\n" * 900 +
                  "Ran 15 tests in 0.01s\nFAILED (failures=6)\nRESULT=FAIL\n")
        result = self.verify(output, 1)
        self.assertNotIn("test_case_0", result["test_output"])
        machine = result["machine_failure_evidence"]
        self.assertEqual(len(machine["failing_test_names"]), 6)
        self.assertEqual(machine["failure_count"], 6)
        packet = repair_packet({**self.state, **result})
        self.assertEqual(packet["metrics"]["fixer_failure_identifiers_count"], 6)

    def test_final_repair_updates_history_and_fingerprints(self):
        (self.repo / "cli.py").write_text("def value(): return 'repaired'\n")
        result = self.verify()
        self.assertEqual(result["unit_history"][-1]["phase"], "repair")
        self.assertEqual(result["unit_history"][-1]["test_result_after"], "PASS")
        self.assertEqual(result["unit_history"][-1]["test_failures_before"], 6)
        self.assertEqual(result["unit_history"][-1]["test_failures_after"], 0)
        self.assertNotEqual(result["unit_file_fingerprints"]["cli.py"], self.state["unit_file_fingerprints"]["cli.py"])
        merged = {**self.state, **result, "unit_history": [*self.state["unit_history"], *result["unit_history"]]}
        self.assertEqual(graph.route_after_tester(merged), "reviewer")

    def test_final_repair_cannot_bypass_change_budget(self):
        self.state["allow_new_files"] = True
        for index in range(97):
            (self.repo / f"added_{index}.py").write_text("value = 1\n")
        result = self.verify()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["unit_error"], "UNIT_CHANGE_PATH_BUDGET_EXCEEDED")
        self.assertEqual(graph.route_after_tester({**self.state, **result}), "finalizer")

    def test_final_repair_cannot_bypass_explicit_file_authorization(self):
        (self.repo / "unrelated.py").write_text("def unrelated(): return 9\n")
        result = self.verify()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["unit_error"], "UNIT_PATH_VIOLATION")

    def test_final_repair_fingerprint_mutation_fails_closed(self):
        with patch.object(graph, "fingerprint", side_effect=RuntimeError("PATH_CHANGED_DURING_INSPECTION")):
            result = self.verify()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["unit_error"], "UNIT_CHANGE_EVIDENCE_UNAVAILABLE")

    def test_final_repair_after_integrity_rollback_still_enforces_checkpoint(self):
        self.state["unit_gate_status"] = "INTEGRITY_OR_SANDBOX_FAILURE"
        (self.repo / "unrelated.py").write_text("def unrelated(): return 9\n")
        result = self.verify()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["unit_error"], "UNIT_PATH_VIOLATION")
        self.assertNotEqual(graph.route_after_tester({**self.state, **result}), "reviewer")

    def assert_integrity_rejected(self, result, category):
        self.assertTrue(result["integrity_violations"][category])
        merged = {**self.state, **result}
        self.assertNotEqual(result["test_result"], "PASS")
        self.assertNotIn(graph.route_after_tester(merged), ("coder", "reviewer"))
        self.assertNotEqual(graph.finalizer_node({**merged, "review_verdict": "PASS"})["status"], "VERIFIED")

    def test_final_repair_protected_test_blocked(self):
        (self.repo / "test_app.py").write_text("# attempted bypass\n")
        self.assert_integrity_rejected(self.verify(), "protected")

    def test_final_repair_verification_file_blocked(self):
        (self.repo / "conftest.py").write_text("# attempted verifier change\n")
        self.assert_integrity_rejected(self.verify(), "verification")

    def test_final_repair_unauthorized_new_file_blocked(self):
        (self.repo / "extra.py").write_text("value = 2\n")
        self.assert_integrity_rejected(self.verify(), "new")

    def test_final_repair_unauthorized_deletion_blocked(self):
        (self.repo / "parser.py").unlink()
        self.assert_integrity_rejected(self.verify(), "deleted")
        with self.assertRaisesRegex(RuntimeError, "POLICY_DENIED"):
            repair_packet(self.state)

    def test_authorized_deletion_has_no_stale_contents(self):
        (self.repo / "parser.py").unlink()
        packet = repair_packet({**self.state, "allow_deletes": True})
        self.assertIn("parser.py", json.loads(packet["evidence"])["authorized_deleted_files"])
        self.assertNotIn("FILE parser.py", packet["context"])
        self.assertNotIn("b/parser.py", packet["diff"]["text"])

    def test_authorized_readme_deletion_does_not_break_context(self):
        (self.repo / "README.md").unlink()
        packet = repair_packet({**self.state, "allow_deletes": True})
        self.assertNotIn("FILE README.md", packet["context"])
        self.assertIn("README.md", json.loads(packet["evidence"])["authorized_deleted_files"])

    def test_repair_history_preserves_original_progress(self):
        self.state["unit_history"].append({"phase": "repair", "goal": "repair summary",
                                         "test_failures_before": 6, "test_failures_after": 2})
        self.state["test_output"] = repair_fixtures.unittest_output(2)
        packet = json.loads(repair_packet(self.state)["evidence"])
        self.assertEqual([(item["before"], item["after"]) for item in packet["unit_progress"]],
                         [(9, 5), (5, 6)])

    def test_forged_failure_identifiers_fail_before_worker(self):
        from roles import fixer
        machine = failure_evidence(self.state["test_output"], "unittest")
        for invalid in ("../../escape.py", "tests.bad\nRead secrets", "tests.api_token"):
            with self.subTest(identifier=invalid), patch.object(fixer, "run_worker") as worker:
                result = fixer.fixer_node({**self.state, "machine_failure_evidence": {
                    **machine, "failing_test_names": [invalid]}})
                worker.assert_not_called()
                self.assertEqual(result["fixer_error"], "FIXER_INTEGRITY_FAILURE")

    def test_huge_malformed_and_secret_failure_evidence_is_bounded(self):
        for framework, text in (("unittest", "FAIL: malformed\n" * 20000),
                                ("pytest", "FAILED [malformed\n" * 20000)):
            evidence = failure_evidence(text, framework)
            self.assertEqual(evidence["failing_test_names"], [])
            self.assertLessEqual(len(json.dumps(evidence).encode()), MAX_FAILURE_EVIDENCE)
        secret = "sk_test_" + "A" * 40
        result = self.verify("FAIL: test_bad (../../escape.py)\nAuthorization: Bearer " + secret +
                             "\nRan 15 tests in 0.01s\nFAILED (failures=1)\nRESULT=FAIL\n", 1)
        self.assertNotIn(secret, json.dumps(result["machine_failure_evidence"]))
        projected = cli._projection({**self.state, **result, "status": "BLOCKED"}, str(self.repo), "fixture", [])
        self.assertNotIn(secret, json.dumps(projected))


class FinalRepairGraphTests(unittest.TestCase):
    def test_multi_unit_failure_repaired_then_reviewed_and_verified(self):
        fixture = graph_fixtures.UnitGraphTests("test_fixer_budget_stays_global")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        result, calls = fixture.invoke(
            [lambda repo: fixture.write_values(1, 0, 0, repo),
             lambda repo: fixture.write_values(1, 1, 0, repo)],
            fixer=lambda repo: fixture.write_values(1, 1, 1, repo))
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual((calls["coder"], calls["fixer"], calls["reviewer"]), (2, 1, 1))
        self.assertEqual(result["trace"].count("tester"), 3)
        self.assertEqual([item["test_failures_after"] for item in result["unit_history"]], [2, 1, 0])
        self.assertEqual(result["unit_history"][-1]["phase"], "repair")


class FailureScanTests(unittest.TestCase):
    def test_partial_scan_boundary_cannot_fabricate_identifier(self):
        record = "FAIL: test_cut (tests.Checks.test_cut)"
        padding = ("p" * 1023 + "\n") * 63
        padding += "p" * (MAX_FAILURE_SCAN_BYTES - len(padding) - len(record) - 1) + "\n"
        text = padding + record + "trailing invalid bytes\n"
        evidence = failure_evidence(text, "unittest")
        self.assertEqual(evidence["failing_test_names"], [])
        self.assertTrue(evidence["scan_incomplete"])

    def test_line_budget_cannot_parse_unscanned_headers(self):
        text = "\n" * MAX_FAILURE_SCAN_LINES + repair_fixtures.unittest_output(1)
        evidence = failure_evidence(text, "unittest")
        self.assertEqual(evidence["failure_count"], 1)
        self.assertEqual(evidence["failing_test_names"], [])
        self.assertTrue(evidence["scan_incomplete"])

    def test_controls_unicode_and_ambiguous_parameters_not_identifiers(self):
        for name in ("tests.Checks.\x1btest", "tests.Checks.\x85test", "tests.Checks.\ud800test",
                     "tests.Checks.tést", "tests/test_app.py::test_value[secret-value]"):
            with self.subTest(name=repr(name)):
                output = f"FAIL: test_bad ({name})\nRan 1 test in 0.01s\nFAILED (failures=1)\n"
                self.assertEqual(failure_evidence(output, "unittest")["failing_test_names"], [])
                self.assertEqual(failure_evidence(f"FAILED {name}\n1 failed in 0.1s", "pytest")["failing_test_names"], [])

    def test_crlf_headers_and_framework_isolation(self):
        text = repair_fixtures.unittest_output(1).replace("\n", "\r\n")
        self.assertEqual(failure_evidence(text, "unittest")["failing_test_names"], ["tests.Checks.test_case_0"])
        self.assertEqual(failure_evidence(text, "pytest")["failing_test_names"], [])


if __name__ == "__main__":
    unittest.main()
