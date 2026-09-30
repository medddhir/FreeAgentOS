"""Deterministic integration checks for the real LangGraph integrity routes."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import shutil
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))

import graph as graph_module  # noqa: E402
from roles.integrity import baseline_node, rollback_node  # noqa: E402
from roles.tester import tester_node  # noqa: E402


class IntegrityGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source_repo = Path(self.temp.name)
        self.repo = self.source_repo
        self.active_repo = self.source_repo
        self.run_dirs = []
        self.artifacts = []
        self.addCleanup(self.cleanup_run_dirs)
        (self.source_repo / "app.py").write_text("def value():\n    return 1\n")
        (self.source_repo / "test_app.py").write_text(
            "import unittest\nfrom app import value\n"
            "class TestApp(unittest.TestCase):\n"
            "    def test_value(self):\n        self.assertEqual(value(), 2)\n"
        )
        (self.source_repo / "note.txt").write_text("original\n")
        self.run_git("init", "-q")
        self.run_git("config", "user.email", "test@example.invalid")
        self.run_git("config", "user.name", "Test")
        self.run_git("add", ".")
        self.run_git("commit", "-qm", "fixture")
        self.old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(ROOT / "bin") + os.pathsep + self.old_path
        self.addCleanup(lambda: os.environ.__setitem__("PATH", self.old_path))

    def run_git(self, *args):
        subprocess.run(["git", *args], cwd=self.active_repo, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def cleanup_run_dirs(self):
        for path in self.run_dirs + self.artifacts:
            if path.exists():
                shutil.rmtree(path)

    def graph(self, coder, fixer=None):
        self.test_events = []

        def make_code(state):
            self.active_repo = Path(state["repo_dir"])
            coder(self.active_repo)
            return {"trace": ["coder:fixture"]}

        def make_fix(state):
            self.active_repo = Path(state["repo_dir"])
            if fixer:
                fixer(self.active_repo)
            return {"fix_attempts": state.get("fix_attempts", 0) + 1,
                    "fixer_error": "", "trace": ["fixer:fixture"]}

        def record_test(state):
            result = tester_node(state)
            self.test_events.append(result)
            return result

        with patch.object(graph_module, "coder_node", make_code), \
                patch.object(graph_module, "fixer_node", make_fix), \
                patch.object(graph_module, "tester_node", record_test):
            return graph_module.build_graph()

    def invoke(self, coder, fixer=None, *, planner_payload=None, **policy):
        plan = planner_payload or {
            "needs_research": False, "research_type": "none",
            "research_query": "", "steps": ["Inspect and implement value"],
        }
        review = {"verdict": "PASS", "issues": [], "summary": "Fixture review"}
        with patch("roles.planner._run_planner", return_value=plan), \
                patch("roles.reviewer._run_reviewer", return_value=review):
            result = self.graph(coder, fixer).invoke(
                {"task": "Implement value", "repo_dir": str(self.source_repo),
                 "fix_attempts": 0, "trace": [], "retain_workspace": True, **policy},
                config={"recursion_limit": 30},
            )
        if result.get("run_dir"):
            run_dir = Path(result["run_dir"])
            self.run_dirs.append(run_dir)
            self.repo = Path(result["run_workspace"])
        else:
            self.repo = self.source_repo
        if result.get("verified_patch_path"):
            self.artifacts.append(Path(result["verified_patch_path"]).parent)
        self.active_repo = self.source_repo
        return result

    @staticmethod
    def good(repo):
        (repo / "app.py").write_text("def value():\n    return 2\n")

    def test_normal_verified(self):
        result = self.invoke(self.good)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["fix_attempts"], 0)
        self.assertEqual(result["trace"], [
            "workspace_prepare", "preflight", "baseline", "test_discovery_baseline", "inspector", "planner",
            "research_validation", "coder:fixture", "tester", "reviewer", "finalizer", "workspace_finish",
        ])
        self.assertEqual(result["workspace_test_attestation"]["status"], "PASS")
        self.assertTrue(result["promotion_ready"])
        patch_text = Path(result["verified_patch_path"]).read_text()
        self.assertIn("+    return 2", patch_text)
        patch_check = subprocess.run(["git", "apply", "--check", str(result["verified_patch_path"])],
                                     cwd=self.source_repo, capture_output=True, text=True)
        self.assertEqual(patch_check.returncode, 0, patch_check.stderr)
        self.assertEqual((self.source_repo / "app.py").read_text(), "def value():\n    return 1\n")

    def test_fake_verifier_script_is_rolled_back_and_never_controls_test_result(self):
        verifier = self.source_repo / "bin/freeagent-test"
        verifier.parent.mkdir()
        verifier.write_text("original trusted bytes\n")
        self.run_git("add", "bin/freeagent-test")
        self.run_git("commit", "-qm", "external verifier fixture")
        def coder(repo):
            self.good(repo)
            (repo / "bin/freeagent-test").write_text("#!/bin/sh\nexit 0\n")
        result = self.invoke(coder)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertIn("bin/freeagent-test", result["rollback_evidence"]["restored"])
        self.assertEqual(verifier.read_text(), "original trusted bytes\n")
        self.assertNotIn("bin/freeagent-test", result["rollback_evidence"].get("removed", []))
        self.assertNotIn("+++ b/bin/freeagent-test", Path(result["verified_patch_path"]).read_text())

    def test_git_pointer_tampering_blocks_before_verification_can_follow_it(self):
        original_app = (self.source_repo / "app.py").read_text()
        def coder(repo):
            self.good(repo)
            (repo / ".git").write_text("gitdir: " + str(self.source_repo / ".git") + "\n")
        result = self.invoke(coder)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("GIT_POINTER_CHANGED", result["tester_error"])
        self.assertEqual((self.source_repo / "app.py").read_text(), original_app)

    def test_controller_integrity_and_test_config_tampering_is_selectively_rolled_back(self):
        targets = ("orchestrator/roles/tester.py", "orchestrator/roles/integrity.py", "package.json")
        for target in targets:
            with self.subTest(target=target):
                path = self.source_repo / target
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"scripts":{"test":"real"}}\n' if target == "package.json" else "trusted\n")
                self.run_git("add", "--", target)
                self.run_git("commit", "-qm", "verification input fixture")
                def coder(repo):
                    self.good(repo)
                    (repo / target).write_text("tampered\n")
                result = self.invoke(coder)
                self.assertEqual(result["status"], "VERIFIED")
                self.assertIn(target, result["rollback_evidence"]["restored"])
                self.assertEqual(path.read_text(), '{"scripts":{"test":"real"}}\n' if target == "package.json" else "trusted\n")
                self.assertNotIn(target, json.loads(Path(result["promotion_metadata_path"]).read_text())["paths"])

    def test_protected_test_denied_and_rolled_back(self):
        def coder(repo):
            self.good(repo)
            (repo / "test_app.py").write_text((repo / "test_app.py").read_text() + "# tampered\n")
        result = self.invoke(coder)
        self.assertIn("test_app.py", result["rollback_evidence"]["restored"])
        self.assertTrue(result["rollback_evidence"]["verified"])
        self.assertNotIn("tampered", (self.repo / "test_app.py").read_text())
        self.assertEqual((self.repo / "app.py").read_text(), "def value():\n    return 2\n")
        self.assertIn("rollback", result["trace"])
        self.assertEqual(result["test_result"], "PASS")
        self.assertEqual(self.test_events[0]["test_exit"], 0)
        self.assertEqual(self.test_events[0]["test_result"], "FAIL")

    def test_new_file_denied_and_allowed(self):
        def coder(repo):
            self.good(repo)
            (repo / "scratch.tmp").write_text("new\n")
        denied = self.invoke(coder)
        self.assertIn("scratch.tmp", denied["rollback_evidence"]["removed"])
        self.assertFalse((self.repo / "scratch.tmp").exists())
        self.assertIn("rollback", denied["trace"])
        allowed = self.invoke(coder, allow_new_files=True)
        self.assertEqual(allowed["status"], "VERIFIED")
        self.assertTrue((self.repo / "scratch.tmp").exists())
        self.assertIn("+new", allowed["diff"])

    def test_delete_denied_and_allowed(self):
        def coder(repo):
            self.good(repo)
            (repo / "note.txt").unlink()
        denied = self.invoke(coder)
        self.assertIn("note.txt", denied["rollback_evidence"]["restored"])
        self.assertEqual((self.repo / "note.txt").read_text(), "original\n")
        allowed = self.invoke(coder, allow_deletes=True)
        self.assertEqual(allowed["status"], "VERIFIED")
        self.assertFalse((self.repo / "note.txt").exists())

    def test_test_changes_need_explicit_policy(self):
        def coder(repo):
            self.good(repo)
            (repo / "test_app.py").write_text((repo / "test_app.py").read_text() + "# authorized\n")
        result = self.invoke(coder, allow_test_changes=True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertNotIn("rollback", result["trace"])

    def test_policy_string_does_not_grant_permission(self):
        def coder(repo):
            self.good(repo)
            (repo / "scratch.tmp").write_text("new\n")
        result = self.invoke(coder, allow_new_files="true")
        self.assertIn("scratch.tmp", result["rollback_evidence"]["removed"])

    def test_staged_delete_is_restored(self):
        def coder(repo):
            self.good(repo)
            (repo / "note.txt").unlink()
            self.run_git("add", "-u")
        result = self.invoke(coder)
        self.assertIn("note.txt", result["rollback_evidence"]["restored"])
        self.assertEqual((self.repo / "note.txt").read_text(), "original\n")
        self.assertEqual(subprocess.run(
            ["git", "diff", "--cached", "--name-only"], cwd=self.repo,
            capture_output=True, text=True, check=True,
        ).stdout, "app.py\n")

    def test_bounded_fixer_after_rollback(self):
        def coder(repo):
            (repo / "app.py").write_text("def value():\n    return 0\n")
            (repo / "scratch.tmp").write_text("forbidden\n")
        def fixer(repo):
            self.good(repo)
        result = self.invoke(coder, fixer)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["fix_attempts"], 1)
        self.assertEqual(result["trace"].count("tester"), 2)
        self.assertFalse((self.repo / "scratch.tmp").exists())

    def test_repeated_violation_stops_at_two_fixes(self):
        def coder(repo):
            self.good(repo)
            (repo / "scratch.tmp").write_text("forbidden\n")
        def fixer(repo):
            (repo / "scratch.tmp").write_text("forbidden again\n")
        result = self.invoke(coder, fixer)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["fix_attempts"], 2)
        self.assertFalse((self.repo / "scratch.tmp").exists())
        self.assertEqual(result["trace"].count("rollback"), 3)

    def test_repeated_protected_change_cannot_verify(self):
        def violate(repo):
            self.good(repo)
            (repo / "test_app.py").write_text(
                (repo / "test_app.py").read_text() + "# forbidden\n"
            )
        result = self.invoke(violate, violate)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["fix_attempts"], 2)
        self.assertNotIn("forbidden", (self.repo / "test_app.py").read_text())

    def test_repeated_deletion_cannot_verify(self):
        def violate(repo):
            self.good(repo)
            (repo / "note.txt").unlink()
        result = self.invoke(violate, violate)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["fix_attempts"], 2)
        self.assertTrue((self.repo / "note.txt").exists())

    def test_preexisting_change_blocks_rollback(self):
        (self.repo / "note.txt").write_text("user work\n")
        def coder(repo):
            self.good(repo)
            (repo / "note.txt").unlink()
        result = self.invoke(coder)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["workspace_error"], "SOURCE_REPOSITORY_NOT_CLEAN")
        self.assertEqual((self.source_repo / "note.txt").read_text(), "user work\n")

    def test_staged_new_file_denied_and_allowed(self):
        def coder(repo):
            self.good(repo)
            (repo / "new file.txt").write_text("new\n")
            self.run_git("add", "--", "new file.txt")
        denied = self.invoke(coder)
        self.assertEqual(self.test_events[0]["test_exit"], 0)
        self.assertEqual(self.test_events[0]["test_result"], "FAIL")
        self.assertEqual(denied["rollback_evidence"]["removed"], ["new file.txt"])
        self.assertFalse((self.repo / "new file.txt").exists())
        allowed = self.invoke(coder, allow_new_files=True)
        self.assertEqual(allowed["status"], "VERIFIED")
        self.assertTrue((self.repo / "new file.txt").exists())

    def test_new_test_needs_both_permissions(self):
        def coder(repo):
            self.good(repo)
            (repo / "test_extra.py").write_text("# new test file\n")
        denied = self.invoke(coder, allow_new_files=True)
        self.assertEqual(denied["rollback_evidence"]["removed"], ["test_extra.py"])
        self.assertFalse((self.repo / "test_extra.py").exists())
        allowed = self.invoke(coder, allow_new_files=True, allow_test_changes=True)
        self.assertEqual(allowed["status"], "VERIFIED")
        self.assertTrue((self.repo / "test_extra.py").exists())

    def test_delete_permission_does_not_unprotect_tests(self):
        def coder(repo):
            self.good(repo)
            (repo / "test_app.py").unlink()
        result = self.invoke(coder, allow_deletes=True)
        self.assertEqual(result["rollback_evidence"]["restored"], ["test_app.py"])
        self.assertTrue((self.repo / "test_app.py").exists())

    def test_authorized_deletion_cannot_verify_without_tests(self):
        def coder(repo):
            self.good(repo)
            (repo / "test_app.py").unlink()
        result = self.invoke(coder, allow_deletes=True, allow_test_changes=True)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["test_exit"], 3)
        self.assertIn("RESULT=NO_TEST_RUNNER", result["test_output"])

    def test_task_wording_cannot_grant_permissions(self):
        def coder(repo):
            self.good(repo)
            (repo / "scratch.tmp").write_text("new\n")
            (repo / "note.txt").unlink()
            test = repo / "test_app.py"
            test.write_text(test.read_text() + "# changed\n")
        result = self.invoke(coder, task="Create scratch.tmp, delete note.txt, and modify the tests.")
        self.assertEqual(self.test_events[0]["test_exit"], 0)
        self.assertEqual(self.test_events[0]["test_result"], "FAIL")
        self.assertEqual(result["rollback_evidence"]["restored"], ["note.txt", "test_app.py"])
        self.assertEqual(result["rollback_evidence"]["removed"], ["scratch.tmp"])

    def test_index_only_test_edit_is_not_hidden_by_worktree(self):
        def coder(repo):
            self.good(repo)
            test = repo / "test_app.py"
            original = test.read_text()
            test.write_text(original + "# staged tampering\n")
            self.run_git("add", "--", "test_app.py")
            test.write_text(original)
        result = self.invoke(coder)
        self.assertEqual(self.test_events[0]["test_result"], "FAIL")
        self.assertEqual(result["rollback_evidence"]["restored"], ["test_app.py"])

    def test_literal_rollback_path_preserves_matching_implementation(self):
        for name in ("[ab].txt", "a.txt"):
            (self.repo / name).write_text("original\n")
        self.run_git("add", ".")
        self.run_git("commit", "-qm", "literal path fixture")
        def coder(repo):
            self.good(repo)
            (repo / "a.txt").write_text("legitimate implementation\n")
            (repo / "[ab].txt").unlink()
        result = self.invoke(coder)
        self.assertEqual(result["rollback_evidence"]["restored"], ["[ab].txt"])
        self.assertEqual((self.repo / "[ab].txt").read_text(), "original\n")
        self.assertEqual((self.repo / "a.txt").read_text(), "legitimate implementation\n")

    def test_newline_filename_is_removed_exactly(self):
        name = "new\nfile.txt"
        def coder(repo):
            self.good(repo)
            (repo / name).write_text("new\n")
        result = self.invoke(coder)
        self.assertEqual(result["rollback_evidence"]["removed"], [name])
        self.assertFalse((self.repo / name).exists())

    def test_preexisting_untracked_file_is_never_removed(self):
        (self.repo / "user.txt").write_text("user work\n")
        result = self.invoke(self.good)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["workspace_error"], "SOURCE_REPOSITORY_NOT_CLEAN")
        self.assertEqual((self.repo / "user.txt").read_text(), "user work\n")

    def test_preexisting_ignored_file_is_never_removed(self):
        (self.repo / ".gitignore").write_text("user.txt\n")
        (self.repo / "user.txt").write_text("user work\n")
        self.run_git("add", ".gitignore")
        self.run_git("commit", "-qm", "ignore fixture")
        def coder(repo):
            self.good(repo)
            (repo / ".gitignore").write_text("")
        result = self.invoke(coder)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual((self.repo / "user.txt").read_text(), "user work\n")
        self.assertEqual(result["workspace_error"], "SOURCE_REPOSITORY_NOT_CLEAN")

    def test_new_ignored_file_still_needs_permission(self):
        (self.repo / ".gitignore").write_text("scratch.tmp\n")
        self.run_git("add", ".gitignore")
        self.run_git("commit", "-qm", "ignore fixture")
        def coder(repo):
            self.good(repo)
            (repo / "scratch.tmp").write_text("new\n")
        result = self.invoke(coder)
        self.assertEqual(result["rollback_evidence"]["removed"], ["scratch.tmp"])
        self.assertFalse((self.repo / "scratch.tmp").exists())

    def test_changed_evidence_blocks_rollback(self):
        def coder(repo):
            self.good(repo)
            (repo / "scratch.tmp").write_text("new\n")
        def raced_rollback(state):
            (Path(state["repo_dir"]) / "scratch.tmp").write_text("concurrent work\n")
            return rollback_node(state)
        with patch.object(graph_module, "rollback_node", raced_rollback):
            result = self.invoke(coder)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("EVIDENCE_CHANGED", result["rollback_error"])
        self.assertEqual((self.repo / "scratch.tmp").read_text(), "concurrent work\n")

    def test_symlink_target_blocks_without_following_it(self):
        def coder(repo):
            self.good(repo)
            (repo / "scratch.tmp").symlink_to("note.txt")
        result = self.invoke(coder)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual((self.repo / "note.txt").read_text(), "original\n")
        self.assertTrue((self.repo / "scratch.tmp").is_symlink())

    def test_head_change_cannot_hide_integrity_violations(self):
        def coder(repo):
            self.good(repo)
            (repo / "new.txt").write_text("new\n")
            self.run_git("add", ".")
            self.run_git("commit", "-qm", "unauthorized agent commit")
        result = self.invoke(coder)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["tester_error"], "BASELINE_CHANGED")

    def test_staged_whitespace_failure_cannot_verify(self):
        def coder(repo):
            self.good(repo)
            app = repo / "app.py"
            original = app.read_text()
            app.write_text(original + "# whitespace   \n")
            self.run_git("add", "app.py")
            app.write_text(original)
        result = self.invoke(coder)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["test_exit"], 0)
        self.assertNotEqual(result["diff_check_exit"], 0)

    def test_allowed_untracked_whitespace_failure_cannot_verify(self):
        def coder(repo):
            self.good(repo)
            (repo / "new.txt").write_text("trailing whitespace   \n")
        result = self.invoke(coder, allow_new_files=True)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["test_exit"], 0)
        self.assertNotEqual(result["diff_check_exit"], 0)

    def test_normal_test_failure_repair_still_verifies(self):
        result = self.invoke(lambda repo: None, self.good)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["fix_attempts"], 1)
        self.assertNotIn("rollback", result["trace"])

    def _calculator_regression(self, repair):
        source = ROOT / "test-workspace"
        original = subprocess.run(
            ["git", "show", "HEAD:calculator.py"], cwd=source,
            capture_output=True, text=True, check=True,
        ).stdout
        (self.repo / "calculator.py").write_text(original)
        (self.repo / "test_calculator.py").write_bytes((source / "test_calculator.py").read_bytes())
        self.run_git("add", ".")
        self.run_git("commit", "-qm", "original calculator regression tests")
        good = original.replace(
            "discount = subtotal * discount_percent",
            "discount = subtotal * (discount_percent / 100)",
        )
        self.assertNotEqual(original, good)
        def coder(repo):
            self.good(repo)
            (repo / "calculator.py").write_text(original if repair else good)
        def fixer(repo):
            (repo / "calculator.py").write_text(good)
        result = self.invoke(coder, fixer)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["fix_attempts"], int(repair))
        self.assertIn("test_ten_percent_discount", result["test_output"])
        self.assertEqual((self.repo / "test_calculator.py").read_bytes(),
                         (source / "test_calculator.py").read_bytes())

    def test_existing_calculator_workflow_regression(self):
        self._calculator_regression(repair=False)

    def test_existing_calculator_repair_regression(self):
        self._calculator_regression(repair=True)

    def _research_regression(self, fake_parameter=False, wrong_domain=False):
        # Synthetic transport fixtures exercise real provenance, extraction,
        # coverage, role nodes, graph routing and unchanged weather tests.
        source = ROOT / "research-workspace"
        for name in ("weather_client.py", "test_weather_client.py"):
            (self.repo / name).write_bytes((source / name).read_bytes())
        self.run_git("add", ".")
        self.run_git("commit", "-qm", "original weather regression tests")
        query = ("Open-Meteo Forecast API /v1/forecast HTTPS endpoint current "
                 "temperature_2m relative_humidity_2m weather_code timezone auto")
        if fake_parameter:
            query += " quantum_weather_mode"
        plan = {"needs_research": True, "research_type": "api_reference",
                "research_query": query, "steps": ["Research and implement weather URL"]}
        docs = (
            "# Synthetic Open-Meteo documentation fixture\n"
            "API endpoint: https://api.open-meteo.com/v1/forecast\n"
            "| current | temperature_2m,relative_humidity_2m,weather_code |\n"
            "| timezone | Set timezone=auto for automatic timezone selection. |\n"
        )
        def transport(cmd):
            if cmd[0] == "dev-intel":
                return {"apis": [{"name": "Open-Meteo", "https": True,
                                  "url": "https://open-meteo.com/"}]}
            self.assertEqual(cmd[0], "exa-intel")
            return {"results": [{"title": "Forecast API",
                                  "url": "https://unrelated.invalid/docs" if wrong_domain
                                  else "https://open-meteo.com/en/docs"}]}
        def coder(repo):
            self.good(repo)
            (repo / "weather_client.py").write_text(
                "from urllib.parse import urlencode\n\n"
                "def build_forecast_url(latitude, longitude):\n"
                "    params = {'latitude': latitude, 'longitude': longitude,\n"
                "              'current': 'temperature_2m,relative_humidity_2m,weather_code',\n"
                "              'timezone': 'auto'}\n"
                "    return 'https://api.open-meteo.com/v1/forecast?' + urlencode(params)\n"
            )
        with patch("roles.researcher._run_json", side_effect=transport), \
                patch("roles.researcher._fetch_jina", return_value=docs) as fetch:
            result = self.invoke(coder, planner_payload=plan, task=query)
        self.assertTrue(fetch.called)
        self.assertTrue(all(call.args[0].startswith("https://open-meteo.com/")
                            for call in fetch.call_args_list))
        if fake_parameter:
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["trace"], ["workspace_prepare", "preflight", "baseline", "test_discovery_baseline",
                                              "inspector", "planner", "research_validation",
                                              "researcher:error", "finalizer", "workspace_finish"])
            self.assertFalse(result.get("research"))
            self.assertFalse(self.test_events)
            self.assertIn("quantum_weather_mode", result["research_error"])
        else:
            self.assertEqual(result["status"], "VERIFIED")
            self.assertIn("researcher", result["trace"])
            coverage = json.loads(result["research"])["results"][0]["official_docs"]["grounding_coverage"]
            self.assertTrue(coverage["passed"])
            self.assertTrue({"/v1/forecast", "current", "temperature_2m", "relative_humidity_2m",
                             "weather_code", "timezone", "auto", "https"} <= set(coverage["covered"]))
            self.assertIn("test_uses_automatic_timezone", result["test_output"])

    def test_open_meteo_grounding_graph_regression(self):
        self._research_regression()

    def test_fake_weather_parameter_blocks_before_coder(self):
        self._research_regression(fake_parameter=True)

    def test_wrong_domain_docs_are_not_fetched(self):
        self._research_regression(wrong_domain=True)


if __name__ == "__main__":
    unittest.main()
