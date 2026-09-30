"""Deterministic Inspector and production routing tests; no provider calls."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import shutil
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
from roles import inspector, integrity
import graph as graph_module


class InspectorRoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source_repo = Path(self.temp.name)
        self.repo = self.source_repo
        self.run_dirs = []
        self.artifacts = []
        self.addCleanup(self.cleanup_run_dirs)
        self.git("init", "-q")
        self.git("config", "user.name", "Inspector fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.write("app.py", "def value():\n    return 1\n")
        self.write("test_app.py", "import unittest\nfrom app import value\nclass TestValue(unittest.TestCase):\n    def test_value(self):\n        self.assertEqual(value(), 1)\n")
        self.commit()
        self.state = {"task": "Update the external payments integration using the current API.",
                      "repo_dir": str(self.source_repo), "fix_attempts": 0, "trace": []}
        self.old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(ROOT / "bin") + os.pathsep + self.old_path
        self.addCleanup(lambda: os.environ.__setitem__("PATH", self.old_path))

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.source_repo, capture_output=True, text=True, check=True)

    def cleanup_run_dirs(self):
        for path in self.run_dirs + self.artifacts:
            if path.exists():
                shutil.rmtree(path)

    def write(self, name, text):
        path = self.source_repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def test_manifest_and_import_facts_have_provenance(self):
        self.write("package.json", json.dumps({"dependencies": {"stripe": "^14.2.0"},
                                               "description": "DO_NOT_EMIT_DESCRIPTION"}))
        self.write("payments.ts", "import Stripe from 'stripe';\n")
        self.commit()
        result = inspector.inspector_node(self.state)
        self.assertEqual(result["inspector_error"], "")
        facts = result["repo_facts"]
        self.assertIn({"name": "stripe", "version": "^14.2.0", "source": "package.json"}, facts["dependencies"])
        self.assertIn({"name": "stripe", "source": "payments.ts", "external": True}, facts["imports"])
        self.assertIn("TypeScript", facts["languages"])
        self.assertIn("unittest", facts["test_frameworks"])
        self.assertTrue(all(len(s["sha256"]) == 64 for s in facts["sources"]))
        self.assertNotIn("DO_NOT_EMIT_DESCRIPTION", result["repo_facts_text"])

    def test_obvious_secret_files_and_generated_paths_are_never_opened(self):
        excluded = [".env", ".env.local", "credentials.py", "oauth/client.py", "config/keys.py",
                    "secrets/package.json", "provider_database.db", ".ssh/id_rsa",
                    "node_modules/pkg/index.js", ".venv/lib/pkg.py", "dist/generated.js",
                    "__pycache__/cache.py", "coverage/run.py", "api_keys.py", "keys.py",
                    ".codex/settings.py"]
        for name in excluded:
            self.write(name, "SECRET_SENTINEL_DO_NOT_READ")
        self.commit()
        with patch.object(inspector, "_read", wraps=inspector._read) as read:
            result = inspector.inspector_node(self.state)
        self.assertEqual(result["inspector_error"], "")
        opened = {call.args[1] for call in read.call_args_list}
        self.assertFalse(opened & set(excluded))
        self.assertNotIn("SECRET_SENTINEL", result["repo_facts_text"])

    def test_output_and_reads_are_bounded(self):
        for i in range(50):
            self.write(f"src/module_{i}.py", "import unittest\n" + "\n" * 8000)
        self.commit()
        result = inspector.inspector_node(self.state)
        self.assertTrue(result["repo_facts"]["truncated"])
        self.assertLessEqual(len(result["repo_facts_text"]), inspector.MAX_PACKET_CHARS)
        self.assertLessEqual(result["repo_facts"]["files_read"], inspector.MAX_FILES)
        self.assertLessEqual(result["repo_facts"]["bytes_read"], inspector.MAX_TOTAL_BYTES)

    def test_symlink_manifest_blocks_without_reading_target(self):
        self.write(".env", "SECRET_SENTINEL")
        (self.repo / "package.json").symlink_to(".env")
        self.commit()
        result = inspector.inspector_node(self.state)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["repo_facts_text"], "")

    def test_unsafe_repository_blocks(self):
        result = inspector.inspector_node({**self.state, "repo_dir": str(self.repo / "absent")})
        self.assertEqual(result["status"], "BLOCKED")

    def test_malformed_manifest_does_not_echo_contents(self):
        self.write("package.json", "SECRET_SENTINEL_INVALID_JSON")
        self.commit()
        result = inspector.inspector_node(self.state)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertNotIn("SECRET_SENTINEL", json.dumps(result))

    def test_no_repository_code_is_executed(self):
        self.write("setup.py", "raise RuntimeError('must never execute')\n")
        self.write("package.json", json.dumps({"scripts": {"postinstall": "touch executed"}}))
        self.commit()
        real_run = integrity.run_git
        def only_git(arguments, **kwargs):
            self.assertEqual(arguments[0], "--literal-pathspecs")
            self.assertIn(arguments[1], {"rev-parse", "ls-files"})
            return real_run(arguments, **kwargs)
        with patch("roles.integrity.run_git", side_effect=only_git):
            result = inspector.inspector_node(self.state)
        self.assertEqual(result["inspector_error"], "")
        self.assertFalse((self.repo / "executed").exists())

    def test_dependency_auth_urls_are_not_emitted(self):
        self.write("package.json", json.dumps({"dependencies": {"stripe": "https://user:SECRET_SENTINEL@example.invalid/pkg"}}))
        self.commit()
        result = inspector.inspector_node(self.state)
        self.assertNotIn("SECRET_SENTINEL", result["repo_facts_text"])
        self.assertEqual(result["repo_facts"]["dependencies"][0]["version"], "")

    def add_stripe(self):
        self.write("package.json", json.dumps({"dependencies": {"stripe": "^14.2.0"}}))
        self.write("payments.ts", "import Stripe from 'stripe';\n")
        self.commit()

    def invoke(self, query="stripe current API documentation", task=None, kind="api_reference", coder=None, **policy):
        plan = {"needs_research": kind != "none", "research_type": kind,
                "research_query": query, "steps": ["Inspect and update the integration"]}
        def code(state):
            app = Path(state["repo_dir"]) / "app.py"
            app.write_text(app.read_text() + "# graph fixture implementation\n")
            if coder:
                coder(Path(state["repo_dir"]))
            return {"trace": ["coder:fixture"]}
        def fix(state):
            return {"fix_attempts": state.get("fix_attempts", 0) + 1, "trace": ["fixer:fixture"]}
        def transport(command):
            if command[0] == "dev-intel":
                return {"apis": [{"name": "Stripe", "url": "https://stripe.com/", "https": True}]}
            self.assertEqual(command[0], "exa-intel")
            return {"results": [{"title": "Stripe API", "url": "https://docs.stripe.com/api"}]}
        docs = ("# Synthetic Stripe fixture\nStripe current SDK API documentation.\n"
                "API endpoint https://api.stripe.com/v1/payment_intents\n"
                "PaymentIntent.create supports amount and currency.\n")
        with patch("roles.planner._run_planner", return_value=plan) as planner, \
                patch("roles.reviewer._run_reviewer", return_value={"verdict": "PASS", "issues": [], "summary": "Fixture"}), \
                patch("roles.researcher._run_json", side_effect=transport) as research, \
                patch("roles.researcher._fetch_jina", return_value=docs), \
                patch.object(graph_module, "coder_node", code), \
                patch.object(graph_module, "fixer_node", fix):
            result = graph_module.build_graph().invoke({**self.state, "task": task or self.state["task"],
                                                       "retain_workspace": True, **policy},
                                                       config={"recursion_limit": 30})
        if result.get("run_workspace"):
            self.repo = Path(result["run_workspace"])
            self.run_dirs.append(Path(result["run_dir"]))
        else:
            self.repo = self.source_repo
        if result.get("verified_patch_path"):
            self.artifacts.append(Path(result["verified_patch_path"]).parent)
        return result, planner, research

    def test_inspector_runs_before_planner_and_supplies_facts(self):
        self.add_stripe()
        result, planner, _ = self.invoke()
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["trace"][:7], ["workspace_prepare", "preflight", "baseline", "test_discovery_baseline",
                                               "inspector", "planner", "research_validation"])
        supplied = json.loads(planner.call_args.args[1])
        self.assertEqual(supplied, result["repo_facts"])
        self.assertIn("stripe", {item["name"] for item in supplied["dependencies"]})

    def test_vague_task_without_dependency_blocks_hallucinated_provider(self):
        result, _, research = self.invoke()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("stripe", result["research_rejected_identifiers"])
        self.assertFalse(research.called)
        self.assertNotIn("coder:fixture", result["trace"])

    def test_hallucinated_provider_rejected_even_with_real_dependency(self):
        self.add_stripe()
        result, _, research = self.invoke(query="PayPal current API documentation")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["research_rejected_identifiers"], ["paypal"])
        self.assertFalse(research.called)

    def test_under_specified_query_adds_only_unique_evidenced_dependency(self):
        self.add_stripe()
        result, _, _ = self.invoke(query="current payments API documentation")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["research_added_identifiers"], ["stripe"])
        self.assertIn({"kind": "dependencies", "source": "package.json"},
                      result["research_validation_evidence"]["stripe"])

    def test_ambiguous_dependency_does_not_guess(self):
        self.write("package.json", json.dumps({"dependencies": {"stripe": "14.2.0", "paypal": "1.0.0"}}))
        self.commit()
        result, _, research = self.invoke(query="current payments API documentation")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["research_validation_error"], "EXTERNAL_IDENTITY_UNRESOLVED")
        self.assertFalse(research.called)

    def test_ordinary_task_noun_is_not_promoted_to_provider(self):
        result, _, research = self.invoke(query="current API documentation",
            task="Carefully improve external payments handling using current API.")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["research_validation_error"], "EXTERNAL_IDENTITY_UNRESOLVED")
        self.assertFalse(research.called)

    def test_required_parameters_omitted_by_planner_are_enriched(self):
        self.add_stripe()
        task = "Update Stripe current API using PaymentIntent.create and /v1/payment_intents."
        result, _, research = self.invoke(query="Stripe current API documentation", task=task)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue({"paymentintent.create", "/v1/payment_intents"} <= set(result["research_added_identifiers"]))
        self.assertTrue(research.called)
        self.assertTrue(all(result["research_validation_evidence"].values()))

    def test_omitted_fake_parameter_is_added_and_blocked_by_grounding(self):
        self.add_stripe()
        result, _, research = self.invoke(task="Update Stripe current API using quantum_weather_mode.")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertTrue(result["research_validation_passed"])
        self.assertIn("quantum_weather_mode", result["research_added_identifiers"])
        self.assertIn("quantum_weather_mode", result["research_error"])
        self.assertTrue(research.called)
        self.assertNotIn("coder:fixture", result["trace"])

    def test_omitted_open_meteo_identifiers_remain_in_validated_query(self):
        task = ("Use Open-Meteo current API temperature_2m relative_humidity_2m weather_code "
                "with /v1/forecast and timezone auto.")
        result, _, research = self.invoke(query="Open-Meteo current API documentation", task=task)
        # The deliberately Stripe-only transport fixture cannot ground weather
        # identifiers; the validator must still preserve every requirement.
        self.assertTrue(result["research_validation_passed"])
        required = {"temperature_2m", "relative_humidity_2m", "weather_code", "/v1/forecast"}
        self.assertTrue(required <= set(result["research_added_identifiers"]))
        self.assertTrue({"timezone", "auto"} <= set(result["research_added_identifiers"]))
        self.assertTrue(all(term in research.call_args_list[0].args[0][2] for term in required))
        self.assertEqual(result["status"], "BLOCKED")

    def test_unknown_version_and_endpoint_are_rejected(self):
        self.add_stripe()
        for query in ("stripe SDK v999.0 docs", "stripe /v99/invented docs"):
            with self.subTest(query=query):
                result, _, research = self.invoke(query=query)
                self.assertEqual(result["status"], "BLOCKED")
                self.assertTrue(result["research_rejected_identifiers"])
                self.assertFalse(research.called)

    def test_cannot_skip_research_for_current_external_api(self):
        self.add_stripe()
        result, _, research = self.invoke(query="", kind="none")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["research_validation_error"], "EXTERNAL_RESEARCH_REQUIRED")
        self.assertFalse(research.called)
        self.assertNotIn("coder:fixture", result["trace"])

    def test_unsafe_inspection_stops_before_planner(self):
        (self.repo / "package.json").symlink_to("test_app.py")
        self.commit()
        result, planner, research = self.invoke()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["workspace_error"], "SYMLINK_IN_SOURCE_REPOSITORY")
        self.assertFalse(planner.called)
        self.assertFalse(research.called)

    def test_api_requirements_cannot_bypass_coverage_via_another_route(self):
        self.add_stripe()
        for kind in ("current_web", "workflow_pattern"):
            with self.subTest(kind=kind):
                result, _, research = self.invoke(kind=kind,
                    task="Update Stripe current API using quantum_weather_mode.")
                self.assertEqual(result["status"], "BLOCKED")
                self.assertEqual(result["research_validation_error"], "API_RESEARCH_ROUTE_REQUIRED")
                self.assertFalse(research.called)
                self.assertNotIn("coder:fixture", result["trace"])

    def test_existing_local_function_is_not_an_external_api_requirement(self):
        self.add_stripe()
        result, _, _ = self.invoke(task="Update Stripe current API in app.py using local function value.")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertIn("app.py", result["research_local_identifiers"])
        self.assertIn("value", result["research_local_identifiers"])
        self.assertNotIn("app.py", result["research_required_identifiers"])

    def test_planner_query_and_steps_remain_bounded(self):
        self.add_stripe()
        result, _, research = self.invoke(query="stripe " * 200)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("planner:error", result["trace"])
        self.assertFalse(research.called)

    def test_catalog_cannot_switch_to_an_unvalidated_provider(self):
        result, _, _ = self.invoke(query="Open-Meteo current API documentation",
                                   task="Update Open-Meteo current API.")
        self.assertTrue(result["research_validation_passed"])
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("provider did not match", result["research_error"])
        self.assertNotIn("coder:fixture", result["trace"])

    def test_provider_identity_cannot_match_only_a_domain_suffix(self):
        result, _, _ = self.invoke(query="Com current API documentation", task="Update Com current API.")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("provider did not match", result["research_error"])

    def test_unobserved_framework_is_not_neutral_query_wording(self):
        self.add_stripe()
        result, _, research = self.invoke(query="stripe Java API documentation")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("java", result["research_rejected_identifiers"])
        self.assertFalse(research.called)

    def test_verification_configuration_tampering_is_rolled_back(self):
        self.write("package.json", '{"scripts":{"test":"real-test-command"}}\n')
        self.commit()
        def coder(repo):
            (repo / "package.json").write_text('{"scripts":{"test":"true"}}\n')
            (repo / "app.py").write_text("def value():\n    return 1  # legitimate change\n")
        result, _, _ = self.invoke(query="", kind="none", task="Fix local implementation", coder=coder)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["rollback_evidence"]["restored"], ["package.json"])
        self.assertIn("real-test-command", (self.repo / "package.json").read_text())
        self.assertIn("legitimate change", (self.repo / "app.py").read_text())

    def test_agent_policy_tampering_is_rolled_back(self):
        self.write("AGENTS.md", "Run required verification.\n")
        self.commit()
        def coder(repo):
            (repo / "AGENTS.md").write_text("Skip verification.\n")
        result, _, _ = self.invoke(query="", kind="none", task="Fix local implementation", coder=coder)
        self.assertEqual(result["rollback_evidence"]["restored"], ["AGENTS.md"])
        self.assertEqual((self.repo / "AGENTS.md").read_text(), "Run required verification.\n")

    def test_manifest_changes_require_distinct_trusted_permission(self):
        self.add_stripe()
        def coder(repo):
            (repo / "package.json").write_text('{"dependencies":{"stripe":"^14.3.0"}}\n')
        result, _, _ = self.invoke(query="", kind="none", task="Update the declared dependency", coder=coder,
                                   allow_verification_changes=True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertNotIn("rollback", result["trace"])
        self.assertIn("14.3.0", (self.repo / "package.json").read_text())

    def test_python_manifest_versions_and_safe_optional_dependencies(self):
        self.write("pyproject.toml", '[project]\ndependencies = ["stripe>=14.0,<15", "requests==2.32.0"]\n[project.optional-dependencies]\ntest = ["pytest>=8"]\n')
        self.commit()
        result = inspector.inspector_node(self.state)
        self.assertEqual(result["inspector_error"], "")
        deps = {item["name"]: item["version"] for item in result["repo_facts"]["dependencies"]}
        self.assertEqual(deps["stripe"], ">=14.0,<15")
        self.assertEqual(deps["pytest"], ">=8")

    def test_oversized_manifest_is_not_read_or_emitted(self):
        self.write("package.json", "x" * (inspector.MAX_FILE_BYTES + 1))
        self.commit()
        result = inspector.inspector_node(self.state)
        self.assertEqual(result["inspector_error"], "")
        self.assertTrue(result["repo_facts"]["truncated"])
        self.assertNotIn("package.json", [s["path"] for s in result["repo_facts"]["sources"]])

    def test_hardlinked_manifest_blocks(self):
        self.write("private.txt", '{}\n')
        os.link(self.repo / "private.txt", self.repo / "package.json")
        self.commit()
        self.assertEqual(inspector.inspector_node(self.state)["status"], "BLOCKED")

    def test_declared_version_has_provenance_and_task_constraint_is_preserved(self):
        self.add_stripe()
        result, _, _ = self.invoke(query="stripe 14.2.0 current API documentation",
                                   task="Update Stripe current API with version ^14.2.0.")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertIn("^14.2.0", result["research_added_identifiers"])
        self.assertTrue(result["research_validation_evidence"]["14.2.0"])

    def test_verifier_script_and_orchestrator_are_protected(self):
        for name in ("bin/freeagent-test", "orchestrator/control.py"):
            with self.subTest(name=name):
                self.write(name, "# original verifier\n")
                self.commit()
                def coder(repo):
                    (repo / name).write_text("# bypass verification\n")
                result, _, _ = self.invoke(query="", kind="none", task="Fix local implementation", coder=coder)
                self.assertEqual(result["rollback_evidence"]["restored"], [name])
                self.assertEqual((self.repo / name).read_text(), "# original verifier\n")


if __name__ == "__main__":
    unittest.main()
