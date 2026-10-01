"""Stage 1.5 file capabilities and real stdio dispatch; no model calls."""

import copy
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
from roles import coder, fixer, inspector, read_policy, reviewer
from roles.file_tools import FileTools, serve, tool_list
from roles.read_policy import (MAX_READ_BYTES, MAX_RESULTS, MAX_SESSION_BYTES, MAX_TOOL_CALLS,
                               ReadDenied, build_policy, context_read, file_tool_flags,
                               inspector_read, no_file_tool_flags, read_authorized, validate_policy)
from roles.coding_units import local_context_packet
from roles.integrity import baseline_node
from roles.repair_context import repair_packet
from roles.worker import WorkerResult, run_worker
import graph


def messages(path="app.py"):
    return [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "read_file", "arguments": {"path": path}}},
    ]


class FileReadPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-read-policy-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        contents = {"app.py": "def value():\n    return 1\n", "helper.py": "def extra(): return 2\n",
                    "unrelated.py": "outside_scope = 9\n", "README.md": "A small application.\n",
                    "test_app.py": "# public test\n", "pyproject.toml": "[project]\nname='fixture'\n",
                    ".gitignore": ".env\n"}
        for name, text in contents.items():
            (self.repo / name).write_text(text)
        for args in (("init", "-q"), ("add", "."),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "baseline")):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        self.state = {"repo_dir": str(self.repo), "task": "Improve app.py",
                      "repo_facts": {"relevant_files": ["app.py"]},
                      "plan_steps": ["Improve app.py"], "trace": []}
        self.state.update(baseline_node(self.state))
        self.unit = {"id": "unit-1", "goal": "Improve the implementation", "target_files": ["app.py"], "files": []}
        self.policy = build_policy(self.state, "coder", unit=self.unit)
        self.tools = FileTools(self.policy)

    def test_authorized_target_read(self):
        result = self.tools.call("read_file", {"path": "app.py"})
        self.assertIn("return 1", result["text"])
        self.assertFalse(result["truncated"])

    def test_unauthorized_source_rejected_before_open(self):
        with patch.object(read_policy, "_read") as read:
            with self.assertRaisesRegex(ReadDenied, "READ_DENIED"):
                self.tools.call("read_file", {"path": "unrelated.py"})
        read.assert_not_called()

    def test_secret_host_traversal_and_malformed_paths(self):
        denied = [".env", "../secret", "../../.ssh/id_rsa", "/proc/self/environ", ".git/config",
                  "foo/../../secret", "app.py\n", "app.py\x00", "a" * 181 + ".py", "app\\.py",
                  "./app.py", "a//app.py", "аpp.py", "credentials.py", "private_key.py",
                  "data/a.py", "fixtures/a.py", "uploads/a.py", "generated/a.py", "generated.py",
                  "a.pem", "cache.db", ".aws/config", "orchestrator/state.py"]
        for path in denied:
            with self.subTest(path=path), patch.object(read_policy, "_read") as read:
                with self.assertRaises(ReadDenied):
                    self.tools.call("read_file", {"path": path})
                read.assert_not_called()
                self.assertFalse(read_policy.path_allowed(path))

    def test_symlink_replacement_is_denied(self):
        (self.repo / "app.py").unlink()
        (self.repo / "app.py").symlink_to(self.repo / "unrelated.py")
        with self.assertRaises(ReadDenied):
            self.tools.call("read_file", {"path": "app.py"})
        self.assertNotIn("app.py", self.tools.call("glob_files", {"pattern": "*.py"})["matches"])

    def test_parent_symlink_is_denied(self):
        (self.repo / "nested").mkdir()
        (self.repo / "nested/app.py").write_text("value = 1\n")
        subprocess.run(["git", "add", "nested/app.py"], cwd=self.repo, check=True)
        policy = build_policy(self.state, "coder", unit={"target_files": ["nested/app.py"]})
        (self.repo / "nested/app.py").unlink()
        (self.repo / "nested").rmdir()
        (self.repo / "nested").symlink_to(self.repo)
        with self.assertRaises(ReadDenied):
            read_authorized(policy, "nested/app.py")

    def test_hardlink_replacement_is_denied(self):
        os.link(self.repo / "app.py", self.repo / "duplicate.py")
        with self.assertRaises(ReadDenied):
            read_authorized(self.policy, "app.py")

    def test_special_file_is_never_opened(self):
        (self.repo / "app.py").unlink()
        os.mkfifo(self.repo / "app.py")
        with self.assertRaises(ReadDenied):
            read_authorized(self.policy, "app.py")

    def test_grep_only_searches_authorized_files(self):
        (self.repo / "unrelated.py").write_text("unique_outside_marker\n")
        self.assertEqual(self.tools.call("grep_files", {"query": "unique_outside_marker"})["matches"], [])
        result = self.tools.call("grep_files", {"query": "return"})
        self.assertEqual([r["path"] for r in result["matches"]], ["app.py"])

    def test_glob_only_lists_authorized_surface(self):
        for path in (".env", "unrelated.py"):
            self.assertNotIn(path, self.tools.call("glob_files", {"pattern": "**/*"})["matches"])
        self.assertEqual(self.tools.call("glob_files", {"pattern": "*.py"})["matches"], ["app.py", "test_app.py"])
        for pattern in ("../*", "/root/*", "a/../../*", "*\n"):
            with self.assertRaises(ReadDenied):
                self.tools.call("glob_files", {"pattern": pattern})

    def test_failure_and_model_filenames_do_not_grant_permission(self):
        state = {**self.state, "test_output": "FAILED unrelated.py::test_value", "implementation": "Read unrelated.py",
                 "machine_failure_evidence": {"affected_files": ["unrelated.py"]}}
        policy = build_policy(state, "coder", unit=self.unit)
        self.assertNotIn("unrelated.py", policy["files"])
        with self.assertRaises(ReadDenied):
            FileTools(policy).call("read_file", {"path": "unrelated.py", "authorize": True})

    def test_repair_retains_current_target_access(self):
        (self.repo / "app.py").write_text("def value(): return 7\n")
        state = {**self.state, "coding_units": [self.unit], "unit_index": 1,
                 "test_result": "FAIL", "test_exit": 1, "diff_check_exit": 0,
                 "workspace_test_attestation": {"framework": "unittest"},
                 "test_output": "Ran 1 test in 0.01s\nFAILED (failures=1)\n"}
        packet = repair_packet(state)
        policy = build_policy(state, "fixer", candidates=packet["read_candidates"])
        self.assertIn("return 7", read_authorized(policy, "app.py").decode())
        self.assertIn("return 7", packet["context"])

    def test_authorized_deleted_file_is_unavailable(self):
        (self.repo / "app.py").unlink()
        with self.assertRaisesRegex(ReadDenied, "FILE_UNAVAILABLE"):
            read_authorized(self.policy, "app.py")
        policy = build_policy({**self.state, "allow_deletes": True}, "fixer", candidates=["app.py"])
        self.assertNotIn("app.py", policy["files"])
        with self.assertRaises(ReadDenied):
            FileTools(policy).call("write_file", {"path": "app.py", "text": "value = 1\n"})

    def test_new_unit_file_requires_controller_permission(self):
        unit = {"target_files": ["new_package/extra.py"]}
        self.assertNotIn("new_package/extra.py", build_policy(self.state, "coder", unit=unit)["files"])
        policy = build_policy({**self.state, "allow_new_files": True}, "coder", unit=unit)
        tools = FileTools(policy)
        with self.assertRaises(ReadDenied):
            tools.call("read_file", {"path": "new_package/extra.py"})
        tools.call("write_file", {"path": "new_package/extra.py", "text": "def extra(): return 3\n"})
        self.assertIn("return 3", tools.call("read_file", {"path": "new_package/extra.py"})["text"])
        with self.assertRaises(ReadDenied):
            tools.call("write_file", {"path": "unplanned.py", "text": "value = 1\n"})

    def test_protected_tests_and_verification_inputs(self):
        unit = {"target_files": ["test_app.py", "pyproject.toml"]}
        self.assertNotIn("test_app.py", build_policy(self.state, "coder", unit=unit)["write_files"])
        policy = build_policy({**self.state, "allow_test_changes": True, "allow_verification_changes": True}, "coder", unit=unit)
        self.assertIn("test_app.py", policy["files"])
        self.assertIn("pyproject.toml", policy["files"])
        self.assertNotIn("pyproject.toml", policy["write_files"])
        self.assertIn("[project]", inspector_read(self.repo, "pyproject.toml", ["pyproject.toml"]).decode())

    def test_secret_content_is_not_returned_or_enumerated(self):
        secret = "ghp_" + "X" * 40
        (self.repo / "app.py").write_text("api_key = '" + secret + "'\n")
        with self.assertRaises(ReadDenied) as denied:
            read_authorized(self.policy, "app.py")
        self.assertNotIn(secret, str(denied.exception))
        self.assertEqual(self.tools.call("grep_files", {"query": "X"})["matches"], [])
        self.assertNotIn("app.py", self.tools.call("glob_files", {"pattern": "*"})["matches"])
        self.assertNotIn(secret, local_context_packet(self.state, self.unit)["text"])

    def test_large_reads_and_searches_are_bounded(self):
        (self.repo / "app.py").write_text("value = 1\n" * 4000)
        result = self.tools.call("read_file", {"path": "app.py"})
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["text"].encode()), MAX_READ_BYTES)
        result = self.tools.call("grep_files", {"query": "value"})
        self.assertLessEqual(len(result["matches"]), MAX_RESULTS)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(json.dumps(result).encode()), MAX_READ_BYTES)

    def test_oversized_and_generated_files_are_denied(self):
        for text in ("# @generated\nvalue = 1\n", "x" * 65537):
            (self.repo / "app.py").write_text(text)
            with self.assertRaises(ReadDenied):
                read_authorized(self.policy, "app.py")

    def test_generated_scan_is_line_bounded_and_preserves_markers(self):
        from roles.coding_units import GENERATED_MARKER
        for marker in ("# @generated", "// generated", "/* auto-generated", "* do not edit", "generated"):
            self.assertFalse(read_policy.content_allowed(("\n\n  " + marker + "\nvalue = 1\n").encode()))
        content = "import unittest\n" + "\n" * 8000
        with patch("roles.coding_units.GENERATED_MARKER", wraps=GENERATED_MARKER) as scan:
            self.assertTrue(read_policy.content_allowed(content.encode()))
        scan.search.assert_not_called()
        self.assertTrue(scan.match.called)
        for call in scan.match.call_args_list:
            self.assertNotIn("\n", call.args[0])
            self.assertEqual(call.args[0], call.args[0].lstrip())

    def test_tool_call_and_session_budgets(self):
        self.tools.calls = MAX_TOOL_CALLS
        with self.assertRaises(ReadDenied):
            self.tools.call("read_file", {"path": "app.py"})
        self.tools.calls = 0
        self.tools.bytes_returned = MAX_SESSION_BYTES
        before = (self.repo / "app.py").read_bytes()
        with self.assertRaises(ReadDenied):
            self.tools.call("write_file", {"path": "app.py", "text": "value = 99\n"})
        self.assertEqual((self.repo / "app.py").read_bytes(), before)

    def test_edit_and_write_implicit_reads_enforce_same_policy(self):
        for name, arguments in (("edit_file", {"path": "unrelated.py", "old_text": "9", "new_text": "1"}),
                                ("write_file", {"path": "unrelated.py", "text": "value = 1\n"})):
            with self.assertRaises(ReadDenied):
                self.tools.call(name, arguments)
        self.tools.call("edit_file", {"path": "app.py", "old_text": "return 1", "new_text": "return 4"})
        self.assertIn("return 4", (self.repo / "app.py").read_text())

    def test_root_identity_replacement_is_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy["root_identity"][1] += 1
        with self.assertRaises(ReadDenied):
            FileTools(policy)
        with self.assertRaises(ReadDenied):
            read_authorized(policy, "app.py")

    def test_context_authorization_is_checked_before_open(self):
        with patch.object(read_policy, "_read") as read:
            with self.assertRaises(ReadDenied):
                context_read(self.state, "unrelated.py", [])
        read.assert_not_called()

    def test_capability_count_is_bounded(self):
        names = [f"part_{i}.py" for i in range(20)]
        for name in names:
            (self.repo / name).write_text("value = 1\n")
        subprocess.run(["git", "add", *names], cwd=self.repo, check=True)
        policy = build_policy({**self.state, "repo_facts": {"relevant_files": names}}, "coder")
        self.assertEqual(len(policy["files"]), 8)

    def test_unit_two_reads_current_workspace_version(self):
        first = build_policy(self.state, "coder", unit=self.unit)
        FileTools(first).call("edit_file", {"path": "app.py", "old_text": "return 1", "new_text": "return 8"})
        second = build_policy(self.state, "coder", unit=self.unit)
        self.assertIn("return 8", read_authorized(second, "app.py").decode())

    def test_launch_disables_native_tools_and_external_configuration(self):
        flags = file_tool_flags(self.state, "coder", unit=self.unit)
        self.assertEqual(flags[flags.index("--tools") + 1], "")
        self.assertIn("--system-prompt", flags)
        for flag in ("--strict-mcp-config", "--bare", "--restricted", "--disable-slash-commands"):
            self.assertIn(flag, flags)
        config = json.loads(flags[flags.index("--mcp-config") + 1])
        self.assertEqual(set(config["mcpServers"]), {"freeagent_files"})
        server = config["mcpServers"]["freeagent_files"]
        self.assertEqual(server["command"], sys.executable)
        self.assertEqual(server["args"][0], "-I")
        self.assertEqual(server["args"][3], hashlib.sha256(server["args"][2].encode()).hexdigest())
        self.assertEqual(set(flags[flags.index("--allowedTools") + 1].split(",")),
                         {"mcp__freeagent_files__" + t["name"] for t in tool_list(self.policy)})
        self.assertEqual(json.loads(no_file_tool_flags()[-1]), {"mcpServers": {}})

    def test_real_stdio_server_handshake_authorization_and_errors(self):
        flags = file_tool_flags(self.state, "coder", unit=self.unit)
        config = json.loads(flags[flags.index("--mcp-config") + 1])["mcpServers"]["freeagent_files"]
        requests = messages() + [messages("../secret")[-1]]
        result = subprocess.run([config["command"], *config["args"]],
                                input="".join(json.dumps(r) + "\n" for r in requests),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(replies[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(len(replies[1]["result"]["tools"]), 5)
        self.assertIn("return 1", replies[2]["result"]["content"][0]["text"])
        self.assertTrue(replies[3]["result"]["isError"])
        self.assertEqual(replies[3]["result"]["content"][0]["text"], "FILE_TOOL_DENIED:READ_DENIED")
        self.assertNotIn("../secret", result.stdout)

    def test_stdio_rejects_policy_tampering(self):
        flags = file_tool_flags(self.state, "coder", unit=self.unit)
        config = json.loads(flags[flags.index("--mcp-config") + 1])["mcpServers"]["freeagent_files"]
        config["args"][2] = config["args"][2].replace('"app.py"', '"unrelated.py"')
        result = subprocess.run([config["command"], *config["args"]], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 125)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"FILE_TOOL_POLICY_INVALID\n")

    def test_stdio_startup_ignores_workspace_python_modules(self):
        marker = self.repo / "startup-executed"
        injected = "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('unexpected')\n"
        (self.repo / "sitecustomize.py").write_text(injected)
        (self.repo / "json.py").write_text(injected + "raise RuntimeError('workspace module')\n")
        flags = file_tool_flags(self.state, "coder", unit=self.unit)
        config = json.loads(flags[flags.index("--mcp-config") + 1])["mcpServers"]["freeagent_files"]
        result = subprocess.run([config["command"], *config["args"]], cwd=self.repo,
                                env={**os.environ, "PYTHONPATH": str(self.repo)},
                                input="".join(json.dumps(r) + "\n" for r in messages()),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertIn("return 1", json.loads(result.stdout.splitlines()[-1])["result"]["content"][0]["text"])
        self.assertFalse(marker.exists())

    def test_stdio_descendant_is_resource_contained_and_reaped(self):
        flags = file_tool_flags(self.state, "coder", unit=self.unit)
        config = json.loads(flags[flags.index("--mcp-config") + 1])["mcpServers"]["freeagent_files"]
        harness = ("import json,subprocess,sys\n"
                   "cfg=json.loads(sys.argv[1]); result=subprocess.run([cfg['command'],*cfg['args']],"
                   "input=sys.argv[2],capture_output=True,text=True,timeout=5)\n"
                   "assert result.returncode==0\n"
                   "replies=[json.loads(line) for line in result.stdout.splitlines()]\n"
                   "assert replies[-1]['result']['isError'] is True\n"
                   "print('FILE_POLICY_CONTAINED')\n")
        requests = "".join(json.dumps(r) + "\n" for r in messages("../secret"))
        result = run_worker([sys.executable, "-c", harness, json.dumps(config), requests],
                            cwd=self.repo, timeout=10, role="coder")
        self.assertEqual(result.returncode, 0)
        self.assertIn("FILE_POLICY_CONTAINED", result.stdout)
        self.assertEqual(result.evidence["cleanup_status"], "CONFIRMED")
        self.assertEqual(result.evidence["remaining_processes"], 0)
        self.assertEqual(result.evidence["cgroup_status"], "ENFORCED")

    def test_inspector_does_not_enumerate_data_or_generated_source(self):
        for name in ("uploads/private.py", "generated/output.py", "fixtures/test_hidden.py"):
            path = self.repo / name
            path.parent.mkdir()
            path.write_text("value = 1\n")
            subprocess.run(["git", "add", name], cwd=self.repo, check=True)
        result = inspector.inspector_node(self.state)
        self.assertEqual(result["inspector_error"], "")
        self.assertNotIn("private.py", json.dumps(result))
        self.assertNotIn("test_hidden.py", json.dumps(result))

    def test_reviewer_has_no_file_tools_and_sanitizes_secondary_evidence(self):
        secret = "ghp_" + "X" * 40
        state = {**self.state, "test_output": "Authorization: Bearer " + secret,
                 "diff": "api_key = '" + secret + "'"}
        response = WorkerResult(0, json.dumps({"structured_output": {"verdict": "PASS", "issues": []}}), {})
        with patch.object(reviewer, "run_worker", return_value=response) as worker:
            reviewer._run_reviewer(state)
        command = worker.call_args.args[0]
        self.assertNotIn(secret, command[-1])
        self.assertEqual(command[command.index("--tools") + 1], "")
        self.assertEqual(json.loads(command[command.index("--mcp-config") + 1]), {"mcpServers": {}})

    def test_malformed_and_oversized_stdio_records(self):
        for records in (b"{bad}\n", b"x" * 65537 + b"\n", b"{}", b"[]\n"):
            output = io.StringIO()
            serve(self.policy, io.BytesIO(records), output)
            self.assertLess(len(output.getvalue()), 256)
            self.assertNotIn("bad", output.getvalue())

    def test_uninitialized_or_unknown_tools_never_read(self):
        output = io.StringIO()
        serve(self.policy, io.BytesIO((json.dumps(messages()[-1]) + "\n").encode()), output)
        self.assertIn("FILE_TOOL_PROTOCOL_INVALID", output.getvalue())
        with self.assertRaises(ReadDenied):
            self.tools.call("authorize_file", {"path": "unrelated.py"})

    def test_role_worker_calls_use_broker_without_additional_model_calls(self):
        result = WorkerResult(0, "done", {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
        state = {**self.state, "coding_units": [self.unit], "unit_index": 0}
        with patch.object(coder, "run_worker", return_value=result) as worker:
            coded = coder.coder_node(state)
        self.assertEqual(coded["coder_error"], "")
        worker.assert_called_once()
        command = worker.call_args.args[0]
        self.assertEqual(command[command.index("--tools") + 1], "")
        (self.repo / "app.py").write_text("def value(): return 5\n")
        state.update({"unit_index": 1, "test_result": "FAIL", "test_exit": 1, "diff_check_exit": 0,
                      "test_output": "Ran 1 test in 0.01s\nFAILED (failures=1)\n",
                      "workspace_test_attestation": {"framework": "unittest"}})
        with patch.object(fixer, "run_worker", return_value=result) as worker:
            repaired = fixer.fixer_node(state)
        self.assertEqual(repaired["fixer_error"], "")
        worker.assert_called_once()
        self.assertEqual(worker.call_args.kwargs["timeout"], 180)
        command = worker.call_args.args[0]
        self.assertEqual(command[command.index("--tools") + 1], "")

    def test_normal_graph_uses_real_file_server_then_isolated_tester(self):
        (self.repo / "test_app.py").write_text(
            "import unittest\nfrom app import value\nclass Values(unittest.TestCase):\n"
            "    def test_value(self): self.assertEqual(value(), 2)\n")
        subprocess.run(["git", "add", "test_app.py"], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "meaningful public verification"], cwd=self.repo, check=True)
        original = (self.repo / "app.py").read_bytes()
        plan = {"needs_research": False, "research_type": "none", "research_query": "",
                "steps": ["Fix the app value implementation and verify behavior"],
                "coding_units": [{"goal": "Fix the app implementation and verify behavior", "target_files": ["app.py"]}]}
        calls = []

        def fake_cli(command, **kwargs):
            self.assertEqual(command[command.index("--tools") + 1], "")
            cfg = json.loads(command[command.index("--mcp-config") + 1])["mcpServers"]["freeagent_files"]
            requests = messages() + [{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
                "name": "edit_file", "arguments": {"path": "app.py", "old_text": "return 1", "new_text": "return 2"}}}]
            reply = subprocess.run([cfg["command"], *cfg["args"]],
                                   input="".join(json.dumps(r) + "\n" for r in requests),
                                   capture_output=True, text=True, timeout=5)
            self.assertEqual(reply.returncode, 0)
            self.assertFalse(json.loads(reply.stdout.splitlines()[-1])["result"]["isError"])
            calls.append("coder")
            return WorkerResult(0, "implemented", {"cleanup_status": "CONFIRMED", "remaining_processes": 0})

        review = WorkerResult(0, json.dumps({"structured_output": {"verdict": "PASS", "issues": []}}),
                              {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
        with patch("roles.planner._run_planner", return_value=plan), \
                patch.object(coder, "run_worker", side_effect=fake_cli), \
                patch.object(reviewer, "run_worker", return_value=review) as review_worker:
            result = graph.build_graph().invoke({"repo_dir": str(self.repo),
                                                "task": "Fix the app value implementation", "trace": []})
        if result.get("verified_patch_path"):
            self.addCleanup(shutil.rmtree, Path(result["verified_patch_path"]).parent)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["test_result"], "PASS")
        self.assertEqual(result["trace"].count("tester"), 1)
        self.assertEqual(calls, ["coder"])
        review_worker.assert_called_once()
        self.assertEqual((self.repo / "app.py").read_bytes(), original)
        self.assertEqual(subprocess.run(["git", "apply", "--check", result["verified_patch_path"]],
                                        cwd=self.repo, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
