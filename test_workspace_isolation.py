"""Production workspace contract and OS-boundary adversarial tests."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))

from roles import coder, fixer
from roles.sandbox import run_isolated
from roles.workspace import _load_verified_manifest, finish_workspace, prepare_workspace_node, test_discovery_count


class WorkspaceIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-isolation-test-")
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "source"
        self.source.mkdir()
        self.run_git("init", "-q")
        self.run_git("config", "user.name", "Fixture")
        self.run_git("config", "user.email", "fixture@example.invalid")
        (self.source / "app.py").write_text("def value():\n    return 1\n")
        (self.source / "test_app.py").write_text(
            "import unittest\nclass TestApp(unittest.TestCase):\n"
            " def test_value(self): self.assertEqual(1, 1)\n")
        self.run_git("add", ".")
        self.run_git("commit", "-qm", "fixture")
        self.run_dirs = []
        self.addCleanup(self.cleanup_runs)

    def run_git(self, *args):
        return subprocess.run(["git", *args], cwd=self.source, capture_output=True,
                              text=True, check=True)

    def cleanup_runs(self):
        for path in self.run_dirs:
            if path.exists():
                shutil.rmtree(path)

    def prepare(self):
        state = prepare_workspace_node({"repo_dir": str(self.source), "task": "Update app"})
        if state.get("run_dir"):
            self.run_dirs.append(Path(state["run_dir"]))
        return state

    def test_workspace_is_separate_and_manifest_is_external(self):
        before = hashlib.sha256((self.source / "app.py").read_bytes()).hexdigest()
        state = self.prepare()
        self.assertEqual(state["workspace_status"], "READY")
        workspace = Path(state["run_workspace"])
        manifest = Path(state["verification_manifest"])
        self.assertNotEqual(workspace.resolve(), self.source.resolve())
        self.assertNotEqual(workspace, manifest.parent)
        self.assertEqual(manifest.parent, Path(state["run_dir"]) / "controller")
        self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(hashlib.sha256((self.source / "app.py").read_bytes()).hexdigest(), before)
        self.assertEqual(_load_verified_manifest(state)["source_repo"], str(self.source))

    def test_cleanup_removes_only_controller_run_workspace(self):
        state = self.prepare()
        run_dir = Path(state["run_dir"])
        source_file = self.source / "app.py"
        original = source_file.read_bytes()
        result = finish_workspace({**state, "status": "UNVERIFIED"})
        self.assertEqual(result["workspace_status"], "CLEANED")
        self.assertFalse(run_dir.exists())
        self.assertEqual(source_file.read_bytes(), original)

    def test_obvious_secret_paths_are_skipped_without_opening(self):
        (self.source / ".env").write_text("SYNTHETIC_SECRET_SENTINEL=value\n")
        (self.source / "credentials").mkdir()
        (self.source / "credentials/provider.json").write_text("SYNTHETIC_SECRET_SENTINEL")
        (self.source / "provider_database.db").write_bytes(b"SYNTHETIC_SECRET_SENTINEL")
        (self.source / "private.pem").write_text("SYNTHETIC_SECRET_SENTINEL")
        (self.source / ".npmrc").write_text("SYNTHETIC_SECRET_SENTINEL")
        self.run_git("add", "-f", ".env", "credentials/provider.json", "provider_database.db",
                     "private.pem", ".npmrc")
        self.run_git("commit", "-qm", "synthetic secret path fixtures")
        state = self.prepare()
        workspace = Path(state["run_workspace"])
        self.assertFalse((workspace / ".env").exists())
        self.assertFalse((workspace / "credentials/provider.json").exists())
        self.assertFalse((workspace / "provider_database.db").exists())
        self.assertFalse((workspace / "private.pem").exists())
        self.assertFalse((workspace / ".npmrc").exists())
        self.assertNotIn("SYNTHETIC_SECRET_SENTINEL", Path(state["verification_manifest"]).read_text())

    def test_source_symlink_blocks_snapshot(self):
        (self.source / "outside-link").symlink_to("/etc/passwd")
        state = prepare_workspace_node({"repo_dir": str(self.source), "task": "inspect"})
        self.assertEqual(state["status"], "BLOCKED")
        self.assertIn("SYMLINK", state["workspace_error"])

    def test_manifest_replacement_is_detected(self):
        state = self.prepare()
        path = Path(state["verification_manifest"])
        original = path.read_bytes()
        path.chmod(0o600)
        path.write_text("{}\n")
        with self.assertRaisesRegex(RuntimeError, "MANIFEST_CHANGED"):
            _load_verified_manifest(state)
        path.chmod(0o600)
        path.write_bytes(original)

    def test_git_pointer_replacement_is_detected_before_git_verification(self):
        state = self.prepare()
        pointer = Path(state["run_workspace"]) / ".git"
        original = pointer.read_bytes()
        pointer.write_text("gitdir: " + str(self.source / ".git") + "\n")
        with self.assertRaisesRegex(RuntimeError, "GIT_POINTER_CHANGED"):
            _load_verified_manifest(state)
        pointer.write_bytes(original)

    def test_coder_has_restricted_file_tools_and_no_shell(self):
        state = self.prepare()
        calls = []
        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout="edited", evidence={"cleanup_status": "CONFIRMED"})
        with patch.object(coder, "_git_clean", return_value=True), \
                patch.object(coder, "verify_execution_contract", return_value=None), \
                patch.object(coder, "run_worker", side_effect=fake_run):
            result = coder.coder_node({**state, "task": "Implement value", "plan_steps": ["edit app.py"]})
        command, kwargs = calls[-1]
        self.assertEqual(result["coder_error"], "")
        self.assertEqual(kwargs["cwd"], state["run_workspace"])
        self.assertIn("--restricted", command)
        self.assertIn("--bare", command)
        self.assertIn("--tools", command)
        self.assertNotIn("Bash", command[command.index("--tools") + 1])
        self.assertNotIn("--add-dir", command)

    def test_fixer_has_restricted_file_tools_and_no_shell(self):
        state = self.prepare()
        calls = []
        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout="repaired", evidence={"cleanup_status": "CONFIRMED"})
        with patch.object(fixer, "verify_execution_contract", return_value=None), \
                patch.object(fixer, "run_worker", side_effect=fake_run):
            result = fixer.fixer_node({**state, "task": "Repair app.py", "fix_attempts": 1})
        command, kwargs = calls[-1]
        self.assertEqual(result["fixer_error"], "")
        self.assertEqual(kwargs["cwd"], state["run_workspace"])
        self.assertIn("--restricted", command)
        self.assertIn("--bare", command)
        tools_index = command.index("--tools")
        self.assertNotIn("Bash", command[tools_index + 1])
        self.assertNotIn("--add-dir", command)

    def test_supported_test_discovery_summaries(self):
        self.assertEqual(test_discovery_count("Ran 12 tests in 0.3s"), (12, "unittest"))
        self.assertEqual(test_discovery_count("12 passed, 2 skipped in 0.3s"), (14, "pytest"))
        self.assertEqual(test_discovery_count("Tests: 9 passed, 9 total"), (9, "jest"))
        self.assertEqual(test_discovery_count("Ran 99 tests in 0.1s\nRan 4 tests in 0.2s"),
                         (4, "unittest"))
        self.assertEqual(test_discovery_count("= 99 passed in 0.1s =\n= 3 passed, 1 skipped in 0.2s ="),
                         (4, "pytest"))
        self.assertEqual(test_discovery_count("RESULT=PASS"), (None, "unrecognized"))

    def test_chroot_blocks_controller_manifest_traversal_symlink_and_network(self):
        state = self.prepare()
        run_dir = Path(state["run_dir"])
        runner = (run_dir / "controller/freeagent-test").read_bytes()
        workspace = Path(state["run_workspace"])
        attack = workspace / "test_boundary.py"
        host_controller = ROOT / "orchestrator/roles/tester.py"
        controller_hash = hashlib.sha256(host_controller.read_bytes()).hexdigest()
        manifest_path = state["verification_manifest"]
        attack.write_text(f'''import pathlib, socket, unittest
class Boundary(unittest.TestCase):
 def blocked(self, path):
  with self.assertRaises(OSError): pathlib.Path(path).write_text("PWNED")
 def test_controller_path(self):
  self.blocked("/root/agent-stack/orchestrator/roles/tester.py")
 def test_manifest_path(self):
  self.blocked({manifest_path!r})
 def test_path_traversal(self):
  self.blocked("/workspace/../../../root/agent-stack/orchestrator/roles/tester.py")
 def test_symlink_escape(self):
  link=pathlib.Path("/workspace/escape")
  try: link.symlink_to("/root/agent-stack/orchestrator/roles/tester.py")
  except FileExistsError: pass
  with self.assertRaises(OSError): link.write_text("PWNED")
 def test_runner_is_read_only(self):
  self.blocked("/opt/freeagent/freeagent-test")
 def test_network_is_unavailable(self):
  with self.assertRaises(OSError): socket.create_connection(("1.1.1.1",53),timeout=1)
''')
        result = run_isolated(workspace, run_dir, hashlib.sha256(runner).hexdigest(), timeout=25)
        self.assertTrue(result["isolated"])
        self.assertEqual(result["result"], "PASS", result["output"])
        self.assertEqual(hashlib.sha256(host_controller.read_bytes()).hexdigest(), controller_hash)
        self.assertFalse((workspace / "escape").exists())


if __name__ == "__main__":
    unittest.main()
