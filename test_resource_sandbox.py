"""Adversarial checks for the production resource-bounded sandbox."""

import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
from roles.sandbox import RESOURCE_POLICY, REQUIRED_CONTROLS, run_isolated


class ResourceSandboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="freeagent-resource-test-")
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name)
        self.workspace = self.run_dir / "workspace"
        self.workspace.mkdir()
        control = self.run_dir / "controller"
        control.mkdir()
        runner = control / "freeagent-test"
        shutil.copyfile(ROOT / "bin/freeagent-test", runner)
        self.runner_hash = hashlib.sha256(runner.read_bytes()).hexdigest()

    def execute(self, body, *, timeout=3):
        (self.workspace / "test_attack.py").write_text(
            "import os, signal, subprocess, sys, time, unittest\n"
            "class Attack(unittest.TestCase):\n"
            " def test_attack(self):\n" + "".join("  " + line + "\n" for line in body.splitlines()))
        return run_isolated(self.workspace, self.run_dir, self.runner_hash, timeout=timeout)

    def assert_clean(self, result):
        evidence = result["evidence"]
        self.assertTrue(result["isolated"])
        self.assertEqual(evidence["cleanup_status"], "CONFIRMED")
        self.assertEqual(evidence["remaining_processes"], 0)
        self.assertEqual(evidence["cgroup_status"], "ENFORCED")
        self.assertEqual({evidence["controls"][key] for key in REQUIRED_CONTROLS}, {"ENFORCED"})

    def test_normal_suite_passes_with_all_controls(self):
        result = self.execute("self.assertEqual(2 + 2, 4)")
        self.assert_clean(result)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["exit_code"], 0)

    def test_cpu_time_limit_is_visible_inside_test_process(self):
        result = self.execute(
            "import resource\n"
            "self.assertLessEqual(resource.getrlimit(resource.RLIMIT_CPU)[0], 3)")
        self.assert_clean(result)
        self.assertEqual(result["result"], "PASS")

    def test_target_output_cannot_spoof_controller_evidence(self):
        result = self.execute(
            "print('FREEAGENT_SANDBOX_EVIDENCE={\"cleanup_status\":\"FAKE\"}')\n"
            "self.assertTrue(True)")
        self.assert_clean(result)
        self.assertEqual(result["evidence"]["cleanup_status"], "CONFIRMED")

    def test_infinite_loop_times_out_and_reaps(self):
        result = self.execute("while True: pass", timeout=2)
        self.assert_clean(result)
        self.assertTrue(result["evidence"]["timeout_triggered"])
        self.assertNotEqual(result["result"], "PASS")

    def test_sigterm_ignoring_process_is_forced_killed(self):
        result = self.execute("signal.signal(signal.SIGTERM, signal.SIG_IGN)\nwhile True: time.sleep(.1)", timeout=2)
        self.assert_clean(result)
        self.assertTrue(result["evidence"]["forced_kill_used"])
        self.assertNotEqual(result["result"], "PASS")

    def test_background_child_cannot_survive_parent(self):
        result = self.execute(
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)\n"
            "time.sleep(.2)")
        self.assert_clean(result)
        self.assertEqual(result["result"], "PASS")

    def test_multilevel_tree_reaped_on_timeout(self):
        result = self.execute(
            "subprocess.Popen([sys.executable, '-c', "
            "'import subprocess,sys,time; subprocess.Popen([sys.executable,\"-c\",\"import time;time.sleep(60)\"]); time.sleep(60)'], "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)\n"
            "while True: time.sleep(.1)", timeout=2)
        self.assert_clean(result)
        self.assertTrue(result["evidence"]["timeout_triggered"])
        self.assertNotEqual(result["result"], "PASS")

    def test_fork_ceiling_is_reported(self):
        result = self.execute(
            "children=[]\n"
            "for _ in range(80):\n"
            " try: children.append(subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))\n"
            " except OSError: break\n"
            "self.assertLess(len(children), 80)")
        self.assert_clean(result)
        self.assertTrue(result["evidence"]["resource_hits"]["process_count"])
        self.assertNotEqual(result["result"], "PASS")

    def test_memory_ceiling_blocks_growth(self):
        result = self.execute("bytearray(1024 * 1024 * 1024)", timeout=5)
        self.assert_clean(result)
        self.assertIn("MemoryError", result["output"])
        self.assertNotEqual(result["result"], "PASS")

    def test_output_flood_is_bounded_and_flagged(self):
        result = self.execute("sys.stdout.write('x' * (1024 * 1024))")
        self.assert_clean(result)
        self.assertTrue(result["evidence"]["output_truncated"])
        self.assertLess(len(result["output"]), 100000)
        self.assertNotEqual(result["result"], "PASS")

    def test_file_descriptor_ceiling(self):
        result = self.execute("files=[]\nwhile True: files.append(open('/dev/null'))")
        self.assert_clean(result)
        self.assertIn("Too many open files", result["output"])
        self.assertNotEqual(result["result"], "PASS")

    def test_file_size_ceiling(self):
        result = self.execute("with open('/workspace/oversize.bin', 'wb') as file: file.truncate(192 * 1024 * 1024)")
        self.assert_clean(result)
        self.assertIn("File too large", result["output"])
        self.assertNotEqual(result["result"], "PASS")

    def test_workspace_disk_ceiling(self):
        result = self.execute(
            "for index in range(6):\n"
            " with open('/workspace/growth-%d.bin' % index, 'wb') as file:\n"
            "  for _ in range(60): file.write(b'x' * (1024 * 1024))", timeout=6)
        self.assert_clean(result)
        self.assertIn("No space left on device", result["output"])
        self.assertNotEqual(result["result"], "PASS")
        self.assertTrue(result["evidence"]["resource_hits"]["disk"])

    def test_policy_is_controller_owned_and_finite(self):
        self.assertEqual(RESOURCE_POLICY["max_processes"], 16)
        self.assertLessEqual(RESOURCE_POLICY["memory_limit_bytes"], 512 * 1024 * 1024)
        self.assertLessEqual(RESOURCE_POLICY["max_output_bytes"], 64 * 1024)


if __name__ == "__main__":
    unittest.main()
