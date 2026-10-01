"""Production model-worker cgroup adversarial fixtures without provider calls."""

import os
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))
from roles.worker import (WORKER_POLICY, WorkerBoundaryError, WorkerResult, _validate_evidence,
                          run_worker)
from roles import coder, fixer
from roles.read_policy import no_file_tool_flags
import graph


class WorkerResourceTests(unittest.TestCase):
    def execute(self, code, *, role="coder", timeout=3, limits=None):
        return run_worker([sys.executable, "-c", code], cwd=ROOT, role=role,
                          timeout=timeout, limits=limits)

    def assert_clean(self, result):
        evidence = result.evidence
        self.assertEqual(evidence["cleanup_status"], "CONFIRMED")
        self.assertEqual(evidence["remaining_processes"], 0)
        self.assertEqual(evidence["cgroup_status"], "ENFORCED")
        self.assertTrue(all(value == "ENFORCED" for value in evidence["controls"].values()))

    def test_normal_coder_fixture(self):
        before = Path("/proc/self/cgroup").read_text()
        result = self.execute("print('coder-ok')")
        self.assert_clean(result)
        self.assertEqual(result.returncode, 0)
        self.assertIn("coder-ok", result.stdout)
        self.assertEqual(Path("/proc/self/cgroup").read_text(), before)

    def test_normal_fixer_fixture(self):
        result = self.execute("print('fixer-ok')", role="fixer")
        self.assert_clean(result)
        self.assertEqual(result.evidence["role"], "fixer")
        self.assertEqual(result.returncode, 0)

    def test_worker_cannot_change_its_cgroup_limits(self):
        code = ("import os\nfrom pathlib import Path\n"
                "caps=next(line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))\n"
                "assert int(caps.split()[1],16)==0\n"
                "mounts=[line for line in Path('/proc/self/mountinfo').read_text().splitlines() "
                "if ' - cgroup2 ' in line and '/freeagentos-worker-' in line]\n"
                "assert mounts and all('ro' in line.split()[5].split(',') for line in mounts)\n"
                "path=Path(mounts[0].split()[4])/'cgroup.procs'\n"
                "try:\n"
                " with open(path,'w') as stream:stream.write(str(os.getpid()))\n"
                "except OSError:pass\n"
                "else:raise AssertionError('worker migrated cgroup')\n"
                "print('blocked')")
        result = self.execute(code)
        self.assert_clean(result)
        self.assertEqual(result.returncode, 0)
        self.assertIn("blocked", result.stdout)

    def test_worker_cannot_write_controller_resource_policy(self):
        code = ("from pathlib import Path\n"
                f"policy=Path({str(ROOT / 'orchestrator/roles/worker.py')!r})\n"
                "try:\n"
                " policy.open('ab').close()\n"
                "except OSError:pass\n"
                "else:raise AssertionError('controller writable')\n"
                "print('controller-readonly')")
        result = self.execute(code)
        self.assert_clean(result)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.evidence["worker_controller_readonly"])

    def test_infinite_loop_times_out(self):
        result = self.execute("while True: pass", timeout=2)
        self.assert_clean(result)
        self.assertTrue(result.evidence["timeout_triggered"])
        self.assertEqual(result.returncode, 124)

    def test_sigterm_ignore_forces_kill(self):
        result = self.execute("import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True: time.sleep(.1)", timeout=2)
        self.assert_clean(result)
        self.assertTrue(result.evidence["forced_kill_used"])

    def test_background_child_is_reaped_after_parent_exit(self):
        result = self.execute("import subprocess,sys,time\nsubprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\ntime.sleep(.2)")
        self.assert_clean(result)
        self.assertEqual(result.returncode, 0)

    def test_multilevel_descendants_are_reaped(self):
        result = self.execute("import subprocess,sys,time\nsubprocess.Popen([sys.executable,'-c','import subprocess,sys,time;subprocess.Popen([sys.executable,\"-c\",\"import time;time.sleep(60)\"]);time.sleep(60)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\nwhile True:time.sleep(.1)", timeout=2)
        self.assert_clean(result)
        self.assertTrue(result.evidence["timeout_triggered"])

    def test_output_flood_is_bounded(self):
        result = self.execute("import sys;sys.stdout.write('x'*1048576)", limits={"max_output_bytes": 32768})
        self.assert_clean(result)
        self.assertTrue(result.evidence["output_truncated"])
        self.assertLess(len(result.stdout), 40000)
        self.assertNotEqual(result.returncode, 0)

    def test_memory_exhaustion_is_contained(self):
        result = self.execute("chunks=[]\nwhile True:chunks.append(bytearray(16*1024*1024))",
                              timeout=5, limits={"memory_limit_bytes": 128 * 1024 * 1024})
        self.assert_clean(result)
        self.assertTrue(result.evidence["resource_hits"]["memory"])
        self.assertNotEqual(result.returncode, 0)

    def test_process_explosion_is_contained(self):
        code = ("import subprocess,sys,time\nchildren=[]\n"
                "for _ in range(50):\n"
                " try:children.append(subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))\n"
                " except OSError:break\nprint(len(children))")
        result = self.execute(code, limits={"max_processes": 8})
        self.assert_clean(result)
        self.assertTrue(result.evidence["resource_hits"]["process_count"])
        self.assertNotEqual(result.returncode, 0)

    def test_cleanup_failure_evidence_blocks(self):
        result = self.execute("print('ok')")
        bad = {**result.evidence, "cleanup_status": "UNPROVEN", "remaining_processes": 1}
        with self.assertRaisesRegex(WorkerBoundaryError, "WORKER_BOUNDARY_UNVERIFIED"):
            _validate_evidence(bad, WORKER_POLICY, 0)

    def test_worker_policy_cannot_be_increased(self):
        with self.assertRaisesRegex(WorkerBoundaryError, "POLICY_OVERRIDE_INVALID"):
            self.execute("print('never runs')", limits={"memory_limit_bytes": WORKER_POLICY["memory_limit_bytes"] + 1})

    def test_coder_cleanup_failure_blocks_before_tester(self):
        with TemporaryDirectory() as temp:
            repo = Path(temp)
            (repo / ".git").write_text("fixture")
            failure = WorkerBoundaryError("WORKER_BOUNDARY_UNVERIFIED",
                                          {"cleanup_status": "UNPROVEN", "remaining_processes": 1})
            with patch.object(coder, "_git_clean", return_value=True), \
                    patch.object(coder, "file_tool_flags", return_value=no_file_tool_flags()), \
                    patch.object(coder, "capability_contract", return_value="Fixture: no file capabilities"), \
                    patch.object(coder, "sealed_policy", return_value={"files": [], "write_files": [], "new_files": []}), \
                    patch.object(coder, "run_worker", side_effect=failure) as worker:
                result = coder.coder_node({"task": "edit app", "repo_dir": str(repo), "plan_steps": ["edit"]})
                worker.assert_called_once()
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(graph.route_after_coder(result), "finalizer")
            self.assertEqual(result["worker_history"][0]["evidence"]["remaining_processes"], 1)

    def test_fixer_cleanup_failure_blocks_before_tester(self):
        with TemporaryDirectory() as temp:
            failure = WorkerBoundaryError("WORKER_BOUNDARY_UNVERIFIED",
                                          {"cleanup_status": "UNPROVEN", "remaining_processes": 1})
            with patch.object(fixer, "repair_packet", return_value={"evidence": "{}", "context": "", "diff": {"text": "", "omitted_or_truncated_files": 0}, "metrics": {}}), \
                    patch.object(fixer, "file_tool_flags", return_value=no_file_tool_flags()), \
                    patch.object(fixer, "capability_contract", return_value="Fixture: no file capabilities"), \
                    patch.object(fixer, "sealed_policy", return_value={"files": [], "write_files": [], "new_files": []}), \
                    patch.object(fixer, "run_worker", side_effect=failure) as worker:
                result = fixer.fixer_node({"task": "repair app", "repo_dir": temp, "fix_attempts": 1})
                worker.assert_called_once()
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["fix_attempts"], 2)
            self.assertEqual(graph.route_after_fixer(result), "finalizer")

    def test_coder_timeout_with_proven_cleanup_cannot_verify(self):
        with TemporaryDirectory() as temp:
            repo = Path(temp)
            (repo / ".git").write_text("fixture")
            timeout = WorkerResult(124, "", {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
            with patch.object(coder, "_git_clean", return_value=True), \
                    patch.object(coder, "file_tool_flags", return_value=no_file_tool_flags()), \
                    patch.object(coder, "capability_contract", return_value="Fixture: no file capabilities"), \
                    patch.object(coder, "sealed_policy", return_value={"files": [], "write_files": [], "new_files": []}), \
                    patch.object(coder, "run_worker", return_value=timeout) as worker:
                result = coder.coder_node({"task": "edit app", "repo_dir": str(repo), "plan_steps": ["edit"]})
                worker.assert_called_once()
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["coder_error"], "CODER_TIMEOUT")
            self.assertEqual(graph.route_after_coder(result), "finalizer")

    def test_fixer_timeout_with_proven_cleanup_cannot_verify(self):
        with TemporaryDirectory() as temp:
            timeout = WorkerResult(124, "", {"cleanup_status": "CONFIRMED", "remaining_processes": 0})
            with patch.object(fixer, "repair_packet", return_value={"evidence": "{}", "context": "", "diff": {"text": "", "omitted_or_truncated_files": 0}, "metrics": {}}), \
                    patch.object(fixer, "file_tool_flags", return_value=no_file_tool_flags()), \
                    patch.object(fixer, "capability_contract", return_value="Fixture: no file capabilities"), \
                    patch.object(fixer, "sealed_policy", return_value={"files": [], "write_files": [], "new_files": []}), \
                    patch.object(fixer, "run_worker", return_value=timeout) as worker:
                result = fixer.fixer_node({"task": "repair app", "repo_dir": temp, "fix_attempts": 1})
                worker.assert_called_once()
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["fixer_error"], "FIXER_TIMEOUT")
            self.assertEqual(graph.route_after_fixer(result), "finalizer")


if __name__ == "__main__":
    unittest.main()
