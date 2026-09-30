"""Monotonic, secret-safe worker timing evidence without model calls."""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "orchestrator"))

from roles import coder, planner, worker
from roles.worker import WorkerBoundaryError, WorkerResult, run_worker
import cli


class WorkerTimingTests(unittest.TestCase):
    def execute(self, code, *, timeout=3, role="planner"):
        return run_worker([sys.executable, "-c", code], cwd=ROOT, timeout=timeout, role=role)

    def assert_timing(self, result):
        evidence = result.evidence
        self.assertEqual(evidence["cleanup_status"], "CONFIRMED")
        self.assertEqual(evidence["remaining_processes"], 0)
        for key in ("worker_scope_setup_ms", "worker_process_spawn_ms",
                    "worker_process_runtime_ms", "worker_cleanup_ms", "worker_total_ms"):
            self.assertIsInstance(evidence[key], int)
            self.assertGreaterEqual(evidence[key], 0)
        self.assertGreaterEqual(evidence["worker_total_ms"], evidence["worker_process_runtime_ms"])

    def test_fast_stdout(self):
        result = self.execute("print('ok', flush=True)")
        self.assert_timing(result)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.evidence["worker_phase"], "NORMAL_COMPLETE")
        self.assertIsInstance(result.evidence["worker_first_stdout_byte_ms"], int)
        self.assertIsNone(result.evidence["worker_first_stderr_byte_ms"])
        self.assertGreater(result.evidence["worker_stdout_bytes_seen"], 0)

    def test_delayed_first_byte(self):
        result = self.execute("import time;time.sleep(.15);print('late',flush=True)")
        self.assert_timing(result)
        self.assertGreaterEqual(result.evidence["worker_first_stdout_byte_ms"], 100)

    def test_stderr_first(self):
        code = "import sys,time;sys.stderr.write('first\\n');sys.stderr.flush();time.sleep(.15);print('second',flush=True)"
        result = self.execute(code)
        self.assert_timing(result)
        evidence = result.evidence
        self.assertEqual(evidence["worker_phase"], "STDERR_BEFORE_STDOUT")
        self.assertLess(evidence["worker_first_stderr_byte_ms"], evidence["worker_first_stdout_byte_ms"])
        self.assertEqual(result.stdout, "second\n")
        self.assertEqual(evidence["worker_stderr_bytes_seen"], len("first\n"))

    def test_stderr_does_not_corrupt_json_stdout(self):
        code = "import sys;sys.stderr.write('status\\n');sys.stderr.flush();print('{\"value\":\"ok\"}',flush=True)"
        result = self.execute(code)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"value": "ok"})
        self.assertFalse(result.evidence["output_truncated"])

    def test_no_output_timeout(self):
        result = self.execute("import time;time.sleep(10)", timeout=1)
        self.assert_timing(result)
        evidence = result.evidence
        self.assertEqual(result.returncode, 124)
        self.assertTrue(evidence["timeout_triggered"])
        self.assertEqual(evidence["worker_phase"], "PROCESS_STARTED_NO_OUTPUT")
        self.assertIsNone(evidence["worker_first_stdout_byte_ms"])
        self.assertIsNone(evidence["worker_first_stderr_byte_ms"])

    def test_output_then_timeout(self):
        result = self.execute("import time;print('started',flush=True);time.sleep(10)", timeout=1)
        self.assert_timing(result)
        self.assertEqual(result.evidence["worker_phase"], "FIRST_OUTPUT_BEFORE_TIMEOUT")
        self.assertTrue(result.evidence["timeout_triggered"])

    def test_spawn_failure(self):
        with patch.object(worker.subprocess, "Popen", side_effect=OSError("fake secret value")):
            with self.assertRaises(WorkerBoundaryError) as caught:
                self.execute("print('never')")
        self.assertEqual(str(caught.exception), "WORKER_SPAWN_FAILURE")
        self.assertEqual(caught.exception.evidence["worker_phase"], "PROCESS_NEVER_STARTED")
        self.assertNotIn("fake secret value", json.dumps(caught.exception.evidence))

    def test_cleanup_failure_blocks(self):
        with patch.object(worker, "_cleanup_outer_scope", side_effect=WorkerBoundaryError("WORKER_SCOPE_CLEANUP_UNPROVEN")):
            with self.assertRaisesRegex(WorkerBoundaryError, "WORKER_SCOPE_CLEANUP_UNPROVEN"):
                self.execute("print('ok')")

    def test_normal_coder_timing(self):
        result = self.execute("print('coder-ok')", role="coder")
        self.assert_timing(result)
        self.assertEqual(result.evidence["role"], "coder")

    def test_normal_planner_diagnostic_timing(self):
        evidence = {"cleanup_status": "CONFIRMED", "remaining_processes": 0,
                    "worker_total_ms": 140, "worker_first_stdout_byte_ms": 90,
                    "worker_first_stderr_byte_ms": None, "worker_phase": "NORMAL_COMPLETE",
                    "gateway_health_status": "HEALTHY", "gateway_health_latency_ms": 3}
        response = {"structured_output": {"needs_research": False, "research_type": "none",
                                           "research_query": "", "steps": ["Fix bug"],
                                           "coding_units": [{"goal": "Fix the bug", "target_files": []}]}}
        with patch.object(planner, "verify_execution_contract"), \
                patch.object(planner, "run_worker", return_value=WorkerResult(0, json.dumps(response), evidence)):
            state = planner.planner_node({"task": "Fix bug"})
        self.assertEqual(state["planner_diagnostic"]["worker_total_ms"], 140)
        self.assertEqual(state["planner_diagnostic"]["first_stdout_byte_ms"], 90)
        self.assertIsInstance(state["planner_diagnostic"]["response_parse_ms"], int)

    def test_secret_environment_is_absent_from_evidence(self):
        secret = "Bearer fake_secret_123"
        with patch.dict(os.environ, {"FREEAGENT_TIMING_TEST_SECRET": secret}):
            result = self.execute("import os;print('ok')")
        self.assert_timing(result)
        self.assertNotIn(secret, json.dumps(result.evidence))

    def test_gateway_health_is_optional_and_local(self):
        class Response:
            status = 200
        class Connection:
            def __init__(self, host, port, timeout):
                self.assertion = (host, port, timeout)
            def request(self, method, path):
                self.requested = (method, path)
            def getresponse(self):
                return Response()
            def close(self):
                pass
        with patch.object(worker.http.client, "HTTPConnection", Connection):
            health = worker._gateway_health()
        self.assertEqual(health["gateway_health_status"], "HEALTHY")
        self.assertEqual(health["gateway_request_observed"], "UNAVAILABLE")
        self.assertIsInstance(health["gateway_health_latency_ms"], int)

    def test_cli_projection_keeps_only_safe_timing(self):
        secret = "Bearer fake_secret_123"
        evidence = {"worker_phase": "PROCESS_STARTED_NO_OUTPUT", "worker_total_ms": 90000,
                    "worker_first_stdout_byte_ms": None, "gateway_health_status": "HEALTHY",
                    "gateway_health_latency_ms": 3, "worker_exit_code": 124,
                    "cleanup_status": "CONFIRMED", "remaining_processes": 0, "raw": secret}
        state = {"status": "BLOCKED", "trace": ["planner:error"],
                 "planner_error_code": "PLANNER_WORKER_TIMEOUT",
                 "planner_diagnostic": {"worker_phase": "PROCESS_STARTED_NO_OUTPUT",
                                        "worker_total_ms": 90000, "gateway_health_status": "HEALTHY",
                                        "raw": secret},
                 "worker_history": [{"role": "planner", "evidence": evidence}],
                 "role_timing_history": [{"role": "planner", "elapsed_ms": 90020}]}
        result = cli._projection(state, Path("/tmp/fixture"), "task", {})
        self.assertEqual(result["role_timings_ms"][0]["elapsed_ms"], 90020)
        self.assertEqual(result["resource_evidence"]["workers"][0]["evidence"]["worker_phase"],
                         "PROCESS_STARTED_NO_OUTPUT")
        self.assertNotIn(secret, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
