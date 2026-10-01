"""Stage 1.7 broker-authenticated outcomes, synthetic requests only."""
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_file_read_policy as fixtures
from roles import file_tools
from roles.broker_telemetry import COUNTER_MAX, REASONS, safe_broker
from roles.broker_session import BrokerSession, prepare_session
from roles.read_policy import MAX_SESSION_BYTES, MAX_TOOL_CALLS, ReadDenied, file_tool_flags
from roles.worker import run_worker
import cli


class BrokerTelemetryTests(unittest.TestCase):
    def setUp(self):
        fixtures.FileReadPolicyTests.setUp(self)

    def evidence(self):
        return self.tools.telemetry.snapshot()

    def deny(self, name, arguments, reason):
        with self.assertRaises(ReadDenied):
            self.tools.call(name, arguments)
        self.assertEqual(self.evidence()["denials_by_reason"], {reason: 1})
        self.assertEqual(self.evidence()["denied_total"], 1)

    def test_read_success(self):
        self.tools.call("read_file", {"path": "app.py"})
        self.assertEqual(self.evidence()["read_success"], 1)
        self.assertEqual(self.evidence()["requests_total"], 1)

    def test_glob_success(self):
        self.tools.call("glob_files", {"pattern": "*.py"})
        self.assertEqual(self.evidence()["glob_success"], 1)

    def test_grep_success(self):
        self.tools.call("grep_files", {"query": "return"})
        self.assertEqual(self.evidence()["grep_success"], 1)

    def test_edit_success(self):
        self.tools.call("edit_file", {"path": "app.py", "old_text": "return 1", "new_text": "return 2"})
        self.assertEqual(self.evidence()["edit_success"], 1)

    def test_write_success(self):
        self.tools.call("write_file", {"path": "app.py", "text": "value = 2\n"})
        self.assertEqual(self.evidence()["write_success"], 1)

    def test_unauthorized(self):
        self.deny("read_file", {"path": "unrelated.py"}, "READ_DENIED")

    def test_protected(self):
        self.deny("write_file", {"path": "test_app.py", "text": "# replaced"}, "WRITE_DENIED")

    def test_secret_path(self):
        self.deny("read_file", {"path": ".env"}, "READ_DENIED")

    def test_symlink(self):
        (self.repo / "app.py").unlink()
        (self.repo / "app.py").symlink_to("unrelated.py")
        self.deny("read_file", {"path": "app.py"}, "FILE_UNAVAILABLE")

    def test_hardlink(self):
        os.link(self.repo / "app.py", self.repo / "alias.py")
        self.deny("read_file", {"path": "app.py"}, "FILE_UNAVAILABLE")

    def test_special_file(self):
        (self.repo / "app.py").unlink()
        os.mkfifo(self.repo / "app.py")
        self.deny("read_file", {"path": "app.py"}, "FILE_UNAVAILABLE")

    def test_missing_file(self):
        (self.repo / "app.py").unlink()
        self.deny("read_file", {"path": "app.py"}, "FILE_UNAVAILABLE")

    def test_malformed_arguments(self):
        self.deny("read_file", {"path": []}, "INVALID_REQUEST")

    def test_session_budget(self):
        self.tools.bytes_returned = MAX_SESSION_BYTES
        self.deny("read_file", {"path": "app.py"}, "SESSION_BUDGET")

    def test_tool_budget(self):
        self.tools.calls = MAX_TOOL_CALLS
        self.deny("read_file", {"path": "app.py"}, "TOOL_BUDGET")

    def test_internal_exception(self):
        with patch.object(file_tools, "read_authorized", side_effect=RuntimeError("secret /host/path")):
            with self.assertRaisesRegex(RuntimeError, "^FILE_TOOL_INTERNAL$"):
                self.tools.call("read_file", {"path": "app.py"})
        self.assertEqual(self.evidence()["error_total"], 1)
        self.assertNotIn("secret", json.dumps(self.evidence()))

    def test_os_error_sanitized(self):
        with patch.object(file_tools, "read_authorized", side_effect=OSError("secret /host/path")):
            with self.assertRaisesRegex(OSError, "^FILE_TOOL_INTERNAL$"):
                self.tools.call("read_file", {"path": "app.py"})
        self.assertEqual(self.evidence()["error_total"], 1)

    def test_fake_secrets_and_paths(self):
        for path in ("sk-fake-secret-token", "password=fake", "/host/private", "../private",
                     "../../.ssh/id_rsa", "app.py\nprivate", "秘密", "a" * 100000):
            with self.assertRaises(ReadDenied):
                self.tools.call("read_file", {"path": path})
            evidence = json.dumps(cli._evidence({"broker": self.evidence()}))
            self.assertNotIn(path, evidence)
        self.assertEqual(self.evidence()["requests_total"], 8)

    def test_unknown_name_never_retained(self):
        self.deny("fake_secret_tool", {}, "INVALID_REQUEST")
        self.assertNotIn("fake_secret_tool", json.dumps(self.evidence()))

    def test_unhashable_name_is_sanitized(self):
        self.deny(["fake-secret"], {}, "INVALID_REQUEST")
        self.assertNotIn("fake-secret", json.dumps(self.evidence()))

    def test_unknown_exception_code_sanitized(self):
        with patch.object(file_tools, "read_authorized", side_effect=ReadDenied("fake-secret /host/path")):
            with self.assertRaisesRegex(ReadDenied, "^FILE_TOOL_INTERNAL$"):
                self.tools.call("read_file", {"path": "app.py"})
        self.assertEqual(self.evidence()["error_total"], 1)
        self.assertNotIn("fake-secret", json.dumps(self.evidence()))

    def test_cli_drops_forged_nested_fields(self):
        public = cli._evidence({"broker": {"requests_total": 4, "raw": "fake-secret",
                                         "denials_by_reason": {"/host/private": 2}}})
        self.assertEqual(public["broker"]["requests_total"], 4)
        self.assertNotIn("fake-secret", json.dumps(public))
        self.assertNotIn("/host/private", json.dumps(public))

    def test_fixed_projection_saturation(self):
        projected = safe_broker({"requests_total": 10**100, "read_success": True,
                                 "evil": "fake-secret", "denials_by_reason": {"evil-secret": 9, "READ_DENIED": -1}})
        self.assertEqual(projected["requests_total"], COUNTER_MAX)
        self.assertEqual(projected["read_success"], 0)
        self.assertNotIn("evil", json.dumps(projected))
        self.assertEqual(projected["denials_by_reason"], {})

    def test_protocol_malformed_and_oversized(self):
        for raw in (b'{bad}\n', b'a' * (65536 + 1) + b'\n'):
            telemetry = file_tools.BrokerTelemetry()
            output = io.StringIO()
            file_tools.serve(self.policy, io.BytesIO(raw), output, telemetry)
            self.assertEqual(telemetry.snapshot()["denials_by_reason"], {"MALFORMED_REQUEST": 1})
            self.assertNotIn("bad", output.getvalue())

    def test_session_relay_no_counter_api(self):
        session = BrokerSession(self.temp.name, self.policy)
        session.start()
        try:
            with socket.socket(socket.AF_UNIX) as channel:
                channel.connect(session.path)
                request = {"jsonrpc": "2.0", "id": 1, "method": "telemetry/update", "params": {"success_total": 999}}
                channel.sendall((json.dumps(request) + "\n").encode())
                self.assertIn(b'FILE_TOOL_PROTOCOL_INVALID', channel.recv(4096))
        finally:
            result = session.stop()
        self.assertEqual(result["success_total"], 0)
        self.assertEqual(result["denials_by_reason"], {"MALFORMED_REQUEST": 1})
        self.assertFalse(Path(session.path).exists())

    def worker_fixture(self, mode, role="coder"):
        flags = file_tool_flags(self.state, role, unit=self.unit)
        script = '''import json, subprocess, sys, time
config = json.loads(sys.argv[sys.argv.index("--mcp-config") + 1])["mcpServers"]["freeagent_files"]
p = subprocess.Popen([config["command"], *config["args"]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def call(message, response=True):
 p.stdin.write(json.dumps(message) + "\\n"); p.stdin.flush()
 if response: assert json.loads(p.stdout.readline()).get("result") is not None
call({"jsonrpc":"2.0","id":1,"method":"initialize"})
call({"jsonrpc":"2.0","method":"notifications/initialized"},False)
for n,(name,args) in enumerate([("read_file",{"path":"app.py"}),("read_file",{"path":".env"}),("glob_files",{"pattern":"*.py"}),("read_file",{"path":"../../.ssh/id_rsa"})],2):
 call({"jsonrpc":"2.0","id":n,"method":"tools/call","params":{"name":name,"arguments":args}})
mode=sys.argv[1]
if mode=="timeout": time.sleep(10)
p.stdin.close(); p.wait(timeout=2)
if mode=="nonzero": sys.exit(7)
if mode!="missing": print(json.dumps({"type":"result","subtype":"success","is_error":False,"result":"fake-secret discarded"}))
'''
        result = run_worker([sys.executable, "-c", script, mode, *flags], cwd=str(self.repo),
                            timeout=1 if mode == "timeout" else 8, role=role, stream_activity=True)
        self.assertEqual(result.evidence["broker"]["requests_total"], 4)
        self.assertEqual(result.evidence["broker"]["success_total"], 2)
        self.assertEqual(result.evidence["broker"]["denied_total"], 2)
        self.assertEqual(result.evidence["broker"]["read_requests"], 3)
        self.assertNotIn("fake-secret", json.dumps(result.evidence))
        self.assertEqual(result.evidence["remaining_processes"], 0)
        return result

    def test_counters_survive_timeout(self):
        self.assertEqual(self.worker_fixture("timeout").returncode, 124)

    def test_counters_survive_nonzero(self):
        self.assertEqual(self.worker_fixture("nonzero").returncode, 7)

    def test_counters_survive_missing_final(self):
        self.assertEqual(self.worker_fixture("missing").returncode, 65)

    def test_normal_coder(self):
        result = self.worker_fixture("complete")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.evidence["activity"]["tool_events_total"], 0)

    def test_normal_fixer(self):
        self.assertEqual(self.worker_fixture("complete", "fixer").returncode, 0)

    def test_configuration_identity_and_policy_hash(self):
        flags = file_tool_flags(self.state, "coder", unit=self.unit)
        cfg = json.loads(flags[flags.index("--mcp-config") + 1])
        cfg["mcpServers"]["freeagent_files"]["args"][-1] = "invalid"
        with self.assertRaisesRegex(ValueError, "BROKER_CONFIGURATION_INVALID"):
            prepare_session(["fake-cli", "--mcp-config", json.dumps(cfg)], self.temp.name)

    def test_sessions_do_not_share_outcomes(self):
        other = file_tools.FileTools(self.policy)
        self.tools.call("read_file", {"path": "app.py"})
        self.assertEqual(other.telemetry.snapshot()["requests_total"], 0)


if __name__ == "__main__":
    unittest.main()
