"""Supervisor-owned MCP broker session, with a request-only worker relay.

Outcomes remain in supervisor memory. No telemetry API/file/token is given
to the CLI. The same validated policy is used for every request in a session.
"""

import hashlib
import json
import os
import selectors
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from roles.broker_telemetry import BrokerTelemetry
from roles.file_tools import MAX_MESSAGE_BYTES, serve
from roles.read_policy import validate_policy


class BrokerSession:
    def __init__(self, directory, policy):
        self.policy = validate_policy(policy)
        self.telemetry = BrokerTelemetry()
        self.path = str(Path(directory) / "broker.sock")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.listener.bind(self.path)
            os.chmod(self.path, 0o600)
            self.listener.listen(1)
            self.listener.settimeout(0.1)
        except Exception:
            self.listener.close()
            raise RuntimeError("BROKER_SESSION_SETUP_FAILED") from None
        self.connection = None
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        # Started after Popen: never fork the CLI with a live broker thread.
        self.thread.start()

    def _serve(self):
        try:
            while not self.stopping.is_set():
                try:
                    connection, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            self.connection = connection
            # One MCP connection for this worker; reconnects cannot reset budgets.
            self.listener.close()
            if self.stopping.is_set():
                return
            with connection.makefile("rb") as incoming, connection.makefile("w", encoding="utf-8") as outgoing:
                serve(self.policy, incoming, outgoing, self.telemetry)
        except Exception as exc:
            # FileTools already counted and sanitized fatal operation errors.
            counted = isinstance(exc, RuntimeError) and exc.args == ("FILE_TOOL_INTERNAL",)
            if not self.stopping.is_set() and not counted:
                self.telemetry.failure("BROKER_INTERNAL", error=True)
        finally:
            if self.connection is not None:
                self.connection.close()

    def stop(self):
        self.stopping.set()
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.listener.close()
        if self.thread.ident is not None:
            self.thread.join(timeout=3)
            if self.thread.is_alive():
                raise RuntimeError("BROKER_CLEANUP_FAILED")
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        return self.telemetry.snapshot()


def prepare_session(command, directory):
    """Replace only the controller's exact file-server configuration.

    The model receives a relay endpoint, not a policy or outcome writer.
    Commands without the file broker (e.g. Planner) remain unchanged.
    """
    if "--mcp-config" not in command:
        return list(command), None
    index = command.index("--mcp-config") + 1
    config = json.loads(command[index])
    servers = config.get("mcpServers", {})
    if not servers:
        return list(command), None
    if set(servers) != {"freeagent_files"}:
        raise ValueError("BROKER_CONFIGURATION_INVALID")
    server = servers["freeagent_files"]
    args = server.get("args")
    expected = str(Path(__file__).with_name("file_tools.py"))
    if (server.get("type") != "stdio" or server.get("command") != sys.executable
            or not isinstance(args, list) or len(args) != 4 or args[:2] != ["-I", expected]
            or not isinstance(args[2], str) or len(args[2].encode()) > MAX_MESSAGE_BYTES
            or hashlib.sha256(args[2].encode()).hexdigest() != args[3]):
        raise ValueError("BROKER_CONFIGURATION_INVALID")
    session = BrokerSession(directory, json.loads(args[2]))
    replacement = list(command)
    server["args"] = ["-I", str(Path(__file__)), "--relay", session.path]
    replacement[index] = json.dumps(config)
    return replacement, session


def relay(endpoint):
    """Bounded byte transport only: no policy, outcomes, or telemetry updates."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.connect(endpoint)
        with selectors.DefaultSelector() as selector:
            selector.register(sys.stdin.buffer, selectors.EVENT_READ, "input")
            selector.register(channel, selectors.EVENT_READ, "broker")
            while True:
                for key, _ in selector.select():
                    if key.data == "input":
                        data = os.read(sys.stdin.fileno(), 8192)
                        if not data:
                            channel.shutdown(socket.SHUT_WR)
                            selector.unregister(sys.stdin.buffer)
                        else:
                            channel.sendall(data)
                    else:
                        data = channel.recv(8192)
                        if not data:
                            return
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--relay":
            raise ValueError("BROKER_RELAY_INVALID")
        relay(sys.argv[2])
    except Exception:
        sys.stderr.write("BROKER_RELAY_FAILED\n")
        sys.exit(125)
