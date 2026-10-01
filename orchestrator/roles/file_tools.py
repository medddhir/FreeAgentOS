"""Bounded stdio MCP file tools; no shell, network, or caller-created policy.

Transport/lifecycle: modelcontextprotocol.io/specification/2025-06-18/basic.
All responses contain authorized data or fixed error codes, never exceptions.
"""

import fnmatch
import copy
import hashlib
import json
import os
import stat
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from roles.broker_telemetry import BrokerTelemetry, REASONS
from roles.inspector import _parent_fd
from roles.read_policy import (MAX_QUERY_CHARS, MAX_READ_BYTES, MAX_RESULTS, MAX_SESSION_BYTES,
                               MAX_TOOL_CALLS, TOOLS, ReadDenied, content_allowed,
                               read_authorized, require_write, validate_policy)

MAX_MESSAGE_BYTES = 64 * 1024
PROTOCOL = "2025-06-18"
SCHEMAS = {
    "read_file": {"path": {"type": "string"}, "offset": {"type": "integer", "minimum": 0}},
    "glob_files": {"pattern": {"type": "string"}},
    "grep_files": {"query": {"type": "string"}},
    "edit_file": {"path": {"type": "string"}, "old_text": {"type": "string"},
                  "new_text": {"type": "string"}},
    "write_file": {"path": {"type": "string"}, "text": {"type": "string"}},
}


def tool_list(policy):
    """Bound tool argument choices to the controller's validated session policy."""
    policy = validate_policy(policy)
    existing = []
    for path in policy["write_files"]:
        if path in policy["new_files"]:
            try:
                read_authorized(policy, path)
            except ReadDenied:
                continue
        existing.append(path)
    choices = {"read_file": policy["files"], "edit_file": existing,
               "write_file": policy["write_files"]}
    descriptions = {"read_file": "Read a listed workspace-relative path exactly (no absolute path or ./), in bounded byte chunks.",
                    "glob_files": "List only authorized current files matching a relative glob; results grant no write access.",
                    "grep_files": "Literal substring search only within authorized current files; results grant no write access.",
                    "edit_file": "Edit a listed writable existing file; use its exact relative path and one nonempty unique old_text match.",
                    "write_file": "Replace a listed writable existing file, or create a listed creation-approved path. Exact relative path; text at most 8192 UTF-8 bytes. Prefer Edit for focused changes."}
    creation = ("NEW FILE CREATION: only CREATION APPROVED paths." if policy["new_files"]
                else "NEW FILE CREATION: NONE. Write replaces listed existing files only.")
    descriptions["write_file"] += " " + creation
    result = []
    for name, definition in SCHEMAS.items():
        properties = copy.deepcopy(definition)
        if name in choices:
            paths = list(choices[name])
            # Do not publish an invalid empty enum or a fake sentinel path.
            properties["path"].update({"enum": paths} if paths else {"not": {}})
            if not paths:
                descriptions[name] += " NO AUTHORIZED PATHS; do not call this tool."
        result.append({"name": name, "description": descriptions[name],
                       "inputSchema": {"type": "object", "properties": properties,
                                       "required": [key for key in properties if key != "offset"],
                                       "additionalProperties": False}})
    return result


def denial_reason(exc, calls):
    """Map fixed internal codes to the existing safe broker reason taxonomy."""
    code = exc.args[0] if len(exc.args) == 1 else None
    if code == "FILE_TOOL_BUDGET_EXHAUSTED":
        return "TOOL_BUDGET" if calls > MAX_TOOL_CALLS else "SESSION_BUDGET"
    if code == "FILE_TOOL_ARGUMENT_INVALID":
        return "INVALID_REQUEST"
    return code if isinstance(code, str) and code in REASONS else "BROKER_INTERNAL"


def _identity(info):
    return None if info is None else (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                                      info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _write(policy, name, text, expected=None):
    require_write(policy, name)
    if not isinstance(text, str):
        raise ReadDenied("READ_DENIED")
    encoded = text.encode("utf-8")
    if len(encoded) > 65536 or not content_allowed(encoded):
        raise ReadDenied("WRITE_DENIED")
    directory = _parent_fd(policy["root"], name, policy["root_identity"],
                           create=name in policy["new_files"])
    base = name.split("/")[-1]
    temporary = ".freeagent-write-" + uuid.uuid4().hex
    try:
        try:
            before = os.stat(base, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            before = None
        if before is None:
            if name not in policy["new_files"]:
                raise ReadDenied("WRITE_DENIED")
        else:
            # Write and Edit cannot be used to probe or overwrite denied data.
            current = read_authorized(policy, name)
            if expected is not None and current != expected:
                raise ReadDenied("WRITE_CHANGED")
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ReadDenied("WRITE_DENIED")
        mode = stat.S_IMODE(before.st_mode) & 0o755 if before is not None else 0o644
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
                     dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            now = os.stat(base, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            now = None
        if _identity(before) != _identity(now):
            raise ReadDenied("WRITE_CHANGED")
        os.replace(temporary, base, src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


class FileTools:
    def __init__(self, policy, telemetry=None):
        self.policy = validate_policy(copy.deepcopy(policy))
        self.telemetry = telemetry if telemetry is not None else BrokerTelemetry()
        self.calls = 0
        self.bytes_returned = 0

    def call(self, name, arguments):
        self.telemetry.request(name)
        try:
            result = self._call(name, arguments)
        except ReadDenied as exc:
            reason = denial_reason(exc, self.calls)
            self.telemetry.failure(reason, error=reason == "BROKER_INTERNAL", tool=name)
            if reason == "BROKER_INTERNAL":
                raise ReadDenied("FILE_TOOL_INTERNAL") from None
            raise
        except (OSError, ValueError, TypeError) as exc:
            self.telemetry.failure("BROKER_INTERNAL", error=True)
            error_type = (OSError if isinstance(exc, OSError) else
                          TypeError if isinstance(exc, TypeError) else ValueError)
            raise error_type("FILE_TOOL_INTERNAL") from None
        except Exception:
            self.telemetry.failure("BROKER_INTERNAL", error=True)
            raise RuntimeError("FILE_TOOL_INTERNAL") from None
        self.telemetry.success(name)
        return result

    def _call(self, name, arguments):
        self.calls += 1
        if self.calls > MAX_TOOL_CALLS or self.bytes_returned >= MAX_SESSION_BYTES:
            raise ReadDenied("FILE_TOOL_BUDGET_EXHAUSTED")
        if name not in TOOLS or not isinstance(arguments, dict):
            raise ReadDenied("FILE_TOOL_ARGUMENT_INVALID")
        required = set(SCHEMAS[name]) - {"offset"}
        if not required <= arguments.keys() or arguments.keys() - SCHEMAS[name].keys():
            raise ReadDenied("FILE_TOOL_ARGUMENT_INVALID")
        for key, value in arguments.items():
            if key == "offset":
                if type(value) is not int or not 0 <= value <= 65536:
                    raise ReadDenied("FILE_TOOL_ARGUMENT_INVALID")
            elif not isinstance(value, str) or len(value.encode()) > MAX_READ_BYTES:
                raise ReadDenied("FILE_TOOL_ARGUMENT_INVALID")
        if name == "read_file":
            raw = read_authorized(self.policy, arguments["path"])
            offset = arguments.get("offset", 0)
            result = {"text": raw[offset:offset + MAX_READ_BYTES].decode("utf-8", "ignore"),
                      "offset": offset, "next_offset": min(len(raw), offset + MAX_READ_BYTES),
                      "file_bytes": len(raw), "truncated": offset + MAX_READ_BYTES < len(raw)}
        elif name in ("glob_files", "grep_files"):
            query = arguments["pattern" if name == "glob_files" else "query"]
            if (not query or len(query) > MAX_QUERY_CHARS or any(ord(ch) < 32 or ord(ch) > 126 for ch in query)
                    or name == "glob_files" and (query.startswith("/") or "\\" in query
                                                  or any(p in ("", ".", "..") for p in query.split("/")))):
                raise ReadDenied("FILE_TOOL_ARGUMENT_INVALID")
            records, used, truncated = [], 0, False
            for path in self.policy["files"]:
                try:
                    raw = read_authorized(self.policy, path)
                except ReadDenied:
                    continue
                if name == "glob_files":
                    items = [path] if fnmatch.fnmatchcase(path, query) or (
                        query.startswith("**/") and fnmatch.fnmatchcase(path, query[3:])) else []
                else:
                    items = ({"path": path, "line": i, "text": line[:300]}
                             for i, line in enumerate(raw.decode("utf-8").splitlines(), 1) if query in line)
                for item in items:
                    size = len(json.dumps(item).encode())
                    if len(records) == MAX_RESULTS or used + size > MAX_READ_BYTES - 512:
                        truncated = True
                        break
                    records.append(item)
                    used += size
                if truncated:
                    break
            result = {"matches": records, "truncated": truncated}
        elif name == "edit_file":
            require_write(self.policy, arguments["path"])
            raw = read_authorized(self.policy, arguments["path"])
            text = raw.decode("utf-8")
            old = arguments["old_text"]
            if not old or text.count(old) != 1:
                raise ReadDenied("EDIT_MATCH_INVALID")
            if self.bytes_returned + len(json.dumps({"updated": True}).encode()) > MAX_SESSION_BYTES:
                raise ReadDenied("FILE_TOOL_BUDGET_EXHAUSTED")
            _write(self.policy, arguments["path"], text.replace(old, arguments["new_text"], 1), expected=raw)
            result = {"updated": True}
        else:
            if self.bytes_returned + len(json.dumps({"updated": True}).encode()) > MAX_SESSION_BYTES:
                raise ReadDenied("FILE_TOOL_BUDGET_EXHAUSTED")
            _write(self.policy, arguments["path"], arguments["text"])
            result = {"updated": True}
        serialized = json.dumps(result)
        if self.bytes_returned + len(serialized.encode()) > MAX_SESSION_BYTES:
            raise ReadDenied("FILE_TOOL_BUDGET_EXHAUSTED")
        self.bytes_returned += len(serialized.encode())
        return result


def serve(policy, input_stream, output_stream, telemetry=None):
    tools = FileTools(policy, telemetry)
    initialized = ready = False
    advertised = tool_list(tools.policy)
    list_changes = bool(tools.policy["new_files"])
    for _ in range(MAX_TOOL_CALLS + 32):
        line = input_stream.readline(MAX_MESSAGE_BYTES + 1)
        if not line:
            return
        # Oversized records end the channel; never parse their fragments.
        if len(line) > MAX_MESSAGE_BYTES or not line.endswith(b"\n"):
            tools.telemetry.failure("MALFORMED_REQUEST")
            return
        request = None
        changed = False
        try:
            request = json.loads(line)
            if (not isinstance(request, dict) or request.get("jsonrpc") != "2.0"
                    or not isinstance(request.get("method"), str)
                    or "id" in request and (type(request["id"]) not in (int, str)
                                               or len(str(request["id"])) > 64)):
                raise ReadDenied("FILE_TOOL_PROTOCOL_INVALID")
            method = request["method"]
            params = request.get("params", {})
            if not isinstance(params, dict):
                raise ReadDenied("FILE_TOOL_PROTOCOL_INVALID")
            if method == "initialize" and not initialized:
                initialized = True
                result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {"listChanged": list_changes}},
                          "serverInfo": {"name": "freeagent_files", "version": "1"}}
            elif method == "notifications/initialized" and initialized:
                ready = True
                continue
            elif method == "ping":
                result = {}
            elif method == "tools/list" and ready:
                advertised = tool_list(tools.policy)
                result = {"tools": advertised}
            elif method == "tools/call" and ready:
                try:
                    data = tools.call(params.get("name"), params.get("arguments", {}))
                    result = {"content": [{"type": "text", "text": json.dumps(data)}], "isError": False}
                    if list_changes and params.get("name") == "write_file":
                        current = tool_list(tools.policy)
                        changed = current != advertised
                        advertised = current
                except (ReadDenied, OSError, ValueError, TypeError) as exc:
                    # No exception/request data leaves this boundary: only a
                    # member of the existing fixed controller reason taxonomy.
                    reason = denial_reason(exc, tools.calls) if isinstance(exc, ReadDenied) else "BROKER_INTERNAL"
                    result = {"content": [{"type": "text", "text": "FILE_TOOL_DENIED:" + reason}], "isError": True}
            elif method.startswith("notifications/"):
                continue
            else:
                raise ReadDenied("FILE_TOOL_PROTOCOL_INVALID")
            response = {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
        except (ValueError, TypeError, ReadDenied, RecursionError):
            tools.telemetry.failure("MALFORMED_REQUEST")
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32600, "message": "FILE_TOOL_PROTOCOL_INVALID"}}
        if isinstance(request, dict) and "id" not in request:
            continue
        output_stream.write(json.dumps(response) + "\n")
        if changed:
            output_stream.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}) + "\n")
        output_stream.flush()


def main():
    try:
        if len(sys.argv) != 3 or len(sys.argv[1].encode()) > MAX_MESSAGE_BYTES:
            raise ReadDenied("READ_POLICY_INVALID")
        if hashlib.sha256(sys.argv[1].encode()).hexdigest() != sys.argv[2]:
            raise ReadDenied("READ_POLICY_INVALID")
        serve(json.loads(sys.argv[1]), sys.stdin.buffer, sys.stdout)
    except (OSError, ValueError, TypeError, ReadDenied, RecursionError):
        sys.stderr.write("FILE_TOOL_POLICY_INVALID\n")
        return 125
    return 0


if __name__ == "__main__":
    sys.exit(main())
