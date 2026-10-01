"""Incremental Claude Code 2.1.284 NDJSON metadata boundary.

Never returns text, arguments, results, names, IDs, or parser exception messages.
Malformed transport blocks completion; timeout and cleanup retain precedence.
"""
import json

MAX_RECORD_BYTES = 64 * 1024
MAX_STREAM_BYTES = 256 * 1024
MAX_EVENTS = 512
MAX_PENDING = 128
MAX_TIME_MS = 10_000_000
TOOL_NAMES = {"mcp__freeagent_files__" + name + "_file": name
              for name in ("read", "edit", "write")}
TOOL_NAMES.update({"mcp__freeagent_files__glob_files": "glob",
                   "mcp__freeagent_files__grep_files": "grep"})
COUNTS = ("stream_events_total", "tool_events_total", "tool_success_events",
          "tool_error_events", "read_events", "glob_events", "grep_events",
          "edit_events", "write_events", "unknown_tool_events", "stream_parser_errors")
TIMES = ("first_stream_event_ms", "first_tool_event_ms", "last_tool_event_ms",
         "last_progress_event_ms", "final_result_ms")
STATUSES = ("ACTIVE", "COMPLETE", "MODEL_ERROR", "INVALID", "NO_FINAL_RESULT")


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("STREAM_OBJECT_INVALID")
        value[key] = item
    return value


def _constant(_value):
    raise ValueError("STREAM_NUMBER_INVALID")


def safe_activity(value):
    if not isinstance(value, dict):
        return {}
    result = {key: value[key] for key in COUNTS if type(value.get(key)) is int
              and 0 <= value[key] <= MAX_EVENTS}
    result.update({key: value[key] for key in TIMES if key in value and (value[key] is None
                   or type(value[key]) is int and 0 <= value[key] <= MAX_TIME_MS)})
    if value.get("activity_status") in STATUSES:
        result["activity_status"] = value["activity_status"]
    if type(value.get("final_result_seen")) is bool:
        result["final_result_seen"] = value["final_result_seen"]
    return result


class ActivityCapture:
    """Bounded capture-compatible sink; raw bytes never reach WorkerResult."""
    def __init__(self):
        self.buffer = bytearray()
        self.pending = {}
        self.total = 0
        self.truncated = False
        self.now_ms = 0
        self.last_tool_success_ms = None
        self.data = {key: 0 for key in COUNTS}
        self.data.update({key: None for key in TIMES})
        self.data.update(activity_status="ACTIVE", final_result_seen=False)

    def fail(self, *, bound=False):
        self.data["activity_status"] = "INVALID"
        self.data["stream_parser_errors"] = min(MAX_EVENTS, self.data["stream_parser_errors"] + 1)
        self.truncated |= bound
        self.buffer.clear()
        self.pending.clear()

    def add(self, chunk):
        self.total += len(chunk)
        if self.data["activity_status"] == "INVALID":
            return
        if self.total > MAX_STREAM_BYTES:
            self.fail(bound=True)
            return
        # Consume a pipe chunk record by record; never accumulate a whole stream.
        for part in chunk.splitlines(keepends=True):
            if len(self.buffer) + len(part) > MAX_RECORD_BYTES:
                self.fail(bound=True)
                return
            self.buffer.extend(part)
            if self.buffer.endswith(b"\n"):
                raw = bytes(self.buffer)
                self.buffer.clear()
                self.record(raw)
                if self.data["activity_status"] == "INVALID":
                    return

    def record(self, raw):
        try:
            event = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
            if not isinstance(event, dict) or not isinstance(event.get("type"), str):
                raise ValueError
            if self.data["final_result_seen"] or self.data["stream_events_total"] >= MAX_EVENTS:
                raise ValueError
            self.data["stream_events_total"] += 1
            if self.data["first_stream_event_ms"] is None:
                self.data["first_stream_event_ms"] = self.now_ms
            kind = event["type"]
            if kind in ("assistant", "user"):
                message = event.get("message")
                if not isinstance(message, dict) or not isinstance(message.get("content"), list):
                    raise ValueError
                blocks = message["content"]
                if len(blocks) > MAX_PENDING:
                    raise ValueError
                for block in blocks:
                    if not isinstance(block, dict) or not isinstance(block.get("type"), str):
                        raise ValueError
                    if kind == "assistant" and block["type"] == "tool_use":
                        identifier = block.get("id")
                        if (not isinstance(identifier, str) or not 1 <= len(identifier) <= 128
                                or identifier in self.pending or len(self.pending) >= MAX_PENDING
                                or not isinstance(block.get("name"), str)
                                or not isinstance(block.get("input"), dict)):
                            raise ValueError
                        category = TOOL_NAMES.get(block["name"])
                        self.pending[identifier] = category
                        self.data["tool_events_total"] += 1
                        self.data[(category + "_events") if category else "unknown_tool_events"] += 1
                        if category:
                            if self.data["first_tool_event_ms"] is None:
                                self.data["first_tool_event_ms"] = self.now_ms
                            self.data["last_tool_event_ms"] = self.now_ms
                            self.data["last_progress_event_ms"] = self.now_ms
                    elif kind == "user" and block["type"] == "tool_result":
                        identifier = block.get("tool_use_id")
                        if not isinstance(identifier, str) or identifier not in self.pending:
                            raise ValueError
                        error = block.get("is_error", False)
                        if type(error) is not bool:
                            raise ValueError
                        category = self.pending.pop(identifier)
                        if category and not error:
                            self.last_tool_success_ms = self.now_ms
                        self.data["tool_error_events" if error else "tool_success_events"] += 1
                        if category:
                            self.data["last_tool_event_ms"] = self.now_ms
                            self.data["last_progress_event_ms"] = self.now_ms
                    # Text/thinking blocks are deliberately not progress.
            elif kind == "result":
                if type(event.get("is_error")) is not bool or not isinstance(event.get("subtype"), str):
                    raise ValueError
                if event["subtype"] == "success" and not event["is_error"]:
                    if not isinstance(event.get("result"), str) or self.pending:
                        raise ValueError
                    self.data["activity_status"] = "COMPLETE"
                elif event["is_error"]:
                    self.data["activity_status"] = "MODEL_ERROR"
                else:
                    raise ValueError
                self.data["final_result_seen"] = True
                self.data["final_result_ms"] = self.now_ms
                self.data["last_progress_event_ms"] = self.now_ms
            elif kind == "system":
                if not isinstance(event.get("subtype"), str) or not event["subtype"]:
                    raise ValueError
            elif kind not in ("tool_progress", "tool_use_summary", "rate_limit_event"):
                raise ValueError
            if any(self.data[key] > MAX_EVENTS for key in COUNTS):
                raise ValueError
        except (ValueError, TypeError, RecursionError, UnicodeError):
            self.fail()

    def finish(self):
        if self.buffer:
            self.fail()  # NDJSON must terminate records; no partial result accepted.
        elif self.data["activity_status"] == "ACTIVE":
            self.data["activity_status"] = "NO_FINAL_RESULT"
        self.pending.clear()
        return safe_activity(self.data)

    def render(self):
        return b"MODEL_WORKER_COMPLETED" if self.data["activity_status"] == "COMPLETE" else b""
