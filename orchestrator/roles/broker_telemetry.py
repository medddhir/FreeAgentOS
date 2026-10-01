"""Finite controller-owned broker outcome projection; no request data survives."""

import time

COUNTER_MAX = 65535
TOOLS = {"read_file": "read", "glob_files": "glob", "grep_files": "grep",
         "edit_file": "edit", "write_file": "write"}
PUBLIC_TOOLS = {"read": "Read", "glob": "Glob", "grep": "Grep", "edit": "Edit", "write": "Write"}
REASONS = ("READ_DENIED", "FILE_UNAVAILABLE", "WRITE_DENIED", "WRITE_CHANGED",
           "EDIT_MATCH_INVALID", "INVALID_REQUEST", "TOOL_BUDGET", "SESSION_BUDGET",
           "MALFORMED_REQUEST", "BROKER_INTERNAL")
FIELDS = ("requests_total", "success_total", "denied_total", "error_total", *(
    field for tool in TOOLS.values() for field in (tool + "_requests", tool + "_success")))


def safe_broker(value):
    value = value if isinstance(value, dict) else {}
    def number(n):
        return min(COUNTER_MAX, max(0, n)) if type(n) is int else 0
    reasons = value.get("denials_by_reason", {})
    reasons = reasons if isinstance(reasons, dict) else {}
    by_tool = value.get("denials_by_tool", {})
    by_tool = by_tool if isinstance(by_tool, dict) else {}
    tool_counts = {}
    for tool in PUBLIC_TOOLS.values():
        counts = by_tool.get(tool, {})
        counts = counts if isinstance(counts, dict) else {}
        clean = {reason: number(counts.get(reason)) for reason in REASONS if number(counts.get(reason))}
        if clean:
            tool_counts[tool] = clean
    return {**{field: number(value.get(field)) for field in FIELDS},
            "denials_by_reason": {reason: number(reasons.get(reason)) for reason in REASONS
                                  if number(reasons.get(reason))},
            "denials_by_tool": tool_counts}


class BrokerTelemetry:
    def __init__(self):
        self.value = safe_broker({})
        self.last_success_ns = None

    def increment(self, field):
        self.value[field] = min(COUNTER_MAX, self.value[field] + 1)

    def request(self, name):
        self.increment("requests_total")
        tool = TOOLS.get(name) if isinstance(name, str) else None
        if tool:
            self.increment(tool + "_requests")

    def success(self, name):
        self.increment("success_total")
        tool = TOOLS.get(name) if isinstance(name, str) else None
        if tool:
            self.increment(tool + "_success")
            self.last_success_ns = time.monotonic_ns()

    def failure(self, reason, error=False, *, tool=None):
        reason = reason if reason in REASONS else "BROKER_INTERNAL"
        self.increment("error_total" if error else "denied_total")
        counts = self.value["denials_by_reason"]
        counts[reason] = min(COUNTER_MAX, counts.get(reason, 0) + 1)
        category = TOOLS.get(tool) if isinstance(tool, str) else None
        if category and not error:
            counts = self.value["denials_by_tool"].setdefault(PUBLIC_TOOLS[category], {})
            counts[reason] = min(COUNTER_MAX, counts.get(reason, 0) + 1)

    def snapshot(self):
        return safe_broker(self.value)
