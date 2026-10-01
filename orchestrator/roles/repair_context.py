"""Bounded repair evidence; diagnostic text never grants file permissions."""

import difflib
import json
import re

from roles.controller_git import ControllerGitError, run_git
from roles.inspector import OPAQUE, SECRET_NAME
from roles.integrity import changes, check_baseline, git
from roles.read_policy import context_read

MAX_FAILURE_IDENTIFIERS = 24
MAX_IDENTIFIER_CHARS = 180
MAX_FAILURE_EVIDENCE = 8192
MAX_SECONDARY_OUTPUT = 4096
MAX_DIFF_BYTES = 8192
MAX_SCAN_CHARS = 7000  # Secondary excerpts and stable count summaries only.
MAX_FAILURE_SCAN_BYTES = 64 * 1024  # Same ceiling as the isolated runner's capture.
MAX_FAILURE_SCAN_LINES = 4096
MAX_FAILURE_LINE_CHARS = 2048
SENSITIVE = re.compile(r"(?i)\bbearer\s+\S+|https?://[^\s/]*@|"
                       r"\b(?:authorization|cookie|api[_-]?key|token|password|secret)\b")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.:/-]*")
EXCEPTION = re.compile(r"(?m)^(AssertionError|ValueError|TypeError|KeyError|IndexError|"
                       r"AttributeError|ImportError|ModuleNotFoundError|RuntimeError|"
                       r"FileNotFoundError|ZeroDivisionError)(?::|$)")


def sanitized(text, limit):
    """Drop suspicious lines wholesale, rather than trying to retain payloads."""
    text = text if isinstance(text, str) else ""
    lines = []
    for line in text[:MAX_SCAN_CHARS].splitlines():
        if SECRET_NAME.search(line) or OPAQUE.search(line) or SENSITIVE.search(line):
            lines.append("[REDACTED]")
        else:
            lines.append("".join(ch for ch in line if ch == "\t" or ord(ch) >= 32 and not 127 <= ord(ch) <= 159))
    return "\n".join(lines).encode("utf-8", "replace")[:limit].decode("utf-8", "ignore")


def _count(value):
    return value if type(value) is int and 0 <= value <= 100000 else None


def failure_evidence(output, framework):
    """Parse bounded complete records before Tester trims human diagnostics."""
    # Lazy imports keep Tester able to share this pure parser without a cycle
    # through coding_units' filesystem context helper.
    from roles.coding_units import failure_count

    output = output if isinstance(output, str) else ""
    try:
        count = _count(failure_count(output[-MAX_SCAN_CHARS:], framework))
    except ValueError:
        count = None
    encoded = output[:MAX_FAILURE_SCAN_BYTES].encode("utf-8", "replace")
    truncated = len(output) > MAX_FAILURE_SCAN_BYTES or len(encoded) > MAX_FAILURE_SCAN_BYTES
    text = encoded[:MAX_FAILURE_SCAN_BYTES].decode("utf-8", "ignore")
    if truncated and not text.endswith("\n"):
        text = text.rsplit("\n", 1)[0] if "\n" in text else ""
    lines = text.split("\n", MAX_FAILURE_SCAN_LINES)
    scan_incomplete = truncated or len(lines) > MAX_FAILURE_SCAN_LINES
    identifiers, exceptions = [], set()
    for line in lines[:MAX_FAILURE_SCAN_LINES]:
        line = line.removesuffix("\r")  # Complete CRLF records are supported.
        if len(line) > MAX_FAILURE_LINE_CHARS or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in line):
            scan_incomplete = True
            continue
        match = None
        if framework == "unittest":
            match = re.fullmatch(r"(?:FAIL|ERROR): [^\n]* \(([^\n()]*)\)", line)
        elif framework == "pytest":
            match = re.fullmatch(r"(?:FAILED|ERROR) ([^\s]+)(?: .*|)", line)
        if match:
            name = match[1]
            if (len(name) <= MAX_IDENTIFIER_CHARS and IDENTIFIER.fullmatch(name)
                    and ".." not in name and not SECRET_NAME.search(name)
                    and not OPAQUE.search(name) and name not in identifiers
                    and len(identifiers) < MAX_FAILURE_IDENTIFIERS):
                identifiers.append(name)
        if framework in ("unittest", "pytest"):
            exception = EXCEPTION.match(line)
            if exception:
                exceptions.add(exception[1])
    result = {"format": framework if count is not None else "UNKNOWN",
              "failure_count": count, "failing_test_names": identifiers,
              "exception_types": sorted(exceptions)[:12],
              "identifiers_complete": not scan_incomplete and count is not None and count == len(identifiers),
              "scan_incomplete": scan_incomplete,
              "secondary_output": sanitized(output[-MAX_SCAN_CHARS:], MAX_SECONDARY_OUTPUT)}
    if len(json.dumps(result).encode()) > MAX_FAILURE_EVIDENCE:
        result["secondary_output"] = "[OMITTED: EVIDENCE LIMIT]"
    return result


def _validated_machine_evidence(value):
    if (not isinstance(value, dict) or set(value) != {"format", "failure_count", "failing_test_names",
            "exception_types", "identifiers_complete", "scan_incomplete", "secondary_output"}
            or value["format"] not in ("unittest", "pytest", "UNKNOWN")
            or not isinstance(value["failing_test_names"], list)
            or len(value["failing_test_names"]) > MAX_FAILURE_IDENTIFIERS
            or any(not isinstance(name, str) or len(name) > MAX_IDENTIFIER_CHARS
                   or not IDENTIFIER.fullmatch(name) or ".." in name
                   or SECRET_NAME.search(name) or OPAQUE.search(name) for name in value["failing_test_names"])
            or len(set(value["failing_test_names"])) != len(value["failing_test_names"])
            or not isinstance(value["exception_types"], list) or len(value["exception_types"]) > 12
            or any(not isinstance(name, str) or not EXCEPTION.fullmatch(name) for name in value["exception_types"])
            or type(value["identifiers_complete"]) is not bool or type(value["scan_incomplete"]) is not bool
            or value["failure_count"] is not None and _count(value["failure_count"]) is None
            or not isinstance(value["secondary_output"], str)
            or len(value["secondary_output"]) > MAX_SECONDARY_OUTPUT
            or len(json.dumps(value).encode()) > MAX_FAILURE_EVIDENCE):
        raise RuntimeError("FIXER_FAILURE_EVIDENCE_INVALID")
    return {**value, "secondary_output": sanitized(value["secondary_output"], MAX_SECONDARY_OUTPUT)}


def _diff(repo, names, new_files):
    """Compare bounded, safe current files to HEAD without copying secret blobs."""
    from roles.coding_units import GENERATED_MARKER
    chunks = []
    omitted = 0
    used = 0
    for index, name in enumerate(names):
        current = context_read({"repo_dir": str(repo)}, name, names)
        if current is None:
            omitted += 1
            continue
        result = None
        try:
            result = run_git(["show", "HEAD:" + name], cwd=repo, max_output=64 * 1024)
        except ControllerGitError as exc:
            if str(exc) != "CONTROLLER_GIT_OUTPUT_LIMIT":
                raise
            omitted += 1
            continue
        # New, controller-authorized implementation files have no HEAD contents.
        if result.returncode and name not in new_files:
            raise RuntimeError("FIXER_DIFF_UNAVAILABLE")
        old = result.stdout if result.returncode == 0 else b""
        try:
            before, after = old.decode("utf-8"), current.decode("utf-8")
        except UnicodeDecodeError:
            omitted += 1
            continue
        if any(SECRET_NAME.search(value) or OPAQUE.search(value)
               or SENSITIVE.search(value) or GENERATED_MARKER.search(value[:1024])
               for value in (before, after)):
            omitted += 1
            continue
        delta = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                           fromfile="a/" + name, tofile="b/" + name, n=2))
        encoded = delta.encode("utf-8")
        remaining = MAX_DIFF_BYTES - used
        chunks.append(encoded[:remaining].decode("utf-8", "ignore"))
        used += min(len(encoded), remaining)
        if len(encoded) > remaining:
            omitted += 1
        if used == MAX_DIFF_BYTES:
            omitted += len(names) - index - 1
            break
    return {"text": "".join(chunks), "omitted_or_truncated_files": omitted}


def repair_packet(state, *, policy=None):
    from roles.coding_units import (_target_path, local_context_packet, MAX_CONTEXT_FILES, MAX_TARGET_FILES)
    from roles.tester import _is_test_file

    repo, _ = check_baseline(state)
    tracked = set(filter(None, git(repo, "ls-files", "-z").split("\0")))
    current = changes(repo, state.get("integrity_baseline"))
    if current["deleted"] and state.get("allow_deletes") is not True:
        raise RuntimeError("FIXER_CONTEXT_POLICY_DENIED")
    history = [item for item in (state.get("unit_history") or [])
               if isinstance(item, dict) and item.get("phase") != "repair"][:3]
    repair_state = state.get("intermediate_repair")
    intermediate = isinstance(repair_state, dict) and repair_state.get("status") == "PENDING"
    active_targets = None
    if intermediate:
        from roles.intermediate_repair import repair_targets
        active_targets = repair_targets(state)
    completed = min(3, max(0, state.get("unit_index", 0)) + int(intermediate))
    units = (state.get("coding_units") or [])[:completed]
    candidates = []
    # Failure text is intentionally never used as a path source. All candidates
    # come from controller Git evidence, validated unit hints, or Inspector facts.
    hints = [name for unit in units for name in unit.get("target_files", [])]
    related = (state.get("repo_facts") or {}).get("relevant_files", [])[:24]
    for name in [*current["changed"], *hints, *related]:
        if not isinstance(name, str) or not _target_path(name) or _is_test_file(name):
            continue
        if active_targets is not None and name not in active_targets:
            continue
        if name in current["deleted"] or name in candidates:
            continue
        if policy is not None and name not in policy["files"]:
            continue
        if name in current["new"] and state.get("allow_new_files") is not True:
            raise RuntimeError("FIXER_CONTEXT_POLICY_DENIED")
        if name not in tracked and name not in current["new"]:
            # An authorized unit may still need to create its intended file.
            # No current contents exist to inject; hints never grant permission.
            continue
        # Enforce regular, single-link, no-symlink reads before inclusion.
        # Model hints never weaken this boundary.
        if context_read(state, name, [name]) is None:
            continue
        candidates.append(name)
        if len(candidates) == MAX_CONTEXT_FILES:
            break
    # Authorized new current files are controller-observed changes, not invented
    # paths. Supply that provenance to the unchanged shared context reader.
    context_state = {**state, "unit_history": [*history, {"changed_files": current["new"]}],
                     "repo_facts": {**(state.get("repo_facts") or {}), "relevant_files": []}}
    context = local_context_packet(context_state, {"target_files": candidates[:MAX_TARGET_FILES],
                                                  "files": candidates[MAX_TARGET_FILES:]},
                                   include_readme="README.md" not in current["deleted"], policy=policy)
    machine = state.get("machine_failure_evidence")
    # Only Tester sets this field in production. Revalidate its bounded shape
    # for direct/legacy fixture callers; never accept path authority from it.
    evidence = _validated_machine_evidence(machine) if machine is not None else failure_evidence(
        state.get("test_output", ""), (state.get("workspace_test_attestation") or {}).get("framework"))
    progress = [{"goal": sanitized(item.get("goal", ""), 300),
                 "before": _count(item.get("test_failures_before")),
                 "after": _count(item.get("test_failures_after"))}
                for item in history]
    repair_progress = [{"before": _count(item.get("test_failures_before")),
                        "after": _count(item.get("test_failures_after")),
                        "fix_attempt": _count(item.get("fix_attempt"))}
                       for item in (state.get("unit_history") or [])[-5:]
                       if isinstance(item, dict) and item.get("phase") == "repair"][-2:]
    previous = progress[-1]["before"] if progress else None
    prior_repairs = [item for item in (state.get("worker_history") or [])
                     if isinstance(item, dict) and item.get("role") == "fixer"][-2:]
    if prior_repairs:
        previous = _count((prior_repairs[-1].get("context") or {}).get("fixer_current_failure_count"))

    def visible(name):
        return policy is None or name in policy["files"]

    packet = {"test_result": state.get("test_result") if state.get("test_result") in ("PASS", "FAIL") else "UNKNOWN",
              "test_exit": _count(state.get("test_exit")),
              "failure_evidence": evidence, "unit_progress": progress, "repair_progress": repair_progress,
              "baseline_failures": _count((state.get("workspace_test_attestation") or {}).get("baseline_failures")),
              "changed_files": [name for name in current["changed"]
                                if _target_path(name) and not _is_test_file(name) and visible(name)][:24],
              "changed_files_truncated": len([name for name in current["changed"]
                                               if _target_path(name) and not _is_test_file(name) and visible(name)]) > 24,
              "authorized_deleted_files": [name for name in current["deleted"]
                                           if (_target_path(name) or name == "README.md") and visible(name)][:24],
              "deleted_files_truncated": len(current["deleted"]) > 24,
              "repair_candidates": candidates, "diff_check_exit": _count(state.get("diff_check_exit")),
              "integrity_clean": not any((state.get("integrity_violations") or {}).values()),
              "rollback_completed": bool(state.get("rollback_evidence")),
              "last_unit_goal": progress[-1]["goal"] if progress else "",
              "intermediate_repair": (state.get("intermediate_repair") if intermediate else None)}
    # A structured packet is never cut into invalid JSON; drop secondary output
    # first if unusual history consumes its independent diagnostic budget.
    text = json.dumps(packet, sort_keys=True)
    if len(text.encode("utf-8")) > MAX_FAILURE_EVIDENCE:
        evidence["secondary_output"] = "[OMITTED: PACKET LIMIT]"
        text = json.dumps(packet, sort_keys=True)
    if len(text.encode("utf-8")) > MAX_FAILURE_EVIDENCE:
        raise RuntimeError("FIXER_EVIDENCE_LIMIT")
    delta = _diff(repo, candidates, current["new"])
    metrics = {"fixer_failure_identifiers_count": len(evidence["failing_test_names"]),
               "fixer_failure_evidence_chars": len(text),
               "fixer_context_files_count": context["local_context_files_count"],
               "fixer_context_chars": context["local_context_chars"],
               "fixer_target_files_count": context["target_files_count"],
               "fixer_target_context_chars": context["target_context_chars"],
               "fixer_diff_chars": len(delta["text"]),
               "fixer_diff_omitted_files_count": delta["omitted_or_truncated_files"],
               "fixer_previous_failure_count": previous,
               "fixer_current_failure_count": evidence["failure_count"]}
    return {"evidence": text, "context": context["text"], "diff": delta, "metrics": metrics,
            "read_candidates": candidates}
