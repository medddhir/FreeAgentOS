"""The sole trusted user-facing task entrypoint for FreeAgentOS."""

import argparse
import hashlib
import json
import re
import signal
import sys
from pathlib import Path

import graph
from roles.controller_git import ControllerGitError, run_git
from roles.workspace import cleanup_active_workspace, recover_stale_workspaces
from roles.inspector import OPAQUE, SECRET_NAME


MAX_TASK_CHARS = 12000
MAX_JSON_BYTES = 32768
EXIT_CODES = {"VERIFIED": 0, "UNVERIFIED": 1, "BLOCKED": 2}
SAFE_CODE = re.compile(r"[A-Z][A-Z0-9_:/.-]{0,119}\Z")


class UsageError(ValueError):
    pass


class _Stopped(BaseException):
    def __init__(self, signum):
        self.signum = signum


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def _parser():
    parser = _Parser(prog="freeagent-run", description="Run a task through the complete FreeAgentOS production graph. "
                     "The source repository is not changed; VERIFIED runs return a promotion-ready patch.")
    parser.add_argument("--repo", required=True, help="Clean Git repository root to snapshot.")
    parser.add_argument("--task", required=True, help="Task text (treated only as data; maximum 12000 characters).")
    parser.add_argument("--allow-new-files", action="store_true", help="Trusted permission for new files.")
    parser.add_argument("--allow-deletes", action="store_true", help="Trusted permission for deletions.")
    parser.add_argument("--allow-test-changes", action="store_true",
                        help="Trusted permission for test edits; other protections still apply.")
    parser.add_argument("--json", action="store_true", help="Emit bounded machine-readable final status.")
    parser.epilog = ("Exit codes: 0 VERIFIED, 1 UNVERIFIED, 2 BLOCKED, 3 invalid input, "
                     "4 controller failure, 130/143 interrupted. freeagent-test alone is not full verification.")
    return parser


def _repo(value):
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise UsageError("INVALID_REPOSITORY_PATH")
    candidate = Path(value).expanduser()
    if candidate.is_symlink():
        raise UsageError("SYMLINK_REPOSITORY_PATH")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        raise UsageError("REPOSITORY_NOT_FOUND") from None
    if not resolved.is_dir():
        raise UsageError("REPOSITORY_NOT_DIRECTORY")
    try:
        result = run_git(["rev-parse", "--show-toplevel"], cwd=resolved, timeout=10,
                         max_output=8192)
    except ControllerGitError:
        raise
    if result.returncode != 0:
        raise UsageError("NOT_A_GIT_REPOSITORY")
    top = Path(result.stdout.decode("utf-8", "replace").strip()).resolve()
    if top != resolved:
        raise UsageError("REPOSITORY_PATH_NOT_ROOT")
    return resolved


def _task(value):
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TASK_CHARS or "\0" in value:
        raise UsageError("TASK_INVALID_OR_TOO_LONG")
    return value.strip()


def _reason(state):
    for field in ("preflight_error", "workspace_error", "inspector_error", "planner_error", "unit_error",
                  "research_validation_error", "research_error", "coder_error", "tester_error",
                  "rollback_error", "reviewer_error", "fixer_error", "promotion_error"):
        value = state.get(field)
        if value:
            return value if isinstance(value, str) and SAFE_CODE.fullmatch(value) else field.upper()
    return "VERIFICATION_INCOMPLETE"


def _evidence(value):
    if not isinstance(value, dict):
        return {}
    keys = ("cleanup_status", "remaining_processes", "timeout_triggered", "forced_kill_used",
            "output_truncated", "cgroup_status", "resource_hits", "controls")
    result = {key: value[key] for key in keys if key in value}
    for key in ("worker_scope_setup_ms", "worker_process_spawn_ms", "worker_process_runtime_ms",
                "worker_cleanup_ms", "worker_total_ms", "worker_first_stdout_byte_ms",
                "worker_first_stderr_byte_ms", "worker_stdout_bytes_seen", "worker_stderr_bytes_seen",
                "worker_exit_code", "gateway_health_latency_ms"):
        if type(value.get(key)) is int and -255 <= value[key] <= 10_000_000:
            result[key] = value[key]
    for key in ("worker_executable_resolved", "claude_free_resolved", "claude_executable_available"):
        if type(value.get(key)) is bool:
            result[key] = value[key]
    if value.get("worker_phase") in ("PROCESS_NEVER_STARTED", "PROCESS_STARTED_NO_OUTPUT",
                                      "STDERR_BEFORE_STDOUT", "FIRST_OUTPUT_BEFORE_TIMEOUT", "NORMAL_COMPLETE"):
        result["worker_phase"] = value["worker_phase"]
    if value.get("gateway_health_status") in ("HEALTHY", "UNHEALTHY", "UNAVAILABLE", "NOT_CHECKED"):
        result["gateway_health_status"] = value["gateway_health_status"]
    if value.get("gateway_request_observed") == "UNAVAILABLE":
        result["gateway_request_observed"] = "UNAVAILABLE"
    from roles.broker_telemetry import safe_broker
    if "broker" in value:
        result["broker"] = safe_broker(value["broker"])
    from roles.activity import safe_activity
    if "activity" in value:
        result["activity"] = safe_activity(value["activity"])
    from roles.lease import safe_lease
    if "lease" in value:
        result["lease"] = safe_lease(value["lease"])
    return result


def _planner_diagnostic(value):
    if not isinstance(value, dict):
        return {}
    result = {}
    for key in ("response_bytes", "worker_exit", "worker_total_ms", "first_stdout_byte_ms",
                "first_stderr_byte_ms", "gateway_health_latency_ms", "response_parse_ms",
                "json_error_position", "stderr_bytes"):
        item = value.get(key)
        if type(item) is int and -255 <= item <= 1024 * 1024:
            result[key] = item
    for key in ("outer_json_valid", "explicit_error", "timeout", "output_truncated",
                "cleanup_confirmed", "trailing_non_whitespace", "direct_schema_candidate"):
        if type(value.get(key)) is bool:
            result[key] = value[key]
    for key in ("top_level_type", "structured_output_type", "result_type"):
        if value.get(key) in ("dict", "list", "str", "int", "bool", "NoneType", "unknown"):
            result[key] = value[key]
    if value.get("worker_phase") in ("PROCESS_NEVER_STARTED", "PROCESS_STARTED_NO_OUTPUT",
                                      "STDERR_BEFORE_STDOUT", "FIRST_OUTPUT_BEFORE_TIMEOUT", "NORMAL_COMPLETE"):
        result["worker_phase"] = value["worker_phase"]
    if value.get("gateway_health_status") in ("HEALTHY", "UNHEALTHY", "UNAVAILABLE", "NOT_CHECKED"):
        result["gateway_health_status"] = value["gateway_health_status"]
    if value.get("supported_envelope_detected") in ("STRUCTURED_OUTPUT", "DIRECT_STRUCTURED_OBJECT", "RESULT_JSON"):
        result["supported_envelope_detected"] = value["supported_envelope_detected"]
    if value.get("unit_validation_code") in ("UNIT_PLAN_INVALID", "UNIT_COUNT_INVALID",
                                                   "UNIT_SCHEMA_INVALID", "UNIT_GOAL_INVALID",
                                                   "UNIT_TARGET_FILE_INVALID"):
        result["unit_validation_code"] = value["unit_validation_code"]
    from roles.coding_units import GOAL_VALIDATION_REASONS
    if value.get("unit_goal_validation_reason") in GOAL_VALIDATION_REASONS:
        result["unit_goal_validation_reason"] = value["unit_goal_validation_reason"]
    present = value.get("known_keys_present")
    if isinstance(present, list):
        result["known_keys_present"] = [key for key in
                                        ("structured_output", "result", "error", "is_error", "type")
                                        if key in present]
    return result


def _projection(state, repo, task, recovery):
    status = state.get("status")
    if status not in EXIT_CODES:
        raise RuntimeError("INVALID_GRAPH_FINAL_STATUS")
    changed = state.get("changed_files") or []
    trace = state.get("trace") or []
    if not isinstance(changed, list) or not isinstance(trace, list):
        raise RuntimeError("INVALID_GRAPH_EVIDENCE")
    violations = state.get("integrity_violations") or {}
    integrity = ("FAIL" if isinstance(violations, dict) and violations.get("all") else
                 "PASS" if state.get("test_result") == "PASS" and state.get("diff_check_exit") == 0 else "UNKNOWN")
    research = ("BLOCKED" if state.get("research_error") else
                "PASS" if state.get("needs_research") and state.get("research_results", 0) > 0 else "SKIPPED")
    from roles.intermediate_repair import safe_intermediate
    workers = state.get("worker_history") or []
    research_workers = state.get("research_execution_history") or []
    role_timings = state.get("role_timing_history") or []
    unit_history = state.get("unit_history") or []

    def safe_goal(value):
        value = str(value or "")[:180]
        return "[REDACTED]" if SECRET_NAME.search(value) or OPAQUE.search(value) else value

    units = []
    for item in unit_history[-8:]:
        if not isinstance(item, dict):
            continue
        unit = {"id": str(item.get("unit_id", ""))[:16], "goal": safe_goal(item.get("goal")),
                "index": item.get("unit_index") if type(item.get("unit_index")) is int else None,
                "changed_files": [str(p)[:180] for p in (item.get("changed_files") or [])[:30]],
                "test_failures_before": item.get("test_failures_before"),
                "test_failures_after": item.get("test_failures_after"),
                "test_result_after": item.get("test_result_after")}
        if item.get("phase") == "repair":
            unit["phase"] = "repair"
            if type(item.get("fix_attempt")) is int and 1 <= item["fix_attempt"] <= 2:
                unit["fix_attempt"] = item["fix_attempt"]
        for key in ("worker_total_ms", "first_stdout_byte_ms", "first_stderr_byte_ms", "worker_exit"):
            value = item.get(key)
            if type(value) is int and 0 <= value <= 10_000_000:
                unit[key] = value
        for key in ("coder_prompt_chars", "repo_facts_chars", "local_context_chars",
                    "local_context_files_count", "target_files_count", "target_files_existing_count",
                    "target_files_new_count", "target_context_chars", "target_context_truncated_count",
                    "planner_steps_context_count"):
            value = item.get(key)
            if type(value) is int and 0 <= value <= 1_000_000:
                unit[key] = value
        for key in ("timeout", "output_truncated"):
            if type(item.get(key)) is bool:
                unit[key] = item[key]
        hits = item.get("resource_hits") or {}
        unit["resource_hits"] = {key: hits[key] for key in ("memory", "process_count")
                                 if type(hits.get(key)) is bool}
        units.append(unit)
    result = {
        "status": status, "trace": [str(item)[:80] for item in trace[:64]],
        "task": {"sha256": hashlib.sha256(task.encode()).hexdigest(), "characters": len(task)},
        "repo": str(repo), "source_repo": str(state.get("source_repo") or repo),
        "workspace_id": str(state.get("workspace_id") or ""),
        "workspace": str(state.get("run_workspace") or ""),
        "research": {"status": research, "source": str(state.get("research_source") or ""),
                     "failure_kind": str(state.get("research_failure_kind") or "")},
        "changed_files": [str(item)[:200] for item in changed[:100]],
        "changed_files_total": len(changed), "test_result": str(state.get("test_result") or ""),
        "review_verdict": str(state.get("review_verdict") or ""),
        "fix_attempts": int(state.get("fix_attempts") or 0), "integrity": integrity,
        "preflight": str(state.get("preflight_status") or ""),
        "promotion_patch": str(state.get("verified_patch_path") or "") if status == "VERIFIED" else "",
        "block_reason": _reason(state) if status != "VERIFIED" else "",
        "block_stage": "planner" if state.get("planner_error_code") else "",
        "planner_error_code": (state.get("planner_error_code")
                               if isinstance(state.get("planner_error_code"), str)
                               and SAFE_CODE.fullmatch(state["planner_error_code"]) else ""),
        "planner_error_stage": (state.get("planner_error_stage")
                                if state.get("planner_error_stage") in
                                ("input", "worker", "model", "response", "parse", "schema", "controller") else ""),
        "planner_diagnostic": _planner_diagnostic(state.get("planner_diagnostic")),
        "planner_steps_count": min(5, len(state.get("plan_steps") or [])),
        "planner_coding_units_count": min(3, len(state.get("planner_coding_units") or [])),
        "unit_derivation_source": (state.get("unit_derivation_source")
                                   if state.get("unit_derivation_source") in
                                   ("PLANNER_EXPLICIT", "LEGACY_COMPACTION") else ""),
        "role_timings_ms": [{"role": str(item.get("role", ""))[:40],
                             "elapsed_ms": item["elapsed_ms"]}
                            for item in role_timings[-32:] if isinstance(item, dict)
                            and type(item.get("elapsed_ms")) is int
                            and 0 <= item["elapsed_ms"] <= 10_000_000],
        "coding_units_planned": min(3, len(state.get("coding_units") or [])),
        "coding_units_completed": min(3, int(state.get("unit_index") or 0)),
        "unit_error": (state.get("unit_error") if isinstance(state.get("unit_error"), str)
                       and SAFE_CODE.fullmatch(state["unit_error"]) else ""),
        "unit_history": units,
        "intermediate_repair": safe_intermediate(state.get("intermediate_repair"), state.get("fix_attempts", 0), status == "BLOCKED"),
        "resource_evidence": {
            "workers": [{"role": str(item.get("role", ""))[:40],
                         "unit_id": item.get("unit_id") if item.get("unit_id") in
                         ("unit-1", "unit-2", "unit-3") else "",
                         "attempt": item.get("attempt") if item.get("attempt") in (1, 2) else None,
                         "context": {key: value for key, value in (item.get("context") or {}).items()
                                     if key in ("fixer_prompt_chars", "fixer_failure_identifiers_count",
                                                "fixer_failure_evidence_chars", "fixer_context_files_count",
                                                "fixer_context_chars", "fixer_target_files_count",
                                                "fixer_target_context_chars", "fixer_diff_chars",
                                                "fixer_diff_omitted_files_count", "fixer_previous_failure_count",
                                                "fixer_current_failure_count")
                                     and (value is None or type(value) is int and 0 <= value <= 100000)},
                         "evidence": _evidence(item.get("evidence"))}
                        for item in workers[-8:] if isinstance(item, dict)],
            "research": [{"action": str(item.get("action", ""))[:40],
                          "status": str(item.get("status", ""))[:40],
                          "evidence": _evidence(item.get("evidence"))}
                         for item in research_workers[-8:] if isinstance(item, dict)],
            "target": _evidence(state.get("sandbox_evidence")),
        },
        "stale_recovery": recovery,
    }
    raw = json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode()
    if len(raw) > MAX_JSON_BYTES:
        raise RuntimeError("CLI_OUTPUT_BUDGET_EXCEEDED")
    return result


def _emit(result, json_mode):
    if json_mode:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return
    for label, key in (("STATUS", "status"), ("TRACE", "trace"), ("TASK", "task"),
                       ("SOURCE_REPO", "source_repo"), ("WORKSPACE", "workspace"),
                       ("WORKSPACE_ID", "workspace_id"), ("RESEARCH_STATUS", "research"),
                       ("FILES_CHANGED", "changed_files"), ("TEST_RESULT", "test_result"),
                       ("REVIEW_RESULT", "review_verdict"), ("FIX_ATTEMPTS", "fix_attempts"),
                       ("INTEGRITY_STATUS", "integrity"), ("PREFLIGHT", "preflight"),
                       ("PROMOTION_PATCH", "promotion_patch"), ("BLOCK_REASON", "block_reason")):
        value = result.get(key, "")
        if isinstance(value, (dict, list)):
            value = json.dumps(value, separators=(",", ":"))
        print(f"{label}={value}")
    for label, key in (("BLOCK_STAGE", "block_stage"), ("PLANNER_ERROR_CODE", "planner_error_code"),
                       ("PLANNER_ERROR_STAGE", "planner_error_stage"),
                       ("PLANNER_DIAGNOSTIC", "planner_diagnostic")):
        value = result.get(key, "")
        print(f"{label}={json.dumps(value, separators=(',', ':')) if isinstance(value, dict) else value}")
    print("ROLE_TIMINGS_MS=" + json.dumps(result.get("role_timings_ms", []), separators=(",", ":")))
    for label, key in (("PLANNER_STEPS_COUNT", "planner_steps_count"),
                       ("PLANNER_CODING_UNITS_COUNT", "planner_coding_units_count"),
                       ("UNIT_DERIVATION_SOURCE", "unit_derivation_source")):
        print(f"{label}={result.get(key, '')}")
    print("CODING_UNITS=" + json.dumps(result.get("unit_history", []), separators=(",", ":")))
    workers = result.get("resource_evidence", {}).get("workers", [])
    if workers:
        last = workers[-1]["evidence"]
        for label, key in (("WORKER_PHASE", "worker_phase"), ("WORKER_TOTAL_MS", "worker_total_ms"),
                           ("FIRST_STDOUT_BYTE_MS", "worker_first_stdout_byte_ms"),
                           ("FIRST_STDERR_BYTE_MS", "worker_first_stderr_byte_ms"),
                           ("GATEWAY_HEALTH", "gateway_health_status"),
                           ("GATEWAY_HEALTH_MS", "gateway_health_latency_ms"),
                           ("WORKER_EXIT", "worker_exit_code"), ("CLEANUP", "cleanup_status")):
            print(f"{label}={last.get(key, 'NONE')}")


def _problem(status, code, json_mode, cleanup="NONE"):
    result = {"status": status, "block_reason": code, "workspace_cleanup": cleanup}
    _emit(result, json_mode)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    json_mode = "--json" in argv
    try:
        args = _parser().parse_args(argv)
        repo = _repo(args.repo)
        task = _task(args.task)
    except UsageError as exc:
        _problem("INVALID_INPUT", str(exc) if SAFE_CODE.fullmatch(str(exc)) else "CLI_USAGE_ERROR", json_mode)
        return 3
    except ControllerGitError:
        _problem("CONTROLLER_ERROR", "REPOSITORY_VALIDATION_FAILED", json_mode)
        return 4
    old_int = signal.getsignal(signal.SIGINT)
    old_term = signal.getsignal(signal.SIGTERM)

    def stop(signum, _frame):
        raise _Stopped(signum)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        recovery = recover_stale_workspaces()
        state = {"repo_dir": str(repo), "task": task, "trace": [],
                 "allow_new_files": args.allow_new_files, "allow_deletes": args.allow_deletes,
                 "allow_test_changes": args.allow_test_changes}
        final = graph.build_graph().invoke(state)
        result = _projection(final, repo, task, recovery)
        return_code = EXIT_CODES[result["status"]]
        _emit(result, args.json)
        return return_code
    except _Stopped as exc:
        cleanup = cleanup_active_workspace()
        _problem("INTERRUPTED", "SIGNAL_" + str(exc.signum), args.json, cleanup)
        return 128 + exc.signum if cleanup != "UNPROVEN" else 4
    except Exception:
        cleanup = cleanup_active_workspace()
        _problem("CONTROLLER_ERROR", "CONTROLLER_FAILURE", args.json, cleanup)
        return 4
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)


if __name__ == "__main__":
    sys.exit(main())
