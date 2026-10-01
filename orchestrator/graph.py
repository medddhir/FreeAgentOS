import time
from pathlib import Path

from langgraph.graph import StateGraph, START, END

from state import AgentState
from roles.planner import planner_node
from roles.researcher import researcher_node
from roles.coder import coder_node
from roles.tester import tester_node
from roles.reviewer import reviewer_node, machine_verification_error
from roles.fixer import fixer_node
from roles.integrity import baseline_node, rollback_node
from roles.inspector import inspector_node
from roles.research_validator import research_validation_node
from roles.workspace import prepare_workspace_node, discovery_baseline_node, finish_workspace
from roles.preflight import preflight_node
from roles.coding_units import MAX_UNITS, derive_units_node, failure_count
from roles.integrity import ERRORS, fingerprint
from roles.intermediate_repair import repair_checkpoint, repair_targets


MAX_FIX_ATTEMPTS = 2


def route_after_planner(state: AgentState):
    if (
        state.get("planner_error")
        or state.get("status") == "BLOCKED"
    ):
        return "finalizer"

    return "unit_derivation"


def route_after_unit_derivation(state: AgentState):
    return "finalizer" if state.get("status") == "BLOCKED" or state.get("unit_error") else "research_validation"


def route_after_inspector(state: AgentState):
    return "finalizer" if state.get("inspector_error") or state.get("status") == "BLOCKED" else "planner"


def route_after_research_validation(state: AgentState):
    if not state.get("research_validation_passed") or state.get("status") == "BLOCKED":
        return "finalizer"
    return "researcher" if state.get("needs_research") else "coder"


def route_after_researcher(state: AgentState):
    if (
        state.get("research_error")
        or state.get("status") == "BLOCKED"
    ):
        return "finalizer"

    return "coder"


def route_after_tester(state: AgentState):
    if state.get("status") == "BLOCKED":
        return "finalizer"

    violations = state.get("integrity_violations")
    if isinstance(violations, dict) and any(violations.get(key) for key in
                                            ("protected", "verification", "untracked", "new", "deleted", "all")):
        return "rollback"
    if machine_verification_error(state, final=False):
        return "finalizer"

    if state.get("unit_gate_status") == "REPAIR_REQUIRED":
        try:
            repair_checkpoint(state)
        except ValueError:
            return "finalizer"
        return "fixer"

    if state.get("unit_gate_status") == "CONTINUE":
        return "coder"

    if state.get("test_result") == "PASS":
        return "reviewer" if state.get("unit_gate_status") == "FINAL" else "finalizer"

    if state.get("fix_attempts", 0) < MAX_FIX_ATTEMPTS:
        return "fixer"

    return "finalizer"


def tested_unit_node(state: AgentState, tester_runner=tester_node):
    """Use the unchanged Tester, then allow only non-regressing intermediate units."""
    try:
        result = tester_runner(state)
        if not isinstance(result, dict):
            raise TypeError("TESTER_RESULT_INVALID")
    except Exception as exc:
        return {"tester_error": "TESTER_EXCEPTION:" + type(exc).__name__,
                "test_result": "FAIL", "test_exit": 125, "status": "BLOCKED",
                "unit_gate_status": "BLOCKED", "trace": ["tester:error"]}
    units = state.get("coding_units") or []
    index = state.get("unit_index", 0)
    attempts = state.get("fix_attempts", 0)
    repair_state = state.get("intermediate_repair")
    intermediate = isinstance(repair_state, dict) and repair_state.get("status") == "PENDING"
    checkpoint = None
    if intermediate:
        try:
            checkpoint = repair_checkpoint(state, tested=True)
        except ValueError:
            return {**result, "status": "BLOCKED", "unit_error": "INTERMEDIATE_REPAIR_STATE_INVALID",
                    "unit_gate_status": "BLOCKED"}
    # Final Coders advance past the last unit even when tests still fail.
    # Repaired integration must revisit that checkpoint, including its gates.
    repairing_final = (bool(units) and type(index) is int and index == len(units)
                       and state.get("unit_gate_status") in ("FINAL", "INTEGRITY_OR_SANDBOX_FAILURE")
                       and type(attempts) is int and 1 <= attempts <= MAX_FIX_ATTEMPTS)
    if repairing_final:
        index -= 1
    repairing = intermediate or repairing_final or ((len(units) == 1 or state.get("unit_gate_status") == "INTEGRITY_OR_SANDBOX_FAILURE")
                                    and type(index) is int and 0 <= index < len(units)
                                    and type(attempts) is int and 1 <= attempts <= MAX_FIX_ATTEMPTS)
    if not units or type(index) is not int or index >= len(units):
        return result
    unit = units[index]
    before = state.get("unit_failure_before")
    framework = (result.get("workspace_test_attestation") or {}).get("framework")
    if repairing:
        prior_evidence = state.get("machine_failure_evidence") or {}
        before = (prior_evidence.get("failure_count") if isinstance(prior_evidence, dict)
                  and type(prior_evidence.get("failure_count")) is int else
                  failure_count(state.get("test_output"), framework))
    count = (result.get("machine_failure_evidence") or {}).get("failure_count")
    after = (0 if result.get("test_result") == "PASS" else count if type(count) is int and count >= 0 else
             failure_count(result.get("test_output"), framework))
    workers = state.get("worker_history") or []
    worker_record = next((item for item in reversed(workers)
                   if isinstance(item, dict) and
                   ((repairing and item.get("role") == "fixer") or
                    (not repairing and item.get("role") == "coder" and item.get("unit_id") == unit["id"]))), {})
    worker = worker_record.get("evidence") or {}
    context_metrics = worker_record.get("context") or {}
    if len(units) == 1 and not repairing:
        # Preserve the proven one-unit Tester/rollback/Fixer route exactly.
        # Per-unit fingerprints are useful only for distinguishing later units.
        record = {"unit_id": unit["id"], "unit_index": 1, "goal": unit["goal"],
                  "files": unit["files"], "changed_files": (result.get("changed_files") or [])[:100],
                  **context_metrics,
                  "test_failures_before": before, "test_failures_after": after,
                  "test_result_after": result.get("test_result"),
                  "worker_total_ms": worker.get("worker_total_ms"),
                  "first_stdout_byte_ms": worker.get("worker_first_stdout_byte_ms"),
                  "first_stderr_byte_ms": worker.get("worker_first_stderr_byte_ms"),
                  "worker_exit": worker.get("worker_exit_code"),
                  "timeout": worker.get("timeout_triggered"),
                  "output_truncated": worker.get("output_truncated"),
                  "resource_hits": worker.get("resource_hits", {})}
        completed = (result.get("test_result") == "PASS" and result.get("status") != "BLOCKED"
                     and not (result.get("integrity_violations") or {}).get("all"))
        return {**result, "unit_history": [record],
                **({"unit_index": 1, "unit_gate_status": "FINAL"} if completed else {})}
    changed = result.get("changed_files") or []
    if len(changed) > 100:
        return {**result, "status": "BLOCKED", "unit_error": "UNIT_CHANGE_PATH_BUDGET_EXCEEDED",
                "unit_gate_status": "BLOCKED"}
    try:
        repo = Path(state["repo_dir"])
        current_fingerprints = {path: fingerprint(repo, path)
                                for path in changed}
    except ERRORS:
        return {**result, "status": "BLOCKED", "unit_error": "UNIT_CHANGE_EVIDENCE_UNAVAILABLE",
                "unit_gate_status": "BLOCKED"}
    prior_fingerprints = state.get("unit_file_fingerprints") or {}
    unit_changed = sorted(path for path in set(prior_fingerprints) | set(current_fingerprints)
                          if prior_fingerprints.get(path) != current_fingerprints.get(path))
    record = {"unit_id": unit["id"], "unit_index": index + 1, "goal": unit["goal"],
              "files": unit["files"], "changed_files": unit_changed[:100],
              **context_metrics,
              "test_failures_before": before, "test_failures_after": after,
              "test_result_after": result.get("test_result"),
              "worker_total_ms": worker.get("worker_total_ms"),
              "first_stdout_byte_ms": worker.get("worker_first_stdout_byte_ms"),
              "first_stderr_byte_ms": worker.get("worker_first_stderr_byte_ms"),
              "worker_exit": worker.get("worker_exit_code"),
              "timeout": worker.get("timeout_triggered"),
              "output_truncated": worker.get("output_truncated"),
              "resource_hits": worker.get("resource_hits", {})}
    if repairing:
        record.update({"phase": "repair", "fix_attempt": attempts})
    result = {**result, "unit_history": [record], "unit_file_fingerprints": current_fingerprints}
    if result.get("status") == "BLOCKED" or (result.get("integrity_violations") or {}).get("all"):
        if intermediate:
            return {**result, "status": "BLOCKED", "unit_error": "INTERMEDIATE_REPAIR_INTEGRITY_FAILED",
                    "unit_file_fingerprints": prior_fingerprints, "unit_gate_status": "BLOCKED"}
        return {**result, "unit_file_fingerprints": prior_fingerprints,
                "unit_gate_status": "INTEGRITY_OR_SANDBOX_FAILURE"}
    if unit.get("enforced_files"):
        allowed = {path for prior in units[:index + 1] for path in prior.get("enforced_files", [])}
        existing = set((state.get("integrity_baseline") or {}).get("existing", []))
        unauthorized = sorted(set(unit_changed) & existing - allowed)
        if unauthorized:
            return {**result, "status": "BLOCKED", "unit_error": "UNIT_PATH_VIOLATION",
                    "unit_gate_status": "BLOCKED"}
    if intermediate:
        allowed = set(repair_targets({**state, "fix_attempts": checkpoint["fix_attempts_before"]}))
        if set(unit_changed) - allowed:
            return {**result, "status": "BLOCKED", "unit_error": "UNIT_PATH_VIOLATION",
                    "unit_gate_status": "BLOCKED"}
    if index == len(units) - 1:
        return {**result, "unit_index": index + 1, "unit_gate_status": "FINAL"}
    if (result.get("tester_error") or result.get("workspace_integrity_error")
            or result.get("diff_check_exit") != 0 or result.get("test_exit") == 125
            or type(before) is not int or type(after) is not int):
        return {**result, "status": "BLOCKED", "unit_error": "UNIT_TEST_EVIDENCE_UNAVAILABLE",
                "unit_gate_status": "BLOCKED"}
    threshold = checkpoint["failures_before_unit"] if intermediate else before
    if intermediate:
        recovered = after <= threshold
        repair = {**checkpoint, "status": "RECOVERED" if recovered else "FAILED",
                  "failures_after_intermediate_fix": after}
        if machine_verification_error({**state, **result}, final=False) or not recovered:
            return {**result, "status": "BLOCKED", "unit_error": "UNIT_TEST_FAILURES_INCREASED",
                    "unit_gate_status": "BLOCKED", "intermediate_repair": repair}
        return {**result, "unit_index": index + 1, "unit_failure_before": after,
                "unit_gate_status": "CONTINUE", "unit_error": "", "intermediate_repair": repair}
    if after > before:
        clean = not machine_verification_error({**state, **result}, final=False)
        if clean and type(attempts) is int and 0 <= attempts < MAX_FIX_ATTEMPTS:
            return {**result, "unit_error": "", "unit_gate_status": "REPAIR_REQUIRED",
                    "intermediate_repair": {"status": "PENDING", "unit_index": index,
                        "failures_before_unit": before, "failures_after_coder": after,
                        "fix_attempts_before": attempts, "failures_after_intermediate_fix": None}}
        return {**result, "status": "BLOCKED", "unit_error": "UNIT_TEST_FAILURES_INCREASED",
                "unit_gate_status": "BLOCKED"}
    return {**result, "unit_index": index + 1, "unit_failure_before": after,
            "unit_gate_status": "CONTINUE"}


def route_after_baseline(state: AgentState):
    return "finalizer" if state.get("status") == "BLOCKED" else "discovery_baseline"


def route_after_workspace(state: AgentState):
    return "finalizer" if state.get("status") == "BLOCKED" else "preflight"


def route_after_preflight(state: AgentState):
    return "baseline" if state.get("preflight_status") == "PASS" and state.get("status") != "BLOCKED" else "finalizer"


def route_after_discovery_baseline(state: AgentState):
    return "finalizer" if state.get("status") == "BLOCKED" else "inspector"


def route_after_rollback(state: AgentState):
    if state.get("rollback_error") or state.get("status") == "BLOCKED":
        return "finalizer"
    if state.get("fix_attempts", 0) < MAX_FIX_ATTEMPTS:
        return "fixer"
    return "finalizer"


def route_after_reviewer(state: AgentState):
    if state.get("status") == "BLOCKED":
        return "finalizer"
    if state.get("review_verdict") == "PASS":
        return "finalizer"
    # The sole final Reviewer has no retry lease. A failed review cannot be
    # promoted without another independent review, so finish UNVERIFIED.
    return "finalizer"


def route_after_fixer(state: AgentState):
    if state.get("status") == "BLOCKED":
        return "finalizer"
    if state.get("fixer_error"):
        return "finalizer"

    return "tester"


def route_after_coder(state: AgentState):
    return "finalizer" if state.get("status") == "BLOCKED" else "tester"


def guarded_coder_node(state: AgentState, runner=coder_node):
    units = state.get("coding_units")
    if not isinstance(units, list) or not 1 <= len(units) <= MAX_UNITS:
        return {"status": "BLOCKED", "unit_error": "UNIT_LIMIT_OR_STATE_INVALID",
                "trace": ["coder:unit-guard"]}
    return runner(state)


def finalizer_node(state: AgentState):
    units = state.get("coding_units")
    if isinstance(units, list) and len(units) > MAX_UNITS:
        final_status = "BLOCKED"
        unit_error = "UNIT_LIMIT_EXCEEDED"
    elif state.get("status") == "BLOCKED":
        final_status = "BLOCKED"
        unit_error = ""

    else:
        final_status = "UNVERIFIED"
        unit_error = ""
        if state.get("review_verdict") == "PASS" and not machine_verification_error(state):
            try:
                from roles.workspace import verify_execution_contract
                verify_execution_contract(state)
                final_status = "VERIFIED"
            except Exception:
                final_status = "BLOCKED"

    result = {
        "status": final_status,
        "trace": ["finalizer"],
        **({"unit_error": unit_error} if unit_error else {}),
    }
    if state.get("run_dir"):
        return {**result, **finish_workspace({**state, **result})}
    return result


def build_graph(*, model_profiles=None):
    """Build the production graph; tests can replace model boundaries."""
    from roles.model_profiles import configured_selection, profile_scope
    selection = configured_selection(model_profiles)
    builder = StateGraph(AgentState)

    def timed(name, node):
        def run(state):
            started = time.monotonic_ns()
            with profile_scope(selection):
                result = node(state)
            return {**result, "role_timing_history": [{
                "role": name, "elapsed_ms": max(0, (time.monotonic_ns() - started) // 1_000_000)}]}
        return run

    # Capture the Tester supplied when this graph is built. Deterministic graph
    # fixtures replace that boundary before build_graph(), as production does.
    def unit_tester(state, runner=tester_node):
        return tested_unit_node(state, runner)

    def unit_coder(state, runner=coder_node):
        return guarded_coder_node(state, runner)

    for name, node in (("baseline", baseline_node), ("workspace", prepare_workspace_node),
                       ("preflight", preflight_node), ("discovery_baseline", discovery_baseline_node),
                       ("inspector", inspector_node), ("planner", planner_node),
                       ("unit_derivation", derive_units_node),
                       ("research_validation", research_validation_node), ("researcher", researcher_node),
                       ("coder", unit_coder), ("tester", unit_tester), ("reviewer", reviewer_node),
                       ("fixer", fixer_node), ("rollback", rollback_node), ("finalizer", finalizer_node)):
        builder.add_node(name, timed(name, node))

    builder.add_edge(
        START,
        "workspace",
    )

    builder.add_conditional_edges("workspace", route_after_workspace, {"preflight": "preflight", "finalizer": "finalizer"})
    builder.add_conditional_edges("preflight", route_after_preflight, {"baseline": "baseline", "finalizer": "finalizer"})
    builder.add_conditional_edges("baseline", route_after_baseline, {"discovery_baseline": "discovery_baseline", "finalizer": "finalizer"})
    builder.add_conditional_edges("discovery_baseline", route_after_discovery_baseline, {"inspector": "inspector", "finalizer": "finalizer"})
    builder.add_conditional_edges("inspector", route_after_inspector, {"planner": "planner", "finalizer": "finalizer"})

    builder.add_conditional_edges(
        "planner",
        route_after_planner,
        {
            "unit_derivation": "unit_derivation",
            "finalizer": "finalizer",
        },
    )
    builder.add_conditional_edges("unit_derivation", route_after_unit_derivation,
                                  {"research_validation": "research_validation", "finalizer": "finalizer"})

    builder.add_conditional_edges("research_validation", route_after_research_validation,
                                  {"researcher": "researcher", "coder": "coder", "finalizer": "finalizer"})

    builder.add_conditional_edges(
        "researcher",
        route_after_researcher,
        {
            "coder": "coder",
            "finalizer": "finalizer",
        },
    )

    builder.add_conditional_edges("coder", route_after_coder, {"tester": "tester", "finalizer": "finalizer"})

    builder.add_conditional_edges(
        "tester",
        route_after_tester,
        {
            "reviewer": "reviewer", "coder": "coder",
            "fixer": "fixer",
            "rollback": "rollback",
            "finalizer": "finalizer",
        },
    )

    builder.add_conditional_edges(
        "rollback",
        route_after_rollback,
        {"fixer": "fixer", "finalizer": "finalizer"},
    )

    builder.add_conditional_edges(
        "reviewer",
        route_after_reviewer,
        {
            "fixer": "fixer",
            "finalizer": "finalizer",
        },
    )

    builder.add_conditional_edges(
        "fixer",
        route_after_fixer,
        {
            "tester": "tester",
            "finalizer": "finalizer",
        },
    )

    builder.add_edge(
        "finalizer",
        END,
    )

    return builder.compile()


graph = build_graph()
