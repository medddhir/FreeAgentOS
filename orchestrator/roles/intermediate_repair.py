"""Controller-owned bounded intermediate repair checkpoint and safe projection."""

FIELDS = {"status", "unit_index", "failures_before_unit", "failures_after_coder",
          "fix_attempts_before", "failures_after_intermediate_fix"}


def repair_checkpoint(state, *, tested=False):
    value = state.get("intermediate_repair")
    units = state.get("coding_units")
    index = state.get("unit_index")
    if (not isinstance(value, dict) or set(value) != FIELDS or value["status"] != "PENDING"
            or not isinstance(units, list) or not 2 <= len(units) <= 3
            or type(index) is not int or not 0 <= index < len(units) - 1
            or type(value["unit_index"]) is not int or value["unit_index"] != index or state.get("unit_gate_status") != "REPAIR_REQUIRED"
            or state.get("status") == "BLOCKED" or state.get("unit_error")
            or any(type(value[key]) is not int or not 0 <= value[key] <= 1_000_000
                   for key in ("failures_before_unit", "failures_after_coder"))
            or value["failures_after_coder"] <= value["failures_before_unit"]
            or type(state.get("unit_failure_before")) is not int
            or value["failures_before_unit"] != state.get("unit_failure_before")
            or type(value["fix_attempts_before"]) is not int or not 0 <= value["fix_attempts_before"] < 2
            or type(state.get("fix_attempts", 0)) is not int
            or state.get("fix_attempts", 0) != value["fix_attempts_before"] + int(tested)
            or value["failures_after_intermediate_fix"] is not None):
        raise ValueError("INTERMEDIATE_REPAIR_STATE_INVALID")
    return value


def repair_targets(state):
    """Narrow existing permissions; neither text nor failure paths grant access."""
    from roles.coding_units import _target_path, MAX_TARGET_FILES, MAX_CONTEXT_FILES
    checkpoint = repair_checkpoint(state)
    unit = state["coding_units"][checkpoint["unit_index"]]
    if not isinstance(unit, dict):
        raise ValueError("INTERMEDIATE_REPAIR_STATE_INVALID")
    hints = unit.get("target_files")
    if hints is not None and not isinstance(hints, list):
        raise ValueError("INTERMEDIATE_REPAIR_TARGETS_INVALID")
    targets = hints or unit.get("files") or []
    limit = MAX_TARGET_FILES if hints else MAX_CONTEXT_FILES
    if (not isinstance(targets, list) or len(targets) > limit
            or any(not isinstance(path, str) or not _target_path(path) for path in targets)
            or len(set(targets)) != len(targets)):
        raise ValueError("INTERMEDIATE_REPAIR_TARGETS_INVALID")
    enforced = unit.get("enforced_files") or []
    return [path for path in targets if not enforced or path in enforced]


def safe_intermediate(value, attempts, blocked=False):
    value = value if isinstance(value, dict) else {}
    if blocked and value.get("status") == "PENDING":
        value = {**value, "status": "FAILED"}
    result = {"intermediate_regression_detected": value.get("status") in ("PENDING", "RECOVERED", "FAILED"),
              "intermediate_fix_attempted": (type(attempts) is int and
                  type(value.get("fix_attempts_before")) is int and attempts > value["fix_attempts_before"]),
              "intermediate_fix_result": value.get("status") if value.get("status") in
                  ("PENDING", "RECOVERED", "FAILED") else "NONE",
              "global_fix_attempts": attempts if type(attempts) is int and 0 <= attempts <= 2 else None}
    for key in ("failures_before_unit", "failures_after_coder", "failures_after_intermediate_fix"):
        n = value.get(key)
        result[key] = n if type(n) is int and 0 <= n <= 1_000_000 else None
    return result


def completed_repair_error(state):
    value = state.get("intermediate_repair")
    if value is None:
        return None
    units = state.get("coding_units")
    if (not isinstance(value, dict) or set(value) != FIELDS or value.get("status") != "RECOVERED"
            or not isinstance(units, list) or not 2 <= len(units) <= 3
            or type(value.get("unit_index")) is not int or not 0 <= value["unit_index"] < len(units) - 1
            or any(type(value.get(key)) is not int or not 0 <= value[key] <= 1_000_000
                   for key in ("failures_before_unit", "failures_after_coder", "failures_after_intermediate_fix"))
            or value["failures_after_coder"] <= value["failures_before_unit"]
            or value["failures_after_intermediate_fix"] > value["failures_before_unit"]
            or type(value.get("fix_attempts_before")) is not int or not 0 <= value["fix_attempts_before"] < 2
            or type(state.get("fix_attempts")) is not int
            or not value["fix_attempts_before"] < state["fix_attempts"] <= 2):
        return "INTERMEDIATE_REPAIR_INCOMPLETE"
    return None
