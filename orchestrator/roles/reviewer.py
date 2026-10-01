import json
import subprocess
from pathlib import Path
from typing import Any

from state import AgentState
from roles.worker import WorkerBoundaryError, run_worker
from roles.model_profiles import model_command
from roles.workspace import verify_execution_contract
from roles.coding_units import MAX_UNITS
from roles.sandbox import REQUIRED_CONTROLS
from roles.read_policy import no_file_tool_flags
from roles.repair_context import sanitized


REVIEWER_TIMEOUT = 90
MAX_EVIDENCE = 6500


REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": [
                "PASS",
                "FAIL",
            ],
        },
        "issues": {
            "type": "array",
            "items": {
                "type": "string",
            },
            "maxItems": 5,
        },
        "summary": {
            "type": "string",
        },
    },
    "required": [
        "verdict",
        "issues",
        "summary",
    ],
    "additionalProperties": False,
}


def machine_verification_error(state, *, final=True):
    """Return a bounded code when controller evidence cannot support review."""
    if final:
        from roles.intermediate_repair import completed_repair_error
        error = completed_repair_error(state)
        if error:
            return error
    if state.get("status") == "BLOCKED":
        return "CONTROLLER_BLOCKED"
    if (state.get("tester_error") or state.get("workspace_integrity_error")
            or state.get("rollback_error") or state.get("unit_error")):
        return "TESTER_OR_WORKSPACE_ERROR"
    if final and (state.get("reviewer_error") or state.get("fixer_error")):
        return "MODEL_REVIEW_OR_REPAIR_ERROR"
    if state.get("diff_check_exit") != 0:
        return "DIFF_CHECK_FAILED"
    violations = state.get("integrity_violations")
    if not isinstance(violations, dict):
        return "INTEGRITY_EVIDENCE_MISSING"
    if any(not isinstance(violations.get(key), list) or violations[key]
           for key in ("protected", "verification", "untracked", "new", "deleted", "all")):
        return "INTEGRITY_VIOLATION_OR_INVALID_EVIDENCE"
    if state.get("protected_files_changed") and state.get("allow_test_changes") is not True:
        return "PROTECTED_TEST_CHANGED"
    if state.get("verification_files_changed") and state.get("allow_verification_changes") is not True:
        return "VERIFICATION_FILE_CHANGED"
    if not final and state.get("test_result") != "PASS":
        if state.get("test_exit") == 125:
            return "TESTER_SETUP_FAILED"
    elif state.get("test_result") != "PASS" or state.get("test_exit") != 0:
        return "MACHINE_TEST_NOT_PASSED"

    workspace = state.get("run_workspace")
    if not workspace:
        return "ISOLATED_WORKSPACE_MISSING"
    try:
        if Path(state.get("repo_dir", "")).resolve(strict=True) != Path(workspace).resolve(strict=True):
            return "WORKSPACE_IDENTITY_MISMATCH"
    except (OSError, RuntimeError, ValueError):
        return "WORKSPACE_IDENTITY_UNAVAILABLE"
    if state.get("preflight_status") != "PASS":
        return "PREFLIGHT_NOT_PASSED"
    attestation = state.get("workspace_test_attestation")
    if (not isinstance(attestation, dict) or attestation.get("status") != "PASS"
            or attestation.get("baseline_status") != "ATTESTED"
            or attestation.get("isolated") is not True
            or type(attestation.get("baseline_count")) is not int
            or type(attestation.get("final_count")) is not int
            or attestation["final_count"] < attestation["baseline_count"]
            or attestation.get("count_not_reduced") is not True):
        return "DISCOVERY_ATTESTATION_FAILED"
    sandbox = state.get("sandbox_evidence")
    if (not isinstance(sandbox, dict) or sandbox.get("cleanup_status") != "CONFIRMED"
            or sandbox.get("remaining_processes") != 0 or sandbox.get("cgroup_status") != "ENFORCED"
            or sandbox.get("timeout_triggered") is not False
            or sandbox.get("output_truncated") is not False
            or not isinstance(sandbox.get("controls"), dict)
            or not isinstance(sandbox.get("resource_hits"), dict)
            or any(sandbox["resource_hits"].values())
            or any(sandbox.get("controls", {}).get(key) != "ENFORCED" for key in REQUIRED_CONTROLS)):
        return "ISOLATED_VERIFICATION_UNPROVEN"

    if final:
        units = state.get("coding_units")
        if not isinstance(units, list) or not 1 <= len(units) <= MAX_UNITS:
            return "CODING_UNITS_INVALID"
        if (type(state.get("unit_index")) is not int or state["unit_index"] != len(units)
                or state.get("unit_gate_status") != "FINAL"):
            return "CODING_UNITS_INCOMPLETE"
        ids = [unit.get("id") if isinstance(unit, dict) else None for unit in units]
        if ids != [f"unit-{index + 1}" for index in range(len(units))]:
            return "CODING_UNIT_IDENTITIES_INVALID"
        history = state.get("unit_history")
        if not isinstance(history, list):
            return "CODING_UNIT_HISTORY_MISSING"
        progress = []
        for record in history:
            if not isinstance(record, dict) or record.get("unit_id") not in ids:
                return "CODING_UNIT_HISTORY_INVALID"
            index = ids.index(record["unit_id"])
            if record.get("unit_index") != index + 1:
                return "CODING_UNIT_HISTORY_INVALID"
            if not progress or progress[-1] != record["unit_id"]:
                progress.append(record["unit_id"])
        if progress != ids or history[-1].get("test_result_after") != "PASS":
            return "CODING_UNIT_HISTORY_INCOMPLETE"
    return None


def _trim(
    value: str,
    limit: int = MAX_EVIDENCE,
) -> str:
    value = value or ""

    if len(value) <= limit:
        return value

    return (
        "... evidence truncated ...\n"
        + value[-limit:]
    )


def _run_reviewer(
    state: AgentState,
) -> dict[str, Any]:
    schema = json.dumps(
        REVIEW_SCHEMA,
        separators=(",", ":"),
    )

    task = state.get(
        "task",
        "",
    )

    steps = state.get(
        "plan_steps",
        [],
    )

    plan = "\n".join(
        f"{i}. {step}"
        for i, step in enumerate(
            steps,
            1,
        )
    )

    research = state.get(
        "research",
        "",
    ).strip()

    if not research:
        research = "No external research was required."

    test_output = _trim(
        state.get(
            "test_output",
            "",
        ),
        3000,
    )

    diff = _trim(
        state.get(
            "diff",
            "",
        ),
        3500,
    )

    changed = ",".join(
        state.get(
            "changed_files",
            [],
        )
    ) or "none"

    prompt = f"""
You are the REVIEWER node in a controlled coding-agent system.

You have NO repository access and NO tools.
Review only the supplied evidence.

TASK:
{task}

PLANNER STEPS:
{plan}

RESEARCH EVIDENCE:
{research}

MACHINE TEST RESULT:
{state.get("test_result", "")}

TEST EXIT:
{state.get("test_exit", "")}

DIFF CHECK EXIT:
{state.get("diff_check_exit", "")}

CHANGED FILES:
{changed}

TEST FILES CHANGED:
{",".join(state.get("protected_files_changed", [])) or "none"}

ISOLATED TEST DISCOVERY ATTESTATION:
{json.dumps(state.get("workspace_test_attestation", {}), sort_keys=True)}

WORKSPACE INTEGRITY ERROR:
{state.get("workspace_integrity_error", "")}

TRUSTED POLICY ALLOWS TEST CHANGES:
{state.get("allow_test_changes") is True}

TEST OUTPUT:
{sanitized(test_output, 3000)}

FINAL DIFF:
{sanitized(diff, 3500)}

Review requirements:
- determine whether the actual diff addresses the task
- check for obvious logic mistakes or unrelated changes
- treat machine test evidence as evidence, not as proof of every requirement
- do not invent repository facts not present above
- do not request stylistic changes unless they affect correctness or the task
- PASS only when the supplied evidence supports the requested change
- FAIL when there is a concrete correctness, scope, safety, or requirement issue
- issues must be specific and actionable
- if verdict is PASS, issues should normally be empty

Return only the schema-constrained structured result.
""".strip()

    result = run_worker(
        model_command("reviewer", no_file_tool_flags(), prompt, schema=schema),
        timeout=REVIEWER_TIMEOUT,
        role="reviewer",
    )

    if result.returncode != 0:
        error = RuntimeError("Reviewer model failed or timed out.")
        error.evidence = result.evidence
        raise error

    try:
        envelope = json.loads(
            result.stdout
        )
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Reviewer returned invalid outer JSON."
        ) from exc

    payload = envelope.get(
        "structured_output"
    )

    if not isinstance(payload, dict):
        raw = envelope.get("result")

        if isinstance(raw, str):
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = None

    if not isinstance(payload, dict):
        raise RuntimeError(
            "Reviewer structured output missing."
        )

    payload["_worker_evidence"] = result.evidence
    return payload


def reviewer_node(
    state: AgentState,
) -> AgentState:
    error = machine_verification_error(state)
    if error:
        return {"review": "Machine verification is incomplete or rejected.",
                "review_verdict": "FAIL", "review_issues": [error],
                "reviewer_error": "", "status": "BLOCKED",
                "trace": ["reviewer:machine-reject"]}

    contract_verified = False
    try:
        verify_execution_contract(state)
        contract_verified = True
        payload = _run_reviewer(
            state
        )

        verdict = str(
            payload.get(
                "verdict",
                "FAIL",
            )
        ).strip().upper()

        issues_raw = payload.get(
            "issues",
            [],
        )

        if not isinstance(
            issues_raw,
            list,
        ):
            issues_raw = []

        issues = [
            str(issue).strip()
            for issue in issues_raw[:5]
            if str(issue).strip()
        ]

        summary = str(
            payload.get(
                "summary",
                "",
            )
        ).strip()

        if verdict not in {
            "PASS",
            "FAIL",
        }:
            raise RuntimeError(
                "Invalid reviewer verdict."
            )

        if (
            verdict == "PASS"
            and issues
        ):
            # Keep the contract internally consistent.
            verdict = "FAIL"

    except Exception as exc:
        return {
            "review": "",
            "review_verdict": "FAIL",
            "review_issues": [],
            "reviewer_error": str(exc),
            "worker_history": ([{"role": "reviewer", "evidence": exc.evidence}]
                               if getattr(exc, "evidence", None) else []),
            **({"status": "BLOCKED"} if not contract_verified or isinstance(exc, WorkerBoundaryError) else {}),
            "trace": [
                "reviewer:error"
            ],
        }

    return {
        "review": summary,
        "review_verdict": verdict,
        "review_issues": issues,
        "reviewer_error": "",
        "worker_history": ([{"role": "reviewer", "evidence": payload["_worker_evidence"]}]
                           if payload.get("_worker_evidence") else []),
        "trace": ["reviewer"],
    }
