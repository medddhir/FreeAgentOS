"""One opt-in synthetic Coder profile session; descriptions send no generation.

No payloads/transcripts are persisted. Passing the session smoke is not proof
of upstream served identity, coding quality or long-session reliability.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from roles.model_profiles import profile_scope, resolve_profile, requested_identity, model_command
from roles.read_policy import file_tool_flags, capability_contract, sealed_policy, read_authorized, ReadDenied
from roles.model_attribution import attribution_for
from roles.worker import run_worker
from roles.controller_git import run_git
from roles.workspace import prepare_workspace_node, verify_execution_contract, cleanup_active_workspace
from roles.preflight import preflight_node
from cli import _evidence

PROFILE = "claude-free-gpt-oss-120b"
DEFAULT_PROFILE = "claude-free-default"
MODEL = "openai/gpt-oss-120b"
CONTAINER = "freellmapi-freellmapi-1"
FIXTURE_INITIAL = b"value = 0\n"
FIXTURE_EXPECTED = b"value = 1\n"
FIXTURE_TASK = ("Use Read once on the authorized existing implementation file, then Edit once "
                "to change only its integer literal 0 to 1. Preserve every other byte, including "
                "the final newline. Do not use Write, discovery, shell or tests. Finish with a concise result.")
# No gateway imports/initializers: open the installed driver read-only and project booleans only.
CATALOG_SCRIPT = r'''
const DB=require("better-sqlite3");
if(process.env.FREEAPI_DB_PATH && process.env.FREEAPI_DB_PATH!=="/app/server/data/freeapi.db") process.exit(2);
const db=new DB("/app/server/data/freeapi.db",{readonly:true,fileMustExist:true});
const row=db.prepare("SELECT m.enabled,m.supports_tools,m.context_window,COALESCE(f.enabled,1) AS route_enabled,(SELECT COUNT(*) FROM api_keys k WHERE k.platform=m.platform AND k.enabled=1) AS credentials FROM models m LEFT JOIN fallback_config f ON f.model_db_id=m.id WHERE m.model_id=? AND m.platform=?").get("openai/gpt-oss-120b","groq");
console.log(JSON.stringify({catalog_ready:!!row&&row.enabled===1&&row.supports_tools===1&&row.route_enabled===1&&row.context_window>=131072&&row.credentials>0}));
db.close();
'''


def catalog_ready():
    """Reject stale/removed configuration before a live session; never echo stderr."""
    try:
        result = subprocess.run(["docker", "exec", CONTAINER, "node", "-e", CATALOG_SCRIPT],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
                                check=False)
        return result.returncode == 0 and len(result.stdout) <= 128 and json.loads(result.stdout) == {"catalog_ready": True}
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        return False


def describe(profile_id):
    if profile_id not in (PROFILE, DEFAULT_PROFILE):
        raise ValueError("QUALIFICATION_PROFILE_INVALID")
    profile = resolve_profile("coder", profile_id)
    resolve_profile("fixer", profile_id)
    with profile_scope({"coder": profile_id}):
        identity = requested_identity("coder")
        attribution = attribution_for("coder")
    return {"status": "CONFIGURED", "live_result": "NOT_RUN", "model_selection": identity,
            "identity_attribution": attribution,
            "coder_compatibility": "CONFIGURED", "fixer_compatibility": "CONFIGURED",
            "context_class": profile.context_class, "long_session_verified": False,
            "qualification_scope": ("CLIENT_DEFAULT_SESSION" if profile_id == DEFAULT_PROFILE else "EXPLICIT_MODEL_SESSION"),
            "base_ms": 180000, "max_grace_ms": 60000, "hard_cap_ms": 240000}


def verify_fixture(policy):
    """Read the actual sealed workspace target, before workspace cleanup."""
    try:
        return read_authorized(policy, "sample.py") == FIXTURE_EXPECTED
    except ReadDenied:
        return None


def qualification_checks(returncode, evidence, fixture_matches):
    """Independent fixed outcomes; completion never implies task correctness."""
    broker = evidence.get("broker", {})
    activity = evidence.get("activity", {})
    completion = evidence.get("completion", {})
    hits = evidence.get("resource_hits")
    resource_clear = (isinstance(hits, dict) and set(hits) == {"memory", "process_count"}
                      and all(value is False for value in hits.values()))
    execution = (returncode == 0 and evidence.get("cleanup_status") == "CONFIRMED"
                 and evidence.get("remaining_processes") == 0
                 and evidence.get("cgroup_status") == "ENFORCED" and resource_clear
                 and all(evidence.get("controls", {}).get(key) == "ENFORCED"
                         for key in ("cpu", "memory", "process_count", "output", "file_descriptors", "file_size")))
    tools = (broker.get("requests_total") == 2 and broker.get("success_total") == 2
             and broker.get("denied_total") == 0 and broker.get("error_total") == 0
             and broker.get("read_success") == 1 and broker.get("edit_success") == 1)
    result = (activity.get("activity_status") == "COMPLETE"
              and activity.get("result_event_observed") is True
              and activity.get("result_category") == "SUCCESS")
    exited = (completion.get("state") == "PROCESS_EXITED"
              and completion.get("process_alive_at_observation_end") is False
              and completion.get("stdout_eof_before_cleanup") is True
              and completion.get("stderr_eof_before_cleanup") is True)
    return {"execution_compatibility": "PASS" if execution else "FAIL",
            "tool_loop_compatibility": "PASS" if tools else "FAIL",
            "result_compatibility": "PASS" if result else "FAIL",
            "completion_compatibility": "PASS" if exited else "FAIL",
            "fixture_semantics": ("PASS" if fixture_matches is True else
                                  "FAIL" if fixture_matches is False else "NOT_OBSERVED")}


def qualify(profile_id):
    result = describe(profile_id)
    # Only the explicit candidate depends on its pinned catalog route.
    # Client default deliberately leaves model selection to the installed client/gateway.
    if profile_id == PROFILE and not catalog_ready():
        return {**result, "status": "BLOCKED", "reason": "MODEL_CATALOG_UNAVAILABLE"}
    with tempfile.TemporaryDirectory(prefix="freeagentos-qualification-") as temporary:
        source = Path(temporary) / "source"
        source.mkdir()
        (source / "sample.py").write_bytes(FIXTURE_INITIAL)
        for args in (["init", "--quiet"], ["config", "user.name", "FreeAgentOS qualification"],
                     ["config", "user.email", "qualification@localhost.invalid"],
                     ["config", "core.hooksPath", "/dev/null"], ["add", "--", "sample.py"],
                     ["commit", "--quiet", "-m", "Synthetic qualification fixture"]):
            if run_git(args, cwd=source, timeout=10).returncode:
                return {**result, "status": "BLOCKED", "reason": "QUALIFICATION_FIXTURE_FAILED"}
        state = {"repo_dir": str(source), "allow_new_files": False, "allow_test_changes": False,
                 "allow_deletes": False, "allow_verification_changes": False}
        state.update(prepare_workspace_node(state))
        if state.get("workspace_error"):
            return {**result, "status": "BLOCKED", "reason": "QUALIFICATION_WORKSPACE_FAILED"}
        try:
            state.update(preflight_node(state))
            verify_execution_contract(state)
            unit = {"target_files": ["sample.py"]}
            flags = file_tool_flags(state, "coder", unit=unit)
            policy = sealed_policy(flags)
            prompt = capability_contract(flags) + "\n" + FIXTURE_TASK
            with profile_scope({"coder": profile_id}):
                command = model_command("coder", flags, prompt)
                worker = run_worker(command, cwd=state["repo_dir"], timeout=180,
                                    role="coder", stream_activity=True)
            verify_execution_contract(state)
            evidence = _evidence(worker.evidence)
            observation = evidence.get("gateway_attribution", {})
            if observation.get("routed_evidence") == "ROUTER_DISPATCH":
                result["identity_attribution"].update(observation)
                result["identity_attribution"]["attribution_status"] = "SESSION_BOUND_DISPATCH"

            # Do not short-circuit the semantic read behind unrelated execution gates.
            fixture_matches = verify_fixture(policy)
            checks = qualification_checks(worker.returncode, evidence, fixture_matches)
            passed = all(value == "PASS" for value in checks.values())
            return {**result, "status": "SESSION_SMOKE_PASS" if passed else "UNQUALIFIED",
                    "live_result": "PASS" if passed else "FAIL", "evidence": evidence,
                    "qualification_checks": checks,
                    "fixture_change_verified": fixture_matches is True}
        finally:
            if cleanup_active_workspace() != "CONFIRMED":
                raise RuntimeError("QUALIFICATION_CLEANUP_UNPROVEN")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Describe the explicit candidate or client-default profile, or explicitly run its contained session smoke.")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--live", action="store_true", help="Run one live Coder session; requires separate operator authorization.")
    args = parser.parse_args(argv)
    try:
        result = qualify(args.profile) if args.live else describe(args.profile)
    except Exception:
        result = {"status": "BLOCKED", "reason": "QUALIFICATION_FAILED", "served_model_id": "UNAVAILABLE"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in ("CONFIGURED", "SESSION_SMOKE_PASS") else 2


if __name__ == "__main__":
    raise SystemExit(main())
