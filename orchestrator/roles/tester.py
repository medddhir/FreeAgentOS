from pathlib import Path

from state import AgentState
from roles.integrity import ERRORS, changes, check_baseline, fingerprint, is_verification_file
from roles.controller_git import ControllerGitError, run_git
from roles.sandbox import run_isolated
from roles.workspace import _inventory, _load_verified_manifest, test_discovery_count
from roles.repair_context import failure_evidence


TEST_TIMEOUT = 130
MAX_OUTPUT = 7000


def _run(
    cmd: list[str],
    repo: str,
    timeout: int = 30,
):
    try:
        if not cmd or cmd[0] != "git":
            raise ControllerGitError("TESTER_CONTROLLER_COMMAND_DENIED")
        result = run_git(cmd[1:], cwd=repo, timeout=timeout)

        return (
            result.returncode,
            result.stdout.decode("utf-8", "replace") or "",
        )

    except ControllerGitError as exc:
        return 124, str(exc)

    except OSError:
        return 127, "PROCESS_UNAVAILABLE"


def _trim(text: str) -> str:
    text = text or ""

    if len(text) <= MAX_OUTPUT:
        return text

    return (
        "... output truncated ...\n"
        + text[-MAX_OUTPUT:]
    )


def _is_test_file(path: str) -> bool:
    value = path.lower().replace("\\", "/")
    name = Path(value).name
    parts = value.split("/")

    return (
        "tests" in parts
        or "__tests__" in parts
        or name.startswith("test_")
        or "_test." in name
        or ".test." in name
        or ".spec." in name
    )


def tester_node(
    state: AgentState,
) -> AgentState:
    repo = state.get(
        "repo_dir",
        "",
    ).strip()

    if not repo:
        return {
            "tester_error": "MISSING_REPO_DIR",
            "test_result": "FAIL",
            "status": "BLOCKED",
            "trace": ["tester:error"],
        }

    if not Path(repo).is_dir():
        return {
            "tester_error": "REPO_DIR_NOT_FOUND",
            "test_result": "FAIL",
            "status": "BLOCKED",
            "trace": ["tester:error"],
        }

    manifest = None
    attestation = state.get("workspace_test_attestation", {})
    isolated = False
    sandbox_evidence = {}
    if not state.get("run_workspace"):
        return {"tester_error": "MISSING_ISOLATED_WORKSPACE", "test_result": "FAIL",
                "test_exit": 125, "status": "BLOCKED", "trace": ["tester:missing-workspace"]}
    else:
        try:
            manifest = _load_verified_manifest(state)
            check_baseline(state)
            if Path(repo).resolve() != Path(manifest["workspace_repo"]).resolve():
                raise RuntimeError("WORKSPACE_IDENTITY_MISMATCH")
            workspace_test = run_isolated(repo, state["run_dir"], manifest["runner_sha256"], TEST_TIMEOUT)
            test_exit, test_output, isolated = workspace_test["exit_code"], workspace_test["output"], workspace_test["isolated"]
            sandbox_evidence = workspace_test["evidence"]
            if not isolated:
                raise RuntimeError("ISOLATION_NOT_ESTABLISHED")
        except Exception as exc:
            return {"tester_error": str(exc), "test_result": "FAIL", "test_exit": 125,
                    "sandbox_evidence": getattr(exc, "evidence", {}),
                    "status": "BLOCKED", "trace": ["tester:isolation-error"]}

    diff_checks = [
        _run(["git", "diff", "--check", *comparison], repo)[0]
        for comparison in (("HEAD",), ("--cached", "HEAD"), ())
    ]
    diff_check_exit = next((code for code in diff_checks if code != 0), 0)

    diff_exit, diff = _run(
        [
            "git",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "HEAD",
        ],
        repo,
    )

    try:
        repo_path, _ = check_baseline(state)
        if diff_exit:
            raise RuntimeError("GIT_DIFF_FAILED")
        current = changes(repo_path, state.get("integrity_baseline"))
    except ERRORS as exc:
        return {"tester_error": str(exc), "test_result": "FAIL",
                "status": "BLOCKED", "trace": ["tester:error"]}

    changed_files = current["changed"]
    untracked_files = current["untracked"]
    deleted_files = current["deleted"]
    new_files = current["new"]

    # Git's ordinary diff omits untracked files and can omit index-only edits.
    # Authorized new files still need code-review and whitespace evidence.
    cached_exit, cached_diff = _run(
        ["git", "diff", "--no-ext-diff", "--no-textconv", "--cached", "HEAD"], repo,
    )
    if cached_exit:
        return {"tester_error": "GIT_CACHED_DIFF_FAILED", "test_result": "FAIL",
                "status": "BLOCKED", "trace": ["tester:error"]}
    if cached_diff:
        diff += "\n=== INDEX VS HEAD ===\n" + cached_diff
    if state.get("allow_new_files") is True:
        for name in untracked_files:
            args = ["git", "--literal-pathspecs", "diff", "--no-index",
                    "--no-ext-diff", "--no-textconv"]
            path = str(repo_path / name)
            code, new_diff = _run([*args, "--", "/dev/null", path], repo)
            if code not in (0, 1):
                return {"tester_error": "NEW_FILE_DIFF_FAILED", "test_result": "FAIL",
                        "status": "BLOCKED", "trace": ["tester:error"]}
            diff += "\n=== NEW FILE ===\n" + new_diff
            code, output = _run([*args, "--check", "--", "/dev/null", path], repo)
            # --no-index returns 1 for ordinary differences, 3 for whitespace
            # errors plus differences. Diagnostics also fail closed.
            if code not in (0, 1) or output:
                diff_check_exit = code if code not in (0, 1) else 2

    # Policy is supplied by the trusted graph caller. Model text cannot grant it.
    protected = [path for path in changed_files if _is_test_file(path)]
    verification = [path for path in changed_files if is_verification_file(path)]
    forbidden_verification = [] if state.get("allow_verification_changes") is True else verification
    forbidden_protected = [] if state.get("allow_test_changes") is True else protected
    forbidden_untracked = ([] if state.get("allow_new_files") is True else
                           sorted(set(untracked_files) & set(new_files)))
    forbidden_new = [] if state.get("allow_new_files") is True else new_files
    forbidden_deleted = [] if state.get("allow_deletes") is True else deleted_files
    violations = {
        "protected": forbidden_protected,
        "verification": forbidden_verification,
        "untracked": forbidden_untracked,
        "new": forbidden_new,
        "deleted": forbidden_deleted,
        "all": sorted(set(forbidden_protected + forbidden_verification + forbidden_new + forbidden_deleted)),
    }

    try:
        violations["evidence"] = {
            name: fingerprint(repo_path, name) for name in violations["all"]
        }
    except ERRORS as exc:
        return {"tester_error": str(exc), "test_result": "FAIL",
                "status": "BLOCKED", "trace": ["tester:error"]}

    integrity_failures = []

    if forbidden_verification:
        integrity_failures.append("VERIFICATION_FILES_CHANGED=" + ",".join(forbidden_verification))

    if forbidden_protected:
        integrity_failures.append(
            "PROTECTED_TEST_FILES_CHANGED="
            + ",".join(forbidden_protected)
        )

    if forbidden_new:
        integrity_failures.append(
            "NEW_FILES="
            + ",".join(forbidden_new)
        )

    if forbidden_deleted:
        integrity_failures.append(
            "DELETED_FILES="
            + ",".join(forbidden_deleted)
        )

    result_markers = [line for line in test_output.splitlines() if line.startswith("RESULT=")]
    discovery = None
    discovery_ok = True
    workspace_integrity_error = ""
    if manifest is not None:
        try:
            final_files, _ = _inventory(repo_path)
            final_hashes = {name: __import__("hashlib").sha256(data).hexdigest()
                            for name, data, _ in final_files}
            changed_tests = sorted(name for name in set(manifest["test_inventory"]) | set(final_hashes)
                                   if ((name in manifest["test_inventory"] or _is_test_file(name))
                                       and manifest["test_inventory"].get(name) != final_hashes.get(name)))
            changed_verification = sorted(name for name in set(manifest["verification_inputs"]) | set(final_hashes)
                                          if ((name in manifest["verification_inputs"] or is_verification_file(name))
                                              and manifest["verification_inputs"].get(name) != final_hashes.get(name)))
            if changed_tests and state.get("allow_test_changes") is not True:
                workspace_integrity_error = "PROTECTED_TEST_INVENTORY_CHANGED"
            if changed_verification and state.get("allow_verification_changes") is not True:
                workspace_integrity_error = workspace_integrity_error or "VERIFICATION_INPUTS_CHANGED"
            final_count, framework = test_discovery_count(test_output)
            expected_count = attestation.get("baseline_count")
            discovery_ok = (attestation.get("baseline_status") == "ATTESTED" and final_count is not None
                            and expected_count is not None and final_count >= expected_count)
            discovery = {**attestation, "final_count": final_count, "framework": framework,
                         "status": "PASS" if discovery_ok else "FAIL",
                         "count_not_reduced": bool(discovery_ok and final_count >= expected_count)}
            if not discovery_ok:
                workspace_integrity_error = workspace_integrity_error or "TEST_DISCOVERY_UNATTESTED_OR_REDUCED"
            _load_verified_manifest(state)
        except Exception as exc:
            workspace_integrity_error = "VERIFIER_ATTESTATION_FAILED:" + str(exc)
            discovery_ok = False
    passed = (
        test_exit == 0
        and result_markers[-1:] == ["RESULT=PASS"]
        and diff_check_exit == 0
        and not integrity_failures
        and discovery_ok
        and not workspace_integrity_error
    )

    if workspace_integrity_error:
        integrity_failures.append(workspace_integrity_error)

    if integrity_failures:
        test_output = (
            test_output.rstrip()
            + "\n\n"
            + "=== REPOSITORY INTEGRITY ===\n"
            + "\n".join(
                integrity_failures
            )
            + "\n"
        )

    machine_failure_evidence = failure_evidence(test_output, (discovery or attestation).get("framework"))

    return {
        "machine_failure_evidence": machine_failure_evidence,
        "test_result": (
            "PASS"
            if passed
            else "FAIL"
        ),
        "test_exit": test_exit,
        "test_output": _trim(
            test_output
        ),
        "diff_check_exit": diff_check_exit,
        "changed_files": changed_files,
        "untracked_files": untracked_files,
        "new_files": new_files,
        "deleted_files": deleted_files,
        "protected_files_changed": protected,
        "verification_files_changed": verification,
        "integrity_violations": violations,
        "diff": _trim(diff),
        "tester_error": "",
        "workspace_test_attestation": discovery or attestation,
        "sandbox_evidence": sandbox_evidence,
        "workspace_integrity_error": workspace_integrity_error,
        "trace": ["tester"],
    }
