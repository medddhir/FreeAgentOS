from typing import Annotated, TypedDict
import operator


class AgentState(TypedDict, total=False):
    task: str
    repo_dir: str
    source_repo: str
    source_head: str
    run_workspace: str
    run_dir: str
    workspace_id: str
    workspace_status: str
    workspace_error: str
    workspace_preexisting_dirty: list[str]
    verification_manifest: str
    verification_manifest_sha256: str
    verification_manifest_data: dict
    workspace_test_attestation: dict
    preflight_status: str
    preflight_capabilities: dict
    preflight_required_failures: list[str]
    preflight_optional_failures: list[str]
    preflight_error: str
    preflight_evidence_sha256: str
    sandbox_evidence: dict
    worker_history: Annotated[list[dict], operator.add]
    role_timing_history: Annotated[list[dict], operator.add]
    research_execution_history: list[dict]
    research_failure_kind: str
    workspace_integrity_error: str
    retain_workspace: bool
    verified_patch_path: str
    promotion_metadata_path: str
    promotion_ready: bool
    promotion_error: str
    # Trusted caller policy. Only literal True grants an exception.
    allow_new_files: bool
    allow_deletes: bool
    allow_test_changes: bool
    allow_verification_changes: bool
    integrity_baseline: dict
    integrity_violations: dict
    rollback_evidence: dict
    rollback_history: Annotated[list[dict], operator.add]
    rollback_error: str

    # Deterministic Inspector
    repo_facts: dict
    repo_facts_text: str
    inspector_error: str

    # Deterministic research routing
    research_validation_passed: bool
    research_validation_error: str
    research_required_identifiers: list[str]
    research_query_identifiers: list[str]
    research_added_identifiers: list[str]
    research_rejected_identifiers: list[str]
    research_local_identifiers: list[str]
    research_validation_evidence: dict
    research_expected_entities: list[str]

    # Planner
    plan: str
    plan_steps: list[str]
    planner_coding_units: list[dict]
    unit_derivation_source: str
    needs_research: bool
    research_type: str
    research_query: str
    planner_error: str
    planner_error_code: str
    planner_error_stage: str
    planner_diagnostic: dict

    # Deterministic bounded coding units; one fresh Coder lease per unit.
    coding_units: list[dict]
    unit_index: int
    unit_failure_before: int
    unit_gate_status: str
    unit_error: str
    unit_history: Annotated[list[dict], operator.add]
    unit_file_fingerprints: dict

    # Researcher
    research: str
    research_source: str
    research_results: int
    research_error: str

    # Coder
    implementation: str
    coder_error: str

    # Machine tester
    test_result: str
    test_exit: int
    test_output: str
    machine_failure_evidence: dict
    diff_check_exit: int
    changed_files: list[str]
    untracked_files: list[str]
    new_files: list[str]
    deleted_files: list[str]
    protected_files_changed: list[str]
    verification_files_changed: list[str]
    diff: str
    tester_error: str

    # Fixer
    fix_attempts: int
    fixer_output: str
    fixer_error: str

    # Reviewer
    review: str
    review_verdict: str
    review_issues: list[str]
    reviewer_error: str

    # Final state
    status: str

    trace: Annotated[
        list[str],
        operator.add,
    ]
