from langgraph.graph import StateGraph, START, END

from state import AgentState
from roles.tester import tester_node
from roles.fixer import fixer_node
from roles.reviewer import reviewer_node

from graph import (
    route_after_tester,
    route_after_reviewer,
    route_after_fixer,
    finalizer_node,
)


REPO = "/root/agent-stack/test-workspace"


builder = StateGraph(AgentState)

builder.add_node(
    "tester",
    tester_node,
)

builder.add_node(
    "fixer",
    fixer_node,
)

builder.add_node(
    "reviewer",
    reviewer_node,
)

builder.add_node(
    "finalizer",
    finalizer_node,
)

builder.add_edge(
    START,
    "tester",
)

builder.add_conditional_edges(
    "tester",
    route_after_tester,
    {
        "reviewer": "reviewer",
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

builder.add_conditional_edges(
    "reviewer",
    route_after_reviewer,
    {
        "fixer": "fixer",
        "finalizer": "finalizer",
    },
)

builder.add_edge(
    "finalizer",
    END,
)

repair_graph = builder.compile()


result = repair_graph.invoke(
    {
        "task": (
            "Fix the existing failing calculator tests. "
            "Do not modify the tests. "
            "Make the smallest correct implementation repair."
        ),
        "repo_dir": REPO,
        "fix_attempts": 0,
        "trace": [],
    },
    config={
        "recursion_limit": 20,
    },
)


print()
print("=== REAL SELF-REPAIR RESULT ===")

print(
    "TRACE="
    + " -> ".join(
        result.get("trace", [])
    )
)

print(
    "STATUS="
    + result.get("status", "")
)

print(
    "FIX_ATTEMPTS="
    + str(
        result.get("fix_attempts", 0)
    )
)

print(
    "FIXER_ERROR="
    + result.get("fixer_error", "")
)

print(
    "TEST_RESULT="
    + result.get("test_result", "")
)

print(
    "TEST_EXIT="
    + str(result.get("test_exit", ""))
)

print(
    "REVIEW_VERDICT="
    + result.get("review_verdict", "")
)

print(
    "REVIEW_ISSUES="
    + " | ".join(
        result.get("review_issues", [])
    )
)

print(
    "CHANGED_FILES="
    + ",".join(
        result.get("changed_files", [])
    )
)

print(
    "PROTECTED_FILES_CHANGED="
    + ",".join(
        result.get(
            "protected_files_changed",
            [],
        )
    )
)

print()
print("=== FINAL DIFF ===")
print(
    result.get("diff", "")
)

success = (
    result.get("status") == "VERIFIED"
    and result.get("test_result") == "PASS"
    and result.get("review_verdict") == "PASS"
    and result.get("fix_attempts") == 1
)

raise SystemExit(
    0 if success else 1
)
