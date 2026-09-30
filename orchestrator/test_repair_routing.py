from pathlib import Path

from langgraph.graph import StateGraph, START, END

from state import AgentState
from roles.tester import tester_node

from graph import (
    route_after_tester,
    route_after_reviewer,
    route_after_fixer,
    finalizer_node,
)


REPO = "/root/agent-stack/test-workspace"


def deterministic_fixer(state: AgentState):
    path = Path(REPO) / "calculator.py"
    text = path.read_text()

    old = "discount = subtotal * (discount_percent / 10)"
    new = "discount = subtotal * (discount_percent / 100)"

    if old not in text:
        return {
            "fix_attempts": (
                state.get("fix_attempts", 0) + 1
            ),
            "fixer_error": "EXPECTED_BAD_CODE_NOT_FOUND",
            "trace": ["fixer:deterministic:error"],
        }

    path.write_text(
        text.replace(old, new, 1)
    )

    return {
        "fix_attempts": (
            state.get("fix_attempts", 0) + 1
        ),
        "fixer_output": "Repaired /10 to /100.",
        "fixer_error": "",
        "trace": ["fixer:deterministic"],
    }


def deterministic_reviewer(state: AgentState):
    if (
        state.get("test_result") == "PASS"
        and state.get("diff_check_exit") == 0
        and not state.get(
            "protected_files_changed",
            [],
        )
    ):
        verdict = "PASS"
        issues = []
    else:
        verdict = "FAIL"
        issues = ["Machine evidence was not acceptable."]

    return {
        "review": "Deterministic routing review.",
        "review_verdict": verdict,
        "review_issues": issues,
        "reviewer_error": "",
        "trace": ["reviewer:deterministic"],
    }


builder = StateGraph(AgentState)

builder.add_node(
    "tester",
    tester_node,
)

builder.add_node(
    "fixer",
    deterministic_fixer,
)

builder.add_node(
    "reviewer",
    deterministic_reviewer,
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
            "Do not modify the tests."
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
print("=== DETERMINISTIC REPAIR RESULT ===")

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
    "TEST_RESULT="
    + result.get("test_result", "")
)

print(
    "TEST_EXIT="
    + str(
        result.get("test_exit", "")
    )
)

print(
    "REVIEW_VERDICT="
    + result.get("review_verdict", "")
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
