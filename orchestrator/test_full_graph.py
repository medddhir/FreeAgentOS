from graph import graph


initial_state = {
    "task": (
        "Fix the existing failing calculator tests. "
        "Do not modify the tests. "
        "Make the smallest correct implementation change."
    ),
    "repo_dir": (
        "/root/agent-stack/test-workspace"
    ),
    "trace": [],
}


result = graph.invoke(
    initial_state,
    config={
        "recursion_limit": 20,
    },
)


print()
print("=== FREEAGENTOS GRAPH RESULT ===")

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
    "NEEDS_RESEARCH="
    + str(
        result.get(
            "needs_research",
            False,
        )
    )
)

print(
    "RESEARCH_SOURCE="
    + result.get(
        "research_source",
        "none",
    )
)

print(
    "CODER_ERROR="
    + result.get(
        "coder_error",
        "",
    )
)

print(
    "TEST_RESULT="
    + result.get(
        "test_result",
        "",
    )
)

print(
    "TEST_EXIT="
    + str(
        result.get(
            "test_exit",
            "",
        )
    )
)

print(
    "CHANGED_FILES="
    + ",".join(
        result.get(
            "changed_files",
            [],
        )
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

print(
    "REVIEW_VERDICT="
    + result.get(
        "review_verdict",
        "",
    )
)

print(
    "REVIEW_ISSUES="
    + " | ".join(
        result.get(
            "review_issues",
            [],
        )
    )
)

print()
print("=== PLAN ===")

for i, step in enumerate(
    result.get(
        "plan_steps",
        [],
    ),
    1,
):
    print(f"{i}. {step}")

print()
print("=== FINAL DIFF ===")
print(
    result.get(
        "diff",
        "",
    )
)
