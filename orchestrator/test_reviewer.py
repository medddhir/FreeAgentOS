from roles.tester import tester_node
from roles.reviewer import reviewer_node


base = {
    "task": (
        "Fix the existing failing calculator tests. "
        "Do not modify the tests. "
        "Make the smallest correct implementation change."
    ),
    "repo_dir": (
        "/root/agent-stack/test-workspace"
    ),
    "plan_steps": [
        "Inspect calculator.py and its tests",
        "Identify the calculation bug",
        "Make the minimal implementation fix",
        "Run tests",
        "Inspect final diff",
    ],
    "research": "",
    "trace": [],
}

tested = {
    **base,
    **tester_node(base),
}

reviewed = reviewer_node(
    tested
)

print(
    "TRACE="
    + ",".join(
        reviewed.get(
            "trace",
            [],
        )
    )
)

print(
    "VERDICT="
    + reviewed.get(
        "review_verdict",
        "",
    )
)

print(
    "ERROR="
    + reviewed.get(
        "reviewer_error",
        "",
    )
)

print(
    "ISSUES="
    + " | ".join(
        reviewed.get(
            "review_issues",
            [],
        )
    )
)

print(
    "SUMMARY="
    + reviewed.get(
        "review",
        "",
    )
)
