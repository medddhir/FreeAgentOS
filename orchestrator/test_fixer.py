from roles.tester import tester_node
from roles.fixer import fixer_node


base = {
    "task": (
        "Fix the existing failing calculator tests. "
        "Do not modify the tests."
    ),
    "repo_dir": (
        "/root/agent-stack/test-workspace"
    ),
    "fix_attempts": 0,
    "trace": [],
}

tested = {
    **base,
    **tester_node(base),
}

fixed = fixer_node(
    tested
)

print(
    "TRACE="
    + ",".join(
        fixed.get(
            "trace",
            [],
        )
    )
)

print(
    "FIX_ATTEMPTS="
    + str(
        fixed.get(
            "fix_attempts",
            0,
        )
    )
)

print(
    "FIXER_ERROR="
    + fixed.get(
        "fixer_error",
        "",
    )
)

print()
print("=== FIXER OUTPUT ===")

print(
    fixed.get(
        "fixer_output",
        "",
    )
)
