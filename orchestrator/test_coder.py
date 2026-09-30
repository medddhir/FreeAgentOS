from roles.coder import coder_node


state = {
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
        "Run freeagent-test",
        "Inspect git diff",
    ],
    "research": "",
    "trace": [],
}

result = coder_node(state)

print(
    "TRACE="
    + ",".join(
        result.get("trace", [])
    )
)

print(
    "CODER_ERROR="
    + result.get("coder_error", "")
)

print()
print("=== CODER OUTPUT ===")
print(
    result.get(
        "implementation",
        "",
    )
)
