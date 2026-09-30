from roles.tester import tester_node


result = tester_node(
    {
        "task": (
            "Fix the existing failing calculator tests. "
            "Do not modify the tests."
        ),
        "repo_dir": (
            "/root/agent-stack/test-workspace"
        ),
        "trace": [],
    }
)

print(
    "TRACE="
    + ",".join(
        result.get("trace", [])
    )
)

print(
    "TEST_RESULT="
    + result.get("test_result", "")
)

print(
    "TEST_EXIT="
    + str(result.get("test_exit"))
)

print(
    "DIFF_CHECK_EXIT="
    + str(result.get("diff_check_exit"))
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
    "UNTRACKED_FILES="
    + ",".join(
        result.get(
            "untracked_files",
            [],
        )
    )
)

print(
    "DELETED_FILES="
    + ",".join(
        result.get(
            "deleted_files",
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

print()
print("=== TEST OUTPUT ===")
print(
    result.get(
        "test_output",
        "",
    )
)

print()
print("=== DIFF ===")
print(
    result.get(
        "diff",
        "",
    )
)
