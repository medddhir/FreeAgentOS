from roles.planner import planner_node


def run(task):
    result = planner_node(
        {
            "task": task,
            "trace": [],
        }
    )

    print()
    print("TASK=" + task)
    print(
        "TRACE="
        + ",".join(result.get("trace", []))
    )
    print(
        "NEEDS_RESEARCH="
        + str(result.get("needs_research"))
    )
    print(
        "RESEARCH_TYPE="
        + str(result.get("research_type"))
    )
    print(
        "RESEARCH_QUERY="
        + str(result.get("research_query"))
    )

    print("STEPS:")

    for i, step in enumerate(
        result.get("plan_steps", []),
        1,
    ):
        print(f"  {i}. {step}")

    if result.get("planner_error"):
        print(
            "ERROR="
            + result["planner_error"]
        )


run(
    "Fix the failing calculator function "
    "without changing its tests."
)

run(
    "Implement support for the latest version "
    "of an external payments API."
)
