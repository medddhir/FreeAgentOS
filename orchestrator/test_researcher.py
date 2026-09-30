from roles.researcher import researcher_node


def run_case(
    name,
    research_type,
    query,
    task,
):
    result = researcher_node(
        {
            "task": task,
            "needs_research": True,
            "research_type": research_type,
            "research_query": query,
            "trace": [],
        }
    )

    print()
    print("CASE=" + name)
    print(
        "TRACE="
        + ",".join(
            result.get(
                "trace",
                [],
            )
        )
    )
    print(
        "SOURCE="
        + str(
            result.get(
                "research_source",
                "",
            )
        )
    )
    print(
        "RESULTS="
        + str(
            result.get(
                "research_results",
                0,
            )
        )
    )

    if result.get("research_error"):
        print(
            "ERROR="
            + result["research_error"]
        )
    else:
        print("PACKET:")
        print(result["research"])


run_case(
    "current-web",
    "current_web",
    "AI coding agents",
    "Find AI coding-agent developments from the last 7 days.",
)

run_case(
    "api-reference",
    "api_reference",
    "cryptocurrency price API",
    "Find a cryptocurrency price API.",
)

run_case(
    "workflow-pattern",
    "workflow_pattern",
    "failed tests retry verification",
    "Improve coding-agent failure recovery.",
)
