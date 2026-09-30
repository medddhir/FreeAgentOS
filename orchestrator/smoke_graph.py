from langgraph.graph import StateGraph, START, END

from state import AgentState


def planner(state: AgentState):
    task = state["task"]

    research_words = (
        "latest",
        "current",
        "recent",
        "external",
        "api",
    )

    needs_research = any(
        word in task.lower()
        for word in research_words
    )

    return {
        "plan": "Inspect → research if needed → implement → test → review",
        "needs_research": needs_research,
        "trace": ["planner"],
    }


def researcher(state: AgentState):
    return {
        "research": "SMOKE_RESEARCH_COMPLETE",
        "trace": ["researcher"],
    }


def coder(state: AgentState):
    return {
        "implementation": "SMOKE_IMPLEMENTATION_COMPLETE",
        "trace": ["coder"],
    }


def tester(state: AgentState):
    return {
        "test_result": "PASS",
        "trace": ["tester"],
    }


def reviewer(state: AgentState):
    verified = (
        state.get("test_result") == "PASS"
        and bool(state.get("implementation"))
    )

    return {
        "review": "PASS" if verified else "FAIL",
        "status": "VERIFIED" if verified else "UNVERIFIED",
        "trace": ["reviewer"],
    }


def route_after_planner(state: AgentState):
    if state.get("needs_research"):
        return "researcher"

    return "coder"


builder = StateGraph(AgentState)

builder.add_node("planner", planner)
builder.add_node("researcher", researcher)
builder.add_node("coder", coder)
builder.add_node("tester", tester)
builder.add_node("reviewer", reviewer)

builder.add_edge(
    START,
    "planner",
)

builder.add_conditional_edges(
    "planner",
    route_after_planner,
    {
        "researcher": "researcher",
        "coder": "coder",
    },
)

builder.add_edge(
    "researcher",
    "coder",
)

builder.add_edge(
    "coder",
    "tester",
)

builder.add_edge(
    "tester",
    "reviewer",
)

builder.add_edge(
    "reviewer",
    END,
)

graph = builder.compile()


def run_case(task):
    result = graph.invoke(
        {
            "task": task,
            "trace": [],
        }
    )

    print()
    print("TASK=" + task)
    print("TRACE=" + " -> ".join(result["trace"]))
    print("NEEDS_RESEARCH=" + str(result["needs_research"]))
    print("STATUS=" + result["status"])


if __name__ == "__main__":
    run_case(
        "Fix the failing calculator function."
    )

    run_case(
        "Use the latest API information to implement a feature."
    )
