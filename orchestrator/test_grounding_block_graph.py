from graph import graph


TASK = """
Using current Open-Meteo Forecast API documentation,
modify weather_client.py to use the quantum_weather_mode
parameter.

Requirements:
- use the official HTTPS Open-Meteo Forecast API endpoint
- include temperature_2m
- use the documented quantum_weather_mode parameter
- do not modify the tests
""".strip()


result = graph.invoke(
    {
        "task": TASK,
        "repo_dir": (
            "/root/agent-stack/research-workspace"
        ),
        "fix_attempts": 0,
        "trace": [],
    },
    config={
        "recursion_limit": 20,
    },
)


trace = result.get(
    "trace",
    [],
)


print()
print(
    "=== FULL GRAPH GROUNDING BLOCK TEST ==="
)

print(
    "TRACE="
    + " -> ".join(trace)
)

print(
    "STATUS="
    + result.get(
        "status",
        "",
    )
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
    "RESEARCH_TYPE="
    + result.get(
        "research_type",
        "",
    )
)

print(
    "RESEARCH_ERROR="
    + result.get(
        "research_error",
        "",
    )
)

print(
    "CODER_REACHED="
    + str(
        "coder" in trace
    )
)

print(
    "TESTER_REACHED="
    + str(
        "tester" in trace
    )
)

print(
    "PACKET_PRESENT="
    + str(
        bool(
            result.get(
                "research",
                "",
            )
        )
    )
)


success = (
    result.get("status") == "BLOCKED"
    and result.get("needs_research") is True
    and result.get("research_type") == "api_reference"
    and bool(
        result.get(
            "research_error",
            "",
        )
    )
    and "coder" not in trace
    and "tester" not in trace
    and not result.get(
        "research",
        "",
    )
)


print(
    "GRAPH_GROUNDING_GATE="
    + (
        "PASS"
        if success
        else "FAIL"
    )
)


raise SystemExit(
    0 if success else 1
)
