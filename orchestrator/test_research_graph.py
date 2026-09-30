from graph import graph


TASK = """
Using current Open-Meteo Forecast API documentation, implement
build_forecast_url in weather_client.py.

Requirements:
- use the official HTTPS Open-Meteo Forecast API endpoint
- include the supplied latitude and longitude
- request the current fields:
  temperature_2m,
  relative_humidity_2m,
  weather_code
- use automatic timezone handling
- do not modify the tests
- make the smallest implementation change necessary
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
        "recursion_limit": 30,
    },
)


print()
print("=== FREEAGENTOS RESEARCH GRAPH RESULT ===")

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
    "RESEARCH_TYPE="
    + result.get(
        "research_type",
        "",
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
    "RESEARCH_RESULTS="
    + str(
        result.get(
            "research_results",
            0,
        )
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
    "CODER_ERROR="
    + result.get(
        "coder_error",
        "",
    )
)

print(
    "FIX_ATTEMPTS="
    + str(
        result.get(
            "fix_attempts",
            0,
        )
    )
)

print(
    "FIXER_ERROR="
    + result.get(
        "fixer_error",
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
print("=== RESEARCH PACKET ===")

research = result.get(
    "research",
    "",
)

print(
    research[:5000]
    if research
    else "(none)"
)

print()
print("=== FINAL DIFF ===")

print(
    result.get(
        "diff",
        "",
    )
)

success = (
    result.get("status") == "VERIFIED"
    and result.get("test_result") == "PASS"
    and result.get("review_verdict") == "PASS"
    and result.get("needs_research") is True
    and result.get("research_source") not in {
        "",
        "none",
    }
)

raise SystemExit(
    0 if success else 1
)
