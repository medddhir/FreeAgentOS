import json
import re
from contextvars import ContextVar
from typing import Any
from urllib.parse import urlparse

from state import AgentState
from roles.research_execution import (ResearchExecutionError, run_research_action,
                                      run_research_command)
from roles.workspace import verify_execution_contract


RESULT_LIMIT = 3
MAX_PACKET_CHARS = 6500
MAX_DOC_CHARS = 120000
DOC_SNIPPET_LIMIT = 14
_execution_log = ContextVar("research_execution_log", default=None)


def _bounded_call(action, call):
    log = _execution_log.get()
    try:
        result = call()
    except ResearchExecutionError as exc:
        if log is not None:
            log.append({"action": action, "status": "BLOCKED", "evidence": exc.evidence})
        raise
    if log is not None:
        failed = (result.returncode != 0 or result.evidence.get("output_truncated")
                  or result.evidence.get("timeout_triggered")
                  or any(result.evidence.get("resource_hits", {}).values()))
        log.append({"action": action, "status": "BLOCKED" if failed else "COMPLETE",
                    "exit_code": result.returncode,
                    "evidence": result.evidence})
    if result.evidence.get("output_truncated"):
        raise ResearchExecutionError("RESEARCH_OUTPUT_TRUNCATED", result.evidence)
    if result.evidence.get("timeout_triggered"):
        raise ResearchExecutionError("RESEARCH_TIMEOUT", result.evidence)
    if any(result.evidence.get("resource_hits", {}).values()):
        raise ResearchExecutionError("RESEARCH_RESOURCE_LIMIT", result.evidence)
    if result.returncode != 0:
        if action == "jina" and result.returncode == 22:
            raise RuntimeError("JINA_DOCUMENT_NOT_FOUND")
        raise ResearchExecutionError("RESEARCH_TOOL_EXIT_" + str(result.returncode), result.evidence)
    return result


def _run_json(cmd: list[str]) -> dict[str, Any]:
    result = _bounded_call(cmd[0] if cmd else "invalid",
                           lambda: run_research_command(cmd))

    try:
        payload = json.loads(
            result.stdout
        )
    except json.JSONDecodeError as exc:
        log = _execution_log.get()
        if log:
            log[-1]["status"] = "INVALID_OUTPUT"
        raise ResearchExecutionError("RESEARCH_INVALID_JSON", result.evidence) from exc

    if not isinstance(payload, dict):
        log = _execution_log.get()
        if log:
            log[-1]["status"] = "INVALID_OUTPUT"
        raise ResearchExecutionError("RESEARCH_INVALID_PAYLOAD", result.evidence)

    return payload


def _extract_days(text: str) -> int | None:
    patterns = (
        r"\blast\s+(\d{1,3})\s+days?\b",
        r"\bpast\s+(\d{1,3})\s+days?\b",
        r"\bwithin\s+(\d{1,3})\s+days?\b",
    )

    lowered = text.lower()

    for pattern in patterns:
        match = re.search(
            pattern,
            lowered,
        )

        if match:
            value = int(
                match.group(1)
            )

            return max(
                1,
                min(value, 365),
            )

    return None


def _domain(url: str) -> str:
    try:
        host = (
            urlparse(url)
            .hostname
            or ""
        ).lower()
    except Exception:
        return ""

    if host.startswith("www."):
        host = host[4:]

    return host


def _same_domain(
    left: str,
    right: str,
) -> bool:
    a = _domain(left)
    b = _domain(right)

    if not a or not b:
        return False

    return (
        a == b
        or a.endswith("." + b)
        or b.endswith("." + a)
    )


def _fetch_jina(
    url: str,
) -> str:
    result = _bounded_call("jina", lambda: run_research_action("jina", url=url))

    text = result.stdout or ""

    if not text.strip():
        raise RuntimeError(
            "Jina returned an empty document."
        )

    return text[:MAX_DOC_CHARS]


def _discover_official_docs(
    api_name: str,
    official_url: str,
    query: str,
) -> dict[str, str] | None:
    search_query = (
        f"official {api_name} API documentation "
        f"{query}"
    )

    payload = _run_json(
        [
            "exa-intel",
            search_query,
            "--limit",
            "3",
            "--json",
        ]
    )

    results = payload.get(
        "results",
        [],
    )

    if not isinstance(
        results,
        list,
    ):
        return None

    for item in results:
        if not isinstance(
            item,
            dict,
        ):
            continue

        url = str(
            item.get(
                "url",
                "",
            )
        ).strip()

        if not url:
            continue

        # Critical provenance rule:
        # docs evidence must come from the same
        # official domain discovered by dev-intel.
        if _same_domain(
            url,
            official_url,
        ):
            return {
                "title": str(
                    item.get(
                        "title",
                        "",
                    )
                ).strip(),
                "url": url,
            }

    return None


def _evidence_terms(
    query: str,
    api_name: str,
) -> list[str]:
    raw = re.findall(
        r"[A-Za-z0-9_./:-]+",
        query + " " + api_name,
    )

    stop = {
        "official",
        "documentation",
        "docs",
        "https",
        "http",
        "api",
        "apis",
        "using",
        "with",
        "from",
        "into",
        "latest",
        "current",
        "support",
        "implement",
        "implementation",
        "version",
        "correct",
    }

    terms = []

    for value in raw:
        value = value.lower().strip()

        if not value:
            continue

        if value in stop:
            continue

        if (
            len(value) < 4
            and value != "auto"
        ):
            continue

        if value not in terms:
            terms.append(value)

    # Useful API-document signals. These do not
    # assert facts; they only help rank source lines.
    for value in (
        "endpoint",
        "current",
        "timezone",
        "auto",
    ):
        if value not in terms:
            terms.append(value)

    return terms


def _extract_doc_evidence(
    text: str,
    query: str,
    api_name: str,
    doc_url: str,
) -> list[str]:
    lines = text.splitlines()

    terms = _evidence_terms(
        query,
        api_name,
    )

    # Technical identifiers from the user's actual
    # research query deserve much higher priority than
    # generic documentation/navigation text.
    technical_terms = [
        term
        for term in terms
        if (
            "_" in term
            or "/" in term
            or any(
                ch.isdigit()
                for ch in term
            )
        )
    ]

    candidates = []

    for number, raw in enumerate(
        lines,
        1,
    ):
        line = re.sub(
            r"\s+",
            " ",
            raw,
        ).strip()

        if not line:
            continue

        lowered = line.lower()

        hits = [
            term
            for term in terms
            if term in lowered
        ]

        endpoint_hit = bool(
            re.search(
                r"https?://[^ )]+/v\d+(?:/|\\b)",
                lowered,
            )
            or re.search(
                r"/v\d+(?:/|\\b)",
                lowered,
            )
        )

        current_param_hit = bool(
            re.search(
                r"\|\s*current\s*\|",
                lowered,
            )
            or "current=" in lowered
            or "current weather" in lowered
        )

        timezone_auto_hit = (
            "timezone" in lowered
            and "auto" in lowered
        )

        score = 0

        if endpoint_hit:
            score += 20

        if "api url" in lowered:
            score += 10

        if current_param_hit:
            score += 12

        if timezone_auto_hit:
            score += 18

        for term in hits:
            if term in technical_terms:
                score += 14

            elif term in {
                "endpoint",
                "current",
                "timezone",
                "auto",
            }:
                score += 5

            else:
                score += 1

        # Navigation menus can contain the official
        # domain many times without containing useful
        # implementation evidence.
        if (
            line.startswith("* [")
            or line.startswith("- [")
        ):
            score -= 10

        if score <= 0:
            continue

        candidates.append(
            {
                "score": score,
                "number": number,
                "line": line[:700],
                "hits": set(hits),
                "endpoint": endpoint_hit,
                "current_param": current_param_hit,
                "timezone_auto": timezone_auto_hit,
            }
        )

    selected = []
    used = set()

    def add_best(predicate):
        matches = [
            item
            for item in candidates
            if (
                item["number"] not in used
                and predicate(item)
            )
        ]

        if not matches:
            return

        best = max(
            matches,
            key=lambda item: (
                item["score"],
                -item["number"],
            ),
        )

        used.add(
            best["number"]
        )

        selected.append(
            best
        )

    # First guarantee coverage of implementation-
    # critical evidence classes.
    add_best(
        lambda item:
        item["endpoint"]
    )

    for term in technical_terms:
        add_best(
            lambda item, term=term:
            term in item["hits"]
        )

    add_best(
        lambda item:
        item["current_param"]
    )

    add_best(
        lambda item:
        item["timezone_auto"]
    )

    # Then cover important semantic parameters if
    # they were not already captured.
    for term in (
        "current",
        "timezone",
        "auto",
        "endpoint",
    ):
        add_best(
            lambda item, term=term:
            term in item["hits"]
        )

    # Fill remaining packet capacity with the
    # strongest unused evidence.
    remaining = sorted(
        (
            item
            for item in candidates
            if item["number"] not in used
        ),
        key=lambda item: (
            -item["score"],
            item["number"],
        ),
    )

    for item in remaining:
        if len(selected) >= DOC_SNIPPET_LIMIT:
            break

        selected.append(item)
        used.add(
            item["number"]
        )

    # Return snippets in original document order so
    # the evidence packet remains readable.
    selected.sort(
        key=lambda item:
        item["number"]
    )

    return [
        f"L{item['number']}: {item['line']}"
        for item in selected[
            :DOC_SNIPPET_LIMIT
        ]
    ]


def _research_current_web(
    query: str,
    task: str,
) -> tuple[
    str,
    list[dict[str, Any]],
]:
    cmd = [
        "exa-intel",
        query,
        "--limit",
        str(RESULT_LIMIT),
        "--json",
    ]

    days = _extract_days(
        task + " " + query
    )

    if days is not None:
        cmd.extend(
            [
                "--days",
                str(days),
            ]
        )

    payload = _run_json(cmd)

    results = payload.get(
        "results",
        [],
    )

    if not isinstance(
        results,
        list,
    ):
        raise RuntimeError(
            "exa-intel results were invalid."
        )

    normalized = []

    for item in results[:RESULT_LIMIT]:
        if not isinstance(
            item,
            dict,
        ):
            continue

        normalized.append(
            {
                "title": str(
                    item.get(
                        "title",
                        "",
                    )
                ).strip(),
                "url": str(
                    item.get(
                        "url",
                        "",
                    )
                ).strip(),
                "published": str(
                    item.get(
                        "published",
                        "",
                    )
                ).strip(),
                "author": str(
                    item.get(
                        "author",
                        "",
                    )
                ).strip(),
                "summary": str(
                    item.get(
                        "highlight",
                        "",
                    )
                ).strip(),
            }
        )

    return (
        "exa-intel",
        normalized,
    )


def _required_grounding_terms(
    query: str,
) -> dict[str, object]:
    lowered = query.lower()

    raw = re.findall(
        r"[A-Za-z0-9_./:-]+",
        query,
    )

    exact = []

    for value in raw:
        term = value.lower().strip()

        # Technical identifiers are strong enough
        # to require literal documentation evidence.
        if (
            "_" in term
            or "/" in term
        ):
            if term not in exact:
                exact.append(term)

    semantic = []

    for term in (
        "current",
        "timezone",
        "auto",
    ):
        if (
            term in lowered
            and term not in semantic
        ):
            semantic.append(term)

    return {
        "exact": exact,
        "semantic": semantic,
        "require_endpoint": (
            "endpoint" in lowered
        ),
        "require_https": (
            "https" in lowered
        ),
    }


def _check_grounding_coverage(
    evidence: list[str],
    query: str,
    doc_url: str,
    provider_https: bool,
) -> dict[str, object]:
    requirements = (
        _required_grounding_terms(
            query
        )
    )

    joined = "\n".join(
        evidence
    ).lower()

    missing = []
    covered = []

    for term in requirements["exact"]:
        if term in joined:
            covered.append(term)
        else:
            missing.append(term)

    for term in requirements["semantic"]:
        if term in joined:
            covered.append(term)
        else:
            missing.append(term)

    if requirements["require_endpoint"]:
        endpoint_found = bool(
            re.search(
                r"https?://[^\\s)]+",
                joined,
            )
            or "api endpoint" in joined
            or re.search(
                r"/v\\d+(?:/|\\b)",
                joined,
            )
        )

        if endpoint_found:
            covered.append(
                "endpoint"
            )
        else:
            missing.append(
                "endpoint"
            )

    if requirements["require_https"]:
        https_found = (
            provider_https
            and (
                "https://" in joined
                or doc_url.lower().startswith(
                    "https://"
                )
            )
        )

        if https_found:
            covered.append(
                "https"
            )
        else:
            missing.append(
                "https"
            )

    return {
        "passed": not missing,
        "covered": sorted(
            set(covered)
        ),
        "missing": sorted(
            set(missing)
        ),
    }


def _research_api(
    query: str,
    expected_entities: list[str] | None = None,
) -> tuple[
    str,
    list[dict[str, Any]],
]:
    payload = _run_json(
        [
            "dev-intel",
            "api",
            query,
            "--limit",
            str(RESULT_LIMIT),
            "--json",
        ]
    )

    results = payload.get(
        "apis",
        [],
    )

    if not isinstance(
        results,
        list,
    ):
        raise RuntimeError(
            "dev-intel API results were invalid."
        )

    normalized = []

    for item in results[:RESULT_LIMIT]:
        if not isinstance(
            item,
            dict,
        ):
            continue

        normalized.append(
            {
                "name": str(
                    item.get(
                        "name",
                        "",
                    )
                ).strip(),
                "category": str(
                    item.get(
                        "category",
                        "",
                    )
                ).strip(),
                "description": str(
                    item.get(
                        "description",
                        "",
                    )
                ).strip(),
                "auth": str(
                    item.get(
                        "auth",
                        "",
                    )
                ).strip(),
                "https": bool(
                    item.get(
                        "https",
                        False,
                    )
                ),
                "url": str(
                    item.get(
                        "url",
                        "",
                    )
                ).strip(),
            }
        )

    if not normalized:
        raise RuntimeError(
            "No API reference results found."
        )

    primary = normalized[0]

    api_name = primary[
        "name"
    ]

    official_url = primary[
        "url"
    ]

    if expected_entities:
        compact = lambda value: re.sub(r"[^a-z0-9]", "", value.lower())
        domain_parts = _domain(official_url).split(".")
        provider_names = {compact(api_name)}
        if len(domain_parts) >= 2:
            # A TLD or generic API subdomain is not a provider identity.
            provider_names.add(compact(domain_parts[-2]))
        if not any(compact(entity) in provider_names for entity in expected_entities):
            raise RuntimeError("API provider did not match validated task/repository identity.")

    if not (
        api_name
        and official_url
    ):
        raise RuntimeError(
            "Primary API result lacks "
            "provider identity or URL."
        )

    discovered = (
        _discover_official_docs(
            api_name,
            official_url,
            query,
        )
    )

    doc_candidates = []

    if discovered:
        doc_candidates.append(
            discovered
        )

    # Safe fallback: the dev-intel URL is itself
    # known to belong to the selected provider.
    doc_candidates.append(
        {
            "title": (
                f"{api_name} official reference"
            ),
            "url": official_url,
        }
    )

    evidence_record = None
    last_error = None

    seen_urls = set()

    for candidate in doc_candidates:
        doc_url = candidate[
            "url"
        ]

        if doc_url in seen_urls:
            continue

        seen_urls.add(doc_url)

        try:
            page = _fetch_jina(
                doc_url
            )

            evidence = (
                _extract_doc_evidence(
                    page,
                    query,
                    api_name,
                    doc_url,
                )
            )

            if not evidence:
                continue

            coverage = (
                _check_grounding_coverage(
                    evidence,
                    query,
                    doc_url,
                    bool(
                        primary.get(
                            "https",
                            False,
                        )
                    ),
                )
            )

            if not coverage["passed"]:
                last_error = (
                    "Official documentation did not "
                    "cover all requested technical "
                    "requirements. Missing: "
                    + ",".join(
                        coverage["missing"]
                    )
                )
                continue

            evidence_record = {
                "title": candidate[
                    "title"
                ],
                "url": doc_url,
                "official_domain": _domain(
                    official_url
                ),
                "evidence": evidence,
                "grounding_coverage": coverage,
            }

            break

        except ResearchExecutionError:
            raise
        except Exception as exc:
            last_error = str(exc)

    if evidence_record is None:
        message = (
            "Could not ground API reference "
            "in exact official documentation."
        )

        if last_error:
            message += (
                " Last error: "
                + last_error
            )

        raise RuntimeError(
            message
        )

    primary[
        "official_docs"
    ] = evidence_record

    primary[
        "docs_grounded"
    ] = True

    return (
        "dev-intel+exa-intel+jina",
        normalized,
    )


def _research_workflow(
    query: str,
) -> tuple[
    str,
    list[dict[str, Any]],
]:
    payload = _run_json(
        [
            "prompt-intel",
            query,
            "--limit",
            str(RESULT_LIMIT),
            "--json",
        ]
    )

    results = payload.get(
        "results",
        [],
    )

    if not isinstance(
        results,
        list,
    ):
        raise RuntimeError(
            "prompt-intel results were invalid."
        )

    normalized = []

    for item in results[:RESULT_LIMIT]:
        if not isinstance(
            item,
            dict,
        ):
            continue

        normalized.append(
            {
                "id": str(
                    item.get(
                        "id",
                        "",
                    )
                ).strip(),
                "title": str(
                    item.get(
                        "title",
                        "",
                    )
                ).strip(),
                "summary": str(
                    item.get(
                        "summary",
                        "",
                    )
                ).strip(),
                "use_when": str(
                    item.get(
                        "use_when",
                        "",
                    )
                ).strip(),
                "sources": item.get(
                    "sources",
                    [],
                ),
            }
        )

    return (
        "prompt-intel",
        normalized,
    )


def _make_packet(
    source: str,
    query: str,
    results: list[dict[str, Any]],
) -> str:
    packet = {
        "source": source,
        "query": query,
        "count": len(results),
        "results": results,
    }

    text = json.dumps(
        packet,
        indent=2,
        ensure_ascii=False,
    )

    if (
        len(text)
        > MAX_PACKET_CHARS
    ):
        text = (
            text[:MAX_PACKET_CHARS]
            + "\n... research packet truncated ..."
        )

    return text


def researcher_node(
    state: AgentState,
) -> AgentState:
    if not state.get(
        "needs_research",
        False,
    ):
        return {
            "research": "",
            "research_source": "none",
            "research_results": 0,
            "research_error": "",
            "trace": [
                "researcher:skipped"
            ],
        }

    research_type = state.get(
        "research_type",
        "none",
    ).strip()

    query = state.get(
        "research_query",
        "",
    ).strip()

    task = state.get(
        "task",
        "",
    ).strip()

    if not query:
        return {
            "research_error": (
                "MISSING_RESEARCH_QUERY"
            ),
            "status": "BLOCKED",
            "trace": [
                "researcher:error"
            ],
            "research_execution_history": [],
            "research_failure_kind": "RESULT",
        }

    execution_log = []
    token = _execution_log.set(execution_log)
    try:
        try:
            verify_execution_contract(state)
        except Exception as exc:
            raise ResearchExecutionError("RESEARCH_CONTRACT_INVALID") from exc
        if (
            research_type
            == "current_web"
        ):
            source, results = (
                _research_current_web(
                    query,
                    task,
                )
            )

        elif (
            research_type
            == "api_reference"
        ):
            source, results = (
                _research_api(
                    query,
                    state.get("research_expected_entities"),
                )
            )

        elif (
            research_type
            == "workflow_pattern"
        ):
            source, results = (
                _research_workflow(
                    query
                )
            )

        else:
            raise RuntimeError(
                "Unsupported research type: "
                + research_type
            )

        packet = _make_packet(
            source,
            query,
            results,
        )

    except ResearchExecutionError as exc:
        return {"research_error": str(exc), "research_failure_kind": "EXECUTION",
                "research_execution_history": execution_log, "status": "BLOCKED",
                "trace": ["researcher:error"]}
    except Exception as exc:
        return {
            "research_error": str(exc),
            "research_failure_kind": "RESULT",
            "research_execution_history": execution_log,
            "status": "BLOCKED",
            "trace": [
                "researcher:error"
            ],
        }
    finally:
        _execution_log.reset(token)

    return {
        "research": packet,
        "research_source": source,
        "research_results": len(
            results
        ),
        "research_error": "",
        "research_failure_kind": "",
        "research_execution_history": execution_log,
        "trace": ["researcher"],
    }
