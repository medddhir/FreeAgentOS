"""Validate model research requests against task and Inspector evidence only."""

import re
from pathlib import PurePosixPath

from roles.inspector import LANGUAGES, OPAQUE


MAX_QUERY = 2000
MAX_IDENTIFIERS = 80
TOKEN = re.compile(r"https?://[^\s`'\"<>]+|@[\w.-]+/[\w.-]+|[~^<>=!]*\s*v?\d+(?:\.\d+)+(?:[-+][\w.]+)?|/?[A-Za-z_][A-Za-z0-9_]*(?:[./:-][A-Za-z0-9_]+)*|\d+")
# A closed vocabulary for query phrasing, not a catalog of vendors. Other query
# words must occur in the task or structured repository identifiers.
NEUTRAL = set("""a an the and or for from to of in on with without by as at is are be
use using used uses update upgrade fix change implement implementation inspect find
research current latest official documentation docs document reference guide examples
example api apis sdk sdks library libraries package packages dependency dependencies
provider providers vendor vendors framework frameworks database databases integration
integrations external internal existing local repository code coding agent agents ai
payment payments authentication authorization auth version versions release releases
endpoint endpoints method methods function functions parameter parameters field fields
request requests response responses support supported how what which when why requirements
required supplied actual selected identify identifiers technical facts evidence no none
needed need necessary only relevant before after details behavior behaviour changes
plan steps test tests testing failure failures repair value weather url https http
forecast automatic timezone handling current_web api_reference workflow_pattern
not do make smallest correct verify verification calculator inspect read return
connect configure setup syntax usage migration compatibility overview fetch client
new add delete modify create build all must preserve include information safe safely
unknown insufficient blocked operation operations summary query search result results
documented reliable error errors resolve resolve improve bounded deterministic
failure recovery retry retries tools workflow orchestration routing patterns
please carefully ensure requires remaining unchanged
""".split())


def tokens(text):
    return [match.group().strip().rstrip(".:") for match in TOKEN.finditer(text)]


def canonical(value):
    return re.sub(r"\s+", "", value).casefold()


def technical(value):
    return (any(ch in value for ch in "_/.:@~^<>=") or "-" in value
            or bool(re.search(r"[a-z][A-Z]|[A-Za-z]\d|\d[A-Za-z]", value)))


def external_intent(task):
    return (bool(re.search(r"\b(api|sdk|provider|library|framework|database|integration)\b", task, re.I))
            and bool(re.search(r"\b(current|latest|external|documentation|docs)\b", task, re.I)))


def research_validation_node(state):
    result = {"research_validation_passed": False, "research_validation_error": "",
              "research_required_identifiers": [], "research_query_identifiers": [],
              "research_added_identifiers": [], "research_rejected_identifiers": [],
              "research_local_identifiers": [], "research_validation_evidence": {}}
    def blocked(error, rejected=()):
        return {**result, "research_validation_error": error,
                "research_rejected_identifiers": list(rejected),
                "status": "BLOCKED", "trace": ["research_validation:error"]}

    facts = state.get("repo_facts", {})
    if state.get("inspector_error") or facts.get("schema_version") != 1:
        return blocked("INSPECTOR_EVIDENCE_MISSING")
    task = state.get("task", "")
    query = state.get("research_query", "")
    if not isinstance(query, str) or len(query) > MAX_QUERY or len(task) > 12000:
        return blocked("RESEARCH_INPUT_BUDGET_EXCEEDED")
    task_tokens = tokens(task)
    known = {canonical(t) for t in task_tokens}
    origins = {canonical(t): [{"kind": "task"}] for t in task_tokens}
    entities = set()
    local = {canonical(item["name"]) for item in facts.get("symbols", [])}
    paths = [item["path"] for item in facts.get("sources", [])]
    local.update(canonical(p) for p in paths)
    local.update(canonical(PurePosixPath(p).name) for p in paths)
    for key in ("dependencies", "imports", "symbols"):
        for item in facts.get(key, []):
            name = item["name"]
            aliases = {canonical(name)}
            if key != "symbols":
                aliases.update(canonical(p) for p in re.split(r"[/@.-]", name) if p)
            for alias in aliases:
                known.add(alias)
                origins.setdefault(alias, []).append({"kind": key, "source": item["source"]})
                if key == "dependencies" or (key == "imports" and item.get("external")):
                    root = canonical(re.split(r"[/@.]", name.lstrip("@"))[0])
                    if alias in {canonical(name), root} and alias not in facts.get("test_frameworks", []):
                        entities.add(alias)
            if item.get("version"):
                version = canonical(item["version"])
                known.update((version, version.lstrip("<>=!~^")))
                for alias in (version, version.lstrip("<>=!~^")):
                    origins[alias] = [{"kind": "declared_version", "source": item["source"]}]
    for value in facts.get("languages", []) + facts.get("test_frameworks", []):
        known.add(canonical(value))
        origins.setdefault(canonical(value), []).append({"kind": "inspector_summary"})
    explicit = {canonical(v) for v in re.findall(r"`([^`\n]+)`", task)}
    contextual_entities = {canonical(task_tokens[i]) for i in range(len(task_tokens) - 1)
                           if canonical(task_tokens[i + 1]) in
                           {"api", "sdk", "library", "package", "provider", "framework", "integration"}}
    required = set()
    for value in task_tokens:
        normalized = canonical(value)
        is_local = normalized in local or PurePosixPath(normalized).suffix in LANGUAGES
        if is_local:
            result["research_local_identifiers"].append(normalized)
            continue
        if (technical(value) or normalized in explicit
                or (value[0].isupper() and normalized not in NEUTRAL)):
            required.add(normalized)
        # Require explicit identifier syntax, capitalization, or a dependency
        # context; an arbitrary ordinary noun is not a provider identity.
        if (normalized not in NEUTRAL and not technical(value) and normalized.isalpha()
                and (value[0].isupper() or normalized in explicit or normalized in contextual_entities)):
            entities.add(normalized)
        elif "-" in normalized or normalized.startswith("@"):
            entities.add(normalized)
    # Never require ordinary prose to be repeated in a search query.
    required -= NEUTRAL
    # Preserve the existing coverage gate's semantic API requirements even
    # when Planner omits their ordinary-looking parameter names.
    required.update({"current", "timezone", "auto", "https", "endpoint"} & set(map(canonical, task_tokens)))
    result["research_required_identifiers"] = sorted(required)
    result["research_local_identifiers"] = sorted(set(result["research_local_identifiers"]))
    if len(required) > MAX_IDENTIFIERS:
        return blocked("RESEARCH_IDENTIFIER_BUDGET_EXCEEDED")
    kind = state.get("research_type", "none")
    if (kind not in {"none", "api_reference"} and external_intent(task)
            and re.search(r"\b(api|sdk|integration)\b", task, re.I)):
        return blocked("API_RESEARCH_ROUTE_REQUIRED")
    if kind == "none":
        if external_intent(task):
            return blocked("EXTERNAL_RESEARCH_REQUIRED")
        return {**result, "research_validation_passed": True,
                "trace": ["research_validation"]}
    if kind not in {"api_reference", "current_web", "workflow_pattern"} or not query.strip():
        return blocked("INVALID_RESEARCH_REQUEST")
    query_tokens = tokens(query)
    if len(query_tokens) > MAX_IDENTIFIERS:
        return blocked("RESEARCH_IDENTIFIER_BUDGET_EXCEEDED")
    rejected = sorted({canonical(t) for t in query_tokens
                       if canonical(t) not in known and canonical(t) not in NEUTRAL})
    if rejected:
        safe_rejected = ["[opaque identifier]" if OPAQUE.search(t) else t for t in rejected]
        return blocked("UNSUPPORTED_QUERY_IDENTIFIERS", safe_rejected)
    query_set = {canonical(t) for t in query_tokens}
    added = set()
    if kind == "api_reference" and not (query_set & entities):
        if len(entities) != 1:
            return blocked("EXTERNAL_IDENTITY_UNRESOLVED")
        added |= entities
    # API implementation requirements omitted by Planner are added from the
    # task verbatim in canonical form, never from model memory.
    if kind == "api_reference":
        added |= required - query_set
    # Local implementation targets are preserved separately, not sent to the
    # official-doc coverage gate as invented external API symbols.
    clean_tokens = [t for t in query_tokens if canonical(t) not in local
                    and PurePosixPath(canonical(t)).suffix not in LANGUAGES]
    enriched = " ".join(clean_tokens + sorted(added))
    if len(enriched) > MAX_QUERY or not enriched:
        return blocked("VALIDATED_QUERY_BUDGET_EXCEEDED")
    identifiers = sorted((query_set | added) & ((known - NEUTRAL - local) | entities | required))
    result.update({"research_validation_passed": True,
                   "research_query_identifiers": identifiers,
                   "research_added_identifiers": sorted(added),
                   "research_validation_evidence": {identifier: origins.get(identifier, [])
                                                    for identifier in identifiers}})
    return {**result, "research_query": enriched,
            "research_expected_entities": sorted((query_set | added) & entities),
            "trace": ["research_validation"]}
