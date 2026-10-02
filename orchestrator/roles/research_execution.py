"""Controller-owned dispatch for resource-bounded research commands."""

import ipaddress
from pathlib import Path
from urllib.parse import urlparse

from roles.worker import WorkerBoundaryError, run_worker


ROOT = Path(__file__).resolve().parents[2]
TOOL_BIN = ROOT / "bin"
JINA_READER = "https://r.jina.ai/"


class ResearchExecutionError(RuntimeError):
    def __init__(self, code, evidence=None):
        super().__init__(code)
        self.evidence = evidence or {"cleanup_status": "UNPROVEN", "remaining_processes": None,
                                     "error": code}


def _query(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4000 or "\0" in value:
        raise ResearchExecutionError("RESEARCH_QUERY_INVALID")
    return value.strip()


def _tool(name):
    from foundation import bundled_tool, bundled_tools_root
    path = bundled_tool(name)
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(bundled_tools_root()):
        raise ResearchExecutionError("RESEARCH_TOOL_IDENTITY_INVALID")
    return str(path)


def _public_https_url(value):
    if not isinstance(value, str) or len(value) > 4000 or any(ord(ch) < 32 for ch in value):
        raise ResearchExecutionError("RESEARCH_URL_INVALID")
    try:
        parsed = urlparse(value)
    except ValueError as exc:
        raise ResearchExecutionError("RESEARCH_URL_INVALID") from exc
    host = parsed.hostname or ""
    if parsed.scheme != "https" or not host or not parsed.netloc or parsed.username or parsed.password:
        raise ResearchExecutionError("RESEARCH_URL_INVALID")
    if host.lower() == "localhost" or host.lower().endswith(".localhost") or "." not in host:
        raise ResearchExecutionError("RESEARCH_URL_INVALID")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ResearchExecutionError("RESEARCH_URL_INVALID")
    return value


def run_research_action(action, *, query=None, days=None, url=None):
    """Only these four structured actions may use network-enabled research scope."""
    if action == "exa":
        command = [_tool("exa-intel"), _query(query), "--limit", "3", "--json"]
        if days is not None:
            if type(days) is not int or not 1 <= days <= 365:
                raise ResearchExecutionError("RESEARCH_DAYS_INVALID")
            command += ["--days", str(days)]
        timeout = 50
    elif action == "dev_api":
        command = [_tool("dev-intel"), "api", _query(query), "--limit", "3", "--json"]
        timeout = 30
    elif action == "prompt":
        command = [_tool("prompt-intel"), _query(query), "--limit", "3", "--json"]
        timeout = 30
    elif action == "jina":
        command = ["/usr/bin/curl", "--proto", "=https", "--tlsv1.2", "-fsSL",
                   "--max-time", "35", JINA_READER + _public_https_url(url)]
        timeout = 40
    else:
        raise ResearchExecutionError("RESEARCH_ACTION_DENIED")
    if action != "jina" and (url is not None or (days is not None and action != "exa")):
        raise ResearchExecutionError("RESEARCH_ACTION_ARGUMENT_INVALID")
    if action == "jina" and (query is not None or days is not None):
        raise ResearchExecutionError("RESEARCH_ACTION_ARGUMENT_INVALID")
    try:
        return run_worker(command, cwd=ROOT, timeout=timeout, role="research:" + action,
                          policy_profile="research")
    except WorkerBoundaryError as exc:
        raise ResearchExecutionError("RESEARCH_EXECUTION_BOUNDARY:" + str(exc), exc.evidence) from exc


def run_research_command(command):
    """Validate legacy Researcher argument shapes before structured dispatch."""
    if not isinstance(command, list):
        raise ResearchExecutionError("RESEARCH_ACTION_DENIED")
    if len(command) == 6 and command[:2] == ["dev-intel", "api"] \
            and command[3:] == ["--limit", "3", "--json"]:
        return run_research_action("dev_api", query=command[2])
    if len(command) == 5 and command[0] == "prompt-intel" \
            and command[2:] == ["--limit", "3", "--json"]:
        return run_research_action("prompt", query=command[1])
    if len(command) in (5, 7) and command[0] == "exa-intel" \
            and command[2:5] == ["--limit", "3", "--json"]:
        if len(command) == 5:
            return run_research_action("exa", query=command[1])
        if command[5] == "--days" and str(command[6]).isdigit():
            return run_research_action("exa", query=command[1], days=int(command[6]))
    raise ResearchExecutionError("RESEARCH_ACTION_DENIED")
