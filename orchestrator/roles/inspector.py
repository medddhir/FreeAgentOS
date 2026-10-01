"""Bounded, read-only repository facts. No model, network, or code execution."""

import ast
import hashlib
import json
import os
import re
import stat
import sys
import tomllib
from pathlib import PurePosixPath

from roles.integrity import ERRORS, check_baseline, git


MAX_PATHS = 10000
MAX_FILES = 20
MAX_FILE_BYTES = 65536
MAX_TOTAL_BYTES = 262144
MAX_PACKET_CHARS = 12000
MAX_RECORDS = 64
EXCLUDED = {
    ".git", "node_modules", "venv", "virtualenv", "env", "dist", "build",
    "target", "vendor", "__pycache__", "coverage", "htmlcov", ".cache",
    ".pytest_cache", ".mypy_cache", ".next", ".nuxt", "generated",
    "credentials", "secrets", "tokens", "oauth", ".ssh", ".aws",
    ".config", ".codex", ".agents", ".auth", "config", "configs", "settings", "backups",
}
MANIFESTS = {"package.json", "pyproject.toml", "requirements.txt", "Cargo.toml", "go.mod", "composer.json"}
LANGUAGES = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
             ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
             ".rs": "Rust", ".java": "Java", ".php": "PHP", ".rb": "Ruby"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}
SECRET_NAME = re.compile(r"(?:secret|credential|password|token|oauth|private.?key|api.?key|auth.?key|provider.?database)", re.I)
NAME = re.compile(r"@?[A-Za-z][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)*\Z")
OPAQUE = re.compile(r"(?:sk_|ghp_|gho_|eyJ|AKIA|-----BEGIN)|[A-Za-z0-9]{32,}")


def safe_identifier(value):
    return (isinstance(value, str) and len(value) <= 100 and bool(NAME.fullmatch(value))
            and not SECRET_NAME.search(value) and not OPAQUE.search(value))


def safe_path(name):
    if (not isinstance(name, str) or not name or len(name) > 180
            or "\\" in name or any(ord(ch) < 32 or ord(ch) > 126 for ch in name)
            or any(part in ("", ".", "..") for part in name.split("/"))):
        return False
    parts = PurePosixPath(name).parts
    if not parts or PurePosixPath(name).is_absolute() or ".." in parts:
        return False
    for part in parts:
        value = part.lower()
        if (value in EXCLUDED or value.startswith((".env", ".venv", ".tox"))
                or SECRET_NAME.search(value) or OPAQUE.search(value)):
            return False
    return not parts[-1].lower().startswith(("settings.", "config.", "keys.", "ssh_config", "id_rsa", "id_ed25519"))


def _parent_fd(repo, name, root_identity=None, *, create=False):
    """Anchor path operations to a verified root and no-follow directories."""
    if not safe_path(name):
        raise RuntimeError("UNSAFE_INSPECTION_PATH")
    directory = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if root_identity is not None and (info.st_dev, info.st_ino) != tuple(root_identity):
            raise RuntimeError("INSPECTION_ROOT_CHANGED")
        parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, mode=0o755, dir_fd=directory)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def _read(repo, name, root_identity=None):
    """Open every component without following symlinks; never open special files."""
    directory = _parent_fd(repo, name, root_identity)
    try:
        parts = PurePosixPath(name).parts
        before = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("UNSAFE_INSPECTION_FILE")
        if before.st_size > MAX_FILE_BYTES:
            return None
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            if os.fstat(stream.fileno()) != before:
                raise RuntimeError("INSPECTION_FILE_CHANGED")
            content = stream.read(MAX_FILE_BYTES + 1)
            after = os.fstat(stream.fileno())
        if len(content) > MAX_FILE_BYTES or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError("INSPECTION_FILE_CHANGED")
        return content
    finally:
        os.close(directory)


def _version(value):
    if isinstance(value, dict):
        value = value.get("version", "")
    if (isinstance(value, str) and len(value) <= 80
            and re.fullmatch(r"[v0-9*<>=~^!.,+| -]+(?:[a-z][a-z0-9.-]*)?", value)
            and not OPAQUE.search(value)):
        return value
    return ""  # Never return URLs, local paths, environment expressions or auth.


def _requirement(value):
    if not isinstance(value, str) or "://" in value or " @ " in value:
        return None
    match = re.match(r"^\s*([A-Za-z][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*([^;#]*)", value)
    return (match[1], _version(match[2].strip())) if match else None


def _dependencies(name, text):
    base = PurePosixPath(name).name
    values = []
    if base in {"package.json", "composer.json"}:
        data = json.loads(text)
        for key in ("dependencies", "devDependencies", "peerDependencies", "require", "require-dev"):
            section = data.get(key, {})
            if isinstance(section, dict):
                values.extend((key, _version(value)) for key, value in sorted(section.items()))
    elif base in {"pyproject.toml", "Cargo.toml"}:
        data = tomllib.loads(text)
        project = data.get("project", {})
        values.extend(filter(None, (_requirement(v) for v in project.get("dependencies", []))))
        for group in project.get("optional-dependencies", {}).values():
            values.extend(filter(None, (_requirement(v) for v in group)))
        poetry = data.get("tool", {}).get("poetry", {})
        for section in (poetry.get("dependencies", {}), data.get("dependencies", {}), data.get("dev-dependencies", {})):
            if isinstance(section, dict):
                values.extend((key, _version(value)) for key, value in sorted(section.items()))
    elif base == "requirements.txt":
        values.extend(filter(None, (_requirement(line) for line in text.splitlines())))
    elif base == "go.mod":
        values.extend((m[1], _version(m[2])) for m in re.finditer(
            r"(?m)^\s*(?:require\s+)?([\w./-]+)\s+(v[\w.+-]+)\s*$", text))
    return [(key, value) for key, value in values if safe_identifier(key)][:MAX_RECORDS]


def _source_facts(name, text):
    modules, symbols = set(), set()
    if name.endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return [], []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                modules.add(node.module)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbols.add(node.name)
    else:
        modules.update(re.findall(r"(?m)^\s*(?:import|export)\b[^\n;]*?\bfrom\s*['\"]([^'\"]+)['\"]", text))
        modules.update(re.findall(r"(?m)^\s*import\s*['\"]([^'\"]+)['\"]", text))
        modules.update(re.findall(r"(?m)^\s*(?:const|let|var)\s+[^\n=]+=\s*require\(['\"]([^'\"]+)['\"]\)", text))
        symbols.update(re.findall(r"\b(?:function|class)\s+([A-Za-z_][A-Za-z0-9_]*)", text))
    return (sorted(filter(safe_identifier, modules))[:MAX_RECORDS],
            sorted(filter(safe_identifier, symbols))[:MAX_RECORDS])


def inspector_node(state):
    try:
        repo, _ = check_baseline(state)
        raw_paths = git(repo, "ls-files", "-z").split("\0")
        if len(raw_paths) > MAX_PATHS + 1:
            raise RuntimeError("INSPECTION_PATH_BUDGET_EXCEEDED")
        from roles.read_policy import inspector_path_allowed, inspector_read
        paths = sorted({name for name in raw_paths if name and inspector_path_allowed(name)})
        task_words = set(re.findall(r"[a-z]{3,}", state.get("task", "").lower()))
        def rank(name):
            manifest = PurePosixPath(name).name in MANIFESTS
            relevance = sum(word.rstrip("s") in name.lower() for word in task_words)
            return (not manifest, -relevance, name.count("/"), name)
        candidates = sorted((p for p in paths if PurePosixPath(p).name in MANIFESTS
                             or PurePosixPath(p).suffix in SOURCE_SUFFIXES), key=rank)
        facts = {"schema_version": 1, "languages": sorted({LANGUAGES[PurePosixPath(p).suffix]
                  for p in paths if PurePosixPath(p).suffix in LANGUAGES}),
                 "sources": [], "dependencies": [], "imports": [], "symbols": [],
                 "relevant_files": candidates[:12], "test_locations": [],
                 "test_frameworks": [], "truncated": len(candidates) > MAX_FILES}
        local_modules = {PurePosixPath(p).stem for p in paths} | {PurePosixPath(p).parts[0] for p in paths if "/" in p}
        consumed = 0
        for name in candidates[:MAX_FILES]:
            if consumed + MAX_FILE_BYTES > MAX_TOTAL_BYTES:
                facts["truncated"] = True
                break
            content = inspector_read(repo, name, candidates)
            if content is None:
                facts["truncated"] = True
                continue
            consumed += len(content)
            text = content.decode("utf-8")
            facts["sources"].append({"path": name, "sha256": hashlib.sha256(content).hexdigest()})
            if PurePosixPath(name).name in MANIFESTS:
                for dep, version in _dependencies(name, text):
                    facts["dependencies"].append({"name": dep, "version": version, "source": name})
            else:
                modules, symbols = _source_facts(name, text)
                for module in modules:
                    root = module.split(".")[0]
                    external = root not in sys.stdlib_module_names and root not in local_modules
                    facts["imports"].append({"name": module, "source": name, "external": external})
                facts["symbols"].extend({"name": s, "source": name} for s in symbols)
        facts["test_locations"] = [p for p in paths if "tests" in PurePosixPath(p).parts
                                    or PurePosixPath(p).name.startswith("test_")
                                    or ".test." in p or ".spec." in p][:12]
        names = {item["name"] for key in ("dependencies", "imports") for item in facts[key]}
        facts["test_frameworks"] = sorted(names & {"pytest", "unittest", "jest", "vitest", "mocha"})
        for key in ("dependencies", "imports", "symbols"):
            if len(facts[key]) > MAX_RECORDS:
                facts[key] = facts[key][:MAX_RECORDS]
                facts["truncated"] = True
        facts["files_read"] = len(facts["sources"])
        facts["bytes_read"] = consumed
        while len(json.dumps(facts, sort_keys=True)) > MAX_PACKET_CHARS:
            facts["truncated"] = True
            for key in ("symbols", "imports", "dependencies", "relevant_files", "test_locations", "sources"):
                if facts[key]:
                    facts[key].pop()
                    break
        packet = json.dumps(facts, sort_keys=True)
        return {"repo_facts": facts, "repo_facts_text": packet,
                "inspector_error": "", "trace": ["inspector"]}
    except (*ERRORS, ValueError, TypeError, AttributeError, RecursionError):
        # Do not echo file contents or parser exception text into model context.
        return {"repo_facts": {}, "repo_facts_text": "", "inspector_error": "UNSAFE_OR_INVALID_INSPECTION",
                "status": "BLOCKED", "trace": ["inspector:error"]}
