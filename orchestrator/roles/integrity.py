"""Deterministic integrity evidence and selective rollback of forbidden paths.

The caller owns policy fields. Model output cannot grant permission. A baseline
is required for rollback; pre-existing dirty files are never restored from HEAD.
"""

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

from state import AgentState
from roles.controller_git import run_git


ERRORS = (OSError, RuntimeError, subprocess.TimeoutExpired)


def policy_summary(state):
    return json.dumps({key: state.get(key) is True for key in (
        "allow_new_files", "allow_deletes", "allow_test_changes",
        "allow_verification_changes",
    )}, sort_keys=True)


def is_verification_file(name):
    path = Path(name.lower())
    return (path.name in {
        "agents.md", "claude.md", "freeagent-test", "freeagent-run", "freeagent-code",
        "package.json", "pyproject.toml", "pytest.ini", "tox.ini", "setup.cfg", "conftest.py",
    } or bool(set(path.parts) & {"orchestrator", ".agents", ".codex"})
        or name.lower().startswith(".github/workflows/"))


def git(repo, *args):
    # -- alone does not disable Git pathspec magic such as :(glob) or '*'.
    result = run_git(["--literal-pathspecs", *args], cwd=repo, timeout=30)
    if result.returncode:
        raise RuntimeError("GIT_COMMAND_FAILED:" + args[0])
    return result.stdout.decode("utf-8", "surrogateescape")


def repository(repo):
    if not repo:
        raise RuntimeError("MISSING_REPO_DIR")
    path = Path(repo).resolve(strict=True)
    root = Path(git(path, "rev-parse", "--show-toplevel").strip()).resolve()
    if path != root:
        raise RuntimeError("REPO_DIR_NOT_GIT_ROOT")
    return path, git(path, "rev-parse", "HEAD").strip()


def check_baseline(state):
    repo, head = repository(state.get("repo_dir", ""))
    base = state.get("integrity_baseline")
    if base is not None and (base.get("repo") != str(repo) or base.get("head") != head):
        raise RuntimeError("BASELINE_CHANGED")
    return repo, head


def head_entries(repo):
    entries = {}
    for item in git(repo, "ls-tree", "-r", "-z", "HEAD").split("\0"):
        if item:
            meta, name = item.split("\t", 1)
            mode, kind, oid = meta.split()
            entries[name] = {"mode": mode, "kind": kind, "oid": oid}
    return entries


def _others(repo, ignored=False):
    args = ["ls-files", "--others", "--exclude-standard", "-z"]
    if ignored:
        args.append("--ignored")
    return set(filter(None, git(repo, *args).split("\0")))


def changes(repo, baseline=None):
    changed, deleted = set(), set()
    # Include index-only edits even when the worktree has been put back to HEAD.
    for comparison in (("HEAD",), ("--cached", "HEAD"), ()):
        parts = git(
            repo, "diff", "--no-ext-diff", "--no-textconv",
            "--name-status", "--no-renames", "-z", *comparison,
        ).split("\0")
        for index in range(0, len(parts) - 1, 2):
            kind, path = parts[index:index + 2]
            if path:
                changed.add(path)
                if kind == "D":
                    deleted.add(path)
    untracked = _others(repo)
    if baseline is not None:
        # Newly ignored files are still new files. Existing ignored build/cache
        # content is recorded by name only and is never eligible for cleanup.
        untracked |= _others(repo, ignored=True) - set(baseline["existing"])
    changed |= untracked
    new = changed - set(head_entries(repo))
    return {
        "changed": sorted(changed), "untracked": sorted(untracked),
        "deleted": sorted(deleted), "new": sorted(new),
    }


def baseline_node(state: AgentState):
    try:
        repo, head = repository(state.get("repo_dir", ""))
        current = changes(repo)
        existing = set(head_entries(repo)) | _others(repo) | _others(repo, ignored=True)
        return {"integrity_baseline": {
            "repo": str(repo), "head": head,
            "dirty": sorted(set(current["changed"]) | set(state.get("workspace_preexisting_dirty", []))),
            "existing": sorted(existing),
        }, "trace": ["baseline"]}
    except ERRORS as exc:
        return {"status": "BLOCKED", "rollback_error": str(exc),
                "trace": ["baseline:error"]}


def _safe_path(repo, name):
    if (not name or name.startswith("/")
            or any(p in ("", ".", "..", ".git") for p in name.split("/"))):
        raise RuntimeError("UNSAFE_PATH:" + name)
    path = repo
    for component in name.split("/")[:-1]:
        path = path / component
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise RuntimeError("UNSAFE_PARENT:" + name)
    return repo / name


def fingerprint(repo, name):
    """Evidence binds a decision to the exact worktree file and index entry."""
    path = _safe_path(repo, name)
    result = {"index": git(repo, "ls-files", "--stage", "-z", "--", name)}
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {**result, "kind": "missing"}
    if not stat.S_ISREG(before.st_mode):
        return {**result, "kind": "nonregular", "mode": before.st_mode}
    digest = hashlib.sha256()
    with open(path, "rb", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW)) as stream:
        if os.fstat(stream.fileno()) != before:
            raise RuntimeError("PATH_CHANGED_DURING_INSPECTION:" + name)
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size, after.st_mtime_ns, after.st_ino):
        raise RuntimeError("PATH_CHANGED_DURING_INSPECTION:" + name)
    return {**result, "kind": "regular", "sha256": digest.hexdigest(),
            "mode": before.st_mode, "inode": before.st_ino,
            "device": before.st_dev, "mtime_ns": before.st_mtime_ns}


def rollback_node(state: AgentState):
    evidence = {"restored": [], "removed": [], "verified": False, "actions": []}
    try:
        repo, head = check_baseline(state)
        base = state.get("integrity_baseline")
        if not base:
            raise RuntimeError("BASELINE_MISSING")
        violations = state.get("integrity_violations") or {}
        targets = sorted(set(violations.get("all", [])))
        if not targets:
            raise RuntimeError("NO_IDENTIFIED_VIOLATIONS")
        entries = head_entries(repo)
        dirty, existing = set(base["dirty"]), set(base["existing"])
        observations = violations.get("evidence", {})
        # Preflight every target before the first mutation.
        for name in targets:
            current = fingerprint(repo, name)
            if current != observations.get(name):
                raise RuntimeError("ROLLBACK_EVIDENCE_CHANGED:" + name)
            if name in entries:
                if name in dirty:
                    raise RuntimeError("PREEXISTING_CHANGE:" + name)
                if entries[name]["mode"] not in ("100644", "100755"):
                    raise RuntimeError("UNSUPPORTED_TRACKED_TYPE:" + name)
                action = "restore"
            else:
                if name in existing:
                    raise RuntimeError("PREEXISTING_FILE:" + name)
                action = "remove"
            if current["kind"] not in ("missing", "regular"):
                raise RuntimeError("UNSAFE_TARGET_TYPE:" + name)
            evidence["actions"].append({"path": name, "action": action, "before": current})
        for action in evidence["actions"]:
            name = action["path"]
            if fingerprint(repo, name) != action["before"]:
                raise RuntimeError("ROLLBACK_EVIDENCE_CHANGED:" + name)
            if action["action"] == "restore":
                git(repo, "restore", "--source=" + head, "--staged", "--worktree", "--", name)
                evidence["restored"].append(name)
            else:
                # A staged addition is still a new file; remove only its index
                # entry, then unlink exactly that file if it exists.
                git(repo, "update-index", "--force-remove", "--", name)
                if action["before"]["kind"] != "missing":
                    os.unlink(_safe_path(repo, name))
                evidence["removed"].append(name)
        after = changes(repo, base)
        if set(targets) & set(after["changed"]):
            raise RuntimeError("ROLLBACK_POSTCHECK_FAILED")
        evidence["verified"] = True
        return {"rollback_evidence": evidence, "rollback_history": [evidence],
                "rollback_error": "", "trace": ["rollback"]}
    except ERRORS as exc:
        evidence["error"] = str(exc)
        return {"rollback_evidence": evidence, "rollback_history": [evidence],
                "rollback_error": str(exc), "status": "BLOCKED",
                "trace": ["rollback:error"]}
