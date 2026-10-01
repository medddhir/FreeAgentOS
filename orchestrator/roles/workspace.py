"""Create controller-owned snapshots, manifests and promotion-only patches."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from contextvars import ContextVar
from pathlib import Path, PurePosixPath

from state import AgentState
from roles.sandbox import RESOURCE_POLICY
from roles.controller_git import run_git
from roles.preflight import REQUIRED as PREFLIGHT_REQUIRED
from roles.worker import WORKER_POLICY, RESEARCH_POLICY


ROOT = Path(__file__).resolve().parents[2]
ACTIVE_RUN_DIR = ContextVar("freeagentos_active_run_dir", default=None)
MAX_FILES = 20000
MAX_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", "venv", "virtualenv", "__pycache__", "dist", "build",
             "target", "coverage", "htmlcov", ".cache", ".pytest_cache", ".mypy_cache",
             ".next", ".nuxt", ".tox", ".docker", ".kube", ".azure"}
SECRET_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".pem", ".key", ".p12", ".pfx",
                   ".jks", ".keystore", ".ppk"}
SECRET_PART = re.compile(r"(?:^|[._-])(secret|credential|password|token|oauth|private.?key|api.?key|auth.?key)(?:$|[._-])", re.I)
OPAQUE = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:sk_live_|sk_test_|gh[pousr]_|xox[baprs]-)[A-Za-z0-9_-]{16,}|\bAKIA[0-9A-Z]{16}\b|FREELLMAPI_API_KEY\s*=|ANTHROPIC_AUTH_TOKEN\s*=", re.I)
TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__)(?:/|$)|(?:^|/)(?:test_[^/]*|[^/]*_test\.[^/]*|[^/]*\.(?:test|spec)\.[^/]*)$", re.I)
VERIFY_CONFIG = {"agents.md", "claude.md", "freeagent-test", "freeagent-run", "freeagent-code",
                 "package.json", "pyproject.toml", "pytest.ini", "tox.ini", "setup.cfg", "conftest.py"}
CONTROLLER_FILES = (
    "bin/freeagent-test", "orchestrator/graph.py", "orchestrator/state.py",
    "orchestrator/roles/coder.py", "orchestrator/roles/fixer.py",
    "orchestrator/roles/tester.py", "orchestrator/roles/integrity.py",
    "orchestrator/roles/workspace.py", "orchestrator/roles/sandbox.py",
    "orchestrator/roles/preflight.py", "orchestrator/roles/worker.py",
    "orchestrator/roles/inspector.py", "orchestrator/roles/research_validator.py",
    "orchestrator/roles/planner.py", "orchestrator/roles/researcher.py",
    "orchestrator/roles/research_execution.py",
    "orchestrator/roles/controller_git.py",
    "orchestrator/cli.py", "bin/freeagent-run", "bin/freeagent-code",
    "orchestrator/roles/reviewer.py",
    "orchestrator/roles/coding_units.py",
    "orchestrator/roles/repair_context.py",
    "orchestrator/roles/read_policy.py",
    "orchestrator/roles/file_tools.py",
    "bin/exa-intel", "bin/dev-intel", "bin/prompt-intel",
)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _process_birth(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def _safe_run_dir(path):
    path = Path(path)
    info = path.lstat()
    return (path.parent == Path(tempfile.gettempdir()).resolve()
            and path.name.startswith("freeagentos-run-")
            and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700
            and shutil.rmtree.avoids_symlink_attacks)


def _owner_marker(control, run_dir):
    marker = {"schema_version": 1, "workspace_id": run_dir.name,
              "controller_root": str(ROOT), "pid": os.getpid(),
              "process_birth": _process_birth(os.getpid())}
    if not marker["process_birth"]:
        raise RuntimeError("WORKSPACE_OWNER_BIRTH_UNAVAILABLE")
    raw = json.dumps(marker, sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(control / "owner.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def cleanup_active_workspace():
    """On interruption, remove only the exact run directory this process created."""
    name = ACTIVE_RUN_DIR.get()
    if not name:
        return "NONE"
    try:
        if not _safe_run_dir(name):
            return "UNPROVEN"
        shutil.rmtree(name)
        return "CONFIRMED"
    except (OSError, ValueError):
        return "UNPROVEN"
    finally:
        ACTIVE_RUN_DIR.set(None)


def recover_stale_workspaces(limit=128):
    """Delete only dead, marker-proven FreeAgentOS run directories; leave others."""
    cleaned = skipped = scanned = 0
    with os.scandir(tempfile.gettempdir()) as entries:
        for entry in entries:
            if not entry.name.startswith("freeagentos-run-"):
                continue
            scanned += 1
            if scanned > limit:
                skipped += 1
                continue
            path = Path(entry.path)
            try:
                if not _safe_run_dir(path):
                    skipped += 1
                    continue
                if {entry.name for entry in path.iterdir()} - {"controller", "workspace"}:
                    skipped += 1
                    continue
                control = path / "controller"
                control_info = control.lstat()
                if (not stat.S_ISDIR(control_info.st_mode) or control_info.st_uid != os.getuid()
                        or stat.S_IMODE(control_info.st_mode) != 0o700
                        or {entry.name for entry in control.iterdir()} != {"owner.json"}):
                    skipped += 1
                    continue
                marker_path = path / "controller" / "owner.json"
                info = marker_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096):
                    skipped += 1
                    continue
                marker = json.loads(marker_path.read_text())
                if (marker.get("schema_version") != 1 or marker.get("workspace_id") != path.name
                        or marker.get("controller_root") != str(ROOT)
                        or type(marker.get("pid")) is not int or marker["pid"] <= 0
                        or not isinstance(marker.get("process_birth"), str)):
                    skipped += 1
                    continue
                current_birth = _process_birth(marker["pid"])
                if current_birth is None and Path(f"/proc/{marker['pid']}").exists():
                    skipped += 1
                    continue
                if current_birth == marker["process_birth"]:
                    skipped += 1
                    continue
                target = path / "workspace"
                if target.exists() and (target.is_symlink() or not target.is_dir() or any(target.iterdir())):
                    # A crashed run can contain unpromoted work; retain it for review.
                    skipped += 1
                    continue
                shutil.rmtree(path)
                cleaned += 1
            except (OSError, ValueError, KeyError, TypeError):
                skipped += 1
    return {"cleaned": cleaned, "skipped": skipped, "scanned": scanned}


def _git(repo, *args, check=True):
    result = run_git(["--literal-pathspecs", *args], cwd=repo, timeout=30)
    if check and result.returncode:
        raise RuntimeError("WORKSPACE_GIT_FAILED:" + args[0])
    return result


def _read_regular(path, max_bytes=MAX_FILE_BYTES):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError("UNSAFE_WORKSPACE_SOURCE")
    if before.st_size > max_bytes:
        raise RuntimeError("WORKSPACE_FILE_BUDGET_EXCEEDED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if os.fstat(stream.fileno()) != before:
            raise RuntimeError("WORKSPACE_SOURCE_CHANGED")
        data = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    if len(data) > max_bytes or (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size, after.st_mtime_ns, after.st_ino):
        raise RuntimeError("WORKSPACE_SOURCE_CHANGED")
    if OPAQUE.search(data):
        raise RuntimeError("SECRET_MATERIAL_DETECTED")
    return data, stat.S_IMODE(before.st_mode) & 0o755


def _excluded(path):
    parts = PurePosixPath(path).parts
    for part in parts:
        lower = part.lower()
        if (lower in SKIP_DIRS or lower.startswith((".venv", ".env", ".hermes"))
                or SECRET_PART.search(lower) or lower in {".ssh", ".aws", ".gnupg", ".auth", "credentials"}
                or lower in {"id_rsa", "id_ed25519", "known_hosts", ".netrc", ".npmrc", ".pypirc"}
                or PurePosixPath(lower).suffix in SECRET_SUFFIXES):
            return True
    if any(parts[index:index + 2] in ((".config", "gh"), (".config", "gcloud"))
           for index in range(max(0, len(parts) - 1))):
        return True
    return False


def _inventory(repo):
    root = Path(repo)
    files, skipped, total = [], 0, 0
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        rel_dir = Path(current).relative_to(root).as_posix()
        dirs[:] = sorted(d for d in dirs if not _excluded((rel_dir + "/" if rel_dir != "." else "") + d)
                         and not (Path(current) / d).is_symlink())
        for name in sorted(names):
            relative = (rel_dir + "/" if rel_dir != "." else "") + name
            if name == ".git" or _excluded(relative):
                skipped += 1
                continue
            path = root / relative
            if path.is_symlink():
                raise RuntimeError("SYMLINK_IN_SOURCE_REPOSITORY")
            data, mode = _read_regular(path)
            total += len(data)
            if len(files) >= MAX_FILES or total > MAX_BYTES:
                raise RuntimeError("WORKSPACE_BUDGET_EXCEEDED")
            files.append((relative, data, mode))
    return files, skipped


def _source_dirty(repo):
    values = _git(repo, "diff", "--name-only", "--no-renames", "-z", "HEAD").stdout
    dirty = set(values.decode("utf-8", "surrogateescape").split("\0"))
    for args in (("ls-files", "--others", "--exclude-standard", "-z"),
                 ("ls-files", "--others", "--ignored", "--exclude-standard", "-z")):
        result = _git(repo, *args, check=False)
        if result.returncode == 0:
            dirty.update(result.stdout.decode("utf-8", "surrogateescape").split("\0"))
    return sorted(name for name in dirty if name and not _excluded(name))


def _controller_hashes():
    result = {}
    for name in CONTROLLER_FILES:
        path = ROOT / name
        if path.is_file() and not path.is_symlink():
            result[name] = _sha(path.read_bytes())
    return result


def _verify_controller(hashes):
    return _controller_hashes() == hashes


def _write_manifest(control, manifest):
    path = control / "verification.json"
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return path, _sha(raw)


def _load_verified_manifest(state):
    run_dir = Path(state.get("run_dir", ""))
    path = run_dir / "controller" / "verification.json"
    raw = path.read_bytes()
    if _sha(raw) != state.get("verification_manifest_sha256"):
        raise RuntimeError("VERIFICATION_MANIFEST_CHANGED")
    data = json.loads(raw)
    if data.get("resource_policy") != RESOURCE_POLICY:
        raise RuntimeError("RESOURCE_POLICY_CHANGED")
    if data.get("host_capability_policy") != list(PREFLIGHT_REQUIRED):
        raise RuntimeError("HOST_CAPABILITY_POLICY_CHANGED")
    if data.get("worker_resource_policy") != WORKER_POLICY:
        raise RuntimeError("WORKER_RESOURCE_POLICY_CHANGED")
    if data.get("research_resource_policy") != RESEARCH_POLICY:
        raise RuntimeError("RESEARCH_RESOURCE_POLICY_CHANGED")
    if state.get("preflight_status") == "PASS":
        preflight_raw, _ = _read_regular(run_dir / "controller" / "preflight.json", max_bytes=65536)
        if _sha(preflight_raw) != state.get("preflight_evidence_sha256"):
            raise RuntimeError("PREFLIGHT_EVIDENCE_CHANGED")
        preflight = json.loads(preflight_raw)
        if preflight.get("status") != "PASS" or preflight.get("required_failures"):
            raise RuntimeError("PREFLIGHT_EVIDENCE_INVALID")
    if not _verify_controller(data["controller_hashes"]):
        raise RuntimeError("CONTROLLER_FILES_CHANGED")
    pointer = Path(state.get("run_workspace", "")) / ".git"
    pointer_data, _ = _read_regular(pointer, max_bytes=4096)
    if _sha(pointer_data) != data.get("workspace_git_pointer_sha256"):
        raise RuntimeError("WORKSPACE_GIT_POINTER_CHANGED")
    return data


def verify_execution_contract(state):
    if state.get("run_workspace"):
        if state.get("preflight_status") != "PASS":
            raise RuntimeError("PREFLIGHT_NOT_PASSED")
        return _load_verified_manifest(state)
    return None


def prepare_workspace_node(state: AgentState):
    run_dir = None
    try:
        source = Path(state.get("repo_dir", "")).resolve(strict=True)
        top = _git(source, "rev-parse", "--show-toplevel").stdout.decode().strip()
        if Path(top).resolve() != source:
            raise RuntimeError("REPO_DIR_NOT_GIT_ROOT")
        head = _git(source, "rev-parse", "HEAD").stdout.decode().strip()
        files, skipped = _inventory(source)
        dirty = _source_dirty(source)
        if dirty:
            raise RuntimeError("SOURCE_REPOSITORY_NOT_CLEAN")
        run_dir = Path(tempfile.mkdtemp(prefix="freeagentos-run-"))
        os.chmod(run_dir, 0o700)
        ACTIVE_RUN_DIR.set(str(run_dir))
        repo = run_dir / "workspace"
        control = run_dir / "controller"
        repo.mkdir(mode=0o755)
        control.mkdir(mode=0o700)
        _owner_marker(control, run_dir)
        clean_hashes = {}
        for name, data, mode in files:
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode or 0o644)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            clean_hashes[name] = _sha(data)
        git_dir = control / "workspace.git"
        _git(repo, "init", "--quiet", "--separate-git-dir", str(git_dir))
        for key, value in (("user.name", "FreeAgentOS run snapshot"),
                           ("user.email", "freeagentos@localhost.invalid"),
                           ("core.hooksPath", "/dev/null"), ("core.autocrlf", "false")):
            _git(repo, "config", key, value)
        env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        added = run_git(["--literal-pathspecs", "add", "-f", "-A"], cwd=repo, env=env, timeout=60)
        if added.returncode:
            raise RuntimeError("WORKSPACE_GIT_ADD_FAILED")
        committed = run_git(["commit", "--quiet", "-m", "FreeAgentOS isolated baseline"],
                            cwd=repo, env=env, timeout=60)
        if committed.returncode:
            raise RuntimeError("WORKSPACE_BASELINE_FAILED")
        head_workspace = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        git_pointer, _ = _read_regular(repo / ".git", max_bytes=4096)
        runner = control / "freeagent-test"
        shutil.copyfile(ROOT / "bin/freeagent-test", runner, follow_symlinks=False)
        os.chmod(runner, 0o400)
        controller_hashes = _controller_hashes()
        source_inventory = {name: digest for name, digest in clean_hashes.items()}
        manifest = {
            "schema_version": 1, "workspace_id": run_dir.name,
            "source_repo": str(source), "source_head": head,
            "source_inventory": source_inventory, "workspace_repo": str(repo),
            "source_dirty_paths": dirty,
            "workspace_head": head_workspace,
            "workspace_git_pointer_sha256": _sha(git_pointer),
            "integrity_policy": {key: state.get(key) is True for key in
                                 ("allow_new_files", "allow_deletes", "allow_test_changes", "allow_verification_changes")},
            "test_inventory": {name: digest for name, digest in clean_hashes.items() if TEST_PATH.search(name)},
            "verification_inputs": {name: digest for name, digest in clean_hashes.items()
                                     if PurePosixPath(name).name.lower() in VERIFY_CONFIG
                                     or "orchestrator" in PurePosixPath(name).parts
                                     or name.startswith(".github/workflows/")},
            "runner_sha256": _sha(runner.read_bytes()),
            "controller_hashes": controller_hashes,
            "excluded_file_count": skipped,
            "workspace_limits": {"files": MAX_FILES, "bytes": MAX_BYTES, "file_bytes": MAX_FILE_BYTES},
            "resource_policy": dict(RESOURCE_POLICY),
            "host_capability_policy": list(PREFLIGHT_REQUIRED),
            "worker_resource_policy": dict(WORKER_POLICY),
            "research_resource_policy": dict(RESEARCH_POLICY),
        }
        manifest_path, digest = _write_manifest(control, manifest)
        return {"source_repo": str(source), "source_head": head,
                "source_inventory_sha256": _sha(json.dumps(source_inventory, sort_keys=True).encode()),
                "workspace_preexisting_dirty": dirty,
                "run_workspace": str(repo), "repo_dir": str(repo), "run_dir": str(run_dir),
                "workspace_id": run_dir.name, "workspace_status": "READY",
                "verification_manifest": str(manifest_path), "verification_manifest_sha256": digest,
                "verification_manifest_data": manifest,
                "workspace_test_attestation": {}, "trace": ["workspace_prepare"]}
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        if run_dir is not None:
            try:
                if (run_dir.parent == Path(tempfile.gettempdir()).resolve()
                        and run_dir.name.startswith("freeagentos-run-")
                        and shutil.rmtree.avoids_symlink_attacks):
                    shutil.rmtree(run_dir)
            except OSError:
                pass
        ACTIVE_RUN_DIR.set(None)
        return {"workspace_status": "BLOCKED", "workspace_error": str(exc),
                "status": "BLOCKED", "trace": ["workspace_prepare:error"]}


def _source_drift(manifest):
    source = Path(manifest["source_repo"])
    head = _git(source, "rev-parse", "HEAD").stdout.decode().strip()
    if head != manifest["source_head"]:
        return ["HEAD"]
    files, _ = _inventory(source)
    actual = {name: _sha(data) for name, data, _ in files}
    expected = manifest["source_inventory"]
    return sorted(name for name in set(actual) | set(expected) if actual.get(name) != expected.get(name))


def verified_patch(state):
    """Return a promotion-only artifact. This function never writes to source_repo."""
    manifest = _load_verified_manifest(state)
    drift = _source_drift(manifest)
    if drift:
        raise RuntimeError("SOURCE_REPOSITORY_DRIFT")
    repo = Path(state["run_workspace"])
    if _git(repo, "rev-parse", "HEAD").stdout.decode().strip() != manifest["workspace_head"]:
        raise RuntimeError("WORKSPACE_HEAD_CHANGED")
    all_paths = sorted(set(state.get("changed_files", [])))
    if not all_paths:
        raise RuntimeError("EMPTY_VERIFIED_PATCH")
    for name in all_paths:
        path = repo / name
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise RuntimeError("UNSAFE_PATCH_PATH")
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    added = run_git(["--literal-pathspecs", "add", "-f", "-A", "--", *all_paths],
                    cwd=repo, env=env, timeout=60)
    if added.returncode:
        raise RuntimeError("PATCH_STAGING_FAILED")
    diff = _git(repo, "diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv", "HEAD").stdout
    if not diff:
        raise RuntimeError("EMPTY_VERIFIED_PATCH")
    artifact = Path(tempfile.mkdtemp(prefix="freeagentos-promotion-"))
    os.chmod(artifact, 0o700)
    patch_path = artifact / "verified.patch"
    fd = os.open(patch_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(diff)
        stream.flush()
        os.fsync(stream.fileno())
    metadata = {"schema_version": 1, "workspace_id": manifest["workspace_id"],
                "source_repo": manifest["source_repo"], "source_head": manifest["source_head"],
                "source_inventory_sha256": _sha(json.dumps(manifest["source_inventory"], sort_keys=True).encode()),
                "patch_sha256": _sha(diff), "paths": all_paths, "promotion_ready": True,
                "automatic_promotion": False}
    meta_path = artifact / "promotion.json"
    meta_path.write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    os.chmod(meta_path, 0o400)
    return {"verified_patch_path": str(patch_path), "promotion_metadata_path": str(meta_path),
            "promotion_ready": True, "promotion_error": "", "trace": ["patch_artifact"]}


def test_discovery_count(output):
    text = output or ""
    matches = re.findall(r"(?m)^\s*Tests:\s*.*?(\d+)\s+total\b", text)
    if matches:
        return int(matches[-1]), "jest"
    matches = re.findall(r"(?m)^\s*Ran\s+(\d+)\s+tests?\s+in\s+[^\n]+", text)
    if matches:
        return int(matches[-1]), "unittest"
    categories = r"\b(\d+)\s+(passed|failed|error|errors|skipped|xfailed|xpassed|deselected)\b"
    for line in reversed(text.splitlines()):
        summary = line.strip().strip("= ").strip()
        counts = re.findall(categories, summary, re.I)
        if counts and re.search(r"\bin\s+\d+(?:\.\d+)?s\b", summary):
            return sum(int(count) for count, _ in counts), "pytest"
    return None, "unrecognized"


def discovery_baseline_node(state: AgentState):
    from roles.sandbox import run_isolated
    from roles.coding_units import failure_count

    try:
        manifest = _load_verified_manifest(state)
        result = run_isolated(state["run_workspace"], state["run_dir"],
                              manifest["runner_sha256"], timeout=150)
        count, framework = test_discovery_count(result["output"])
        evidence = {"status": "ATTESTED" if count is not None else "UNAVAILABLE",
                    "baseline_status": "ATTESTED" if count is not None else "UNAVAILABLE",
                    "baseline_count": count, "final_count": None, "framework": framework,
                    "baseline_failures": failure_count(result["output"], framework),
                    "runner_exit": result["exit_code"], "runner_result": result["result"],
                    "isolated": result["isolated"], "sandbox_evidence": result["evidence"],
                    "test_inventory_sha256": _sha(
                        json.dumps(manifest["test_inventory"], sort_keys=True).encode())}
        _load_verified_manifest(state)
        return {"workspace_test_attestation": evidence,
                "trace": ["test_discovery_baseline"]}
    except Exception as exc:
        return {"workspace_test_attestation": {"status": "BLOCKED", "error": str(exc)},
                "sandbox_evidence": getattr(exc, "evidence", {}),
                "status": "BLOCKED", "workspace_error": str(exc),
                "trace": ["test_discovery_baseline:error"]}


def finish_workspace(state):
    """Attach artifact only on success; clean only controller-generated paths."""
    artifact = {}
    status = state.get("status")
    if status == "VERIFIED":
        try:
            artifact = verified_patch(state)
        except Exception as exc:
            status = "BLOCKED"
            artifact = {"promotion_ready": False, "promotion_error": str(exc)}
    if state.get("retain_workspace") is True:
        (Path(state["run_dir"]) / "controller" / "owner.json").unlink(missing_ok=True)
        ACTIVE_RUN_DIR.set(None)
        return {**artifact, "status": status, "workspace_status":
                "VERIFIED_ARTIFACT_READY" if status == "VERIFIED" else "RETAINED_FOR_REVIEW",
                "trace": ["finalizer", "workspace_finish"]}
    try:
        run_dir = Path(state["run_dir"]).resolve(strict=True)
        if (run_dir.parent != Path(tempfile.gettempdir()).resolve()
                or not run_dir.name.startswith("freeagentos-run-")
                or run_dir.is_symlink() or not shutil.rmtree.avoids_symlink_attacks):
            raise RuntimeError("UNSAFE_WORKSPACE_CLEANUP")
        _load_verified_manifest(state)
        shutil.rmtree(run_dir)
        ACTIVE_RUN_DIR.set(None)
        return {**artifact, "status": status, "run_dir": "", "run_workspace": "",
                "verification_manifest": "", "workspace_status": "CLEANED",
                "trace": ["finalizer", "workspace_finish"]}
    except Exception as exc:
        ACTIVE_RUN_DIR.set(None)
        return {**artifact, "status": "BLOCKED", "promotion_ready": False,
                "promotion_error": artifact.get("promotion_error") or str(exc),
                "workspace_status": "CLEANUP_BLOCKED", "trace": ["finalizer", "workspace_finish:error"]}
