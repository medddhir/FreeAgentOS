"""Controller-owned cgroup lease for model CLI processes and descendants."""

import hashlib
import http.client
import json
import os
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from roles.activity import ActivityCapture, MAX_TIME_MS, safe_completion
from roles.lease import ActivityLease, hard_cap_seconds
from roles.sandbox import (BoundedCapture, MS_BIND, MS_PRIVATE, MS_RDONLY, MS_REC, MS_REMOUNT,
                           _drain_ready, _event_values, _mount, _read_bounded,
                           _scope_pids, _start_cgroup, _stop_scope, _umount)


MIB = 1024 * 1024
CONTROLLER_ROOT = Path(__file__).resolve().parents[2]
WORKER_POLICY = {
    "schema_version": 1,
    "wall_timeout_seconds": 240,
    "termination_grace_seconds": 1,
    "cpu_quota_us": 100000,
    "cpu_period_us": 100000,
    "cpu_time_seconds": 180,
    "memory_limit_bytes": 1536 * MIB,
    "swap_limit_bytes": 0,
    "max_processes": 64,
    "max_open_files": 256,
    "max_file_size_bytes": 128 * MIB,
    "max_output_bytes": 256 * 1024,
}
RESEARCH_POLICY = {
    "schema_version": 1,
    "wall_timeout_seconds": 60,
    "termination_grace_seconds": 1,
    "cpu_quota_us": 100000,
    "cpu_period_us": 100000,
    "cpu_time_seconds": 50,
    "memory_limit_bytes": 1024 * MIB,
    "swap_limit_bytes": 0,
    "max_processes": 32,
    "max_open_files": 128,
    "max_file_size_bytes": 64 * MIB,
    "max_output_bytes": 512 * 1024,
}
POLICIES = {"model": WORKER_POLICY, "research": RESEARCH_POLICY}
MARKER = "FREEAGENT_WORKER_EVIDENCE="
GATEWAY_HEALTH_HOST = "127.0.0.1"
GATEWAY_HEALTH_PORT = 3001


def _elapsed_ms(start_ns):
    return max(0, (time.monotonic_ns() - start_ns) // 1_000_000)


def _gateway_health():
    """Optional loopback observation; never sends a model request or credentials."""
    start = time.monotonic_ns()
    connection = None
    try:
        from foundation import current_config
        from urllib.parse import urlsplit
        endpoint = urlsplit(current_config().endpoint)
        client = http.client.HTTPSConnection if endpoint.scheme == "https" else http.client.HTTPConnection
        connection = client(endpoint.hostname, endpoint.port, timeout=0.75)
        connection.request("GET", "/health")
        response = connection.getresponse()
        status = "HEALTHY" if response.status == 200 else "UNHEALTHY"
    except (OSError, http.client.HTTPException):
        status = "UNAVAILABLE"
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
    return {"gateway_health_status": status, "gateway_health_latency_ms": _elapsed_ms(start),
            "gateway_request_observed": "UNAVAILABLE"}


def _read_worker_streams(proc, seconds, capture, spawned_ns, *, lease=None, broker=None):
    """Drain both pipes with one bounded capture and independent byte counters."""
    stats = {"worker_stdout_bytes_seen": 0, "worker_stderr_bytes_seen": 0,
             "worker_first_stdout_byte_ms": None, "worker_first_stderr_byte_ms": None,
             "stdout_eof_before_cleanup": False, "stderr_eof_before_cleanup": False,
             "last_stdout_ms": None, "last_stderr_ms": None}
    lease = lease or ActivityLease(seconds, "worker", "model", False, seconds, spawned_ns)
    with selectors.DefaultSelector() as selector:
        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while True:
            now_ns = time.monotonic_ns()
            lease.observe(broker=broker, capture=capture)
            if now_ns >= lease.deadline_ns:
                if proc.poll() is not None or not lease.extend(now_ns, broker=broker, capture=capture):
                    break
            events = selector.select(min(0.05, max(0, (lease.deadline_ns - time.monotonic_ns()) / 1e9)))
            for key, _ in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    stats[f"{key.data}_eof_before_cleanup"] = True
                    selector.unregister(key.fileobj)
                    continue
                name = key.data
                count_key = f"worker_{name}_bytes_seen"
                first_key = f"worker_first_{name}_byte_ms"
                stats[count_key] += len(chunk)
                stats[f"last_{name}_ms"] = min(MAX_TIME_MS, _elapsed_ms(spawned_ns))
                if stats[first_key] is None:
                    stats[first_key] = _elapsed_ms(spawned_ns)
                # Stderr is diagnostic transport, never model/research stdout.
                # Drain it without retaining its potentially sensitive text.
                if name == "stdout":
                    if isinstance(capture, ActivityCapture):
                        capture.now_ms = min(MAX_TIME_MS, _elapsed_ms(spawned_ns))
                    capture.add(chunk)
            if proc.poll() is not None and not events:
                return False, stats
    return proc.poll() is None, stats


def _completion_observation(proc, capture, stats, spawned_ns, ended_ns, broker):
    """Snapshot BEFORE termination/draining; diagnostic clocks never affect lease."""
    elapsed = min(MAX_TIME_MS, max(0, (ended_ns - spawned_ns) // 1_000_000))
    gap = lambda last: None if last is None else min(MAX_TIME_MS, max(0, elapsed - last))
    alive = proc.poll() is None
    data = getattr(capture, "data", {})
    last = broker.telemetry.last_success_ns if broker is not None else None
    state = ("PROCESS_EXITED" if not alive else "ALIVE_WITH_RESULT" if data.get("final_result_seen")
             else "ALIVE_AFTER_STDOUT_EOF" if stats["stdout_eof_before_cleanup"] else "ALIVE_NO_RESULT")
    return safe_completion({
        "state": state, "process_alive_at_observation_end": alive,
        "stdout_eof_before_cleanup": stats["stdout_eof_before_cleanup"],
        "stderr_eof_before_cleanup": stats["stderr_eof_before_cleanup"],
        "stdout_idle_ms": gap(stats["last_stdout_ms"]),
        "stderr_idle_ms": gap(stats["last_stderr_ms"]),
        "valid_stream_idle_ms": gap(data.get("last_valid_stream_event_ms")),
        "broker_success_idle_ms": gap(None if last is None else (last - spawned_ns) // 1_000_000),
        "provider_completion_observed": "UNAVAILABLE"})


def _drain_worker_ready(proc, capture, stats, spawned_ns):
    for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        while True:
            try:
                chunk = os.read(stream.fileno(), 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            count_key = f"worker_{name}_bytes_seen"
            first_key = f"worker_first_{name}_byte_ms"
            stats[count_key] += len(chunk)
            if stats[first_key] is None:
                stats[first_key] = _elapsed_ms(spawned_ns)
            if name == "stdout":
                if isinstance(capture, ActivityCapture):
                    capture.now_ms = min(MAX_TIME_MS, _elapsed_ms(spawned_ns))
                capture.add(chunk)


def _phase(timed_out, stats):
    if timed_out:
        if stats["worker_stdout_bytes_seen"] == stats["worker_stderr_bytes_seen"] == 0:
            return "PROCESS_STARTED_NO_OUTPUT"
        if stats["worker_first_stdout_byte_ms"] is not None:
            return "FIRST_OUTPUT_BEFORE_TIMEOUT"
        return "STDERR_BEFORE_STDOUT"
    if stats["worker_stderr_bytes_seen"] and (stats["worker_first_stdout_byte_ms"] is None or
            stats["worker_first_stderr_byte_ms"] <= stats["worker_first_stdout_byte_ms"]):
        return "STDERR_BEFORE_STDOUT"
    return "NORMAL_COMPLETE"


class WorkerBoundaryError(RuntimeError):
    def __init__(self, code, evidence=None):
        super().__init__(code)
        self.evidence = evidence or {"cleanup_status": "UNPROVEN", "remaining_processes": None,
                                     "cgroup_status": "UNAVAILABLE", "error": code}


@dataclass
class WorkerResult:
    returncode: int
    stdout: str
    evidence: dict


# Preparation only: this profile has no qualified activation producer. Fixed
# paths name the intended private layout, not observed/protected artifacts.
TEXT_INFERENCE_PROFILE = "text-inference-v1"
TEXT_INFERENCE_EXECUTABLE = "/runtime/bin/claude-free"
TEXT_INFERENCE_LIMITS = {
    "schema_version": 1, "wall_timeout_seconds": 60,
    "termination_grace_seconds": 1, "cpu_quota_us": 100000,
    "cpu_period_us": 100000, "cpu_time_seconds": 60,
    "memory_limit_bytes": 1536 * MIB, "swap_limit_bytes": 0,
    "max_processes": 64, "max_open_files": 256,
    "max_file_size_bytes": 128 * MIB, "max_output_bytes": 64 * 1024,
}
TEXT_INFERENCE_BOUNDS = {"request_bytes": 48 * 1024,
                         "response_bytes": 64 * 1024, "cli_invocations": 1}
TEXT_INFERENCE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL",
                           "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN")
TEXT_INFERENCE_REQUIREMENTS = (
    "PROTECTED_RUNTIME_IDENTITY", "REPOSITORY_AND_SECRET_VISIBILITY_EXCLUDED",
    "NARROW_CREDENTIAL_PROVISIONING", "INDEPENDENT_ACTION_RESTRICTIONS",
    "QUALIFIED_ACTIVATION", "BOUND_CANCELLATION_AND_CLEANUP",
)


@dataclass(frozen=True)
class TextInferencePlan:
    """Declared invocation binding, never an activation/qualification ticket."""
    request: bytes
    request_sha256: str
    argv: tuple
    runtime_sha256: str
    executable_sha256: str
    invocation: str
    credential_reference: str
    policy_sha256: str
    profile_sha256: str
    binding_sha256: str


def text_inference_environment():
    """Preparation data only; not selected by any admitted launch.

    No inherited env or credential read. Future admission requires actual
    environment enforcement and trusted credential provisioning, not this hash.
    """
    return {"PATH": "/runtime/bin", "HOME": "/tmp/text-inference-home",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "ANTHROPIC_BASE_URL": "http://127.0.0.1:3001"}


def prepare_text_inference(request, *, runtime_sha256, executable_sha256,
                           invocation, credential_reference, policy_sha256):
    """Bound canonical request and declared identities; no discovery or launch.

    Only website request fields are accepted. Their values remain data. Neither
    hashes nor an environment reference establish runtime/credential authority.
    """
    import re
    from roles.read_policy import no_file_tool_flags
    fields = {"version", "run", "profile", "phase", "contract", "base_snapshot",
              "brief", "guidance", "guidance_sha256", "files"}
    try:
        if (type(request) is not dict or set(request) != fields
                or type(request["version"]) is not int or request["version"] != 1
                or request["profile"] != "website-static-v1"
                or request["phase"] not in ("code", "revision")
                or any(type(v) is not str or re.fullmatch(r"[0-9a-f]{64}", v) is None
                       for v in (runtime_sha256, executable_sha256, policy_sha256))
                or type(invocation) is not str or re.fullmatch(r"[0-9a-f]{32}", invocation) is None
                or type(credential_reference) is not str
                or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", credential_reference) is None):
            raise ValueError()
        brief_keys = {"title", "heading", "button", "revision_heading",
                      "revision_button", "design", "confirmed"}
        brief = request["brief"]
        files = request["files"]
        if (type(brief) is not dict or set(brief) != brief_keys or brief["confirmed"] is not True
                or any(type(brief[k]) is not str or len(brief[k].encode("utf-8")) > 512
                       for k in brief_keys - {"confirmed"})
                or type(files) is not list or len(files) != 4
                or type(request["guidance"]) is not str or len(request["guidance"].encode("utf-8")) > 8192
                # Producer formats only: these declarations prove neither
                # provenance nor freshness, and confer no admission authority.
                or type(request["run"]) is not str
                or re.fullmatch(r"[0-9a-f]{32}", request["run"]) is None
                or any(type(request[k]) is not str
                       or re.fullmatch(r"[0-9a-f]{64}", request[k]) is None
                       for k in ("contract", "base_snapshot", "guidance_sha256"))):
            raise ValueError()
        allowed = {"index.html", "styles.css", "app.js", "README.md"}
        seen = set()
        for entry in files:
            if (type(entry) is not dict or set(entry) != {"path", "text"}
                    or type(entry["path"]) is not str or entry["path"] not in allowed
                    or entry["path"] in seen or type(entry["text"]) is not str
                    or len(entry["text"].encode("utf-8")) > 8192):
                raise ValueError()
            seen.add(entry["path"])
        raw = json.dumps(request, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
        if not 0 < len(raw) <= TEXT_INFERENCE_BOUNDS["request_bytes"]:
            raise ValueError()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise WorkerBoundaryError("TEXT_INFERENCE_REQUEST_INVALID") from None
    # Existing flags are compatibility requests, not independent action proof.
    argv = (TEXT_INFERENCE_EXECUTABLE, *no_file_tool_flags(),
            "--permission-mode", "dontAsk", "--permission-prompts", "none",
            "--output-format", "json", "--json-schema", '{"type":"object"}',
            "-p", raw.decode("utf-8"))
    profile = {"version": 1, "profile": TEXT_INFERENCE_PROFILE,
               "model_profile": "claude-free-default", "executable": argv[0],
               "options": argv[1:-1], "limits": TEXT_INFERENCE_LIMITS,
               "bounds": TEXT_INFERENCE_BOUNDS, "environment_keys": TEXT_INFERENCE_ENV_KEYS,
               "environment": text_inference_environment(),
               "requirements": TEXT_INFERENCE_REQUIREMENTS, "streaming": False}
    profile_sha = _digest(profile)
    # Preparation source/policy identity, supplied as declared binding data.
    # This is not the effective resource-policy digest used by _validate_evidence.
    policy_sha = policy_sha256  # never admission authority
    request_sha = hashlib.sha256(raw).hexdigest()
    binding = {"profile": profile_sha, "policy": policy_sha,
               "runtime": runtime_sha256, "executable": executable_sha256,
               "invocation": invocation, "request": request_sha,
               "credential_reference": credential_reference}
    return TextInferencePlan(raw, request_sha, argv, runtime_sha256,
                             executable_sha256, invocation, credential_reference,
                             policy_sha, profile_sha, _digest(binding))


def _text_inference_admission():
    # Existing staging registrations, recording approvals and Linux tokens are
    # not producers for the six requirements. There is deliberately no boolean,
    # evidence-dict, callback or fake ticket path to a positive decision.
    raise WorkerBoundaryError("TEXT_INFERENCE_QUALIFICATION_UNPROVEN")


def _validate_evidence(evidence, policy, exit_code, outer_truncated=False):
    # Evidence policy_sha256 hashes the effective resource-policy dictionary.
    # TextInferencePlan.policy_sha256 instead binds preparation source identity;
    # neither field may be substituted for the other digest domain.
    if (not isinstance(exit_code, int) or evidence.get("cleanup_status") != "CONFIRMED"
            or evidence.get("remaining_processes") != 0 or evidence.get("cgroup_status") != "ENFORCED"
            or evidence.get("policy_sha256") != _digest(policy)
            or evidence.get("worker_cgroup_readonly") is not True
            or evidence.get("worker_controller_readonly") is not True
            or evidence.get("worker_capabilities_dropped") is not True
            or any(evidence.get("controls", {}).get(name) != "ENFORCED" for name in
                   ("cpu", "memory", "process_count", "output", "file_descriptors", "file_size"))
            or outer_truncated):
        raise WorkerBoundaryError("WORKER_BOUNDARY_UNVERIFIED", evidence)


def _digest(policy):
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _effective_policy(limits, profile="model"):
    if profile == TEXT_INFERENCE_PROFILE:
        if limits:
            raise WorkerBoundaryError("WORKER_POLICY_OVERRIDE_INVALID")
        return dict(TEXT_INFERENCE_LIMITS)
    if profile not in POLICIES:
        raise WorkerBoundaryError("WORKER_PROFILE_INVALID")
    policy = dict(POLICIES[profile])
    for key, value in (limits or {}).items():
        if (key not in policy or key in ("schema_version", "cpu_period_us", "swap_limit_bytes")
                or type(value) is not int or value <= 0 or value > policy[key]):
            raise WorkerBoundaryError("WORKER_POLICY_OVERRIDE_INVALID")
        policy[key] = value
    return policy


def _child_limits(scope, policy, timeout):
    (scope / "cgroup.procs").write_text(str(os.getpid()))
    os.unshare(os.CLONE_NEWNS)
    _mount(None, "/", flags=MS_REC | MS_PRIVATE)
    _mount(None, scope.parent, flags=MS_BIND | MS_REMOUNT | MS_RDONLY)
    _mount(CONTROLLER_ROOT, CONTROLLER_ROOT, flags=MS_BIND | MS_REC)
    _mount(None, CONTROLLER_ROOT, flags=MS_BIND | MS_REMOUNT | MS_RDONLY)
    cpu = min(timeout, policy["cpu_time_seconds"])
    for kind, soft, hard in (
        (resource.RLIMIT_CPU, cpu, cpu + 1),
        (resource.RLIMIT_NPROC, max(policy["max_processes"], 64), max(policy["max_processes"], 64)),
        (resource.RLIMIT_NOFILE, policy["max_open_files"], policy["max_open_files"]),
        (resource.RLIMIT_FSIZE, policy["max_file_size_bytes"], policy["max_file_size_bytes"]),
        (resource.RLIMIT_CORE, 0, 0),
    ):
        resource.setrlimit(kind, (soft, hard))


def _run_inner(area, request):
    if type(request) is not dict:
        raise WorkerBoundaryError("WORKER_REQUEST_INVALID")
    if request.get("profile") == TEXT_INFERENCE_PROFILE:
        _text_inference_admission()
    cmd = request.get("cmd")
    if (type(cmd) is not list or not cmd or type(cmd[0]) is not str or not cmd[0]
            or any(type(arg) is not str or "\x00" in arg for arg in cmd)):
        raise WorkerBoundaryError("WORKER_REQUEST_INVALID")
    # This path is intentionally reserved even under an ordinary profile.
    # A configured ordinary launcher at this exact path remains unavailable.
    if cmd[0] == TEXT_INFERENCE_EXECUTABLE:
        _text_inference_admission()
    inner_started_ns = time.monotonic_ns()
    policy = request["policy"]
    if _effective_policy(request["limits"], request["profile"]) != policy:
        raise WorkerBoundaryError("WORKER_POLICY_CHANGED")
    timeout = min(request["timeout"], policy["wall_timeout_seconds"])
    setup_started_ns = time.monotonic_ns()
    mountpoint, scope = _start_cgroup(Path(area) / "root", policy, request["scope_name"])
    setup_ms = _elapsed_ms(setup_started_ns)
    process = None
    broker = None
    evidence = None
    capture = (ActivityCapture() if request.get("stream_activity") else
               BoundedCapture(policy["max_output_bytes"]))
    try:
        from roles.broker_session import prepare_session
        broker_command, broker = prepare_session(request["cmd"], area)
        command = ["/usr/bin/setpriv", "--bounding-set=-all", "--no-new-privs", "--", *broker_command]
        spawn_started_ns = time.monotonic_ns()
        try:
            from roles.model_attribution import transport_environment, valid_transport
            process = subprocess.Popen(command, cwd=request["cwd"],
                                       env=_worker_environment(request),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True,
                                       preexec_fn=lambda: _child_limits(scope, policy, timeout))
        except OSError as exc:
            raise WorkerBoundaryError("WORKER_SPAWN_FAILURE", {
                "worker_phase": "PROCESS_NEVER_STARTED", "cleanup_status": "UNPROVEN",
                "remaining_processes": None}) from exc
        spawn_ms = _elapsed_ms(spawn_started_ns)
        spawned_ns = time.monotonic_ns()
        if broker is not None:
            broker.start()
        lease = ActivityLease(timeout, request["role"], request["profile"],
                              request.get("stream_activity"), policy["wall_timeout_seconds"], spawned_ns)
        timed_out, streams = _read_worker_streams(process, timeout, capture, spawned_ns,
                                                lease=lease, broker=broker)
        ended_ns = time.monotonic_ns()
        completion = _completion_observation(process, capture, streams, spawned_ns, ended_ns, broker)
        # Keep raw transport clocks internal; public diagnostics are bounded/projection-safe.
        for key in ("last_stdout_ms", "last_stderr_ms", "stdout_eof_before_cleanup", "stderr_eof_before_cleanup"):
            streams.pop(key)
        cleanup_started_ns = time.monotonic_ns()
        cleanup = _stop_scope(scope, process, policy["termination_grace_seconds"])
        runtime_ms = _elapsed_ms(spawned_ns)
        broker_evidence = broker.stop() if broker is not None else None
        _drain_worker_ready(process, capture, streams, spawned_ns)
        activity = capture.finish() if isinstance(capture, ActivityCapture) else None
        memory = _event_values(scope / "memory.events")
        pids = _event_values(scope / "pids.events")
        hits = {"memory": bool(memory.get("oom", 0) or memory.get("oom_kill", 0)),
                "process_count": bool(pids.get("max", 0))}
        truncated = (capture.truncated or
                     streams["worker_stdout_bytes_seen"] + streams["worker_stderr_bytes_seen"]
                     > policy["max_output_bytes"])
        code = 124 if timed_out else (1 if truncated or any(hits.values()) else process.returncode)
        if activity is not None and not timed_out and code == 0 and activity["activity_status"] != "COMPLETE":
            code = 65
        evidence = {**cleanup, "attribution_headers_configured": bool(valid_transport(request.get("attribution_transport"))),
                    "completion": completion, "lease": lease.evidence(ended_ns, success=code == 0),
                    **({"broker": broker_evidence} if broker_evidence is not None else {}),
                    **({"activity": activity} if activity is not None else {}),
                    "role": request["role"], "timeout_triggered": timed_out,
                    "output_truncated": truncated,
                    "output_total_bytes": (streams["worker_stdout_bytes_seen"] +
                                           streams["worker_stderr_bytes_seen"]),
                    **streams, "worker_phase": _phase(timed_out, streams),
                    "worker_scope_setup_ms": setup_ms, "worker_process_spawn_ms": spawn_ms,
                    "worker_process_runtime_ms": runtime_ms,
                    "worker_cleanup_ms": _elapsed_ms(cleanup_started_ns),
                    "worker_total_ms": _elapsed_ms(inner_started_ns),
                    "worker_exit_code": code,
                    "resource_hits": hits, "cgroup_status": "ENFORCED",
                    "controls": {name: "ENFORCED" for name in
                                 ("cpu", "memory", "process_count", "output", "file_descriptors", "file_size")},
                    "policy_sha256": _digest(policy),
                    "worker_cgroup_readonly": True, "worker_controller_readonly": True,
                    "worker_capabilities_dropped": True,
                    "cleanup_status": "CONFIRMED" if cleanup["remaining_processes"] == 0 else "UNPROVEN"}
        return {"returncode": code, "stdout": capture.render().decode("utf-8", "replace"),
                "evidence": evidence}
    finally:
        if process is not None and process.poll() is None:
            (scope / "cgroup.kill").write_text("1")
            process.wait(timeout=3)
        if _scope_pids(scope):
            raise WorkerBoundaryError("WORKER_PROCESSES_REMAIN")
        if process is not None:
            process.stdout.close()
            process.stderr.close()
        try:
            if broker is not None:
                broker.stop()
        finally:
            scope.rmdir()
            _umount(mountpoint)
            mountpoint.rmdir()
        if evidence is not None:
            evidence["worker_cleanup_ms"] = _elapsed_ms(cleanup_started_ns)
            evidence["worker_total_ms"] = _elapsed_ms(inner_started_ns)


def _worker_environment(request):
    from roles.model_attribution import transport_environment
    env = transport_environment(request.get("attribution_transport"))
    if "adapter_settings" in request:
        from foundation import adapter_environment
        env = adapter_environment(env, request["adapter_settings"])
    return env


def _model_command(cmd):
    from foundation import current_config
    return bool(cmd and cmd[0] == current_config().launcher)


def _run_worker_impl(cmd, *, cwd=None, timeout=180, role="worker", limits=None,
                     policy_profile="model", stream_activity=False):
    """Run only the CLI tree in a cgroup; keep this controller outside it."""
    if (policy_profile == TEXT_INFERENCE_PROFILE or
            isinstance(cmd, list) and cmd and cmd[0] == TEXT_INFERENCE_EXECUTABLE):
        _text_inference_admission()
    outer_started_ns = time.monotonic_ns()
    policy = _effective_policy(limits, policy_profile)
    if (type(stream_activity) is not bool or stream_activity and
            (policy_profile != "model" or role not in ("coder", "fixer"))):
        raise WorkerBoundaryError("WORKER_ACTIVITY_MODE_INVALID")
    if (type(timeout) is not int or timeout <= 0 or not isinstance(cmd, list) or not cmd
            or any(not isinstance(item, str) for item in cmd)):
        raise WorkerBoundaryError("WORKER_REQUEST_INVALID")
    scope_name = "freeagentos-worker-" + uuid.uuid4().hex
    request = {"cmd": cmd, "cwd": str(cwd or os.getcwd()), "timeout": min(timeout, policy["wall_timeout_seconds"]),
               "role": role, "policy": policy, "limits": limits or {}, "profile": policy_profile}
    from roles.model_attribution import current_transport
    transport = current_transport()
    if transport is not None:
        request["attribution_transport"] = transport
    if _model_command(cmd):
        from foundation import current_config, discover_launcher
        config = current_config()
        discover_launcher(config)
        request["adapter_settings"] = {"endpoint": config.endpoint, "credential_env": config.credential_env}
    request["scope_name"] = scope_name
    request["stream_activity"] = stream_activity
    raw = json.dumps(request, separators=(",", ":")).encode()
    if len(raw) > 128 * 1024 and "attribution_transport" in request:
        request.pop("attribution_transport")
        raw = json.dumps(request, separators=(",", ":")).encode()
    if len(raw) > 128 * 1024:
        raise WorkerBoundaryError("WORKER_REQUEST_TOO_LARGE")
    from roles.model_profiles import command_identity, requested_identity, ModelProfileError
    try:
        model_selection = (command_identity(cmd, role) if _model_command(cmd) else
                           requested_identity("researcher") if role.startswith("research:") else None)
    except ModelProfileError as exc:
        raise WorkerBoundaryError(str(exc)) from None
    resolution = {"worker_executable_resolved": shutil.which(cmd[0]) is not None,
                  "claude_free_resolved": shutil.which("claude-free") is not None
                  if _model_command(cmd) else None,
                  "claude_executable_available": shutil.which("claude") is not None
                  if _model_command(cmd) else None}
    if model_selection is not None:
        resolution["model_selection"] = model_selection
    health = _gateway_health() if _model_command(cmd) and policy_profile == "model" else {
        "gateway_health_status": "NOT_CHECKED", "gateway_health_latency_ms": None,
        "gateway_request_observed": "UNAVAILABLE"}
    with tempfile.TemporaryDirectory(prefix="freeagentos-worker-") as area:
        try:
            process = subprocess.Popen(["unshare", "--mount", "--pid", "--fork", "--kill-child=SIGKILL",
                                        "--propagation", "private", sys.executable, __file__, "--enter", area],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as exc:
            raise WorkerBoundaryError("WORKER_SPAWN_FAILURE", {
                "worker_phase": "PROCESS_NEVER_STARTED", "cleanup_status": "UNPROVEN",
                "remaining_processes": None, **resolution, **health,
                "worker_total_ms": _elapsed_ms(outer_started_ns)}) from exc
        capture = BoundedCapture(policy["max_output_bytes"] + 8192)
        try:
            process.stdin.write(raw)
            process.stdin.close()
            emergency_seconds = hard_cap_seconds(request["timeout"], role, policy_profile,
                                                 stream_activity, policy["wall_timeout_seconds"])
            emergency = _read_bounded(process, emergency_seconds + 10, capture)
            if emergency:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
                raise WorkerBoundaryError("WORKER_EMERGENCY_TIMEOUT")
            process.wait(timeout=3)
            _drain_ready(process, capture)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
            process.stdout.close()
            _cleanup_outer_scope(scope_name)
        output = capture.render().decode("utf-8", "replace")
        lines = [line for line in output.splitlines() if line.startswith(MARKER)]
        if not lines:
            raise WorkerBoundaryError("WORKER_EVIDENCE_MISSING")
        try:
            evidence = json.loads(lines[-1][len(MARKER):])
        except (ValueError, TypeError) as exc:
            raise WorkerBoundaryError("WORKER_EVIDENCE_INVALID") from exc
        _validate_evidence(evidence, policy, process.returncode, capture.truncated)
        evidence.update(resolution)
        evidence.update(health)
        evidence["worker_total_ms"] = _elapsed_ms(outer_started_ns)
        clean_output = "\n".join(line for line in output.splitlines() if not line.startswith(MARKER))
        return WorkerResult(process.returncode, clean_output, evidence)


def _cleanup_outer_scope(scope_name):
    """Reap this invocation's cgroup if namespace init died before its own finally."""
    scope = Path("/sys/fs/cgroup") / scope_name
    if not scope.exists():
        return
    if not scope.is_dir() or scope.is_symlink():
        raise WorkerBoundaryError("WORKER_SCOPE_CLEANUP_UNPROVEN")
    try:
        (scope / "cgroup.kill").write_text("1")
        deadline = time.monotonic() + 3
        while _scope_pids(scope) and time.monotonic() < deadline:
            time.sleep(0.02)
        if _scope_pids(scope):
            raise WorkerBoundaryError("WORKER_PROCESSES_REMAIN")
        scope.rmdir()
    except OSError as exc:
        raise WorkerBoundaryError("WORKER_SCOPE_CLEANUP_UNPROVEN") from exc


def run_worker(cmd, *, cwd=None, timeout=180, role="worker", limits=None,
               policy_profile="model", stream_activity=False):
    if (policy_profile == TEXT_INFERENCE_PROFILE or
            isinstance(cmd, list) and cmd and cmd[0] == TEXT_INFERENCE_EXECUTABLE):
        _text_inference_admission()
    try:
        from roles.model_attribution import GatewaySession, safe_attribution_diagnostics, diagnostic_defaults, _ipc_failure
        setup_diagnostics = diagnostic_defaults()
        try:
            from foundation import current_config
            session = GatewaySession() if _model_command(cmd) and current_config().attribution_enabled else None
        except Exception as exc:
            session = None
            setup_diagnostics['registration_status'] = _ipc_failure(exc)
        if session is None:
            result = _run_worker_impl(cmd, cwd=cwd, timeout=timeout, role=role, limits=limits,
                                    policy_profile=policy_profile, stream_activity=stream_activity)
            if cmd and _model_command(cmd):
                result.evidence["attribution_diagnostics"] = safe_attribution_diagnostics(setup_diagnostics)
            return result
        session.begin()
        failure = None
        result = None
        try:
            with session.scope():
                result = _run_worker_impl(cmd, cwd=cwd, timeout=timeout, role=role, limits=limits,
                                          policy_profile=policy_profile, stream_activity=stream_activity)
        except WorkerBoundaryError as exc:
            failure = exc
            raise
        finally:
            observation = session.finish()
            evidence = failure.evidence if failure is not None else (result.evidence if result is not None else None)
            if evidence is not None:
                session.diagnostics['custom_headers_configured'] = evidence.pop('attribution_headers_configured',
                    False if session.diagnostics['registration_status'] != 'REGISTERED' else 'UNAVAILABLE')
                evidence['attribution_diagnostics'] = safe_attribution_diagnostics(session.diagnostics)
        result.evidence["gateway_attribution"] = observation
        return result
    except WorkerBoundaryError:
        raise
    except Exception as exc:
        from foundation import ConfigError
        if isinstance(exc, ConfigError):
            raise WorkerBoundaryError(str(exc)) from None
        raise WorkerBoundaryError("WORKER_CONTROLLER_ERROR:" + type(exc).__name__) from exc


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--enter":
    try:
        request = json.loads(sys.stdin.buffer.read(128 * 1024 + 1))
        result = _run_inner(sys.argv[2], request)
        sys.stdout.write(result["stdout"] + "\n" + MARKER + json.dumps(result["evidence"], sort_keys=True) + "\n")
        sys.stdout.flush()
        sys.exit(result["returncode"])
    except Exception as exc:
        code = str(exc).split(":", 1)[0] if isinstance(exc, RuntimeError) else type(exc).__name__
        evidence = (dict(exc.evidence) if isinstance(exc, WorkerBoundaryError) else {})
        evidence.update({"cleanup_status": "UNPROVEN", "remaining_processes": None,
                         "cgroup_status": "UNAVAILABLE", "error": code})
        sys.stdout.write(MARKER + json.dumps(evidence, sort_keys=True) + "\n")
        sys.stdout.flush()
        sys.exit(125)
