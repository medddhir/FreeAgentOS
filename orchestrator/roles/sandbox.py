"""Run target tests in a networkless chroot with only disposable target files."""

import ctypes
import hashlib
import json
import os
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LIBC = ctypes.CDLL(None, use_errno=True)
MS_RDONLY = 1
MS_BIND = 4096
MS_REMOUNT = 32
MS_REC = 16384
MS_PRIVATE = 1 << 18
MIB = 1024 * 1024

# This policy is controller code and is copied into the external run manifest.
# Callers may shorten a lease, but cannot enlarge any of these limits.
RESOURCE_POLICY = {
    "schema_version": 1,
    "wall_timeout_seconds": 150,
    "termination_grace_seconds": 1,
    "cpu_quota_us": 50000,
    "cpu_period_us": 100000,
    "cpu_time_seconds": 120,
    "memory_limit_bytes": 512 * MIB,
    "swap_limit_bytes": 0,
    "max_processes": 16,
    "max_open_files": 128,
    "max_file_size_bytes": 128 * MIB,
    "max_output_bytes": 64 * 1024,
    "test_workspace_bytes": 256 * MIB,
    "max_copy_bytes": 192 * MIB,
    "max_copy_files": 20000,
}
REQUIRED_CONTROLS = ("cpu", "memory", "process_count", "output", "file_descriptors", "disk_file_size")
EVIDENCE_PREFIX = "FREEAGENT_SANDBOX_EVIDENCE="


class SandboxBoundaryError(RuntimeError):
    def __init__(self, message, evidence):
        super().__init__(message)
        self.evidence = evidence


def _unavailable_evidence(code):
    return {"cleanup_status": "UNPROVEN", "remaining_processes": None,
            "cgroup_status": "UNAVAILABLE", "controls": {name: "UNAVAILABLE" for name in REQUIRED_CONTROLS},
            "timeout_triggered": False, "forced_kill_used": False,
            "output_truncated": False, "resource_hits": {}, "setup_error": code}


class BoundedCapture:
    """Drain unlimited pipe input while retaining a fixed-size head and tail."""

    def __init__(self, limit):
        self.limit = limit
        self.head_limit = min(4096, limit // 2)
        self.tail_limit = limit - self.head_limit
        self.head = bytearray()
        self.tail = bytearray()
        self.total_bytes = 0

    @property
    def truncated(self):
        return self.total_bytes > self.limit

    def add(self, chunk):
        self.total_bytes += len(chunk)
        needed = self.head_limit - len(self.head)
        self.head.extend(chunk[:needed])
        rest = chunk[needed:]
        if rest:
            self.tail.extend(rest)
            if len(self.tail) > self.tail_limit:
                del self.tail[:-self.tail_limit]

    def render(self):
        gap = b"\n... OUTPUT_TRUNCATED ...\n" if self.truncated else b""
        return bytes(self.head) + gap + bytes(self.tail)


def _mount(source, target, fstype=None, flags=0, data=None):
    src = os.fsencode(source) if source is not None else None
    dst = os.fsencode(target)
    fs = os.fsencode(fstype) if fstype is not None else None
    opts = os.fsencode(data) if data is not None else None
    if LIBC.mount(src, dst, fs, flags, opts) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _umount(target):
    if LIBC.umount2(os.fsencode(target), 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _safe_copy(source, dest, *, mounted=False):
    """Copy only bounded regular files into the disposable test filesystem."""
    source, dest = Path(source), Path(dest)
    if not mounted:
        dest.mkdir(parents=True, exist_ok=False)
    count = total = 0
    for current, dirs, names in os.walk(source, followlinks=False):
        relative = Path(current).relative_to(source)
        target_dir = dest / relative
        for directory in list(dirs):
            path = Path(current) / directory
            if directory == ".git":
                dirs.remove(directory)
                continue
            if path.is_symlink():
                raise RuntimeError("UNSAFE_TEST_WORKSPACE")
            (target_dir / directory).mkdir(exist_ok=True)
        for name in names:
            path = Path(current) / name
            if name == ".git":
                continue
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise RuntimeError("UNSAFE_TEST_WORKSPACE")
            count += 1
            total += before.st_size
            if (count > RESOURCE_POLICY["max_copy_files"]
                    or total > RESOURCE_POLICY["max_copy_bytes"]
                    or before.st_size > RESOURCE_POLICY["max_file_size_bytes"]):
                raise RuntimeError("TEST_WORKSPACE_COPY_LIMIT")
            out = target_dir / name
            source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            target_fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                opened = os.fstat(source_fd)
                if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                        opened.st_mode, opened.st_nlink) != (
                        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                        before.st_mode, before.st_nlink):
                    raise RuntimeError("TEST_WORKSPACE_SOURCE_CHANGED")
                copied = 0
                while True:
                    data = os.read(source_fd, 65536)
                    if not data:
                        break
                    copied += len(data)
                    if copied > RESOURCE_POLICY["max_file_size_bytes"]:
                        raise RuntimeError("TEST_WORKSPACE_COPY_LIMIT")
                    view = memoryview(data)
                    while view:
                        view = view[os.write(target_fd, view):]
                after = os.fstat(source_fd)
                if (copied != before.st_size or after.st_size != before.st_size
                        or after.st_mtime_ns != before.st_mtime_ns):
                    raise RuntimeError("TEST_WORKSPACE_SOURCE_CHANGED")
            finally:
                os.close(source_fd)
                os.close(target_fd)
            os.chmod(out, stat.S_IMODE(before.st_mode) & 0o777)
    for current, dirs, names in os.walk(dest):
        os.chmod(current, (Path(current).stat().st_mode & 0o777) | 0o700)
        for name in names:
            path = Path(current) / name
            os.chmod(path, (path.stat().st_mode & 0o777) | 0o600)
            os.chown(path, 65534, 65534)
        os.chown(current, 65534, 65534)


def _start_cgroup(rootfs, policy=RESOURCE_POLICY, scope_name=None):
    mountpoint = rootfs.parent / "cgroup"
    mountpoint.mkdir(mode=0o700)
    _mount("none", mountpoint, "cgroup2")
    if scope_name is not None and not re.fullmatch(r"freeagentos-worker-[0-9a-f]{32}", scope_name):
        raise RuntimeError("INVALID_CGROUP_SCOPE_NAME")
    scope = mountpoint / (scope_name or "freeagentos-" + uuid.uuid4().hex)
    scope.mkdir(mode=0o700)
    try:
        settings = {
            "memory.max": policy["memory_limit_bytes"],
            "memory.swap.max": policy["swap_limit_bytes"],
            "memory.oom.group": 1,
            "pids.max": policy["max_processes"],
            "cpu.max": f'{policy["cpu_quota_us"]} {policy["cpu_period_us"]}',
        }
        for name, value in settings.items():
            path = scope / name
            if not path.exists():
                raise RuntimeError("REQUIRED_CGROUP_CONTROL_UNAVAILABLE:" + name)
            path.write_text(str(value))
            if path.read_text().strip() != str(value):
                raise RuntimeError("CGROUP_CONTROL_NOT_APPLIED:" + name)
        if not (scope / "cgroup.kill").exists():
            raise RuntimeError("CGROUP_KILL_UNAVAILABLE")
    except Exception:
        scope.rmdir()
        _umount(mountpoint)
        mountpoint.rmdir()
        raise
    return mountpoint, scope


def _apply_child_limits(scope, timeout):
    (scope / "cgroup.procs").write_text(str(os.getpid()))
    cpu_seconds = min(timeout, RESOURCE_POLICY["cpu_time_seconds"])
    for kind, soft, hard in (
        (resource.RLIMIT_CPU, cpu_seconds, cpu_seconds + 1),
        (resource.RLIMIT_AS, 384 * MIB, 384 * MIB),
        (resource.RLIMIT_NPROC, 64, 64),
        (resource.RLIMIT_NOFILE, RESOURCE_POLICY["max_open_files"], RESOURCE_POLICY["max_open_files"]),
        (resource.RLIMIT_FSIZE, RESOURCE_POLICY["max_file_size_bytes"], RESOURCE_POLICY["max_file_size_bytes"]),
        (resource.RLIMIT_CORE, 0, 0),
    ):
        resource.setrlimit(kind, (soft, hard))


def _read_bounded(proc, seconds, capture):
    """Keep draining while the direct process runs; orphan pipes never hang us."""
    descriptor = proc.stdout.fileno()
    os.set_blocking(descriptor, False)
    deadline = time.monotonic() + seconds
    with selectors.DefaultSelector() as selector:
        selector.register(descriptor, selectors.EVENT_READ)
        eof = False
        while time.monotonic() < deadline:
            if eof:
                if proc.poll() is not None:
                    return False
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
                continue
            events = selector.select(min(0.05, max(0, deadline - time.monotonic())))
            if events:
                try:
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    chunk = None
                if chunk == b"":
                    selector.unregister(descriptor)
                    eof = True
                    continue
                if chunk:
                    capture.add(chunk)
            elif proc.poll() is not None:
                return False
        return proc.poll() is None


def _drain_ready(proc, capture):
    while True:
        try:
            chunk = os.read(proc.stdout.fileno(), 65536)
        except BlockingIOError:
            return
        if not chunk:
            return
        capture.add(chunk)


def _scope_pids(scope):
    return [int(value) for value in (scope / "cgroup.procs").read_text().split()]


def _stop_scope(scope, proc, grace):
    pids = _scope_pids(scope)
    termination_signal = "NONE"
    forced = False
    if pids:
        termination_signal = "SIGTERM"
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and _scope_pids(scope):
            time.sleep(0.02)
    if _scope_pids(scope):
        termination_signal = "SIGKILL"
        forced = True
        (scope / "cgroup.kill").write_text("1")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and _scope_pids(scope):
            time.sleep(0.02)
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        forced = True
        termination_signal = "SIGKILL"
        (scope / "cgroup.kill").write_text("1")
        proc.wait(timeout=2)
    return {"termination_signal": termination_signal, "forced_kill_used": forced,
            "remaining_processes": len(_scope_pids(scope))}


def _event_values(path):
    return {key: int(value) for key, value in (line.split() for line in path.read_text().splitlines())
            if value.isdigit()}


def _setup_and_exec(rootfs, workspace, venv):
    """Trusted PID-namespace init: own the cgroup, lease and complete cleanup."""
    rootfs, workspace, venv = Path(rootfs), Path(workspace), Path(venv)
    timeout = int(os.environ.get("FREEAGENT_SANDBOX_TIMEOUT", "150"))
    timeout = min(timeout, RESOURCE_POLICY["wall_timeout_seconds"])
    _mount(None, "/", flags=MS_REC | MS_PRIVATE)
    _mount("/usr", rootfs / "usr", flags=MS_BIND | MS_REC)
    _mount(None, rootfs / "usr", flags=MS_BIND | MS_REMOUNT | MS_RDONLY)
    _mount(venv, rootfs / "opt/freeagent/venv", flags=MS_BIND | MS_REC)
    _mount(None, rootfs / "opt/freeagent/venv", flags=MS_BIND | MS_REMOUNT | MS_RDONLY)
    for name, size, mode in (("workspace", RESOURCE_POLICY["test_workspace_bytes"], 0o755),
                             ("tmp", 64 * MIB, 0o1777), ("root", 8 * MIB, 0o700),
                             ("home", 16 * MIB, 0o755), ("run", 8 * MIB, 0o755),
                             ("var", 16 * MIB, 0o755), ("dev/shm", 16 * MIB, 0o1777)):
        target = rootfs / name
        _mount("tmpfs", target, "tmpfs", data=f"size={size},nr_inodes=20000,mode={mode:o}")
        os.chmod(target, mode)
    _safe_copy(workspace, rootfs / "workspace", mounted=True)
    (rootfs / "root/agent-stack").mkdir(parents=True, exist_ok=True)
    (rootfs / "home/freeagent").mkdir(parents=True, exist_ok=True)
    (rootfs / "var/tmp").mkdir(parents=True, exist_ok=True)
    os.chown(rootfs / "home/freeagent", 65534, 65534)
    os.chown(rootfs / "var/tmp", 65534, 65534)
    for name, major, minor in (("null", 1, 3), ("zero", 1, 5), ("random", 1, 8), ("urandom", 1, 9)):
        device = rootfs / "dev" / name
        os.mknod(device, stat.S_IFCHR | 0o666, os.makedev(major, minor))
        os.chmod(device, 0o666)

    mountpoint, scope = _start_cgroup(rootfs)
    capture = BoundedCapture(RESOURCE_POLICY["max_output_bytes"])
    process = None
    cleanup = {"cleanup_status": "UNCERTAIN", "remaining_processes": None}
    try:
        python_rel = Path("lib") / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
        env = ["/usr/bin/env", "-i", "HOME=/home/freeagent", "TMPDIR=/tmp", "PATH=/usr/bin:/bin",
               "PYTHONDONTWRITEBYTECODE=1", "PYTHONPATH=" + str(Path("/opt/freeagent/venv") / python_rel)]
        command = ["/usr/sbin/chroot", "--userspec=65534:65534", str(rootfs), *env,
                   "/usr/bin/python3", "-c",
                   "import os,runpy; os.chdir('/workspace'); runpy.run_path('/opt/freeagent/freeagent-test', run_name='__main__')"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True, preexec_fn=lambda: _apply_child_limits(scope, timeout))
        timeout_triggered = _read_bounded(process, timeout, capture)
        cleanup = _stop_scope(scope, process, RESOURCE_POLICY["termination_grace_seconds"])
        _drain_ready(process, capture)
        memory_events = _event_values(scope / "memory.events")
        pid_events = _event_values(scope / "pids.events")
        disk = os.statvfs(rootfs / "workspace")
        hits = {"memory": bool(memory_events.get("oom", 0) or memory_events.get("oom_kill", 0)),
                "process_count": bool(pid_events.get("max", 0)),
                "disk": disk.f_bavail == 0 or disk.f_favail == 0}
        output = capture.render().decode("utf-8", "replace")
        output_truncated = capture.truncated or "OUTPUT_TRUNCATED=true" in output
        if timeout_triggered:
            output += "\nRESULT=TIMEOUT\nEXIT_CODE=124\n"
        elif any(hits.values()) or output_truncated:
            output += "\nRESULT=RESOURCE_LIMIT\nEXIT_CODE=1\n"
        if timeout_triggered:
            exit_code = 124
        elif any(hits.values()) or output_truncated:
            exit_code = 1
        else:
            exit_code = process.returncode
        evidence = {**cleanup, "cleanup_status": "CONFIRMED" if cleanup["remaining_processes"] == 0 else "UNCERTAIN",
                    "timeout_triggered": timeout_triggered, "output_truncated": output_truncated,
                    "output_total_bytes": capture.total_bytes, "resource_hits": hits,
                    "cgroup_status": "ENFORCED",
                    "controls": {name: "ENFORCED" for name in REQUIRED_CONTROLS}}
        return {"exit_code": exit_code, "output": output, "evidence": evidence}
    finally:
        if process is not None and process.poll() is None:
            (scope / "cgroup.kill").write_text("1")
            process.wait(timeout=2)
        if _scope_pids(scope):
            raise RuntimeError("SANDBOX_PROCESSES_REMAIN")
        scope.rmdir()
        _umount(mountpoint)
        mountpoint.rmdir()


def run_isolated(workspace, run_dir, runner_sha256, timeout=150):
    control = Path(run_dir) / "controller"
    test_area = Path(tempfile.mkdtemp(prefix="test-copy-", dir=control))
    try:
        return _run_isolated_in_area(workspace, run_dir, runner_sha256, timeout, test_area)
    finally:
        if test_area.exists() and shutil.rmtree.avoids_symlink_attacks:
            # The sandbox runs as nobody and may leave directories owned by
            # that uid. Reclaim only this controller-created temporary tree;
            # do not follow links while walking it.
            for current, dirs, files in os.walk(test_area, topdown=True, followlinks=False):
                current_path = Path(current)
                for name in dirs:
                    path = current_path / name
                    if not path.is_symlink():
                        os.chown(path, 0, 0)
                        os.chmod(path, 0o700)
                for name in files:
                    path = current_path / name
                    if not path.is_symlink():
                        os.chown(path, 0, 0)
                        os.chmod(path, 0o600)
            os.chown(test_area, 0, 0)
            os.chmod(test_area, 0o700)
            shutil.rmtree(test_area)


def _run_isolated_in_area(workspace, run_dir, runner_sha256, timeout, test_area):
    run_dir = Path(run_dir)
    control = run_dir / "controller"
    runner = control / "freeagent-test"
    raw = runner.read_bytes()
    if hashlib.sha256(raw).hexdigest() != runner_sha256:
        raise RuntimeError("VERIFICATION_RUNNER_CHANGED")
    rootfs = test_area / "rootfs"
    rootfs.mkdir(mode=0o755)
    for name in ("usr", "tmp", "root", "home", "run", "var", "dev", "dev/shm", "proc", "workspace", "etc", "opt/freeagent/venv"):
        (rootfs / name).mkdir(parents=True, exist_ok=True)
    for name, target in (("bin", "usr/bin"), ("sbin", "usr/sbin"), ("lib", "usr/lib"), ("lib64", "usr/lib64")):
        (rootfs / name).symlink_to(target)
    (rootfs / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/home/nobody:/bin/sh\n")
    (rootfs / "etc/group").write_text("root:x:0:\nnogroup:x:65534:\n")
    (rootfs / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files\n")
    (rootfs / "etc/hosts").write_text("127.0.0.1 localhost\n::1 localhost\n")
    (rootfs / "opt/freeagent/freeagent-test").write_bytes(raw)
    os.chmod(rootfs / "opt/freeagent/freeagent-test", 0o444)
    os.chmod(rootfs / "opt/freeagent", 0o555)
    python_prefix = Path(sys.prefix)
    if not python_prefix.is_dir():
        raise RuntimeError("TEST_RUNTIME_UNAVAILABLE")

    cmd = ["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=SIGKILL", "--propagation", "private",
           "--mount-proc=" + str(rootfs / "proc"), sys.executable,
           str(ROOT / "orchestrator/roles/sandbox.py"), "--enter",
           str(rootfs), str(workspace), str(python_prefix)]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "PYTHONDONTWRITEBYTECODE": "1", "FREEAGENT_SANDBOX_TIMEOUT": str(timeout)}
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True, env=env)
    capture = BoundedCapture(96 * 1024)
    try:
        emergency_timeout = _read_bounded(process, min(timeout, RESOURCE_POLICY["wall_timeout_seconds"]) + 12, capture)
        if emergency_timeout:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
            raise RuntimeError("ISOLATED_TEST_TIMEOUT_CLEANUP_UNPROVEN")
        process.wait(timeout=3)
        _drain_ready(process, capture)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        process.stdout.close()
    output = capture.render().decode("utf-8", "replace")
    evidence_lines = [line for line in output.splitlines() if line.startswith(EVIDENCE_PREFIX)]
    if not evidence_lines:
        raise SandboxBoundaryError("ISOLATED_SANDBOX_EVIDENCE_MISSING", _unavailable_evidence("EVIDENCE_MISSING"))
    try:
        evidence = json.loads(evidence_lines[-1][len(EVIDENCE_PREFIX):])
    except (ValueError, TypeError) as exc:
        raise SandboxBoundaryError("ISOLATED_SANDBOX_EVIDENCE_INVALID", _unavailable_evidence("EVIDENCE_INVALID")) from exc
    if (evidence.get("cleanup_status") != "CONFIRMED" or evidence.get("remaining_processes") != 0
            or evidence.get("cgroup_status") != "ENFORCED"
            or any(evidence.get("controls", {}).get(name) != "ENFORCED" for name in REQUIRED_CONTROLS)):
        raise SandboxBoundaryError("ISOLATED_SANDBOX_BOUNDARY_UNVERIFIED", evidence)
    output = "\n".join(line for line in output.splitlines() if not line.startswith(EVIDENCE_PREFIX))
    markers = [line for line in output.splitlines() if line.startswith("RESULT=")]
    if process.returncode not in (0, 1, 3, 124) or not markers:
        raise RuntimeError("ISOLATED_SANDBOX_SETUP_FAILED")
    return {"exit_code": process.returncode, "output": output,
            "result": markers[-1].partition("=")[2] if markers else "MISSING_RESULT",
            "isolated": process.returncode in (0, 1, 3, 124) and "RESULT=" in output,
            "evidence": evidence}


if __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--enter":
    try:
        result = _setup_and_exec(*sys.argv[2:])
        sys.stdout.write(result["output"])
        sys.stdout.write("\n" + EVIDENCE_PREFIX + json.dumps(result["evidence"], sort_keys=True) + "\n")
        sys.stdout.flush()
        sys.exit(result["exit_code"])
    except Exception as exc:
        code = str(exc).split(":", 1)[0] if isinstance(exc, RuntimeError) else type(exc).__name__
        sys.stderr.write("ISOLATED_SANDBOX_SETUP_FAILED:" + code + "\n")
        sys.stdout.write(EVIDENCE_PREFIX + json.dumps(_unavailable_evidence(code), sort_keys=True) + "\n")
        sys.stdout.flush()
        sys.exit(125)
