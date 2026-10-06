"""Run target tests in a networkless chroot with only disposable target files."""

import ctypes
import errno
import hashlib
import json
import math
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


# Optional fixture diagnostics are observations, never boundary/cleanup proof.
DISK_DIAGNOSTIC_FILE = "freeagent-disk-progress.jsonl"
DIAGNOSTIC_BYTES = 8192
DIAGNOSTIC_RECORDS = 40
RETENTION_BYTES = 32 * 1024
RETENTION_RECORDS = DIAGNOSTIC_RECORDS
RETENTION_FILE_PREFIX = "disk-diagnostic-"
CPU_DIAGNOSTIC_KEYS = ("usage_usec", "user_usec", "system_usec", "nr_periods",
                       "nr_throttled", "throttled_usec")


def _diagnostic_read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > DIAGNOSTIC_BYTES:
            raise ValueError("DIAGNOSTIC_BOUNDS")
        data = os.read(descriptor, DIAGNOSTIC_BYTES + 1)
        if len(data) > DIAGNOSTIC_BYTES:
            raise ValueError("DIAGNOSTIC_BOUNDS")
        return data.decode("ascii")
    finally:
        os.close(descriptor)


def _disk_sample(scope, workspace):
    try:
        values = dict(line.split() for line in _diagnostic_read(scope / "cpu.stat").splitlines())
        cpu = {key: int(values[key]) for key in CPU_DIAGNOSTIC_KEYS}
        if any(value < 0 or value >= 2 ** 63 for value in cpu.values()):
            raise ValueError("DIAGNOSTIC_BOUNDS")
        disk = os.statvfs(workspace)
        return {"status": "OBSERVED", "monotonic": time.monotonic(), "cpu_stat": cpu,
                "available_bytes": disk.f_bavail * disk.f_frsize,
                "available_inodes": disk.f_favail}
    except (OSError, ValueError, KeyError, UnicodeError):
        return {"status": "UNAVAILABLE"}


def _disk_progress(rootfs):
    try:
        text = _diagnostic_read(rootfs / "tmp" / DISK_DIAGNOSTIC_FILE)
        if not text.endswith("\n"):
            raise ValueError("DIAGNOSTIC_PARTIAL")
        lines = text.splitlines()
        if not 1 <= len(lines) <= DIAGNOSTIC_RECORDS:
            raise ValueError("DIAGNOSTIC_BOUNDS")
        records = []
        for line in lines:
            record = json.loads(line)
            legacy = set(record) == {"phase", "monotonic", "written_bytes"}
            phased = set(record) == {"phase", "monotonic", "written_bytes", "demand", "category"}
            phases = ("test_start", "write", "complete", "write_error")
            allocation_phases = ("reservation_before", "reservation_after", "fallback_before", "fallback_after")
            if (not (legacy or phased)
                    or record["phase"] not in phases + (allocation_phases if phased else ())
                    or phased and (type(record["demand"]) is not int or not 0 <= record["demand"] <= 6
                                   or record["category"] not in ("NONE", "OK", "ENOSPC", "UNSUPPORTED", "UNEXPECTED", "INVALID"))
                    or type(record["monotonic"]) not in (int, float)
                    or not 0 <= record["monotonic"] < 2 ** 63
                    or type(record["written_bytes"]) is not int
                    or not 0 <= record["written_bytes"] <= 360 * MIB
                    or records and (record["monotonic"] < records[-1]["monotonic"]
                                    or record["written_bytes"] < records[-1]["written_bytes"])):
                raise ValueError("DIAGNOSTIC_INVALID")
            records.append(record)
        return {"status": "CHILD_REPORTED", "records": records}
    except (OSError, ValueError, TypeError, UnicodeError):
        return {"status": "MISSING_OR_INVALID"}


class _DiagnosticRetentionError(ValueError):
    """A fixed, safe diagnostic-retention failure code."""

    def __init__(self, code, artifact=None):
        super().__init__(code)
        self.code = code
        self.artifact = artifact


def _retention_error(code, artifact=None):
    raise _DiagnosticRetentionError(code, artifact)


def _retention_integer(value, *, maximum=2 ** 63 - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        _retention_error("DIAGNOSTIC_VALUE_INVALID")
    return value


def _retention_number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value < 2 ** 63:
        _retention_error("DIAGNOSTIC_VALUE_INVALID")
    return value


def _retention_sample(sample):
    if type(sample) is not dict or sample.get("status") not in ("OBSERVED", "UNAVAILABLE"):
        _retention_error("DIAGNOSTIC_SAMPLE_INVALID")
    if sample["status"] == "UNAVAILABLE":
        return {"status": "UNAVAILABLE"}
    cpu_stat = sample.get("cpu_stat")
    if type(cpu_stat) is not dict:
        _retention_error("DIAGNOSTIC_SAMPLE_INVALID")
    return {
        "status": "OBSERVED",
        "monotonic": _retention_number(sample.get("monotonic")),
        "cpu_stat": {key: _retention_integer(cpu_stat.get(key)) for key in CPU_DIAGNOSTIC_KEYS},
        "available_bytes": _retention_integer(sample.get("available_bytes")),
        "available_inodes": _retention_integer(sample.get("available_inodes")),
    }


def _retention_cpu_delta(delta):
    if delta is None:
        return None
    if type(delta) is not dict:
        _retention_error("DIAGNOSTIC_CPU_DELTA_INVALID")
    return {key: _retention_integer(delta.get(key)) for key in CPU_DIAGNOSTIC_KEYS}


def _retention_progress(progress):
    if type(progress) is not dict or progress.get("status") not in ("CHILD_REPORTED", "MISSING_OR_INVALID"):
        _retention_error("DIAGNOSTIC_PROGRESS_INVALID")
    if progress["status"] == "MISSING_OR_INVALID":
        return {"status": "MISSING_OR_INVALID"}
    records = progress.get("records")
    if type(records) is not list or not 1 <= len(records) <= RETENTION_RECORDS:
        _retention_error("DIAGNOSTIC_PROGRESS_INVALID")
    retained = []
    for record in records:
        if type(record) is not dict:
            _retention_error("DIAGNOSTIC_PROGRESS_INVALID")
        phased = set(record) == {"phase", "monotonic", "written_bytes", "demand", "category"}
        legacy = set(record) == {"phase", "monotonic", "written_bytes"}
        allowed_phases = ("test_start", "write", "complete", "write_error")
        allocation_phases = ("reservation_before", "reservation_after",
                             "fallback_before", "fallback_after")
        if not (phased or legacy) or record.get("phase") not in (
                allowed_phases + (allocation_phases if phased else ())):
            _retention_error("DIAGNOSTIC_PROGRESS_INVALID")
        if phased and (type(record.get("demand")) is not int
                       or not 0 <= record["demand"] <= 6
                       or record.get("category") not in ("NONE", "OK", "ENOSPC",
                                                          "UNSUPPORTED", "UNEXPECTED", "INVALID")):
            _retention_error("DIAGNOSTIC_PROGRESS_INVALID")
        retained_record = {
            "phase": record["phase"],
            "monotonic": _retention_number(record.get("monotonic")),
            "written_bytes": _retention_integer(record.get("written_bytes"),
                                                 maximum=360 * MIB),
        }
        if phased:
            retained_record.update(demand=record["demand"], category=record["category"])
        if retained and (retained_record["monotonic"] < retained[-1]["monotonic"]
                         or retained_record["written_bytes"] < retained[-1]["written_bytes"]):
            _retention_error("DIAGNOSTIC_PROGRESS_INVALID")
        retained.append(retained_record)
    return {"status": "CHILD_REPORTED", "records": retained}


def _retention_memory_readings(readings):
    if type(readings) is not list or len(readings) != len(MEMORY_DIAGNOSTIC_FILES):
        _retention_error("DIAGNOSTIC_MEMORY_INVALID")
    expected = {name: (kind, keys) for name, kind, keys in MEMORY_DIAGNOSTIC_FILES}
    retained = []
    seen = set()
    for reading in readings:
        if type(reading) is not dict:
            _retention_error("DIAGNOSTIC_MEMORY_INVALID")
        name = reading.get("file")
        if name in seen or name not in expected or reading.get("kind") != expected[name][0]:
            _retention_error("DIAGNOSTIC_MEMORY_INVALID")
        status = reading.get("status")
        if status not in ("OBSERVED", "UNAVAILABLE"):
            _retention_error("DIAGNOSTIC_MEMORY_INVALID")
        retained_reading = {
            "file": name,
            "kind": reading["kind"],
            "start": _retention_number(reading.get("start")),
            "end": _retention_number(reading.get("end")),
            "status": status,
        }
        if retained_reading["end"] < retained_reading["start"]:
            _retention_error("DIAGNOSTIC_MEMORY_INVALID")
        if status == "UNAVAILABLE":
            if reading.get("values") is not None:
                _retention_error("DIAGNOSTIC_MEMORY_INVALID")
            retained_reading["values"] = None
        else:
            values = reading.get("values")
            if type(values) is not dict:
                _retention_error("DIAGNOSTIC_MEMORY_INVALID")
            keys = expected[name][1]
            if keys is None:
                value = values.get("value")
                if name == "memory.oom.group":
                    value = _retention_integer(value, maximum=1)
                elif value != "max":
                    value = _retention_integer(value)
                retained_reading["values"] = {"value": value}
            elif name == "memory.pressure":
                retained_reading["values"] = {
                    key: (None if values.get(key) is None else _retention_integer(values[key]))
                    for key in keys
                }
            else:
                retained_reading["values"] = {
                    key: (None if values.get(key) is None else _retention_integer(values[key]))
                    for key in keys
                }
        retained.append(retained_reading)
        seen.add(name)
    if seen != set(expected):
        _retention_error("DIAGNOSTIC_MEMORY_INVALID")
    return retained


def _retention_memory_deltas(deltas):
    if type(deltas) is not dict:
        _retention_error("DIAGNOSTIC_MEMORY_INVALID")
    retained = {}
    for name, keys in (("memory.stat", MEMORY_COUNTERS),
                       ("memory.events", MEMORY_EVENTS),
                       ("memory.events.local", MEMORY_EVENTS),
                       ("memory.pressure", ("some", "full"))):
        values = deltas.get(name)
        if type(values) is not dict:
            _retention_error("DIAGNOSTIC_MEMORY_INVALID")
        retained[name] = {
            key: (None if values.get(key) is None else _retention_integer(values[key]))
            for key in keys
        }
    return retained


def _retention_diagnostic(diagnostic):
    if (type(diagnostic) is not dict
            or type(diagnostic.get("schema_version")) is not int
            or diagnostic["schema_version"] != 1):
        _retention_error("DIAGNOSTIC_OBJECT_INVALID")
    phases = diagnostic.get("phases")
    phase_names = ("setup_start", "setup_complete", "launch_start", "launch_return",
                   "wait_return", "result_collection")
    if type(phases) is not dict or any(name not in phases for name in phase_names):
        _retention_error("DIAGNOSTIC_PHASES_INVALID")
    memory = diagnostic.get("memory")
    if type(memory) is not dict:
        _retention_error("DIAGNOSTIC_MEMORY_INVALID")
    return {
        "schema_version": 1,
        "authority": "NONE",
        "phases": {name: _retention_number(phases[name]) for name in phase_names},
        "before": _retention_sample(diagnostic.get("before")),
        "after": _retention_sample(diagnostic.get("after")),
        "cpu_delta": _retention_cpu_delta(diagnostic.get("cpu_delta")),
        "progress": _retention_progress(diagnostic.get("progress")),
        "memory": {
            "before": _retention_memory_readings(memory.get("before")),
            "after": _retention_memory_readings(memory.get("after")),
            "deltas": _retention_memory_deltas(memory.get("deltas")),
        },
    }


class _RetentionDirectory:
    def __init__(self, descriptors, path, *, created=False, private=True):
        self.descriptors = descriptors
        self.descriptor = descriptors[-1]
        self.path = path
        self.created = created
        self.private = private
        self.identities = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                           for fd in descriptors]

    def close(self):
        descriptors, self.descriptors = self.descriptors, []
        self.descriptor = None
        error = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as caught:
                error = caught
        if error is not None:
            _retention_error("DIAGNOSTIC_DIRECTORY_CLOSE_FAILED")


def _retention_absolute_path(destination):
    if not isinstance(destination, (str, bytes, os.PathLike)):
        _retention_error("DIAGNOSTIC_DESTINATION_TYPE_INVALID")
    try:
        value = os.fspath(destination)
        if isinstance(value, bytes):
            value = os.fsdecode(value)
        if not value:
            _retention_error("DIAGNOSTIC_DESTINATION_INVALID")
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            _retention_error("DIAGNOSTIC_DESTINATION_UNSAFE")
        return path
    except (OSError, TypeError, ValueError):
        _retention_error("DIAGNOSTIC_DESTINATION_INVALID")


def _retention_directory_info(info, *, private=False):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
        _retention_error("DIAGNOSTIC_DESTINATION_UNSAFE")
    if private:
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            _retention_error("DIAGNOSTIC_DESTINATION_UNSAFE")
    elif (info.st_mode & 0o022
          and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
        # Root-owned sticky temporary roots are safe ancestors, not private
        # destinations. Untrusted owners and other shared writers are rejected.
        _retention_error("DIAGNOSTIC_DESTINATION_UNSAFE")


def _check_retention_directory(directory):
    parts = directory.path.parts[1:]
    for index, descriptor in enumerate(directory.descriptors):
        held = os.fstat(descriptor)
        _retention_directory_info(held, private=directory.private and
                                  index == len(directory.descriptors) - 1)
        if (held.st_dev, held.st_ino) != directory.identities[index]:
            _retention_error("DIAGNOSTIC_DESTINATION_REPLACED")
        if index:
            visible = os.stat(parts[index - 1], dir_fd=directory.descriptors[index - 1],
                              follow_symlinks=False)
            if (not stat.S_ISDIR(visible.st_mode)
                    or (visible.st_dev, visible.st_ino) != directory.identities[index]):
                _retention_error("DIAGNOSTIC_DESTINATION_REPLACED")


def _open_private_retention_directory(destination, *, private=True):
    """Hold the no-follow ancestor chain as well as the validated leaf."""
    path = _retention_absolute_path(destination)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors = []
    try:
        descriptors.append(os.open(os.sep, flags))
        _retention_directory_info(os.fstat(descriptors[-1]))
        for component in path.parts[1:]:
            descriptors.append(os.open(component, flags, dir_fd=descriptors[-1]))
            _retention_directory_info(os.fstat(descriptors[-1]))
        directory = _RetentionDirectory(descriptors, path, private=private)
        _check_retention_directory(directory)
        return directory
    except _DiagnosticRetentionError:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise
    except OSError as error:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if error.errno in (errno.ENOTDIR, errno.ELOOP):
            _retention_error("DIAGNOSTIC_DESTINATION_UNSAFE")
        _retention_error("DIAGNOSTIC_DESTINATION_INVALID")
    except (TypeError, ValueError):
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        _retention_error("DIAGNOSTIC_DESTINATION_INVALID")


def _retention_destination():
    configured = os.environ.get("FREEAGENT_CONTROLLER_PROGRESS_DIR")
    if configured is not None:
        return _open_private_retention_directory(configured)
    parent = _open_private_retention_directory(tempfile.gettempdir(), private=False)
    created = False
    try:
        _check_retention_directory(parent)
        name = "freeagent-disk-diagnostics-" + uuid.uuid4().hex
        os.mkdir(name, mode=0o700, dir_fd=parent.descriptor)
        created = True
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent.descriptor)
        parent.descriptors.append(child)
        parent.descriptor = child
        parent.identities.append((os.fstat(child).st_dev, os.fstat(child).st_ino))
        parent.path = parent.path / name
        parent.private = parent.created = True
        _check_retention_directory(parent)
        return parent
    except (OSError, ValueError, TypeError):
        parent.close()
        # Never remove a fallback directory by a re-resolved pathname. Even an
        # empty, newly created directory remains explicitly scoped on failure.
        artifact = {"partial_file": "NOT_CREATED",
                    "fallback_directory": "RETAINED" if created else "NOT_CREATED"}
        _retention_error("DIAGNOSTIC_DESTINATION_CREATE_FAILED", artifact)


def _retention_object_identity(descriptor):
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        _retention_error("DIAGNOSTIC_RETENTION_OBJECT_UNSAFE")
    return info.st_dev, info.st_ino


def _remove_partial_retention(directory, name, identity, *, links=1):
    try:
        info = os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
        if (identity is None or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != links
                or (info.st_dev, info.st_ino) != identity):
            return "RETAINED"
        os.unlink(name, dir_fd=directory.descriptor)
        return "REMOVED"
    except FileNotFoundError:
        return "ABSENT"
    except OSError:
        return "RETAINED"


def _failure_artifact(directory, name, identity):
    partial = _remove_partial_retention(directory, name, identity)
    return {"partial_file": partial,
            "fallback_directory": "RETAINED" if directory.created else "NOT_CREATED"}


def _retention_payload_bytes(payload):
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    if len(raw) > RETENTION_BYTES:
        _retention_error("DIAGNOSTIC_RETENTION_BOUNDS")
    return raw


def _write_retention_payload(raw, invocation_id, directory):
    final_name = RETENTION_FILE_PREFIX + invocation_id + ".json"
    partial_name = final_name + ".partial"
    descriptor = None
    identity = None
    created = False
    try:
        _check_retention_directory(directory)
        descriptor = os.open(partial_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                             dir_fd=directory.descriptor)
        created = True
        identity = _retention_object_identity(descriptor)
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:])
            if count <= 0:
                raise OSError("DIAGNOSTIC_RETENTION_WRITE_FAILED")
            offset += count
    except FileExistsError:
        _retention_error("DIAGNOSTIC_DESTINATION_EXISTS")
    except _DiagnosticRetentionError as error:
        artifact = (_failure_artifact(directory, partial_name, identity)
                    if created else {"partial_file": "NOT_CREATED",
                                     "fallback_directory": "RETAINED" if directory.created
                                     else "NOT_CREATED"})
        _retention_error(error.code, artifact)
    except (OSError, TypeError, ValueError):
        artifact = (_failure_artifact(directory, partial_name, identity)
                    if created else {"partial_file": "NOT_CREATED",
                                     "fallback_directory": "RETAINED" if directory.created
                                     else "NOT_CREATED"})
        _retention_error("DIAGNOSTIC_RETENTION_WRITE_FAILED", artifact)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                if identity is not None:
                    artifact = _failure_artifact(directory, partial_name, identity)
                    _retention_error("DIAGNOSTIC_RETENTION_CLOSE_FAILED", artifact)
    try:
        _check_retention_directory(directory)
        info = os.stat(partial_name, dir_fd=directory.descriptor, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or (info.st_dev, info.st_ino) != identity or info.st_size != len(raw)):
            _retention_error("DIAGNOSTIC_RETENTION_OBJECT_REPLACED")
        os.link(partial_name, final_name, src_dir_fd=directory.descriptor,
                dst_dir_fd=directory.descriptor, follow_symlinks=False)
    except FileExistsError:
        artifact = _failure_artifact(directory, partial_name, identity)
        _retention_error("DIAGNOSTIC_DESTINATION_EXISTS", artifact)
    except _DiagnosticRetentionError as error:
        artifact = _failure_artifact(directory, partial_name, identity)
        _retention_error(error.code, artifact)
    except (OSError, TypeError, ValueError):
        artifact = _failure_artifact(directory, partial_name, identity)
        _retention_error("DIAGNOSTIC_RETENTION_PUBLISH_FAILED", artifact)
    temporary_alias = _remove_partial_retention(directory, partial_name, identity, links=2)
    return {"status": "RETAINED", "path": str(directory.path / final_name),
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "invocation_id": invocation_id, "temporary_alias": temporary_alias}


def _retention_invocation_id(value=None):
    value = uuid.uuid4().hex if value is None else value
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{32}", value):
        _retention_error("DIAGNOSTIC_INVOCATION_INVALID")
    return value


def _retain_disk_diagnostics(result, runner_sha256, timeout, destination=None, invocation_id=None):
    """Exclusively retain a bounded projection before the fixture sees result.

    The input is existing controller evidence. Only fixed fields are copied;
    child progress remains explicitly CHILD_REPORTED and never becomes authority.
    """
    if type(result) is not dict or type(result.get("evidence")) is not dict:
        _retention_error("DIAGNOSTIC_RESULT_INVALID")
    if type(runner_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", runner_sha256):
        _retention_error("DIAGNOSTIC_INVOCATION_INVALID")
    if type(timeout) is not int or not 0 <= timeout <= RESOURCE_POLICY["wall_timeout_seconds"]:
        _retention_error("DIAGNOSTIC_INVOCATION_INVALID")
    invocation_id = _retention_invocation_id(invocation_id)
    exit_code = result.get("exit_code")
    if type(exit_code) is not int or not 0 <= exit_code <= 255:
        _retention_error("DIAGNOSTIC_RESULT_INVALID")
    if result.get("result") not in ("PASS", "FAIL", "RESOURCE_LIMIT", "TIMEOUT"):
        _retention_error("DIAGNOSTIC_RESULT_INVALID")
    if type(result.get("isolated")) is not bool:
        _retention_error("DIAGNOSTIC_RESULT_INVALID")
    diagnostic = _retention_diagnostic(result["evidence"].get("disk_diagnostics"))
    payload = {
        "schema_version": 1,
        "invocation": {"id": invocation_id, "pid": os.getpid(),
                        "runner_sha256": runner_sha256, "timeout_seconds": timeout},
        "authority": {"controller_observations": "CONTROLLER_OBSERVED",
                       "child_progress": "CHILD_REPORTED", "qualification": "NONE"},
        "outcome": {"exit_code": exit_code, "result": result["result"],
                    "isolated": result["isolated"]},
        "diagnostic": diagnostic,
    }
    raw = _retention_payload_bytes(payload)
    directory = (_open_private_retention_directory(destination)
                 if destination is not None else _retention_destination())
    try:
        report = _write_retention_payload(raw, invocation_id, directory)
    finally:
        directory.close()
    records = diagnostic["progress"].get("records", [])
    report.update(records=len(records), authority="CONTROLLER_OBSERVED/CHILD_REPORTED")
    return report


def _retain_post_evidence_guard(metadata, runner_sha256, timeout, destination=None):
    if type(metadata) is not dict:
        _retention_error("DIAGNOSTIC_GUARD_METADATA_INVALID")
    if type(runner_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", runner_sha256):
        _retention_error("DIAGNOSTIC_INVOCATION_INVALID")
    if type(timeout) is not int or not 0 <= timeout <= RESOURCE_POLICY["wall_timeout_seconds"]:
        _retention_error("DIAGNOSTIC_INVOCATION_INVALID")
    invocation_id = _retention_invocation_id()
    payload = {
        "schema_version": 1,
        "kind": "POST_EVIDENCE_RESULT_GUARD",
        "invocation": {"id": invocation_id, "pid": os.getpid(),
                        "runner_sha256": runner_sha256, "timeout_seconds": timeout},
        "authority": "NONE",
        "guard": {
            "child_returncode": metadata.get("child_returncode"),
            "child_pid": metadata.get("child_pid"),
            "marker_present": metadata.get("marker_present"),
            "marker_count": metadata.get("marker_count"),
            "capture_total_bytes": metadata.get("capture_total_bytes"),
            "capture_retained_bytes": metadata.get("capture_retained_bytes"),
            "capture_sha256": metadata.get("capture_sha256"),
            "output_truncated": metadata.get("output_truncated"),
            "branch": metadata.get("branch"),
            "source_sha256": metadata.get("source_sha256", "UNAVAILABLE"),
        },
    }
    raw = _retention_payload_bytes(payload)
    directory = (_open_private_retention_directory(destination)
                 if destination is not None else _retention_destination())
    try:
        return _write_retention_payload(raw, invocation_id, directory)
    finally:
        directory.close()


def _post_evidence_guard(process, capture, output, runner_sha256, timeout,
                         disk_diagnostics):
    markers = [line for line in output.splitlines() if line.startswith("RESULT=")]
    invalid_return = process.returncode not in (0, 1, 3, 124)
    missing_marker = not markers
    branch = ("RETURN_CODE_INVALID_AND_RESULT_MARKER_ABSENT" if invalid_return and missing_marker
              else "RETURN_CODE_INVALID" if invalid_return else "RESULT_MARKER_ABSENT")
    rendered = capture.render()
    try:
        source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        source_sha256 = "UNAVAILABLE"
    metadata = {
        "child_returncode": process.returncode if type(process.returncode) is int else None,
        "child_pid": process.pid if type(process.pid) is int else None,
        "marker_present": bool(markers), "marker_count": len(markers),
        "capture_total_bytes": min(capture.total_bytes, 2 ** 63 - 1),
        "capture_retained_bytes": len(rendered),
        "capture_sha256": hashlib.sha256(rendered).hexdigest(),
        "output_truncated": bool(capture.truncated or "OUTPUT_TRUNCATED=true" in output),
        "branch": branch, "source_sha256": source_sha256,
    }
    if disk_diagnostics is True:
        try:
            _retain_post_evidence_guard(metadata, runner_sha256, timeout)
        except Exception:
            pass
    raise RuntimeError("ISOLATED_SANDBOX_SETUP_FAILED")


def _retention_failure(error):
    if isinstance(error, _DiagnosticRetentionError):
        result = {"status": "ERROR", "code": error.code}
        if error.artifact is not None:
            result["artifact"] = error.artifact
        return result
    return {"status": "ERROR", "code": "DIAGNOSTIC_RETENTION_FAILED"}


def _cpu_delta(before, after):
    if before.get("status") != "OBSERVED" or after.get("status") != "OBSERVED":
        return None
    delta = {key: after["cpu_stat"][key] - before["cpu_stat"][key]
             for key in CPU_DIAGNOSTIC_KEYS}
    return delta if all(value >= 0 for value in delta.values()) else None


# Fixed owned-scope files only. Missing keys are None, never synthesized zeroes.
MEMORY_GAUGES = ("anon", "file", "shmem")
MEMORY_COUNTERS = ("pgfault", "pgmajfault", "pgscan", "pgsteal", "pgscan_direct",
                   "pgsteal_direct", "workingset_refault_anon", "workingset_refault_file")
MEMORY_EVENTS = ("low", "high", "max", "oom", "oom_kill", "oom_group_kill")
MEMORY_DIAGNOSTIC_FILES = (
    ("memory.current", "GAUGE_BYTES", None),
    ("memory.peak", "HIGH_WATER_BYTES", None),
    ("memory.events", "CUMULATIVE_EVENTS_HIERARCHICAL", MEMORY_EVENTS),
    ("memory.events.local", "CUMULATIVE_EVENTS_LOCAL", MEMORY_EVENTS),
    ("memory.stat", "MIXED_GAUGES_AND_COUNTERS", MEMORY_GAUGES + MEMORY_COUNTERS),
    ("memory.pressure", "CUMULATIVE_STALL_MICROSECONDS", ("some", "full")),
    ("memory.min", "CONFIGURED_BYTES", None),
    ("memory.low", "CONFIGURED_BYTES", None),
    ("memory.high", "CONFIGURED_BYTES", None),
    ("memory.max", "CONFIGURED_BYTES", None),
    ("memory.swap.max", "CONFIGURED_BYTES", None),
    ("memory.oom.group", "CONFIGURED_BOOLEAN", None),
)


def _diagnostic_integer(value):
    if not value.isascii() or not value.isdecimal() or not 0 <= int(value) < 2 ** 63:
        raise ValueError("DIAGNOSTIC_BOUNDS")
    return int(value)


def _memory_sample(scope):
    readings = []
    for name, kind, keys in MEMORY_DIAGNOSTIC_FILES:
        reading = {"file": name, "kind": kind, "start": time.monotonic()}
        try:
            text = _diagnostic_read(scope / name)
            if keys is None:
                value = text.strip()
                values = {"value": "max" if kind == "CONFIGURED_BYTES" and value == "max"
                          else _diagnostic_integer(value)}
            elif name == "memory.pressure":
                rows = {}
                for line in text.splitlines():
                    fields = line.split()
                    if not fields or fields[0] not in keys or fields[0] in rows:
                        raise ValueError("DIAGNOSTIC_INVALID")
                    totals = [field[6:] for field in fields[1:] if field.startswith("total=")]
                    if len(totals) != 1:
                        raise ValueError("DIAGNOSTIC_INVALID")
                    rows[fields[0]] = _diagnostic_integer(totals[0])
                values = {key: rows.get(key) for key in keys}
            else:
                rows = {}
                for line in text.splitlines():
                    key, value = line.split()
                    if key in keys:
                        if key in rows:
                            raise ValueError("DIAGNOSTIC_INVALID")
                        rows[key] = _diagnostic_integer(value)
                values = {key: rows.get(key) for key in keys}
            reading.update(status="OBSERVED", values=values)
        except (OSError, ValueError, UnicodeError):
            reading.update(status="UNAVAILABLE", values=None)
        reading["end"] = time.monotonic()
        readings.append(reading)
    return readings


def _memory_deltas(before, after):
    deltas = {}
    for first, last in zip(before, after):
        name = first["file"]
        keys = (MEMORY_COUNTERS if name == "memory.stat" else
                MEMORY_EVENTS if name in ("memory.events", "memory.events.local") else
                ("some", "full") if name == "memory.pressure" else ())
        if not keys:
            continue  # Gauges, high-water marks and configured limits are not event counters.
        values = {}
        for key in keys:
            initial = (first.get("values") or {}).get(key)
            final = (last.get("values") or {}).get(key)
            values[key] = (final - initial if name == last["file"] and
                           type(initial) is int and type(final) is int and final >= initial else None)
        deltas[name] = values
    return deltas


def _setup_and_exec(rootfs, workspace, venv):
    """Trusted PID-namespace init: own the cgroup, lease and complete cleanup."""
    rootfs, workspace, venv = Path(rootfs), Path(workspace), Path(venv)
    diagnostic = os.environ.get("FREEAGENT_DISK_DIAGNOSTICS") == "1"
    phases = {"setup_start": time.monotonic()} if diagnostic else None
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
        if diagnostic:
            phases["setup_complete"] = time.monotonic()
            before = _disk_sample(scope, rootfs / "workspace")
            memory_before = _memory_sample(scope)
            phases["launch_start"] = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True, preexec_fn=lambda: _apply_child_limits(scope, timeout))
        if diagnostic:
            phases["launch_return"] = time.monotonic()
        timeout_triggered = _read_bounded(process, timeout, capture)
        if diagnostic:
            phases["wait_return"] = time.monotonic()
            after = _disk_sample(scope, rootfs / "workspace")
            memory_after = _memory_sample(scope)
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
        if diagnostic:
            phases["result_collection"] = time.monotonic()
            evidence["disk_diagnostics"] = {"schema_version": 1, "authority": "NONE",
                "phases": phases, "before": before, "after": after,
                "cpu_delta": _cpu_delta(before, after), "progress": _disk_progress(rootfs),
                "memory": {"before": memory_before, "after": memory_after,
                           "deltas": _memory_deltas(memory_before, memory_after)}}
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


def run_isolated(workspace, run_dir, runner_sha256, timeout=150, *, disk_diagnostics=False):
    control = Path(run_dir) / "controller"
    test_area = Path(tempfile.mkdtemp(prefix="test-copy-", dir=control))
    try:
        result = _run_isolated_in_area(workspace, run_dir, runner_sha256, timeout, test_area, disk_diagnostics)
        if disk_diagnostics is True:
            try:
                retained = _retain_disk_diagnostics(result, runner_sha256, timeout)
            except Exception as error:
                retained = _retention_failure(error)
            result["evidence"]["disk_diagnostics_retention"] = retained
        return result
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


def _run_isolated_in_area(workspace, run_dir, runner_sha256, timeout, test_area, disk_diagnostics=False):
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
    if disk_diagnostics is True:
        env["FREEAGENT_DISK_DIAGNOSTICS"] = "1"
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
        if disk_diagnostics is True:
            _post_evidence_guard(process, capture, output, runner_sha256, timeout, True)
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
