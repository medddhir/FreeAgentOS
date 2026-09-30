"""Bounded controller-only Git commands; never accepts an executable name."""

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass


MAX_GIT_OUTPUT = 64 * 1024 * 1024


class ControllerGitError(RuntimeError):
    pass


@dataclass
class GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    evidence: dict


def _kill_group(process):
    if process.poll() is None:
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            pass
    def alive():
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
    if not alive():
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 0.5
    while alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if alive():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as exc:
        raise ControllerGitError("CONTROLLER_GIT_CLEANUP_UNPROVEN") from exc
    deadline = time.monotonic() + 1
    while alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if alive():
        raise ControllerGitError("CONTROLLER_GIT_CLEANUP_UNPROVEN")


def run_git(args, *, cwd, timeout=30, env=None, max_output=MAX_GIT_OUTPUT):
    if (not isinstance(args, (list, tuple)) or not args or
            any(not isinstance(arg, str) or "\0" in arg for arg in args) or
            sum(len(arg) for arg in args) > 128 * 1024 or
            type(timeout) is not int or timeout <= 0 or max_output > MAX_GIT_OUTPUT):
        raise ControllerGitError("CONTROLLER_GIT_REQUEST_INVALID")
    clean_env = dict(os.environ if env is None else env)
    clean_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                      "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"})
    command = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args]
    process = subprocess.Popen(command, cwd=cwd, env=clean_env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    result = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ControllerGitError("CONTROLLER_GIT_TIMEOUT")
            for key, _ in selector.select(min(remaining, 0.25)):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if sum(len(value) for value in streams.values()) + len(data) > max_output:
                    raise ControllerGitError("CONTROLLER_GIT_OUTPUT_LIMIT")
                streams[key.fileobj].extend(data)
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise ControllerGitError("CONTROLLER_GIT_TIMEOUT") from exc
        result = GitResult(process.returncode, bytes(streams[process.stdout]),
                           bytes(streams[process.stderr]),
                           {"output_bytes": sum(len(value) for value in streams.values()),
                            "output_limit_bytes": max_output, "timeout_triggered": False})
    finally:
        selector.close()
        try:
            _kill_group(process)
        finally:
            process.stdout.close()
            process.stderr.close()
    result.evidence["cleanup_status"] = "CONFIRMED"
    result.evidence["remaining_processes"] = 0
    return result
