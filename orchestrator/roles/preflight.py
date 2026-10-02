"""Fail-closed, bounded host capability check before model or target execution."""

import hashlib
import json
import os
import platform
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from foundation import bundled_tool

from state import AgentState
from roles.sandbox import REQUIRED_CONTROLS, run_isolated
from roles.worker import run_worker


ROOT = Path(__file__).resolve().parents[2]
STATIC_REQUIRED = ("linux", "unshare", "chroot", "git", "python3", "setpriv", "cgroup_v2",
                   "memory_controller", "pids_controller", "cpu_controller")
REQUIRED = (*STATIC_REQUIRED,
            "sandbox_boundary", "cgroup_scope", "cgroup_kill", "unprivileged_test_user", "worker_scope")


def _static_capabilities():
    controls = Path("/sys/fs/cgroup/cgroup.controllers")
    available = controls.read_text().split() if controls.is_file() else []
    mountinfo = Path("/proc/self/mountinfo").read_text()
    result = {"linux": "SUPPORTED" if platform.system() == "Linux" else "UNSUPPORTED",
              "cgroup_v2": "SUPPORTED" if controls.is_file() and " - cgroup2 " in mountinfo else "UNSUPPORTED"}
    for name in ("unshare", "chroot", "git", "python3", "setpriv"):
        present = Path("/usr/sbin/chroot").is_file() if name == "chroot" else bool(shutil.which(name))
        result[name] = "SUPPORTED" if present else "UNSUPPORTED"
    for name in ("memory", "pids", "cpu"):
        result[name + "_controller"] = "SUPPORTED" if name in available else "UNSUPPORTED"
    result["pidfd_optional"] = "SUPPORTED" if hasattr(os, "pidfd_open") else "UNSUPPORTED"
    return result


def _probe_sandbox():
    """Execute a trusted tiny test through the exact production sandbox."""
    with tempfile.TemporaryDirectory(prefix="freeagentos-preflight-") as temp:
        run_dir = Path(temp)
        workspace = run_dir / "workspace"
        controller = run_dir / "controller"
        workspace.mkdir()
        controller.mkdir(mode=0o700)
        (workspace / "test_boundary.py").write_text(
            "import os, unittest\n"
            "class Boundary(unittest.TestCase):\n"
            " def test_unprivileged(self): self.assertEqual(os.geteuid(), 65534)\n")
        runner = controller / "freeagent-test"
        shutil.copyfile(bundled_tool("freeagent-test"), runner)
        digest = hashlib.sha256(runner.read_bytes()).hexdigest()
        return run_isolated(workspace, run_dir, digest, timeout=8)


def _probe_worker():
    code = ("from pathlib import Path\n"
            "caps=next(line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))\n"
            "assert int(caps.split()[1],16)==0\n"
            "scopes=[line for line in Path('/proc/self/mountinfo').read_text().splitlines() "
            "if ' - cgroup2 ' in line and '/freeagentos-worker-' in line]\n"
            "assert scopes and all('ro' in line.split()[5].split(',') for line in scopes)\n"
            "from pathlib import Path\n"
            f"policy=Path({str(ROOT / 'orchestrator/roles/worker.py')!r})\n"
            "try:\n"
            " policy.open('ab').close()\n"
            "except OSError:pass\n"
            "else:raise AssertionError('controller writable')\n"
            "print('WORKER_PREFLIGHT_OK')")
    return run_worker([sys.executable, "-c", code],
                      timeout=8, role="preflight")


def check_host():
    try:
        capabilities = _static_capabilities()
    except (OSError, ValueError) as exc:
        capabilities = {name: "ERROR" for name in REQUIRED}
        return {"status": "BLOCKED", "capabilities": capabilities,
                "required_failures": list(REQUIRED), "optional_failures": [],
                "error": "STATIC_PREFLIGHT_ERROR:" + type(exc).__name__}
    for name in ("sandbox_boundary", "cgroup_scope", "cgroup_kill", "unprivileged_test_user", "worker_scope"):
        capabilities[name] = "UNSUPPORTED"
    if not any(capabilities[name] != "SUPPORTED" for name in STATIC_REQUIRED):
        try:
            probe = _probe_sandbox()
            evidence = probe.get("evidence", {})
            good = (probe.get("isolated") is True and probe.get("result") == "PASS"
                    and evidence.get("cleanup_status") == "CONFIRMED"
                    and evidence.get("remaining_processes") == 0
                    and evidence.get("cgroup_status") == "ENFORCED"
                    and all(evidence.get("controls", {}).get(key) == "ENFORCED" for key in REQUIRED_CONTROLS))
            if good:
                for name in ("sandbox_boundary", "cgroup_scope", "cgroup_kill", "unprivileged_test_user"):
                    capabilities[name] = "SUPPORTED"
                worker = _probe_worker()
                worker_evidence = worker.evidence
                if (worker.returncode == 0 and worker_evidence.get("cleanup_status") == "CONFIRMED"
                        and worker_evidence.get("remaining_processes") == 0
                        and worker_evidence.get("cgroup_status") == "ENFORCED"):
                    capabilities["worker_scope"] = "SUPPORTED"
                else:
                    capabilities["worker_scope"] = "ERROR"
            else:
                for name in ("sandbox_boundary", "cgroup_scope", "cgroup_kill", "unprivileged_test_user"):
                    capabilities[name] = "ERROR"
        except Exception as exc:
            for name in ("sandbox_boundary", "cgroup_scope", "cgroup_kill", "unprivileged_test_user", "worker_scope"):
                if capabilities[name] != "SUPPORTED":
                    capabilities[name] = "ERROR"
            return {"status": "BLOCKED", "capabilities": capabilities,
                    "required_failures": [name for name in REQUIRED if capabilities[name] != "SUPPORTED"],
                    "optional_failures": ["pidfd_optional"] if capabilities["pidfd_optional"] != "SUPPORTED" else [],
                    "error": "ACTIVE_PREFLIGHT_ERROR:" + type(exc).__name__}
    failures = [name for name in REQUIRED if capabilities[name] != "SUPPORTED"]
    return {"status": "BLOCKED" if failures else "PASS", "capabilities": capabilities,
            "required_failures": failures,
            "optional_failures": ["pidfd_optional"] if capabilities["pidfd_optional"] != "SUPPORTED" else [],
            "error": "REQUIRED_HOST_CAPABILITY_UNAVAILABLE" if failures else ""}


def preflight_node(state: AgentState):
    try:
        result = check_host()
        if result["status"] != "PASS":
            return {"preflight_status": "BLOCKED", "preflight_capabilities": result["capabilities"],
                    "preflight_required_failures": result["required_failures"],
                    "preflight_optional_failures": result["optional_failures"],
                    "preflight_error": result["error"], "status": "BLOCKED", "trace": ["preflight:error"]}
        control = Path(state["run_dir"]) / "controller"
        raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        path = control / "preflight.json"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if not stat.S_ISREG(path.lstat().st_mode):
            raise RuntimeError("PREFLIGHT_EVIDENCE_NOT_REGULAR")
        return {"preflight_status": "PASS", "preflight_capabilities": result["capabilities"],
                "preflight_required_failures": [], "preflight_optional_failures": result["optional_failures"],
                "preflight_error": "", "preflight_evidence_sha256": hashlib.sha256(raw).hexdigest(),
                "trace": ["preflight"]}
    except Exception as exc:
        return {"preflight_status": "BLOCKED", "preflight_error": type(exc).__name__,
                "status": "BLOCKED", "trace": ["preflight:error"]}
