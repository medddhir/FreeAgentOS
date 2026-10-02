"""Synthetic ownership ledger only. No mount, cgroup, sudo or namespace syscall."""
from collections import deque
from dataclasses import dataclass
import os
import secrets
import subprocess
import sys
from .policy import worker_environment, RECIPES
from .protocol import BoundaryError, MAX_ENTRIES, identifier


@dataclass
class ProcessHandle:
    owner: str
    process: object = None
    pidfd: int | None = None

    def terminate(self, owner):
        if owner != self.owner:raise BoundaryError('UNKNOWN_HANDLE')
        if self.process is not None:
            if self.process.poll() is None:
                # Popen retains ownership of its unreaped direct child; pidfd preferred.
                if self.pidfd is not None:
                    import signal
                    signal.pidfd_send_signal(self.pidfd,signal.SIGTERM)
                else:self.process.terminate()
            try:self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait(timeout=1)
            if self.process.stdout:self.process.stdout.close()
            if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None


class FakeBackend:
    simulation_only=True
    def __init__(self):
        self.owner=secrets.token_hex(16)
        self.resources={}
        self.completed=set()
        self.events=deque(maxlen=256)
        self.fail_at=None

    def _step(self, name, handle):
        self.events.append((name,handle))
        if self.fail_at==name:raise RuntimeError('synthetic private exception must never escape')

    def owns(self, handle, owner):
        return owner==self.owner and handle in self.resources and self.resources[handle]['owner']==owner

    def cleaned(self, handle, owner):
        return owner==self.owner and handle in self.completed

    def prepare(self, handle, recipe, limits):
        if not identifier(handle) or recipe not in RECIPES:raise BoundaryError('INVALID_REQUEST')
        if handle in self.resources or handle in self.completed:raise BoundaryError('INVALID_STATE')
        if len(self.resources)+len(self.completed)>=MAX_ENTRIES:raise BoundaryError('BOUNDS_EXCEEDED')
        self.resources[handle]={'owner':self.owner,'recipe':recipe,'limits':dict(limits),'process':None}
        for step in ('namespace','rootfs','mount_recipe','cgroup_create','cgroup_limits','identity_prepare'):
            self._step(step,handle)

    def start(self, handle):
        if not self.owns(handle,self.owner):raise BoundaryError('UNKNOWN_HANDLE')
        self._step('spawn_barrier',handle)
        self._step('cgroup_attach_owned_child',handle)
        self._step('identity_drop_simulated',handle)
        self.resources[handle]['process']=ProcessHandle(handle)
        self._step('start',handle)

    def running(self, handle):
        if not self.owns(handle,self.owner):raise BoundaryError('UNKNOWN_HANDLE')
        p=self.resources[handle]['process']
        return p is not None and (p.process is None or p.process.poll() is None)

    def terminate(self, handle):
        if not self.owns(handle,self.owner):raise BoundaryError('UNKNOWN_HANDLE')
        self._step('cgroup_kill',handle)
        p=self.resources[handle]['process']
        if p is not None:p.terminate(handle)
        self._step('reap',handle)
        self.resources[handle]['process']=None

    def cleanup(self, handle):
        if not self.owns(handle,self.owner):raise BoundaryError('UNKNOWN_HANDLE')
        self.terminate(handle)
        for step in ('unmount_owned_recipe','cgroup_remove','remove_owned_root'):
            self._step(step,handle)
        del self.resources[handle]
        self.completed.add(handle)

    def probe(self):
        return {'mode':'SIMULATED','enforcement':'UNPROVEN'}


class SyntheticProcessBackend(FakeBackend):
    """Explicit test fixture: fixed isolated Python snippet, never a model/client.

    This tests direct-child pidfd/FD/argv mechanics, not privileged isolation or
    descendant containment. Literal arguments are fixture constructor inputs,
    never RPC inputs. Environment includes no caller variables.
    """
    def __init__(self, literal_args=()):
        super().__init__()
        if (type(literal_args) not in (list,tuple) or len(literal_args)>8
                or any(type(s) is not str or len(s)>256 for s in literal_args)):
            raise BoundaryError('INVALID_REQUEST')
        self.literal_args=tuple(literal_args)

    def start(self, handle):
        super().start(handle)
        process=subprocess.Popen([sys.executable,'-I','-c',
            'import json,sys,time; print(json.dumps(sys.argv[1:]),flush=True); time.sleep(2)',
            *self.literal_args],env=worker_environment({}),stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True)
        p=ProcessHandle(handle,process)
        self.resources[handle]['process']=p
        if hasattr(os,'pidfd_open'):
            p.pidfd=os.pidfd_open(process.pid,0)
