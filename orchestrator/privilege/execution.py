"""Administrative immutable executable/argv binding. Never RPC-supplied paths."""
from dataclasses import dataclass
import os
from types import MappingProxyType
from .linux import PinnedFile, MOUNT_RECIPES, DEVICES, secure_open
import stat
from .policy import execution_class, worker_environment
from .protocol import BoundaryError, identifier

# Fixed installed adapters consume opaque job IDs after privilege drop. Task
# text and credentials are delivered by the unprivileged broker, not this RPC.
FLAGS=MappingProxyType({
 'MODEL_WORKER':('--broker-job',),
 'DETERMINISTIC_TESTER':('--verification-job',),
 'RESEARCH_HELPER':('--research-job',),
})

@dataclass(frozen=True)
class ApprovedExecution:
    execution: str
    role: str
    executable: PinnedFile
    runtime_fd: int
    uid: int
    gid: int
    job_id: str
    validation: bool=False

    def __post_init__(self):
        execution_class(self.execution,self.role)
        if (type(self.executable) is not PinnedFile or type(self.uid) is not int or type(self.gid) is not int
                or not 1<=self.uid<2**31 or not 1<=self.gid<2**31 or not identifier(self.job_id)
                or type(self.validation) is not bool):raise BoundaryError('POLICY_REJECTED')
        if os.get_inheritable(self.runtime_fd) or os.get_inheritable(self.executable.fd):raise BoundaryError('POLICY_REJECTED')

    def argv(self):
        # Only enrolled bindings select jobs. No unknown/duplicate flags API.
        return ('freeagentos-worker', '--synthetic') if self.validation else ('freeagentos-worker',*FLAGS[self.execution],self.job_id)

    def environment(self):return worker_environment({})
    def recipe(self):return MOUNT_RECIPES[self.execution]
    def devices(self):return DEVICES
    def verify(self):
        self.executable.verify()
        root=os.fstat(self.runtime_fd)
        if root.st_uid!=0 or stat.S_IMODE(root.st_mode)!=0o755:raise BoundaryError('POLICY_REJECTED')
        pending=[os.dup(self.runtime_fd)];count=0
        try:
            while pending:
                directory=pending.pop()
                try:
                    for name in os.listdir(directory):
                        count+=1
                        if count>20000:raise BoundaryError('BOUNDS_EXCEEDED')
                        info=os.stat(name,dir_fd=directory,follow_symlinks=False)
                        if info.st_uid!=0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):raise BoundaryError('POLICY_REJECTED')
                        if stat.S_ISDIR(info.st_mode):pending.append(secure_open(directory,name,os.O_RDONLY|os.O_DIRECTORY))
                        elif not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise BoundaryError('POLICY_REJECTED')
                finally:os.close(directory)
        finally:
            for fd in pending:os.close(fd)
        # A complete minimal runtime is enrolled; never bind the host root/home.
        marker=secure_open(self.runtime_fd,'.freeagent-runtime')
        try:
            if os.read(marker,65)!=b'FREEAGENTOS_MINIMAL_RUNTIME_V1\n':raise BoundaryError('POLICY_REJECTED')
        finally:os.close(marker)
        for name in ('tmp','run','home','dev','workspace','proc'):
            fd=secure_open(self.runtime_fd,name,os.O_RDONLY|os.O_DIRECTORY)
            try:
                info=os.fstat(fd)
                if info.st_uid!=0 or info.st_mode & 0o022:raise BoundaryError('POLICY_REJECTED')
            finally:os.close(fd)



class ExecutionRegistry:
    def __init__(self, entries):
        if type(entries) is not dict or not 1<=len(entries)<=16:raise BoundaryError('POLICY_REJECTED')
        for slot,entry in entries.items():
            import re
            if type(slot) is not str or re.fullmatch('[a-z][a-z0-9_-]{0,31}',slot) is None or type(entry) is not ApprovedExecution:
                raise BoundaryError('POLICY_REJECTED')
        self.entries=MappingProxyType(dict(entries))

    def bind(self,slot,execution,role):
        entry=self.entries.get(slot)
        if entry is None or (entry.execution,entry.role)!=(execution,role):raise BoundaryError('EXECUTION_CLASS_REJECTED')
        entry.verify();return entry
