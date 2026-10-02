"""Linux preparation primitives. Inert imports; no production activation.

Administrative code owns every FD. Nothing here is reachable through RPC.
The existing supervisor deliberately rejects this incomplete backend.
"""
import ctypes
from dataclasses import dataclass
import hashlib
import os
import platform
import select
import signal
import stat
import time
from types import MappingProxyType
from .policy import CLASSES, resource_limits, worker_environment
from .protocol import BoundaryError, identifier

RESOLVE_NO_XDEV=1
RESOLVE_NO_MAGICLINKS=2
RESOLVE_NO_SYMLINKS=4
RESOLVE_BENEATH=8
RESOLVE=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV

class OpenHow(ctypes.Structure):
    _fields_=[('flags',ctypes.c_uint64),('mode',ctypes.c_uint64),('resolve',ctypes.c_uint64)]


def secure_open(root_fd, relative, flags=os.O_RDONLY):
    """Read-only descriptor resolution on qualified x86_64. No fallback.

    NO_XDEV applies below an already registered anchor, not across / -> anchor.
    Writable/create flags are intentionally unavailable in this resolver.
    """
    if (platform.system()!='Linux' or platform.machine()!='x86_64'
            or type(relative) is not str or len(relative.encode())>256
            or any(p in ('','.','..') for p in relative.split('/'))
            or '\\' in relative or '\0' in relative
            or flags not in (os.O_RDONLY,os.O_RDONLY|os.O_DIRECTORY)):
        raise BoundaryError('PATH_REJECTED')
    libc=ctypes.CDLL(None,use_errno=True)
    libc.syscall.restype=ctypes.c_long
    how=OpenHow(flags|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,0,RESOLVE)
    fd=libc.syscall(ctypes.c_long(437),ctypes.c_int(root_fd),
                    ctypes.c_char_p(relative.encode()),ctypes.byref(how),ctypes.c_size_t(ctypes.sizeof(how)))
    if fd<0:raise BoundaryError('PATH_REJECTED')
    info=os.fstat(fd)
    if not (stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink==1)):
        os.close(fd);raise BoundaryError('PATH_REJECTED')
    return fd


def path_primitive_available(root_fd, known_file):
    try:
        fd=secure_open(root_fd,known_file);os.close(fd);return True
    except (OSError,BoundaryError):return False


def platform_report():
    """Bounded, read-only prerequisites, not an enforcement qualification."""
    def read(path):
        try:
            with open(path) as stream:return stream.read(8192)
        except OSError:return ''
    release=read('/etc/os-release')
    kernel=platform.release()
    ubuntu='ID=ubuntu\n' in release and 'VERSION_ID="24.04"' in release
    return {'reference_platform':platform.system()=='Linux' and platform.machine()=='x86_64' and ubuntu,
            'wsl2':'microsoft-standard-WSL2' in kernel,
            'kernel':kernel[:128], 'pidfd':hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),
            'namespaces':all(os.path.exists('/proc/self/ns/'+s) for s in ('mnt','pid','net','user')),
            'cgroup_v2':os.path.isfile('/sys/fs/cgroup/cgroup.controllers'),
            'controllers':sorted(set(read('/sys/fs/cgroup/cgroup.controllers').split()) & {'cpu','memory','pids'}),
            'enforcement':'UNPROVEN'}


@dataclass(frozen=True)
class PinnedFile:
    fd: int
    device: int
    inode: int
    digest: str

    @classmethod
    def executable(cls, root_fd, relative):
        fd=secure_open(root_fd,relative)
        try:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022
                    or info.st_mode & 0o6000 or not info.st_mode & 0o111 or info.st_size>32*1024*1024):
                raise BoundaryError('POLICY_REJECTED')
            digest=hashlib.sha256()
            while block:=os.read(fd,65536):digest.update(block)
            os.lseek(fd,0,os.SEEK_SET)
            return cls(fd,info.st_dev,info.st_ino,digest.hexdigest())
        except BaseException:
            os.close(fd);raise

    def verify(self):
        info=os.fstat(self.fd)
        if (info.st_dev,info.st_ino)!=(self.device,self.inode) or info.st_mode & 0o022 or info.st_uid!=0:
            raise BoundaryError('POLICY_REJECTED')
        digest=hashlib.sha256()
        offset=0
        while block:=os.pread(self.fd,65536,offset):
            digest.update(block);offset+=len(block)
            if offset>32*1024*1024:raise BoundaryError('BOUNDS_EXCEEDED')
        if digest.hexdigest()!=self.digest:raise BoundaryError('POLICY_REJECTED')


# Logical mount classes only. No host source/target/fstype values in requests.
MOUNT_RECIPES=MappingProxyType({
    'MODEL_WORKER':('PRIVATE_PROPAGATION','SEALED_WORKSPACE','READONLY_RUNTIME','PRIVATE_SCRATCH','PRIVATE_PROC'),
    'DETERMINISTIC_TESTER':('PRIVATE_PROPAGATION','TEST_COPY','READONLY_RUNTIME','PRIVATE_SCRATCH','PRIVATE_PROC','PRIVATE_NET'),
    'RESEARCH_HELPER':('PRIVATE_PROPAGATION','READONLY_RUNTIME','PRIVATE_SCRATCH','PRIVATE_PROC'),
})
DEVICES=('null','zero','random','urandom')
CHILD_ORDER=('ATTACH_CGROUP_BARRIER','UNSHARE_MOUNT_PID','PRIVATE_PROPAGATION','FIXED_ROOTFS',
             'CHROOT_AND_CHDIR','DROP_BOUNDING_AMBIENT','CLEAR_GROUPS','SET_GID','SET_UID',
             'CLEAR_CAPSET','NO_NEW_PRIVS','CLOSE_PRIVILEGED_FDS','EXEC_PINNED_CLASS')


def execution_plan(execution,role,uid,gid,limits=None):
    if type(uid) is not int or type(gid) is not int or not 1<=uid<=2**31-1 or not 1<=gid<=2**31-1:
        raise BoundaryError('POLICY_REJECTED')
    values=resource_limits(execution,role,limits or {})
    return {'class':execution,'role':role,'identity':(uid,gid),'limits':values,
            'recipe':MOUNT_RECIPES[execution],'devices':DEVICES,'order':CHILD_ORDER,
            'environment':worker_environment({}),'activation':'BLOCKED_PENDING_CHILD_LAUNCHER'}


class OwnedPidfd:
    """Only a helper-created child object, never a protocol PID."""
    def __init__(self, handle, child):
        if not identifier(handle) or child.poll() is not None:raise BoundaryError('UNKNOWN_HANDLE')
        if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
            raise BoundaryError('POLICY_REJECTED')
        self.handle=handle;self.child=child;self.fd=os.pidfd_open(child.pid,0)
        os.set_inheritable(self.fd,False)

    def running(self,handle):
        if handle!=self.handle:raise BoundaryError('UNKNOWN_HANDLE')
        return not select.select([self.fd],[],[],0)[0]

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


class Deadline:
    """Controller disconnect is immediately terminal; no reconnect ownership."""
    def __init__(self, clock=time.monotonic):
        from ..roles.lease import BASE_SECONDS, HARD_SECONDS
        self.clock=clock;self.started=clock();self.base=BASE_SECONDS;self.hard=HARD_SECONDS;self.grace=False

    def grant_grace(self, authenticated_recent_activity):
        # This boolean must originate in trusted broker telemetry, never RPC.
        if authenticated_recent_activity is not True or self.clock()-self.started>self.base:
            raise BoundaryError('POLICY_REJECTED')
        self.grace=True

    def expired(self, connected=True):
        elapsed=self.clock()-self.started
        from ..roles.lease import GRACE_SECONDS
        return connected is not True or elapsed>=min(self.hard,self.base+(GRACE_SECONDS if self.grace else 0))


class OwnedCgroup:
    """Explicit mutation API on an administrator-pinned delegated subtree.

    Construction/read checks are inert. No caller chooses a host cgroup path.
    Activation is unavailable until the launcher/recovery integration is reviewed.
    """
    def __init__(self, root_fd):
        self.root_fd=os.dup(root_fd);os.set_inheritable(self.root_fd,False)
        self.scopes={}

    def _mutation_guard(self):
        raise BoundaryError('RECOVERY_REQUIRED')

    def _write(self, fd, name, value):
        self._mutation_guard()
        if name not in ('memory.max','memory.swap.max','pids.max','cpu.max','cgroup.procs','cgroup.kill'):
            raise BoundaryError('POLICY_REJECTED')
        child=os.open(name,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            raw=value.encode('ascii')
            if len(raw)>64 or os.write(child,raw)!=len(raw):raise BoundaryError('BACKEND_FAILURE')
        finally:os.close(child)

    def create(self, handle, execution,role,limits=None):
        self._mutation_guard()
        if not identifier(handle) or handle in self.scopes or len(self.scopes)>=16:
            raise BoundaryError('INVALID_REQUEST')
        policy=resource_limits(execution,role,limits or {})
        name='scope-'+handle
        os.mkdir(name,0o700,dir_fd=self.root_fd)
        fd=secure_open(self.root_fd,name,os.O_RDONLY|os.O_DIRECTORY)
        self.scopes[handle]=fd  # Retain ownership even if a later limit write fails.
        for field,value in [('memory.max',policy['memory_limit_bytes']),('memory.swap.max',0),
                            ('pids.max',policy['max_processes']),
                            ('cpu.max',f"{policy['cpu_quota_us']} {policy['cpu_period_us']}")]:
            self._write(fd,field,str(value))

    def terminate(self,handle):
        self._mutation_guard()
        if handle not in self.scopes:raise BoundaryError('UNKNOWN_HANDLE')
        self._write(self.scopes[handle],'cgroup.kill','1')
        # No PID enumeration fallback.

    def attach(self, handle, child):
        self._mutation_guard()
        if handle not in self.scopes or child.poll() is not None:
            raise BoundaryError('UNKNOWN_HANDLE')
        # Only a backend-created unreaped child may be attached. A raw PID is
        # not accepted by the API. Future launcher supplies the paused child.
        self._write(self.scopes[handle],'cgroup.procs',str(child.pid))

    def empty(self, handle):
        if handle not in self.scopes:raise BoundaryError('UNKNOWN_HANDLE')
        fd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.scopes[handle])
        try:
            raw=os.read(fd,4097)
            if len(raw)>4096:raise BoundaryError('BOUNDS_EXCEEDED')
            lines=raw.decode('ascii').splitlines()
            populated=[line for line in lines if line.startswith('populated ')]
            if populated not in (['populated 0'],['populated 1']):raise BoundaryError('BACKEND_FAILURE')
            return populated==['populated 0']
        finally:os.close(fd)

    def remove(self, handle):
        self._mutation_guard()
        if not self.empty(handle):raise BoundaryError('CLEANUP_INCOMPLETE')
        os.rmdir('scope-'+handle,dir_fd=self.root_fd)
        os.close(self.scopes.pop(handle))

    def close(self):
        for fd in self.scopes.values():os.close(fd)
        self.scopes.clear();os.close(self.root_fd)


def recovery_plan(record, policy, boot_id):
    """No mutation: reject ambiguous identifiers instead of host-wide scans."""
    fields={'version','handle','policy','boot_id','state','recipe'}
    if (type(record) is not dict or set(record)!=fields or type(record['version']) is not int or record['version']!=1
            or not identifier(record['handle']) or record['policy']!=policy
            or type(record['boot_id']) is not str or len(record['boot_id'])>64
            or record['boot_id']!=boot_id or type(record['recipe']) is not str or record['recipe'] not in MOUNT_RECIPES
            or type(record['state']) is not str or record['state'] not in ('CREATING','RUNNING','FAILED_DIRTY','TERMINATED')):
        raise BoundaryError('JOURNAL_INVALID')
    return ('VERIFY_OWNED_SCOPE','KILL_OWNED_SCOPE','VERIFY_EMPTY','REAP_OWNED_PIDFD',
            'REMOVE_PRIVATE_ROOT','REMOVE_OWNED_SCOPE','MARK_RELEASED')


class LinuxIsolationBackend:
    """Preparation-only backend. Intentionally cannot be activated this stage."""
    simulation_only=False
    def __init__(self):self.readiness=platform_report()
    def prepare(self,*args,**kwargs):raise BoundaryError('RECOVERY_REQUIRED')
    def start(self,*args,**kwargs):raise BoundaryError('RECOVERY_REQUIRED')
    def probe(self):return {'mode':'LINUX_PREPARATION','enforcement':'UNPROVEN'}

class ChildSetup:
    """Explicit child-only syscall implementation, never selected by RPC.

    Construct before a future single-threaded fork. All calls refuse to run in
    that process. No launcher exists yet; tests replace syscalls with mocks.
    FD roots must first be qualified by the still-pending snapshot integration.
    """
    def __init__(self):
        self.parent_pid=os.getpid();self.stage='NEW'

    def _child(self):
        if os.getpid()==self.parent_pid:raise BoundaryError('POLICY_REJECTED')

    def _libc(self):
        self._child()
        return ctypes.CDLL(None,use_errno=True)

    def namespaces(self, private_network=False):
        self._child()
        if self.stage!='NEW' or type(private_network) is not bool:
            raise BoundaryError('INVALID_STATE')
        libc=self._libc()
        # CLONE_NEWNS|CLONE_NEWPID; NEWPID applies to the next fork, not caller.
        flags=0x00020000|0x20000000|(0x40000000 if private_network else 0)
        if libc.unshare(ctypes.c_int(flags))!=0:raise BoundaryError('BACKEND_FAILURE')
        self.stage='PID_FORK_REQUIRED'

    def pid_namespace_child(self):
        self._child()
        # Launcher must prove fork/PID namespace identity; cannot self-assert it.
        # Until that integration exists no mount/rootfs operation is admitted.
        raise BoundaryError('RECOVERY_REQUIRED')

    def drop_identity(self,uid,gid):
        self._child()
        if self.stage!='ROOTFS_READY' or type(uid) is not int or type(gid) is not int or not 1<=uid<=2**31-1 or not 1<=gid<=2**31-1:
            raise BoundaryError('POLICY_REJECTED')
        libc=self._libc()
        libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
        libc.prctl.restype=ctypes.c_int
        # Drop ambient and bounding capabilities while setup still has authority.
        if libc.prctl(47,4,0,0,0)!=0:raise BoundaryError('BACKEND_FAILURE')
        with open('/proc/sys/kernel/cap_last_cap') as stream:
            raw=stream.read(16)
        try:last=int(raw)
        except ValueError:raise BoundaryError('POLICY_REJECTED') from None
        if not 0<=last<=63:raise BoundaryError('POLICY_REJECTED')
        for capability in range(last+1):
            if libc.prctl(24,capability,0,0,0)!=0:raise BoundaryError('BACKEND_FAILURE')
        if libc.prctl(8,0,0,0,0)!=0:raise BoundaryError('BACKEND_FAILURE')
        os.setgroups([]);os.setgid(gid);os.setuid(uid)
        class Header(ctypes.Structure):
            _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
        class Data(ctypes.Structure):
            _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
        libc.capset.argtypes=[ctypes.c_void_p,ctypes.c_void_p];libc.capset.restype=ctypes.c_int
        header=Header(0x20080522,0);data=(Data*2)()
        if libc.capset(ctypes.byref(header),ctypes.byref(data))!=0:raise BoundaryError('BACKEND_FAILURE')
        if libc.prctl(38,1,0,0,0)!=0:raise BoundaryError('BACKEND_FAILURE')
        if (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(uid,uid,gid,gid):
            raise BoundaryError('POLICY_REJECTED')
        self.stage='DROPPED'
