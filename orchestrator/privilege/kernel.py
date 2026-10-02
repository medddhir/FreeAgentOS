"""Real Linux operations, unreachable without an administrator installation permit.

Only fixed descriptor-derived recipes. No public RPC imports or model imports.
"""
import ctypes
from dataclasses import dataclass
import json
import os
import select
import stat
import subprocess
import time
from .linux import secure_open, OwnedPidfd, ChildSetup, platform_report
from .protocol import BoundaryError, identifier
from .security import private_file
from .policy import resource_limits

CGROUP2_MAGIC=0x63677270
REQUIRED_CONTROLLERS=frozenset(('cpu','memory','pids'))


def read_at(fd,name,maximum=4096):
    child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
    try:
        raw=os.read(child,maximum+1)
        if len(raw)>maximum:raise BoundaryError('BOUNDS_EXCEEDED')
        return raw.decode('ascii')
    except UnicodeError:raise BoundaryError('POLICY_REJECTED') from None
    finally:os.close(child)


def cgroup_qualification(fd,*,expected_uid=0,filesystem=None):
    """Read-only. Availability never certifies active enforcement."""
    codes=[]
    if filesystem is None:
        buf=ctypes.create_string_buffer(256)
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.fstatfs(ctypes.c_int(fd),ctypes.byref(buf))!=0:
            return {'codes':['CGROUP_V2_UNAVAILABLE'],'enforcement':'UNPROVEN'}
        filesystem=ctypes.c_long.from_buffer(buf).value
    if filesystem!=CGROUP2_MAGIC:codes.append('CGROUP_V2_UNAVAILABLE')
    info=os.fstat(fd)
    if info.st_uid!=expected_uid or info.st_mode & 0o022:codes.append('DELEGATION_UNPROVEN')
    for name,reason in (('cgroup.controllers','CONTROLLER_MISSING'),('cgroup.subtree_control','CONTROLLERS_DISABLED')):
        try:
            if not REQUIRED_CONTROLLERS<=set(read_at(fd,name).split()):codes.append(reason)
        except (OSError,BoundaryError):codes.append(reason)
    try:
        info=os.stat('cgroup.kill',dir_fd=fd,follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o200:codes.append('CGROUP_KILL_UNAVAILABLE')
    except OSError:codes.append('CGROUP_KILL_UNAVAILABLE')
    return {'codes':sorted(set(codes)),'enforcement':'UNPROVEN'}


@dataclass(frozen=True)
class InstallationPermit:
    registry_hash: str
    policy_hash: str

    def __post_init__(self):
        if not identifier(self.registry_hash,64) or not identifier(self.policy_hash,64):raise BoundaryError('POLICY_REJECTED')

    @classmethod
    def load(cls,path,expected_registry,expected_policy):
        if os.geteuid()!=0:raise BoundaryError('POLICY_REJECTED')
        import hashlib
        raw=private_file(path,0)
        if hashlib.sha256(raw).hexdigest()!=expected_registry:raise BoundaryError('POLICY_REJECTED')
        from .protocol import _pairs
        try:data=json.loads(raw,object_pairs_hook=_pairs)
        except (ValueError,UnicodeError):raise BoundaryError('POLICY_REJECTED') from None
        if (type(data) is not dict or set(data)!= {'version','policy','purpose','administrator_enabled'}
                or type(data['version']) is not int or data['version']!=1 or data['policy']!=expected_policy
                or data['purpose']!='STAGE31D_SYNTHETIC_VALIDATION' or data['administrator_enabled'] is not True):
            raise BoundaryError('POLICY_REJECTED')
        return cls(expected_registry,expected_policy)


def scope_name(record):
    if not identifier(record['owner']) or not identifier(record['handle']):raise BoundaryError('JOURNAL_INVALID')
    return 'fa-'+record['owner']+'-'+record['handle']


def delete_tree_at(parent,name,budget=None):
    """Only helper-owned private trees, descriptors never symlink-followed."""
    if budget is None:budget=[22000]
    budget[0]-=1
    if budget[0]<0:raise BoundaryError('BOUNDS_EXCEEDED')
    fd=secure_open(parent,name,os.O_RDONLY|os.O_DIRECTORY)
    try:
        for child in os.listdir(fd):
            info=os.stat(child,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):delete_tree_at(fd,child,budget)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:os.unlink(child,dir_fd=fd)
            else:raise BoundaryError('CLEANUP_INCOMPLETE')
    finally:os.close(fd)
    os.rmdir(name,dir_fd=parent)


class LinuxDriver:
    """Fixed owned scope/root creation and paused-child launch.

    InstallationPermit is loaded only by the separately authorized service.
    Stage3.1C never creates a permit and never constructs an active driver.
    """
    def __init__(self,permit,root_fd,cgroup_fd,launcher,owner):
        if type(permit) is not InstallationPermit or os.geteuid()!=0 or not identifier(owner):
            raise BoundaryError('POLICY_REJECTED')
        self.permit=permit;self.root_fd=os.dup(root_fd);self.cgroup_fd=os.dup(cgroup_fd)
        self.launcher=launcher;self.owner=owner;self.scopes={};self.roots={};self.children={};self.validation_files={};self.qualified=False;self.sealed=set()
        with open('/proc/sys/kernel/random/boot_id') as stream:self.boot_id=stream.read(64).strip()

    def qualify(self):
        report=platform_report()
        if not report['reference_platform'] or not report['pidfd'] or not report['namespaces']:
            raise BoundaryError('POLICY_REJECTED')
        if set(cgroup_qualification(self.cgroup_fd)['codes'])-{'CONTROLLERS_DISABLED'}:raise BoundaryError('POLICY_REJECTED')
        for fd in (self.root_fd,self.cgroup_fd):
            info=os.fstat(fd)
            if info.st_uid!=0 or info.st_mode & 0o077:raise BoundaryError('POLICY_REJECTED')
        self.qualified=True

    def _write(self,fd,name,value):
        if name not in ('memory.max','memory.swap.max','cpu.max','pids.max','cgroup.procs','cgroup.kill','cgroup.subtree_control'):
            raise BoundaryError('POLICY_REJECTED')
        child=os.open(name,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            raw=str(value).encode('ascii')
            if len(raw)>64 or os.write(child,raw)!=len(raw):raise BoundaryError('BACKEND_FAILURE')
        finally:os.close(child)

    def allocate(self,r,limits):
        if not self.qualified or r['owner']!=self.owner:raise BoundaryError('POLICY_REJECTED')
        name=scope_name(r)
        limits=resource_limits(r['class'],r['role'],limits)
        if read_at(self.cgroup_fd,'cgroup.procs').strip():raise BoundaryError('POLICY_REJECTED')
        enabled=set(read_at(self.cgroup_fd,'cgroup.subtree_control').split())
        if not REQUIRED_CONTROLLERS<=enabled:
            self._write(self.cgroup_fd,'cgroup.subtree_control',' '.join('+'+c for c in sorted(REQUIRED_CONTROLLERS-enabled)))
        # Admission intent already durable. Names are exclusive in root-private
        # registered roots; ownership survives a crash before inode journal update.
        os.mkdir(name,0o700,dir_fd=self.root_fd)
        root=secure_open(self.root_fd,name,os.O_RDONLY|os.O_DIRECTORY);self.roots[r['handle']]=root
        os.mkdir('workspace',0o700,dir_fd=root);os.mkdir('rootfs',0o755,dir_fd=root)
        os.mkdir(name,0o700,dir_fd=self.cgroup_fd)
        scope=secure_open(self.cgroup_fd,name,os.O_RDONLY|os.O_DIRECTORY);self.scopes[r['handle']]=scope
        for key,value in (('memory.max',limits['memory_limit_bytes']),('memory.swap.max',0),
                          ('cpu.max',f"{limits['cpu_quota_us']} {limits['cpu_period_us']}"),('pids.max',limits['max_processes'])):
            self._write(scope,key,value)
        root_info=os.fstat(root);scope_info=os.fstat(scope)
        return {'root_inode':root_info.st_ino,'root_device':root_info.st_dev,'scope_inode':scope_info.st_ino,'scope_device':scope_info.st_dev}

    def snapshot(self,r,source):
        fd=secure_open(self.roots[r['handle']],'workspace',os.O_RDONLY|os.O_DIRECTORY)
        try:
            source.copy_into(fd);self.validation_files[r['handle']]=next(iter(source.seal.files));self.sealed.add(r['handle'])
        finally:os.close(fd)

    def validation_read(self,r):
        # Only the explicit synthetic validation coordinator calls this method.
        parent=secure_open(self.roots[r['handle']],'workspace',os.O_RDONLY|os.O_DIRECTORY)
        try:
            fd=secure_open(parent,self.validation_files[r['handle']])
            try:os.read(fd,1)
            finally:os.close(fd)
        finally:os.close(parent)

    def launch(self,r,entry,limits):
        """Fresh trusted interpreter avoids threaded-fork preexec_fn hazards.

        Parent attaches a paused launcher before releasing its pipe barrier.
        Launcher then creates namespace init, drops privileges, and FD-execs.
        """
        if not self.qualified or r['owner']!=self.owner or r['handle'] not in self.sealed:raise BoundaryError('POLICY_REJECTED')
        entry.verify();self.launcher.verify()
        root=self.roots[r['handle']]
        workspace=secure_open(root,'workspace',os.O_RDONLY|os.O_DIRECTORY)
        rootfs=os.dup(root)
        read_barrier,write_barrier=os.pipe2(os.O_CLOEXEC)
        receipt_r,receipt_w=os.pipe2(os.O_CLOEXEC)
        fds=(workspace,rootfs,entry.runtime_fd,entry.executable.fd,read_barrier,receipt_w)
        config={'version':1,'class':entry.execution,'role':entry.role,'uid':entry.uid,'gid':entry.gid,
                'job_id':entry.job_id,'validation':entry.validation,'fds':list(fds),'limits':limits}
        # No prompts/tokens/env in config. Child input is bounded trusted policy.
        child=None;process=None
        try:
            child=subprocess.Popen(['freeagentos-launcher','-I','-m','orchestrator.privilege.child'],
                executable='/proc/self/fd/'+str(self.launcher.fd),pass_fds=(*fds,self.launcher.fd),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE if entry.validation else subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},close_fds=True)
            process=OwnedPidfd(r['handle'],child);self.children[r['handle']]=process
            self._write(self.scopes[r['handle']],'cgroup.procs',child.pid)
            child.stdin.write(json.dumps(config,separators=(',',':')).encode());child.stdin.close()
            os.write(write_barrier,b'G')
            # Setup receipt is fixed category, never worker stdout.
            ready=select.select([receipt_r],[],[],10)[0]
            if not ready or os.read(receipt_r,16)!=b'EXEC_READY\n':raise BoundaryError('BACKEND_FAILURE')
            return process
        except Exception:
            self._write(self.scopes[r['handle']],'cgroup.kill',1)
            if child is not None:child.wait(timeout=2)
            if process is not None:process.close()
            self.children.pop(r['handle'],None)
            raise BoundaryError('BACKEND_FAILURE') from None
        finally:
            for fd in (workspace,rootfs,read_barrier,write_barrier,receipt_r,receipt_w):os.close(fd)

    def running(self,r,process):return process.running(r['handle'])

    def terminate(self,r,process=None):
        if process is None:process=self.children.get(r['handle'])
        fd=self._scope(r)
        if fd is not None:
            self._write(fd,'cgroup.kill',1)
            deadline=time.monotonic()+2
            while 'populated 0' not in read_at(fd,'cgroup.events').splitlines():
                if time.monotonic()>=deadline:raise BoundaryError('CLEANUP_INCOMPLETE')
                time.sleep(.01)
        if process and process.fd is not None:
            process.child.wait(timeout=2);process.close()
            if process.child.stdout:process.child.stdout.close()
            self.children.pop(r['handle'],None)

    def _owned_fd(self,parent,r,kind):
        name=scope_name(r)
        try:fd=secure_open(parent,name,os.O_RDONLY|os.O_DIRECTORY)
        except BoundaryError:
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:return None
            raise BoundaryError('CLEANUP_INCOMPLETE') from None
        info=os.fstat(fd);expected=(r[kind+'_device'],r[kind+'_inode'])
        if info.st_uid!=0 or info.st_mode & (0o022 if kind=='scope' else 0o077) or (expected!=(0,0) and (info.st_dev,info.st_ino)!=expected):
            os.close(fd);raise BoundaryError('CLEANUP_INCOMPLETE')
        return fd

    def _scope(self,r):
        if r['boot_id']!=self.boot_id:
            # Old boot processes cannot be addressed. Existing same-named scope
            # on a new boot is ambiguous, not evidence for scoped termination.
            try:os.stat(scope_name(r),dir_fd=self.cgroup_fd,follow_symlinks=False)
            except FileNotFoundError:return None
            raise BoundaryError('CLEANUP_INCOMPLETE')
        existing=self.scopes.get(r['handle'])
        if existing is not None:return existing
        fd=self._owned_fd(self.cgroup_fd,r,'scope')
        if fd is not None:self.scopes[r['handle']]=fd
        return fd

    def absent(self,r):
        name=scope_name(r)
        for fd in (self.root_fd,self.cgroup_fd):
            try:os.stat(name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:continue
            return False
        return True

    def prove(self,r):
        scope=self._scope(r)
        root=self._owned_fd(self.root_fd,r,'root')
        if root is not None:os.close(root)
        return {'scope':True,'root':True}  # verified matching inode or absence

    def remove(self,r):
        scope=self._scope(r)
        if scope is not None:
            if 'populated 0' not in read_at(scope,'cgroup.events').splitlines():raise BoundaryError('CLEANUP_INCOMPLETE')
            os.rmdir(scope_name(r),dir_fd=self.cgroup_fd)
            os.close(self.scopes.pop(r['handle']))
        root=self._owned_fd(self.root_fd,r,'root')
        if root is not None:
            os.close(root);delete_tree_at(self.root_fd,scope_name(r))
        if r['handle'] in self.roots:os.close(self.roots.pop(r['handle']))

    def recover(self,r,actions):
        self.prove(r);self.terminate(r);self.remove(r)

    def close(self):
        for fd in self.scopes.values():os.close(fd)
        for fd in self.roots.values():os.close(fd)
        for process in self.children.values():process.close()
        self.children.clear();self.scopes.clear();self.roots.clear();os.close(self.root_fd);os.close(self.cgroup_fd)
