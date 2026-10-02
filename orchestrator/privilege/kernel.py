"""Real Linux operations, unreachable without an administrator installation permit.

Only fixed descriptor-derived recipes. No public RPC imports or model imports.
"""
import ctypes
from dataclasses import dataclass
import json
import os
import select
import signal
import stat
import subprocess
import time
from .linux import secure_open, OwnedPidfd, ChildSetup, platform_report
from .protocol import BoundaryError, identifier
from .security import private_file
from .policy import resource_limits
from .evidence import SyntheticCollector, binding, validate

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
        self.launcher=launcher;self.owner=owner;self.scopes={};self.roots={};self.children={};self.launch_fds={};self.close_errors=set();self.launch_settled=set();self.validation_files={};self.qualified=False;self.sealed=set();self.collectors={};self.proofs={};self.proof_bindings={}
        self.observers={}
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
        owned=[];self.launch_fds[r['handle']]=owned
        process=None;failed=False
        try:
            workspace=secure_open(root,'workspace',os.O_RDONLY|os.O_DIRECTORY);owned.append(workspace)
            rootfs=os.dup(root);owned.append(rootfs)
            read_barrier,write_barrier=os.pipe2(os.O_CLOEXEC);owned.extend((read_barrier,write_barrier))
            receipt_r,receipt_w=os.pipe2(os.O_CLOEXEC);owned.extend((receipt_r,receipt_w))
            fds=(workspace,rootfs,entry.runtime_fd,entry.executable.fd,read_barrier,receipt_w)
            config={'version':1,'class':entry.execution,'role':entry.role,'uid':entry.uid,'gid':entry.gid,
                    'job_id':entry.job_id,'validation':entry.validation,'fds':list(fds),'limits':limits}
            # Reserve the ownership slot before creating any process. Failure to
            # register cannot strand a child outside the supervisor ledger.
            process=OwnedPidfd.pending(r['handle'],None)
            self.children[r['handle']]=process
            child=subprocess.Popen(['freeagentos-launcher','-I','-m','orchestrator.privilege.child'],
                executable='/proc/self/fd/'+str(self.launcher.fd),pass_fds=(*fds,self.launcher.fd),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE if entry.validation else subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},close_fds=True)
            process.child=child
            process.acquire()
            self._write(self.scopes[r['handle']],'cgroup.procs',child.pid)
            child.stdin.write(json.dumps(config,separators=(',',':')).encode());child.stdin.close()
            os.write(write_barrier,b'G')
            receipt=bytearray();deadline=time.monotonic()+10
            while len(receipt)<len(b'EXEC_READY\n'):
                remaining=deadline-time.monotonic()
                if remaining<=0 or not select.select([receipt_r],[],[],remaining)[0]:raise BoundaryError('BACKEND_FAILURE')
                raw=os.read(receipt_r,len(b'EXEC_READY\n')-len(receipt))
                if not raw:raise BoundaryError('BACKEND_FAILURE')
                receipt.extend(raw)
            if receipt!=b'EXEC_READY\n':raise BoundaryError('BACKEND_FAILURE')
            if entry.validation:
                identity=binding(r,entry)
                self.proof_bindings[r['handle']]=identity
                collector=SyntheticCollector(identity,child,receipt_r)
                self.collectors[r['handle']]=collector
                owned.remove(receipt_r)  # exact ownership transfer, not FD duplication
                collector.start()
        except Exception:
            failed=True
        # FD closure is part of launch success, and each closure is independent.
        if not self._close_launch_fds(r['handle']):failed=True
        if failed:
            try:self.terminate(r,process)
            except Exception:pass  # retained child/FD ownership + durable start intent
            raise BoundaryError('BACKEND_FAILURE') from None
        return process

    def _close_launch_fds(self,handle):
        pending=self.launch_fds.get(handle,[])
        for fd in tuple(pending):
            pending.remove(fd)
            try:os.close(fd)
            except Exception:self.close_errors.add(handle)
        self.launch_fds.pop(handle,None)
        # Ambiguous close is retained as dirty evidence, never a numeric FD to
        # retry after possible kernel release/reuse. Other closes still run.
        return handle not in self.close_errors

    def running(self,r,process):return process.running(r['handle'])

    def collection_failed(self,handle):
        collector=self.collectors.get(handle)
        observer=getattr(self,'observers',{}).get(handle)
        if observer is not None:
            from .security_proof import MAX_CAPTURE_NS
            if time.monotonic_ns()>observer.expectation.started_ns+MAX_CAPTURE_NS:
                try:observer.close()
                except Exception:pass  # retain owned reader and dirty evidence
                self.close_errors.add(handle)
        return handle in self.close_errors or collector is not None and collector.close_failed

    def collect(self,r):
        if r['owner']!=self.owner:raise BoundaryError('UNKNOWN_HANDLE')
        collector=self.collectors.get(r['handle'])
        value=collector.snapshot() if collector is not None else self.proofs.get(r['handle'])
        if value is None:raise BoundaryError('INVALID_STATE')  # no invented evidence
        identity=self.proof_bindings[r['handle']]
        if any(identity[k]!=r[k] for k in identity if k!='executable_sha256'):raise BoundaryError('POLICY_REJECTED')
        return validate(value,identity)

    def _register_observer(self,r,observer):
        if r['owner']!=self.owner or r['state']!='RUNNING' or r['handle'] not in self.children:
            raise BoundaryError('POLICY_REJECTED')
        if not hasattr(self,'observers'):self.observers={}
        if r['handle'] in self.observers:raise BoundaryError('INVALID_STATE')
        self.observers[r['handle']]=observer

    def _forget_observer(self,r,observer):
        if getattr(self,'observers',{}).get(r['handle']) is not observer:
            raise BoundaryError('CLEANUP_INCOMPLETE')
        self.observers.pop(r['handle'])

    def _close_observers(self,r):
        observer=getattr(self,'observers',{}).get(r['handle'])
        if observer is None:return
        try:observer.close()
        except Exception:
            self.close_errors.add(r['handle']);raise BoundaryError('CLEANUP_INCOMPLETE') from None
        if r['handle'] in self.observers:
            self.close_errors.add(r['handle']);raise BoundaryError('CLEANUP_INCOMPLETE')

    def terminate(self,r,process=None):
        if r['owner']!=self.owner:raise BoundaryError('UNKNOWN_HANDLE')
        owned=self.children.get(r['handle'])
        if process is not None and process is not owned:raise BoundaryError('UNKNOWN_HANDLE')
        process=owned;failed=False
        try:self._close_observers(r)
        except Exception:failed=True  # never skip scope/child/pipe cleanup
        collector=self.collectors.get(r['handle'])
        if collector is not None:
            try:
                collector.close();self.proofs[r['handle']]=collector.snapshot()
                self.collectors.pop(r['handle'])
            except Exception:
                failed=True;self.close_errors.add(r['handle'])
        # Failure draining the scope must not skip direct-child or FD cleanup.
        try:
            fd=self._scope(r)
            if fd is not None:
                self._write(fd,'cgroup.kill',1)
                deadline=time.monotonic()+2
                while 'populated 0' not in read_at(fd,'cgroup.events').splitlines():
                    if time.monotonic()>=deadline:raise BoundaryError('CLEANUP_INCOMPLETE')
                    time.sleep(.01)
        except Exception:failed=True
        if process is not None and process.child is None:
            self.children.pop(r['handle'],None)  # reservation; Popen never succeeded
        elif process is not None:
            reaped=False;closed=True
            try:
                # Popen owns the unreaped direct child even before attachment or
                # pidfd acquisition. Its kill method checks child exit/reaping;
                # no external PID or process-group interface is accepted here.
                if process.child.poll() is None:
                    if process.fd is not None:signal.pidfd_send_signal(process.fd,signal.SIGKILL)
                    else:process.child.kill()
            except Exception:failed=True
            try:process.child.wait(timeout=2);reaped=True
            except Exception:failed=True
            for pipe in (process.child.stdin,process.child.stdout,process.child.stderr):
                if pipe is not None:
                    try:pipe.close()
                    except Exception:closed=False;failed=True
            try:process.close()
            except Exception:closed=False;failed=True
            if process.close_failed:closed=False;failed=True
            if reaped and closed:self.children.pop(r['handle'],None)
        if not self._close_launch_fds(r['handle']):failed=True
        if failed:raise BoundaryError('CLEANUP_INCOMPLETE') from None
        self.launch_settled.add(r['handle'])

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
        if r['owner']!=self.owner or r['handle'] in self.children or r['handle'] in self.collectors or r['handle'] in getattr(self,'observers',{}) or self.launch_fds.get(r['handle']) or r['handle'] in self.close_errors:return False
        name=scope_name(r)
        for fd in (self.root_fd,self.cgroup_fd):
            try:os.stat(name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:continue
            return False
        return True

    def prove(self,r):
        if r['owner']!=self.owner:raise BoundaryError('CLEANUP_INCOMPLETE')
        # A restart loses an unattached child's Popen/pidfd reference. Empty
        # scope/root alone cannot disprove that orphan. Retain dirty admission
        # until independently owned cleanup is established; never scan PIDs.
        if (r.get('started_ns',0)>0 and r['state'] in ('CREATED','FAILED_DIRTY')
                and r['handle'] not in self.children and r['handle'] not in self.launch_settled):
            raise BoundaryError('CLEANUP_INCOMPLETE')
        scope=self._scope(r)
        root=self._owned_fd(self.root_fd,r,'root')
        if root is not None:os.close(root)
        return {'scope':True,'root':True}  # verified matching inode or absence

    def remove(self,r):
        if r['owner']!=self.owner or r['handle'] in self.children or r['handle'] in self.collectors or r['handle'] in getattr(self,'observers',{}) or self.launch_fds.get(r['handle']) or r['handle'] in self.close_errors:raise BoundaryError('CLEANUP_INCOMPLETE')
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
        failed=False
        for handle,observer in list(getattr(self,'observers',{}).items()):
            try:observer.close()
            except Exception:self.close_errors.add(handle);failed=True
            if handle in self.observers:self.close_errors.add(handle);failed=True
        for handle,collector in self.collectors.items():
            try:collector.close()
            except Exception:self.close_errors.add(handle);failed=True
        fds=(*self.scopes.values(),*self.roots.values(),self.root_fd,self.cgroup_fd)
        self.scopes.clear();self.roots.clear();self.root_fd=None;self.cgroup_fd=None
        # Retain failure evidence, never retry an ambiguous numeric FD after reuse.
        for fd in fds:
            if fd is None:continue
            try:os.close(fd)
            except Exception:failed=True
        for process in self.children.values():
            try:process.close()
            except Exception:failed=True
        if failed:raise BoundaryError('CLEANUP_INCOMPLETE')
        self.children.clear();self.scopes.clear();self.roots.clear()
