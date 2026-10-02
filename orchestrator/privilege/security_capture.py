"""B8 fixed read-only capture recipe, inert until explicitly called.

Not installed, not RPC-exposed, not called by run_worker/service. Only an already
owned LinuxDriver validation ledger may issue this reader. Pending readers are
registered before FD allocation and must close before positive cleanup proof.
Tests use recording FD fixtures; Stage31C never activates a live backend.
"""
import contextlib
import hashlib
import os
import select
import stat
import time
import threading
from . import protocol as p
from . import security_observe as obs
from . import security_proof as proof
from .kernel import LinuxDriver, InstallationPermit

READ_BUDGET=65536
READ_NS=500_000_000


class OwnedSecurityCapture:
    def __init__(self,*args,**kwargs):raise p.BoundaryError('POLICY_REJECTED')

    @classmethod
    def _from_owned_driver(cls,driver,record,entry,expectation):
        # No controller/model PID/path/FD input. The deterministic helper ledger
        # chooses the scope and registry artifact. Root caller alone is not proof.
        if (type(driver) is not LinuxDriver or type(getattr(driver,'permit',None)) is not InstallationPermit or not driver.qualified or record['owner']!=driver.owner
                or record['handle'] not in driver.children or record['boot_id']!=driver.boot_id or not entry.validation
                or driver.permit.policy_hash!=expectation.binding['policy'] or expectation.binding!=proof_binding(record,entry)
                or expectation.scope!=(record['scope_device'],record['scope_inode'])):
            raise p.BoundaryError('POLICY_REJECTED')
        process=driver.children[record['handle']]
        if process.fd is None or process.handle!=record['handle']:raise p.BoundaryError('UNKNOWN_HANDLE')
        driver.prove(record)  # descriptor/inode ownership; no mutations
        value=object.__new__(cls);value.driver=driver;value.record=record;value.entry=entry;value.expectation=expectation
        value.closed=False;value.cleanup_unproven=False;value.subject_start=None
        value.descendant_fds={};value.private_proc=None;value.worker_ns=None;value.namespace_match=None
        value.scope=None;value.host=None;value._lock=threading.RLock()
        # Register the pending acquisition before any descriptor is allocated.
        # The driver refuses positive absence while this reservation exists.
        value._lock.acquire()
        try:driver._register_observer(record,value)
        except Exception:
            value._lock.release();raise
        def close_pending(fd):
            try:os.close(fd)
            except OSError:
                driver.close_errors.add(record['handle']);raise p.BoundaryError('CLEANUP_INCOMPLETE') from None
        try:
            with contextlib.ExitStack() as pending:
                value.scope=os.dup(driver._scope(record));pending.callback(close_pending,value.scope)
                os.set_inheritable(value.scope,False)
                value.host=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);pending.callback(close_pending,value.host)
                pending.pop_all()
        except Exception:
            # ExitStack attempted every acquired FD. Do not retry numeric FDs
            # whose close outcome is ambiguous; retain the ownership fence.
            value.closed=True;value.scope=None;value.host=None
            value.cleanup_unproven=record['handle'] in driver.close_errors
            if not value.cleanup_unproven:driver._forget_observer(record,value)
            raise p.BoundaryError('BACKEND_FAILURE') from None
        finally:value._lock.release()
        return value

    def __enter__(self):return self
    def __exit__(self,*args):self.close()

    def close(self):
        lock=getattr(self,'_lock',None)
        if lock is None:
            self._close();return
        try:acquired=lock.acquire(timeout=READ_NS/1_000_000_000)
        except Exception:acquired=False
        if not acquired:
            # Joining/cancelling a task does not prove that its active reader
            # stopped. Retain the exact reader and fence; do not block remaining
            # owned termination forever on its lock or close FDs underneath it.
            self.cleanup_unproven=True;self.driver.close_errors.add(self.record['handle'])
            raise p.BoundaryError('CLEANUP_INCOMPLETE')
        try:self._close()
        finally:lock.release()

    def _close(self):
        if self.closed:return
        self.closed=True;failed=False
        for fd in (self.scope,self.host,*self.descendant_fds.values(),self.private_proc):
            if fd is None:continue
            try:os.close(fd)
            except Exception:failed=True
        if failed:
            self.cleanup_unproven=True;self.driver.close_errors.add(self.record['handle'])
            raise p.BoundaryError('CLEANUP_INCOMPLETE')
        if hasattr(self.driver,'_forget_observer'):
            self.driver._forget_observer(self.record,self)

    def _check(self):
        if self.closed:raise p.BoundaryError('INVALID_STATE')
        now=time.monotonic_ns()
        if not self.expectation.started_ns<=now<=self.expectation.started_ns+proof.MAX_CAPTURE_NS:raise p.BoundaryError('INVALID_STATE')
        self.driver.prove(self.record)
        info=os.fstat(self.scope)
        if (info.st_dev,info.st_ino)!=(self.record['scope_device'],self.record['scope_inode']):raise p.BoundaryError('POLICY_REJECTED')

    def _close_fd(self,fd):
        try:os.close(fd)
        except OSError:
            self.cleanup_unproven=True;self.driver.close_errors.add(self.record['handle'])
            raise p.BoundaryError('CLEANUP_INCOMPLETE') from None

    def _read(self,fd,name):
        # Fixed call sites below; no exported arbitrary path API. NONBLOCK and
        # one aggregate read budget/deadline per capture. Only regular proc/cgroup.
        self._deadline()
        if '/' in name or name not in ('status','stat','mountinfo','cgroup.procs','cgroup.events','cpu.max','cpu.stat','memory.max','memory.swap.max','memory.peak','memory.events','pids.max','pids.peak','pids.current','pids.events'):
            raise p.BoundaryError('PATH_REJECTED')
        child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
        try:
            if not stat.S_ISREG(os.fstat(child).st_mode):raise p.BoundaryError('PATH_REJECTED')
            chunks=[]
            while True:
                self._deadline();raw=os.read(child,min(self.budget+1,4096))
                self.budget-=len(raw)
                if self.budget<0:raise p.BoundaryError('BOUNDS_EXCEEDED')
                if not raw:break
                chunks.append(raw)
            return b''.join(chunks)
        finally:self._close_fd(child)

    def _deadline(self):
        if time.monotonic_ns()>self.deadline:raise p.BoundaryError('TRANSPORT_FAILURE')

    def _members(self):
        raw=self._read(self.scope,'cgroup.procs')
        values=[obs.number(v) for v in raw.decode('ascii').split()]
        if len(values)>proof.MAX_PROCESSES or len(set(values))!=len(values) or any(not v for v in values):raise p.BoundaryError('BOUNDS_EXCEEDED')
        return values

    def _directory(self,fd,name):
        return os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)

    def _names(self,fd,limit):
        values=[]
        with os.scandir(fd) as iterator:
            for item in iterator:
                self._deadline();values.append(item.name)
                if len(values)>limit:raise p.BoundaryError('BOUNDS_EXCEEDED')
        return values

    def _namespace(self,fd):
        result={}
        ns=self._directory(fd,'ns')
        try:
            # Intentional proc namespace links, never generic host traversal.
            for kind in proof.NAMESPACES:
                self._deadline();result[kind]=os.stat(kind,dir_fd=ns).st_ino
        finally:self._close_fd(ns)
        return result

    def _isolation(self):
        """Capture one identified executable in the owned scope, not raw PID RPC.

        Returns explicit OBSERVED_SUMMARY data, not ENFORCEMENT_PROVEN records.
        Missing/exit races are failures, never copied from B7 child claims.
        """
        self._check();self.budget=READ_BUDGET;self.deadline=time.monotonic_ns()+READ_NS
        # Scope membership supplies candidate PIDs. Pin proc entry before pidfd;
        # stale proc FDs fail on exit and are never reopened by an untrusted PID.
        found=[]
        with contextlib.ExitStack() as resources:
            own=self._directory(self.host,str(os.getpid()));resources.callback(self._close_fd,own)
            host_ns=self._namespace(own)
            for pid in self._members():
                self._deadline()
                proc=self._directory(self.host,str(pid));resources.callback(self._close_fd,proc)
                before=self._read(proc,'stat');start=proc_start(before)
                pidfd=os.pidfd_open(pid,0);resources.callback(self._close_fd,pidfd);os.set_inheritable(pidfd,False)
                if select.select([pidfd],[],[],0)[0]:continue
                # Intentional fixed executable proc link, verified byte-for-byte
                # against the immutable approved artifact, with bounded reading.
                exe=os.open('exe',os.O_RDONLY|os.O_CLOEXEC,dir_fd=proc);resources.callback(self._close_fd,exe)
                pinned=os.fstat(exe);expected=self.entry.executable
                if (pinned.st_dev,pinned.st_ino)!=(expected.device,expected.inode):continue
                if pinned.st_size>32*1024*1024:raise p.BoundaryError('BOUNDS_EXCEEDED')
                digest=hashlib.sha256();offset=0
                while offset<pinned.st_size:
                    self._deadline();block=os.pread(exe,min(65536,pinned.st_size-offset),offset)
                    if not block:raise p.BoundaryError('POLICY_REJECTED')
                    digest.update(block);offset+=len(block)
                if digest.hexdigest()!=expected.digest:raise p.BoundaryError('POLICY_REJECTED')
                identity,caps,inner=obs.status(self._read(proc,'status'))
                if inner!=1:continue  # approved namespace init, not its descendants
                if self.subject_start is not None and self.subject_start!=start:raise p.BoundaryError('POLICY_REJECTED')
                fd_dir=self._directory(proc,'fd');resources.callback(self._close_fd,fd_dir)
                standards=[os.stat(str(v),dir_fd=fd_dir) for v in range(3)]  # fixed owned proc FD links
                safe=stat.S_ISFIFO(standards[0].st_mode) and stat.S_ISFIFO(standards[1].st_mode) and stat.S_ISCHR(standards[2].st_mode) and (os.major(standards[2].st_rdev),os.minor(standards[2].st_rdev))==(1,3)
                inventory=obs.fds(self._names(fd_dir,proof.MAX_FDS),standard_safe=safe)
                namespaces=obs.namespace_comparison(host_ns,self._namespace(proc),inner)
                root=os.open('root',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=proc);resources.callback(self._close_fd,root)
                device_dir=self._directory(root,'dev');resources.callback(self._close_fd,device_dir)
                devices={}
                for name in self._names(device_dir,16):
                    info=os.stat(name,dir_fd=device_dir,follow_symlinks=False)
                    devices[name]={'character':stat.S_ISCHR(info.st_mode),'major':os.major(info.st_rdev),'minor':os.minor(info.st_rdev),'mode':stat.S_IMODE(info.st_mode)}
                forbidden_absent=True
                for name in ('root','etc/freeagentos-stage31d','var/lib/freeagentos-stage31d','var/run/docker.sock'):
                    forbidden_absent &= self._absent(root,name)
                root_info=os.fstat(root);runtime=os.fstat(self.entry.runtime_fd)
                private_proc=self._directory(root,'proc');resources.callback(self._close_fd,private_proc)
                fs=obs.filesystem(self._read(proc,'mountinfo'),root=(root_info.st_dev,root_info.st_ino),
                    runtime=(runtime.st_dev,runtime.st_ino),proc_device=os.fstat(private_proc).st_dev,
                    host_proc_device=os.fstat(self.host).st_dev,devices=devices,forbidden_absent=forbidden_absent)
                if proc_start(self._read(proc,'stat'))!=start:raise p.BoundaryError('POLICY_REJECTED')
                if select.select([pidfd],[],[],0)[0] or pid not in self._members():raise p.BoundaryError('POLICY_REJECTED')
                matched_start=start
                if self.private_proc is None:
                    self.private_proc=os.dup(private_proc);os.set_inheritable(self.private_proc,False)
                self.worker_ns=namespaces['worker']['pid']
                found.append({'identity':identity,'capabilities':caps,'fds':inventory,'namespaces':namespaces,'filesystem':fs})
            if len(found)!=1:raise p.BoundaryError('INVALID_STATE')
            self.subject_start=matched_start;self._check();return {'schema_version':1,'source':'OWNED_KERNEL_READ','enforcement':'UNPROVEN',
                                  **self._header(),'data':found[0]}

    def _resources(self):
        self._check();self.budget=READ_BUDGET;self.deadline=time.monotonic_ns()+READ_NS
        # Reads are paired by the later coordinator using one sample+owned scope.
        result={'cpu':obs.cpu(self._read(self.scope,'cpu.max'),self._read(self.scope,'cpu.stat')),
                'memory':obs.memory(self._read(self.scope,'memory.max'),self._read(self.scope,'memory.swap.max'),self._read(self.scope,'memory.peak'),self._read(self.scope,'memory.events')),
                'pids':obs.pids(self._read(self.scope,'pids.max'),self._read(self.scope,'pids.peak'),self._read(self.scope,'pids.events'))}
        self._check();return {'schema_version':1,'source':'OWNED_KERNEL_READ',**self._header(),'enforcement':'UNPROVEN','data':result}

    def _containment(self):
        self._check();self.budget=READ_BUDGET;self.deadline=time.monotonic_ns()+READ_NS
        released=self.record['state']=='RELEASED' and self.record['cleanup']=='CONFIRMED'
        if released and self.driver.absent(self.record):members=[]
        else:members=self._members()
        # Exclude only the owned trusted outer launcher, never caller-selected PIDs.
        process=self.driver.children.get(self.record['handle'])
        launcher=process.child.pid if process is not None and process.child is not None else None
        inner_members=[]
        for pid in members:
            if pid==launcher:continue
            proc=self._directory(self.host,str(pid))
            try:
                identity,caps,inner=obs.status(self._read(proc,'status'))
                if self._namespace(proc)['pid']!=self.worker_ns:raise p.BoundaryError('POLICY_REJECTED')
                inner_members.append(inner)
            finally:self._close_fd(proc)
            if pid in self.descendant_fds and select.select([self.descendant_fds[pid]],[],[],0)[0]:raise p.BoundaryError('INVALID_STATE')
            if pid==launcher or pid in self.descendant_fds:continue
            if len(self.descendant_fds)>=proof.MAX_PROCESSES:raise p.BoundaryError('BOUNDS_EXCEEDED')
            with contextlib.ExitStack() as pinned:
                proc=self._directory(self.host,str(pid));pinned.callback(self._close_fd,proc)
                start=proc_start(self._read(proc,'stat'))
                fd=os.pidfd_open(pid,0)
                try:
                    os.set_inheritable(fd,False)
                    if select.select([fd],[],[],0)[0] or proc_start(self._read(proc,'stat'))!=start or pid not in self._members():raise p.BoundaryError('INVALID_STATE')
                    self.descendant_fds[pid]=fd  # kernel-derived PID is PRIVATE; only counts leave
                except Exception:
                    self._close_fd(fd);raise
        namespace_checked=False;contained=False
        if released and self.driver.absent(self.record):
            namespace_checked=self.namespace_match is not None;contained=self.namespace_match is True
        elif self.private_proc is not None:
            private=[int(v) for v in self._names(self.private_proc,128) if v.isdecimal()]
            if len(private)>proof.MAX_PROCESSES:raise p.BoundaryError('BOUNDS_EXCEEDED')
            if set(members)!=set(self._members()):raise p.BoundaryError('INVALID_STATE')
            namespace_checked=True;contained=set(private)==set(inner_members)
            self.namespace_match=contained
        # One PID namespace init is the fixture itself, others are descendants.
        observed=max(0,len(self.descendant_fds)-1)
        exited=all(bool(select.select([fd],[],[],0)[0]) for fd in self.descendant_fds.values())
        empty=not members
        data={'created':observed,'contained':contained,'namespace_checked':namespace_checked,'population':len(members),'pidfds_exited':exited,
              'scope_empty':empty,'reaped':empty and self.record['handle'] in self.driver.launch_settled,
              'released':released,'cleanup_confirmed':released and self.driver.absent(self.record)}
        # This is an owned-scope observation. It proves membership of seen
        # descendants, not absence of an unobserved escape; evaluator requires
        # the independent global-namespace/fixed-fixture containment check below.
        return {'schema_version':1,'source':'OWNED_KERNEL_READ','enforcement':'UNPROVEN',**self._header(),'data':data}

    def _header(self):
        return {'binding':dict(self.expectation.binding),'sample':self.expectation.sample,
                'subject':self.expectation.subject,'scope':list(self.expectation.scope),
                'at_ns':time.monotonic_ns()}

    def _absent(self,root,relative):
        # Only the fixed forbidden paths chosen in _isolation reach here.
        with contextlib.ExitStack() as parents:
            directory=root;parts=relative.split('/')
            for part in parts[:-1]:
                try:directory=self._directory(directory,part)
                except FileNotFoundError:return True
                parents.callback(self._close_fd,directory)
            try:os.stat(parts[-1],dir_fd=directory,follow_symlinks=False)
            except FileNotFoundError:return True
            return False

    def _capture(self,method):
        lock=getattr(self,'_lock',None)
        with lock if lock is not None else contextlib.nullcontext():
            return self._capture_locked(method)

    def _capture_locked(self,method):
        try:return method()
        except p.BoundaryError:raise
        except Exception:
            # Unknown read/FD failure is retained; no observation or clean claim.
            self.cleanup_unproven=True;self.driver.close_errors.add(self.record['handle'])
            raise p.BoundaryError('BACKEND_FAILURE') from None

    def isolation(self):return self._capture(self._isolation)
    def resources(self):return self._capture(self._resources)
    def containment(self):return self._capture(self._containment)


def proof_binding(record,entry):
    from .evidence import binding
    return binding(record,entry)


def proc_start(raw):
    # stat comm can contain ')' and spaces; field22 remains in the fixed suffix.
    if type(raw) is not bytes or len(raw)>8192 or b') ' not in raw:raise p.BoundaryError('INVALID_REQUEST')
    try:fields=raw.rsplit(b') ',1)[1].decode('ascii').split();return obs.number(fields[19])
    except (IndexError,UnicodeError):raise p.BoundaryError('INVALID_REQUEST') from None
