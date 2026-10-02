"""Fixed trusted single-thread launcher. NEVER executed during Stage3.1C.

No subprocess preexec_fn and no root model exec. Parent attaches the launcher
before pipe release; PID namespace init then executes only after all drops.
"""
import ctypes
import json
import os
import resource
import stat
import sys
import threading
from .linux import ChildSetup, secure_open
from .policy import resource_limits, worker_environment
from .protocol import BoundaryError, identifier, _pairs
from .execution import FLAGS

DEVICES=(('null',1,3),('zero',1,5),('random',1,8),('urandom',1,9))
ORDER=('CGROUP_BARRIER','UNSHARE','PID_NAMESPACE_FORK','PRIVATE_PROPAGATION','ROOTFS',
       'MINIMAL_DEVICES_PROC','CHROOT_CHDIR','RLIMITS','DROP_BOUNDING_AMBIENT','CLEAR_GROUPS',
       'SET_GID','SET_UID','CLEAR_CAPSET','NO_NEW_PRIVS','CLOSE_PRIVILEGED_FDS','EXEC')


def validate_configuration(c):
    from .policy import execution_class
    if type(c) is not dict or set(c)!= {'version','class','role','uid','gid','job_id','validation','fds','limits'}:
        raise BoundaryError('INVALID_REQUEST')
    if type(c['version']) is not int or c['version']!=1:raise BoundaryError('PROTOCOL_MISMATCH')
    execution_class(c['class'],c['role'])
    if (type(c['validation']) is not bool or not identifier(c['job_id'])
            or any(type(c[k]) is not int or not 1<=c[k]<2**31 for k in ('uid','gid'))
            or type(c['fds']) is not list or len(c['fds'])!=6
            or any(type(fd) is not int or not 3<=fd<=65535 for fd in c['fds']) or len(set(c['fds']))!=6):
        raise BoundaryError('POLICY_REJECTED')
    if resource_limits(c['class'],c['role'],c['limits'])!=c['limits']:raise BoundaryError('RESOURCE_LIMIT_INVALID')
    return c


class ChildRoutine:
    """Same exact composition with real calls or an injected recording syscall set."""
    def __init__(self,calls):self.calls=calls
    def run(self,config):
        validate_configuration(config)
        for operation in ORDER:
            self.calls.perform(operation,config)


class LinuxChildCalls:
    def __init__(self):
        if os.geteuid()!=0 or threading.active_count()!=1:raise BoundaryError('POLICY_REJECTED')
        self.setup=ChildSetup();self.position=0;self.libc=ctypes.CDLL(None,use_errno=True)

    def _mount(self,source,target,kind=None,flags=0,options=None):
        def encoded(v):return os.fsencode(v) if v is not None else None
        if self.libc.mount(ctypes.c_char_p(encoded(source)),ctypes.c_char_p(encoded(target)),
                           ctypes.c_char_p(encoded(kind)),ctypes.c_ulong(flags),ctypes.c_char_p(encoded(options)))!=0:
            raise BoundaryError('BACKEND_FAILURE')

    def _copy(self,source,dest,uid,gid,budget=None):
        if budget is None:budget=[20000,192*1024*1024]
        for name in os.listdir(source):
            budget[0]-=1
            if budget[0]<0:raise BoundaryError('BOUNDS_EXCEEDED')
            fd=secure_open(source,name)
            try:
                info=os.fstat(fd)
                if stat.S_ISDIR(info.st_mode):
                    os.mkdir(name,0o700,dir_fd=dest)
                    out=secure_open(dest,name,os.O_RDONLY|os.O_DIRECTORY)
                    try:self._copy(fd,out,uid,gid,budget);os.fchown(out,uid,gid)
                    finally:os.close(out)
                else:
                    out=os.open(name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dest)
                    try:
                        while block:=os.read(fd,65536):
                            budget[1]-=len(block)
                            if budget[1]<0:raise BoundaryError('BOUNDS_EXCEEDED')
                            view=memoryview(block)
                            while view:
                                n=os.write(out,view)
                                if n<=0:raise BoundaryError('BACKEND_FAILURE')
                                view=view[n:]
                        os.fchown(out,uid,gid)
                    finally:os.close(out)
            finally:os.close(fd)

    def perform(self,op,c):
        if self.position>=len(ORDER) or op!=ORDER[self.position]:raise BoundaryError('INVALID_STATE')
        self.position+=1
        workspace,runroot,runtime,executable,barrier,receipt=c['fds']
        # These are inherited helper-only FDs, not raw caller paths. Rootfs is
        # under a private helper-owned parent and never writable by a worker.
        target='/proc/self/fd/'+str(runroot)+'/rootfs'
        if op=='CGROUP_BARRIER':
            if os.read(barrier,1)!=b'G':raise BoundaryError('POLICY_REJECTED')
            os.close(barrier)
        elif op=='UNSHARE':
            # Direct API, single-thread fresh interpreter. NEWPID takes effect
            # for the next fork, not the launcher itself.
            flags=0x20000|0x20000000|(0x40000000 if c['class']=='DETERMINISTIC_TESTER' or c['validation'] else 0)
            if self.libc.unshare(ctypes.c_int(flags))!=0:raise BoundaryError('BACKEND_FAILURE')
        elif op=='PID_NAMESPACE_FORK':
            child=os.fork()
            if child:
                for fd in c['fds']:
                    try:os.close(fd)
                    except OSError:pass
                _,status=os.waitpid(child,0);os._exit(os.waitstatus_to_exitcode(status)&255)
            if os.getpid()!=1:raise BoundaryError('POLICY_REJECTED')
        elif op=='PRIVATE_PROPAGATION':self._mount(None,'/',flags=16384|262144)
        elif op=='ROOTFS':
            self._mount('/proc/self/fd/'+str(runtime),target,flags=4096)
            self._mount(None,target,flags=4096|32|1|2) # bind remount readonly/nosuid
            for name in ('tmp','run','home','dev','workspace'):
                self._mount('tmpfs',target+'/'+name,'tmpfs',2|(0 if name=='dev' else 4),
                            f"size={c['limits'].get('test_workspace_bytes',67108864) if name=='workspace' else 67108864},nr_inodes=20000,mode=755")
            if c['class']=='DETERMINISTIC_TESTER':
                out=os.open(target+'/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
                try:self._copy(workspace,out,c['uid'],c['gid']);os.fchown(out,c['uid'],c['gid'])
                finally:os.close(out)
            # MODEL/RESEARCH get no direct project read/write access. Their
            # controller-owned broker job remains the only workspace interface.
            os.chown(target+'/tmp',c['uid'],c['gid']);os.chmod(target+'/tmp',0o700)
            os.chown(target+'/home',c['uid'],c['gid']);os.chmod(target+'/home',0o700)
        elif op=='MINIMAL_DEVICES_PROC':
            for name,major,minor in DEVICES:
                os.mknod(target+'/dev/'+name,stat.S_IFCHR|0o666,os.makedev(major,minor));os.chmod(target+'/dev/'+name,0o666)
            self._mount('proc',target+'/proc','proc',2|4|8)
        elif op=='CHROOT_CHDIR':
            os.chroot(target);os.chdir('/workspace' if c['class']=='DETERMINISTIC_TESTER' else '/')
            self.setup.stage='ROOTFS_READY'
        elif op=='RLIMITS':
            limits=c['limits']
            for key,value in ((resource.RLIMIT_CPU,limits['cpu_time_seconds']),
                              (resource.RLIMIT_NOFILE,limits['max_open_files']),
                              (resource.RLIMIT_FSIZE,limits['max_file_size_bytes']),
                              (resource.RLIMIT_CORE,0)):
                resource.setrlimit(key,(value,value))
        elif op=='DROP_BOUNDING_AMBIENT':
            # Atomic identity/capability sequence in the existing syscall wrapper.
            self.setup.drop_identity(c['uid'],c['gid'])
        elif op in ('CLEAR_GROUPS','SET_GID','SET_UID','CLEAR_CAPSET','NO_NEW_PRIVS'):
            if self.setup.stage!='DROPPED':raise BoundaryError('POLICY_REJECTED')
        elif op=='CLOSE_PRIVILEGED_FDS':
            # Enumerate the private fd table before closing proc access. Preserve
            # only ELF executable FD + fixed setup receipt, both CLOEXEC.
            for name in os.listdir('/proc/self/fd'):
                fd=int(name)
                if fd>2 and fd not in (executable,receipt):
                    try:os.close(fd)
                    except OSError:pass
            os.set_inheritable(executable,False);os.set_inheritable(receipt,False)
        elif op=='EXEC':
            if self.setup.stage!='DROPPED':raise BoundaryError('POLICY_REJECTED')
            if os.pread(executable,4,0)!=b'\x7fELF':raise BoundaryError('POLICY_REJECTED')
            argv=['freeagentos-worker','--synthetic'] if c['validation'] else ['freeagentos-worker',*FLAGS[c['class']],c['job_id']]
            environment=worker_environment({});environment['HOME']='/home';environment['TMPDIR']='/tmp'
            os.write(receipt,b'EXEC_READY\n')
            os.execve(executable,argv,environment)


def main():
    # Executed solely by a future explicitly authorized root-owned supervisor.
    receipt=None
    try:
        raw=sys.stdin.buffer.read(16385)
        if len(raw)>16384:raise BoundaryError('BOUNDS_EXCEEDED')
        c=json.loads(raw,object_pairs_hook=_pairs)
        validate_configuration(c)
        if c['validation']:receipt=c['fds'][5]
        ChildRoutine(LinuxChildCalls()).run(c)
    except Exception:
        # No raw exceptions, configuration, credentials or worker data printed.
        try:
            if receipt is not None:os.write(receipt,b'EXEC_FAILED\n')
        except Exception:pass  # abrupt exit/EOF alone is never successful exec proof
        os._exit(125)

if __name__=='__main__':main()
