"""Future administrator-installed service contract. No installation on import."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import threading
from .protocol import BoundaryError, VERSION, BUILD, _pairs, identifier
from .security import directory_fd, private_file, Enrollment, RegisteredRoots
from .policy import policy_hash
from .linux import PinnedFile, secure_open
from .execution import ExecutionRegistry, ApprovedExecution
from .sealed import Seal, SnapshotSource
from .real_journal import ResourceJournal
from .kernel import InstallationPermit, LinuxDriver
from .isolation import LinuxBackend
from .journal import Journal
from .supervisor import Supervisor, LocalServer


# No developer checkout or absolute RPC path. Only administrator configuration.
ADMIN_FIELDS={'version','policy','owner','enrollment','permit_hash','root','cgroup',
              'journal','control_journal','socket','runtime','launcher','worker','workspace','manifest','manifest_hash','worker_uid','worker_gid'}


def owned_file(path,uid=0):return private_file(path,uid)


def trusted_anchor(path,uid=0):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise BoundaryError('PATH_REJECTED')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=nxt
            info=os.fstat(fd)
            if info.st_uid!=uid or info.st_mode & 0o022:raise BoundaryError('POLICY_REJECTED')
        return fd
    except BaseException:
        os.close(fd);raise


def check_package(path,uid=0):
    """Root-owned regular package files and parents, with no writable component."""
    path=Path(path)
    if not path.is_absolute():raise BoundaryError('POLICY_REJECTED')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=nxt
            info=os.fstat(fd)
            if info.st_uid!=uid or info.st_mode & 0o022:raise BoundaryError('POLICY_REJECTED')
        # Check ownership, object type and mode throughout the package tree.
        # Content integrity is a separate artifact/closure observation contract.
        stack=[os.dup(fd)];count=0
        try:
            while stack:
                current=stack.pop()
                try:
                    for name in os.listdir(current):
                        count+=1
                        if count>4096:raise BoundaryError('BOUNDS_EXCEEDED')
                        info=os.stat(name,dir_fd=current,follow_symlinks=False)
                        if info.st_uid!=uid or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):raise BoundaryError('POLICY_REJECTED')
                        if stat.S_ISDIR(info.st_mode):stack.append(os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=current))
                        elif not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise BoundaryError('POLICY_REJECTED')
                finally:os.close(current)
        finally:
            for current in stack:os.close(current)
    except OSError:raise BoundaryError('POLICY_REJECTED') from None
    finally:os.close(fd)


def prepare_enrollment(directory,uid,gid):
    """NON-INSTALLED preparation; caller uses an empty private staging directory.

    No token returned/logged. Future administrator copies server-side material
    and securely delivers a separate private client token file.
    """
    if type(uid) is not int or type(gid) is not int or not 1<=uid<2**31 or not 1<=gid<2**31:
        raise BoundaryError('AUTH_FAILED')
    fd=directory_fd(directory,os.getuid())
    if os.listdir(fd):
        os.close(fd);raise BoundaryError('INVALID_STATE')
    token=secrets.token_hex(32)
    public={'version':VERSION,'build':BUILD,'policy':policy_hash(),'enrollment_id':secrets.token_hex(16),'uid':uid,'gid':gid}
    try:
        for name,raw in (('enrollment.json',json.dumps(public,sort_keys=True,separators=(',',':')).encode()),('token',token.encode())):
            child=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
            try:
                os.fchmod(child,0o600)
                if os.write(child,raw)!=len(raw):raise BoundaryError('BACKEND_FAILURE')
                os.fsync(child)
            finally:os.close(child)
        os.fsync(fd)
    finally:os.close(fd)
    return public  # no credential material


def load_enrollment(directory):
    raw=owned_file(Path(directory)/'enrollment.json')
    try:value=json.loads(raw,object_pairs_hook=_pairs)
    except (ValueError,UnicodeError):raise BoundaryError('AUTH_FAILED') from None
    if (type(value) is not dict or set(value)!= {'version','build','policy','enrollment_id','uid','gid'}
            or type(value['version']) is not int or value['version']!=VERSION
            or value['build']!=BUILD or value['policy']!=policy_hash()):raise BoundaryError('POLICY_REJECTED')
    try:token=owned_file(Path(directory)/'token').decode('ascii')
    except UnicodeError:raise BoundaryError('AUTH_FAILED') from None
    return Enrollment(value['enrollment_id'],value['uid'],value['gid'],token)


def delegated_unit_fd(expected):
    # Root-service activation only: derive service-domain identity from kernel
    # membership before restricting that exact delegated directory. Never a
    # host-root cgroup or arbitrary administrator-selected unrelated subtree.
    with open('/proc/self/cgroup') as stream:membership=stream.read(4097)
    if len(membership)>4096:raise BoundaryError('POLICY_REJECTED')
    lines=membership.splitlines()
    if len(lines)!=1 or not lines[0].startswith('0::/'):raise BoundaryError('POLICY_REJECTED')
    relative=lines[0][4:]
    parts=relative.split('/')
    if len(parts)<2 or parts[-2:]!=['freeagentos-stage31d.service','supervisor']:
        raise BoundaryError('POLICY_REJECTED')
    parent='/sys/fs/cgroup/'+('/'.join(parts[:-1]))
    if parent!=expected:raise BoundaryError('POLICY_REJECTED')
    fd=trusted_anchor(parent)
    try:
        from .kernel import cgroup_qualification
        report=cgroup_qualification(fd)
        if set(report['codes'])-{'CONTROLLERS_DISABLED'}:raise BoundaryError('POLICY_REJECTED')
        os.fchmod(fd,0o700)
        return fd
    except BaseException:
        os.close(fd);raise


def load_admin(path):
    raw=owned_file(path)
    try:c=json.loads(raw,object_pairs_hook=_pairs)
    except (ValueError,UnicodeError):raise BoundaryError('POLICY_REJECTED') from None
    if (type(c) is not dict or set(c)!=ADMIN_FIELDS or type(c['version']) is not int or c['version']!=1
            or c['policy']!=policy_hash() or not identifier(c['owner']) or not identifier(c['permit_hash'],64)
            or not identifier(c['manifest_hash'],64)):
        raise BoundaryError('POLICY_REJECTED')
    for key in ADMIN_FIELDS-{'version','policy','owner','permit_hash','manifest_hash','worker_uid','worker_gid'}:
        if type(c[key]) is not str or len(c[key])>256 or not Path(c[key]).is_absolute() or '..' in Path(c[key]).parts:
            raise BoundaryError('PATH_REJECTED')
    for key in ('worker_uid','worker_gid'):
        if type(c[key]) is not int or not 1<=c[key]<2**31:raise BoundaryError('POLICY_REJECTED')
    return c


def serve(admin_path,permit_path):
    # This is a future Stage31D entrypoint, not called by tests or imports.
    if os.geteuid()!=0:raise BoundaryError('POLICY_REJECTED')
    check_package(Path(__file__).parents[1])
    c=load_admin(admin_path);permit=InstallationPermit.load(permit_path,c['permit_hash'],c['policy'])
    enrollment=load_enrollment(c['enrollment'])
    if c['worker_uid']==enrollment.uid:raise BoundaryError('POLICY_REJECTED')
    roots=RegisteredRoots();fds=[];backend=None;server=None;driver=None;journal=None;control=None;source=None
    try:
        root=directory_fd(c['root'],0);fds.append(root)
        cgroup=delegated_unit_fd(c['cgroup']);fds.append(cgroup)
        runtime=directory_fd(c['runtime'],0,mode=0o755);fds.append(runtime)
        # The controller's enrolled workspace root is opened once, not from RPC.
        roots.register('validation',c['workspace'],enrollment.uid)
        source_fd=roots.check('validation');fds.append(source_fd)
        manifest_parent=directory_fd(Path(c['manifest']).parent,0);fds.append(manifest_parent)
        manifest_fd=secure_open(manifest_parent,Path(c['manifest']).name)
        try:
            info=os.fstat(manifest_fd)
            if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:raise BoundaryError('POLICY_REJECTED')
            raw=os.read(manifest_fd,4*1024*1024+1)
        finally:os.close(manifest_fd)
        seal=Seal.from_verification(raw,c['manifest_hash'])
        source=SnapshotSource(source_fd,seal)
        launcher_parent=trusted_anchor(Path(c['launcher']).parent);fds.append(launcher_parent)
        launcher=PinnedFile.executable(launcher_parent,Path(c['launcher']).name);fds.append(launcher.fd)
        worker=PinnedFile.executable(runtime,c['worker'].removeprefix(c['runtime']+'/'))
        fds.append(worker.fd)
        entry=ApprovedExecution('MODEL_WORKER','coder',worker,runtime,c['worker_uid'],c['worker_gid'],secrets.token_hex(16),True)
        registry=ExecutionRegistry({'validation':entry})
        driver=LinuxDriver(permit,root,cgroup,launcher,c['owner'])
        journal=ResourceJournal(c['journal'],policy_hash(),c['owner'])
        backend=LinuxBackend(registry,{'validation':source},driver,journal,validation_grace=True)
        backend.recover()  # always ownership-proofed, no host scanning
        control=Journal(c['control_journal'],policy_hash())
        supervisor=Supervisor(enrollment,roots,backend,control,linux_validation=True)
        # A recovered previous connection cannot resume. Reconcile both ledgers.
        supervisor.recover()
        parent=Path(c['socket']).parent
        parentfd=trusted_anchor(parent)
        try:
            info=os.fstat(parentfd)
            if info.st_gid!=enrollment.gid or stat.S_IMODE(info.st_mode)!=0o750:raise BoundaryError('POLICY_REJECTED')
        finally:os.close(parentfd)
        server=LocalServer(c['socket'],supervisor,enrolled_group=enrollment.gid).start()
        stopped=threading.Event()
        for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stopped.set())
        stopped.wait()
    finally:
        socket_failed=False
        if server:
            try:server.close()
            except Exception:socket_failed=True  # preserve socket proof; still drain owned backend
        if backend:
            for h,r in list(backend.records.items()):
                if r['state']!='RELEASED':
                    try:backend.cleanup(h)
                    except BoundaryError:pass  # preserve dirty ledger, never claim clean
            backend.close()
        if driver:driver.close()
        if journal:journal.close()
        if control:control.close()
        if source:source.close()
        roots.close()
        for fd in fds:os.close(fd)
        if socket_failed:raise BoundaryError('SOCKET_RECOVERY_BLOCKED') from None


def main():
    parser=argparse.ArgumentParser(description='Administrator-installed synthetic validation supervisor; no automatic installation')
    parser.add_argument('--admin',required=True);parser.add_argument('--permit',required=True)
    args=parser.parse_args()
    try:serve(args.admin,args.permit)
    except Exception:return 2  # no raw privileged exception output
    return 0

if __name__=='__main__':raise SystemExit(main())
