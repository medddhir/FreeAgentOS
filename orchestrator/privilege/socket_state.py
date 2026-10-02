"""Installation-bound socket ledger/lock; no RPC or arbitrary cleanup scanner.

Linux renameat2 retirement avoids unlinking a substituted pathname. The trusted
parent is private/root-owned; enrolled/model identities must not write it.
Same-UID privileged compromise is not defended by advisory locks.
"""
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
from . import protocol as p
from .security import directory_fd

MAX_RECORD = 2048


def _rename(parent, source, target):
    libc=ctypes.CDLL(None,use_errno=True)
    call=getattr(libc,'renameat2',None)
    if call is None:raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
    call.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    call.restype=ctypes.c_int
    if call(parent,os.fsencode(source),parent,os.fsencode(target),1)!=0:
        raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')


class SocketState:
    def __init__(self,path,installation,policy,*,group=None):
        self.path=Path(path);self.name=self.path.name
        self.uid=os.geteuid();self.gid=os.getegid() if group is None else group
        self.mode=0o600 if group is None else 0o660
        self.parent_mode=0o700 if group is None else 0o750
        self.fd=None;self.lock_fd=None;self.record=None;self.closed=False
        if (not self.name or len(os.fsencode(self.name))>64 or self.name in ('.','..')
                or type(installation) is not dict or set(installation)!={'owner','enrollment'}
                or any(not p.identifier(v) for v in installation.values()) or not p.identifier(policy,64)):
            raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        self.ledger=self.name+'.owner.json';self.lock_name=self.name+'.lock'
        self.retired=self.name+'.retired';self.pending=self.name+'.pending'
        try:
            self.fd=directory_fd(self.path.parent,self.uid,self.parent_mode)
            info=os.fstat(self.fd)
            self.binding={'version':1,'policy':policy,**installation,'name':self.name,
                          'parent_device':info.st_dev,'parent_inode':info.st_ino,
                          'uid':self.uid,'gid':self.gid,'mode':self.mode}
            self.lock_fd=os.open(self.lock_name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600,dir_fd=self.fd)
            self._private(self.lock_fd)
            try:fcntl.flock(self.lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise p.BoundaryError('SOCKET_BUSY') from None
            self.check_parent();self.record=self._load()
        except BaseException as error:
            try:self.close()
            except Exception:raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED') from None
            if isinstance(error,p.BoundaryError) or not isinstance(error,Exception):raise
            raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED') from None

    def _private(self,fd):
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=self.uid or info.st_gid!=os.getegid()
                or stat.S_IMODE(info.st_mode)!=0o600):raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        return info

    def check_parent(self):
        fd=directory_fd(self.path.parent,self.uid,self.parent_mode)
        try:
            a=os.fstat(fd);b=os.fstat(self.fd)
            if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino):raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
            lock=os.stat(self.lock_name,dir_fd=self.fd,follow_symlinks=False)
            held=self._private(self.lock_fd)
            if (lock.st_dev,lock.st_ino)!=(held.st_dev,held.st_ino):raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        finally:os.close(fd)

    def address(self,name=None):
        # Linux AF_UNIX has no bindat/connectat: pinned no-follow parent FD.
        return '/proc/self/fd/'+str(self.fd)+'/'+(self.name if name is None else name)

    def _stat(self,name):
        try:return os.stat(name,dir_fd=self.fd,follow_symlinks=False)
        except FileNotFoundError:return None

    @staticmethod
    def _identity(info):
        return {'device':info.st_dev,'inode':info.st_ino,'ctime_ns':info.st_ctime_ns,
                'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}

    def _load(self):
        try:fd=os.open(self.ledger,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
        except FileNotFoundError:return None
        try:
            info=self._private(fd)
            if info.st_size>MAX_RECORD:raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
            raw=os.read(fd,MAX_RECORD+1)
        finally:os.close(fd)
        try:
            r=json.loads(raw,object_pairs_hook=p._pairs)
            p.keys(r,tuple(self.binding)+('phase','socket'))
            if any(r[k]!=v or type(r[k]) is not type(v) for k,v in self.binding.items()):raise ValueError()
            if r['phase'] not in ('PREPARING','BOUND','READY','CLEAN'):raise ValueError()
            if r['socket'] is not None:
                p.keys(r['socket'],('device','inode','ctime_ns','uid','gid','mode'))
                if any(type(v) is not int or not 0<=v<2**63 for v in r['socket'].values()):raise ValueError()
            if r['phase'] in ('BOUND','READY') and r['socket'] is None:raise ValueError()
            return r
        except (ValueError,TypeError,RecursionError,p.BoundaryError):
            raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED') from None

    def _save(self):
        self.check_parent()
        self._load()  # reject a mismatched/unsafe existing ledger, never relabel it
        raw=json.dumps(self.record,sort_keys=True,separators=(',',':')).encode()
        if len(raw)>MAX_RECORD:raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        # Fixed pending name is protected by the lifetime lock. A leftover is
        # ambiguous: never overwrite/delete it as speculative recovery.
        fd=os.open(self.pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            self._private(fd)
            with os.fdopen(fd,'wb',closefd=False) as out:out.write(raw);out.flush()
            os.fsync(fd)
        finally:os.close(fd)
        os.replace(self.pending,self.ledger,src_dir_fd=self.fd,dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def recover(self):
        self.check_parent()
        if self._stat(self.retired) is not None or self._stat(self.pending) is not None:
            raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        info=self._stat(self.name)
        if info is None:
            if self.record is not None and self.record['phase']!='CLEAN':
                raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
            return
        self.remove()

    def intent(self):
        self.record={**self.binding,'phase':'PREPARING','socket':None};self._save()

    def capture(self,phase):
        self.check_parent();info=self._stat(self.name)
        if info is None or not stat.S_ISSOCK(info.st_mode) or info.st_uid!=self.uid or info.st_nlink!=1:
            raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        old=self.record.get('socket') if self.record else None
        if old is not None and (old['device'],old['inode'])!=(info.st_dev,info.st_ino):
            raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        if phase=='READY' and (info.st_gid!=self.gid or stat.S_IMODE(info.st_mode)!=self.mode):
            raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        self.record={**self.binding,'phase':phase,'socket':self._identity(info)}
        self._save()

    def _owned(self,info):
        if (info is None or not stat.S_ISSOCK(info.st_mode) or self.record is None
                or info.st_nlink!=1
                or self.record['phase'] not in ('BOUND','READY')
                or info.st_uid!=self.uid or info.st_gid not in (os.getegid(),self.gid)
                or self._identity(info)!=self.record['socket']):
            raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        if self.record['phase']=='READY' and (info.st_gid!=self.gid or stat.S_IMODE(info.st_mode)!=self.mode):
            raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')

    def remove(self):
        self.check_parent()
        info=self._stat(self.name)
        if info is None:
            if self.record is None or self.record['phase']!='CLEAN':raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
            return
        self._owned(info)
        if self._stat(self.retired) is not None:raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
        pinned=os.open(self.name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)
        try:
            self._owned(os.fstat(pinned))
            probe=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                probe.settimeout(p.TIMEOUT)
                try:probe.connect(self.address())
                except OSError as error:
                    if error.errno!=errno.ECONNREFUSED:raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED') from None
                else:raise p.BoundaryError('SOCKET_ACTIVE')
            finally:probe.close()
            self.check_parent();self._owned(self._stat(self.name))
            _rename(self.fd,self.name,self.retired)
            # Conditional unlink is unavailable: quarantine without overwriting,
            # then compare against the pinned inode before deleting anything.
            moved=self._stat(self.retired);held=os.fstat(pinned)
            if (moved is None or not stat.S_ISSOCK(moved.st_mode)
                    or (moved.st_dev,moved.st_ino)!=(held.st_dev,held.st_ino)):
                # Restore a raced-in foreign object only if the old name is empty.
                _rename(self.fd,self.retired,self.name)
                raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
            os.unlink(self.retired,dir_fd=self.fd);os.fsync(self.fd)
            self.record={**self.binding,'phase':'CLEAN','socket':None};self._save()
        finally:os.close(pinned)

    def close(self):
        if self.closed:return
        self.closed=True;failed=False
        for name in ('lock_fd','fd'):
            fd=getattr(self,name);setattr(self,name,None)
            if fd is not None:
                try:os.close(fd)
                except OSError:failed=True
        if failed:raise p.BoundaryError('SOCKET_RECOVERY_BLOCKED')
