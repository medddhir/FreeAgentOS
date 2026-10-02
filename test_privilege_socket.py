"""B5 local unprivileged socket faults; no installed service or kernel backend."""
import errno
import json
import os
from pathlib import Path
import socket
import unittest
from unittest.mock import patch
from orchestrator.privilege import protocol as p, socket_state as state
from orchestrator.privilege.supervisor import LocalServer
from test_privilege import PrivilegeCases


class SocketRecoveryCases(unittest.TestCase):
    def cases(self):
        for name in ('normal','setup','unproven','stale','active','replacements',
                     'ownership','concurrency','unlink_failure','race','descriptor_failure','journal_failure','policy'):
            with self.subTest(case=name):getattr(self,'case_'+name)()

    def blocked(self,call,code='SOCKET_RECOVERY_BLOCKED'):
        with self.assertRaises(p.BoundaryError) as caught:call()
        self.assertEqual(caught.exception.code,code)

    def crash(self,server):
        # Process-death simulation: close kernel listener/lock FDs, deliberately
        # bypass the normal unlink path. No daemon installed/launched as root.
        server.listener.close();server.socket_state.close();server.closed=True

    def case_normal(self):
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            server=LocalServer(base/'worker.sock',engine).start()
            server.close();server.close()
            self.assertFalse(server.path.exists())
            self.assertIsNone(server.socket_state.fd);self.assertIsNone(server.socket_state.lock_fd)
            record=json.loads((base/'worker.sock.owner.json').read_text())
            self.assertEqual(record['phase'],'CLEAN');self.assertIsNone(record['socket'])
            self.assertNotIn(e.token,json.dumps(record))
            self.assertEqual((base/'worker.sock.owner.json').stat().st_mode&0o777,0o600)
            again=LocalServer(server.path,engine);again.close()

    def case_setup(self):
        real_socket=socket.socket
        for fault in ('chmod','listen','timeout','ready','bound_save','close'):
            with self.subTest(fault=fault):
                with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
                    made=[]
                    class Listener:
                        def __init__(self,*a,**kw):self.raw=real_socket(*a,**kw);made.append(self)
                        def __getattr__(self,key):return getattr(self.raw,key)
                        def listen(self,n):
                            if fault=='listen':raise OSError('private fault')
                            return self.raw.listen(n)
                        def settimeout(self,n):
                            if fault=='timeout' and n==.1:raise OSError('private fault')
                            self.raw.settimeout(n)
                        def close(self):
                            self.raw.close()
                            if fault=='close' and made[0] is self:raise OSError('private fault')
                    capture=state.SocketState.capture;save=state.SocketState._save
                    def fail_capture(obj,phase):
                        if phase=='READY' and fault in ('ready','close'):raise OSError('private fault')
                        return capture(obj,phase)
                    count=[0]
                    def fail_save(obj):
                        count[0]+=1
                        if fault=='bound_save' and count[0]==2:raise OSError('private fault')
                        return save(obj)
                    with patch('orchestrator.privilege.supervisor.socket.socket',Listener), \
                         patch.object(state.SocketState,'capture',fail_capture), \
                         patch.object(state.SocketState,'_save',fail_save):
                        if fault=='chmod':
                            with patch('orchestrator.privilege.supervisor.os.chmod',side_effect=OSError('private fault')):
                                self.blocked(lambda:LocalServer(base/'fail.sock',engine))
                        else:self.blocked(lambda:LocalServer(base/'fail.sock',engine))
                    self.assertTrue(all(x.raw.fileno()==-1 for x in made))
                    self.assertFalse((base/'fail.sock').exists())
                    # Lifetime lock was closed despite failures: restart works.
                    again=LocalServer(base/'fail.sock',engine);again.close()

    def case_unproven(self):
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            with patch.object(state.SocketState,'capture',side_effect=OSError('no identity')):
                self.blocked(lambda:LocalServer(base/'early.sock',engine))
            before=(base/'early.sock').lstat().st_ino
            self.blocked(lambda:LocalServer(base/'early.sock',engine))
            self.assertEqual((base/'early.sock').lstat().st_ino,before)

    def case_stale(self):
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            old=LocalServer(base/'stale.sock',engine);self.crash(old)
            new=LocalServer(old.path,engine).start()
            try:self.assertEqual(json.loads((base/'stale.sock.owner.json').read_text())['phase'],'READY')
            finally:new.close()
            self.assertFalse(old.path.exists())

    def case_active(self):
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            old=LocalServer(base/'active.sock',engine)
            # A listener may outlive the lock holder (e.g. unexpected inherited
            # listener FD). Even free lock + correct ledger cannot authorize it.
            old.socket_state.close()
            try:
                self.blocked(lambda:LocalServer(old.path,engine),'SOCKET_ACTIVE')
                self.assertTrue(old.path.exists())
            finally:old.listener.close();old.closed=True
            new=LocalServer(old.path,engine);new.close()

    def case_replacements(self):
        for kind in ('file','symlink','socket','parent'):
            with self.subTest(kind=kind):
                with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
                    old=LocalServer(base/'replace.sock',engine);foreign=None
                    try:
                        if kind=='parent':
                            moved=base.with_name(base.name+'-moved');base.rename(moved);base.mkdir(mode=0o700)
                            try:self.blocked(old.close)
                            finally:base.rmdir();moved.rename(base)
                        else:
                            old.path.rename(base/'original')  # original inode pinned by listener
                            if kind=='file':old.path.write_bytes(b'foreign')
                            elif kind=='symlink':old.path.symlink_to(base/'original')
                            else:
                                foreign=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);foreign.bind(str(old.path))
                            before=old.path.lstat();self.blocked(old.close)
                            self.assertEqual((old.path.lstat().st_dev,old.path.lstat().st_ino),(before.st_dev,before.st_ino))
                    finally:
                        if foreign:foreign.close()
                        if not old.closed:self.crash(old)

    def case_ownership(self):
        for change in ('mode','uid','missing','policy','owner','parent_mode','ledger_mode','lock_mode'):
            with self.subTest(change=change):
                with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
                    old=LocalServer(base/'proof.sock',engine);self.crash(old)
                    ledger=base/'proof.sock.owner.json';record=json.loads(ledger.read_text())
                    if change=='mode':old.path.chmod(0o666)
                    elif change=='missing':ledger.unlink()
                    elif change=='parent_mode':base.chmod(0o755)
                    elif change=='ledger_mode':ledger.chmod(0o666)
                    elif change=='lock_mode':(base/'proof.sock.lock').chmod(0o666)
                    else:
                        if change=='uid':record['socket']['uid']+=1
                        elif change=='policy':record['policy']='f'*64
                        elif change=='owner':record['owner']='f'*32
                        ledger.write_text(json.dumps(record))
                    before=old.path.lstat().st_ino
                    try:
                        with self.assertRaises(p.BoundaryError):LocalServer(old.path,engine)
                        self.assertEqual(old.path.lstat().st_ino,before)
                    finally:base.chmod(0o700)

    def case_concurrency(self):
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            old=LocalServer(base/'lock.sock',engine)
            self.blocked(lambda:LocalServer(old.path,engine),'SOCKET_BUSY')
            self.assertTrue(old.path.exists());old.close()

    def case_unlink_failure(self):
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            old=LocalServer(base/'dirty.sock',engine)
            unlink=os.unlink
            def fail(name,*a,**kw):
                if name=='dirty.sock.retired':raise PermissionError('private fault')
                return unlink(name,*a,**kw)
            with patch.object(state.os,'unlink',fail):self.blocked(old.close)
            self.assertIsNone(old.socket_state.fd);self.assertIsNone(old.socket_state.lock_fd)
            self.assertTrue((base/'dirty.sock.retired').exists())
            self.assertEqual(json.loads((base/'dirty.sock.owner.json').read_text())['phase'],'READY')
            self.blocked(lambda:LocalServer(old.path,engine))
            self.blocked(old.close)  # idempotent blocked outcome, no second deletion

    def case_race(self):
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            old=LocalServer(base/'race.sock',engine);rename=state._rename
            switched=[False]
            def race(fd,source,target):
                if source=='race.sock' and not switched[0]:
                    switched[0]=True
                    os.rename(source,'kept-original',src_dir_fd=fd,dst_dir_fd=fd)
                    (base/source).write_bytes(b'foreign replacement')
                return rename(fd,source,target)
            with patch.object(state,'_rename',race):self.blocked(old.close)
            self.assertEqual(old.path.read_bytes(),b'foreign replacement')
            self.assertTrue((base/'kept-original').exists())

    def case_descriptor_failure(self):
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            old=LocalServer(base/'fd.sock',engine);lock=old.socket_state.lock_fd;parent=old.socket_state.fd
            close=os.close;seen=[]
            def failure(fd):
                seen.append(fd);close(fd)
                if fd==lock:raise OSError('private fault')
            with patch.object(state.os,'close',failure):self.blocked(old.close)
            self.assertIn(lock,seen);self.assertIn(parent,seen)
            for fd in (lock,parent):
                with self.assertRaises(OSError) as error:os.fstat(fd)
                self.assertEqual(error.exception.errno,errno.EBADF)

    def case_policy(self):
        # Old ledger mismatch must remain byte-for-byte unchanged.
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            old=LocalServer(base/'policy.sock',engine);self.crash(old)
            ledger=base/'policy.sock.owner.json';before=ledger.read_bytes()
            with patch.object(j,'policy','f'*64):self.blocked(lambda:LocalServer(old.path,engine))
            self.assertEqual(before,ledger.read_bytes());self.assertTrue(old.path.exists())

    def case_journal_failure(self):
        with PrivilegeCases().fixture() as (base,e,r,j,b,engine):
            replace=os.replace
            def fail(source,target,*a,**kw):
                if source=='write.sock.pending':raise OSError('private persistence fault')
                return replace(source,target,*a,**kw)
            with patch.object(state.os,'replace',fail):
                self.blocked(lambda:LocalServer(base/'write.sock',engine))
            self.assertTrue((base/'write.sock.pending').exists())
            before=(base/'write.sock.pending').read_bytes()
            self.blocked(lambda:LocalServer(base/'write.sock',engine))
            self.assertEqual((base/'write.sock.pending').read_bytes(),before)
            # Recovery attempt acquired/released the lifetime lock; a pending
            # record, not a leaked lock FD, is what continues to fence startup.
            guard=state.SocketState(base/'write.sock',{'owner':b.owner,'enrollment':e.enrollment_id},j.policy)
            try:self.blocked(guard.recover)
            finally:guard.close()
