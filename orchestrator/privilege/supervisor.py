"""Non-installed supervisor state machine and private Unix test transport."""
from collections import deque
import os
from pathlib import Path
import secrets
import socket
import threading
import time
from . import protocol as p
from .policy import execution_class, policy_hash, resource_limits
from .security import directory_fd, peer_credentials


class Supervisor:
    def __init__(self, enrollment, roots, backend, journal, *, linux_validation=False):
        # No dispatch to arbitrary pluggable privileged code or production fallback.
        from .backend import FakeBackend, SyntheticProcessBackend
        from .isolation import LinuxBackend
        self.linux=type(backend) is LinuxBackend and linux_validation is True
        if not self.linux and (type(backend) not in (FakeBackend,SyntheticProcessBackend) or not backend.simulation_only):
            raise p.BoundaryError('POLICY_REJECTED')
        self.enrollment=enrollment;self.roots=roots;self.backend=backend;self.journal=journal
        if journal.policy!=policy_hash():raise p.BoundaryError('POLICY_REJECTED')
        self.lock=threading.RLock();self.records={r['handle']:r for r in journal.load()}
        self.log=deque(maxlen=256)
        self.recovery_required=any(r['state']!='RELEASED' for r in self.records.values())

    def _save(self):self.journal.save(list(self.records.values()))

    def _owned(self, handle, connection, peer):
        r=self.records.get(handle)
        if r is None or r['connection']!=connection or (r['uid'],r['gid'])!=peer[1:]:
            raise p.BoundaryError('UNKNOWN_HANDLE')
        return r

    def _snapshot(self, r):
        return {'handle':r['handle'],'state':r['state'],'class':r['class'],'role':r['role'],
                'mode':'LINUX' if self.linux else 'SIMULATED','enforcement':'UNPROVEN',
                'cleanup':('CONFIRMED' if self.linux else 'SIMULATED') if r['state']=='RELEASED' and self.backend.cleanup_proof(r['handle'],r['owner']) in ('NEVER_ALLOCATED','OWNED_CLEANED') else 'UNPROVEN'}

    def _release(self,r):
        try:
            if r['state']=='RELEASED' and self.backend.cleanup_proof(r['handle'],r['owner']) in ('NEVER_ALLOCATED','OWNED_CLEANED'):return
            if self.backend.owns(r['handle'],r['owner']):self.backend.cleanup(r['handle'])
            if self.backend.cleanup_proof(r['handle'],r['owner']) not in ('NEVER_ALLOCATED','OWNED_CLEANED'):
                raise p.BoundaryError('CLEANUP_INCOMPLETE')
            r['state']='RELEASED';self._save()
        except Exception:
            r['state']='FAILED_DIRTY';self.recovery_required=True
            try:self._save()
            except Exception:self.recovery_required=True
            raise p.BoundaryError('CLEANUP_INCOMPLETE') from None

    def dispatch(self, request, connection, peer):
        request=p.validate_request(request)
        with self.lock:
            op=request['op'];args=request['args'];handle=args.get('handle')
            try:
                if op=='HELLO':raise p.BoundaryError('INVALID_STATE')
                if self.recovery_required and op in ('CREATE','START','PROBE'):
                    raise p.BoundaryError('RECOVERY_REQUIRED')
                if op=='CREATE':
                    c=execution_class(args['class'],args['role'])
                    limits=resource_limits(args['class'],args['role'],args['limits'])
                    active=[r for r in self.records.values() if r['state']!='RELEASED']
                    if (len(self.records)>=p.MAX_ENTRIES or len(active)>=p.MAX_ACTIVE
                            or sum(r['uid']==peer[1] for r in active)>=p.MAX_PER_UID):raise p.BoundaryError('BOUNDS_EXCEEDED')
                    if any(r['run_id']==args['run_id'] for r in self.records.values()):raise p.BoundaryError('INVALID_STATE')
                    fd=self.roots.check(args['slot']);os.close(fd)
                    handle=secrets.token_hex(16)
                    if handle in self.records:raise p.BoundaryError('BOUNDS_EXCEEDED')
                    r={'handle':handle,'run_id':args['run_id'],'connection':connection,'uid':peer[1],'gid':peer[2],
                       'owner':self.backend.owner,'state':'CREATING','class':args['class'],'role':args['role'],'policy':self.journal.policy}
                    self.records[handle]=r
                    self._save()  # Durable ownership intent before backend creation.
                    try:
                        if self.linux:self.backend.create(handle,args['run_id'],args['slot'],args['class'],args['role'],limits)
                        else:self.backend.prepare(handle,c.recipe,limits)
                        r['state']='CREATED';self._save()
                    except Exception:
                        r['state']='FAILED_DIRTY';self._save()
                        raise p.BoundaryError('BACKEND_FAILURE') from None
                    result=self._snapshot(r)
                elif op=='PROBE':result=self.backend.probe()
                else:
                    r=self._owned(handle,connection,peer)
                    if op=='START':
                        if r['state']!='CREATED':raise p.BoundaryError('INVALID_STATE')
                        try:self.backend.start(handle)
                        except Exception:
                            r['state']='FAILED_DIRTY';self.recovery_required=True
                            try:self.backend.terminate(handle)
                            except Exception:pass  # keep unresolved backend ownership
                            try:self._save()
                            except Exception:pass
                            raise p.BoundaryError('BACKEND_FAILURE') from None
                        r['state']='RUNNING'
                        try:self._save()
                        except Exception:
                            r['state']='FAILED_DIRTY';self.recovery_required=True
                            try:self.backend.terminate(handle)
                            except Exception:pass  # backend retains unresolved ownership
                            try:self._save()
                            except Exception:pass
                            raise p.BoundaryError('BACKEND_FAILURE') from None
                    elif op=='STATUS':
                        if self.linux:r['state']=self.backend.status(handle)['state'];self._save()
                        if r['state']=='RUNNING' and not self.backend.running(handle):
                            r['state']='TERMINATED';self._save()
                    elif op=='TERMINATE':
                        if r['state'] not in ('CREATED','RUNNING','TERMINATED'):raise p.BoundaryError('INVALID_STATE')
                        if r['state']!='TERMINATED':
                            r['state']='TERMINATING';self._save()
                            try:self.backend.terminate(handle)
                            except Exception:
                                r['state']='FAILED_DIRTY';self._save();raise p.BoundaryError('CLEANUP_INCOMPLETE') from None
                            r['state']='TERMINATED';self._save()
                    elif op=='RELEASE':self._release(r)
                    result=self._snapshot(r)
                self.log.append((op,handle,'OK'))
                return result
            except p.BoundaryError as error:
                self.log.append((op,handle,error.code));raise
            except Exception:
                self.recovery_required=True
                self.log.append((op,handle,'BACKEND_FAILURE'))
                raise p.BoundaryError('BACKEND_FAILURE') from None

    def disconnect(self, connection):
        with self.lock:
            for r in self.records.values():
                if r['connection']==connection and r['state']!='RELEASED':
                    try:self._release(r)
                    except p.BoundaryError:self.recovery_required=True

    def recover(self):
        """Administrative startup simulation; never offered as a public RPC."""
        with self.lock:
            pending=[r for r in self.records.values() if r['state']!='RELEASED']
            if self.linux:
                self.backend.reconcile_control(pending)
                self.backend.recover()
            # Validate every ownership claim before doing any cleanup.
            if any(r['owner']!=self.backend.owner or
                   (not self.backend.owns(r['handle'],r['owner']) and self.backend.cleanup_proof(r['handle'],r['owner']) not in ('NEVER_ALLOCATED','OWNED_CLEANED')) for r in pending):
                self.recovery_required=True;raise p.BoundaryError('JOURNAL_INVALID')
            for r in pending:self._release(r)
            self.recovery_required=False


class LocalServer:
    """Explicit temporary socket fixture; no executable daemon entrypoint/install.

    Real peer credentials and token checks, synthetic enforcement only.
    No ancillary FD acceptance: FD provisioning waits for Stage 3.1C review.
    """
    def __init__(self, path, supervisor, *, enrolled_group=None, clock=time.monotonic):
        self.path=Path(path);self.supervisor=supervisor
        self.clock=clock  # trusted monotonic clock; test injection, never RPC input
        if enrolled_group is not None and (not supervisor.linux or os.geteuid()!=0 or enrolled_group!=supervisor.enrollment.gid):raise p.BoundaryError('POLICY_REJECTED')
        self.parent=directory_fd(self.path.parent,os.getuid(),0o750 if enrolled_group is not None else 0o700)
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.channels=set();self.threads=[];self.lock=threading.Lock();self.stop_event=threading.Event()
        self.semaphore=threading.BoundedSemaphore(p.MAX_CLIENTS)
        try:
            # Never unlink an existing path to force socket creation.
            self.listener.bind(str(self.path));os.chmod(self.path,0o660 if enrolled_group is not None else 0o600)
            if enrolled_group is not None:os.chown(self.path,0,enrolled_group)
            self.inode=self.path.lstat().st_ino
            self.listener.listen(p.MAX_CLIENTS);self.listener.settimeout(.1)
        except BaseException:
            self.listener.close();os.close(self.parent);raise
        self.thread=threading.Thread(target=self._accept,daemon=True)

    def start(self):self.thread.start();return self

    def _accept(self):
        while not self.stop_event.is_set():
            try:channel,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            if not self.semaphore.acquire(blocking=False):channel.close();continue
            with self.lock:
                self.channels.add(channel)
                # Remove completed threads so total session count never grows storage.
                self.threads=[t for t in self.threads if t.is_alive()]
                thread=threading.Thread(target=self._serve,args=(channel,),daemon=True)
                self.threads.append(thread);thread.start()

    def _serve(self, channel):
        connection=secrets.token_hex(16);seq=0;authenticated=False
        try:
            peer=peer_credentials(channel)
            if peer[1:]!=(self.supervisor.enrollment.uid,self.supervisor.enrollment.gid):raise p.BoundaryError('PEER_NOT_ALLOWED')
            challenge=secrets.token_hex(16)
            p.send(channel,p.response(0,'OK',{'challenge':challenge}))
            request=p.validate_request(p.receive(channel));seq=request['seq']
            if seq!=1 or request['op']!='HELLO':raise p.BoundaryError('INVALID_STATE')
            a=request['args'];e=self.supervisor.enrollment
            if a['enrollment']!=e.enrollment_id or a['challenge']!=challenge:raise p.BoundaryError('AUTH_FAILED')
            e.authenticate(peer,a['token'])
            if a['build']!=p.BUILD or a['policy']!=self.supervisor.journal.policy:raise p.BoundaryError('POLICY_REJECTED')
            authenticated=True
            idle_deadline=self.clock()+p.AUTHENTICATED_LIFETIME
            recent=deque(maxlen=p.MAX_RATE)
            p.send(channel,p.response(seq,'OK',{'build':p.BUILD,'policy':self.supervisor.journal.policy,'mode':'LINUX' if self.supervisor.linux else 'SIMULATED'}))
            while seq<p.MAX_REQUESTS:
                request=p.validate_request(p.receive(channel,idle_deadline=idle_deadline,
                                                     clock=self.clock,stop=self.stop_event))
                if request['seq']!=seq+1:raise p.BoundaryError('INVALID_REQUEST')
                seq=request['seq']
                now=self.clock()
                while recent and now-recent[0]>=1:recent.popleft()
                if len(recent)>=p.MAX_RATE:raise p.BoundaryError('BOUNDS_EXCEEDED')
                recent.append(now)
                try:data=self.supervisor.dispatch(request,connection,peer);code='OK'
                except p.BoundaryError as error:data={};code=error.code
                p.send(channel,p.response(seq,code,data))
        except p.BoundaryError as error:
            try:p.send(channel,p.response(seq,error.code))
            except p.BoundaryError:pass
        except Exception:
            try:p.send(channel,p.response(seq,'BACKEND_FAILURE'))
            except p.BoundaryError:pass
        finally:
            if authenticated:self.supervisor.disconnect(connection)
            channel.close()
            with self.lock:self.channels.discard(channel)
            self.semaphore.release()

    def close(self):
        self.stop_event.set();self.listener.close()
        with self.lock:
            for channel in self.channels:
                try:channel.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            threads=list(self.threads)
        if self.thread.ident:self.thread.join(timeout=2)
        for thread in threads:thread.join(timeout=2)
        # Only unlink the socket inode this fixture created.
        try:
            info=os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False)
            if info.st_ino==self.inode:os.unlink(self.path.name,dir_fd=self.parent)
        except FileNotFoundError:pass
        os.close(self.parent)
