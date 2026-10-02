"""Non-installed boundary tests. Kernel resources are fake; sockets are temporary."""
import contextlib
import inspect
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from orchestrator.privilege import protocol as p
from orchestrator.privilege.policy import CLASSES, policy_hash, resource_limits, worker_environment
from orchestrator.privilege.security import Enrollment, RegisteredRoots, create_token, load_token, peer_credentials, validate_socket
from orchestrator.privilege.backend import FakeBackend, SyntheticProcessBackend, ProcessHandle
from orchestrator.privilege.journal import Journal
from orchestrator.privilege.supervisor import Supervisor, LocalServer
from orchestrator.privilege.client import ControllerClient, Sandbox


class PrivilegeCases(unittest.TestCase):
    def cases(self):
        # Compact contract table retains existing trusted-suite capture limits.
        for name in ('protocol','framing','auth','storage','paths','policy','lifecycle','bounds',
                     'failures','recovery','journal','transport','processes','static'):
            with self.subTest(case=name):getattr(self,name)()

    def error(self,code,call):
        with self.assertRaises(p.BoundaryError) as caught:call()
        self.assertEqual(caught.exception.code,code)
        self.assertNotIn('synthetic private exception',str(caught.exception))

    def request(self,op,args,seq=2):
        return p.validate_request({'version':1,'seq':seq,'op':op,'args':args})

    def protocol(self):
        hello={'enrollment':'1'*32,'token':'2'*64,'challenge':'3'*32,'build':p.BUILD,'policy':policy_hash()}
        good=self.request('HELLO',hello,1)
        self.assertEqual(p.decode(p.encode(good)),good)
        for code,value in [('PROTOCOL_MISMATCH',dict(good,version=2)),('PROTOCOL_MISMATCH',dict(good,version=True)),
                           ('INVALID_REQUEST',dict(good,op='ROOT_EXEC')),('INVALID_REQUEST',dict(good,pid=5)),
                           ('INVALID_REQUEST',dict(good,args=dict(hello,command=['sh'])))]:
            self.error(code,lambda value=value:p.validate_request(value))
        for raw in (b'{',b'{"a":1,"a":2}',b'NaN',b'[]garbage',b'{"v":-1}',b'{"v":1e99}'):
            self.error('INVALID_REQUEST',lambda raw=raw:p.decode(raw))
        self.error('BOUNDS_EXCEEDED',lambda:p.decode(b' '* (p.MAX_FRAME+1)))
        self.error('BOUNDS_EXCEEDED',lambda:p.encode({'a':'x'*257}))
        self.error('BOUNDS_EXCEEDED',lambda:p.encode({'a':{'b':{'c':{'d':{'e':1}}}}}))
        for args in ({'handle':'../x'},{'handle':'a'*32,'pid':42},{'handle':'a'*32,'mount':['/','/tmp']}, {'handle':'a'*32,'argv':['sh']}):
            self.error('INVALID_REQUEST',lambda args=args:self.request('START',args))
        for slot in ('../root','/root','./work','a//b','a\\b'):
            self.error('PATH_REJECTED',lambda slot=slot:self.request('CREATE',{'run_id':'a'*32,'slot':slot,'class':'MODEL_WORKER','role':'coder','limits':{}}))
        self.error('INVALID_REQUEST',lambda:self.request('CREATE',{'run_id':'model chose this','slot':'work','class':'MODEL_WORKER','role':'coder','limits':{}}))
        self.assertNotIn('run_id',inspect.signature(ControllerClient.create_sandbox).parameters)
        self.assertFalse(hasattr(ControllerClient,'send_raw_rpc'))

    def framing(self):
        a,b=socket.socketpair()
        try:
            p.send(a,{'value':'safe'});self.assertEqual(p.receive(b),{'value':'safe'})
            a.sendall(struct.pack('!I',p.MAX_FRAME+1));self.error('BOUNDS_EXCEEDED',lambda:p.receive(b))
            a.sendall(struct.pack('!I',2)+b'{]');self.error('INVALID_REQUEST',lambda:p.receive(b))
        finally:a.close();b.close()
        a,b=socket.socketpair()
        a.sendall(struct.pack('!I',10)+b'xx');a.close()
        try:self.error('TRANSPORT_FAILURE',lambda:p.receive(b))
        finally:b.close()
        a,b=socket.socketpair()
        try:
            with patch.object(p,'TIMEOUT',.01):self.error('TRANSPORT_FAILURE',lambda:p.receive(b))
        finally:a.close();b.close()

    @contextlib.contextmanager
    def fixture(self,backend=None):
        with tempfile.TemporaryDirectory(prefix='freeagentos-privilege-test-') as tmp:
            base=Path(tmp);work=base/'work';work.mkdir(mode=0o700)
            state=base/'state';state.mkdir(mode=0o700)
            e=Enrollment(secrets.token_hex(16),os.getuid(),os.getgid(),secrets.token_hex(32))
            roots=RegisteredRoots();roots.register('work',work,os.getuid())
            journal=Journal(state,policy_hash());backend=backend or FakeBackend()
            engine=Supervisor(e,roots,backend,journal)
            self.connection='a'*32;self.peer=(os.getpid(),os.getuid(),os.getgid())
            try:yield base,e,roots,journal,backend,engine
            finally:
                engine.disconnect(self.connection)
                roots.close();journal.close()

    def create(self,engine,limits=None,execution='MODEL_WORKER',role='coder'):
        return engine.dispatch(self.request('CREATE',{'run_id':secrets.token_hex(16),'slot':'work','class':execution,'role':role,'limits':limits or {}}),self.connection,self.peer)['handle']

    def operation(self,engine,op,handle,connection=None):
        return engine.dispatch(self.request(op,{'handle':handle}),connection or self.connection,self.peer)

    def auth(self):
        e=Enrollment('a'*32,1000,1000,'b'*64)
        e.authenticate((1,1000,1000),'b'*64)
        self.error('PEER_NOT_ALLOWED',lambda:e.authenticate((1,1001,1000),'b'*64))
        self.error('PEER_NOT_ALLOWED',lambda:e.authenticate((1,1000,1001),'b'*64))
        self.error('AUTH_FAILED',lambda:e.authenticate((1,1000,1000),'c'*64))
        self.assertNotIn('b'*64,repr(e))
        a,b=socket.socketpair()
        try:self.assertEqual(peer_credentials(a)[1:],(os.getuid(),os.getgid()))
        finally:a.close();b.close()

    def storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            tokenfile=Path(tmp)/'token';token=create_token(tokenfile)
            self.assertEqual(len(token),64);self.assertEqual(load_token(tokenfile),token)
            self.assertEqual(tokenfile.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):create_token(tokenfile)
            tokenfile.chmod(0o644);self.error('PATH_REJECTED',lambda:load_token(tokenfile))
            tokenfile.chmod(0o600);alias=Path(tmp)/'alias';alias.symlink_to(tokenfile)
            with self.assertRaises(OSError):load_token(alias)

    def paths(self):
        with self.fixture() as (base,e,roots,journal,backend,engine):
            (base/'work/file').write_text('safe')
            fd=roots.open_file('work','file')
            try:self.assertEqual(os.read(fd,4),b'safe');self.assertFalse(os.get_inheritable(fd))
            finally:os.close(fd)
            for relative in ('../file','/etc/passwd','./file','a//file','a\\file'):
                self.error('PATH_REJECTED',lambda relative=relative:roots.open_file('work',relative))
            (base/'work/alias').symlink_to(base/'work/file')
            self.error('PATH_REJECTED',lambda:roots.open_file('work','alias'))
            os.link(base/'work/file',base/'work/hard')
            self.error('PATH_REJECTED',lambda:roots.open_file('work','hard'))
            (base/'work/dir').mkdir();(base/'work/dirlink').symlink_to(base/'work/dir')
            self.error('PATH_REJECTED',lambda:roots.open_file('work','dirlink/file'))
            (base/'work').rename(base/'old');(base/'work').mkdir(mode=0o700)
            self.error('PATH_REJECTED',lambda:roots.check('work'))
            self.assertFalse(backend.resources)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'unsafe';root.mkdir(mode=0o777);root.chmod(0o777)
            roots=RegisteredRoots()
            try:self.error('PATH_REJECTED',lambda:roots.register('work',root,os.getuid()))
            finally:roots.close()

    def policy(self):
        self.assertEqual(policy_hash(),policy_hash());self.assertEqual(len(policy_hash()),64)
        for name,c in CLASSES.items():
            self.assertEqual(resource_limits(name,c.roles[0],dict(c.limits)),dict(c.limits))
            for values in ({'memory_limit_bytes':-1},{'max_processes':0},{'max_processes':True},
                           {'memory_limit_bytes':2**80},{'cpu_quota_us':c.limits['cpu_quota_us']+1},{'unlimited':1}):
                self.error('RESOURCE_LIMIT_INVALID',lambda values=values:resource_limits(name,c.roles[0],values))
        self.error('EXECUTION_CLASS_REJECTED',lambda:resource_limits('SHELL','coder',{}))
        self.error('EXECUTION_CLASS_REJECTED',lambda:resource_limits('MODEL_WORKER','tester',{}))
        environment=worker_environment({k:'PRIVATE' for k in ('LD_PRELOAD','LD_LIBRARY_PATH','PYTHONPATH','PYTHONINSPECT','BASH_ENV','ENV','SHELLOPTS','PATH','PROVIDER_KEY')})
        self.assertEqual(environment['PATH'],'/usr/bin:/bin');self.assertNotIn('PRIVATE',str(environment))
        self.assertEqual(CLASSES['MODEL_WORKER'].limits['wall_timeout_seconds'],240)

    def lifecycle(self):
        with self.fixture() as (_,e,roots,journal,backend,engine):
            self.error('UNKNOWN_HANDLE',lambda:self.operation(engine,'START','b'*32))
            h=self.create(engine);self.assertEqual(self.operation(engine,'STATUS',h)['state'],'CREATED')
            self.assertEqual(self.operation(engine,'START',h)['state'],'RUNNING')
            self.error('INVALID_STATE',lambda:self.operation(engine,'START',h))
            self.error('UNKNOWN_HANDLE',lambda:self.operation(engine,'TERMINATE',h,'c'*32))
            self.assertEqual(self.operation(engine,'TERMINATE',h)['state'],'TERMINATED')
            self.assertEqual(self.operation(engine,'RELEASE',h)['state'],'RELEASED')
            self.assertEqual(self.operation(engine,'RELEASE',h)['state'],'RELEASED')
            self.error('INVALID_STATE',lambda:self.operation(engine,'START',h))
            events=[s for s,_ in backend.events]
            self.assertEqual(events[:6],['namespace','rootfs','mount_recipe','cgroup_create','cgroup_limits','identity_prepare'])
            self.assertLess(events.index('cgroup_attach_owned_child'),events.index('start'))
            self.assertFalse(backend.resources)
            self.assertEqual(engine.dispatch(self.request('PROBE',{'probe':'BOUNDARY_V1'}),self.connection,self.peer)['enforcement'],'UNPROVEN')
            self.assertEqual(journal.load()[0]['state'],'RELEASED')

    def bounds(self):
        with self.fixture() as (_,e,roots,journal,backend,engine):
            self.create(engine);self.create(engine)
            self.error('BOUNDS_EXCEEDED',lambda:self.create(engine))
            self.assertEqual(len(backend.resources),2)
            with patch.object(p,'MAX_ENTRIES',2):self.error('BOUNDS_EXCEEDED',lambda:self.create(engine))
        with patch.object(p,'MAX_ACTIVE',1):
            with self.fixture() as (_,e,roots,journal,backend,engine):
                self.create(engine);self.error('BOUNDS_EXCEEDED',lambda:self.create(engine))
        self.assertLessEqual(FakeBackend().events.maxlen,256)
        backend=FakeBackend();backend.completed={'a'+format(n,'031x') for n in range(p.MAX_ENTRIES)}
        self.error('BOUNDS_EXCEEDED',lambda:backend.prepare('b'*32,'MODEL',{}))
        self.error('INVALID_REQUEST',lambda:backend.prepare('c'*32,'/arbitrary/mount',{}))

    def failures(self):
        with self.fixture() as (_,e,roots,journal,backend,engine):
            backend.fail_at='mount_recipe'
            self.error('BACKEND_FAILURE',lambda:self.create(engine))
            r=next(iter(engine.records.values()));h=r['handle']
            self.assertEqual(r['state'],'FAILED_DIRTY')
            self.error('INVALID_STATE',lambda:self.operation(engine,'START',h))
            backend.fail_at=None;self.operation(engine,'RELEASE',h)
            h=self.create(engine);self.operation(engine,'START',h)
            backend.fail_at='cgroup_remove'
            self.error('CLEANUP_INCOMPLETE',lambda:self.operation(engine,'RELEASE',h))
            self.assertEqual(engine.records[h]['state'],'FAILED_DIRTY')
            self.assertTrue(backend.owns(h,backend.owner))
            backend.fail_at=None;self.operation(engine,'RELEASE',h)
            self.assertFalse(backend.resources)
            self.assertNotIn('synthetic private exception',str(engine.log))
        with self.fixture() as (_,e,roots,journal,backend,engine):
            with patch.object(journal,'save',side_effect=OSError('PRIVATE SECRET')):
                self.error('BACKEND_FAILURE',lambda:self.create(engine))
            self.assertFalse(backend.resources);self.assertTrue(engine.recovery_required)
            self.error('RECOVERY_REQUIRED',lambda:self.create(engine))
            engine.recover();self.assertFalse(engine.recovery_required)
        with self.fixture() as (_,e,roots,journal,backend,engine):
            h=self.create(engine)
            with patch.object(journal,'save',side_effect=OSError('private')):
                self.error('CLEANUP_INCOMPLETE',lambda:self.operation(engine,'RELEASE',h))
            self.assertFalse(backend.resources);self.assertTrue(backend.cleaned(h,backend.owner))
            engine.recover();self.assertEqual(engine.records[h]['state'],'RELEASED')

    def recovery(self):
        with self.fixture() as (_,e,roots,journal,backend,engine):
            h=self.create(engine);self.operation(engine,'START',h)
            engine.disconnect(self.connection)
            self.assertEqual(engine.records[h]['state'],'RELEASED');self.assertFalse(backend.resources)
            h=self.create(engine);self.operation(engine,'START',h)
            restarted=Supervisor(e,roots,backend,journal)
            self.assertTrue(restarted.recovery_required)
            self.error('RECOVERY_REQUIRED',lambda:self.create(restarted))
            restarted.recover();self.assertEqual(restarted.records[h]['state'],'RELEASED')
            self.assertFalse(backend.resources)
        with self.fixture() as (_,e,roots,journal,backend,engine):
            h=self.create(engine)
            records=journal.load();records[0]['owner']='f'*32;journal.save(records)
            restarted=Supervisor(e,roots,backend,journal)
            before=list(backend.events)
            self.error('JOURNAL_INVALID',restarted.recover)
            self.assertEqual(before,list(backend.events));self.assertTrue(backend.resources)
        with self.fixture() as (_,e,roots,journal,backend,engine):
            h=self.create(engine);backend.fail_at='cgroup_kill'
            engine.disconnect(self.connection)
            self.assertTrue(engine.recovery_required)
            self.assertEqual(engine.records[h]['state'],'FAILED_DIRTY')
            backend.fail_at=None;engine.recover();self.assertFalse(engine.recovery_required)

    def journal(self):
        with self.fixture() as (base,e,roots,journal,backend,engine):
            self.create(engine)
            self.assertEqual((base/'state/state.json').stat().st_mode&0o777,0o600)
            self.assertFalse(list((base/'state').glob('pending-*')))
            raw=(base/'state/state.json').read_text()
            self.assertNotIn(e.token,raw);self.assertNotIn('work',raw)
            records=journal.load()
            with patch('orchestrator.privilege.journal.os.replace',side_effect=OSError('private')):
                with self.assertRaises(OSError):journal.save(records)
            self.assertEqual((base/'state/state.json').read_text(),raw)
            self.assertFalse(list((base/'state').glob('pending-*')))
            (base/'state/state.json').write_text('{"version":1,"version":1}')
            self.error('JOURNAL_INVALID',journal.load)
            # Keep fixture cleanup able to save its valid in-memory record.
            journal.save(records)
            (base/'state/state.json').chmod(0o644)
            self.error('JOURNAL_INVALID',journal.load)
            (base/'state/state.json').chmod(0o600)

    def transport(self):
        with self.fixture() as (base,e,roots,journal,backend,engine):
            server=LocalServer(base/'gateway.sock',engine).start()
            client=None;other=None
            try:
                validate_socket(base/'gateway.sock',os.getuid(),os.getgid())
                wrong=Enrollment(e.enrollment_id,e.uid,e.gid,'e'*64)
                self.error('AUTH_FAILED',lambda:ControllerClient(base/'gateway.sock',wrong,os.getuid(),os.getgid()))
                client=ControllerClient(base/'gateway.sock',e,os.getuid(),os.getgid())
                self.assertEqual(client.probe()['mode'],'SIMULATED')
                h=client.create_sandbox('work','MODEL_WORKER','coder')
                client.start_sandbox(h)
                other=ControllerClient(base/'gateway.sock',e,os.getuid(),os.getgid())
                self.error('UNKNOWN_HANDLE',lambda:other.status(h))
                # Adversarial internal transport fixture, not a public client API.
                self.error('UNKNOWN_HANDLE',lambda:other._rpc('STATUS',{'handle':h.handle}))
                self.error('INVALID_STATE',lambda:client._rpc('HELLO',{'enrollment':e.enrollment_id,'token':e.token,'challenge':'d'*32,'build':p.BUILD,'policy':policy_hash()}))
                client.terminate(h);client.release(h)
                self.assertEqual(client.status(h)['state'],'RELEASED')
                dropped=client.create_sandbox('work','MODEL_WORKER','fixer');client.start_sandbox(dropped)
                client.close();client=None
                deadline=time.monotonic()+2
                while engine.records[dropped.handle]['state']!='RELEASED' and time.monotonic()<deadline:time.sleep(.01)
                self.assertEqual(engine.records[dropped.handle]['state'],'RELEASED')
                self.assertNotIn(e.token,json.dumps(list(engine.log)))
                self.assertNotIn('model prompt',json.dumps(list(engine.log)))
            finally:
                if client:client.close()
                if other:other.close()
                server.close()
            self.assertFalse((base/'gateway.sock').exists())
        with patch.object(p,'MAX_CLIENTS',1), patch.object(p,'MAX_REQUESTS',3):
            with self.fixture() as (base,e,roots,journal,backend,engine):
                server=LocalServer(base/'bounded.sock',engine).start()
                client=None
                try:
                    client=ControllerClient(base/'bounded.sock',e,os.getuid(),os.getgid())
                    self.error('TRANSPORT_FAILURE',lambda:ControllerClient(base/'bounded.sock',e,os.getuid(),os.getgid()))
                    client.probe();client.probe()
                    self.error('INVALID_REQUEST',client.probe)
                finally:
                    if client:client.close()
                    server.close()
        with self.fixture() as (base,e,roots,journal,backend,engine):
            server=LocalServer(base/'replay.sock',engine).start()
            wire=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                wire.connect(str(base/'replay.sock'));greeting=p.receive(wire)
                hello=self.request('HELLO',{'enrollment':e.enrollment_id,'token':e.token,'challenge':greeting['data']['challenge'],'build':p.BUILD,'policy':policy_hash()},1)
                p.send(wire,hello);self.assertEqual(p.receive(wire)['code'],'OK')
                p.send(wire,hello);self.assertEqual(p.receive(wire)['code'],'INVALID_REQUEST')
                self.assertFalse(backend.resources)
            finally:wire.close();server.close()
        with patch.object(p,'MAX_RATE',1):
            with self.fixture() as (base,e,roots,journal,backend,engine):
                server=LocalServer(base/'rate.sock',engine).start()
                client=None
                try:
                    client=ControllerClient(base/'rate.sock',e,os.getuid(),os.getgid())
                    client.probe();self.error('BOUNDS_EXCEEDED',client.probe)
                finally:
                    if client:client.close()
                    server.close()
        with self.fixture() as (base,e,roots,journal,backend,engine):
            server=LocalServer(base/'private.sock',engine).start()
            wire=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                wire.connect(str(base/'private.sock'));greeting=p.receive(wire)
                p.send(wire,self.request('HELLO',{'enrollment':e.enrollment_id,'token':e.token,'challenge':greeting['data']['challenge'],'build':p.BUILD,'policy':policy_hash()},1))
                self.assertEqual(p.receive(wire)['code'],'OK')
                p.send(wire,{'version':1,'seq':2,'op':'START','args':{'handle':'e'*32,'prompt':'PRIVATE_MODEL_PROMPT','env':{'PROVIDER_KEY':'PRIVATE_CREDENTIAL'}}})
                answer=p.receive(wire);self.assertEqual(answer['code'],'INVALID_REQUEST')
                for forbidden in (e.token,'PRIVATE_MODEL_PROMPT','PRIVATE_CREDENTIAL'):
                    self.assertNotIn(forbidden,json.dumps(answer));self.assertNotIn(forbidden,str(engine.log))
            finally:wire.close();server.close()
        with self.fixture() as (base,e,roots,journal,backend,engine):
            engine.enrollment=Enrollment(e.enrollment_id,e.uid+1,e.gid,e.token)
            server=LocalServer(base/'peer.sock',engine).start()
            try:self.error('PEER_NOT_ALLOWED',lambda:ControllerClient(base/'peer.sock',e,os.getuid(),os.getgid()))
            finally:server.close()

    def processes(self):
        args=['space value','"quoted"','semicolon; echo nope','$(echo nope)','`echo nope`','newline\nvalue']
        backend=SyntheticProcessBackend(args)
        with self.fixture(backend) as (_,e,roots,journal,backend,engine):
            h=self.create(engine);self.operation(engine,'START',h)
            process=backend.resources[h]['process']
            self.assertEqual(json.loads(process.process.stdout.readline()),args)
            self.error('UNKNOWN_HANDLE',lambda:process.terminate('f'*32))
            if hasattr(os,'pidfd_open'):self.assertIsNotNone(process.pidfd)
            self.operation(engine,'TERMINATE',h)
            self.assertIsNotNone(process.process.returncode)
            self.operation(engine,'RELEASE',h)
        backend=SyntheticProcessBackend()
        with self.fixture(backend) as (_,e,roots,journal,backend,engine):
            h=self.create(engine);self.operation(engine,'START',h)
            backend.resources[h]['process'].process.wait(timeout=3)
            self.assertEqual(self.operation(engine,'STATUS',h)['state'],'TERMINATED')
            self.operation(engine,'RELEASE',h)

    def static(self):
        root=Path(__file__).parent/'orchestrator/privilege'
        texts={file.name:file.read_text() for file in root.glob('*.py')}
        for code in texts.values():
            for forbidden in ('shell=True','os.system(', 'pickle.', 'yaml.load(', 'os.kill(', 'os.killpg(', 'os.unshare(', 'LIBC.mount', 'chmod(0o777'):
                self.assertNotIn(forbidden,code)
        public=inspect.signature(ControllerClient.start_sandbox)
        self.assertEqual(list(public.parameters),['self','sandbox'])
        self.assertEqual(list(inspect.signature(ControllerClient.terminate).parameters),['self','sandbox'])
        for module in ('worker.py','file_tools.py','coder.py','fixer.py','model_attribution.py'):
            self.assertNotIn('privilege', (root.parent/'roles'/module).read_text())
        self.assertNotIn('from orchestrator.privilege', (root.parent/'doctor.py').read_text())
        self.assertNotIn('orchestrator.privilege', (root.parent.parent/'install.sh').read_text())
        self.assertNotIn('PROVIDER_KEY',str(FakeBackend().probe()))
