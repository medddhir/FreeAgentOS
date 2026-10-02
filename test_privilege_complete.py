"""Deterministic Linux composition tests; no privileged kernel operations."""
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, Mock
from orchestrator.privilege import protocol as p
from orchestrator.privilege.policy import policy_hash, CLASSES
from orchestrator.privilege.linux import PinnedFile, secure_open
from orchestrator.privilege.sealed import Seal, SnapshotSource
from orchestrator.privilege.execution import ApprovedExecution, ExecutionRegistry
from orchestrator.privilege.real_journal import ResourceJournal, recovery_actions
from orchestrator.privilege.isolation import LinuxBackend, role_base
from orchestrator.privilege.recording import RecordingDriver
from orchestrator.privilege.child import ChildRoutine, ORDER, validate_configuration
from orchestrator.privilege.kernel import cgroup_qualification, CGROUP2_MAGIC, LinuxDriver
from orchestrator.privilege.service import prepare_enrollment, check_package
from orchestrator.privilege.validation import bundle_manifest, rollback_targets, PHASES, simulation_report, validate_residuals

class LinuxCompleteCases(unittest.TestCase):
    def cases(self):
        for case in ('snapshot','argv','runtime_root','composition','deadline','recovery','journal','cgroup','bundle','import','entrypoint','production','fd_closure','path_primitives','supervisor_composition','prepared_bundle','pidfd','fixed_mounts'):
            with self.subTest(case=case):getattr(self,'case_'+case)()

    def manifest(self,files):
        return json.dumps({'schema_version':1,'source_inventory':{n:hashlib.sha256(v).hexdigest() for n,v in files.items()},
           'worker_resource_policy':dict(CLASSES['MODEL_WORKER'].limits),
           'research_resource_policy':dict(CLASSES['RESEARCH_HELPER'].limits),
           'resource_policy':dict(CLASSES['DETERMINISTIC_TESTER'].limits)},sort_keys=True).encode()

    def case_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp);root=parent/'source';root.mkdir();(root/'file').write_bytes(b'authorized')
            raw=self.manifest({'file':b'authorized'});seal=Seal.from_verification(raw,hashlib.sha256(raw).hexdigest())
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);source=SnapshotSource(fd,seal);os.close(fd)
            try:
                # Directory and parent replacement leave pinned original inode.
                root.rename(parent/'old');root.mkdir();(root/'file').write_bytes(b'hostile')
                out=parent/'out';out.mkdir();dest=os.open(out,os.O_RDONLY|os.O_DIRECTORY)
                try:self.assertEqual(source.copy_into(dest)['files'],1)
                finally:os.close(dest)
                self.assertEqual((out/'file').read_bytes(),b'authorized')
                moved=parent/'moved';(parent/'old').rename(moved)
                (moved/'file').unlink();(moved/'file').symlink_to(root/'file')
                bad=parent/'bad';bad.mkdir();dest=os.open(bad,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    with self.assertRaises(p.BoundaryError):source.copy_into(dest)
                finally:os.close(dest)
                self.assertFalse(os.get_inheritable(source.fd))
                for name in ('../file','/etc/passwd','a/../b','a//b','a\0b','.git'):
                    raw=self.manifest({name:b'x'})
                    with self.assertRaises(p.BoundaryError):Seal.from_verification(raw,hashlib.sha256(raw).hexdigest())
            finally:source.close()
        raw=self.manifest({'file':b'x'})
        with self.assertRaises(p.BoundaryError):Seal.from_verification(raw,'a'*64)

    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            exe=root/'exe';exe.write_bytes(b'\x7fELFfixture');exe.chmod(0o700)
            ef=os.open(exe,os.O_RDONLY|os.O_CLOEXEC)
            pinned=PinnedFile(ef,os.fstat(ef).st_dev,os.fstat(ef).st_ino,hashlib.sha256(exe.read_bytes()).hexdigest())
            entry=ApprovedExecution('MODEL_WORKER','coder',pinned,fd,1234,1234,'e'*32,True)
            registry=ExecutionRegistry({'validation':entry});journal=ResourceJournal(root,policy_hash(),'a'*32,uid=os.getuid())
            clock=[0];driver=RecordingDriver();backend=LinuxBackend(registry,{'validation':object()},driver,journal,clock=lambda:clock[0])
            try:
                with patch.object(ApprovedExecution,'verify',return_value=None):yield backend,driver,journal,clock,entry
            finally:backend.close();journal.close();os.close(fd);os.close(ef)

    def create(self,b):return b.create('b'*32,'c'*32,'validation','MODEL_WORKER','coder',{})

    def case_argv(self):
        with self.fixture() as (_,_,_,_,entry):
            self.assertEqual(entry.argv(),('freeagentos-worker','--synthetic'))
            with self.assertRaises(TypeError):entry.argv(['--no-sandbox'])
            with self.assertRaises(TypeError):entry.environment({'LD_PRELOAD':'credential-secret'})
            self.assertNotIn('LD_PRELOAD',entry.environment())
            with self.assertRaises(TypeError):ExecutionRegistry({'validation':entry}).entries['other']=entry
            with self.assertRaises(p.BoundaryError):ExecutionRegistry({'validation':entry}).bind('validation','RESEARCH_HELPER','research:exa')
        with self.assertRaises(p.BoundaryError):p.validate_request({'version':1,'seq':1,'op':'START','args':{'handle':'b'*32,'argv':['sh'],'pid':123}})

    def case_runtime_root(self):
        verify=ApprovedExecution.verify
        with self.fixture() as (_,_,_,_,entry):
            with self.assertRaises(p.BoundaryError):verify(entry)
            root=Path('/proc/self/fd/'+str(entry.runtime_fd))
            root.chmod(0o755)
            try:
                (root/'.freeagent-runtime').write_bytes(b'FREEAGENTOS_MINIMAL_RUNTIME_V1\n')
                for name in ('tmp','run','home','dev','workspace','proc'):
                    (root/name).mkdir(mode=0o755)
                verify(entry)
            finally:root.chmod(0o700)

    def case_composition(self):
        with self.fixture() as (b,d,j,clock,entry):
            self.assertEqual(self.create(b)['state'],'CREATED');b.start('b'*32)
            self.assertEqual(b.status('b'*32)['state'],'RUNNING')
            operations=[op for h,op in d.events if h=='b'*32]
            self.assertEqual(operations[-len(ORDER):],list(ORDER))
            self.assertLess(ORDER.index('CGROUP_BARRIER'),ORDER.index('EXEC'))
            self.assertLess(ORDER.index('CLOSE_PRIVILEGED_FDS'),ORDER.index('EXEC'))
            with self.assertRaises(p.BoundaryError):b.start('b'*32)
            b.terminate('b'*32);b.cleanup('b'*32);self.assertTrue(b.cleaned('b'*32,b.owner))
            self.assertEqual(j.load()[0]['cleanup'],'CONFIRMED')
            with self.assertRaises(p.BoundaryError):self.create(b)
        with self.fixture() as (b,d,*_):
            d.fail='SNAPSHOT_FD_SEAL'
            with self.assertRaisesRegex(p.BoundaryError,'BACKEND_FAILURE'):self.create(b)
            self.assertEqual(b.status('b'*32)['state'],'FAILED_DIRTY')
            with self.assertRaises(p.BoundaryError):b.start('b'*32)

    def case_deadline(self):
        with self.fixture() as (b,d,j,clock,_):
            self.create(b);b.start('b'*32)
            broker=Mock();broker.telemetry.last_success_ns=179_000_000_000
            b.observe_progress('b'*32,broker);clock[0]=180_000_000_000;b.enforce()
            self.assertEqual(b.status('b'*32)['state'],'RUNNING')
            clock[0]=240_000_000_000
            # Independent monitor, with no controller request, enforces expiry.
            deadline=time.monotonic()+1
            while b.status('b'*32)['state']=='RUNNING' and time.monotonic()<deadline:time.sleep(.01)
            self.assertEqual(b.status('b'*32)['state'],'TERMINATED')
            self.assertEqual(role_base('MODEL_WORKER','planner',dict(CLASSES['MODEL_WORKER'].limits)),90)
        with self.fixture() as (b,d,j,clock,_):
            self.create(b);b.start('b'*32);b.disconnect(['b'*32]);self.assertTrue(b.cleaned('b'*32,b.owner))
        with self.fixture() as (b,d,j,clock,_):
            self.create(b);b.start('b'*32);clock[0]=180_000_000_000;b.enforce()
            self.assertEqual(b.status('b'*32)['state'],'TERMINATED')

    def case_recovery(self):
        with self.fixture() as (b,d,j,clock,_):
            self.create(b);b.start('b'*32);b.close()
            recovered=LinuxBackend(b.registry,b.sources,d,j,clock=lambda:0)
            try:recovered.recover();self.assertTrue(recovered.cleaned('b'*32,b.owner))
            finally:recovered.close()
        with self.fixture() as (b,d,j,clock,_):
            self.create(b);d.resources[next(iter(d.resources))]['owner']='f'*32
            with self.assertRaisesRegex(p.BoundaryError,'CLEANUP_INCOMPLETE'):b.recover()
            self.assertEqual(b.status('b'*32)['state'],'FAILED_DIRTY')
            self.assertNotIn(('b'*32,'CGROUP_KILL_OWNED'),d.events)

    def case_journal(self):
        with self.fixture() as (b,d,j,clock,_):
            self.create(b);record=j.load()[0]
            for key in ('token','prompt','environment','pid','mount'):
                with self.assertRaises(p.BoundaryError):j.save([{**record,key:'secret-fixture'}])
            for bad in (True,-1,2**64):
                with self.assertRaises(p.BoundaryError):j.save([{**record,'root_inode':bad}])
            os.write(1,b'') # no raw journal printing
            fd=os.open('resources.json',os.O_WRONLY|os.O_TRUNC,dir_fd=j.fd);os.write(fd,b'{"version":2,"version":1}');os.close(fd)
            with self.assertRaises(p.BoundaryError):j.load()

    def case_cgroup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);path.chmod(0o700)
            for name,text in [('cgroup.controllers','cpu memory pids'),('cgroup.subtree_control','cpu memory pids'),('cgroup.kill','')]:
                (path/name).write_text(text)
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            try:
                before={p.name:p.read_bytes() for p in path.iterdir()}
                self.assertEqual(cgroup_qualification(fd,expected_uid=os.getuid(),filesystem=CGROUP2_MAGIC)['codes'],[])
                (path/'cgroup.kill').unlink()
                self.assertIn('CGROUP_KILL_UNAVAILABLE',cgroup_qualification(fd,expected_uid=os.getuid(),filesystem=CGROUP2_MAGIC)['codes'])
                (path/'cgroup.controllers').write_text('cpu')
                self.assertIn('CONTROLLER_MISSING',cgroup_qualification(fd,expected_uid=os.getuid(),filesystem=CGROUP2_MAGIC)['codes'])
                with self.assertRaises(p.BoundaryError):LinuxDriver(None,fd,fd,None,'a'*32)
            finally:os.close(fd)

    def case_bundle(self):
        first=bundle_manifest('a'*64,'b'*64,'c'*64)
        self.assertEqual(first,bundle_manifest('a'*64,'b'*64,'c'*64))
        self.assertNotIn('/root/',json.dumps(first));self.assertNotIn('token_value',json.dumps(first))
        self.assertEqual(len(PHASES),23);self.assertFalse(simulation_report(PHASES)['privileged_executed'])
        self.assertTrue(validate_residuals({'workers':0,'scopes':0,'mounts':0,'dirty':False}))
        with self.assertRaises(p.BoundaryError):rollback_targets([{'owner':'f'*32,'handle':'b'*32,'owned':True}],'a'*32)
        self.assertEqual(rollback_targets([{'owner':'a'*32,'handle':'b'*32,'owned':True}],'a'*32),('b'*32,))
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o700);captured=io.StringIO()
            with contextlib.redirect_stdout(captured):public=prepare_enrollment(tmp,1234,1234)
            self.assertEqual(captured.getvalue(),'');self.assertNotIn('token',public)
            self.assertEqual(stat.S_IMODE((Path(tmp)/'token').stat().st_mode),0o600)

    def case_import(self):
        from orchestrator.privilege import kernel, child, service, isolation
        with patch('os.mkdir',side_effect=AssertionError),patch('os.chroot',side_effect=AssertionError),patch('os.setuid',side_effect=AssertionError),patch('subprocess.Popen',side_effect=AssertionError),patch('ctypes.CDLL',side_effect=AssertionError):
            # Avoid reloading class identity modules used by other tests.
            importlib.import_module('orchestrator.privilege.kernel')
            importlib.import_module('orchestrator.privilege.child')

        code="""import sys
sys.path.insert(0,sys.argv[1])
from unittest.mock import patch
with patch('os.mkdir',side_effect=AssertionError),patch('os.chroot',side_effect=AssertionError),patch('os.setuid',side_effect=AssertionError),patch('os.setgid',side_effect=AssertionError),patch('os.mknod',side_effect=AssertionError),patch('os.fork',side_effect=AssertionError),patch('ctypes.CDLL',side_effect=AssertionError),patch('subprocess.Popen',side_effect=AssertionError):
 import orchestrator.privilege.kernel, orchestrator.privilege.child, orchestrator.privilege.service, orchestrator.privilege.isolation
"""
        result=subprocess.run([sys.executable,'-I','-c',code,str(Path.cwd())],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode()[:1000])

    def case_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);path.chmod(0o777)
            with self.assertRaises(p.BoundaryError):check_package(path,os.getuid())
        from orchestrator.privilege.service import serve
        with patch('os.geteuid',return_value=1234),patch('os.mkdir',side_effect=AssertionError):
            with self.assertRaises(p.BoundaryError):serve('/not/read','/not/read')

    def case_production(self):
        source=Path('orchestrator/roles/worker.py').read_text()
        self.assertNotIn('privilege',source)
        doctor=Path('orchestrator/doctor.py').read_text()
        self.assertIn('UNPROVEN',doctor)

    def case_fd_closure(self):
        from orchestrator.privilege.child import LinuxChildCalls
        calls=LinuxChildCalls.__new__(LinuxChildCalls);calls.position=ORDER.index('CLOSE_PRIVILEGED_FDS');calls.setup=Mock(stage='DROPPED')
        c={'fds':[3,4,5,6,7,8]}
        with patch('os.listdir',return_value=[str(i) for i in range(10)]),patch('os.close') as close,patch('os.set_inheritable') as inherit:
            calls.perform('CLOSE_PRIVILEGED_FDS',c)
        self.assertEqual([v.args[0] for v in close.call_args_list],[3,4,5,7,9])
        self.assertEqual([v.args for v in inherit.call_args_list],[(6,False),(8,False)])

    def case_path_primitives(self):
        root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            with self.assertRaises(p.BoundaryError):secure_open(root,'proc/version')
        finally:os.close(root)
        proc=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            with self.assertRaises(p.BoundaryError):secure_open(proc,'self/fd/0')
        finally:os.close(proc)
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);parent=base/'parent';parent.mkdir();root=parent/'source';root.mkdir();(root/'file').write_bytes(b'valid')
            raw=self.manifest({'file':b'valid'});seal=Seal.from_verification(raw,hashlib.sha256(raw).hexdigest())
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);source=SnapshotSource(fd,seal);os.close(fd)
            try:
                parent.rename(base/'original');parent.mkdir();(parent/'source').symlink_to('/etc')
                out=base/'out';out.mkdir();dest=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
                try:source.copy_into(dest)
                finally:os.close(dest)
                self.assertEqual((out/'file').read_bytes(),b'valid')
            finally:source.close()

    def case_supervisor_composition(self):
        from orchestrator.privilege.supervisor import Supervisor
        from orchestrator.privilege.security import Enrollment, RegisteredRoots
        from orchestrator.privilege.journal import Journal
        with self.fixture() as (b,d,*_):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);root.chmod(0o700);workspace=root/'work';workspace.mkdir(mode=0o700)
                roots=RegisteredRoots();roots.register('validation',workspace,os.getuid());journal=Journal(root,policy_hash())
                enrollment=Enrollment('d'*32,os.getuid(),os.getgid(),'f'*64)
                try:
                    engine=Supervisor(enrollment,roots,b,journal,linux_validation=True)
                    peer=(1,os.getuid(),os.getgid());connection='e'*32
                    def request(op,args):return {'version':1,'seq':1,'op':op,'args':args}
                    result=engine.dispatch(request('CREATE',{'run_id':'c'*32,'slot':'validation','class':'MODEL_WORKER','role':'coder','limits':{}}),connection,peer)
                    self.assertEqual(result['mode'],'LINUX')
                    handle=result['handle'];engine.dispatch(request('START',{'handle':handle}),connection,peer)
                    engine.disconnect(connection)
                    self.assertEqual(engine.dispatch(request('STATUS',{'handle':handle}),connection,peer)['cleanup'],'CONFIRMED')
                finally:roots.close();journal.close()

    def case_prepared_bundle(self):
        from orchestrator.privilege.validation import prepare_bundle
        from orchestrator.privilege.service import load_admin
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o700);raw=self.manifest({'fixture.txt':b'no-model'})
            captured=io.StringIO()
            with contextlib.redirect_stdout(captured):result=prepare_bundle(tmp,'a'*64,'b'*64,'c'*64,1234,1234,2345,2345,raw)
            self.assertEqual(captured.getvalue(),'');self.assertEqual(result['status'],'PREPARED_NOT_INSTALLED')
            public=(Path(tmp)/'install-manifest.json').read_text()
            token=(Path(tmp)/'enrollment/token').read_text()
            self.assertNotIn(token,public);self.assertNotIn(token,json.dumps(result))
            self.assertEqual(stat.S_IMODE((Path(tmp)/'admin.json').stat().st_mode),0o600)
            with self.assertRaises(p.BoundaryError):prepare_bundle(tmp,'a'*64,'b'*64,'c'*64,1234,1234,2345,2345,raw)

    def case_pidfd(self):
        from orchestrator.privilege.linux import OwnedPidfd
        child=Mock();child.poll.return_value=None;child.pid=123
        with patch('os.pidfd_open',return_value=987) as opened,patch('os.set_inheritable') as inherit,patch('select.select',return_value=([],[],[])),patch('os.close') as closed:
            handle=OwnedPidfd('a'*32,child)
            self.assertTrue(handle.running('a'*32))
            with self.assertRaises(p.BoundaryError):handle.running('b'*32)
            opened.assert_called_once_with(123,0);inherit.assert_called_once_with(987,False)
            handle.close();handle.close();closed.assert_called_once_with(987)

    def case_fixed_mounts(self):
        from orchestrator.privilege.child import LinuxChildCalls, DEVICES
        calls=LinuxChildCalls.__new__(LinuxChildCalls);calls.position=ORDER.index('ROOTFS');calls._mount=Mock()
        config={'fds':[3,4,5,6,7,8],'class':'MODEL_WORKER','uid':1234,'gid':1234,'limits':dict(CLASSES['MODEL_WORKER'].limits)}
        with patch('os.chown'),patch('os.chmod'):
            calls.perform('ROOTFS',config)
        values=calls._mount.call_args_list
        self.assertEqual(values[0].args,('/proc/self/fd/5','/proc/self/fd/4/rootfs'))
        self.assertEqual(tuple(n for n,_,_ in DEVICES),('null','zero','random','urandom'))
        self.assertTrue(all('/root/' not in str(c) and 'docker' not in str(c) for c in values))
