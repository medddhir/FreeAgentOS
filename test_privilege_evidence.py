"""B7 bounded proof contracts: pure classifiers, owned unprivileged pipes, recording IPC."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from orchestrator.privilege import evidence as e, protocol as p
from orchestrator.privilege.client import ControllerClient, Sandbox
from orchestrator.privilege.kernel import LinuxDriver
from test_privilege_cleanup import LauncherContainmentCases
from test_privilege_complete import LinuxCompleteCases
from test_privilege_probe import ProbeContractCases

IDENTITY={'handle':'a'*32,'run_id':'b'*32,'owner':'c'*32,'policy':'d'*64,
          'class':'MODEL_WORKER','role':'coder','executable_sha256':'e'*64}
START={'schema_version':2,'fixture':e.FIXTURE,'event':'STARTED',
       'uid':1234,'gid':1234,'pid':123,'pid_ns':456,'mount_ns':789,
       'capabilities_clear':True,'no_new_privs':True,'host_root_visible':False}
DONE={'schema_version':2,'fixture':e.FIXTURE,'event':'COMPLETED'}
def line(v):return json.dumps(v,separators=(',',':')).encode()+b'\n'

class EvidenceCases(unittest.TestCase):
    def cases(self):
        for name in sorted(n for n in dir(self) if n.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()

    def classify(self,output,receipt=b'EXEC_READY\n',**kw):
        return e.classify(IDENTITY,output,receipt,**{'output_eof':True,'receipt_eof':True,'exit_code':0,**kw})

    def case_valid_and_distinct_signals(self):
        valid=self.classify(line(START)+line(DONE))
        self.assertEqual((valid['status'],valid['completion'],valid['enforcement']),('VALID','SUCCESS','UNPROVEN'))
        self.assertEqual(self.classify(b'')['executable_transition'],'UNPROVEN')
        self.assertEqual(self.classify(line(START))['completion'],'UNPROVEN')
        failed=self.classify(line(START),b'EXEC_READY\nEXEC_FAILED\n',exit_code=125)
        self.assertTrue(failed['launcher_ready']);self.assertEqual(failed['reason'],'EXEC_FAILED')
        self.assertEqual(failed['executable_transition'],'UNPROVEN')
        self.assertEqual(self.classify(line(START)+line(DONE),exit_code=125)['completion'],'UNPROVEN')
        for key in ('capabilities_clear','no_new_privs','host_root_visible'):
            claims={**START,key:not START[key]}
            self.assertEqual(self.classify(line(claims)+line(DONE))['enforcement'],'UNPROVEN')

    def case_reject_output(self):
        bad=[(line(START)[:-1],'OUTPUT_TRUNCATED'),(b'{bad}\n','OUTPUT_INVALID'),
             (b'x'*(e.MAX_OUTPUT+1),'OUTPUT_OVERSIZED'),(line(DONE),'OUTPUT_INVALID'),
             (line(START)*2,'OUTPUT_INVALID'),(line(START)+line(DONE)*2,'OUTPUT_INVALID'),
             (line({**START,'extra':'private'}),'OUTPUT_INVALID'),
             (line({**START,'schema_version':True}),'OUTPUT_INVALID'),
             (line({**START,'uid':True}),'OUTPUT_INVALID'),
             (b'{"schema_version":2,"schema_version":2}\n','OUTPUT_INVALID')]
        for raw,reason in bad:
            with self.subTest(reason=reason):
                result=self.classify(raw);self.assertEqual(result['reason'],reason)
                self.assertEqual(result['status'],'REJECTED');self.assertFalse(result['child_claims'])
        self.assertEqual(self.classify(b'')['reason'],'OUTPUT_MISSING')
        self.assertEqual(self.classify(line(START),receipt=b'')['reason'],'OUTPUT_CONTRADICTORY')
        self.assertEqual(self.classify(line(START),receipt=b'EXEC_READY\nforeign')['reason'],'RECEIPT_INVALID')
        self.assertEqual(self.classify(line(START),receipt_eof=False)['executable_transition'],'UNPROVEN')

    def case_strict_binding_and_schema(self):
        v=self.classify(line(START)+line(DONE))
        invalid=[{**v,'schema_version':True},{**v,'extra':1},{**v,'enforcement':'VERIFIED'},
                 {**v,'output_bytes':e.MAX_OUTPUT+2},{**v,'record_count':3},
                 {**v,'launcher_ready':False},{**v,'receipt_eof':False},
                 {**v,'collector_closed':False},{**v,'output_eof':False},{**v,'completion':'UNPROVEN'},
                 {**v,'exit_status':'NONZERO'},{**v,'child_claims':{}},
                 {**v,'status':'INCOMPLETE','completion':'UNPROVEN','reason':'COMPLETE'},
                 {**v,'child_claims':{**v['child_claims'],'uid':True}}]
        for k in e.BINDING:invalid.append({**v,k:'foreign'})
        for bad in invalid:
            with self.assertRaises(p.BoundaryError):e.validate(bad,IDENTITY)
        for k in e.BINDING:
            with self.assertRaises(p.BoundaryError):e.validate(e.empty({**IDENTITY,k:'foreign'}),{**IDENTITY,k:'foreign'})
        self.assertLess(len(p.encode(p.response(1,'OK',v))),p.MAX_FRAME)

    @contextlib.contextmanager
    def child(self,code,*,timeout=1):
        # Fixed local test launcher, no privilege setup/backend or project access.
        r,w=os.pipe2(os.O_CLOEXEC)
        prelude='import os,sys,time\nr=int(sys.argv[1]);os.set_inheritable(r,False)\n'
        child=subprocess.Popen([sys.executable,'-I','-c',prelude+code,str(w)],pass_fds=(w,),
                               stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin'})
        os.close(w)
        collector=e.SyntheticCollector(IDENTITY,child,r)
        try:
            with patch.object(e,'COLLECTION_SECONDS',timeout):
                collector.start();collector.thread.join(timeout=3)
                self.assertFalse(collector.thread.is_alive())
                yield collector,child,r
        finally:
            try:collector.close()
            finally:
                if child.poll() is None:child.kill()
                child.wait(timeout=3)

    def case_unprivileged_fixed_fixture(self):
        compiler=shutil.which('cc')
        self.assertIsNotNone(compiler,'fixed fixture test requires a local C compiler')
        with tempfile.TemporaryDirectory() as tmp:
            executable=Path(tmp)/'synthetic';source=Path('orchestrator/privilege/fixtures/synthetic_worker.c').resolve()
            subprocess.run([compiler,'-O2','-Wall','-Wextra',str(source),'-o',str(executable)],check=True,
                           stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=20)
            # Receipt reader normally consumes READY before transferring to collector.
            # Here seed READY in the collector; actual exec closes the writer.
            code='os.execve('+repr(str(executable))+', ["fixture","--synthetic-complete"], {"PATH":"/usr/bin:/bin"})\n'
            with self.child(code) as (collector,child,fd):
                report=collector.snapshot();self.assertEqual(report['completion'],'SUCCESS')
                self.assertEqual(report['child_claims']['pid'],child.pid)
                self.assertTrue(report['receipt_eof']);self.assertTrue(child.stdout.closed)
                with self.assertRaises(OSError):os.fstat(fd)
            # A completed transition does not imply successful synthetic completion.
            with self.child('os.close(r)\nsys.stdout.buffer.write('+repr(line(START))+');sys.stdout.flush()\nsys.exit(7)') as (collector,child,fd):
                self.assertEqual(collector.snapshot()['executable_transition'],'FIXTURE_STARTED')
                self.assertEqual(collector.snapshot()['completion'],'UNPROVEN')

    def case_pipe_timeout_overflow_and_exit(self):
        with self.child('os.close(r)\ntime.sleep(5)',timeout=.1) as (c,child,fd):
            self.assertEqual(c.snapshot()['reason'],'COLLECTION_TIMEOUT');self.assertTrue(child.stdout.closed)
        with self.child('os.close(r)\nsys.stdout.buffer.write(b"x"*65536);sys.stdout.flush()\ntime.sleep(5)') as (c,child,fd):
            self.assertEqual(c.snapshot()['reason'],'OUTPUT_OVERSIZED');self.assertEqual(c.snapshot()['output_bytes'],2049)
        with self.child('os.write(r,b"EXEC_FAILED\\n")\nsys.exit(125)') as (c,child,fd):
            self.assertEqual(c.snapshot()['reason'],'EXEC_FAILED');self.assertTrue(c.snapshot()['launcher_ready'])
        with self.child('os.close(r)\nsys.exit(0)') as (c,child,fd):
            self.assertEqual(c.snapshot()['reason'],'OUTPUT_MISSING')
        with self.child('os.close(r)\nsys.stdout.buffer.write(b"{");sys.stdout.flush()') as (c,child,fd):
            self.assertEqual(c.snapshot()['reason'],'OUTPUT_TRUNCATED')

    def case_close_failure_preserves_obligations(self):
        stream=Mock();stream.close.side_effect=OSError('private')
        collector=e.SyntheticCollector(IDENTITY,Mock(stdout=stream),17)
        with patch.object(e.os,'close') as close:
            with self.assertRaisesRegex(p.BoundaryError,'CLEANUP_INCOMPLETE'):collector.close()
            close.assert_called_once_with(17)
        self.assertTrue(collector.close_failed)
        cases=LauncherContainmentCases()
        with cases.fixture() as (d,r,entry,child,m):
            d.launch(r,entry,{})
            m['orchestrator.privilege.kernel.SyntheticCollector'].return_value.close.side_effect=OSError('private')
            with self.assertRaises(p.BoundaryError):d.terminate(r)
            child.wait.assert_called_once();child.stdin.close.assert_called();child.stdout.close.assert_called()
            self.assertIn(r['handle'],d.close_errors);self.assertIn(r['handle'],d.collectors)
            self.assertFalse(d.absent(r))
            with self.assertRaises(p.BoundaryError):d.remove(r)
        with LinuxCompleteCases().fixture() as (backend,driver,journal,*_):
            cases=LinuxCompleteCases();cases.create(backend);backend.start('b'*32)
            driver.collection_failed=Mock(return_value=True);driver.fail='CGROUP_KILL_OWNED'
            with self.assertRaises(RuntimeError):backend.enforce()
            self.assertTrue(backend.recovery_required)
            self.assertEqual(journal.load()[0]['state'],'FAILED_DIRTY')
            self.assertEqual(journal.load()[0]['cleanup'],'UNPROVEN')
            driver.fail=None;backend.recover()

    def case_owned_collection_rpc(self):
        cases=ProbeContractCases()
        with cases.endpoint(True) as (server,enrollment,engine,backend),cases.linux_client_profile():
            client=ControllerClient(server.path,enrollment,0,os.getgid(),linux_validation=True)
            try:
                engine.roots.register('validation',server.path.parent/'work',os.getuid())
                sandbox=client.create_sandbox('validation','MODEL_WORKER','coder')
                record=engine.records[sandbox.handle];identity={k:record[k] for k in e.BINDING if k!='executable_sha256'}
                identity['executable_sha256']='e'*64
                proof=e.classify(identity,line(START)+line(DONE),output_eof=True,receipt_eof=True,exit_code=0,receipt=b'EXEC_READY\n')
                with patch.object(backend,'collect',return_value=proof):
                    self.assertEqual(client.collect_synthetic(sandbox),proof)
                    request={'version':1,'seq':1,'op':'COLLECT','args':{'handle':sandbox.handle}}
                    with self.assertRaisesRegex(p.BoundaryError,'UNKNOWN_HANDLE'):
                        engine.dispatch(request,'f'*32,(1,enrollment.uid,enrollment.gid))
                for k in ('handle','run_id','owner','policy'):
                    with patch.object(backend,'collect',return_value={**proof,k:'f'*len(proof[k])}):
                        with self.assertRaises(p.BoundaryError):client.collect_synthetic(sandbox)
                with self.assertRaises(p.BoundaryError):client.collect_synthetic(Sandbox('f'*32))
                with patch.object(client,'_rpc',return_value={**proof,'run_id':'f'*32}):
                    with self.assertRaises(p.BoundaryError):client.collect_synthetic(sandbox)
            finally:client.close()
        with cases.endpoint() as (server,enrollment,*_):
            client=ControllerClient(server.path,enrollment,os.getuid(),os.getgid())
            try:
                with self.assertRaisesRegex(p.BoundaryError,'POLICY_REJECTED'):client.collect_synthetic(Sandbox('a'*32))
            finally:client.close()
        with LinuxCompleteCases().fixture() as (b,d,*_):
            LinuxCompleteCases().create(b)
            with self.assertRaisesRegex(p.BoundaryError,'INVALID_STATE'):b.collect('b'*32)

    def case_retained_owned_evidence(self):
        d=LinuxDriver.__new__(LinuxDriver);d.owner=IDENTITY['owner'];d.collectors={}
        d.proof_bindings={IDENTITY['handle']:dict(IDENTITY)}
        valid=self.classify(line(START)+line(DONE));d.proofs={IDENTITY['handle']:valid}
        record={k:v for k,v in IDENTITY.items() if k!='executable_sha256'}
        self.assertEqual(d.collect(record),valid)
        for k in ('run_id','owner','policy','class','role'):
            with self.assertRaises(p.BoundaryError):d.collect({**record,k:'foreign'})
        d.proofs[record['handle']]={**valid,'executable_sha256':'f'*64}
        with self.assertRaises(p.BoundaryError):d.collect(record)

    def case_stop_and_independent_descriptor_close(self):
        # Emulates controller disconnect: collector stop never waits for child exit.
        r,w=os.pipe2(os.O_CLOEXEC);out,writer=os.pipe2(os.O_CLOEXEC)
        stream=os.fdopen(out,'rb',buffering=0);child=Mock(stdout=stream);child.poll.return_value=None
        collector=e.SyntheticCollector(IDENTITY,child,r)
        try:
            collector.start();collector.close();collector.close()
            self.assertFalse(collector.thread.is_alive());self.assertTrue(stream.closed)
            self.assertEqual(collector.snapshot()['reason'],'COLLECTION_CLOSED')
            with self.assertRaises(OSError):os.fstat(r)
        finally:os.close(w);os.close(writer)
        d=LinuxDriver.__new__(LinuxDriver);d.close_errors=set();d.collectors={'a'*32:Mock()}
        d.collectors['a'*32].close.side_effect=OSError('private');d.scopes={'a'*32:10};d.roots={'a'*32:11}
        d.root_fd=12;d.cgroup_fd=13;d.children={'a'*32:Mock()}
        with patch('os.close') as closed:
            with self.assertRaises(p.BoundaryError):d.close()
            self.assertEqual([c.args[0] for c in closed.call_args_list],[10,11,12,13])
            d.children['a'*32].close.assert_called_once()
        self.assertIn('a'*32,d.close_errors)
