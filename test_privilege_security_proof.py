"""B8 pure recordings/read projections; NO stress or privileged fixture execution."""
import contextlib
import dataclasses
import json
import os
from pathlib import Path
import shutil
import stat
import hashlib
from types import SimpleNamespace
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from orchestrator.privilege import protocol as p, security_proof as s, security_observe as o
from orchestrator.privilege.security_capture import OwnedSecurityCapture, proc_start
from orchestrator.privilege.policy import resource_limits
from test_privilege_evidence import IDENTITY

class SecurityProofCases(unittest.TestCase):
    def cases(self):
        for name in sorted(n for n in dir(self) if n.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()

    def expectation(self):
        limits=resource_limits('MODEL_WORKER','coder',dict(s.PROBE_LIMITS))
        return s.ProofExpectation(IDENTITY,1234,1235,limits,'f'*32,0,'9'*32,(4,5))

    def data(self,kind,phase='DURING'):
        limit=self.expectation().limits
        table={
          'identity':{'uids':[1234]*4,'gids':[1235]*4,'groups':[]},
          'capabilities':{**{k:0 for k in s.CAPS},'no_new_privs':True},
          'fds':{'open':[0,1,2],'unexpected':[],'standard_safe':True},
          'namespaces':{'host':dict(zip(s.NAMESPACES,(1,2,3,4))), 'worker':dict(zip(s.NAMESPACES,(5,6,7,4))),'inner_pid':1},
          'filesystem':dict.fromkeys(s.FIELDS['filesystem'],True),
          'descendants':{'created':2,'contained':True,'namespace_checked':True,'population':0 if phase=='AFTER' else 3,'pidfds_exited':phase=='AFTER','scope_empty':phase=='AFTER','reaped':phase=='AFTER','released':phase=='AFTER','cleanup_confirmed':phase=='AFTER'},
          'cpu':{'quota_us':50000,'period_us':100000,'elapsed_ns':0 if phase=='BEFORE' else 3_000_000_000,'usage_usec':0 if phase=='BEFORE' else 1_400_000,'periods':0 if phase=='BEFORE' else 30,'throttled_periods':0 if phase=='BEFORE' else 20,'throttled_usec':0 if phase=='BEFORE' else 1_500_000,'runnable_tasks':2,'work_completed':phase=='AFTER','cpus_available':2},
          'memory':{'limit_bytes':limit['memory_limit_bytes'],'swap_bytes':0,'peak_bytes':32*1024*1024 if phase=='BEFORE' else 64*1024*1024,'max_events':0 if phase=='BEFORE' else 3,'oom_events':0 if phase=='BEFORE' else 1,'oom_kills':0 if phase=='BEFORE' else 1,'work_completed':False,'termination_requested':False},
          'pids':{'limit':8,'peak':2 if phase=='BEFORE' else 8,'max_events':0 if phase=='BEFORE' else 1,'created':0 if phase=='BEFORE' else 6,'work_completed':phase=='AFTER'}}
        return table[kind]

    def records(self,kind,source='INDEPENDENT_RECORDING'):
        x=self.expectation();phases=('BEFORE','AFTER') if kind in ('cpu','memory','pids') else ('DURING','AFTER') if kind=='descendants' else ('DURING',)
        return [s.record(x,kind,source,phase,self.data(kind,phase),0 if phase!='AFTER' else 3_000_000_000) for phase in phases]

    def evaluate(self,kind,records,**kw):
        values=s.evaluate(self.expectation(),records,**{'execution':'RESOURCE_TERMINATED' if kind=='memory' else 'COMPLETED','cleanup':'CONFIRMED',**kw})
        self.assertEqual(values['enforcement'],'UNPROVEN')
        return values['proofs'][kind]

    def case_each_observable(self):
        for kind in s.KINDS:
            with self.subTest(kind=kind):
                self.assertEqual(self.evaluate(kind,self.records(kind))['assessment'],'PASS')
                self.assertEqual(self.evaluate(kind,[])['assessment'],'INCONCLUSIVE')
                for source in ('CONFIGURED','CHILD_REPORTED'):
                    v=self.evaluate(kind,self.records(kind,source));self.assertEqual(v['assessment'],'INCONCLUSIVE');self.assertEqual(v['level'],source)
                broken=self.records(kind);broken[-1]['data']['unknown_security_claim']=True
                self.assertEqual(self.evaluate(kind,broken)['reason'],'EVIDENCE_INVALID')
                contradictory=self.records(kind)+self.records(kind,'CHILD_REPORTED')
                contradictory[-1]['data']=self.data(kind,contradictory[-1]['phase'])
                if kind=='identity':contradictory[-1]['data']['uids'][0]=99
                elif kind=='fds':contradictory[-1]['data']={'open':[0,1,2,4],'unexpected':[4],'standard_safe':True}
                else:
                    key=next(k for k,v in contradictory[-1]['data'].items() if type(v) is bool or type(v) is int)
                    contradictory[-1]['data'][key]=not contradictory[-1]['data'][key] if type(contradictory[-1]['data'][key]) is bool else contradictory[-1]['data'][key]+1
                contradictory.sort(key=lambda v:v['at_ns'])
                self.assertEqual(self.evaluate(kind,contradictory)['assessment'],'INCONCLUSIVE')

    def case_isolation_failure(self):
        changes={'identity':('uids',[1234,1234,0,1234]),'capabilities':('ambient',1),
                 'fds':('open',[0,1]),'namespaces':('inner_pid',2),'filesystem':('devices_exact',False)}
        for kind,(field,value) in changes.items():
            records=self.records(kind);records[0]['data'][field]=value
            self.assertEqual(self.evaluate(kind,records)['assessment'],'FAIL')
        for k in s.CAPS:
            v=self.records('capabilities');v[0]['data'][k]=1;self.assertEqual(self.evaluate('capabilities',v)['assessment'],'FAIL')
        for key in s.FIELDS['filesystem']:
            v=self.records('filesystem');v[0]['data'][key]=False;self.assertEqual(self.evaluate('filesystem',v)['assessment'],'FAIL')
        for key in ('uids','gids','groups'):
            v=self.records('identity');v[0]['data'][key]=[99] if key=='groups' else [99]*4
            self.assertEqual(self.evaluate('identity',v)['assessment'],'FAIL')
        v=self.records('fds');v[0]['data']={'open':[0,1,2,4],'unexpected':[4],'standard_safe':True};self.assertEqual(self.evaluate('fds',v)['assessment'],'FAIL')
        v=self.records('descendants');v[0]['data']['contained']=False;self.assertEqual(self.evaluate('descendants',v)['assessment'],'FAIL')

    def case_resource_success_failure_inconclusive(self):
        for kind,key,bad in (('cpu','usage_usec',4_000_000),('memory','peak_bytes',96*1024*1024),('pids','peak',9)):
            records=self.records(kind);records[-1]['data'][key]=bad
            self.assertEqual(self.evaluate(kind,records)['assessment'],'FAIL')
        for kind,key in (('cpu','quota_us'),('memory','limit_bytes'),('pids','limit')):
            records=self.records(kind);records[-1]['data'][key]+=1
            self.assertEqual(self.evaluate(kind,records)['reason'],'LIMIT_READBACK_MISMATCH')
        for kind,key in (('cpu','throttled_usec'),('memory','oom_kills'),('pids','max_events')):
            records=self.records(kind);records[-1]['data'][key]=0
            self.assertEqual(self.evaluate(kind,records)['assessment'],'INCONCLUSIVE')
            self.assertEqual(self.evaluate(kind,records[:1])['assessment'],'INCONCLUSIVE')
        records=self.records('memory');records[-1]['data']['termination_requested']=True
        self.assertEqual(self.evaluate('memory',records)['assessment'],'INCONCLUSIVE')
        records=self.records('cpu');records[-1]['at_ns']-=1
        self.assertEqual(self.evaluate('cpu',records)['reason'],'TIME_WINDOW_MISMATCH')
        records=self.records('cpu');records[-1]['data']['cpus_available']=1
        self.assertEqual(self.evaluate('cpu',records)['reason'],'INSUFFICIENT_STRESS')
        records=self.records('pids');records[0]['data']['max_events']=2
        self.assertEqual(self.evaluate('pids',records)['reason'],'COUNTER_RESET_OR_MISMATCH')

    def case_binding_bounds_and_versions(self):
        valid=self.records('identity')[0];x=self.expectation()
        for key in IDENTITY:
            v=json.loads(json.dumps(valid));v['binding'][key]='foreign'
            self.assertEqual(self.evaluate('identity',[v])['reason'],'EVIDENCE_INVALID')
        for field,value in (('schema_version',True),('schema_version',2),('source','KERNEL'),('sample','e'*32),('subject','e'*32),('scope',[4,6]),('at_ns',s.MAX_CAPTURE_NS+1)):
            v={**valid,field:value};self.assertEqual(self.evaluate('identity',[v])['reason'],'EVIDENCE_INVALID')
        for raw in (b'{bad}\n',b'{}',b'x'*(s.MAX_RECORD_BYTES+2),b'{"a":1,"a":2}\n'):
            buffer=s.RecordBuffer(x)
            with self.assertRaises(p.BoundaryError):buffer.add(raw)
            self.assertTrue(buffer.failed);self.assertFalse(buffer.records)
        buffer=s.RecordBuffer(x);raw=json.dumps(valid).encode()+b'\n';buffer.add(raw)
        with self.assertRaises(p.BoundaryError):buffer.add(raw)
        self.assertEqual(self.evaluate('identity',[valid]*25)['reason'],'EVIDENCE_INVALID')
        with self.assertRaises(p.BoundaryError):s.record(x,'identity','INDEPENDENT_RECORDING','DURING',{'uids':[1]*4,'gids':[2]*4,'groups':[1]*17},0)
        with self.assertRaises(p.BoundaryError):s.record(x,'fds','INDEPENDENT_RECORDING','DURING',{'open':list(range(257)),'unexpected':list(range(3,257)),'standard_safe':True},0)
        # Explicit sidecar bounds neither replace nor enlarge B7.
        from orchestrator.privilege import evidence as b7
        self.assertEqual((b7.MAX_OUTPUT,b7.MAX_RECORD,b7.MAX_RECORDS,b7.COLLECTION_SECONDS),(2048,1024,2,10))
        with self.assertRaises(p.BoundaryError):b7.validate(valid,IDENTITY)

    def case_execution_and_cleanup(self):
        for kind in s.KINDS:
            for execution in ('TIMEOUT','ABNORMAL','MISSING'):
                result=s.evaluate(self.expectation(),self.records(kind),execution=execution)
                self.assertTrue(result['cleanup_obligation']);self.assertEqual(result['proofs'][kind]['assessment'],'INCONCLUSIVE')
        self.assertEqual(self.evaluate('memory',self.records('memory'),execution='COMPLETED')['reason'],'EXPECTED_RESOURCE_EXIT_MISSING')
        records=self.records('descendants');records[-1]['data']['released']=False
        self.assertEqual(self.evaluate('descendants',records)['assessment'],'INCONCLUSIVE')

    def case_parsers(self):
        raw=b'Uid:\t1234 1234 1234 1234\nGid:\t1235 1235 1235 1235\nGroups:\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nNSpid:\t321 1\n'
        identity,caps,inner=o.status(raw);self.assertEqual(identity,self.data('identity'));self.assertEqual(caps,self.data('capabilities'));self.assertEqual(inner,1)
        for bad in (raw[:-1],raw.replace(b'CapEff:\t0\n',b''),raw+b'CapEff:\t0\n',b'x'*65537):
            with self.assertRaises(p.BoundaryError):o.status(bad)
        self.assertEqual(o.fds(['2','0','1'],standard_safe=True),self.data('fds'))
        with self.assertRaises(p.BoundaryError):o.fds(['1','1'])
        with self.assertRaises(p.BoundaryError):o.fds(['../1'])
        cpu=o.cpu(b'50000 100000\n',b'usage_usec 3\nnr_periods 2\nnr_throttled 1\nthrottled_usec 4\n');self.assertEqual(cpu['quota_us'],50000)
        with self.assertRaises(p.BoundaryError):o.cpu(b'max 100000\n',b'')
        self.assertEqual(o.memory(b'64\n',b'0\n',b'32\n',b'max 1\noom 1\noom_kill 1\n')['oom_kills'],1)
        self.assertEqual(o.pids(b'8\n',b'8\n',b'max 1\n')['max_events'],1)
        with self.assertRaises(p.BoundaryError):o.counters(b'max 1\nmax 2\n',('max',))
        suffix=b'S '+b'0 '*18+b'123\n';self.assertEqual(proc_start(b'123 (name with ) parenthesis) '+suffix),123)

    def case_mount_device_projection(self):
        raw=b''.join((f'{i+1} 0 1:1 / {target} '+('ro,nosuid' if target=='/' else 'rw,nosuid,nodev,noexec')+' - '+('proc' if target=='/proc' else 'tmpfs')+' none rw\n').encode() for i,target in enumerate(sorted(o.TARGETS)))
        params={'root':(1,2),'runtime':(1,2),'proc_device':5,'host_proc_device':6,
                'devices':{k:{'character':True,'major':v[0],'minor':v[1],'mode':0o666} for k,v in o.DEVICES.items()},'forbidden_absent':True}
        self.assertTrue(all(o.filesystem(raw,**params).values()))
        shared=raw.replace(b' - ',b' shared:12 - ',1);self.assertFalse(o.filesystem(shared,**params)['private_propagation'])
        self.assertFalse(o.filesystem(raw.replace(b'ro,nosuid',b'rw,nosuid'),**params)['root_readonly'])
        with self.assertRaises(p.BoundaryError):o.filesystem(raw[:-1],**params)
        with self.assertRaises(p.BoundaryError):o.filesystem(raw*8,**params)
        bad={**params,'devices':{**params['devices'],'sda':{'character':False,'major':8,'minor':0,'mode':0o666}}}
        self.assertFalse(o.filesystem(raw,**bad)['devices_exact'])
        self.assertFalse(o.filesystem(raw,**{**params,'root':(9,9)})['root_matches_runtime'])

    def case_capture_guard_and_fd_cleanup(self):
        with self.assertRaises(p.BoundaryError):OwnedSecurityCapture()
        with self.assertRaises(p.BoundaryError):OwnedSecurityCapture._from_owned_driver(Mock(),{},Mock(),self.expectation())
        observer=object.__new__(OwnedSecurityCapture);observer.closed=False;observer.scope=10;observer.host=11;observer.cleanup_unproven=False;observer.descendant_fds={};observer.private_proc=None;observer.namespace_match=None;observer.worker_ns=None
        observer.driver=Mock(close_errors=set());observer.record={'handle':IDENTITY['handle']}
        with patch('os.close',side_effect=[OSError('private'),None]) as close:
            with self.assertRaises(p.BoundaryError):observer.close()
            self.assertEqual(close.call_count,2)
        self.assertTrue(observer.cleanup_unproven);self.assertIn(IDENTITY['handle'],observer.driver.close_errors)
        observer.close()  # no ambiguous numeric FD retry
        observer.closed=False;observer.expectation=self.expectation()
        with patch('time.monotonic_ns',return_value=s.MAX_CAPTURE_NS+1):
            with self.assertRaises(p.BoundaryError):observer._check()
        with patch.object(observer,'_resources',side_effect=OSError('private')):
            with self.assertRaisesRegex(p.BoundaryError,'BACKEND_FAILURE'):observer.resources()
        self.assertTrue(observer.cleanup_unproven)

    def case_fixed_plans_and_observation_only_fixture(self):
        x=self.expectation()
        for kind in s.PROBE_BOUNDS:
            plan=s.probe_plan(x,kind)
            self.assertEqual(plan['authorization'],'REQUIRED_NOT_GRANTED');self.assertEqual(plan['bounds']['iterations'],s.PROBE_BOUNDS[kind][3])
            self.assertEqual(plan['output_bytes'],2048);self.assertLessEqual(plan['bounds']['wall_ms'],4000)
        for bad in ('shell','--cpu; command','model'):
            with self.assertRaises(p.BoundaryError):s.probe_plan(x,bad)
        with self.assertRaises(p.BoundaryError):s.probe_plan(dataclasses.replace(x,limits=resource_limits('MODEL_WORKER','coder',{})),'cpu')
        with tempfile.TemporaryDirectory() as tmp:
            cc=shutil.which('cc');self.assertIsNotNone(cc)
            executable=Path(tmp)/'probe';source=Path('orchestrator/privilege/fixtures/security_probe.c').resolve()
            subprocess.run([cc,'-O2','-Wall','-Wextra',str(source),'-o',str(executable)],check=True,capture_output=True,timeout=20)
            # NO stress mode is executed: observe only, finite fixed tiny output.
            done=subprocess.run([str(executable),'--observe'],check=True,capture_output=True,timeout=2,env={'PATH':'/usr/bin:/bin'})
            self.assertLess(len(done.stdout),2048);lines=done.stdout.splitlines();self.assertEqual(len(lines),2)
            self.assertEqual(json.loads(lines[1])['event'],'COMPLETED')
            text=source.read_text();self.assertIn('i<16',text);self.assertIn('96*1024*1024',text);self.assertIn('alarm(5)',text);self.assertIn('poll(&ready,1,1000)',text)
        # Old B7 fixed exec bindings are not silently changed to allow stress.
        from orchestrator.privilege.execution import ApprovedExecution
        self.assertIn("'--synthetic'",__import__('inspect').getsource(ApprovedExecution.argv))

    def case_capture_recordings(self):
        observer=object.__new__(OwnedSecurityCapture);observer.expectation=self.expectation();observer._check=Mock()
        observer.scope=12;observer.host=13;observer.closed=False;observer.cleanup_unproven=False
        observer.driver=Mock(close_errors=set());observer.record={'handle':IDENTITY['handle'],'state':'RELEASED','cleanup':'CONFIRMED'}
        observer.driver.children={};observer.driver.absent.return_value=True;observer.driver.launch_settled={IDENTITY['handle']}
        observer.descendant_fds={111:17,112:18};observer.namespace_match=True;observer.private_proc=None
        raw={'cpu.max':b'50000 100000\n','cpu.stat':b'usage_usec 100\nnr_periods 2\nnr_throttled 1\nthrottled_usec 80\n',
             'memory.max':b'67108864\n','memory.swap.max':b'0\n','memory.peak':b'67108864\n',
             'memory.events':b'max 1\noom 1\noom_kill 1\n','pids.max':b'8\n','pids.peak':b'8\n','pids.events':b'max 1\n'}
        observer._read=Mock(side_effect=lambda fd,name:raw[name])
        with patch('time.monotonic_ns',return_value=3_000_000_000):
            values=observer.resources();self.assertEqual(values['enforcement'],'UNPROVEN')
            self.assertEqual(values['data']['memory']['oom_kills'],1)
            self.assertEqual(values['scope'],[4,5]);self.assertEqual(values['subject'],'9'*32)
            with patch('select.select',return_value=([17],[],[])):
                final=observer.containment()['data'];self.assertTrue(final['pidfds_exited']);self.assertTrue(final['cleanup_confirmed'])
                self.assertEqual(final['created'],1)
            observer.namespace_match=None
            with patch('select.select',return_value=([],[],[])):
                final=observer.containment()['data'];self.assertFalse(final['namespace_checked']);self.assertFalse(final['pidfds_exited'])
        # Factory post-dup failure closes only its owned duplicate; no kernel use.
        from orchestrator.privilege.kernel import LinuxDriver, InstallationPermit
        driver=LinuxDriver.__new__(LinuxDriver);driver.permit=InstallationPermit('a'*64,IDENTITY['policy']);driver.qualified=True
        driver.owner=IDENTITY['owner'];driver.boot_id='test';driver.close_errors=set()
        driver.children={IDENTITY['handle']:Mock(fd=20,handle=IDENTITY['handle'])};driver.prove=Mock();driver._scope=Mock(return_value=10)
        record={**IDENTITY,'boot_id':'test','scope_device':4,'scope_inode':5,'state':'RUNNING'}
        entry=Mock(validation=True,executable=Mock(digest=IDENTITY['executable_sha256']))
        with patch('os.dup',return_value=21),patch('os.set_inheritable'),patch('os.open',side_effect=OSError('private')),patch('os.close') as closed:
            with self.assertRaisesRegex(p.BoundaryError,'BACKEND_FAILURE'):OwnedSecurityCapture._from_owned_driver(driver,record,entry,self.expectation())
            closed.assert_called_once_with(21)
        with patch('os.dup',return_value=21),patch('os.set_inheritable'),patch('os.open',side_effect=OSError('private')),patch('os.close',side_effect=OSError('private')):
            with self.assertRaises(p.BoundaryError):OwnedSecurityCapture._from_owned_driver(driver,record,entry,self.expectation())
        self.assertIn(IDENTITY['handle'],driver.close_errors)

    def case_observer_owned_cleanup_integration(self):
        from orchestrator.privilege.kernel import LinuxDriver
        driver=LinuxDriver.__new__(LinuxDriver)
        handle=IDENTITY['handle'];r={**IDENTITY,'state':'RUNNING'}
        driver.owner=IDENTITY['owner'];driver.children={handle:None}
        driver.observers={};driver.close_errors=set();driver.collectors={}
        driver.launch_fds={};driver.launch_settled=set()
        reader=object.__new__(OwnedSecurityCapture)
        reader.driver=driver;reader.record=r;reader.closed=False
        reader.cleanup_unproven=False;reader.scope=10;reader.host=11
        reader.private_proc=12;reader.descendant_fds={123:13}
        driver._register_observer(r,reader)
        driver.children.clear()
        # Absence and release refuse even when no child remains.
        self.assertFalse(driver.absent(r))
        with self.assertRaises(p.BoundaryError):driver.remove(r)
        # A failed observer close cannot skip owned scope or launch-pipe cleanup.
        driver._scope=Mock(return_value=None)
        driver._close_launch_fds=Mock(return_value=True)
        with patch('os.close',side_effect=[OSError('private'),None,None,None]) as closed:
            with self.assertRaisesRegex(p.BoundaryError,'CLEANUP_INCOMPLETE'):driver.terminate(r)
            self.assertEqual(closed.call_count,4)
        driver._scope.assert_called_once_with(r)
        driver._close_launch_fds.assert_called_once_with(handle)
        self.assertIn(handle,driver.observers);self.assertIn(handle,driver.close_errors)
        self.assertFalse(driver.absent(r))
        # Idempotence must not turn an ambiguous close into positive proof.
        with patch('os.close') as closed:
            with self.assertRaises(p.BoundaryError):driver._close_observers(r)
            closed.assert_not_called()
        # Successful cleanup unregisters exactly its reader, never another.
        driver.observers.clear();driver.close_errors.clear();driver.children[handle]=None
        reader.closed=False;driver._register_observer(r,reader)
        with self.assertRaises(p.BoundaryError):driver._register_observer(r,reader)
        with patch('os.close') as closed:
            reader.close();reader.close();self.assertEqual(closed.call_count,4)
        self.assertNotIn(handle,driver.observers)
        with self.assertRaises(p.BoundaryError):driver._forget_observer(r,reader)
        foreign={**r,'owner':'0'*32}
        with self.assertRaises(p.BoundaryError):driver._register_observer(foreign,reader)

    def case_observer_acquisition_registered_before_allocation(self):
        from orchestrator.privilege.kernel import LinuxDriver, InstallationPermit
        driver=LinuxDriver.__new__(LinuxDriver)
        driver.permit=InstallationPermit('a'*64,IDENTITY['policy']);driver.qualified=True
        driver.owner=IDENTITY['owner'];driver.boot_id='test';driver.close_errors=set()
        handle=IDENTITY['handle'];driver.children={handle:Mock(fd=20,handle=handle)}
        driver.prove=Mock();driver._scope=Mock(return_value=10)
        r={**IDENTITY,'boot_id':'test','scope_device':4,'scope_inode':5,'state':'RUNNING'}
        entry=Mock(validation=True,executable=Mock(digest=IDENTITY['executable_sha256']))
        def duplicate(fd):
            self.assertIn(handle,driver.observers)
            return 21
        with patch('os.dup',side_effect=duplicate),patch('os.set_inheritable'),patch('os.open',return_value=22),patch('os.close') as close:
            reader=OwnedSecurityCapture._from_owned_driver(driver,r,entry,self.expectation())
            self.assertIs(driver.observers[handle],reader)
            reader.close();self.assertEqual(close.call_count,2)
            self.assertNotIn(handle,driver.observers)
        with patch('os.dup',side_effect=OSError('private')):
            with self.assertRaises(p.BoundaryError):OwnedSecurityCapture._from_owned_driver(driver,r,entry,self.expectation())
        self.assertNotIn(handle,driver.observers)

    def case_observer_timeout_supervision(self):
        from orchestrator.privilege.kernel import LinuxDriver
        driver=LinuxDriver.__new__(LinuxDriver);handle=IDENTITY['handle']
        driver.collectors={};driver.observers={};driver.close_errors=set()
        reader=Mock(expectation=self.expectation())
        reader.close.side_effect=lambda:driver.observers.pop(handle)
        driver.observers[handle]=reader
        with patch('time.monotonic_ns',return_value=s.MAX_CAPTURE_NS):
            self.assertFalse(driver.collection_failed(handle));reader.close.assert_not_called()
        with patch('time.monotonic_ns',return_value=s.MAX_CAPTURE_NS+1):
            self.assertTrue(driver.collection_failed(handle));reader.close.assert_called_once()
        self.assertIn(handle,driver.close_errors)
        self.assertNotIn(handle,driver.observers)
        # Expiry never changes a production worker lease, and failed closure
        # retains the exact reader rather than pretending it was unallocated.
        driver.close_errors.clear();driver.observers[handle]=reader
        reader.close.side_effect=OSError('private')
        with patch('time.monotonic_ns',return_value=s.MAX_CAPTURE_NS+1):
            self.assertTrue(driver.collection_failed(handle))
        self.assertIs(driver.observers[handle],reader)

    def case_observer_release_serializes_capture(self):
        from orchestrator.privilege.kernel import LinuxDriver
        driver=LinuxDriver.__new__(LinuxDriver);handle=IDENTITY['handle']
        driver.owner=IDENTITY['owner'];driver.children={handle:None}
        driver.observers={};driver.close_errors=set()
        reader=object.__new__(OwnedSecurityCapture)
        reader.driver=driver;reader.record={**IDENTITY,'state':'RUNNING'}
        reader.closed=False;reader.cleanup_unproven=False;reader.scope=10;reader.host=11
        reader.private_proc=None;reader.descendant_fds={};reader._lock=threading.RLock()
        driver._register_observer(reader.record,reader)
        entered=threading.Event();finish=threading.Event();done=threading.Event();errors=[]
        def sampling():
            entered.set()
            if not finish.wait(2):raise AssertionError('recorded sampling stalled')
            self.assertFalse(reader.closed)
            return {'enforcement':'UNPROVEN'}
        def capture():
            try:reader._capture(sampling)
            except Exception as error:errors.append(type(error).__name__)
        def release():
            try:driver._close_observers(reader.record)
            except Exception as error:errors.append(type(error).__name__)
            finally:done.set()
        with patch('os.close') as closed:
            a=threading.Thread(target=capture);b=threading.Thread(target=release)
            a.start();self.assertTrue(entered.wait(2));b.start()
            try:self.assertFalse(done.wait(.02))
            finally:finish.set();a.join(2);b.join(2)
            self.assertFalse(a.is_alive());self.assertFalse(b.is_alive())
            self.assertEqual(closed.call_count,2)
        self.assertFalse(errors);self.assertTrue(done.is_set());self.assertTrue(reader.closed)
        self.assertNotIn(handle,driver.observers)

    def case_full_isolation_capture_recording(self):
        reader=object.__new__(OwnedSecurityCapture);reader.expectation=self.expectation()
        reader.closed=False;reader.cleanup_unproven=False;reader.subject_start=None
        reader.descendant_fds={};reader.private_proc=None;reader.worker_ns=None
        reader.record={**IDENTITY,'scope_device':4,'scope_inode':5}
        reader.driver=Mock(close_errors=set());reader.scope=12;reader.host=13
        reader.entry=Mock(runtime_fd=14,executable=Mock(device=7,inode=8,digest=hashlib.sha256(b'test').hexdigest()))
        reader._check=Mock();reader._deadline=Mock();reader._members=Mock(return_value=[111])
        reader._directory=Mock(side_effect=range(100,200));reader._absent=Mock(return_value=True)
        reader._names=Mock(side_effect=[['0','1','2'],list(o.DEVICES)])
        host=dict(zip(s.NAMESPACES,(1,2,3,4)));worker=dict(zip(s.NAMESPACES,(5,6,7,4)))
        reader._namespace=Mock(side_effect=[host,worker])
        suffix=b'S '+b'0 '*18+b'123\n'
        reader._read=Mock(side_effect=lambda fd,name:b'111 (recorded) '+suffix if name=='stat' else b'recorded\n')
        def info(name,**kw):
            if name in ('0','1'):return SimpleNamespace(st_mode=stat.S_IFIFO,st_rdev=0)
            if name=='2':return SimpleNamespace(st_mode=stat.S_IFCHR,st_rdev=os.makedev(1,3))
            major,minor=o.DEVICES[name]
            return SimpleNamespace(st_mode=stat.S_IFCHR|0o666,st_rdev=os.makedev(major,minor))
        with patch('os.pidfd_open',return_value=50),patch('os.set_inheritable'),patch('select.select',return_value=([],[],[])),\
             patch('os.open',side_effect=[40,41]),patch('os.fstat',return_value=SimpleNamespace(st_dev=7,st_ino=8,st_size=4)),\
             patch('os.pread',return_value=b'test'),patch('os.stat',side_effect=info),patch('os.dup',return_value=60),\
             patch('os.close') as closed,patch.object(o,'status',return_value=(self.data('identity'),self.data('capabilities'),1)),\
             patch.object(o,'filesystem',return_value=self.data('filesystem')),patch('time.monotonic_ns',return_value=1):
            result=reader.isolation()
            self.assertEqual(result['data']['identity'],self.data('identity'))
            self.assertEqual(result['source'],'OWNED_KERNEL_READ');self.assertEqual(result['enforcement'],'UNPROVEN')
            self.assertEqual(reader.subject_start,123);self.assertEqual(reader.private_proc,60)
            # Temporary FDs close at capture completion; retained private-proc
            # descriptor remains owned until explicit reader cleanup.
            self.assertNotIn(60,[call.args[0] for call in closed.call_args_list])
            reader.close()
            self.assertIn(60,[call.args[0] for call in closed.call_args_list])

    def case_total_buffer_bounds_and_import(self):
        x=self.expectation();buffer=s.RecordBuffer(x)
        # Whitespace padding exercises bytes independently of parsed field limits.
        rejected=False
        for kind in s.KINDS:
            raw=json.dumps(s.record(x,kind,'CONFIGURED','DURING',self.data(kind),0)).encode()
            raw+=b' '*(s.MAX_RECORD_BYTES-len(raw))+b'\n'
            try:buffer.add(raw)
            except p.BoundaryError:rejected=True;break
        self.assertTrue(rejected);self.assertTrue(buffer.failed);self.assertFalse(buffer.records)
        for bad in (b'64',b'max\n',b'6\x00\n'):
            with self.assertRaises(p.BoundaryError):o.scalar(bad)
        import importlib
        with patch('os.open',side_effect=AssertionError('import must not read kernel')),patch('os.pidfd_open',side_effect=AssertionError('no kernel')):
            import orchestrator.privilege.security_capture as module
            importlib.reload(module)
        # Only fixed observation mode was executed. Stress modes remain recipes.
        text=Path('orchestrator/privilege/security_capture.py').read_text()
        self.assertNotIn('os.kill',text);self.assertNotIn('shell=True',text)
        self.assertNotIn('os.chroot',text);self.assertNotIn('os.setuid',text)
