"""TI-JOB-2 syscall seams; no child/process/namespace launches."""
from types import SimpleNamespace
import fcntl
import hashlib
import json
import os
import struct
import unittest
from unittest.mock import patch
import test_text_job as fixtures
from orchestrator.privilege import text_handoff as h, protocol as p
from orchestrator.privilege.child import LinuxChildCalls, validate_configuration, ORDER
from orchestrator.privilege.policy import resource_limits, TEXT_LIMITS, text_resource_limits
from orchestrator.privilege.text_job import _frame, MAX_INPUT, MAX_OUTPUT, SEALS, TextJob
from orchestrator.privilege.kernel import LinuxDriver


class TextHandoffTests(unittest.TestCase):
    def fixture(self, role='coder'):return fixtures.TextJobTests().fixture(role)

    def config(self,b,e,plan):
        b.bind_text_job('b'*32,plan)
        job=b.text_jobs['b'*32];job.begin_execution(0)
        return job,h.configuration(e,dict(TEXT_LIMITS),
                                   list(range(60000,60006)),job)

    def frame(self,owned_job,payload=b'{}',**changes):
        header={'binding':hashlib.sha256(owned_job.binding).hexdigest(),'job':owned_job.job_id,
                'request':p.decode(owned_job.binding)['request'],'status':'COMPLETE',
                'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
        header.update(changes)
        if type(header['bytes']) is float:
            # Untrusted wire bytes; protocol encoder correctly forbids floats.
            raw=json.dumps(header).encode()
            return struct.pack('!I',len(raw))+raw+payload
        return _frame(header,payload)

    def test_rights_schema_and_profile_bounds(self):
        import website
        from orchestrator.roles.worker import TEXT_INFERENCE_BOUNDS
        self.assertEqual(MAX_INPUT,website.MAX_REQUEST_BYTES)
        self.assertEqual(MAX_OUTPUT,website.MAX_RESPONSE_BYTES)
        self.assertEqual(MAX_OUTPUT,TEXT_INFERENCE_BOUNDS['response_bytes'])
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan)
            self.assertEqual(c['version'],2);self.assertEqual(len(c['fds']),8)
            h.verify_descriptors(c)
            for fd,mode in ((job.input_fd,os.O_RDONLY),(job.response_write_fd,os.O_WRONLY),
                            (job.response_read_fd,os.O_RDONLY)):
                self.assertEqual(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE,mode)
            self.assertNotIn(job.output_fd,c['fds'])
            with self.assertRaises(OSError):os.write(job.input_fd,b'x')
            with self.assertRaises(OSError):os.read(job.response_write_fd,1)
            plain=h.configuration(e,c['limits'],list(range(3,9)))
            self.assertEqual(plain['version'],1);self.assertNotIn('text',plain)
            self.assertEqual(len(plain['fds']),6)
            for bad in (dict(c,validation=True),dict(c,text={}),dict(c,version=1),
                        dict(c,fds=c['fds'][:-1]),dict(c,fds=[c['fds'][0]]*8)):
                with self.assertRaises(p.BoundaryError):validate_configuration(bad)

    def test_substitution_modes_and_stale_fd_reject(self):
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan)
            for fd in (job.output_fd,job.response_read_fd,job.input_fd):
                bad=dict(c,fds=c['fds'][:7]+[fd])
                with self.assertRaises(p.BoundaryError):h.verify_descriptors(bad)
            bad=dict(c,text=dict(c['text'],input_identity=[0,0]))
            with self.assertRaises(p.BoundaryError):h.verify_descriptors(bad)
            job.close_response_writer()
            with self.assertRaises(p.BoundaryError):h.verify_descriptors(c)

    def test_complete_descriptor_roles_and_inode_aliases(self):
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan)
            # Only test-owned directories/pipes, no filesystem or child setup.
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                os.mkdir(tmp+'/workspace');os.mkdir(tmp+'/root')
                a=os.open(tmp+'/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
                z=os.open(tmp+'/root',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
                br,bw=os.pipe2(os.O_CLOEXEC);rr,rw=os.pipe2(os.O_CLOEXEC)
                alias=os.dup(job.input_fd)
                try:
                    c['fds']=[a,z,e.runtime_fd,e.executable.fd,br,rw,job.input_fd,job.response_write_fd]
                    h.verify_descriptors(c,complete=True)
                    bad=dict(c,fds=[a,z,e.runtime_fd,alias,br,rw,job.input_fd,job.response_write_fd])
                    with self.assertRaises(p.BoundaryError):h.verify_descriptors(bad,complete=True)
                    bad=dict(c,fds=[a,z,e.runtime_fd,e.executable.fd,bw,rw,job.input_fd,job.response_write_fd])
                    with self.assertRaises(p.BoundaryError):h.verify_descriptors(bad,complete=True)
                finally:
                    for fd in (a,z,br,bw,rr,rw,alias):os.close(fd)

    def test_collision_safe_mapping_and_exec_use_production_operations(self):
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan)
            events=[]
            def dup(fd,op,minimum):
                self.assertEqual(op,fcntl.F_DUPFD_CLOEXEC)
                events.append(('duplicate',fd));return 10+len(events)-1
            # Fake syscalls only; actual production mapping decides ordering.
            with patch.object(h,'verify_descriptors'),patch.object(h.fcntl,'fcntl',side_effect=dup), \
                 patch.object(h.os,'dup2',side_effect=lambda a,z,**kw:events.append(('map',a,z,kw))), \
                 patch.object(h.os,'listdir',return_value=['0','1','2','3','4','10','11','50']), \
                 patch.object(h.os,'close',side_effect=lambda fd:events.append(('close',fd))):
                self.assertEqual(h.map_descriptors(c),(10,11))
            self.assertTrue(all(x[0]=='duplicate' for x in events[:4]))
            self.assertIn(('map',12,3,{'inheritable':True}),events)
            self.assertIn(('map',13,4,{'inheritable':True}),events)
            self.assertIn(('close',50),events)
            calls=LinuxChildCalls.__new__(LinuxChildCalls)
            calls.position=ORDER.index('EXEC');calls.setup=SimpleNamespace(stage='DROPPED')
            calls.text_exec_fds=(10,11)
            with patch('os.pread',return_value=b'\x7fELF'),patch('os.write') as write,patch('os.execve') as execute:
                calls.perform('EXEC',c)
            argv,env=h.exec_contract(c)
            execute.assert_called_once_with(10,argv,env)
            write.assert_called_once_with(11,b'EXEC_READY\n')
            self.assertEqual(argv,['freeagentos-worker','--broker-job',job.job_id])
            self.assertNotIn(plan.request.decode(),argv)
            self.assertEqual(set(env),{'PATH','HOME','TMPDIR','LANG','LC_ALL'})

    def test_actual_child_checks_before_barrier_or_setup(self):
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan)
            c['fds'][7]=job.output_fd
            calls=LinuxChildCalls.__new__(LinuxChildCalls);calls.position=0
            with patch('os.read') as read, self.assertRaises(p.BoundaryError):
                calls.perform('CGROUP_BARRIER',c)
            read.assert_not_called()

    def test_response_requires_process_eof_identity_and_exact_counts(self):
        for kind in ('nonzero','unreaped','bool-exit','missing-eof','empty','bool-count','float-count','cross-job','error','oversize','valid'):
            with self.subTest(kind=kind),self.fixture() as (b,d,e,plan,s):
                job,c=self.config(b,e,plan);job.deliver(job.configuration())
                raw=self.frame(job);exit_code=0;eof=True
                if kind=='nonzero':exit_code=1
                if kind=='unreaped':exit_code=None
                if kind=='bool-exit':exit_code=False
                if kind=='missing-eof':eof=False
                if kind=='empty':raw=self.frame(job,b'')
                if kind=='bool-count':raw=self.frame(job,b'x',bytes=True)
                if kind=='float-count':raw=self.frame(job,b'x',bytes=1.0)
                if kind=='cross-job':raw=self.frame(job,job='f'*32)
                if kind=='error':raw=self.frame(job,status='ERROR')
                if kind=='oversize':raw=b'x'*(h.MAX_FRAME+1)
                if kind=='valid':
                    job.accept_response(raw,exit_code=exit_code,eof=eof,observed_ns=0)
                    self.assertEqual(job.collect().payload,b'{}')
                else:
                    with self.assertRaises(p.BoundaryError):job.accept_response(raw,exit_code=exit_code,eof=eof,observed_ns=0)
                    self.assertFalse(job.completed)

    def test_collector_actual_loop_and_owned_close(self):
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan);job.deliver(job.configuration())
            collector=h.TextCollector(job,SimpleNamespace(poll=lambda:0),clock=lambda:0)
            original=job.response_read_fd
            with patch.object(h.os,'read',side_effect=[self.frame(job),b'']), \
                 patch.object(h.select,'select',return_value=([original],[],[])):
                collector._run()
            self.assertIsNone(collector.error)
            self.assertIsNone(job.response_read_fd)
            self.assertEqual(job.collect().payload,b'{}')
            with self.assertRaises(OSError):os.fstat(original)

    def test_collector_overflow_cancel_and_incomplete(self):
        for kind in ('overflow','cancel','incomplete'):
            with self.subTest(kind=kind),self.fixture() as (b,d,e,plan,s):
                job,c=self.config(b,e,plan);job.deliver(job.configuration())
                collector=h.TextCollector(job,SimpleNamespace(poll=lambda:0),clock=lambda:0)
                if kind=='cancel':collector.stop.set()
                blocks=[b'x'*4096]*18 if kind=='overflow' else [b'bad',b'']
                with patch.object(h.os,'read',side_effect=blocks), \
                     patch.object(h.select,'select',return_value=([job.response_read_fd],[],[])):
                    collector._run()
                self.assertIsNotNone(collector.error);self.assertFalse(job.completed)
                self.assertIsNone(job.response_read_fd)

    def test_real_launch_rejects_before_any_syscall(self):
        driver=LinuxDriver.__new__(LinuxDriver)
        with patch('subprocess.Popen') as launch:
            with self.assertRaises(p.BoundaryError):driver.launch({},None,{},text_job=object())
            with self.assertRaises(p.BoundaryError):driver.launch_text_recording({},None,{},object())
        launch.assert_not_called()

    def test_record_owner_and_runtime_errors_are_fixed(self):
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan)
            for record in ({},None,{'handle':[],'owner':False}):
                with self.assertRaises(p.BoundaryError):job.verify_owner(record,e)
            with patch('os.fstat',side_effect=OSError('must not leak')):
                with self.assertRaises(p.BoundaryError) as exc:job.verify_owner(b.records['b'*32],e)
            self.assertEqual(str(exc.exception),'POLICY_REJECTED')

    def test_complete_policy_required_before_text_allocation(self):
        with self.fixture() as (b,d,e,plan,s):
            defaults=resource_limits(e.execution,e.role,{})
            invalid=[defaults,{},dict(TEXT_LIMITS,extra=1)]
            for key,value in TEXT_LIMITS.items():
                invalid.extend([dict(TEXT_LIMITS,**{key:value+1}),
                                {k:v for k,v in TEXT_LIMITS.items() if k!=key}])
            invalid.append(dict(TEXT_LIMITS,wall_timeout_seconds=True))
            for limits in invalid:
                with self.subTest(keys=sorted(limits)),patch('os.memfd_create') as allocate,patch('os.pipe2') as pipe:
                    with self.assertRaises(p.BoundaryError) as err:TextJob(plan,b.records['b'*32],e,limits)
                    self.assertEqual(err.exception.code,'RESOURCE_LIMIT_INVALID')
                    allocate.assert_not_called();pipe.assert_not_called()
            b.bindings['b'*32]=(e,defaults)
            with patch('os.memfd_create') as allocate,self.assertRaises(p.BoundaryError):b.bind_text_job('b'*32,plan)
            allocate.assert_not_called();self.assertEqual(b.text_jobs,{})

    def test_direct_v2_limits_and_deadline_cannot_bypass_binding(self):
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan)
            self.assertEqual(c['limits'],dict(TEXT_LIMITS))
            self.assertEqual(c['text']['deadline_ns'],60000000000)
            self.assertEqual(p.decode(job.binding)['effective_limits'],c['limits'])
            for limits in (resource_limits(e.execution,e.role,{}),{},dict(TEXT_LIMITS,max_output_bytes=1),
                           dict(TEXT_LIMITS,memory_limit_bytes=1),dict(TEXT_LIMITS,wall_timeout_seconds=59)):
                with self.subTest(limits=limits):
                    with self.assertRaises(p.BoundaryError):h.configuration(e,limits,list(range(60000,60006)),job)
                    with self.assertRaises(p.BoundaryError):validate_configuration(dict(c,limits=limits))
            for changed in (dict(c['text'],deadline_ns=180000000000),dict(c['text'],started_ns=True)):
                with self.assertRaises(p.BoundaryError):validate_configuration(dict(c,text=changed))
            with self.assertRaises(p.BoundaryError):
                d.launch_text_recording(b.records['b'*32],e,resource_limits(e.execution,e.role,{}),job)
            self.assertFalse(job.delivered)
            self.assertNotIn(('b'*32,'TEXT_INPUT_DELIVERY'),d.events)
            with self.assertRaises(p.BoundaryError):job.begin_execution(1)

    def test_actual_text_backend_lease_ends_at_sixty_without_grace(self):
        for role in ('coder','fixer'):
            with self.subTest(role=role),self.fixture(role) as (b,d,e,plan,s):
                b.bind_text_job('b'*32,plan);d.text_response_fixture=b'{}'
                with patch.object(b,'_start_monitor'):b.start('b'*32)
                job=b.text_jobs['b'*32];lease=b.leases['b'*32]
                self.assertEqual(lease.started_ns,job.started_ns)
                self.assertEqual(lease.deadline_ns,job.deadline_ns)
                self.assertEqual(lease.base_ns,60000000000);self.assertFalse(lease.enabled)
                b.clock=lambda:59000000000;b.enforce()
                self.assertTrue(d.running(b.records['b'*32],b.processes['b'*32]))
                b.clock=lambda:60000000000;b.enforce()
                self.assertEqual(b.records['b'*32]['state'],'TERMINATED')
                self.assertFalse(lease.granted)

    def test_collector_uses_execution_window_and_eof_exit_order(self):
        for mode in ('eleven-seconds','deadline','retained-writer','exit-missing','nonzero','poll-crosses-deadline'):
            with self.subTest(mode=mode),self.fixture() as (b,d,e,plan,s):
                job,c=self.config(b,e,plan);job.deliver(job.configuration())
                clock=SimpleNamespace(now=0);events=[];polls=[0]
                def poll():
                    events.append('poll');polls[0]+=1
                    if mode=='poll-crosses-deadline' and polls[0]==3:clock.now=60000000001
                    return None if mode=='exit-missing' else 1 if mode=='nonzero' else 0
                collector=h.TextCollector(job,SimpleNamespace(poll=poll),clock=lambda:clock.now)
                blocks=iter([self.frame(job),b''])
                def ready(*args):
                    if mode=='retained-writer' and 'read' in events:
                        clock.now=60000000000;return ([],[],[])
                    return ([job.response_read_fd],[],[])
                def read(fd,n):
                    events.append('read');clock.now=60000000001 if mode=='deadline' else 11000000000
                    return next(blocks)
                def wait(seconds):clock.now=60000000000
                with patch.object(h.os,'read',side_effect=read),patch.object(h.select,'select',side_effect=ready), \
                     patch.object(collector.stop,'wait',side_effect=wait):collector._run()
                self.assertIsNone(job.response_read_fd)
                if mode=='eleven-seconds':
                    self.assertIsNone(collector.error);self.assertEqual(job.collect().payload,b'{}')
                    self.assertEqual(job.response_observed_ns,11000000000)
                    self.assertEqual(events,['poll','read','poll','read','poll'])
                else:
                    self.assertIn(collector.error,('BACKEND_FAILURE','INVALID_STATE'))
                    self.assertFalse(job.completed)

    def test_cleanup_join_is_separate_and_preserves_uncertainty(self):
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan)
            collector=h.TextCollector(job,SimpleNamespace(poll=lambda:None),clock=lambda:0)
            thread=SimpleNamespace(join=lambda seconds:self.assertEqual(seconds,h.CLEANUP_SECONDS),is_alive=lambda:True)
            collector.thread=thread
            with self.assertRaises(p.BoundaryError) as err:collector.close()
            self.assertEqual(err.exception.code,'CLEANUP_INCOMPLETE');self.assertTrue(collector.close_failed)
            self.assertIsNotNone(job.response_read_fd)  # retain ownership if thread not joined
            self.assertFalse(job.completed)

    def test_malformed_top_level_headers_have_fixed_errors(self):
        for header in (0,[],"text",None,True):
            for path in ('accept','collect'):
                with self.subTest(header=type(header).__name__,path=path),self.fixture() as (b,d,e,plan,s):
                    job,c=self.config(b,e,plan);job.deliver(job.configuration())
                    raw=json.dumps(header).encode();frame=struct.pack('!I',len(raw))+raw+b'{}'
                    if path=='collect':
                        os.pwrite(job.output_fd,frame,0);fcntl.fcntl(job.output_fd,fcntl.F_ADD_SEALS,SEALS)
                        job.completed=True;job.response_observed_ns=0
                    with self.assertRaises(p.BoundaryError) as err:
                        if path=='accept':job.accept_response(frame,exit_code=0,eof=True,observed_ns=0)
                        else:job.collect()
                    self.assertEqual(err.exception.code,'POLICY_REJECTED')

    def test_deadline_cannot_be_extended_by_completion_or_cleanup(self):
        for observed in (-1,60000000000,61000000000,None,True):
            with self.subTest(observed=observed),self.fixture() as (b,d,e,plan,s):
                job,c=self.config(b,e,plan);job.deliver(job.configuration())
                with self.assertRaises(p.BoundaryError):job.accept_response(self.frame(job),exit_code=0,eof=True,observed_ns=observed)
                self.assertFalse(job.completed)
        with self.fixture() as (b,d,e,plan,s):
            job,c=self.config(b,e,plan);job.deliver(job.configuration())
            b.clock=lambda:60000000000
            with self.assertRaises(p.BoundaryError):job.finish_recording(b'{}')
            self.assertFalse(job.completed)
