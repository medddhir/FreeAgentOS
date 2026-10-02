"""B1/B4 fault injection; all Linux mutations and child creation are mocked."""
import contextlib
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from orchestrator.privilege import protocol as p
from orchestrator.privilege.kernel import LinuxDriver
from test_privilege import PrivilegeCases
from test_privilege_complete import LinuxCompleteCases

H='b'*32

class CleanupProofCases(unittest.TestCase):
    def cases(self):
        # Match the existing bounded runner's compact contract-table pattern.
        for name in sorted(n for n in dir(self) if n.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()

    def case_creating_is_not_absence_proof(self):
        cases=PrivilegeCases()
        with cases.fixture() as (_,e,roots,journal,backend,engine):
            h=cases.create(engine);r=engine.records[h];r['state']='CREATING'
            backend.resources.pop(h)  # lost allocation ledger, not never-created
            with self.assertRaisesRegex(p.BoundaryError,'CLEANUP_INCOMPLETE'):engine._release(r)
            self.assertEqual(r['state'],'FAILED_DIRTY');self.assertTrue(engine.recovery_required)
            self.assertEqual(engine._snapshot(r)['cleanup'],'UNPROVEN')
            with self.assertRaisesRegex(p.BoundaryError,'RECOVERY_REQUIRED'):cases.create(engine)

    def case_proven_never_allocated_and_idempotence(self):
        cases=PrivilegeCases()
        with cases.fixture() as (_,e,roots,journal,backend,engine):
            with patch.object(journal,'save',side_effect=OSError('private')):
                with self.assertRaises(p.BoundaryError):cases.create(engine)
            r=next(iter(engine.records.values()))
            self.assertEqual(backend.cleanup_proof(r['handle'],r['owner']),'NEVER_ALLOCATED')
            engine.recover();events=list(backend.events);engine._release(r)
            self.assertEqual(events,list(backend.events));self.assertEqual(r['state'],'RELEASED')
            self.assertEqual(engine._snapshot(r)['cleanup'],'SIMULATED')
            self.assertEqual(backend.cleanup_proof(r['handle'],'f'*32),'UNPROVEN')

    def case_partial_allocation_cleanup_and_dirty_fencing(self):
        cases=PrivilegeCases()
        with cases.fixture() as (_,e,roots,journal,backend,engine):
            backend.fail_at='mount_recipe'
            with self.assertRaises(p.BoundaryError):cases.create(engine)
            r=next(iter(engine.records.values()));h=r['handle']
            backend.fail_at='cgroup_remove'
            with self.assertRaises(p.BoundaryError):engine._release(r)
            self.assertTrue(engine.recovery_required);self.assertEqual(journal.load()[0]['state'],'FAILED_DIRTY')
            backend.fail_at=None;engine.recover()
            self.assertEqual(backend.cleanup_proof(h,backend.owner),'OWNED_CLEANED')

    def case_linux_recovery_requires_absence_after_cleanup(self):
        cases=LinuxCompleteCases()
        with cases.fixture() as (b,d,j,*_):
            d.fail='SNAPSHOT_FD_SEAL'
            with self.assertRaises(p.BoundaryError):cases.create(b)
            d.fail=None
            with patch.object(d,'absent',return_value=False):
                with self.assertRaises(p.BoundaryError):b.recover()
            self.assertTrue(b.recovery_required);self.assertEqual(j.load()[0]['cleanup'],'UNPROVEN')
            b.recover();self.assertTrue(b.cleaned(H,b.owner))

    def case_linux_never_allocated_recovery(self):
        cases=LinuxCompleteCases()
        with cases.fixture() as (b,d,j,*_):
            d.fail='QUALIFY_READONLY'
            with self.assertRaises(p.BoundaryError):cases.create(b)
            d.fail=None;b.recover()
            self.assertEqual(b.cleanup_proof(H,b.owner),'NEVER_ALLOCATED')
            self.assertEqual(j.load()[0]['cleanup'],'NEVER_ALLOCATED')

    def case_contradictory_resource_journal_is_not_cleanup_proof(self):
        cases=LinuxCompleteCases()
        with cases.fixture() as (b,d,j,*_):
            cases.create(b);record=j.load()[0]
            for cleanup in ('PENDING','NEVER_ALLOCATED'):
                with self.assertRaisesRegex(p.BoundaryError,'JOURNAL_INVALID'):
                    j.save([{**record,'state':'RELEASED','cleanup':cleanup}])

    def case_launch_return_then_journal_failure_contains_worker(self):
        cases=LinuxCompleteCases()
        with cases.fixture() as (b,d,j,*_):
            cases.create(b);save=j.save
            def fail_running(records):
                if records[0]['state']=='RUNNING':raise OSError('private')
                save(records)
            with patch.object(j,'save',side_effect=fail_running):
                with self.assertRaisesRegex(p.BoundaryError,'BACKEND_FAILURE'):b.start(H)
            self.assertFalse(b.processes[H].active)
            self.assertEqual(j.load()[0]['state'],'FAILED_DIRTY')
            self.assertEqual(j.load()[0]['cleanup'],'UNPROVEN');self.assertTrue(b.recovery_required)
            b.recover();self.assertTrue(b.cleaned(H,b.owner))

    def case_backend_start_failure_contains_worker_and_fences_controller(self):
        cases=PrivilegeCases()
        with cases.fixture() as (_,e,roots,journal,backend,engine):
            h=cases.create(engine);backend.fail_at='start'
            with self.assertRaises(p.BoundaryError):cases.operation(engine,'START',h)
            self.assertFalse(backend.running(h));self.assertTrue(engine.recovery_required)
            self.assertEqual(journal.load()[0]['state'],'FAILED_DIRTY')
            with self.assertRaisesRegex(p.BoundaryError,'RECOVERY_REQUIRED'):cases.create(engine)
            backend.fail_at=None;engine.recover()

    def case_controller_journal_failure_contains_worker(self):
        cases=PrivilegeCases()
        with cases.fixture() as (_,e,roots,journal,backend,engine):
            h=cases.create(engine);save=journal.save
            def fail_running(records):
                if records[0]['state']=='RUNNING':raise OSError('private')
                save(records)
            with patch.object(journal,'save',side_effect=fail_running):
                with self.assertRaises(p.BoundaryError):cases.operation(engine,'START',h)
            self.assertFalse(backend.running(h));self.assertTrue(engine.recovery_required)
            self.assertEqual(journal.load()[0]['state'],'FAILED_DIRTY')

class LauncherContainmentCases(unittest.TestCase):
    def cases(self):
        for name in sorted(n for n in dir(self) if n.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()

    @contextlib.contextmanager
    def fixture(self):
        d=LinuxDriver.__new__(LinuxDriver)
        d.owner='a'*32;d.qualified=True;d.sealed={H};d.roots={H:10};d.scopes={H:30}
        d.children={};d.launch_fds={};d.close_errors=set();d.launch_settled=set();d.collectors={};d.proofs={};d.proof_bindings={};d.launcher=Mock(fd=40);d._write=Mock();d._scope=Mock(return_value=30)
        entry=SimpleNamespace(verify=Mock(),runtime_fd=20,executable=SimpleNamespace(fd=21,digest='f'*64),execution='MODEL_WORKER',role='coder',uid=1234,gid=1234,job_id='e'*32,validation=True)
        child=Mock(pid=321);child.poll.return_value=None;child.wait.return_value=0
        r={'handle':H,'owner':d.owner,'run_id':'c'*32,'policy':'d'*64,'class':'MODEL_WORKER','role':'coder'}
        with contextlib.ExitStack() as stack:
            mocks={}
            for target,kwargs in [
                ('orchestrator.privilege.kernel.SyntheticCollector',{'return_value':Mock(close_failed=False)}),
                ('orchestrator.privilege.kernel.secure_open',{'return_value':11}),
                ('orchestrator.privilege.kernel.read_at',{'return_value':'populated 0'}),
                ('subprocess.Popen',{'return_value':child}),('os.dup',{'return_value':12}),
                ('os.pipe2',{'side_effect':[(13,14),(15,16)]}),('os.pidfd_open',{'return_value':99}),
                ('os.set_inheritable',{}),('signal.pidfd_send_signal',{}),('os.close',{}),('os.write',{'return_value':1}),
                ('os.read',{'return_value':b'EXEC_READY\n'}),('select.select',{'return_value':([15],[],[])})]:
                mocks[target]=stack.enter_context(patch(target,**kwargs))
            mocks['orchestrator.privilege.kernel.SyntheticCollector'].return_value.close.side_effect=lambda:os.close(15)
            yield d,r,entry,child,mocks

    def case_failure_boundaries(self):
        for boundary in ('spawn','pidfd','inherit','attach','config','receipt','close'):
            with self.subTest(boundary=boundary),self.fixture() as (d,r,e,c,m):
                if boundary=='spawn':m['subprocess.Popen'].side_effect=OSError('private')
                elif boundary=='pidfd':m['os.pidfd_open'].side_effect=OSError('private')
                elif boundary=='inherit':m['os.set_inheritable'].side_effect=OSError('private')
                elif boundary=='attach':
                    d._write.side_effect=lambda fd,name,value: (_ for _ in ()).throw(OSError('private')) if name=='cgroup.procs' else None
                elif boundary=='config':c.stdin.write.side_effect=OSError('private')
                elif boundary=='receipt':m['os.read'].return_value=b'FAIL'
                else:m['os.close'].side_effect=lambda fd: (_ for _ in ()).throw(OSError('private')) if fd==11 else None
                with self.assertRaisesRegex(p.BoundaryError,'BACKEND_FAILURE'):d.launch(r,e,{})
                if boundary!='spawn':
                    if boundary=='pidfd':c.kill.assert_called_once()
                    else:m['signal.pidfd_send_signal'].assert_called_once()
                    c.wait.assert_called_once();c.stdout.close.assert_called();c.stdin.close.assert_called()
                self.assertNotIn(H,d.children)
                closed=[call.args[0] for call in m['os.close'].call_args_list]
                self.assertTrue({12,13,14,15,16}<=set(closed))
                if boundary=='close':self.assertIn(H,d.close_errors);self.assertFalse(d.absent(r))
                else:self.assertNotIn(H,d.launch_fds)

    def case_wait_failure_does_not_skip_cleanup_or_forget_child(self):
        with self.fixture() as (d,r,e,c,m):
            m['os.pidfd_open'].side_effect=OSError('private');c.wait.side_effect=OSError('private')
            with self.assertRaises(p.BoundaryError):d.launch(r,e,{})
            self.assertIn(H,d.children);c.stdin.close.assert_called();c.stdout.close.assert_called()
            self.assertFalse(d.absent(r))
            with self.assertRaises(p.BoundaryError):d.remove(r)
            c.wait.side_effect=None;c.poll.return_value=0;d.terminate(r)
            self.assertNotIn(H,d.children)

    def case_scope_failure_and_pipe_failure_do_not_skip_pidfd_close(self):
        with self.fixture() as (d,r,e,c,m):
            d.launch(r,e,{})
            d._write.side_effect=OSError('private');c.wait.side_effect=OSError('private')
            c.stdin.close.side_effect=OSError('private')
            with self.assertRaisesRegex(p.BoundaryError,'CLEANUP_INCOMPLETE'):d.terminate(r)
            self.assertIn(H,d.children);c.stdout.close.assert_called()
            self.assertIn(99,[call.args[0] for call in m['os.close'].call_args_list])
            self.assertIsNone(d.children[H].fd)

    def case_child_exit_before_pidfd_is_reaped_and_not_signalled(self):
        with self.fixture() as (d,r,e,c,m):
            c.poll.return_value=0
            with self.assertRaises(p.BoundaryError):d.launch(r,e,{})
            m['os.pidfd_open'].assert_not_called();c.kill.assert_not_called()
            m['signal.pidfd_send_signal'].assert_not_called();c.wait.assert_called_once()
            self.assertNotIn(H,d.children);self.assertNotIn(H,d.launch_fds)

    def case_restart_cannot_disprove_unattached_orphan_from_empty_scope(self):
        with self.fixture() as (d,r,e,c,m):
            r.update(started_ns=1,state='FAILED_DIRTY')
            with self.assertRaisesRegex(p.BoundaryError,'CLEANUP_INCOMPLETE'):d.prove(r)
            d._scope.assert_not_called()

    def case_registration_failure_precedes_process_creation(self):
        class RejectRegistration(dict):
            def __setitem__(self,key,value):raise OSError('private')
        with self.fixture() as (d,r,e,c,m):
            d.children=RejectRegistration()
            with self.assertRaises(p.BoundaryError):d.launch(r,e,{})
            m['subprocess.Popen'].assert_not_called()
            self.assertNotIn(H,d.launch_fds)

    def case_pidfd_close_failure_retained_for_recovery(self):
        with self.fixture() as (d,r,e,c,m):
            d.launch(r,e,{})
            m['os.close'].side_effect=lambda fd: (_ for _ in ()).throw(OSError('private')) if fd==99 else None
            with self.assertRaises(p.BoundaryError):d.terminate(r)
            self.assertIn(H,d.children);self.assertIsNone(d.children[H].fd);self.assertTrue(d.children[H].close_failed)
            c.stdout.close.assert_called();c.stdin.close.assert_called()
            m['os.close'].side_effect=None;c.poll.return_value=0
            with self.assertRaises(p.BoundaryError):d.terminate(r)
            self.assertIn(H,d.children)
            self.assertEqual(sum(call.args[0]==99 for call in m['os.close'].call_args_list),1)

    def case_partial_fd_preparation_failure(self):
        with self.fixture() as (d,r,e,c,m):
            m['os.pipe2'].side_effect=OSError('private')
            with self.assertRaises(p.BoundaryError):d.launch(r,e,{})
            m['subprocess.Popen'].assert_not_called()
            self.assertEqual([call.args[0] for call in m['os.close'].call_args_list],[11,12])

    def case_success_and_ownership_mismatch(self):
        with self.fixture() as (d,r,e,c,m):
            process=d.launch(r,e,{})
            self.assertIs(d.children[H],process);self.assertNotIn(H,d.launch_fds)
            with self.assertRaisesRegex(p.BoundaryError,'UNKNOWN_HANDLE'):d.terminate(r,Mock())
            c.kill.assert_not_called();d.terminate(r,process);self.assertNotIn(H,d.children)
