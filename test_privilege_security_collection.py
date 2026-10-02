"""Authenticated B8 IPC and owned async recordings; no privileged/stress activation."""
import contextlib
import dataclasses
import json
import os
import threading
import time
import unittest
from unittest.mock import Mock, patch
from orchestrator.privilege import protocol as p, security_collection as c, security_proof as s
from orchestrator.privilege.client import ControllerClient, Sandbox
from orchestrator.privilege.evidence import binding
from orchestrator.privilege.isolation import LinuxBackend
from test_privilege_probe import ProbeContractCases
from test_privilege_security_proof import SecurityProofCases


class SecurityCollectionCases(unittest.TestCase):
    def cases(self):
        for name in sorted(n for n in dir(self) if n.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()

    def rejected(self,call,code=None):
        with self.assertRaises(p.BoundaryError) as caught:call()
        if code:self.assertEqual(caught.exception.code,code)

    @contextlib.contextmanager
    def endpoint(self):
        fixture=ProbeContractCases()
        with fixture.endpoint(True) as (server,enrollment,engine,b),fixture.linux_client_profile():
            b.clock=time.monotonic_ns;engine.security_pages.clock=b.clock
            client=ControllerClient(server.path,enrollment,0,os.getgid(),linux_validation=True)
            try:
                engine.roots.register('validation',server.path.parent/'work',os.getuid())
                h=client.create_sandbox('validation','MODEL_WORKER','coder');client.start_sandbox(h)
                r=b.records[h.handle];entry,limits=b.bindings[h.handle]
                x=s.ProofExpectation(binding(r,entry),entry.uid,entry.gid,limits,'f'*32,b.clock(),'9'*32,(r['scope_device'],r['scope_inode']))
                yield client,h,x,b,engine,server,enrollment
            finally:
                client.close()
                # Do not hide intentionally dirty ownership test failures in the
                # fixture finalizer; those tests settle synthetic threads first.

    def summary(self,x,kind,at=None):
        fixture=SecurityProofCases()
        if kind=='ISOLATION':
            data={k:fixture.data(k) for k in s.KINDS[:5]}
            data['identity']={'uids':[x.uid]*4,'gids':[x.gid]*4,'groups':[]}
        elif kind=='RESOURCES':
            data={k:{name:fixture.data(k)[name] for name in names} for k,names in c.RESOURCE_FIELDS.items()}
        else:data=fixture.data('descendants')
        return {'schema_version':1,'binding':dict(x.binding),'sample':x.sample,'subject':x.subject,'scope':list(x.scope),
                'source':'INDEPENDENT_RECORDING','at_ns':x.started_ns if at is None else at,'enforcement':'UNPROVEN','data':data}

    def report(self,x,large=False):
        values=[]
        if large:
            fixture=SecurityProofCases()
            for phase in ('BEFORE','DURING','AFTER'):
                for kind in s.KINDS[:8]:
                    data=fixture.data(kind,phase)
                    if kind=='fds':data={'open':list(range(256)),'unexpected':list(range(3,256)),'standard_safe':False}
                    values.append({'kind':'PROOF_RECORD','value':s.record(x,kind,'CONFIGURED',phase,data,x.started_ns)})
        return {'schema_version':1,'binding':dict(x.binding),'sample':x.sample,'subject':x.subject,'scope':list(x.scope),
                'started_ns':x.started_ns,'status':'INCOMPLETE','reason':'INVALID_STATE','observations':values,
                'collector_closed':True,'enforcement':'UNPROVEN'}

    def reader(self,x):
        reader=Mock()
        reader.isolation.return_value=self.summary(x,'ISOLATION')
        reader.resources.return_value=self.summary(x,'RESOURCES')
        reader.containment.return_value=self.summary(x,'CONTAINMENT')
        return reader

    def wait(self,task):self.assertTrue(task.done.wait(2));task.thread.join(2);self.assertFalse(task.thread.is_alive())

    def case_authenticated_multiframe(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            report=self.report(x,True);self.assertGreater(len(c.canonical(report)),p.MAX_FRAME)
            b.security_reports[h.handle]=(x,report)
            before=list(b.driver.events);seq=client.seq
            result=client.collect_security(h,x)
            self.assertEqual(result,report);self.assertEqual(result['enforcement'],'UNPROVEN')
            self.assertLessEqual(client.seq-seq,1+c.MAX_PAGES);self.assertFalse(engine.security_pages.views)
            self.assertEqual(list(b.driver.events),before)  # retrieval never activates backend
            client.release(h)

    def case_owned_async_path(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            reader=self.reader(x)
            def factory(r,entry,expectation):
                self.assertIn(h.handle,b.security_tasks)
                self.assertEqual(b.journal.load()[0]['collection'],'PENDING')
                self.assertEqual(expectation,x);return reader
            with patch.object(b.driver,'security_reader',side_effect=factory):b.begin_security_capture(h.handle,x)
            task=b.security_tasks[h.handle];self.wait(task)
            result=client.collect_security(h,x)
            self.assertEqual(result['status'],'CAPTURED');self.assertEqual(result['enforcement'],'UNPROVEN')
            self.assertEqual([i['value']['source'] for i in result['observations']],['INDEPENDENT_RECORDING']*3)
            self.rejected(lambda:b.begin_security_capture(h.handle,x),'POLICY_REJECTED')
            client.release(h);self.assertNotIn(h.handle,b.security_tasks)
            self.assertEqual(b.journal.load()[0]['collection'],'CLOSED');reader.close.assert_called()
            self.assertFalse(engine.security_pages.views)

    def case_access_and_binding(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            b.security_reports[h.handle]=(x,self.report(x))
            for key in ('handle','run_id','owner','policy','class','role','executable_sha256'):
                raw=dict(x.binding);raw[key]='0'*64 if key in ('policy','executable_sha256') else '0'*32 if key in ('handle','run_id','owner') else 'DETERMINISTIC_TESTER' if key=='class' else 'fixer'
                try:bad=dataclasses.replace(x,binding=raw,limits=dict(x.limits))
                except p.BoundaryError:continue
                self.rejected(lambda:client.collect_security(h,bad))
            # New authenticated connection has no ownership transfer.
            other=ControllerClient(server.path,e,0,os.getgid(),linux_validation=True)
            try:self.rejected(lambda:other._rpc('SECURITY_OPEN',{'handle':h.handle}),'UNKNOWN_HANDLE')
            finally:other.close()
            self.rejected(lambda:engine.dispatch({'version':1,'seq':8,'op':'SECURITY_OPEN','args':{'handle':h.handle}},
                engine.records[h.handle]['connection'],(1,e.uid+1,e.gid)),'UNKNOWN_HANDLE')
            foreign=dataclasses.replace(x,binding={**x.binding,'executable_sha256':'0'*64},limits=dict(x.limits))
            b.security_reports[h.handle]=(foreign,self.report(foreign))
            self.rejected(lambda:client.collect_security(h,x),'POLICY_REJECTED')
            b.security_reports[h.handle]=(x,self.report(x));client.release(h)

    def case_cursors_and_release(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            b.security_reports[h.handle]=(x,self.report(x,True))
            meta=client._rpc('SECURITY_OPEN',{'handle':h.handle})
            self.rejected(lambda:client._rpc('SECURITY_PAGE',{'handle':h.handle,'snapshot':meta['snapshot'],'cursor':'0'*32}),'UNKNOWN_HANDLE')
            page=client._rpc('SECURITY_PAGE',{'handle':h.handle,'snapshot':meta['snapshot'],'cursor':meta['cursor']})
            self.rejected(lambda:client._rpc('SECURITY_PAGE',{'handle':h.handle,'snapshot':meta['snapshot'],'cursor':meta['cursor']}),'UNKNOWN_HANDLE')
            self.rejected(lambda:client._rpc('SECURITY_PAGE',{'handle':h.handle,'snapshot':'0'*32,'cursor':page['next_cursor']}),'UNKNOWN_HANDLE')
            # Concurrent capture publication cannot change already frozen bytes.
            b.security_reports[h.handle]=(x,self.report(x))
            frozen=engine.security_pages.views[engine.records[h.handle]['connection']]['raw']
            self.assertEqual(frozen,c.canonical(self.report(x,True)))
            client.release(h);self.assertFalse(engine.security_pages.views)
            self.rejected(lambda:client._rpc('SECURITY_PAGE',{'handle':h.handle,'snapshot':meta['snapshot'],'cursor':page['next_cursor']}),'INVALID_STATE')

    def case_expiry_and_request_budget(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            b.security_reports[h.handle]=(x,self.report(x));meta=client._rpc('SECURITY_OPEN',{'handle':h.handle})
            engine.security_pages.clock=lambda:x.started_ns+s.MAX_CAPTURE_NS+1
            self.rejected(lambda:client._rpc('SECURITY_PAGE',{'handle':h.handle,'snapshot':meta['snapshot'],'cursor':meta['cursor']}),'UNKNOWN_HANDLE')
            self.assertFalse(engine.security_pages.views)
            with patch.object(client,'_rpc',side_effect=AssertionError('budget must fail before RPC')):
                saved=client.seq;client.seq=p.MAX_REQUESTS-c.MAX_PAGES
                try:self.rejected(lambda:client.collect_security(h,x),'BOUNDS_EXCEEDED')
                finally:client.seq=saved
            client.release(h)

    def case_report_rejection_and_wire_bounds(self):
        fixture=SecurityProofCases();x=fixture.expectation();report=self.report(x,True)
        c.validate_report(report,x)
        pages=c.SnapshotPages(clock=lambda:0);meta=pages.open('e'*32,(1,1234,1234),report,x)
        count=meta['pages'];self.assertLessEqual(count,c.MAX_PAGES);cursor=meta['cursor']
        for i in range(count):
            page=pages.page('e'*32,(1,1234,1234),x.binding['handle'],meta['snapshot'],cursor)
            self.assertLess(len(p.encode(p.response(i+1,'OK',page))),p.MAX_FRAME)
            self.assertLessEqual(len(page['chunks']),32);self.assertTrue(all(len(chunk)<=256 for chunk in page['chunks']))
            c.decode_page(page,meta,i,dict(x.binding));cursor=page['next_cursor']
        for mutate in (lambda r:r.update(enforcement='VERIFIED'),lambda r:r.update(schema_version=2),
                       lambda r:r.update(reason={}),lambda r:r.update(status='PENDING'),
                       lambda r:r['observations'].append(r['observations'][0]),
                       lambda r:r['observations'][0]['value']['binding'].update(owner='0'*32),
                       lambda r:r.update(observations=r['observations']+[r['observations'][0]]*25)):
            bad=json.loads(c.canonical(report));mutate(bad);self.rejected(lambda:c.validate_report(bad,x))
        claims=[{'kind':'PROOF_RECORD','value':fixture.records('identity',source)[0]} for source in ('INDEPENDENT_RECORDING','CHILD_REPORTED')]
        claims[1]['value']['data']['uids'][0]=0
        self.rejected(lambda:c.validate_report({**self.report(x),'observations':claims},x),'INVALID_REQUEST')
        bad=dict(page,index=True);self.rejected(lambda:c.decode_page(bad,meta,count-1,dict(x.binding)))
        self.assertEqual((p.MAX_FRAME,p.MAX_REQUESTS,p.MAX_RATE),(16384,128,32))

    def case_failures_retain_owned_cleanup(self):
        for fault in ('factory','overflow','partial','timeout','close','start','save'):
            with self.subTest(fault=fault),self.endpoint() as (client,h,x,b,engine,server,e):
                reader=self.reader(x)
                if fault=='factory':reader_factory=Mock(side_effect=p.BoundaryError('BACKEND_FAILURE'))
                else:reader_factory=Mock(return_value=reader)
                if fault=='overflow':reader.isolation.return_value={**reader.isolation.return_value,'private':'x'*8193}
                if fault=='partial':reader.resources.return_value={}
                if fault=='timeout':reader.isolation.side_effect=p.BoundaryError('TRANSPORT_FAILURE')
                if fault=='close':reader.close.side_effect=OSError('private fixture')
                with patch.object(b.driver,'security_reader',reader_factory):
                    if fault in ('start','save'):
                        with patch('threading.Thread.start',side_effect=RuntimeError('private')) if fault=='start' else patch.object(b,'_save',side_effect=p.BoundaryError('JOURNAL_INVALID')):
                            self.rejected(lambda:b.begin_security_capture(h.handle,x),'BACKEND_FAILURE')
                    else:b.begin_security_capture(h.handle,x)
                task=b.security_tasks[h.handle]
                if fault in ('start','save'):reader_factory.assert_not_called()
                if fault not in ('start','save'):self.wait(task)
                self.assertNotEqual(task.snapshot()['status'],'CAPTURED')
                self.assertEqual(task.snapshot()['enforcement'],'UNPROVEN')
                if fault=='close':
                    self.rejected(lambda:client.release(h),'CLEANUP_INCOMPLETE')
                    self.assertTrue(b.recovery_required);self.assertEqual(b.records[h.handle]['collection'],'UNPROVEN')
                    self.assertIn(h.handle,b.security_tasks)
                    diagnostic=client.collect_security(h,x)
                    self.assertEqual(diagnostic['reason'],'CLEANUP_INCOMPLETE')
                    self.assertFalse(diagnostic['collector_closed']);self.assertEqual(diagnostic['enforcement'],'UNPROVEN')
                    # Test-only cleanup of synthetic fixture after proving sticky
                    # failure. This is not a production recovery shortcut.
                    reader.close.side_effect=None;task.close_failed=False
                if b.records[h.handle]['state']=='FAILED_DIRTY':
                    b.recover();self.assertEqual(b.records[h.handle]['state'],'RELEASED')
                else:client.release(h)
                self.assertNotIn(h.handle,b.security_tasks)

    def case_disconnect_cancel_join_and_recovery(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            reader=self.reader(x);entered=threading.Event();finish=threading.Event()
            def reading():entered.set();finish.wait(2);return self.summary(x,'ISOLATION')
            reader.isolation.side_effect=reading
            with patch.object(b.driver,'security_reader',return_value=reader):b.begin_security_capture(h.handle,x)
            task=b.security_tasks[h.handle];self.assertTrue(entered.wait(2))
            # Actual authenticated disconnect cancels before joining; settle
            # recording read concurrently, proving no completion promotion.
            client.close();self.assertTrue(task.cancel.wait(2));finish.set();self.wait(task)
            deadline=time.monotonic()+2
            while engine.records[h.handle]['state']!='RELEASED' and time.monotonic()<deadline:time.sleep(.01)
            self.assertEqual(engine.records[h.handle]['state'],'RELEASED')
            self.assertNotEqual(task.snapshot()['status'],'CAPTURED');self.assertFalse(engine.security_pages.views)
        with self.endpoint() as (client,h,x,b,engine,server,e):
            reader=self.reader(x)
            with patch.object(b.driver,'security_reader',return_value=reader):b.begin_security_capture(h.handle,x)
            task=b.security_tasks[h.handle];self.wait(task)
            with patch.object(task.thread,'join',side_effect=RuntimeError('private')):
                self.rejected(lambda:client.release(h),'CLEANUP_INCOMPLETE')
            self.assertTrue(b.recovery_required);self.assertIn(h.handle,b.security_tasks);reader.close.assert_called()
            # Simulate lost task ledger while durable intent says UNPROVEN.
            b.security_tasks.pop(h.handle)
            self.rejected(b.recover,'CLEANUP_INCOMPLETE')
            self.assertEqual(b.records[h.handle]['state'],'FAILED_DIRTY')
            self.rejected(lambda:client.create_sandbox('validation','MODEL_WORKER','coder'),'RECOVERY_REQUIRED')
            # Restore demonstrably owned test task, then remove synthetic state.
            b.security_tasks[h.handle]=task;task.close_failed=False;b.recover()

    def case_client_rejects_substitution_and_partial_wire(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            b.security_reports[h.handle]=(x,self.report(x,True));original=client._rpc
            def changed(op,args):
                result=original(op,args)
                if op=='SECURITY_PAGE':result={**result,'snapshot':'0'*32}
                return result
            with patch.object(client,'_rpc',side_effect=changed):self.rejected(lambda:client.collect_security(h,x))
            def truncated(op,args):
                result=original(op,args)
                if op=='SECURITY_PAGE':result={**result,'chunks':['QQ==']}
                return result
            with patch.object(client,'_rpc',side_effect=truncated):self.rejected(lambda:client.collect_security(h,x))
            def oversized(op,args):
                result=original(op,args)
                if op=='SECURITY_OPEN':result={**result,'total_bytes':s.MAX_BUFFER_BYTES+1}
                return result
            with patch.object(client,'_rpc',side_effect=oversized):self.rejected(lambda:client.collect_security(h,x))
            # Repeated snapshot identity, even on a fresh valid RPC seq, is not
            # accepted. Private RPC mocks here test a malicious response peer.
            old_meta=original('SECURITY_OPEN',{'handle':h.handle})
            client._security_seen.add(old_meta['snapshot'])
            with patch.object(client,'_rpc',return_value=old_meta):self.rejected(lambda:client.collect_security(h,x))
            client.release(h)

    def case_cancel_expiry_and_child_exit(self):
        for event in ('release','expiry','exit'):
            with self.subTest(event=event),self.endpoint() as (client,h,x,b,engine,server,e):
                reader=self.reader(x);entered=threading.Event();finish=threading.Event()
                def read():entered.set();finish.wait(2);return self.summary(x,'ISOLATION')
                reader.isolation.side_effect=read
                with patch.object(b.driver,'security_reader',return_value=reader):b.begin_security_capture(h.handle,x)
                task=b.security_tasks[h.handle];self.assertTrue(entered.wait(2));errors=[]
                def stop():
                    try:
                        if event=='release':client.release(h)
                        else:
                            if event=='expiry':b.clock=lambda:x.started_ns+s.MAX_CAPTURE_NS+1
                            else:b.processes[h.handle].active=False
                            b.enforce()
                    except p.BoundaryError as error:errors.append(error.code)
                worker=threading.Thread(target=stop);worker.start()
                try:self.assertTrue(task.cancel.wait(2))
                finally:finish.set();worker.join(2);self.wait(task)
                self.assertFalse(worker.is_alive());self.assertEqual(task.snapshot()['enforcement'],'UNPROVEN')
                self.assertNotEqual(task.snapshot()['status'],'CAPTURED');reader.close.assert_called()
                self.assertFalse(errors)
                if event=='expiry':
                    self.assertEqual(b.records[h.handle]['state'],'FAILED_DIRTY');self.assertTrue(b.recovery_required)
                    self.rejected(lambda:b.security_evidence(h.handle),'INVALID_STATE');b.recover()
                elif event=='exit':client.release(h)

    def case_partial_snapshot_and_mode_rejection(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            reader=self.reader(x);entered=threading.Event();finish=threading.Event()
            def read():entered.set();finish.wait(2);return self.summary(x,'RESOURCES')
            reader.resources.side_effect=read
            with patch.object(b.driver,'security_reader',return_value=reader):b.begin_security_capture(h.handle,x)
            task=b.security_tasks[h.handle];self.assertTrue(entered.wait(2))
            try:
                partial=client.collect_security(h,x)
                self.assertEqual(partial['status'],'PENDING');self.assertEqual(len(partial['observations']),1)
                self.assertFalse(partial['collector_closed']);self.assertEqual(partial['enforcement'],'UNPROVEN')
            finally:finish.set();self.wait(task)
            client.release(h)
        client=ControllerClient.__new__(ControllerClient);client.mode='SIMULATED'
        self.rejected(lambda:client.collect_security(Sandbox('a'*32),SecurityProofCases().expectation()),'POLICY_REJECTED')
        # There is no transport activation operation or callback/path argument.
        for op in ('SECURITY_START','STRESS','CAPTURE'):
            self.rejected(lambda:p.validate_request({'version':1,'seq':2,'op':op,'args':{'handle':'a'*32}}))
        self.rejected(lambda:p.validate_request({'version':1,'seq':2,'op':'SECURITY_OPEN','args':{'handle':'a'*32,'path':'/proc'}}))

    def case_restart_missing_task_and_stale_evidence(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            reader=self.reader(x)
            with patch.object(b.driver,'security_reader',return_value=reader):b.begin_security_capture(h.handle,x)
            self.wait(b.security_tasks[h.handle]);b.close()
            # Temporary journal fixture simulates crash at durable PENDING.
            records=b.journal.load();records[0]['collection']='PENDING';b.journal.save(records)
            recovered=LinuxBackend(b.registry,b.sources,b.driver,b.journal,clock=b.clock)
            before=list(b.driver.events)
            try:
                self.rejected(recovered.recover,'CLEANUP_INCOMPLETE')
                self.assertTrue(recovered.recovery_required)
                self.assertEqual(recovered.records[h.handle]['state'],'FAILED_DIRTY')
                self.assertEqual(recovered.journal.load()[0]['collection'],'PENDING')
                self.assertEqual(list(b.driver.events),before)  # no ownership guess/kill/scan
            finally:recovered.close()
            # Original fixture still has owned process reference and CLOSED task
            # proof, unlike simulated restarted backend; cleanup that fixture.
            client.release(h)
        with self.endpoint() as (client,h,x,b,engine,server,e):
            b.security_reports[h.handle]=(x,self.report(x))
            b.clock=lambda:x.started_ns+s.MAX_CAPTURE_NS+1
            self.rejected(lambda:client.collect_security(h,x),'INVALID_STATE')
            client.release(h)

    def case_limits_and_explicit_capture_only(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            with patch.object(b.driver,'security_reader',side_effect=AssertionError('retrieval must not allocate')):
                self.rejected(lambda:client.collect_security(h,x),'INVALID_STATE')
            b.security_tasks.update({f'{i:032x}':object() for i in range(p.MAX_ACTIVE)})
            try:self.rejected(lambda:b.begin_security_capture(h.handle,x),'BOUNDS_EXCEEDED')
            finally:b.security_tasks.clear()
            entry,limits=b.bindings[h.handle]
            b.bindings[h.handle]=(dataclasses.replace(entry,validation=False),limits)
            try:self.rejected(lambda:b.begin_security_capture(h.handle,x),'POLICY_REJECTED')
            finally:b.bindings[h.handle]=(entry,limits)
            record=b.journal.load()[0]
            for value in (True,[],{},'UNLIMITED'):
                self.rejected(lambda:b.journal.save([{**record,'collection':value}]),'JOURNAL_INVALID')
            for value in ('PENDING','UNPROVEN'):
                self.rejected(lambda:b.journal.save([{**record,'state':'RELEASED','cleanup':'CONFIRMED','collection':value}]),'JOURNAL_INVALID')
            self.assertEqual(client.status(h)['enforcement'],'UNPROVEN');client.release(h)

    def case_capture_publication_waits_for_reader_close(self):
        with self.endpoint() as (client,h,x,b,engine,server,e):
            reader=self.reader(x);closing=threading.Event();finish=threading.Event()
            def close():closing.set();finish.wait(2)
            reader.close.side_effect=close
            with patch.object(b.driver,'security_reader',return_value=reader):b.begin_security_capture(h.handle,x)
            task=b.security_tasks[h.handle];self.assertTrue(closing.wait(2))
            try:
                result=client.collect_security(h,x)
                self.assertEqual(result['status'],'PENDING');self.assertFalse(result['collector_closed'])
                self.assertEqual(len(result['observations']),3)
            finally:finish.set();self.wait(task)
            self.assertEqual(task.snapshot()['status'],'CAPTURED');client.release(h)

    def case_active_reader_close_wait_is_bounded(self):
        from orchestrator.privilege.security_capture import OwnedSecurityCapture, READ_NS
        reader=OwnedSecurityCapture.__new__(OwnedSecurityCapture)
        reader.closed=False;reader.cleanup_unproven=False;reader.record={'handle':'a'*32}
        reader.driver=Mock(close_errors=set());reader.scope=10;reader.host=11
        reader.descendant_fds={};reader.private_proc=None
        reader._lock=Mock();reader._lock.acquire.return_value=False
        with patch('os.close') as closed:
            self.rejected(reader.close,'CLEANUP_INCOMPLETE');closed.assert_not_called()
        reader._lock.acquire.assert_called_once_with(timeout=READ_NS/1_000_000_000)
        self.assertFalse(reader.closed);self.assertTrue(reader.cleanup_unproven)
        self.assertIn('a'*32,reader.driver.close_errors)
        # No close was attempted while the reader was active. Once ownership of
        # the lock is proven, close its own FDs; the earlier dirty fence persists.
        reader._lock.acquire.return_value=True
        with patch('os.close') as closed:reader.close();self.assertEqual(closed.call_count,2)
        self.assertTrue(reader.closed);self.assertIn('a'*32,reader.driver.close_errors)
