"""Owned descriptor text jobs; no adapter/model/kernel launches or authority."""
import contextlib
from dataclasses import replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
from orchestrator.roles import worker
from orchestrator.privilege import protocol as p
from orchestrator.privilege.execution import ApprovedExecution, ExecutionRegistry
from orchestrator.privilege.isolation import LinuxBackend
from orchestrator.privilege.linux import PinnedFile
from orchestrator.privilege.policy import policy_hash
from orchestrator.privilege.real_journal import ResourceJournal
from orchestrator.privilege.recording import RecordingDriver
from orchestrator.privilege.text_job import TextJob, MAX_OUTPUT, SEALS, _frame
import website as w
from test_website import brief
from test_website_proposals import proposed_files, envelope, encode


class TextJobTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            session=w.Session(brief(), root, preparation='synthetic');session.scaffold()
            request,_=w.proposal_request(session,'code')
            exe=root/'exe';exe.write_bytes(b'\x7fELFfixture');exe.chmod(0o700)
            ef=os.open(exe,os.O_RDONLY|os.O_CLOEXEC);rf=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            st=os.fstat(ef);pinned=PinnedFile(ef,st.st_dev,st.st_ino,hashlib.sha256(exe.read_bytes()).hexdigest())
            entry=ApprovedExecution('MODEL_WORKER','coder',pinned,rf,1234,1234,'e'*32,False)
            plan=worker.prepare_text_inference(request,runtime_sha256='a'*64,
                executable_sha256=pinned.digest,invocation='c'*32,credential_reference='SYNTHETIC_TOKEN',policy_sha256=policy_hash())
            journal=ResourceJournal(root,policy_hash(),'a'*32,uid=os.getuid());driver=RecordingDriver()
            backend=LinuxBackend(ExecutionRegistry({'text':entry}),{'text':object()},driver,journal,clock=lambda:0)
            try:
                with patch.object(ApprovedExecution,'verify',return_value=None):
                    backend.create('b'*32,'d'*32,'text','MODEL_WORKER','coder',{})
                    yield backend,driver,entry,plan,session
            finally:
                backend.close();journal.close();os.close(ef);os.close(rf)

    def response(self,session,phase='code'):
        request,base=w.proposal_request(session,phase)
        return encode(envelope(session,phase,proposed_files(phase=='revision'),base.sha256))

    def test_connected_job_revision_and_exact_export(self):
        with self.fixture() as (b,d,e,plan,s):
            response=self.response(s);d.text_response_fixture=response
            job_id=b.bind_text_job('b'*32,plan);job=b.text_jobs['b'*32]
            self.assertNotEqual(job_id,plan.invocation)
            self.assertNotEqual(job_id,e.job_id)
            inputfd=job.input_fd;outputfd=job.output_fd
            b.start('b'*32)
            self.assertEqual(d.text_request_observed,plan.request)
            self.assertEqual(d.text_argv_observed,('freeagentos-worker','--broker-job',job_id))
            with self.assertRaises(p.BoundaryError):b.collect_text_job('b'*32)
            b.terminate('b'*32);result=b.collect_text_job('b'*32)
            self.assertEqual(result.payload,response)
            self.assertEqual(result.request_sha256,plan.request_sha256)
            self.assertEqual(json.loads(job.binding)['runtime_declared'],'a'*64)
            self.assertEqual(json.loads(job.binding)['executable_observed'],e.executable.digest)
            with self.assertRaises(p.BoundaryError):b.collect('b'*32)
            with self.assertRaises(p.BoundaryError):b.collect_text_job('b'*32)
            # Existing validator/broker apply, not a new write/authority path.
            w.SyntheticProposalAdapter(result.payload,result.payload).apply(s,'code')
            request,_=w.proposal_request(s,'revision')
            revised=worker.prepare_text_inference(request,runtime_sha256='a'*64,executable_sha256=e.executable.digest,
                invocation='f'*32,credential_reference='SYNTHETIC_TOKEN',policy_sha256=policy_hash())
            b.cleanup('b'*32)
            for fd in (inputfd,outputfd):
                with self.assertRaises(OSError):os.fstat(fd)
            self.assertTrue(b.cleaned('b'*32,b.owner))
            b.create('c'*32,'f'*32,'text','MODEL_WORKER','coder',{})
            other=b.bind_text_job('c'*32,revised);self.assertNotEqual(other,job_id)
            d.text_response_fixture=self.response(s,'revision');b.start('c'*32);b.terminate('c'*32)
            rr=b.collect_text_job('c'*32)
            w.SyntheticProposalAdapter(rr.payload,rr.payload).apply(s,'revision')
            snap=s.snapshot();checks=s.checks(snap,True);export=s.export(snap,checks)
            for name,data in snap.files:self.assertEqual((Path(export['directory'])/name).read_bytes(),data)
            self.assertEqual(checks['functional'],'UNPROVEN');b.cleanup('c'*32)

    def test_immutable_request_and_resource_substitution(self):
        with self.fixture() as (b,d,e,plan,s):
            b.bind_text_job('b'*32,plan);job=b.text_jobs['b'*32]
            with self.assertRaises(OSError):os.pwrite(job.input_fd,b'x',0)
            cfg=job.configuration()
            for bad in (dict(cfg,input=job.output_fd),dict(cfg,output=job.input_fd),dict(cfg,job='f'*32),dict(cfg,version=True),dict(cfg,extra=1)):
                with self.subTest(bad=list(bad)),self.assertRaises(p.BoundaryError):job.deliver(bad)
            self.assertEqual(job.deliver(cfg),plan.request)
            with self.assertRaises(p.BoundaryError):job.deliver(cfg)
            with self.assertRaises(p.BoundaryError):b.bind_text_job('b'*32,plan)

    def test_invalid_plan_and_validation_combination(self):
        with self.fixture() as (b,d,e,plan,s):
            for bad in (None,{},replace(plan,invocation=[]),replace(plan,request=b'{}'),replace(plan,request=plan.request+b' '),replace(plan,binding_sha256='0'*64),replace(plan,executable_sha256='0'*64)):
                with self.subTest(kind=type(bad).__name__),self.assertRaises(p.BoundaryError):b.bind_text_job('b'*32,bad)
            with self.assertRaises(p.BoundaryError):TextJob(plan,b.records['b'*32],replace(e,validation=True))
            self.assertEqual(b.text_jobs,{})

    def test_invocation_reuse_and_rejected_proposal_have_no_writes(self):
        from roles.file_tools import FileTools
        with self.fixture() as (b,d,e,plan,s):
            before=s.snapshot()
            b.bind_text_job('b'*32,plan);d.text_response_fixture=b'{"qualified":true}'
            b.start('b'*32);b.terminate('b'*32);response=b.collect_text_job('b'*32)
            with patch.object(FileTools,'call') as writes:
                with self.assertRaises(w.ProposalError):
                    w.SyntheticProposalAdapter(response.payload,response.payload).apply(s,'code')
                writes.assert_not_called()
            self.assertEqual(s.snapshot().files,before.files)
            with self.assertRaises(w.WebsiteError):s.export(before,{})
            b.cleanup('b'*32)
            b.create('c'*32,'f'*32,'text','MODEL_WORKER','coder',{})
            with self.assertRaises(p.BoundaryError):b.bind_text_job('c'*32,plan)

    def test_failed_close_retains_dirty_cleanup_status(self):
        with self.fixture() as (b,d,e,plan,s):
            b.bind_text_job('b'*32,plan);job=b.text_jobs['b'*32]
            original=os.close;failed_fd=job.input_fd
            def ambiguous(fd):
                original(fd)
                if fd==failed_fd:raise OSError('synthetic close failure')
            with patch('orchestrator.privilege.text_job.os.close',side_effect=ambiguous):
                with self.assertRaises(p.BoundaryError):b.cleanup('b'*32)
            self.assertEqual(b.status('b'*32)['state'],'FAILED_DIRTY')
            self.assertEqual(b.cleanup_proof('b'*32,b.owner),'UNPROVEN')
            self.assertIsNone(job.input_fd);self.assertIsNone(job.output_fd)
            with self.assertRaises(p.BoundaryError):job.close()
            # Only test teardown releases the intentionally failed recording;
            # no production recovery converts ambiguous close into confirmation.
            b.text_jobs.pop('b'*32)

    def test_backend_cross_handle_substitution_rejects(self):
        with self.fixture() as (b,d,e,plan,s):
            b.bind_text_job('b'*32,plan);first=b.text_jobs['b'*32]
            b.create('c'*32,'f'*32,'text','MODEL_WORKER','coder',{})
            b.bind_text_job('c'*32,replace(plan,invocation='f'*32,
                binding_sha256=worker.prepare_text_inference(json.loads(plan.request),runtime_sha256=plan.runtime_sha256,
                    executable_sha256=plan.executable_sha256,invocation='f'*32,
                    credential_reference=plan.credential_reference,policy_sha256=plan.policy_sha256).binding_sha256))
            second=b.text_jobs['c'*32]
            b.text_jobs['c'*32]=first
            d.text_response_fixture=b'fixture'
            with self.assertRaises(p.BoundaryError):b.start('c'*32)
            self.assertFalse(first.delivered)
            b.text_jobs['c'*32]=second
            b.recover()

    def test_response_bounds_incomplete_error_and_cross_job(self):
        with self.fixture() as (b,d,e,plan,s):
            b.bind_text_job('b'*32,plan);job=b.text_jobs['b'*32];job.deliver(job.configuration())
            with self.assertRaises(p.BoundaryError):job.collect()
            for raw in (b'',b'x'*(MAX_OUTPUT+1),'not bytes'):
                with self.assertRaises(p.BoundaryError):job.finish_recording(raw)
            job.finish_recording(b'x'*MAX_OUTPUT)
            self.assertEqual(len(job.collect().payload),MAX_OUTPUT)
            b.cleanup('b'*32)
        with self.fixture() as (b,d,e,plan,s):
            b.bind_text_job('b'*32,plan);job=b.text_jobs['b'*32];job.deliver(job.configuration())
            job.finish_recording(b'error',success=False)
            with self.assertRaises(p.BoundaryError):job.collect()
        with self.fixture() as (b,d,e,plan,s):
            b.bind_text_job('b'*32,plan);job=b.text_jobs['b'*32];job.deliver(job.configuration())
            payload=b'cross-job';raw=_frame({'binding':hashlib.sha256(job.binding).hexdigest(),'job':'f'*32,
                'request':plan.request_sha256,'status':'COMPLETE','bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()},payload)
            os.pwrite(job.output_fd,raw,0);fcntl.fcntl(job.output_fd,fcntl.F_ADD_SEALS,SEALS);job.completed=True
            with self.assertRaises(p.BoundaryError):job.collect()

    def test_unsealed_oversized_malformed_and_swapped_outputs(self):
        for mode in ('unsealed','oversized','malformed','swapped','incomplete'):
            with self.subTest(mode=mode),self.fixture() as (b,d,e,plan,s):
                b.bind_text_job('b'*32,plan);job=b.text_jobs['b'*32];job.deliver(job.configuration())
                if mode=='swapped':job.input_fd,job.output_fd=job.output_fd,job.input_fd
                else:
                    raw=b'x'*(MAX_OUTPUT+4101) if mode=='oversized' else struct.pack('!I',5000)+b'{}'
                    os.pwrite(job.output_fd,raw,0)
                    if mode!='unsealed':fcntl.fcntl(job.output_fd,fcntl.F_ADD_SEALS,SEALS)
                job.completed=mode!='incomplete'
                with self.assertRaises(p.BoundaryError):job.collect()

    def test_failure_and_cancel_ownership(self):
        with self.fixture() as (b,d,e,plan,s):
            b.bind_text_job('b'*32,plan);d.text_response_fixture=b'valid';d.fail='TEXT_RESPONSE_COLLECTION'
            with self.assertRaises(p.BoundaryError):b.start('b'*32)
            self.assertEqual(b.status('b'*32)['state'],'FAILED_DIRTY')
            self.assertEqual(b.cleanup_proof('b'*32,b.owner),'UNPROVEN')
            self.assertFalse(next(iter(d.resources.values()))['process'].active)
            b.recover();self.assertEqual(b.text_jobs,{})
            self.assertTrue(b.cleaned('b'*32,b.owner))
        with self.fixture() as (b,d,e,plan,s):
            b.bind_text_job('b'*32,plan);b.cleanup('b'*32)
            self.assertTrue(b.cleaned('b'*32,b.owner))

    def test_production_driver_and_public_collect_stay_closed(self):
        from orchestrator.privilege.kernel import LinuxDriver
        from orchestrator.privilege.child import validate_configuration
        with self.fixture() as (b,d,e,plan,s):
            b.driver=LinuxDriver.__new__(LinuxDriver)
            with self.assertRaises(p.BoundaryError):b.bind_text_job('b'*32,plan)
            b.driver=d
            with self.assertRaises(p.BoundaryError):b.collect('b'*32)
            with self.assertRaises(p.BoundaryError):p.encode({'request':plan.request.decode()})
            c={'version':1,'class':'MODEL_WORKER','role':'coder','uid':1234,'gid':1234,
               'job_id':'e'*32,'validation':True,'fds':list(range(3,11)),'limits':{}}
            with self.assertRaises(p.BoundaryError):validate_configuration(c)
            for fn,args,kwargs in ((worker.run_worker,([worker.TEXT_INFERENCE_EXECUTABLE],),{}),
                                   (worker._run_worker_impl,([worker.TEXT_INFERENCE_EXECUTABLE],),{}),
                                   (worker._run_inner,(None,{'profile':worker.TEXT_INFERENCE_PROFILE}),{})):
                with self.assertRaises(worker.WorkerBoundaryError):fn(*args,**kwargs)
