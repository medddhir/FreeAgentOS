"""Recorded end-to-end assessment through authenticated B8 paging and release."""
import contextlib
import dataclasses
import hashlib
import json
import os
import time
import unittest
from unittest.mock import patch
from orchestrator.privilege import protocol as p, security_proof as s, security_assembly as a
from orchestrator.privilege import stress_gate as g
from orchestrator.privilege.client import ControllerClient
from orchestrator.privilege.evidence import binding
from test_privilege_probe import ProbeContractCases
from test_privilege_security_proof import SecurityProofCases

class SecurityAssemblyCases(unittest.TestCase):
    def cases(self):
        for name in sorted(n for n in dir(self) if n.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()

    @contextlib.contextmanager
    def endpoint(self):
        f=ProbeContractCases()
        with f.endpoint(True) as (server,e,engine,b),f.linux_client_profile():
            b.clock=time.monotonic_ns;engine.security_pages.clock=b.clock
            client=ControllerClient(server.path,e,0,os.getgid(),linux_validation=True)
            try:
                engine.roots.register('validation',server.path.parent/'work',os.getuid())
                h=client.create_sandbox('validation','MODEL_WORKER','coder',limits=dict(s.PROBE_LIMITS));client.start_sandbox(h)
                r=b.records[h.handle];entry,limits=b.bindings[h.handle]
                x=s.ProofExpectation(binding(r,entry),entry.uid,entry.gid,limits,'f'*32,b.clock()-4_000_000_000,'9'*32,(r['scope_device'],r['scope_inode']))
                yield client,h,x,b,engine
            finally:client.close()

    def fixture(self,x,kind):
        plan=s.probe_plan(x,kind)
        plan.update(seal='f'*64,fixture_source_sha256=g.FIXTURE_SHA256,authorization='RECORDING_ONLY',
                    enforcement='UNPROVEN',containment={k:'INDEPENDENT_RECORDING' for k in g.PRECONDITIONS},execution_enabled=False)
        raw=json.dumps(plan,sort_keys=True,separators=(',',':')).encode();prepared=g.PreparedProbe(raw,hashlib.sha256(raw).hexdigest())
        def metadata(kind,data,at):
            return {'kind':kind,'value':{'schema_version':1,'binding':dict(x.binding),'sample':x.sample,'subject':x.subject,
                    'scope':list(x.scope),'source':'INDEPENDENT_RECORDING','enforcement':'UNPROVEN','at_ns':at,'data':data}}
        f=SecurityProofCases()
        before=s.record(x,kind,'INDEPENDENT_RECORDING','BEFORE',f.data(kind,'BEFORE'),x.started_ns)
        after=s.record(x,kind,'INDEPENDENT_RECORDING','AFTER',f.data(kind,'AFTER'),x.started_ns+3_000_000_000)
        demand=metadata('DEMAND',{'selector':kind,'plan_sha256':prepared.digest,'runnable_tasks':2 if kind=='cpu' else 0,
            'allocation_bytes':96*1024*1024 if kind=='memory' else 0,'fork_attempts':16 if kind=='pids' else 0},x.started_ns+1)
        outcome=metadata('OUTCOME',{'plan_sha256':prepared.digest,'state':'RESOURCE_TERMINATED' if kind=='memory' else 'COMPLETED',
            'exec_transition':'RECORDED','exit_status':-9 if kind=='memory' else 0,'cause':'OOM_MATCHED' if kind=='memory' else 'EXPECTED_COMPLETION'},x.started_ns+3_000_000_001)
        report={'schema_version':1,'binding':dict(x.binding),'sample':x.sample,'subject':x.subject,'scope':list(x.scope),
                'started_ns':x.started_ns,'status':'INCOMPLETE','reason':'INVALID_STATE','collector_closed':True,'enforcement':'UNPROVEN',
                'observations':[{'kind':'PROOF_RECORD','value':before},demand,{'kind':'PROOF_RECORD','value':after},outcome]}
        return prepared,report

    def case_integrated_cleanup(self):
        for kind in g.SELECTORS:
            with self.endpoint() as (client,h,x,b,engine):
                prepared,report=self.fixture(x,kind);b.security_reports[h.handle]=(x,report)
                first=client.begin_security_assessment(h,x,prepared)
                self.assertEqual(first['recorded_assessment'],'INCONCLUSIVE');self.assertEqual(first['completeness'],'OBSERVATIONS_COMPLETE')
                self.assertTrue(first['cleanup_obligation'])
                self.assertEqual(client.finish_security_assessment(h)['recorded_assessment'],'INCONCLUSIVE')
                client.release(h);final=client.finish_security_assessment(h)
                self.assertEqual(final['recorded_assessment'],'PASS');self.assertFalse(final['qualifying'])
                self.assertEqual(final['enforcement'],'UNPROVEN');self.assertFalse(final['cleanup_obligation'])
                with self.assertRaises(p.BoundaryError):client.finish_security_assessment(h)

    def case_missing_and_claims(self):
        x=SecurityProofCases().expectation()
        for kind in g.SELECTORS:
            prepared,report=self.fixture(x,kind)
            for i in range(4):
                changed=json.loads(json.dumps(report));changed['observations'].pop(i)
                self.assertEqual(a.assess(x,prepared,changed,'CONFIRMED')['recorded_assessment'],'INCONCLUSIVE')
            for source in ('CONFIGURED','CHILD_REPORTED'):
                changed=json.loads(json.dumps(report))
                for v in changed['observations']:
                    if v['kind']=='PROOF_RECORD':v['value']['source']=source
                self.assertEqual(a.assess(x,prepared,changed,'CONFIRMED')['recorded_assessment'],'INCONCLUSIVE')
            changed=json.loads(json.dumps(report));changed['collector_closed']=False;changed['status']='PENDING';changed['reason']='OK'
            self.assertEqual(a.assess(x,prepared,changed)['reason'],'CAPTURE_INCOMPLETE')

    def case_contradiction_and_identity(self):
        x=SecurityProofCases().expectation();prepared,report=self.fixture(x,'cpu')
        bad=[]
        for k in ('run_id','owner','policy','executable_sha256'):
            changed=json.loads(json.dumps(report));changed['observations'][1]['value']['binding'][k]='8'*(64 if k in ('policy','executable_sha256') else 32);bad.append(changed)
        changed=json.loads(json.dumps(report));changed['observations'][1]['value']['data']['plan_sha256']='0'*64;bad.append(changed)
        changed=json.loads(json.dumps(report));changed['observations'][2]['value']['data']['usage_usec']=-1;bad.append(changed)
        changed=json.loads(json.dumps(report));changed['observations'].reverse();bad.append(changed)
        changed=json.loads(json.dumps(report));changed['observations'][3]['value']['at_ns']=x.started_ns+s.MAX_CAPTURE_NS+1;bad.append(changed)
        changed=json.loads(json.dumps(report));changed['observations']*=7;bad.append(changed)
        for changed in bad:self.assertEqual(a.assess(x,prepared,changed,'CONFIRMED')['recorded_assessment'],'INCONCLUSIVE')
        altered=dataclasses.replace(prepared,payload=prepared.payload+b' ')
        self.assertEqual(a.assess(x,altered,report,'CONFIRMED')['reason'],'EVIDENCE_INVALID')

    def case_outcomes_and_demand(self):
        x=SecurityProofCases().expectation()
        for kind in g.SELECTORS:
            prepared,report=self.fixture(x,kind)
            for state,cause in (('TIMEOUT','TIMEOUT'),('ABNORMAL','UNRELATED'),('RESOURCE_TERMINATED','UNRELATED')):
                changed=json.loads(json.dumps(report));changed['observations'][3]['value']['data'].update(state=state,cause=cause,exit_status=-9)
                self.assertEqual(a.assess(x,prepared,changed,'CONFIRMED')['recorded_assessment'],'INCONCLUSIVE')
            changed=json.loads(json.dumps(report));changed['observations'][1]['value']['data'].update(runnable_tasks=0,allocation_bytes=0,fork_attempts=0)
            self.assertEqual(a.assess(x,prepared,changed,'CONFIRMED')['reason'],'DEMAND_UNPROVEN')
        prepared,report=self.fixture(x,'pids')
        # Six children, not all16 attempts, plus recorded denial still qualifies
        # the recorded predicate; work need not consume its whole allowance.
        self.assertEqual(a.assess(x,prepared,report,'CONFIRMED')['recorded_assessment'],'PASS')
        report['observations'][2]['value']['data']['max_events']=0
        self.assertEqual(a.assess(x,prepared,report,'CONFIRMED')['recorded_assessment'],'INCONCLUSIVE')

    def case_counter_failures_and_cleanup_failure(self):
        x=SecurityProofCases().expectation()
        for kind in g.SELECTORS:
            prepared,report=self.fixture(x,kind)
            key={'cpu':'usage_usec','memory':'max_events','pids':'max_events'}[kind]
            report['observations'][0]['value']['data'][key]=report['observations'][2]['value']['data'][key]+1
            result=a.assess(x,prepared,report,'CONFIRMED')
            self.assertEqual(result['recorded_assessment'],'INCONCLUSIVE')
            self.assertEqual(result['reason'],'COUNTER_RESET_OR_MISMATCH')
        prepared,report=self.fixture(x,'cpu');report['observations'][2]['value']['data']['quota_us']+=1
        self.assertEqual(a.assess(x,prepared,report,'CONFIRMED')['recorded_assessment'],'FAIL')
        with self.endpoint() as (client,h,x,b,engine):
            prepared,report=self.fixture(x,'memory');b.security_reports[h.handle]=(x,report)
            client.begin_security_assessment(h,x,prepared);b.driver.fail='CGROUP_KILL_OWNED'
            with self.assertRaises(p.BoundaryError):client.release(h)
            result=client.finish_security_assessment(h)
            self.assertEqual(result['recorded_assessment'],'INCONCLUSIVE');self.assertTrue(result['cleanup_obligation'])
            self.assertTrue(b.recovery_required);self.assertEqual(b.records[h.handle]['state'],'FAILED_DIRTY')
            b.driver.fail=None

    def case_expiry_dirty_and_replay(self):
        with self.endpoint() as (client,h,x,b,engine):
            prepared,report=self.fixture(x,'cpu');b.security_reports[h.handle]=(x,report)
            client.begin_security_assessment(h,x,prepared)
            with self.assertRaises(p.BoundaryError):client.begin_security_assessment(h,x,prepared)
            b._dirty(b.records[h.handle]);engine.records[h.handle]['state']='FAILED_DIRTY'
            self.assertTrue(client.finish_security_assessment(h)['cleanup_obligation']);self.assertTrue(b.recovery_required)
            with patch('time.monotonic_ns',return_value=x.started_ns+s.MAX_CAPTURE_NS+1):
                with self.assertRaises(p.BoundaryError):client.finish_security_assessment(h)
            self.assertTrue(b.recovery_required)

    def case_early_release_and_partial(self):
        with self.endpoint() as (client,h,x,b,engine):
            prepared,report=self.fixture(x,'cpu');b.security_reports[h.handle]=(x,report)
            client.release(h)
            with self.assertRaises(p.BoundaryError):client.begin_security_assessment(h,x,prepared)
        with self.endpoint() as (client,h,x,b,engine):
            prepared,report=self.fixture(x,'cpu');report['observations'].pop();b.security_reports[h.handle]=(x,report)
            self.assertEqual(client.begin_security_assessment(h,x,prepared)['completeness'],'INCOMPLETE')
            client.release(h);self.assertEqual(client.finish_security_assessment(h)['recorded_assessment'],'INCONCLUSIVE')
