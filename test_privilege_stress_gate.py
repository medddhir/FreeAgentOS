"""Recording-only stress preparation; never runs resource probes."""
import dataclasses
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from orchestrator.privilege import stress_gate as g, security_proof as s, protocol as p
from orchestrator.privilege.evidence import binding
from orchestrator.privilege.execution import ApprovedExecution
from test_privilege_complete import LinuxCompleteCases

class StressGateCases(unittest.TestCase):
    def cases(self):
        for name in sorted(n for n in dir(self) if n.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()

    def setup_plan(self,b,entry):
        b.sources['validation']=SimpleNamespace(seal=SimpleNamespace(verification_sha256='f'*64))
        b.create('b'*32,'c'*32,'validation','MODEL_WORKER','coder',dict(s.PROBE_LIMITS))
        r=b.records['b'*32]
        x=s.ProofExpectation(binding(r,entry),entry.uid,entry.gid,b.bindings[r['handle']][1],'d'*32,0,'e'*32,(1,r['scope_inode']))
        a=g.RecordingApproval(x.binding,'cpu','f'*64)
        pre={k:'INDEPENDENT_RECORDING' for k in g.PRECONDITIONS}
        return r,x,a,pre

    def reject(self,fn):
        with self.assertRaises(p.BoundaryError):fn()

    def case_valid(self):
        with LinuxCompleteCases().fixture() as (b,d,j,clock,entry):
            r,x,a,pre=self.setup_plan(b,entry)
            for selector in g.SELECTORS:
                approval=dataclasses.replace(a,selector=selector)
                raw=b.prepare_stress_recording(r['handle'],x,selector,approval,pre)
                plan=json.loads(raw)
                self.assertEqual(plan['argv'],['freeagentos-security-probe','--'+selector])
                self.assertEqual(plan['binding'],dict(x.binding));self.assertFalse(plan['execution_enabled'])
                self.assertEqual(plan['enforcement'],'UNPROVEN')
            self.assertNotIn('LAUNCH',[v[1] for v in d.events]);self.assertEqual(r['state'],'CREATED')
            b.cleanup(r['handle']);self.assertEqual(b.cleanup_proof(r['handle'],b.owner),'OWNED_CLEANED')

    def case_authorization(self):
        with LinuxCompleteCases().fixture() as (b,d,j,clock,entry):
            r,x,a,pre=self.setup_plan(b,entry)
            for bad in (None,True,{'linux_validation':True},object()):
                self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',bad,pre))
            self.reject(lambda:g.prepare(r,entry,b.sources['validation'],x,'cpu',a,pre,object()))
            self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'unknown',a,pre))
            self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',a,{}))
            for k in pre:
                self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',a,{**pre,k:'CONFIGURED'}))
            b.bindings[r['handle']]=(dataclasses.replace(entry,validation=False),b.bindings[r['handle']][1])
            self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',a,pre))

    def case_binding(self):
        with LinuxCompleteCases().fixture() as (b,d,j,clock,entry):
            r,x,a,pre=self.setup_plan(b,entry)
            for key in ('owner','run_id','handle','policy','executable_sha256'):
                changed=dict(x.binding);changed[key]='9'*(64 if key in ('policy','executable_sha256') else 32)
                bad=dataclasses.replace(a,identity=changed)
                self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',bad,pre))
            self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'memory',a,pre))
            self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',dataclasses.replace(a,seal='8'*64),pre))
            wrong=dataclasses.replace(x,binding=dict(x.binding),limits={**dict(x.limits),'memory_limit_bytes':32*1024*1024})
            self.reject(lambda:b.prepare_stress_recording(r['handle'],wrong,'cpu',a,pre))
            with patch.object(ApprovedExecution,'verify',side_effect=p.BoundaryError('POLICY_REJECTED')):
                self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',a,pre))
            self.assertTrue(b.owns(r['handle'],b.owner))

    def case_delivery_failure(self):
        with LinuxCompleteCases().fixture() as (b,d,j,clock,entry):
            r,x,a,pre=self.setup_plan(b,entry)
            checked=g.prepare(r,entry,b.sources['validation'],x,'cpu',a,pre,d)
            for raw in (checked.payload+b' ',checked.payload.replace(b'--cpu',b'--pids')):
                altered=g.PreparedProbe(raw,checked.digest)
                self.reject(lambda:g.deliver(altered,checked,d))
            d.fail='STRESS_PREPARATION_RECORDING'
            self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',a,pre))
            self.assertEqual(r['state'],'FAILED_DIRTY');self.assertTrue(b.recovery_required)
            self.assertEqual(b.cleanup_proof(r['handle'],b.owner),'UNPROVEN')
            d.fail=None;self.reject(lambda:b.cleanup(r['handle']));self.assertTrue(b.recovery_required)

    def case_substitution(self):
        with LinuxCompleteCases().fixture() as (b,d,j,clock,entry):
            r,x,a,pre=self.setup_plan(b,entry)
            original=g.prepare;calls=[]
            def replaced(*args):
                value=original(*args);calls.append(value)
                if len(calls)==2:return dataclasses.replace(value,payload=value.payload+b' ')
                return value
            with patch.object(g,'prepare',side_effect=replaced):
                self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',a,pre))
            self.assertEqual(r['state'],'FAILED_DIRTY');self.assertTrue(b.recovery_required)
            self.assertFalse(b.processes)

    def case_uncertain_ownership_and_fixture(self):
        with LinuxCompleteCases().fixture() as (b,d,j,clock,entry):
            r,x,a,pre=self.setup_plan(b,entry)
            with patch.object(g,'verify_fixture',side_effect=p.BoundaryError('POLICY_REJECTED')):
                self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',a,pre))
            changed=dict(x.binding);changed.update({'class':'RESEARCH_HELPER','role':'researcher'})
            # Invalid role/class contracts are rejected before any delivery.
            self.reject(lambda:g.RecordingApproval(changed,'cpu','f'*64))
            with patch.object(d,'prove',return_value={'scope':False,'root':True}):
                self.reject(lambda:b.prepare_stress_recording(r['handle'],x,'cpu',a,pre))
            self.assertEqual(r['state'],'FAILED_DIRTY');self.assertTrue(b.recovery_required)
            self.assertEqual(b.cleanup_proof(r['handle'],b.owner),'UNPROVEN')

    def case_bounds_and_rpc(self):
        self.assertEqual(s.PROBE_BOUNDS['cpu'][:2],(3000,3))
        self.assertEqual(s.PROBE_BOUNDS['memory'][2:],(96*1024*1024,24576))
        self.assertEqual(s.PROBE_BOUNDS['pids'][0],4000);self.assertEqual(s.PROBE_BOUNDS['pids'][3],16)
        self.assertNotIn('STRESS',p.OPERATIONS)
        self.assertEqual(p.MAX_FRAME,16384);self.assertEqual(p.MAX_REQUESTS,128)
        self.reject(lambda:p.validate_request({'version':1,'seq':1,'op':'START','args':{'handle':'b'*32,'selector':'cpu'}}))
