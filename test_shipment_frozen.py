"""Frozen-plan benchmark behavior fixtures: all worker boundaries mocked."""
import json
from pathlib import Path
import tempfile
from unittest.mock import patch, Mock
from contextlib import ExitStack
from benchmarks import shipment_frozen as f


def check_frozen_driver(self):
    h=f.h
    self.assertEqual({r for r in f.profiles('auto') if f.profiles('auto')[r]!=f.profiles('gptoss')[r]}, {'coder','fixer'})
    state={'coding_units':[{'id':'unit-1','target_files':f.TARGETS}], 'repo_facts':{},'repo_facts_text':'{}'}
    cap={'files':f.TARGETS+['README.md'],'write_files':f.TARGETS,'new_files':[],'allow_tests':False,'read_tests':True}
    with patch.object(f,'build_policy',return_value=cap): frozen=f.artifact(state,[])
    f.check_frozen(frozen)
    for key,value in (('planner_model',True),('reviewer_model',True),('plan_steps',['solve']),('schema_version',2)):
        with self.assertRaises(h.Abort): f.check_frozen({**frozen,key:value})
    # The benchmark directly invokes only the production Coder/Fixer boundaries.
    worker={'cleanup_status':'CONFIRMED','remaining_processes':0}
    def coder(s):
        return {'worker_history':[{'role':'coder','evidence':worker}], 'status':'BLOCKED','coder_error':'CODER_TIMEOUT'}
    with patch.object(f.graph,'guarded_coder_node',side_effect=coder),patch.object(f.graph,'planner_node') as planner,patch.object(f.graph,'reviewer_node') as reviewer,patch.object(f.graph,'tested_unit_node') as tester:
        s={'fix_attempts':0};f.execute(s,f.profiles('auto'),[])
        planner.assert_not_called();reviewer.assert_not_called();tester.assert_not_called()
    self.assertEqual(s['status'],'BLOCKED')
    with patch.object(h,'public_score',return_value={'passed':10,'failed':5,'errors':0,'total':15}),patch.object(h,'identifiers',return_value=[]):
        self.assertEqual(f.safe_score(s)['passed'],10)
    self.assertEqual(s['status'],'BLOCKED') # partial score cannot grant verification
    s['worker_history'][0]['evidence']={'cleanup_status':'CONFIRMED','remaining_processes':1}
    with patch.object(h,'public_score') as score:
        with self.assertRaisesRegex(h.Abort,'WORKER_CLEANUP_UNPROVEN'): f.safe_score(s)
        score.assert_not_called()
    def successful_coder(s): return {'worker_history':[{'role':'coder','evidence':worker}]}
    def fixer(s): return {'fix_attempts':s['fix_attempts']+1,'worker_history':[{'role':'fixer','evidence':worker}]}
    def tester(s): return {'test_result':'FAIL','unit_gate_status':'FINAL'}
    with patch.object(f.graph,'guarded_coder_node',side_effect=successful_coder),patch.object(f.graph,'tested_unit_node',side_effect=tester),patch.object(f.graph,'fixer_node',side_effect=fixer) as fix,patch.object(f,'safe_score',return_value={'passed':6,'failed':7,'errors':2,'total':15}),patch.object(f.graph,'route_after_tester',side_effect=lambda s:'fixer' if s['fix_attempts']<2 else 'finalizer'):
        for arm in ('auto','gptoss'):
            s={'fix_attempts':0};phases=[];f.execute(s,f.profiles(arm),phases)
            self.assertEqual(s['fix_attempts'],2);self.assertEqual([p['fix_attempts'] for p in phases],[0,1,2])
            self.assertEqual(s['status'],'UNVERIFIED')
        self.assertEqual(fix.call_count,4)
    with tempfile.TemporaryDirectory(prefix='stage28-tests-') as tmp, ExitStack() as stack:
        directory=Path(tmp);evidence=directory/'evidence';evals=directory/'evals'
        stack.enter_context(patch.object(h,'EVIDENCE',evidence));stack.enter_context(patch.object(h,'EVALS',evals))
        stack.enter_context(patch.object(h,'prerequisites'))
        stack.enter_context(patch.object(h,'repo_check'))
        stack.enter_context(patch.object(h,'identifiers',return_value=[]))
        def fake_git(repo,*args):
            if args[0]=='clone': Path(args[-1]).mkdir()
            return b''
        stack.enter_context(patch.object(h,'git',side_effect=fake_git))
        baseline={'passed':6,'failed':7,'errors':2,'total':15,'tests':[]}
        baseline_mock=stack.enter_context(patch.object(f,'inspected_baseline',return_value=(frozen,baseline)))
        with patch.object(f.graph,'guarded_coder_node') as no_worker,patch.object(f.graph,'planner_node') as no_planner:
            prepared=f.prepare('a'*40,['auto','gptoss']);path=Path(prepared['plan'])
            plan,loaded=f.load(path);self.assertEqual(loaded,frozen)
            self.assertEqual(f.validate(path)['models_invoked'],0)
            baseline_mock.return_value=(frozen,{**baseline,'passed':7})
            with self.assertRaisesRegex(h.Abort,'FROZEN_RECONSTRUCTION_MISMATCH'): f.validate(path)
            baseline_mock.return_value=({**frozen,'initial_manifest':{**cap,'write_files':[]}},baseline)
            with self.assertRaisesRegex(h.Abort,'FROZEN_RECONSTRUCTION_MISMATCH'): f.validate(path)
            baseline_mock.return_value=(frozen,baseline)
            no_worker.assert_not_called();no_planner.assert_not_called()
        self.assertEqual(f.compare(path)['arms'],{'auto':{'status':'NOT_RUN'},'gptoss':{'status':'NOT_RUN'}})
        with self.assertRaisesRegex(h.Abort,'LIVE_OPT_IN_REQUIRED'): f.run(path,'auto',False)
        # Timeout collection/scoring exercises the real driver; no model invoked.
        timeout={'status':'BLOCKED','coder_error':'CODER_TIMEOUT','worker_history':[{'role':'coder','evidence':worker}]}
        def executed(s,selection,phases): f.merge(s,timeout)
        with patch.object(f,'setup',return_value=state.copy()),patch.object(f,'artifact',return_value=frozen),patch.object(f,'execute',side_effect=executed),patch.object(f,'safe_score',return_value={'passed':10,'failed':5,'errors':0,'total':15}),patch.object(h,'final_patch',return_value={'changed_files':['file.py'],'final_patch_sha256':'c'*64}),patch.object(h,'cleanup_state',return_value='CONFIRMED'):
            result=f.run(path,'auto',True)
        self.assertEqual(result['controller_final_state'],'BLOCKED')
        self.assertFalse(result['production_verified']);self.assertEqual(result['public_after']['passed'],10)
        self.assertEqual(result['failure_class'],'ARM_OUTCOME_FAILURE')
        self.assertEqual(result['frozen_plan_sha256'],prepared['frozen_plan_sha256'])
        self.assertIn('coder_route',result);self.assertIn('fixer_route',result)
        self.assertEqual(result['fixer_route']['routed_evidence'],'UNAVAILABLE')
        f.eligible(path,plan,'gptoss')
        with self.assertRaisesRegex(h.Abort,'ARM_ALREADY_ATTEMPTED'): f.run(path,'auto',True)
        # Only exact bytes are accepted, even semantically equivalent formatting.
        fp=path.parent/'frozen-plan.json';fp.write_bytes(fp.read_bytes()+b' ')
        with self.assertRaisesRegex(h.Abort,'FROZEN_HASH_CHANGED'): f.load(path)
    self.assertEqual(h.route_summary([])['served_model_id'],'UNAVAILABLE')
    from roles.model_attribution import route_observation
    gateway={'status':'COMPLETE','version':1,'session_id':'d'*32,'request_count':1,
             'requests':[{'ordinal':1,'closed':True,'attempts':[
                 {'ordinal':1,'provider_id':'groq','model_id':'model-a','outcome':'COMPLETED'},
                 {'ordinal':2,'provider_id':'nvidia','model_id':'model-b','outcome':'COMPLETED'}]}]}
    observed=route_observation(gateway,'d'*32)
    coder_route=h.route_summary([{'role':'coder','evidence':{'gateway_attribution':observed}}])
    self.assertEqual(coder_route['route_status'],'MULTIPLE_ROUTES')
    self.assertEqual(len(coder_route['routes']),2)
    self.assertEqual(coder_route['routed_model_id'],'UNAVAILABLE')
    self.assertEqual(coder_route['served_model_id'],'UNAVAILABLE')
