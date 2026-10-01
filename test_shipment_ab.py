"""Deterministic driver fixtures. Every model/graph boundary is mocked."""
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch, Mock
from contextlib import ExitStack
from benchmarks import shipment_ab as h
from roles.model_attribution import route_observation


def check_driver(self):
    ids=[f'tests.test_public.Example.test_{i}' for i in range(15)]
    output='\n'.join(f'test_{i} ({name}) ... '+('ok' if i<6 else 'FAIL') for i,name in enumerate(ids))+'\nRan 15 tests in 0.01s\n'
    ids=sorted(ids)
    baseline=h.score(output,ids)
    self.assertEqual(baseline['passed'],6);self.assertEqual(baseline['failed'],9)
    for bad in (output+'\ntest_0 (tests.test_public.Example.test_0) ... ok',output.replace('Ran 15','Ran 14'),output.replace('Example','Other')):
        with self.assertRaises(h.Abort): h.score(bad,ids)
    self.assertEqual({role for role in h.assignments('auto') if h.assignments('auto')[role]!=h.assignments('gptoss')[role]}, {'coder','fixer'})
    self.assertEqual(h.assignments('gptoss')['planner'],'claude-free-default')
    self.assertEqual(h.assignments('gptoss')['reviewer'],'claude-free-default')
    self.assertEqual(h.assignments('gptoss')['researcher'],'research-tools')
    for kwargs in ({'live':False},{'live':True,'arm':'invalid'}):
        with self.assertRaises(h.Abort): h.run_arm(Path('/not/a/plan'),kwargs.get('arm','auto'),kwargs['live'])
    with patch.dict(h.ARMS,{'gptoss':'invalid'}):
        with self.assertRaises(ValueError): h.assignments('gptoss')
    fake_commit='a'*40
    health=Mock();health.__enter__=Mock(return_value=health);health.__exit__=Mock(return_value=False)
    for status,host_status,code in ((500,'PASS','GATEWAY_UNHEALTHY'),(200,'BLOCKED','HOST_PREFLIGHT_FAILED')):
        health.status=status
        with patch.object(h,'git',side_effect=[fake_commit.encode()+b'\n',b'']),patch.object(h,'repo_check'),patch.object(h.urllib.request,'urlopen',return_value=health),patch.object(h,'check_host',return_value={'status':host_status}):
            with self.assertRaisesRegex(h.Abort,code): h.prerequisites(fake_commit)
    with patch.object(h,'git',return_value=b'b'*40+b'\n'),patch.object(h,'check_host') as host:
        with self.assertRaisesRegex(h.Abort,'CONTROLLER_COMMIT_MISMATCH'): h.prerequisites(fake_commit)
        host.assert_not_called()
    with patch.object(h,'git',side_effect=[str(h.BASELINE).encode()+b'\n',h.BASELINE_COMMIT.encode()+b'\n',b' M changed']):
        with self.assertRaisesRegex(h.Abort,'WORKTREE_DIRTY'): h.repo_check(h.BASELINE,h.BASELINE_COMMIT)
    with patch.object(h,'git',side_effect=[str(h.BASELINE).encode()+b'\n',b'b'*40+b'\n']):
        with self.assertRaisesRegex(h.Abort,'COMMIT_MISMATCH'): h.repo_check(h.BASELINE,h.BASELINE_COMMIT)
    with tempfile.TemporaryDirectory(prefix='ab-driver-') as tmp:
        evidence=Path(tmp)/'evidence';work=Path(tmp)/'evals'
        clones=[]
        def fake_git(repo,*args):
            if args[0]=='clone':
                self.assertIn('--no-local',args);self.assertIn('--no-hardlinks',args)
                target=Path(args[-1]);self.assertFalse(target.exists());target.mkdir();clones.append(target)
            return b''
        with ExitStack() as stack:
            stack.enter_context(patch.object(h,'EVIDENCE',evidence));stack.enter_context(patch.object(h,'EVALS',work))
            ready=stack.enter_context(patch.object(h,'prerequisites'))
            stack.enter_context(patch.object(h,'git',side_effect=fake_git))
            stack.enter_context(patch.object(h,'repo_check'))
            stack.enter_context(patch.object(h,'identifiers',return_value=ids))
            scorer=stack.enter_context(patch.object(h,'baseline_score',return_value=baseline))
            prepared=h.prepare(fake_commit,['auto','gptoss']);path=Path(prepared['plan'])
            self.assertEqual(prepared['models_invoked'],0);self.assertEqual(len(clones),2);self.assertNotEqual(clones[0],clones[1])
            plan=h.load_plan(path);self.assertEqual(plan['baseline'],baseline)
            self.assertEqual(h.compare(path)['arms'],{'auto':{'status':'NOT_RUN'},'gptoss':{'status':'NOT_RUN'}})
            self.assertEqual(h.validate(plan)['models_invoked'],0)
            scorer.return_value={**baseline,'passed':7}
            with self.assertRaisesRegex(h.Abort,'BASELINE_SCORE_MISMATCH'): h.validate(plan)
            scorer.return_value=baseline
            with self.assertRaisesRegex(h.Abort,'RUN_ORDER_VIOLATION'): h.run_arm(path,'gptoss',True)
            gateway={'status':'COMPLETE','version':1,'session_id':'c'*32,'request_count':1,'requests':[{'ordinal':1,'closed':True,'attempts':[{'ordinal':1,'provider_id':'groq','model_id':'openai/gpt-oss-120b','outcome':'COMPLETED'}]}]}
            observation=route_observation(gateway,'c'*32)
            state={'status':'BLOCKED','worker_history':[{'role':'coder','evidence':{'gateway_attribution':observation,'raw_model':'PRIVATE'}}],
                   'coder_output':'PRIVATE','test_output':'PRIVATE','diff':'PRIVATE','fix_attempts':0}
            result=h.state_evidence(state);self.assertNotIn('PRIVATE',json.dumps(result))
            self.assertEqual(result['coding_route']['routed_evidence'],'ROUTER_DISPATCH')
            self.assertEqual(result['coding_route']['served_model_id'],'UNAVAILABLE')
            self.assertEqual(h.route_summary([])['routed_model_id'],'UNAVAILABLE')
            self.assertEqual(h.route_summary([{'role':'coder','evidence':{}},{'role':'fixer','evidence':{'gateway_attribution':observation}}])['routed_model_id'],'UNAVAILABLE')
            gateway['requests'][0]['attempts'].append({'ordinal':2,'provider_id':'nvidia','model_id':'model-b','outcome':'COMPLETED'})
            multiple=route_observation(gateway,'c'*32)
            routes=h.route_summary([{'role':'coder','evidence':{'gateway_attribution':multiple}}])
            self.assertEqual(routes['route_status'],'MULTIPLE_ROUTES');self.assertEqual(routes['routed_model_id'],'UNAVAILABLE')
            import graph
            mocked_graph=Mock();mocked_graph.stream.return_value=[state]
            with patch.object(graph,'build_graph',return_value=mocked_graph) as builder,patch.object(h,'public_score',return_value=baseline),patch.object(h,'final_patch',return_value={'changed_files':['implementation.py'],'final_patch_sha256':'d'*64}),patch.object(h,'cleanup_state',return_value='CONFIRMED') as cleanup:
                result=h.run_arm(path,'auto',True)
            builder.assert_called_once_with(model_profiles=h.assignments('auto'));cleanup.assert_called_once_with(state)
            self.assertEqual(mocked_graph.stream.call_args.args[0]['task'],h.TASK)
            self.assertTrue(mocked_graph.stream.call_args.args[0]['retain_workspace'])
            self.assertEqual(result['final_public_verification'],'FAIL')
            self.assertEqual(result['controller_final_state'],'BLOCKED')
            self.assertEqual(result['promotion_patch_status'],'NONE')
            with self.assertRaisesRegex(h.Abort,'ARM_ALREADY_ATTEMPTED'): h.run_arm(path,'auto',True)
            with patch.object(graph,'build_graph',return_value=mocked_graph),patch.object(h,'public_score',side_effect=h.Abort('PUBLIC_RESULTS_UNAVAILABLE')),patch.object(h,'cleanup_state',return_value='CONFIRMED') as cleanup:
                failed=h.run_arm(path,'gptoss',True)
            cleanup.assert_called_once();self.assertIsNone(failed['public_after'])
            self.assertEqual(failed['failure'],'PUBLIC_RESULTS_UNAVAILABLE')
            comparison=h.compare(path);self.assertFalse(comparison['statistical_superiority_claimed'])
            self.assertFalse(comparison['hidden_suite_available'])
            self.assertEqual(comparison['arms']['auto']['public_after']['passed'],6)
            self.assertIsNone(comparison['arms']['gptoss']['public_after'])
            self.assertNotIn('PRIVATE',json.dumps(comparison))
            tampered={**plan,'role_profiles':{**plan['role_profiles'],'gptoss':h.assignments('auto')}}
            path.write_text(json.dumps(tampered));path.chmod(0o600)
            with self.assertRaisesRegex(h.Abort,'PLAN_CHANGED'): h.load_plan(path)
