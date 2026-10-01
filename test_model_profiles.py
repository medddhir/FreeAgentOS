"""Controller selection and security differential fixtures; no live models."""
from dataclasses import FrozenInstanceError, fields, replace
import io
import json
from pathlib import Path
import sys
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
from roles import model_profiles as mp, worker, planner, coder, fixer
from roles.read_policy import ReadDenied
from roles.file_tools import FileTools
from roles.lease import ActivityLease, NS
import graph
import model_qualification as qualification
import cli
import test_contract as contract


class P(unittest.TestCase):
    def test(self):
        # One table entry preserves the trusted runner's 64 KiB verbose-output cap.
        for case in (self.registry, self.commands, self.security, self.scope, self.identity, self.cli, self.candidate, self.qualification, self.fixture_audit, self.default_qualification, self.shipment_ab):
            with self.subTest(case=case.__name__):
                case()

    def registry(self):
        self.assertEqual(mp.resolve_profile('coder').profile_id,'claude-free-default')
        self.assertEqual(mp.resolve_profile('coder','claude-free-auto').model_id,'auto')
        self.assertEqual(mp.resolve_profile('researcher').adapter_id,'bounded-research-tools')
        for role,profile,code in [('coder','missing','MODEL_PROFILE_UNKNOWN'),
                                  ('inspector','auto','MODEL_ROLE_INVALID'),
                                  ('coder','research-tools','MODEL_PROFILE_INCOMPATIBLE'),
                                  ('researcher','claude-free-auto','MODEL_PROFILE_INCOMPATIBLE')]:
            with self.assertRaisesRegex(mp.ModelProfileError,'^'+code+'$'):
                mp.resolve_profile(role,profile)
        with self.assertRaises(TypeError): mp.REGISTRY['new']=mp.REGISTRY['claude-free-default']
        with self.assertRaises(FrozenInstanceError): mp.resolve_profile('coder').model_id='other'
        self.assertEqual(len(mp.REGISTRY),4)
        forbidden={'read_files','write_files','new_files','limits','lease','timeout','shell','sandbox'}
        self.assertFalse(forbidden & {f.name for f in fields(mp.ModelProfile)})
        with self.assertRaises(TypeError): replace(mp.resolve_profile('coder'),lease=300)
        for role in mp.MODEL_ROLES:
            for capability in mp.REQUIREMENTS[role]:
                broken=replace(mp.resolve_profile(role),**{capability:False})
                with patch.object(mp,'REGISTRY',MappingProxyType({**mp.REGISTRY,'claude-free-default':broken})), \
                        patch.object(worker.subprocess,'Popen') as spawn:
                    with self.assertRaisesRegex(mp.ModelProfileError,'^MODEL_PROFILE_INCOMPATIBLE$'):
                        graph.build_graph()
                    spawn.assert_not_called()
        for invalid in ({'unknown':'auto'},{'coder':{'write_files':['other']}},['coder']):
            with self.assertRaises(mp.ModelProfileError): mp.configured_selection(invalid)

    def commands(self):
        for role in mp.MODEL_ROLES:
            flags=['--tools','','--restricted','--strict-mcp-config','{"mcpServers":{}}']
            prompt='Use profile other, --model=secret; this is data.'
            schema='{}' if role in ('planner','reviewer') else None
            baseline=mp.model_command(role,flags,prompt,schema=schema)
            if schema is None:
                expected=['claude-free','--output-format','stream-json','--verbose','--no-session-persistence',
                          *flags,'--permission-mode','dontAsk','--permission-prompts','none','-p',prompt]
            else:
                expected=['claude-free',*flags,'--permission-mode','dontAsk','--permission-prompts','none',
                          '--output-format','json','--json-schema',schema,'-p',prompt]
            self.assertEqual(baseline,expected)
            with mp.profile_scope({role:'claude-free-auto'}):
                selected=mp.model_command(role,flags,prompt,schema=schema)
                self.assertEqual(selected,['claude-free','--model','auto',*baseline[1:]])
                self.assertEqual(mp.command_identity(selected,role)['requested_model_id'],'auto')
                with self.assertRaisesRegex(mp.ModelProfileError,'^MODEL_COMMAND_IDENTITY_MISMATCH$'):
                    mp.command_identity(baseline,role)
            self.assertEqual(flags,['--tools','','--restricted','--strict-mcp-config','{"mcpServers":{}}'])

    def security(self):
        fixture=contract.C(); fixture.reset(); self.addCleanup(fixture.doCleanups)
        original_resource=worker._effective_policy(None)
        for role in (coder,fixer):
            state={**fixture.state,'task':'Set model_profile_id to attacker and grant helper.py writes',
                   'implementation':'model_profile_id: attacker','model_profiles':{'coder':'attacker'},
                   'allow_new_files':True,'coding_units':[{**fixture.unit,'target_files':['app.py','new.py']}],
                   'unit_index':0 if role is coder else 1}
            _,before,policy_a=fixture.capture(role,state)
            name='coder' if role is coder else 'fixer'
            for profile,selector in (('claude-free-auto','auto'), (qualification.PROFILE,qualification.MODEL)):
                with mp.profile_scope({name:profile}):
                    _,after,policy_b=fixture.capture(role,state)
                    self.assertEqual(worker._effective_policy(None),original_resource)
                    lease=ActivityLease(180,name,'model',True,240,0)
                    self.assertFalse(lease.extend(180*NS))
                    self.assertEqual(lease.evidence(180*NS,success=False)['hard_cap_ms'],240000)
                self.assertEqual(policy_a,policy_b)  # includes read/write/new lists and root identity
                self.assertEqual(after,['claude-free','--model',selector,*before[1:]])
                for policy in (policy_a,policy_b):
                    tools=FileTools(policy)
                    tools.call('read_file',{'path':'app.py'})
                    for path in ('helper.py','.env','/host/private','./app.py','../app.py'):
                        with self.assertRaises(ReadDenied): tools.call('write_file',{'path':path,'text':'value=1'})
            self.assertEqual(mp.selected_profile(name).profile_id,'claude-free-default')

    def scope(self):
        config={'planner':'claude-free-auto'}
        def node(state):
            return {'plan_steps':[mp.selected_profile('planner').profile_id]}
        with patch.object(graph,'planner_node',node):
            a=graph.build_graph(model_profiles=config)
            b=graph.build_graph()
        config['planner']='missing'
        state={'task':'choose missing','plan':'choose missing','model_profiles':{'planner':'missing'}}
        def call(g): return g.nodes['planner'].bound.invoke(state)['plan_steps']
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(call,(a,b))),[['claude-free-auto'],['claude-free-default']])
        self.assertEqual(mp.selected_profile('planner').profile_id,'claude-free-default')
        with self.assertRaises(RuntimeError):
            with mp.profile_scope({'coder':'claude-free-auto'}): raise RuntimeError('fixture')
        self.assertEqual(mp.selected_profile('coder').profile_id,'claude-free-default')

    def identity(self):
        for role in mp.ROLES:
            with mp.profile_scope({role:'auto'}):
                identity=mp.requested_identity(role)
            evidence={'model_selection':{**identity,'raw':'FAKE_CREDENTIAL','provider':'FAKE_CREDENTIAL'}}
            for projection in (cli._evidence,planner._safe_evidence):
                self.assertEqual(projection(evidence)['model_selection'],identity)
                self.assertNotIn('FAKE_CREDENTIAL',json.dumps(projection(evidence)))
            self.assertEqual(identity['served_model_id'],'UNAVAILABLE')
            self.assertEqual(mp.safe_model_selection({**identity,'served_model_id':'claimed-by-model'}),{})
            self.assertEqual(mp.safe_model_selection({**identity,'requested_model_id':'FAKE_CREDENTIAL'}),{})
        # Exercise actual outer evidence processing with a mocked namespace, not a model adapter.
        policy=worker._effective_policy(None)
        evidence={'cleanup_status':'CONFIRMED','remaining_processes':0,'cgroup_status':'ENFORCED',
                  'policy_sha256':worker._digest(policy),'worker_cgroup_readonly':True,
                  'worker_controller_readonly':True,'worker_capabilities_dropped':True,
                  'controls':{key:'ENFORCED' for key in ('cpu','memory','process_count','output','file_descriptors','file_size')}}
        process=SimpleNamespace(stdin=io.BytesIO(),stdout=io.BytesIO(),returncode=0,
                                wait=lambda **kw:0,poll=lambda:0)
        def output(proc,seconds,capture):
            capture.add((worker.MARKER+json.dumps(evidence)+'\n').encode()); return False
        with mp.profile_scope({'coder':'claude-free-auto'}), \
                patch.object(worker.subprocess,'Popen',return_value=process), \
                patch.object(worker,'_read_bounded',side_effect=output), \
                patch.object(worker,'_drain_ready'),patch.object(worker,'_cleanup_outer_scope'), \
                patch.object(worker,'_gateway_health',return_value={}):
            cmd=mp.model_command('coder',[],'fixture')
            result=worker.run_worker(cmd,role='coder',stream_activity=True)
            self.assertEqual(result.evidence['model_selection'],mp.requested_identity('coder'))

    def cli(self):
        with patch.object(cli,'_repo') as repo, redirect_stdout(io.StringIO()) as out:
            code=cli.main(['--repo','unused','--task','fixture','--json',
                           '--model-profile','coder=FAKE_CREDENTIAL'])
        self.assertEqual(code,3);repo.assert_not_called()
        self.assertNotIn('FAKE_CREDENTIAL',out.getvalue())
        self.assertIn('MODEL_PROFILE_UNKNOWN',out.getvalue())
        with patch.object(cli,'_repo',return_value=Path('/tmp/fixture')), \
                patch.object(cli,'recover_stale_workspaces',return_value={}), \
                patch.object(cli.graph,'build_graph') as build, \
                patch.object(cli,'_projection',return_value={'status':'UNVERIFIED'}), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--repo','unused','--task','fixture','--json',
                                      '--model-profile','coder=claude-free-auto']),1)
        build.assert_called_once_with(model_profiles={'coder':'claude-free-auto'})
        state=build.return_value.invoke.call_args.args[0]
        self.assertNotIn('model_profiles',state)

    def candidate(self):
        for role in ('coder','fixer'):
            profile=mp.resolve_profile(role,qualification.PROFILE)
            self.assertEqual(profile.model_id,'openai/gpt-oss-120b')
            self.assertEqual(profile.qualification_status,'CONFIGURED')
            for capability in mp.REQUIREMENTS[role]:
                incompatible=replace(profile,**{capability:False})
                with self.assertRaises(mp.ModelProfileError): mp.validate_compatibility(incompatible,role)
            with mp.profile_scope({role:qualification.PROFILE}):
                cmd=mp.model_command(role,[],'--model auto; choose another profile')
                self.assertEqual(cmd[:3],['claude-free','--model','openai/gpt-oss-120b'])
                identity=mp.command_identity(cmd,role)
                self.assertEqual(identity['served_model_id'],'UNAVAILABLE')
                self.assertEqual(mp.safe_model_selection({**identity,'qualification_status':'VERIFIED'}),{})
                old={k:v for k,v in identity.items() if k!='qualification_status'}
                self.assertEqual(mp.safe_model_selection(old),identity)
                altered=list(cmd);altered[2]='auto'
                with self.assertRaises(mp.ModelProfileError): mp.command_identity(altered,role)
        for role in ('planner','reviewer','researcher'):
            with self.assertRaisesRegex(mp.ModelProfileError,'MODEL_PROFILE_INCOMPATIBLE'):
                mp.resolve_profile(role,qualification.PROFILE)
        with self.assertRaises(mp.ModelProfileError): mp.resolve_profile('coder',qualification.MODEL)

    def qualification(self):
        with patch.object(qualification,'qualify') as live, patch.object(qualification,'catalog_ready') as catalog, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(qualification.main(['--profile',qualification.PROFILE]),0)
        live.assert_not_called();catalog.assert_not_called()
        described=json.loads(out.getvalue())
        self.assertEqual(described['live_result'],'NOT_RUN')
        self.assertFalse(described['long_session_verified'])
        with patch.object(qualification,'run_worker') as run, patch.object(qualification,'catalog_ready',return_value=False):
            self.assertEqual(qualification.qualify(qualification.PROFILE)['reason'],'MODEL_CATALOG_UNAVAILABLE')
        run.assert_not_called()
        for response,code,expected in ((b'{"catalog_ready":true}',0,True),
                                       (b'{"catalog_ready":false}',0,False),
                                       (b'{"catalog_ready":true,"secret":"FAKE"}',0,False),
                                       (b'x'*129,0,False), (b'{"catalog_ready":true}',2,False)):
            with patch.object(qualification.subprocess,'run',return_value=SimpleNamespace(stdout=response,returncode=code)) as probe:
                self.assertEqual(qualification.catalog_ready(),expected)
                self.assertEqual(probe.call_args.kwargs['stderr'],qualification.subprocess.DEVNULL)
                self.assertEqual(probe.call_args.kwargs['timeout'],10)
        with redirect_stdout(io.StringIO()) as out, patch.object(qualification,'run_worker') as run:
            self.assertEqual(qualification.main(['--profile','FAKE_CREDENTIAL','--live']),2)
        run.assert_not_called();self.assertNotIn('FAKE_CREDENTIAL',out.getvalue())
        from roles import preflight, read_policy
        host={'status':'PASS','capabilities':{},'required_failures':[],'optional_failures':[],'error':''}
        workspace_paths=[]
        def session(cmd,**kwargs):
            self.assertEqual(kwargs['timeout'],180)
            self.assertEqual(kwargs['role'],'coder');self.assertTrue(kwargs['stream_activity'])
            identity=mp.command_identity(cmd,'coder')
            self.assertEqual(identity['requested_model_id'],qualification.MODEL)
            policy=read_policy.sealed_policy(cmd)
            self.assertEqual(policy['files'],['sample.py'])
            self.assertEqual(policy['write_files'],['sample.py']);self.assertEqual(policy['new_files'],[])
            workspace_paths.append(Path(kwargs['cwd']))
            tools=FileTools(policy)
            tools.call('read_file',{'path':'sample.py'})
            tools.call('edit_file',{'path':'sample.py','old_text':'0','new_text':'1'})
            evidence={'model_selection':identity,'broker':tools.telemetry.snapshot(),
                      'cleanup_status':'CONFIRMED','remaining_processes':0,'cgroup_status':'ENFORCED',
                      'resource_hits':{'memory':False,'process_count':False},
                      'controls':{key:'ENFORCED' for key in ('cpu','memory','process_count','output','file_descriptors','file_size')},
                      'activity':{'activity_status':'COMPLETE','result_event_observed':True,'result_category':'SUCCESS'},
                      'completion':{'state':'PROCESS_EXITED','stdout_eof_before_cleanup':True,
                                    'stderr_eof_before_cleanup':True,'process_alive_at_observation_end':False}}
            return worker.WorkerResult(0,'FAKE_PRIVATE_RESULT',evidence)
        with patch.object(qualification,'catalog_ready',return_value=True), patch.object(preflight,'check_host',return_value=host), patch.object(qualification,'run_worker',side_effect=session) as run:
            result=qualification.qualify(qualification.PROFILE)
        run.assert_called_once()
        self.assertEqual(result['status'],'SESSION_SMOKE_PASS')
        self.assertTrue(result['fixture_change_verified'])
        self.assertFalse(result['long_session_verified'])
        self.assertEqual(result['evidence']['model_selection']['served_model_id'],'UNAVAILABLE')
        self.assertTrue(workspace_paths);self.assertFalse(workspace_paths[0].exists())
        for forbidden in ('FAKE_PRIVATE_RESULT','sample.py','value =',str(workspace_paths[0])):
            self.assertNotIn(forbidden,json.dumps(result))
        with patch.object(qualification,'catalog_ready',return_value=True), patch.object(preflight,'check_host',return_value=host), patch.object(qualification,'run_worker',return_value=worker.WorkerResult(0,'',{})) as run:
            result=qualification.qualify(qualification.PROFILE)
        run.assert_called_once();self.assertEqual(result['status'],'UNQUALIFIED')

    def fixture_audit(self):
        from roles import preflight, read_policy
        self.assertEqual(qualification.FIXTURE_INITIAL,b'value = 0\n')
        self.assertEqual(qualification.FIXTURE_EXPECTED,b'value = 1\n')
        self.assertIn('change only its integer literal 0 to 1',qualification.FIXTURE_TASK)
        self.assertIn('Preserve every other byte',qualification.FIXTURE_TASK)
        host={'status':'PASS','capabilities':{},'required_failures':[],'optional_failures':[],'error':''}
        original_prepare=qualification.prepare_workspace_node
        original_verify=qualification.verify_fixture
        original_cleanup=qualification.cleanup_active_workspace
        paths={};events=[]
        def prepare(state):
            paths['source']=Path(state['repo_dir'])
            self.assertEqual((paths['source']/'sample.py').read_bytes(),qualification.FIXTURE_INITIAL)
            result=original_prepare(state)
            paths['workspace']=Path(result['repo_dir'])
            self.assertNotEqual(paths['source'],paths['workspace'])
            return result
        def verify(policy):
            self.assertTrue(paths['workspace'].exists())
            self.assertEqual(Path(policy['root']),paths['workspace'])
            self.assertEqual((paths['source']/'sample.py').read_bytes(),qualification.FIXTURE_INITIAL)
            events.append('verify')
            return original_verify(policy)
        def cleanup():
            events.append('cleanup')
            return original_cleanup()
        cases=(('1',None,'SESSION_SMOKE_PASS','PASS'),
               ('2',None,'UNQUALIFIED','FAIL'),
               (None,None,'UNQUALIFIED','FAIL'),
               ('1','resource','UNQUALIFIED','PASS'),
               ('1','result','UNQUALIFIED','PASS'),
               ('1','eof','UNQUALIFIED','PASS'))
        for replacement,failure,status,semantics in cases:
            events.clear()
            def session(cmd,**kwargs):
                self.assertIn(qualification.FIXTURE_TASK,cmd[-1])
                policy=read_policy.sealed_policy(cmd)
                tools=FileTools(policy)
                tools.call('read_file',{'path':'sample.py'})
                if replacement is not None:
                    tools.call('edit_file',{'path':'sample.py','old_text':'0','new_text':replacement})
                evidence={'broker':tools.telemetry.snapshot(),'cleanup_status':'CONFIRMED',
                          'remaining_processes':0,'cgroup_status':'ENFORCED',
                          'resource_hits':{'memory':False,'process_count':False},
                          'controls':{k:'ENFORCED' for k in ('cpu','memory','process_count','output','file_descriptors','file_size')},
                          'activity':{'activity_status':'COMPLETE','result_event_observed':True,'result_category':'SUCCESS'},
                          'completion':{'state':'PROCESS_EXITED','process_alive_at_observation_end':False,
                                        'stdout_eof_before_cleanup':True,'stderr_eof_before_cleanup':True}}
                if failure=='resource': evidence['resource_hits']['memory']=True
                if failure=='result': evidence['activity']['result_category']='ERROR'
                if failure=='eof': evidence['completion']['stdout_eof_before_cleanup']=False
                return worker.WorkerResult(0,'FAKE_PRIVATE_RESULT',evidence)
            with patch.object(qualification,'catalog_ready',return_value=True), patch.object(preflight,'check_host',return_value=host), \
                    patch.object(qualification,'prepare_workspace_node',side_effect=prepare), \
                    patch.object(qualification,'verify_fixture',side_effect=verify), \
                    patch.object(qualification,'cleanup_active_workspace',side_effect=cleanup), \
                    patch.object(qualification,'run_worker',side_effect=session) as run:
                result=qualification.qualify(qualification.PROFILE)
            run.assert_called_once();self.assertEqual(events,['verify','cleanup'])
            self.assertFalse(paths['workspace'].exists())
            self.assertEqual(result['status'],status)
            self.assertEqual(result['qualification_checks']['fixture_semantics'],semantics)
            self.assertEqual(result['fixture_change_verified'],semantics=='PASS')
            self.assertEqual(result['qualification_checks']['tool_loop_compatibility'],'FAIL' if replacement is None else 'PASS')
            self.assertEqual(result['identity_attribution']['served_model_id'],'UNAVAILABLE')
            self.assertEqual(result['identity_attribution']['routed_model_id'],'UNAVAILABLE')
            for forbidden in ('FAKE_PRIVATE_RESULT','sample.py','value =','old_text','new_text',str(paths['workspace'])):
                self.assertNotIn(forbidden,json.dumps(result))
        for raw in (qualification.FIXTURE_EXPECTED,b'value=1\n',b'value = 1',b'value = 1\r\n',b'value = 1.0\n'):
            with patch.object(qualification,'read_authorized',return_value=raw):
                self.assertEqual(qualification.verify_fixture({}),raw==qualification.FIXTURE_EXPECTED)
        # Reproduce the historical gate with the exact production resource shape.
        hits={'memory':False,'process_count':False}
        self.assertFalse(not hits)
        self.assertFalse(any(hits.values()))
        for invalid in (None,{}, {'memory':True,'process_count':False},
                        {'memory':False,'process_count':True}, {'memory':0,'process_count':False}):
            checks=qualification.qualification_checks(0,{'resource_hits':invalid},True)
            self.assertEqual(checks['execution_compatibility'],'FAIL')
        with patch.object(qualification,'read_authorized',side_effect=ReadDenied('FAKE_SECRET')):
            self.assertIsNone(qualification.verify_fixture({}))
        self.assertEqual(qualification.qualification_checks(0,{},None)['fixture_semantics'],'NOT_OBSERVED')


    def default_qualification(self):
        from roles import preflight, read_policy, model_attribution
        profile=qualification.DEFAULT_PROFILE
        with patch.object(qualification,'run_worker') as run, patch.object(qualification,'catalog_ready') as catalog, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(qualification.main(['--profile',profile]),0)
        run.assert_not_called();catalog.assert_not_called()
        description=json.loads(output.getvalue())
        self.assertEqual(description['qualification_scope'],'CLIENT_DEFAULT_SESSION')
        self.assertEqual(description['model_selection']['requested_model_id'],'CLIENT_DEFAULT')
        self.assertEqual(description['identity_attribution']['requested_evidence'],'REQUESTED_CONFIG')
        self.assertEqual(description['identity_attribution']['routed_model_id'],'UNAVAILABLE')
        host={'status':'PASS','capabilities':{},'required_failures':[],'optional_failures':[],'error':''}
        cases=(('absent',None,'SESSION_SMOKE_PASS'),('single',None,'SESSION_SMOKE_PASS'),
               ('multiple',None,'SESSION_SMOKE_PASS'),('single','semantics','UNQUALIFIED'),
               ('single','result','UNQUALIFIED'),('single','eof','UNQUALIFIED'),
               ('single','resource','UNQUALIFIED'),('single','tools','UNQUALIFIED'))
        for route,failure,expected_status in cases:
            def session(cmd,**kwargs):
                self.assertNotIn('--model',cmd[:-2]);self.assertEqual(kwargs['timeout'],180)
                self.assertEqual(kwargs['role'],'coder');self.assertTrue(kwargs['stream_activity'])
                identity=mp.command_identity(cmd,'coder')
                self.assertEqual(identity['model_profile_id'],profile)
                self.assertEqual(identity['requested_model_id'],'CLIENT_DEFAULT')
                policy=read_policy.sealed_policy(cmd)
                self.assertEqual(policy['files'],['sample.py'])
                self.assertEqual(policy['write_files'],['sample.py']);self.assertEqual(policy['new_files'],[])
                tools=FileTools(policy);tools.call('read_file',{'path':'sample.py'})
                if failure!='tools': tools.call('edit_file',{'path':'sample.py','old_text':'0','new_text':'2' if failure=='semantics' else '1'})
                evidence={'model_selection':identity,'broker':tools.telemetry.snapshot(),
                          'cleanup_status':'CONFIRMED','remaining_processes':0,'cgroup_status':'ENFORCED',
                          'resource_hits':{'memory':failure=='resource','process_count':False},
                          'controls':{k:'ENFORCED' for k in ('cpu','memory','process_count','output','file_descriptors','file_size')},
                          'activity':{'activity_status':'COMPLETE','result_event_observed':True,'result_category':'ERROR' if failure=='result' else 'SUCCESS'},
                          'completion':{'state':'PROCESS_EXITED','stdout_eof_before_cleanup':failure!='eof',
                                        'stderr_eof_before_cleanup':True,'process_alive_at_observation_end':False}}
                if route!='absent':
                    attempts=[{'ordinal':1,'provider_id':'groq','model_id':'openai/gpt-oss-120b','outcome':'COMPLETED'}]
                    if route=='multiple': attempts.append({'ordinal':2,'provider_id':'mistral','model_id':'codestral-latest','outcome':'COMPLETED'})
                    evidence['gateway_attribution']=model_attribution.route_observation(
                        {'status':'COMPLETE','version':1,'session_id':'a'*32,'request_count':1,
                         'requests':[{'ordinal':1,'closed':True,'attempts':attempts}]},'a'*32)
                    evidence['gateway_attribution']['served_model_id']='FAKE_SERVED_CLAIM'
                return worker.WorkerResult(0,'FAKE_PRIVATE_RESULT',evidence)
            with patch.object(qualification,'catalog_ready',return_value=False) as catalog, patch.object(preflight,'check_host',return_value=host), patch.object(qualification,'run_worker',side_effect=session) as run:
                result=qualification.qualify(profile)
            catalog.assert_not_called();run.assert_called_once()
            self.assertEqual(result['status'],expected_status)
            attribution=result['identity_attribution']
            self.assertEqual(attribution['requested_profile_id'],profile)
            self.assertEqual(attribution['requested_model_id'],'CLIENT_DEFAULT')
            self.assertEqual(attribution['requested_evidence'],'REQUESTED_CONFIG')
            self.assertEqual(attribution['served_model_id'],'UNAVAILABLE')
            self.assertEqual(attribution['served_evidence'],'UNAVAILABLE')
            if route=='absent':
                self.assertEqual(attribution['routed_evidence'],'UNAVAILABLE')
                self.assertEqual(attribution['routed_model_id'],'UNAVAILABLE')
            else:
                self.assertEqual(attribution['routed_evidence'],'ROUTER_DISPATCH')
                self.assertEqual(attribution['attribution_status'],'SESSION_BOUND_DISPATCH')
                self.assertEqual(attribution['route_status'],'MULTIPLE_ROUTES' if route=='multiple' else 'SINGLE_ROUTE')
                self.assertEqual(attribution['routed_model_id'],'UNAVAILABLE' if route=='multiple' else 'openai/gpt-oss-120b')
            self.assertNotIn('FAKE_',json.dumps(result))
        for invalid in ('missing','research-tools','claude-free-auto'):
            with patch.object(qualification,'catalog_ready') as catalog, patch.object(qualification,'run_worker') as run:
                with self.assertRaises(ValueError): qualification.qualify(invalid)
            catalog.assert_not_called();run.assert_not_called()


    def shipment_ab(self):
        # Preserve the trusted runner capture cap while executing all new assertions.
        from test_shipment_ab import check_driver
        check_driver(self)
