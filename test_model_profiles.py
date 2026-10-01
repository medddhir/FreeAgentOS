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
import cli
import test_contract as contract


class P(unittest.TestCase):
    def test(self):
        # One table entry preserves the trusted runner's 64 KiB verbose-output cap.
        for case in (self.registry, self.commands, self.security, self.scope, self.identity, self.cli):
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
        self.assertEqual(len(mp.REGISTRY),3)
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
            with mp.profile_scope({name:'claude-free-auto'}):
                _,after,policy_b=fixture.capture(role,state)
                self.assertEqual(worker._effective_policy(None),original_resource)
                lease=ActivityLease(180,name,'model',True,240,0)
                self.assertFalse(lease.extend(180*NS))
                self.assertEqual(lease.evidence(180*NS,success=False)['hard_cap_ms'],240000)
            self.assertEqual(policy_a,policy_b)  # includes read/write/new lists and root identity
            self.assertEqual(after,['claude-free','--model','auto',*before[1:]])
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
