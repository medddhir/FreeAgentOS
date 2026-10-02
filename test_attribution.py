"""Requested/dispatch/upstream boundaries, no provider traffic or payload logs."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
from roles import model_profiles as profiles, model_attribution as attribution, worker
from roles.read_policy import file_tool_flags, sealed_policy
from roles.lease import ActivityLease, NS
import model_qualification as qualification
import test_contract as contract


class I(unittest.TestCase):
    def test(self):
        # Grouped to preserve the existing trusted runner's bounded verbose output.
        self.assertEqual(attribution.EVIDENCE_LEVELS,
                         ('REQUESTED_CONFIG','ROUTER_DISPATCH','UPSTREAM_REPORTED','UNAVAILABLE'))
        for role in profiles.MODEL_ROLES:
            for profile in ('claude-free-default','claude-free-auto'):
                with profiles.profile_scope({role:profile}):
                    identity=attribution.attribution_for(role)
                    before=profiles.model_command(role,[],'fixture',schema='{}' if role in ('planner','reviewer') else None)
                    for _ in range(2): attribution.attribution_for(role)
                    self.assertEqual(before,profiles.model_command(role,[],'fixture',schema='{}' if role in ('planner','reviewer') else None))
                self.assertEqual(identity['requested_evidence'],'REQUESTED_CONFIG')
                self.assertEqual(identity['routed_provider_id'],'UNAVAILABLE')
                self.assertEqual(identity['routed_model_id'],'UNAVAILABLE')
                self.assertEqual(identity['served_model_id'],'UNAVAILABLE')
                self.assertEqual(attribution.safe_attribution(identity),identity)
                for field in ('routed_evidence','served_evidence'):
                    self.assertEqual(identity[field],'UNAVAILABLE')
                # A claimed label, echoed model, route header or provider payload
                # never establishes a trusted controller-bound channel.
                for field,value in (('served_model_id',identity['requested_model_id']),
                                    ('routed_model_id','openai/gpt-oss-120b'),
                                    ('routed_provider_id','groq'),('routed_evidence','ROUTER_DISPATCH'),
                                    ('served_evidence','UPSTREAM_REPORTED'),('served_evidence','FAKE_SECRET')):
                    self.assertEqual(attribution.safe_attribution({**identity,field:value}),{})
                raw={'model':identity['requested_model_id'],
                     'headers':{'X-Routed-Via':'groq/openai/gpt-oss-120b','Authorization':'FAKE_SECRET'},
                     'prompt':'FAKE_PROMPT','choices':[{'text':'FAKE_COT','arguments':'FAKE_ARGS'}],
                     'path':'/FAKE_PRIVATE_PATH'}
                self.assertEqual(attribution.safe_attribution(raw),{})
                self.assertEqual(attribution.safe_attribution({**identity,**raw}),identity)
                self.assertNotIn('FAKE_',json.dumps(attribution.safe_attribution({**identity,**raw})))
        for value in (None,[],{'requested_profile_id':'FAKE_SECRET'}):
            self.assertEqual(attribution.safe_attribution(value),{})
        fixture=contract.C();fixture.reset();self.addCleanup(fixture.doCleanups)
        resource=worker._effective_policy(None)
        for role in ('coder','fixer'):
            flags=file_tool_flags(fixture.state,role,unit=fixture.unit)
            baseline=sealed_policy(flags)
            with profiles.profile_scope({role:qualification.PROFILE}):
                self.assertEqual(attribution.attribution_for(role)['requested_model_id'],qualification.MODEL)
                self.assertEqual(sealed_policy(file_tool_flags(fixture.state,role,unit=fixture.unit)),baseline)
                self.assertEqual(worker._effective_policy(None),resource)
                lease=ActivityLease(180,role,'model',True,240,0)
                attribution.attribution_for(role)
                self.assertFalse(lease.extend(180*NS))
                self.assertEqual(lease.evidence(180*NS,success=False)['hard_cap_ms'],240000)
        with patch.object(qualification,'qualify') as live, patch.object(qualification,'catalog_ready') as catalog, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(qualification.main(['--profile',qualification.PROFILE]),0)
        live.assert_not_called();catalog.assert_not_called()
        described=json.loads(output.getvalue())
        self.assertEqual(described['identity_attribution']['requested_model_id'],qualification.MODEL)
        self.assertEqual(described['identity_attribution']['served_evidence'],'UNAVAILABLE')
        self.assertEqual(described['live_result'],'NOT_RUN')
        with patch.object(qualification,'qualify',return_value=described) as live, redirect_stdout(io.StringIO()):
            self.assertEqual(qualification.main(['--profile',qualification.PROFILE,'--live']),0)
        live.assert_called_once_with(qualification.PROFILE)  # mocked; no generation
        with patch.object(qualification,'qualify',side_effect=RuntimeError('FAKE_SECRET')) as live, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(qualification.main(['--profile',qualification.PROFILE,'--live']),2)
        self.assertNotIn('FAKE_SECRET',output.getvalue())
        self.assertEqual(profiles.selected_profile('coder').profile_id,'claude-free-default')
        self.session_binding()
        self.lifecycle_diagnostics()

    def session_binding(self):
        import os,socket,tempfile,threading,subprocess
        import cli
        sid='a'*32
        def payload(session_id=sid):
            return {'status':'COMPLETE','version':1,'session_id':session_id,'request_count':2,
                    'requests':[{'ordinal':i,'closed':True,'attempts':[{'ordinal':1,'provider_id':'groq',
                      'model_id':'openai/gpt-oss-120b','outcome':'COMPLETED'}]} for i in (1,2)]}
        good=attribution.route_observation(payload(),sid)
        # Active transport and attribution cannot affect sealed capabilities or resources.
        fixture=contract.C();fixture.reset();self.addCleanup(fixture.doCleanups)
        baseline=sealed_policy(file_tool_flags(fixture.state,'coder',unit=fixture.unit))
        resource=worker._effective_policy(None)
        active=attribution.GatewaySession();active.token='c'*64
        with active.scope():
            self.assertEqual(sealed_policy(file_tool_flags(fixture.state,'coder',unit=fixture.unit)),baseline)
            self.assertEqual(worker._effective_policy(None),resource)
            lease=ActivityLease(180,'coder','model',True,240,0)
            self.assertFalse(lease.extend(180*NS))
            self.assertEqual(lease.evidence(180*NS,success=False)['hard_cap_ms'],240000)
        self.assertIsNone(attribution.current_transport())
        self.assertEqual(good['route_status'],'SINGLE_ROUTE')
        self.assertEqual(good['routed_evidence'],'ROUTER_DISPATCH')
        many=payload();many['requests'][1]['attempts'][0].update(provider_id='mistral',model_id='codestral-latest')
        observed=attribution.route_observation(many,sid)
        self.assertEqual(observed['route_status'],'MULTIPLE_ROUTES');self.assertEqual(observed['routed_model_id'],'UNAVAILABLE')
        for field,value in (('status','INCOMPLETE'),('session_id','b'*32),('request_count',3),('version',0)):
            bad=payload();bad[field]=value
            self.assertEqual(attribution.route_observation(bad,sid)['routed_evidence'],'UNAVAILABLE')
        bad=payload();bad['requests'][0]['attempts'][0]['model_id']='https://FAKE_SECRET'
        self.assertEqual(attribution.route_observation(bad,sid)['routed_evidence'],'UNAVAILABLE')
        for field,value in (('closed',False),('ordinal',2),('attempts',[])):
            bad=payload();bad['requests'][0][field]=value
            self.assertEqual(attribution.route_observation(bad,sid)['routed_evidence'],'UNAVAILABLE')
        self.assertNotIn('FAKE_SECRET',json.dumps(cli._evidence({'gateway_attribution':{**good,'headers':'FAKE_SECRET','served_model_id':'FAKE_SECRET'}})))
        with tempfile.TemporaryDirectory(prefix='freeagent-attribution-test-') as tmp:
            os.chmod(tmp,0o700);path=Path(tmp)/'gateway.sock'
            server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(path));os.chmod(path,0o600);server.listen(4);server.settimeout(.1)
            stop=threading.Event();seen=[]
            def serve():
                while not stop.is_set():
                    try: connection,_=server.accept()
                    except socket.timeout: continue
                    except OSError: break
                    with connection:
                        raw=connection.recv(1024);request=json.loads(raw);seen.append(request['op'])
                        reply=({'status':'REGISTERED','token':'c'*64} if request['op']=='register' else payload(request['session_id']))
                        connection.sendall(json.dumps(reply).encode()+b'\n')
            thread=threading.Thread(target=serve,daemon=True);thread.start()
            try:
                session=attribution.GatewaySession(path,os.getuid())
                def execute(cmd,**kwargs):
                    self.assertEqual(attribution.current_transport()['session_id'],session.session_id)
                    env=attribution.transport_environment(attribution.current_transport())
                    self.assertIn('X-FreeAgentOS-Attribution-Session: '+session.session_id,env['ANTHROPIC_CUSTOM_HEADERS'])
                    self.assertNotIn(session.session_id,json.dumps(cmd));self.assertEqual(kwargs['timeout'],180)
                    return worker.WorkerResult(0,'FAKE_MODEL_TEXT',{'gateway_attribution':{'served_model_id':'MODEL_CLAIM'}})
                with patch.object(attribution,'GatewaySession',return_value=session),patch.object(worker,'_run_worker_impl',side_effect=execute) as run:
                    result=worker.run_worker(['claude-free','-p','FAKE_TASK'],role='coder',timeout=180)
                run.assert_called_once();self.assertEqual(seen,['register','finish'])
                self.assertEqual(result.evidence['gateway_attribution'],good)
                self.assertIsNone(session.token);self.assertIsNone(attribution.current_transport())
                self.assertNotIn('MODEL_CLAIM',json.dumps(result.evidence))
                self.assertNotIn('c'*64,json.dumps(result.evidence))
                os.chmod(path,0o666)
                denied=attribution.GatewaySession(path,os.getuid());denied.begin();self.assertIsNone(denied.token)
                self.assertEqual(denied.finish()['routed_evidence'],'UNAVAILABLE')
            finally:
                stop.set();server.close();thread.join(timeout=1)
        # Observer failures must leave invocation/return untouched, without retry.
        with patch.object(attribution,'GatewaySession',side_effect=OSError('FAKE_SECRET')),patch.object(worker,'_run_worker_impl',return_value=worker.WorkerResult(0,'',{})) as run:
            self.assertEqual(worker.run_worker(['claude-free','-p','fixture']).returncode,0)
        run.assert_called_once()
        transport={'session_id':sid,'token':'c'*64}
        with patch.dict(os.environ,{'ANTHROPIC_CUSTOM_HEADERS':'x-FREEAGENTOS-attribution-session: bad\nx-freeagentos-attribution-token: bad\nOther-Header: retained'}):
            env=attribution.transport_environment(transport)
        self.assertNotIn(': bad',env['ANTHROPIC_CUSTOM_HEADERS']);self.assertIn('Other-Header: retained',env['ANTHROPIC_CUSTOM_HEADERS'])
        # Execute only the installed client's extracted header parser, not Claude.
        binary=Path('/root/.local/share/claude/versions/2.1.284').read_bytes()
        start=binary.index(b'function $at(){');end=binary.index(b'var YLe=',start)
        parser=binary[start:end].decode()
        self.assertIn(b'ne=$at(),ge=',binary);self.assertIn(b'defaultHeaders:ge',binary)
        wrapper=Path('/usr/local/bin/claude-free').read_text()
        self.assertIn('exec claude "$@"',wrapper);self.assertNotIn('unset ANTHROPIC_CUSTOM_HEADERS',wrapper)
        script='function I0(){return false}function wbn(){return null}function t(){}'+parser+';let h=$at();if(h["X-FreeAgentOS-Attribution-Session"]!==process.env.TEST_SESSION)process.exit(2);if(h["X-FreeAgentOS-Attribution-Token"]!==process.env.TEST_TOKEN)process.exit(3);'
        parser_env={**os.environ,'ANTHROPIC_CUSTOM_HEADERS':attribution.transport_environment(transport)['ANTHROPIC_CUSTOM_HEADERS'],'TEST_SESSION':sid,'TEST_TOKEN':'c'*64}
        checked=subprocess.run(['/usr/bin/node','-e',script],env=parser_env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
        self.assertEqual(checked.returncode,0);self.assertEqual(checked.stdout,b'')


    def lifecycle_diagnostics(self):
        """Pure simulations: no gateway/client/provider is contacted."""
        import cli
        import copy
        def reply(sid, status='COMPLETE', multiple=False):
            return {'status':status, 'version':1, 'session_id':sid, 'request_count':1,
                    'requests':[{'ordinal':1, 'closed':True, 'attempts':[
                        {'ordinal':1,'provider_id':'groq','model_id':'openai/gpt-oss-120b','outcome':'COMPLETED'},
                        *([{'ordinal':2,'provider_id':'nvidia','model_id':'openai/gpt-oss-20b','outcome':'FAILED'}] if multiple else [])]}]}
        # Cases A / D and normal, base timeout, grace completion and hard-cap paths.
        for code, phase, multiple in ((0,'NORMAL_COMPLETE',False), (124,'BASE_TIMEOUT',False),
                                      (0,'GRACE_COMPLETE',False), (124,'HARD_CAP_TIMEOUT',True),
                                      (1,'PROCESS_EXITED_NO_RESULT',False)):
            session=attribution.GatewaySession(); events=[]
            def exchange(op):
                events.append(op)
                if op=='register': return {'status':'REGISTERED','token':'c'*64}
                self.assertEqual(events[-2],'cleanup')
                return reply(session.session_id, multiple=multiple)
            def execute(*args,**kwargs):
                self.assertTrue(attribution.valid_transport(attribution.current_transport()))
                events.append('cleanup')
                return worker.WorkerResult(code,'',{'cleanup_status':'CONFIRMED',
                    'attribution_headers_configured':True,'worker_phase':phase})
            with patch.object(attribution,'GatewaySession',return_value=session), patch.object(session,'_exchange',side_effect=exchange), patch.object(worker,'_run_worker_impl',side_effect=execute):
                result=worker.run_worker(['claude-free'],timeout=180,stream_activity=True)
            self.assertEqual(events,['register','cleanup','finish'])
            self.assertEqual(result.returncode,code)
            route=result.evidence['gateway_attribution']; diag=result.evidence['attribution_diagnostics']
            self.assertEqual(route['route_status'],'MULTIPLE_ROUTES' if multiple else 'SINGLE_ROUTE')
            self.assertEqual(diag['registration_status'],'REGISTERED')
            self.assertTrue(diag['registration_attempted']); self.assertTrue(diag['finish_attempted'])
            self.assertTrue(diag['custom_headers_configured'])
            self.assertEqual(diag['finish_ipc_status'],'SUCCESS')
            self.assertEqual(diag['gateway_record_status'],'COMPLETE')
            self.assertEqual(diag['projection_reason'],'ACCEPTED')
            self.assertEqual(diag['settled_count'],1);self.assertEqual(diag['unsettled_count'],0)
            self.assertEqual(diag['route_count'],2 if multiple else 1)
            self.assertEqual(diag['overflow'],'UNAVAILABLE')
            self.assertNotIn('served_model_id',route)
            self.assertIsNone(session.token)
            self.assertNotIn(session.session_id,json.dumps(result.evidence))
            self.assertNotIn('c'*64,json.dumps(result.evidence))
        # B: incomplete settled state is explained but never accepted.
        session=attribution.GatewaySession(); sid=session.session_id
        incomplete=reply(sid,'INCOMPLETE');incomplete['requests'][0]['closed']=False
        incomplete['requests'][0]['attempts'][0]['outcome']='DISPATCHED'
        for payload, reason, record in ((incomplete,'INCOMPLETE','INCOMPLETE'),
            ({'status':'INCOMPLETE','version':1,'session_id':sid,'requests':[],'request_count':0},'NO_ROUTE_OBSERVED','INCOMPLETE'),
            ({'status':'UNAVAILABLE'},'SESSION_UNAVAILABLE','SESSION_UNAVAILABLE'),
            ({**reply(sid),'session_id':'b'*32},'INVALID_EVIDENCE','INVALID_EVIDENCE'),
            ({**reply(sid),'request_count':999999},'BOUNDS_REJECTED','COMPLETE')):
            session=attribution.GatewaySession();session.session_id=sid
            with patch.object(session,'_exchange',side_effect=[{'status':'REGISTERED','token':'c'*64},payload]):
                session.begin();observed=session.finish()
            self.assertEqual(observed['routed_evidence'],'UNAVAILABLE')
            self.assertEqual(session.diagnostics['projection_reason'],reason)
            self.assertEqual(session.diagnostics['gateway_record_status'],record)
            if reason=='INCOMPLETE':
                self.assertEqual(session.diagnostics['unsettled_count'],1)
                self.assertEqual(session.diagnostics['settled_count'],0)
        # C: registration failure never configures owned headers or blocks work.
        for failure, expected in ((OSError('FAKE_SECRET'),'IPC_FAILURE'),
                                  (ValueError('ATTRIBUTION_PEER_INVALID'),'PEER_INVALID'),
                                  (ValueError('ATTRIBUTION_BOUNDS'),'IPC_BOUNDS')):
            session=attribution.GatewaySession()
            def execute(*args,**kwargs):
                self.assertIsNone(attribution.current_transport())
                return worker.WorkerResult(0,'',{})
            with patch.object(attribution,'GatewaySession',return_value=session), patch.object(session,'_exchange',side_effect=[failure,{'status':'UNAVAILABLE'}]), patch.object(worker,'_run_worker_impl',side_effect=execute):
                result=worker.run_worker(['claude-free'])
            diag=result.evidence['attribution_diagnostics']
            self.assertEqual(diag['registration_status'],expected)
            self.assertFalse(diag['custom_headers_configured'])
            self.assertEqual(diag['projection_reason'],'REGISTRATION_UNAVAILABLE')
            self.assertNotIn('FAKE_SECRET',json.dumps(result.evidence))
        # Finish transport failures distinct from gateway record failures.
        session=attribution.GatewaySession()
        with patch.object(session,'_exchange',side_effect=[{'status':'REGISTERED','token':'c'*64},OSError('FAKE_SECRET')]):
            session.begin(); observed=session.finish()
        self.assertEqual(observed['route_status'],'UNAVAILABLE')
        self.assertEqual(session.diagnostics['finish_ipc_status'],'IPC_FAILURE')
        self.assertEqual(session.diagnostics['projection_reason'],'IPC_FAILURE')
        # Request overflow is proven by the saturated counter; no route acceptance.
        overflow=reply(sid,'INCOMPLETE');overflow['request_count']=65
        overflow['requests']=[{**copy.deepcopy(overflow['requests'][0]),'ordinal':i} for i in range(1,65)]
        diag=attribution.record_diagnostics(overflow,sid,attribution.route_observation(overflow,sid))
        self.assertTrue(diag['overflow']);self.assertEqual(diag['projection_reason'],'BOUNDS_REJECTED')
        # Errors retain diagnostics after finish; execution still raises unchanged.
        session=attribution.GatewaySession(); failure=worker.WorkerBoundaryError('WORKER_EVIDENCE_MISSING')
        with patch.object(attribution,'GatewaySession',return_value=session), patch.object(session,'_exchange',side_effect=[{'status':'REGISTERED','token':'c'*64},reply(session.session_id)]), patch.object(worker,'_run_worker_impl',side_effect=failure):
            with self.assertRaises(worker.WorkerBoundaryError):worker.run_worker(['claude-free'])
        self.assertEqual(failure.evidence['attribution_diagnostics']['finish_ipc_status'],'SUCCESS')
        # Instrumentation failure cannot change already accepted route evidence.
        session=attribution.GatewaySession()
        with patch.object(session,'_exchange',side_effect=[{'status':'REGISTERED','token':'c'*64},reply(session.session_id)]), patch.object(attribution,'record_diagnostics',side_effect=OSError('FAKE_SECRET')):
            session.begin(); observed=session.finish()
        self.assertEqual(observed['routed_evidence'],'ROUTER_DISPATCH')
        self.assertEqual(session.diagnostics['projection_reason'],'DIAGNOSTIC_FAILURE')
        self.assertNotIn('FAKE_SECRET',json.dumps(session.diagnostics))
        # Old payload works without new gateway fields; malicious diagnostics discarded.
        route=attribution.route_observation(reply(sid),sid)
        projected=cli._evidence({'gateway_attribution':route,'attribution_diagnostics':{
            'projection_reason':'FAKE_SECRET','request_count':999999,'token':'FAKE_SECRET',
            'headers':'FAKE_SECRET','prompt':'FAKE_SECRET','raw':'FAKE_SECRET','overflow':[]}})
        self.assertEqual(projected['gateway_attribution'],route)
        self.assertNotIn('FAKE_SECRET',json.dumps(projected))
        self.assertEqual(projected['attribution_diagnostics']['request_count'],'UNAVAILABLE')
        self.assertEqual(projected['attribution_diagnostics']['projection_reason'],'UNAVAILABLE')
        self.assertEqual(attribution.safe_attribution_diagnostics(None),attribution.diagnostic_defaults())
