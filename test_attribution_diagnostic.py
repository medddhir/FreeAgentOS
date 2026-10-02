"""One-shot diagnostic: all model execution boundaries mocked."""
from contextlib import contextmanager
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from contextlib import redirect_stdout
sys.path.insert(0,str(Path(__file__).parent/'orchestrator'))
import attribution_diagnostic as d
from roles import model_attribution as a, worker


def check_diagnostic(self):
    # Grouped to keep the trusted test runner's verbose output bounded.
    with patch.object(d,'prepare',return_value={'status':'DRY_RUN_PASS'}) as dry, patch.object(d,'live') as live, redirect_stdout(io.StringIO()):
        self.assertEqual(d.main(['--expected-controller',d.CHECKPOINT]),0)
    dry.assert_called_once_with(d.CHECKPOINT);live.assert_not_called()
    with patch.object(d,'prepare') as dry, patch.object(d,'live') as live, redirect_stdout(io.StringIO()) as out:
        self.assertEqual(d.main(['--expected-controller',d.CHECKPOINT,'--live','--dry-run']),2)
    dry.assert_not_called();live.assert_not_called();self.assertNotIn('Traceback',out.getvalue())
    with patch.object(d,'git',side_effect=[d.CHECKPOINT,'DIRTY']),patch.object(d,'run_worker') as run:
        with self.assertRaisesRegex(d.Blocked,'CONTROLLER_DIRTY'):d.controller_check(d.CHECKPOINT)
    run.assert_not_called()
    # Dry preparation uses real read-only policy/workspace/preflight only.
    with tempfile.TemporaryDirectory() as tmp:
        base=Path(tmp);w=base/'fixture';e=base/'evidence'
        with patch.object(d,'WORKSPACE',w),patch.object(d,'EVIDENCE',e),patch.object(d,'controller_check'),patch.object(d,'environment_check'),patch.object(d,'run_worker') as no_model:
            result=d.prepare(d.CHECKPOINT)
            self.assertEqual(result['status'],'DRY_RUN_PASS')
            self.assertEqual(result['attempt_status'],'NOT_RUN')
            self.assertFalse(result['worker_spawned']);self.assertFalse(w.exists());self.assertFalse(e.exists())
            no_model.assert_not_called()
    route={'routed_provider_id':'groq','routed_model_id':d.MODEL,'routed_evidence':'ROUTER_DISPATCH',
           'route_status':'SINGLE_ROUTE','routes':[{'provider_id':'groq','model_id':d.MODEL}]}
    diag={**a.diagnostic_defaults(),'registration_attempted':True,'registration_status':'REGISTERED',
          'custom_headers_configured':True,'finish_attempted':True,'finish_ipc_status':'SUCCESS',
          'gateway_record_status':'COMPLETE','request_count':1,'settled_count':1,'unsettled_count':0,
          'attempt_count':1,'route_count':1,'projection_status':'ACCEPTED','projection_reason':'ACCEPTED'}
    ev={'gateway_attribution':route,'attribution_diagnostics':diag,'worker_process_spawn_ms':1,
        'worker_phase':'NORMAL_COMPLETE','cleanup_status':'CONFIRMED','remaining_processes':0,
        'completion':{'state':'PROCESS_EXITED'},'lease':{'base_ms':180000,'hard_cap_ms':240000}}
    result=d.output(ev,0)
    self.assertEqual(result['status'],'DIAGNOSTICS_VALIDATED')
    self.assertEqual(result['attempt_status'],'ATTEMPTED')
    self.assertEqual(result['served_model_id'],'UNAVAILABLE')
    incomplete_diag=dict(diag)
    for field,value in (('gateway_record_status','INCOMPLETE'),('projection_status','REJECTED'),('projection_reason','INCOMPLETE'),('settled_count',0),('unsettled_count',1)):
        incomplete_diag[field]=value
    incomplete=d.output({**ev,'gateway_attribution':None,'attribution_diagnostics':incomplete_diag},124)
    self.assertEqual(incomplete['status'],'DIAGNOSTICS_VALIDATED')
    self.assertEqual(incomplete['routed_evidence'],'UNAVAILABLE')
    self.assertEqual(incomplete['served_model_id'],'UNAVAILABLE')
    self.assertEqual(incomplete['attribution_diagnostics']['gateway']['unsettled_count'],1)
    failed={**ev,'gateway_attribution':None,'attribution_diagnostics':{**a.diagnostic_defaults(),
        'registration_attempted':True,'registration_status':'IPC_FAILURE','custom_headers_configured':False,
        'finish_attempted':True,'finish_ipc_status':'IPC_FAILURE','projection_status':'UNAVAILABLE','projection_reason':'IPC_FAILURE'}}
    self.assertEqual(d.output(failed,0)['status'],'DIAGNOSTICS_VALIDATED')
    self.assertEqual(d.output({},0)['status'],'BLOCKED')
    self.assertEqual(d.output({'worker_phase':'PROCESS_NEVER_STARTED'},1)['attempt_status'],'NOT_RUN')
    self.assertEqual(d.output({},None)['attempt_status'],'UNPROVEN')
    for category,value in (('prompt','FAKE_SECRET'),('headers','FAKE_SECRET'),('token','FAKE_SECRET'),('stdout','FAKE_SECRET'),('raw','FAKE_SECRET')):
        ev[category]=value;diag[category]=value
    self.assertNotIn('FAKE_SECRET',json.dumps(d.output(ev,0)))
    # Single-use reservation; post-start evidence written before final cleanup,
    # final output after cleanup. No production graph/promotion is called.
    with tempfile.TemporaryDirectory() as tmp:
        base=Path(tmp);e=base/'evidence';events=[]
        @contextmanager
        def fake_fixture():
            yield {'repo_dir':str(base)},[]
            events.append('cleanup')
        def execute(command,**kwargs):
            self.assertEqual(command[:3],['claude-free','--model',d.MODEL])
            self.assertEqual(kwargs,{'cwd':str(base),'timeout':180,'role':'coder','stream_activity':True})
            self.assertEqual(json.loads((e/'attempt.json').read_text())['attempt_status'],'NOT_RUN')
            events.append('run_worker')
            return worker.WorkerResult(0,'FAKE_PRIVATE_OUTPUT',ev)
        original=d.save
        def save(path,value,**kwargs):
            if path.name=='result.json': self.assertIn('cleanup',events)
            return original(path,value,**kwargs)
        with patch.object(d,'EVIDENCE',e),patch.object(d,'controller_check'),patch.object(d,'environment_check'),patch.object(d,'fixture',fake_fixture),patch.object(d,'capability_contract',return_value='fixture'),patch.object(d,'verify_execution_contract'),patch.object(d,'run_worker',side_effect=execute) as run,patch.object(d,'save',side_effect=save):
            result=d.live(d.CHECKPOINT)
            self.assertEqual(result['attempt_status'],'ATTEMPTED');self.assertEqual(run.call_count,1)
            self.assertNotIn('FAKE_',json.dumps(result));self.assertNotIn('FAKE_', (e/'result.json').read_text())
            self.assertEqual((e/'result.json').stat().st_mode&0o777,0o600)
            self.assertEqual(e.stat().st_mode&0o777,0o700)
            with self.assertRaisesRegex(d.Blocked,'PRIOR_LIVE_RESERVATION'):d.live(d.CHECKPOINT)
            self.assertEqual(run.call_count,1)
    # Known pre-spawn failure remains NOT_RUN, never an executed workload.
    with tempfile.TemporaryDirectory() as tmp:
        e=Path(tmp)/'evidence'
        @contextmanager
        def ready_fixture(): yield {'repo_dir':tmp},[]
        failure=worker.WorkerBoundaryError('WORKER_SPAWN_FAILURE',{'worker_phase':'PROCESS_NEVER_STARTED'})
        with patch.object(d,'EVIDENCE',e),patch.object(d,'controller_check'),patch.object(d,'environment_check'),patch.object(d,'fixture',ready_fixture),patch.object(d,'capability_contract',return_value='fixture'),patch.object(d,'verify_execution_contract'),patch.object(d,'run_worker',side_effect=failure) as run:
            result=d.live(d.CHECKPOINT)
            self.assertEqual(result['attempt_status'],'NOT_RUN');self.assertFalse(result['worker_spawned'])
            self.assertEqual(result['status'],'BLOCKED');self.assertEqual(run.call_count,1)
    # A cleanup failure retains observations and never reports validation success.
    with tempfile.TemporaryDirectory() as tmp:
        e=Path(tmp)/'evidence'
        @contextmanager
        def bad_cleanup():
            yield {'repo_dir':tmp},[]
            raise d.Blocked('WORKSPACE_CLEANUP_UNPROVEN')
        with patch.object(d,'EVIDENCE',e),patch.object(d,'controller_check'),patch.object(d,'environment_check'),patch.object(d,'fixture',bad_cleanup),patch.object(d,'capability_contract',return_value='fixture'),patch.object(d,'verify_execution_contract'),patch.object(d,'run_worker',return_value=worker.WorkerResult(0,'',ev)):
            result=d.live(d.CHECKPOINT)
            self.assertEqual(result['attempt_status'],'ATTEMPTED')
            self.assertEqual(result['status'],'BLOCKED');self.assertEqual(result['cleanup_status'],'UNPROVEN')
            self.assertEqual(result['routed_evidence'],'ROUTER_DISPATCH')
    # Registration/start uncertainty must not open the guard for a retry.
    with tempfile.TemporaryDirectory() as tmp:
        e=Path(tmp)/'evidence'
        with patch.object(d,'EVIDENCE',e):
            d.reserve()
            with self.assertRaisesRegex(d.Blocked,'PRIOR_LIVE_RESERVATION'):d.reserve()
            self.assertEqual(json.loads((e/'attempt.json').read_text())['attempt_status'],'NOT_RUN')
    # Health/socket checks never register a session or use HTTP generation.
    with patch.object(d,'_gateway_health',return_value={'gateway_health_status':'HEALTHY'}),patch.object(d.GatewaySession,'_exchange',return_value={'status':'UNAVAILABLE'}) as ipc:
        d.environment_check()
    ipc.assert_called_once_with('finish')
