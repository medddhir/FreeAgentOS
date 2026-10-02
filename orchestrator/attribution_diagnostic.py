"""One explicitly opted-in read-only Coder session; default is non-generation dry-run."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil

from roles.controller_git import run_git
from roles.model_attribution import (GatewaySession, attribution_for,
                                     safe_attribution_diagnostics, safe_gateway_observation)
from roles.model_profiles import profile_scope, resolve_profile, model_command
from roles.preflight import preflight_node
from roles.read_policy import capability_contract, file_tool_flags, sealed_policy
from roles.worker import run_worker, WorkerBoundaryError, _gateway_health
from roles.workspace import prepare_workspace_node, verify_execution_contract, cleanup_active_workspace
from cli import _evidence

ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = '5684a8ccfc4e47e4a6e413603492eb1dea57843f'
PROFILE = 'claude-free-gpt-oss-120b'
MODEL = 'openai/gpt-oss-120b'
WORKSPACE = Path('/tmp/freeagentos-evals/stage29-attribution-diagnostic')
EVIDENCE = Path('/root/freeagentos-benchmarks/evidence/stage29-attribution-diagnostic')
INITIAL = b'Isolated attribution diagnostic fixture.\n'
TASK = 'Use Read once on README.md. Do not modify files, use discovery, shell or tests. Finish with a concise final result.'


class Blocked(ValueError):
    pass


def require(condition, code):
    if not condition: raise Blocked(code)


def git(repo, args):
    result = run_git(args, cwd=repo, timeout=10, max_output=8192)
    require(result.returncode == 0, 'DIAGNOSTIC_GIT_FAILED')
    return result.stdout.decode().strip()


def controller_check(expected):
    require(isinstance(expected,str) and len(expected)==40 and all(c in '0123456789abcdef' for c in expected), 'CONTROLLER_COMMIT_REQUIRED')
    require(git(ROOT,['rev-parse','HEAD']) == expected, 'CONTROLLER_COMMIT_CHANGED')
    require(git(ROOT,['status','--porcelain','--untracked-files=all']) == '', 'CONTROLLER_DIRTY')
    require(git(ROOT,['rev-parse','stage-2.9a-verified^{}']) == CHECKPOINT, 'CHECKPOINT_CHANGED')
    git(ROOT,['merge-base','--is-ancestor',CHECKPOINT,expected])
    resolve_profile('coder',PROFILE)


def environment_check():
    require(_gateway_health()['gateway_health_status'] == 'HEALTHY', 'GATEWAY_UNHEALTHY')
    # Existing production client performs ownership/mode/SO_PEERCRED validation.
    # Finish a fresh, never-registered correlation: no session is created, no dispatch.
    try:
        payload = GatewaySession()._exchange('finish')
    except Exception:
        raise Blocked('ATTRIBUTION_IPC_UNAVAILABLE') from None
    require(payload == {'status':'UNAVAILABLE'}, 'ATTRIBUTION_PROTOCOL_UNEXPECTED')


@contextmanager
def fixture():
    require(WORKSPACE.parent.is_dir() and not WORKSPACE.parent.is_symlink(), 'WORKSPACE_PARENT_INVALID')
    try: WORKSPACE.mkdir(mode=0o700)
    except FileExistsError: raise Blocked('WORKSPACE_EXISTS') from None
    try:
        (WORKSPACE/'README.md').write_bytes(INITIAL)
        for args in (['init','--quiet'],['config','user.name','Attribution diagnostic'],
                     ['config','user.email','diagnostic@localhost.invalid'],
                     ['config','core.hooksPath','/dev/null'],['add','--','README.md'],
                     ['commit','--quiet','-m','Isolated attribution fixture']):
            git(WORKSPACE,args)
        state={'repo_dir':str(WORKSPACE), 'allow_new_files':False, 'allow_deletes':False,
               'allow_test_changes':False, 'allow_verification_changes':False}
        state.update(prepare_workspace_node(state))
        require(not state.get('workspace_error'), 'WORKSPACE_PREPARATION_FAILED')
        state.update(preflight_node(state))
        require(state.get('preflight_status')=='PASS','PREFLIGHT_FAILED')
        verify_execution_contract(state)
        flags=file_tool_flags(state,'coder',unit={'target_files':[]})
        policy=sealed_policy(flags)
        require(policy['files']==['README.md'] and policy['write_files']==[] and policy['new_files']==[], 'FIXTURE_POLICY_INVALID')
        yield state,flags
    finally:
        cleanup = cleanup_active_workspace()
        # Only this invocation's exclusively created disposable fixture is removed.
        shutil.rmtree(WORKSPACE)
        require(cleanup in ('CONFIRMED','NONE'),'WORKSPACE_CLEANUP_UNPROVEN')


def diagnostics_shape(value):
    d=safe_attribution_diagnostics(value)
    return {'registration':{'attempted':d['registration_attempted'],'status':d['registration_status']},
            'transport_configuration':{'custom_headers_configured':d['custom_headers_configured']},
            'finish':{'attempted':d['finish_attempted'],'ipc_status':d['finish_ipc_status']},
            'gateway':{'record_class':d['gateway_record_status'],
                       **{k:d[k] for k in ('request_count','settled_count','unsettled_count','attempt_count','route_count','overflow')}},
            'projection':{'status':d['projection_status'],'reason':d['projection_reason']}}


def output(evidence=None, returncode=None):
    evidence=evidence if isinstance(evidence,dict) else {}
    route=safe_gateway_observation(evidence.get('gateway_attribution'))
    d=safe_attribution_diagnostics(evidence.get('attribution_diagnostics'))
    started = (type(evidence.get('worker_process_spawn_ms')) is int or
               evidence.get('worker_phase') in ('PROCESS_STARTED_NO_OUTPUT','STDERR_BEFORE_STDOUT','FIRST_OUTPUT_BEFORE_TIMEOUT','NORMAL_COMPLETE'))
    spawned = True if started else False if evidence.get('worker_phase')=='PROCESS_NEVER_STARTED' else 'UNPROVEN'
    cleanup=evidence.get('cleanup_status') if evidence.get('cleanup_status') in ('CONFIRMED','UNPROVEN') else 'UNAVAILABLE'
    remaining=evidence.get('remaining_processes')
    remaining=remaining if type(remaining) is int and 0<=remaining<=65536 else 'UNAVAILABLE'
    # Telemetry validation is independent of route acceptance or model quality.
    coherent = (d['registration_attempted'] is True and d['registration_status']!='UNAVAILABLE'
                and d['finish_attempted'] is True and d['finish_ipc_status']!='UNAVAILABLE'
                and d['projection_reason'] not in ('UNAVAILABLE','DIAGNOSTIC_FAILURE'))
    coherent = coherent and ((route['routed_evidence']=='ROUTER_DISPATCH') == (d['projection_status']=='ACCEPTED'))
    if d['projection_status']=='ACCEPTED':
        coherent = (coherent and d['gateway_record_status']=='COMPLETE'
                    and d['route_count']==len(route['routes']) and d['unsettled_count']==0
                    and d['settled_count']==d['request_count'])
    if started: coherent = coherent and type(d['custom_headers_configured']) is bool
    timed=evidence.get('timeout_triggered') is True
    lease=evidence.get('lease',{})
    timeout_type=('HARD_CAP' if timed and lease.get('grace_granted') is True else 'BASE_LEASE' if timed else 'NONE')
    return {'status':'DIAGNOSTICS_VALIDATED' if coherent and spawned is True and cleanup=='CONFIRMED' and remaining==0 else 'BLOCKED',
            'attempt_status':'ATTEMPTED' if spawned is True else 'NOT_RUN' if spawned is False else 'UNPROVEN',
            'worker_spawned':spawned,
            'worker_final_state':'NOT_STARTED' if spawned is False else 'TIMEOUT' if timed else 'NORMAL_COMPLETE' if returncode==0 else 'FAILED',
            'timeout_type':timeout_type,
            'requested_profile':PROFILE,'requested_model':MODEL,'requested_evidence':'REQUESTED_CONFIG',
            'attribution_status':'SESSION_BOUND_DISPATCH' if route['routed_evidence']=='ROUTER_DISPATCH' else 'GATEWAY_SESSION_BINDING_UNAVAILABLE',
            **route,'served_model_id':'UNAVAILABLE',
            'attribution_diagnostics':diagnostics_shape(d),
            'cleanup_status':cleanup,'remaining_processes':remaining,
            'lease':_evidence(evidence).get('lease',{}),
            'worker_total_ms':_evidence(evidence).get('worker_total_ms','UNAVAILABLE')}


def save(path, value, *, exclusive=False):
    raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
    require(len(raw)<=8192,'EVIDENCE_BOUNDS')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|(os.O_EXCL if exclusive else os.O_TRUNC),0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def evidence_location_check():
    require(EVIDENCE.parent.is_dir() and not EVIDENCE.parent.is_symlink()
            and os.access(EVIDENCE.parent,os.W_OK),'EVIDENCE_PARENT_INVALID')


def reserve():
    evidence_location_check()
    # The directory itself is the durable run-once reservation, including crashes.
    # Registration/spawn uncertainty must never permit an automatic retry.
    try: EVIDENCE.mkdir(mode=0o700)
    except FileExistsError: raise Blocked('PRIOR_LIVE_RESERVATION') from None
    save(EVIDENCE/'attempt.json',{'attempt_status':'NOT_RUN','launch_state':'RESERVED'},exclusive=True)


def prepare(expected):
    controller_check(expected);environment_check();evidence_location_check()
    require(not EVIDENCE.exists() and not EVIDENCE.is_symlink(),'PRIOR_LIVE_RESERVATION')
    with fixture() as (state,flags):
        with profile_scope({'coder':PROFILE}):
            identity=attribution_for('coder')
            command=model_command('coder',flags,capability_contract(flags)+'\n'+TASK)
            require(command[:3]==['claude-free','--model',MODEL],'MODEL_SELECTION_INVALID')
        require(identity['requested_model_id']==MODEL,'REQUESTED_IDENTITY_INVALID')
    return {'status':'DRY_RUN_PASS','attempt_status':'NOT_RUN','worker_spawned':False,
            'controller_commit':expected,'requested_profile':PROFILE,'requested_model':MODEL,
            'requested_evidence':'REQUESTED_CONFIG','uses_production_run_worker':True,
            'socket_validation':'PASS','preflight':'PASS','fixture_isolation':'PASS',
            'cleanup_status':'CONFIRMED','single_run_guard':'READY',
            'evidence_directory':str(EVIDENCE),'disposable_workspace':str(WORKSPACE)}


def live(expected):
    controller_check(expected);environment_check();evidence_location_check()
    require(not EVIDENCE.exists() and not EVIDENCE.is_symlink(),'PRIOR_LIVE_RESERVATION')
    result=None
    try:
        with fixture() as (state,flags):
            with profile_scope({'coder':PROFILE}):
                command=model_command('coder',flags,capability_contract(flags)+'\n'+TASK)
                reserve()
                try:
                    worker=run_worker(command,cwd=state['repo_dir'],timeout=180,role='coder',stream_activity=True)
                    result=output(worker.evidence,worker.returncode)
                except WorkerBoundaryError as exc:
                    result=output(exc.evidence)
                except Exception:
                    result=output()
                finally:
                    try: verify_execution_contract(state)
                    except Exception:
                        if result is not None: result.update(status='BLOCKED',reason='EXECUTION_CONTRACT_FAILED')
                    if result is not None:
                        save(EVIDENCE/'attempt.json',{'attempt_status':result['attempt_status'],'launch_state':'FINISHED'})
    except Exception:
        if result is None: raise
        result.update(status='BLOCKED',cleanup_status='UNPROVEN')
    # Final evidence is written only after fixture/snapshot cleanup was checked.
    save(EVIDENCE/'result.json',result,exclusive=True)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description='Prepare a one-shot attribution diagnostic; no model is invoked by default.')
    parser.add_argument('--live',action='store_true',help='One separately authorized production Coder session.')
    parser.add_argument('--dry-run',action='store_true')
    parser.add_argument('--expected-controller',required=True)
    args=parser.parse_args(argv)
    try:
        require(not(args.live and args.dry_run),'MODE_INVALID')
        result=live(args.expected_controller) if args.live else prepare(args.expected_controller)
    except Blocked as exc:
        result={**output({'worker_phase':'PROCESS_NEVER_STARTED'}),'reason':str(exc)}
    except Exception:
        # Never claim no spawn after losing trusted worker evidence.
        result={**output(),'reason':'DIAGNOSTIC_CONTROL_FAILURE'}
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status'] in ('DRY_RUN_PASS','DIAGNOSTICS_VALIDATED') else 2


if __name__=='__main__': raise SystemExit(main())
