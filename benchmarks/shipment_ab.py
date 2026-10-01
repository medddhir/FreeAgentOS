"""External controlled benchmark driver; never imported by the production graph.

prepare/validate/compare are non-generation operations. run requires --live.
"""
import argparse
import ast
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'orchestrator'))
from roles.controller_git import run_git
from roles.model_profiles import configured_selection
from roles.model_attribution import safe_gateway_observation
from roles.workspace import (prepare_workspace_node, verify_execution_contract,
                             cleanup_active_workspace, ACTIVE_RUN_DIR, _safe_run_dir)
from roles.preflight import preflight_node, check_host
from roles.integrity import baseline_node, check_baseline, changes
from roles.sandbox import run_isolated, RESOURCE_POLICY
from roles.worker import WORKER_POLICY
from cli import _evidence, _reason

BASELINE = Path('/root/freeagentos-benchmarks/shipment-reconciliation-baseline')
BASELINE_COMMIT = '0df82b5f7f0b6f5c82ff62b12bf84f5add1e97ec'
EVALS = Path('/tmp/freeagentos-evals')
EVIDENCE = Path('/root/freeagentos-benchmarks/evidence')
TASK = ('Complete the shipment reconciliation implementation according to README.md. '
        'Preserve the public interfaces and use only the Python standard library. '
        'Do not change tests or verification files. You may add implementation files.')
ARMS = {'auto': 'claude-free-default', 'gptoss': 'claude-free-gpt-oss-120b'}
MAX_RECORD = 128 * 1024
CODE = re.compile(r'[A-Z][A-Z0-9_]{0,79}')


class Abort(RuntimeError):
    pass


def require(value, code):
    if not value: raise Abort(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def git(repo, *args):
    result = run_git(list(args), cwd=repo, env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0'})
    require(result.returncode == 0, 'GIT_CHECK_FAILED')
    return result.stdout


def assignments(arm):
    require(arm in ARMS, 'ARM_INVALID')
    return dict(configured_selection({'coder': ARMS[arm], 'fixer': ARMS[arm]}))


def controls():
    return {'test_resources': RESOURCE_POLICY, 'worker_resources': WORKER_POLICY,
            'allow_new_files': True, 'allow_test_changes': False, 'allow_deletes': False,
            'allow_verification_changes': False, 'base_ms': 180000, 'grace_ms': 60000,
            'hard_cap_ms': 240000, 'fixer_global_limit': 2,
            'read_cap': 8, 'write_cap': 8, 'planner_target_cap': 4}


def repo_check(repo, expected):
    require(repo.is_dir() and not repo.is_symlink(), 'REPOSITORY_INVALID')
    require(Path(git(repo, 'rev-parse', '--show-toplevel').decode().strip()) == repo.resolve(), 'REPOSITORY_ROOT_INVALID')
    require(git(repo, 'rev-parse', 'HEAD').decode().strip() == expected, 'COMMIT_MISMATCH')
    require(not git(repo, 'status', '--porcelain=v1', '--untracked-files=all'), 'WORKTREE_DIRTY')


def prerequisites(commit, *, clean=True):
    require(re.fullmatch(r'[a-f0-9]{40}', commit) is not None, 'CONTROLLER_COMMIT_INVALID')
    require(git(ROOT, 'rev-parse', 'HEAD').decode().strip() == commit, 'CONTROLLER_COMMIT_MISMATCH')
    if clean: require(not git(ROOT, 'status', '--porcelain=v1', '--untracked-files=all'), 'CONTROLLER_DIRTY')
    repo_check(BASELINE, BASELINE_COMMIT)
    for arm in ARMS: assignments(arm)
    try:
        with urllib.request.urlopen('http://127.0.0.1:3001/api/ping', timeout=3) as response:
            require(response.status == 200, 'GATEWAY_UNHEALTHY')
    except Abort: raise
    except Exception: raise Abort('GATEWAY_UNHEALTHY') from None
    require(check_host().get('status') == 'PASS', 'HOST_PREFLIGHT_FAILED')


def identifiers(repo):
    ids = []
    for path in sorted((repo / 'tests').glob('test_*.py')):
        tree = ast.parse(path.read_text())
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for method in node.body:
                    if isinstance(method, ast.FunctionDef) and method.name.startswith('test_'):
                        ids.append(f'tests.{path.stem}.{node.name}.{method.name}')
    require(len(ids) == 15 and len(set(ids)) == 15, 'PUBLIC_SUITE_CHANGED')
    return sorted(ids)


def score(output, ids):
    entries = re.findall(r'(?m)^test_\w+ \((tests\.\w+\.\w+\.test_\w+)\) \.\.\. (ok|FAIL|ERROR)\s*$', output)
    require(len(entries) == 15 and len({i for i,_ in entries}) == 15 and sorted(i for i,_ in entries) == ids,
            'PUBLIC_RESULTS_UNAVAILABLE')
    require(re.findall(r'(?m)^Ran (\d+) tests in ', output)[-1:] == ['15'], 'PUBLIC_COUNT_CHANGED')
    counts = {name: sum(result == category for _,result in entries)
              for name,category in (('passed','ok'),('failed','FAIL'),('errors','ERROR'))}
    return {'total': 15, **counts, 'tests': [{'id': i, 'result': r} for i,r in sorted(entries)]}


def cleanup_state(state):
    path = state.get('run_dir')
    if path:
        require(_safe_run_dir(path), 'WORKSPACE_CLEANUP_UNSAFE')
        ACTIVE_RUN_DIR.set(path)
    result = cleanup_active_workspace()
    require(result in ('CONFIRMED','NONE'), 'WORKSPACE_CLEANUP_FAILED')
    return result


def public_score(state, ids):
    manifest = verify_execution_contract(state)
    check_baseline(state)
    # Tests and verification inputs are immutable for this experiment.
    repo = Path(state['run_workspace'])
    for name, expected in {**manifest['test_inventory'], **manifest['verification_inputs']}.items():
        path = repo / name
        require(path.is_file() and not path.is_symlink() and digest(path.read_bytes()) == expected, 'PUBLIC_SUITE_CHANGED')
    result = run_isolated(repo, state['run_dir'], manifest['runner_sha256'], timeout=130)
    require(result.get('isolated') is True and result['evidence'].get('cleanup_status') == 'CONFIRMED', 'PUBLIC_SANDBOX_FAILED')
    return score(result['output'], ids)


def baseline_score(repo, ids):
    state = {'repo_dir': str(repo), 'allow_new_files': True}
    try:
        state.update(prepare_workspace_node(state))
        require(not state.get('workspace_error'), 'BASELINE_SNAPSHOT_FAILED')
        state.update(preflight_node(state))
        require(state.get('preflight_status') == 'PASS', 'BASELINE_PREFLIGHT_FAILED')
        state.update(baseline_node(state))
        require(not state.get('baseline_error') and state.get('status') != 'BLOCKED', 'BASELINE_INTEGRITY_FAILED')
        result = public_score(state, ids)
        require(result['passed'] == 6 and result['failed'] + result['errors'] == 9, 'BASELINE_SCORE_MISMATCH')
        return result
    finally:
        cleanup_state(state)


def secure_dir(path):
    require(not path.is_symlink(), 'DIRECTORY_UNSAFE')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022, 'DIRECTORY_UNSAFE')


def write_record(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'
    require(len(raw) <= MAX_RECORD, 'EVIDENCE_TOO_LARGE')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def read_record(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_RECORD, 'EVIDENCE_UNSAFE')
    return json.loads(path.read_bytes())


def prepare(commit, order):
    require(order in (['auto','gptoss'], ['gptoss','auto']), 'ORDER_INVALID')
    prerequisites(commit)
    secure_dir(EVIDENCE);secure_dir(EVALS)
    name = 'stage27-ab-' + uuid.uuid4().hex
    evidence = EVIDENCE / name;work = EVALS / name
    evidence.mkdir(mode=0o700);work.mkdir(mode=0o700)
    ids = identifiers(BASELINE)
    suites = {};repos = {}
    for arm in order:
        path = work / ('shipment-stage27-' + arm)
        # No hard links/alternates; never checkout or run tests in the canonical repo.
        git(ROOT, 'clone', '--quiet', '--no-local', '--no-hardlinks', '--no-checkout', '--', str(BASELINE), str(path))
        git(path, 'checkout', '--quiet', '--detach', BASELINE_COMMIT)
        repo_check(path, BASELINE_COMMIT)
        suites[arm] = baseline_score(path, ids);repos[arm] = str(path)
        repo_check(path, BASELINE_COMMIT)
    require(suites['auto'] == suites['gptoss'], 'BASELINES_DIFFER')
    plan = {'schema_version': 1, 'experiment_id': name, 'controller_commit': commit,
            'baseline_commit': BASELINE_COMMIT, 'task_sha256': digest(TASK.encode()),
            'controls': controls(), 'role_profiles': {a: assignments(a) for a in ARMS},
            'run_order': order, 'workspaces': repos, 'baseline': suites['auto'],
            'public_test_ids': ids, 'created_at': utc(), 'live_workloads_run': 0,
            'hidden_suite_available': False, 'promotion_to_canonical_allowed': False}
    write_record(evidence / 'plan.json', plan)
    return {'status': 'DRY_RUN_PASS', 'plan': str(evidence / 'plan.json'),
            'baseline': {k:plan['baseline'][k] for k in ('passed','failed','errors','total')},
            'run_order': order, 'models_invoked': 0}


def load_plan(path):
    require(path.name == 'plan.json' and path.parent.parent == EVIDENCE and not path.parent.is_symlink(), 'PLAN_PATH_INVALID')
    plan = read_record(path)
    require(plan.get('schema_version') == 1 and plan.get('experiment_id') == path.parent.name, 'PLAN_INVALID')
    require(plan.get('baseline_commit') == BASELINE_COMMIT and plan.get('task_sha256') == digest(TASK.encode()), 'PLAN_CHANGED')
    require(plan.get('controls') == controls() and plan.get('role_profiles') == {a:assignments(a) for a in ARMS}, 'PLAN_CHANGED')
    require(plan.get('run_order') in (['auto','gptoss'],['gptoss','auto']), 'PLAN_CHANGED')
    for arm in ARMS:
        require(plan.get('workspaces',{}).get(arm) == str(EVALS / plan['experiment_id'] / ('shipment-stage27-'+arm)), 'PLAN_WORKSPACE_INVALID')
    require(plan.get('hidden_suite_available') is False and plan.get('promotion_to_canonical_allowed') is False, 'PLAN_INVALID')
    return plan


def execution_commit(plan, harness_commit=None):
    """Explicit harness-only continuation; the experiment/production pin stays intact."""
    commit = harness_commit or plan['controller_commit']
    require(re.fullmatch(r'[a-f0-9]{40}', commit) is not None, 'CONTROLLER_COMMIT_INVALID')
    if commit != plan['controller_commit']:
        require(git(ROOT, 'merge-base', plan['controller_commit'], commit).decode().strip()
                == plan['controller_commit'], 'CONTINUATION_NOT_DESCENDANT')
        allowed = {'benchmarks/shipment_ab.py', 'benchmarks/STAGE27_SHIPMENT_AB.md',
                   'test_shipment_ab.py'}
        paths = set(git(ROOT, 'diff', '--name-only', plan['controller_commit'], commit).decode().splitlines())
        require(bool(paths) and paths <= allowed, 'CONTINUATION_PRODUCTION_CHANGED')
    return commit


def validate(plan, harness_commit=None):
    prerequisites(execution_commit(plan, harness_commit))
    ids = identifiers(BASELINE)
    require(ids == plan['public_test_ids'], 'PUBLIC_SUITE_CHANGED')
    for arm in ARMS:
        path = Path(plan['workspaces'][arm]);repo_check(path, BASELINE_COMMIT)
        require(baseline_score(path, ids) == plan['baseline'], 'BASELINE_SCORE_MISMATCH')
    return {'status':'DRY_RUN_PASS','models_invoked':0}


def route_summary(workers):
    coding = [w for w in workers if w['role'] in ('coder','fixer')]
    unavailable = {'attribution_status':'UNAVAILABLE','route_status':'UNAVAILABLE',
                   'routed_evidence':'UNAVAILABLE','routed_provider_id':'UNAVAILABLE',
                   'routed_model_id':'UNAVAILABLE','served_model_id':'UNAVAILABLE','routes':[]}
    if not coding: return unavailable
    pairs = set()
    for worker in coding:
        observation = safe_gateway_observation(worker['evidence'].get('gateway_attribution'))
        if observation['routed_evidence'] != 'ROUTER_DISPATCH': return unavailable
        pairs.update((p['provider_id'],p['model_id']) for p in observation['routes'])
    if len(pairs)>32: return unavailable
    ordered = [{'provider_id':p,'model_id':m} for p,m in sorted(pairs)]
    single = len(ordered)==1
    return {'attribution_status':'SESSION_BOUND_DISPATCH','routed_evidence':'ROUTER_DISPATCH',
            'route_status':'SINGLE_ROUTE' if single else 'MULTIPLE_ROUTES','routes':ordered,
            'routed_provider_id':ordered[0]['provider_id'] if single else 'UNAVAILABLE',
            'routed_model_id':ordered[0]['model_id'] if single else 'UNAVAILABLE','served_model_id':'UNAVAILABLE'}


def state_evidence(state):
    workers = [{'role':w['role'],'evidence':_evidence(w.get('evidence'))}
               for w in (state.get('worker_history') or [])[:8]
               if w.get('role') in ('planner','coder','fixer','reviewer')]
    reason=_reason(state)
    return {'block_reason':reason if CODE.fullmatch(reason) else 'UNAVAILABLE',
            'fix_attempts':state.get('fix_attempts') if type(state.get('fix_attempts')) is int and 0<=state['fix_attempts']<=2 else 0,
            'target_verification_evidence':_evidence(state.get('sandbox_evidence')),
            'role_timings_ms':[{'role':t['role'],'elapsed_ms':t['elapsed_ms']} for t in (state.get('role_timing_history') or [])[-32:] if t.get('role') in ('planner','coder','fixer','reviewer','tester','preflight','researcher') and type(t.get('elapsed_ms')) is int and 0<=t['elapsed_ms']<=10000000],
            'controller_final_state':state.get('status') if state.get('status') in ('VERIFIED','BLOCKED','UNVERIFIED') else 'UNAVAILABLE',
            'workers':workers,'coding_route':route_summary(workers),
            'worker_cleanup':('NOT_APPLICABLE' if not workers else 'CONFIRMED' if all(w['evidence'].get('cleanup_status')=='CONFIRMED' and w['evidence'].get('remaining_processes')==0 for w in workers) else 'UNPROVEN'),
            'fixer_invocations':sum(w['role']=='fixer' for w in workers),
            'verification_status':state.get('test_result') if state.get('test_result') in ('PASS','FAIL') else 'UNAVAILABLE',
            'preflight':state.get('preflight_status') if state.get('preflight_status') in ('PASS','BLOCKED') else 'UNAVAILABLE'}


def final_patch(state):
    repo,_ = check_baseline(state)
    current = changes(repo, state['integrity_baseline'])
    names = sorted(current['changed'])
    for name in names:
        path=repo/name
        require(not path.is_symlink() and all(not p.is_symlink() for p in path.parents if p!=repo.parent), 'PATCH_PATH_UNSAFE')
        if path.exists(): require(path.is_file() and path.stat().st_nlink==1, 'PATCH_PATH_UNSAFE')
    require(len(names)<=100 and all(re.fullmatch(r'[A-Za-z0-9_.\-/]{1,180}',n) and '..' not in n.split('/') for n in names), 'PATCH_PATH_UNSAFE')
    pieces = [git(repo, 'diff', '--binary', '--no-ext-diff', '--no-textconv', 'HEAD')]
    for name in sorted(current['untracked']):
        result = run_git(['--literal-pathspecs','diff','--no-index','--binary','--no-ext-diff','--no-textconv','--','/dev/null',name], cwd=repo)
        require(result.returncode in (0,1), 'PATCH_HASH_FAILED');pieces.append(result.stdout)
    return {'changed_files':names,'final_patch_sha256':digest(b''.join(pieces)),
            'patch_hash_format':'TRACKED_DIFF_THEN_SORTED_UNTRACKED_DIFFS'}


@contextmanager
def experiment_lock(directory):
    fd=os.open(directory/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Abort('EXPERIMENT_BUSY') from None
        yield
    finally: os.close(fd)


def confirmed_workers(record):
    workers = record.get('workers')
    return (isinstance(workers, list) and len(workers) <= 8
            and all(isinstance(w, dict) and w.get('role') in ('planner','coder','fixer','reviewer')
                    and isinstance(w.get('evidence'), dict)
                    and w['evidence'].get('cleanup_status') == 'CONFIRMED'
                    and type(w['evidence'].get('remaining_processes')) is int
                    and w['evidence']['remaining_processes'] == 0 for w in workers)
            and record.get('worker_cleanup') == ('CONFIRMED' if workers else 'NOT_APPLICABLE'))


def legacy_timeout_outcome(record):
    # Only the pre-2.7B ambiguous scoring failure with independently recorded
    # timeout/cleanup evidence is interpreted as a collected workload outcome.
    role = {'CODER_TIMEOUT':'coder', 'FIXER_TIMEOUT':'fixer'}.get(record.get('block_reason'))
    return (record.get('failure') == 'PUBLIC_RESULTS_UNAVAILABLE'
            and record.get('controller_final_state') == 'BLOCKED'
            and record.get('public_after') is None and role is not None
            and confirmed_workers(record)
            and any(w['role'] == role and w['evidence'].get('timeout_triggered') is True
                    and w['evidence'].get('worker_exit_code') == 124 for w in record['workers']))


def failure_class(record):
    explicit = record.get('failure_class')
    if explicit is not None:
        require(explicit in ('NONE','ARM_OUTCOME_FAILURE','DRIVER_FAILURE'), 'ARM_RECORD_INVALID')
        # A claimed outcome cannot launder an unrelated exception.
        if record.get('failure') != 'NONE':
            require(explicit == 'DRIVER_FAILURE' or
                    (explicit == 'ARM_OUTCOME_FAILURE'
                     and record.get('failure') == 'PUBLIC_RESULTS_UNAVAILABLE'
                     and record.get('controller_final_state') == 'BLOCKED'), 'ARM_RECORD_INVALID')
        return explicit
    if legacy_timeout_outcome(record): return 'ARM_OUTCOME_FAILURE'
    if record.get('failure','NONE') != 'NONE': return 'DRIVER_FAILURE'
    return 'ARM_OUTCOME_FAILURE' if record.get('controller_final_state') == 'BLOCKED' else 'NONE'


def eligibility(path, plan, arm):
    directory = path.parent
    require(arm in ARMS, 'ARM_INVALID')
    require(not (directory/(arm+'-started.json')).exists(), 'ARM_ALREADY_ATTEMPTED')
    for earlier in plan['run_order'][:plan['run_order'].index(arm)]:
        previous = directory/(earlier+'-result.json')
        require(previous.is_file(), 'RUN_ORDER_VIOLATION')
        prior = read_record(previous)
        marker = read_record(directory/(earlier+'-started.json'))
        require(prior.get('failure') is not None and prior.get('controller_final_state') in ('VERIFIED','BLOCKED','UNVERIFIED','UNAVAILABLE')
                and prior.get('arm') == earlier and marker.get('arm') == earlier
                and prior.get('plan_sha256') == marker.get('plan_sha256') == digest(path.read_bytes())
                and prior.get('controller_commit') == plan['controller_commit']
                and prior.get('baseline_commit') == plan['baseline_commit']
                and prior.get('role_profiles') == assignments(earlier)
                and prior.get('public_before') == plan['baseline']
                and prior.get('started_at') == marker.get('started_at')
                and isinstance(prior.get('ended_at'), str), 'PREVIOUS_RECORD_MISMATCH')
        require(prior.get('cleanup') in ('CONFIRMED','NONE') and confirmed_workers(prior),
                'PREVIOUS_CLEANUP_UNPROVEN')
        require(failure_class(prior) != 'DRIVER_FAILURE', 'PREVIOUS_DRIVER_FAILURE')


def validate_arm(path, arm, harness_commit=None):
    plan = load_plan(path)
    with experiment_lock(path.parent):
        eligibility(path, plan, arm)
        result = validate(plan, harness_commit)
        return {**result, 'arm':arm, 'eligible_for_first_live_workload':True,
                'plan_sha256':digest(path.read_bytes()),
                'controller_commit':plan['controller_commit'],
                'harness_commit':execution_commit(plan, harness_commit)}


def run_arm(path, arm, live, harness_commit=None):
    require(live, 'LIVE_OPT_IN_REQUIRED');require(arm in ARMS, 'ARM_INVALID')
    plan=load_plan(path);directory=path.parent
    with experiment_lock(directory):
        eligibility(path, plan, arm)
        validate(plan, harness_commit) # fail closed before graph/model execution
        started=utc();clock=time.monotonic_ns()
        write_record(directory/(arm+'-started.json'),{'arm':arm,'started_at':started,'plan_sha256':digest(path.read_bytes())})
        state={};result={'schema_version':1,'arm':arm,'plan_sha256':digest(path.read_bytes()),
                        'controller_commit':plan['controller_commit'],'harness_commit':execution_commit(plan, harness_commit),'baseline_commit':BASELINE_COMMIT,
                        'role_profiles':assignments(arm),'public_before':plan['baseline'],'started_at':started,
                        'public_after':None,'final_patch_sha256':None,'changed_files':[],
                        'promotion_patch_status':'NONE','verification_status':'UNAVAILABLE','failure':'NONE',
                        'failure_class':'NONE','controller_final_state':'UNAVAILABLE','workers':[],'coding_route':route_summary([]),'worker_cleanup':'NOT_APPLICABLE','fixer_invocations':0}
        old={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
        def interrupted(signum,frame): raise KeyboardInterrupt()
        try:
            for s in old: signal.signal(s,interrupted)
            import graph
            # The production graph is unchanged. Retention permits controller-only
            # scoring before identical guaranteed cleanup for both arms.
            graph_input={
                'repo_dir':plan['workspaces'][arm],'task':TASK,'trace':[],
                'allow_new_files':True,'allow_deletes':False,'allow_test_changes':False,
                'allow_verification_changes':False,'retain_workspace':True}
            for snapshot in graph.build_graph(model_profiles=assignments(arm)).stream(graph_input,stream_mode='values'):
                state=snapshot
            result.update(state_evidence(state))
            # A completed BLOCKED graph is an experimental outcome. An absent
            # final score is not a driver exception in that case; other scoring
            # errors (integrity/sandbox/count failures) still fail closed.
            try:
                result['public_after']=public_score(state,plan['public_test_ids'])
            except Abort as error:
                if str(error) != 'PUBLIC_RESULTS_UNAVAILABLE' or state.get('status') != 'BLOCKED': raise
                result['failure']='PUBLIC_RESULTS_UNAVAILABLE'
                result['failure_class']='ARM_OUTCOME_FAILURE'
            if state.get('status') == 'BLOCKED': result['failure_class']='ARM_OUTCOME_FAILURE'
            result.update(final_patch(state))
            patch=state.get('verified_patch_path')
            if patch and state.get('status')=='VERIFIED':
                target=Path(patch);info=target.lstat()
                parent=target.parent.lstat()
                require(target.parent.parent==Path('/tmp') and target.parent.name.startswith('freeagentos-promotion-')
                        and stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid() and stat.S_IMODE(parent.st_mode)==0o700
                        and stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_size<=16*1024*1024, 'PROMOTION_ARTIFACT_UNSAFE')
                raw=target.read_bytes()
                fd=os.open(directory/(arm+'-verified.patch'),os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:
                    stream.write(raw);stream.flush();os.fsync(stream.fileno())
                result['promotion_patch_status']='STORED_EVIDENCE_ONLY';result['promotion_patch_sha256']=digest(raw)
                shutil.rmtree(target.parent)
            result['final_public_verification']=('UNAVAILABLE' if result['public_after'] is None else 'PASS' if result['public_after']['passed']==15 else 'FAIL')
        except (Exception,KeyboardInterrupt) as error:
            result['failure_class']='DRIVER_FAILURE'
            result['failure']=str(error) if isinstance(error,Abort) and CODE.fullmatch(str(error)) else 'INTERRUPTED' if isinstance(error,KeyboardInterrupt) else 'WORKLOAD_OR_VERIFICATION_FAILED'
        finally:
            if state: result.update(state_evidence(state))
            for s,handler in old.items(): signal.signal(s,handler)
            try: result['cleanup']=cleanup_state(state)
            except Exception: result['cleanup']='UNPROVEN'
            result['ended_at']=utc();result['elapsed_ms']=(time.monotonic_ns()-clock)//1000000
            write_record(directory/(arm+'-result.json'),result)
        repo_check(BASELINE,BASELINE_COMMIT)
        return result


def compare(path):
    plan=load_plan(path);arms={}
    for arm in plan['run_order']:
        record=path.parent/(arm+'-result.json')
        if not record.exists(): arms[arm]={'status':'NOT_RUN'};continue
        result=read_record(record)
        require(result.get('plan_sha256')==digest(path.read_bytes()) and result.get('arm')==arm
                and result.get('controller_commit')==plan['controller_commit']
                and result.get('role_profiles')==assignments(arm), 'COMPARISON_RECORD_MISMATCH')
        allowed={'schema_version','arm','plan_sha256','controller_commit','baseline_commit','role_profiles','public_before','started_at','public_after','final_patch_sha256','changed_files','promotion_patch_status','verification_status','failure','controller_final_state','workers','coding_route','fixer_invocations','preflight','patch_hash_format','promotion_patch_sha256','final_public_verification','cleanup','ended_at','elapsed_ms','block_reason','fix_attempts','target_verification_evidence','role_timings_ms','worker_cleanup','failure_class','harness_commit'}
        require(set(result)<=allowed, 'COMPARISON_RECORD_INVALID')
        result['workers']=[{'role':w['role'],'evidence':_evidence(w.get('evidence'))} for w in result.get('workers',[]) if w.get('role') in ('planner','coder','fixer','reviewer')]
        result['coding_route']=route_summary(result['workers'])
        result['failure_class']=failure_class(result)
        arms[arm]=result
    return {'schema_version':1,'run_order':plan['run_order'],'baseline':plan['baseline'],
            'arms':arms,'single_run_only':True,'statistical_superiority_claimed':False,
            'hidden_suite_available':False}


class DiscardOutput:
    def write(self, text): return len(text)
    def flush(self): pass


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_subparsers(dest='action',required=True)
    prep=actions.add_parser('prepare');prep.add_argument('--expected-controller-commit',required=True)
    prep.add_argument('--order',choices=('auto,gptoss','gptoss,auto'),required=True)
    for action in ('validate','compare','run'):
        sub=actions.add_parser(action);sub.add_argument('--plan',type=Path,required=True)
        if action in ('validate','run'): sub.add_argument('--harness-commit')
        if action=='validate': sub.add_argument('--arm',choices=tuple(ARMS))
        if action=='run': sub.add_argument('--arm',choices=tuple(ARMS),required=True);sub.add_argument('--live',action='store_true')
    args=parser.parse_args(argv)
    try:
        # No raw controller/model/test streams are persisted or emitted.
        with redirect_stdout(DiscardOutput()), redirect_stderr(DiscardOutput()):
            if args.action=='prepare': result=prepare(args.expected_controller_commit,args.order.split(','))
            elif args.action=='validate': result=validate_arm(args.plan,args.arm,args.harness_commit) if args.arm else validate(load_plan(args.plan),args.harness_commit)
            elif args.action=='compare': result=compare(args.plan)
            else: result=run_arm(args.plan,args.arm,args.live,args.harness_commit)
        print(json.dumps(result,sort_keys=True))
        return 0 if failure_class(result)!='DRIVER_FAILURE' and result.get('cleanup')!='UNPROVEN' else 2
    except Exception as error:
        reason=str(error) if isinstance(error,Abort) and CODE.fullmatch(str(error)) else 'BENCHMARK_CONTROLLER_FAILURE'
        print(json.dumps({'status':'BLOCKED','reason':reason}));return 2


if __name__=='__main__': sys.exit(main())
