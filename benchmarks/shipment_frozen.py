"""Frozen-plan Coder/Fixer experiment. prepare/validate/compare never call models."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import json
from pathlib import Path
import sys
import signal
import time
import uuid

from benchmarks import shipment_ab as h
from roles.inspector import inspector_node
from roles.coding_units import derive_units_node
from roles.read_policy import build_policy
from roles.model_profiles import profile_scope
from roles.workspace import discovery_baseline_node
import graph

TARGETS = ['shipment_reconcile/models.py', 'shipment_reconcile/parser.py',
           'shipment_reconcile/reconcile.py', 'shipment_reconcile/cli.py']
STEPS = ['Complete the existing shipment reconciliation package according to README.md while preserving its public interfaces.']
PROPOSED = [{'goal': STEPS[0], 'target_files': TARGETS}]


def profiles(arm):
    return h.assignments(arm)


def merge(state, update):
    for key, value in update.items():
        if key in ('worker_history', 'unit_history', 'role_timing_history', 'trace'):
            state[key] = state.get(key, []) + value
        else: state[key] = value


def setup(repo):
    state = {'repo_dir':str(repo), 'task':h.TASK, 'trace':[], 'fix_attempts':0,
             'allow_new_files':True, 'allow_deletes':False, 'allow_test_changes':False,
             'allow_verification_changes':False, 'retain_workspace':True}
    try:
        for node in (h.prepare_workspace_node, h.preflight_node, h.baseline_node,
                     discovery_baseline_node, inspector_node):
            merge(state, node(state))
            h.require(state.get('status') != 'BLOCKED', 'SETUP_FAILED')
        state.update(plan_steps=STEPS[:], planner_coding_units=PROPOSED,
                     unit_derivation_source='PLANNER_EXPLICIT', needs_research=False,
                     research='No external research was required.')
        # PLANNER_EXPLICIT names the existing validated unit schema, not provenance:
        # these hints are controller constants, never a Planner model response.
        merge(state, derive_units_node(state))
        h.require(state.get('status') != 'BLOCKED', 'FROZEN_UNITS_INVALID')
        return state
    except BaseException:
        h.cleanup_state(state)
        raise


def manifest(state):
    policy = build_policy(state, 'coder', unit=state['coding_units'][0])
    h.require(policy['write_files'] == TARGETS and policy['new_files'] == [], 'TARGET_MANIFEST_INVALID')
    return {k:policy[k] for k in ('files','write_files','new_files','allow_tests','read_tests')}


def artifact(state, ids):
    return {'schema_version':1, 'provenance':'CONTROLLER_FIXTURE', 'task':h.TASK,
            'baseline_commit':h.BASELINE_COMMIT, 'plan_steps':STEPS,
            'planner_coding_units':PROPOSED, 'coding_units':state['coding_units'],
            'repo_facts':state['repo_facts'], 'repo_facts_text':state['repo_facts_text'],
            'initial_manifest':manifest(state), 'public_test_ids':ids, 'controls':h.controls(),
            'planner_model':False, 'reviewer_model':False, 'production_promotion':False}


def canonical(value):
    return json.dumps(value, sort_keys=True, indent=2).encode()+b'\n'


def check_frozen(value):
    h.require(isinstance(value, dict) and value.get('schema_version') == 1
              and value.get('provenance') == 'CONTROLLER_FIXTURE'
              and value.get('task') == h.TASK and value.get('baseline_commit') == h.BASELINE_COMMIT
              and value.get('plan_steps') == STEPS and value.get('planner_coding_units') == PROPOSED
              and value.get('controls') == h.controls()
              and all(value.get(k) is False for k in ('planner_model','reviewer_model','production_promotion')),
              'FROZEN_SCHEMA_INVALID')
    # Whole-object equality against independent deterministic reconstruction below
    # validates facts, units, paths, tests and extra fields without trusting hints.


def inspected_baseline(repo, ids):
    state = setup(repo)
    try:
        score = h.public_score(state, ids)
        h.require({k:score[k] for k in ('passed','failed','errors','total')}
                  == {'passed':6,'failed':7,'errors':2,'total':15}, 'BASELINE_SCORE_MISMATCH')
        return artifact(state, ids), score
    finally: h.cleanup_state(state)


def prepare(commit, order):
    h.require(order in (['auto','gptoss'],['gptoss','auto']), 'ORDER_INVALID')
    h.prerequisites(commit)
    h.secure_dir(h.EVIDENCE);h.secure_dir(h.EVALS)
    name='stage28-ab-'+uuid.uuid4().hex
    directory=h.EVIDENCE/name;work=h.EVALS/name
    directory.mkdir(mode=0o700);work.mkdir(mode=0o700)
    ids=h.identifiers(h.BASELINE);workspaces={};frozen=None;baseline=None
    for arm in order:
        repo=work/('shipment-stage28-'+arm)
        h.git(h.ROOT,'clone','--quiet','--no-local','--no-hardlinks','--no-checkout','--',str(h.BASELINE),str(repo))
        h.git(repo,'checkout','--quiet','--detach',h.BASELINE_COMMIT)
        h.repo_check(repo,h.BASELINE_COMMIT)
        current,score=inspected_baseline(repo,ids)
        if frozen is None: frozen,baseline=current,score
        h.require(canonical(current)==canonical(frozen) and score==baseline, 'ARM_INPUTS_DIFFER')
        h.repo_check(repo,h.BASELINE_COMMIT);workspaces[arm]=str(repo)
    h.write_record(directory/'frozen-plan.json',frozen)
    plan={'schema_version':1,'experiment_id':name,'controller_commit':commit,
          'baseline_commit':h.BASELINE_COMMIT,'run_order':order,'workspaces':workspaces,
          'frozen_plan_sha256':h.digest((directory/'frozen-plan.json').read_bytes()),
          'role_profiles':{a:profiles(a) for a in h.ARMS},'baseline':baseline,
          'created_at':h.utc(),'hidden_suite_available':False,'promotion_to_canonical_allowed':False}
    h.write_record(directory/'plan.json',plan)
    return {'status':'DRY_RUN_PASS','plan':str(directory/'plan.json'),
            'frozen_plan_sha256':plan['frozen_plan_sha256'],'baseline':{k:baseline[k] for k in ('passed','failed','errors','total')},
            'models_invoked':0,'planner_model':False,'reviewer_model':False}


def load(path):
    h.require(path.name=='plan.json' and path.parent.parent==h.EVIDENCE and not path.parent.is_symlink(), 'PLAN_PATH_INVALID')
    plan=h.read_record(path)
    h.require(plan.get('schema_version')==1 and plan.get('experiment_id')==path.parent.name
              and path.parent.name.startswith('stage28-ab-') and plan.get('baseline_commit')==h.BASELINE_COMMIT
              and plan.get('run_order') in (['auto','gptoss'],['gptoss','auto'])
              and plan.get('role_profiles')=={a:profiles(a) for a in h.ARMS}
              and plan.get('hidden_suite_available') is False
              and plan.get('promotion_to_canonical_allowed') is False, 'PLAN_INVALID')
    for arm in h.ARMS:
        h.require(plan.get('workspaces',{}).get(arm)==str(h.EVALS/plan['experiment_id']/('shipment-stage28-'+arm)), 'PLAN_WORKSPACE_INVALID')
    frozen=h.read_record(path.parent/'frozen-plan.json')
    raw=(path.parent/'frozen-plan.json').read_bytes()
    h.require(h.digest(raw)==plan.get('frozen_plan_sha256'), 'FROZEN_HASH_CHANGED')
    check_frozen(frozen)
    h.require(raw==canonical(frozen), 'FROZEN_ENCODING_INVALID')
    return plan,frozen


def eligible(path, plan, arm):
    h.require(arm in h.ARMS, 'ARM_INVALID')
    h.require(not (path.parent/(arm+'-started.json')).exists(), 'ARM_ALREADY_ATTEMPTED')
    for previous in plan['run_order'][:plan['run_order'].index(arm)]:
        record=h.read_record(path.parent/(previous+'-result.json'))
        marker=h.read_record(path.parent/(previous+'-started.json'))
        h.require(record.get('plan_sha256')==marker.get('plan_sha256')==h.digest(path.read_bytes())
                  and record.get('frozen_plan_sha256')==plan['frozen_plan_sha256']
                  and record.get('arm')==marker.get('arm')==previous
                  and record.get('controller_commit')==plan['controller_commit']
                  and record.get('role_profiles')==profiles(previous), 'PREVIOUS_RECORD_MISMATCH')
        h.require(record.get('cleanup')=='CONFIRMED' and h.confirmed_workers(record), 'PREVIOUS_CLEANUP_UNPROVEN')
        h.require(record.get('failure_class') in ('NONE','ARM_OUTCOME_FAILURE'), 'PREVIOUS_DRIVER_FAILURE')


def validate(path, arm=None):
    plan,frozen=load(path)
    with h.experiment_lock(path.parent):
        if arm: eligible(path,plan,arm)
        h.prerequisites(plan['controller_commit'])
        ids=h.identifiers(h.BASELINE)
        for repo in plan['workspaces'].values():
            repo=Path(repo);h.repo_check(repo,h.BASELINE_COMMIT)
            current,score=inspected_baseline(repo,ids)
            h.require(current==frozen and score==plan['baseline'], 'FROZEN_RECONSTRUCTION_MISMATCH')
            h.repo_check(repo,h.BASELINE_COMMIT)
    return {'status':'DRY_RUN_PASS','models_invoked':0,'frozen_plan_sha256':plan['frozen_plan_sha256']}


def execute(state, selection, phases):
    """Only production Coder/Fixer model boundaries; deterministic routing/testing."""
    def node(role, runner):
        started=time.monotonic_ns()
        with profile_scope(selection): merge(state,runner(state))
        state.setdefault('role_timing_history',[]).append({'role':role,'elapsed_ms':(time.monotonic_ns()-started)//1000000})
    node('coder',graph.guarded_coder_node)
    while state.get('status')!='BLOCKED':
        node('tester',graph.tested_unit_node)
        phases.append({'phase':'AFTER_CODER' if state.get('fix_attempts',0)==0 else 'AFTER_FIXER',
                       'fix_attempts':state.get('fix_attempts',0),'public_score':safe_score(state)})
        route=graph.route_after_tester(state)
        if route=='rollback':
            merge(state,graph.rollback_node(state));route=graph.route_after_rollback(state)
        if route!='fixer': break
        h.require(state.get('fix_attempts',0)<graph.MAX_FIX_ATTEMPTS, 'FIXER_BUDGET_INVALID')
        before=state.get('fix_attempts',0)
        node('fixer',graph.fixer_node)
        h.require(state.get('fix_attempts')==before+1, 'FIXER_ATTEMPT_INVALID')
    # No synthetic review or production promotion: a machine PASS stays UNVERIFIED.
    if state.get('status')!='BLOCKED': state['status']='UNVERIFIED'


def safe_score(state):
    summary=h.state_evidence(state)
    h.require(h.confirmed_workers(summary)
              and sum(w['role']=='coder' for w in summary['workers'])==1
              and sum(w['role']=='fixer' for w in summary['workers'])==state.get('fix_attempts',0),
              'WORKER_CLEANUP_UNPROVEN')
    # Uses exact authoritative retained workspace, manifest/inventory checks,
    # networkless production sandbox and unchanged 130s test budget.
    try: return h.public_score(state,h.identifiers(h.BASELINE))
    except h.Abort as exc:
        if str(exc)=='PUBLIC_RESULTS_UNAVAILABLE': return None
        raise


def run(path, arm, live):
    h.require(live,'LIVE_OPT_IN_REQUIRED')
    validate(path,arm) # no generation; validates both fresh clones and all guards
    plan,frozen=load(path)
    with h.experiment_lock(path.parent):
        eligible(path,plan,arm)
        state={};phases=[];started=h.utc();clock=time.monotonic_ns()
        result={'schema_version':1,'arm':arm,'controller_commit':plan['controller_commit'],
                'baseline_commit':h.BASELINE_COMMIT,'plan_sha256':h.digest(path.read_bytes()),
                'frozen_plan_sha256':plan['frozen_plan_sha256'],'role_profiles':profiles(arm),
                'public_before':plan['baseline'],'public_after':None,'phases':phases,
                'started_at':started,'failure':'NONE','failure_class':'NONE',
                'promotion_patch_status':'NONE','production_verified':False,
                'changed_files':[],'final_patch_sha256':None}
        h.write_record(path.parent/(arm+'-started.json'),{'arm':arm,'plan_sha256':result['plan_sha256'],'started_at':started})
        old={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
        def interrupted(signum,frame): raise KeyboardInterrupt()
        try:
            for sig in old: signal.signal(sig,interrupted)
            state=setup(Path(plan['workspaces'][arm]))
            h.require(artifact(state, frozen['public_test_ids'])==frozen,'FROZEN_RECONSTRUCTION_MISMATCH')
            # Inject the validated same artifact, not a newly generated plan.
            for key in ('plan_steps','planner_coding_units','coding_units','repo_facts','repo_facts_text'):
                state[key]=json.loads(json.dumps(frozen[key]))
            execute(state,profiles(arm),phases)
            result.update(h.state_evidence(state))
            result['public_after']=safe_score(state)
            phases.append({'phase':'POST_RUN','fix_attempts':state.get('fix_attempts',0),'public_score':result['public_after']})
            result['post_run_score_semantics']='OBSERVATIONAL_NOT_PRODUCTION_VERIFICATION'
            result.update(h.final_patch(state))
            result['failure_class']='ARM_OUTCOME_FAILURE' if state.get('status')=='BLOCKED' or not result['public_after'] or result['public_after']['passed']!=15 else 'NONE'
        except (Exception,KeyboardInterrupt) as exc:
            result['failure_class']='DRIVER_FAILURE'
            result['failure']=str(exc) if isinstance(exc,h.Abort) and h.CODE.fullmatch(str(exc)) else 'DRIVER_EXCEPTION'
        finally:
            for sig,handler in old.items(): signal.signal(sig,handler)
            result.update(h.state_evidence(state))
            for role in ('coder','fixer'):
                result[role+'_route']=h.route_summary([w for w in result['workers'] if w['role']==role])
            try: result['cleanup']=h.cleanup_state(state)
            except Exception: result['cleanup']='UNPROVEN'
            result['ended_at']=h.utc();result['elapsed_ms']=(time.monotonic_ns()-clock)//1000000
            h.write_record(path.parent/(arm+'-result.json'),result)
        h.repo_check(h.BASELINE,h.BASELINE_COMMIT)
        return result


def compare(path):
    plan,_=load(path);arms={}
    for arm in plan['run_order']:
        record=path.parent/(arm+'-result.json')
        if not record.exists(): arms[arm]={'status':'NOT_RUN'};continue
        value=h.read_record(record)
        h.require(value.get('plan_sha256')==h.digest(path.read_bytes()) and value.get('frozen_plan_sha256')==plan['frozen_plan_sha256']
                  and value.get('arm')==arm and value.get('controller_commit')==plan['controller_commit']
                  and value.get('role_profiles')==profiles(arm), 'COMPARISON_RECORD_MISMATCH')
        allowed={'schema_version','arm','controller_commit','baseline_commit','plan_sha256',
                 'frozen_plan_sha256','role_profiles','public_before','public_after','phases',
                 'started_at','ended_at','elapsed_ms','failure','failure_class',
                 'promotion_patch_status','production_verified','changed_files','final_patch_sha256',
                 'controller_final_state','block_reason','fix_attempts','target_verification_evidence',
                 'role_timings_ms','workers','coding_route','worker_cleanup','fixer_invocations',
                 'verification_status','preflight','post_run_score_semantics','patch_hash_format',
                 'coder_route','fixer_route','cleanup'}
        h.require(set(value)<=allowed and value.get('production_verified') is False
                  and value.get('promotion_patch_status')=='NONE', 'COMPARISON_RECORD_INVALID')
        value['target_verification_evidence']=h._evidence(value.get('target_verification_evidence'))
        value['workers']=[{'role':w['role'],'evidence':h._evidence(w.get('evidence'))}
                          for w in value.get('workers',[])[:3] if w.get('role') in ('coder','fixer')]
        for role in ('coder','fixer'):
            value[role+'_route']=h.route_summary([w for w in value['workers'] if w['role']==role])
        arms[arm]=value
    return {'arms':arms,'baseline':plan['baseline'],'frozen_plan_sha256':plan['frozen_plan_sha256'],
            'single_run_only':True,'statistical_superiority_claimed':False,'hidden_suite_available':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_subparsers(dest='action',required=True)
    p=actions.add_parser('prepare');p.add_argument('--expected-controller-commit',required=True);p.add_argument('--order',choices=('auto,gptoss','gptoss,auto'),required=True)
    for action in ('validate','run','compare'):
        p=actions.add_parser(action);p.add_argument('--plan',type=Path,required=True)
        if action in ('validate','run'): p.add_argument('--arm',choices=tuple(h.ARMS),required=action=='run')
        if action=='run': p.add_argument('--live',action='store_true')
    args=parser.parse_args(argv)
    try:
        with redirect_stdout(h.DiscardOutput()),redirect_stderr(h.DiscardOutput()):
            if args.action=='prepare': result=prepare(args.expected_controller_commit,args.order.split(','))
            elif args.action=='validate': result=validate(args.plan,args.arm)
            elif args.action=='compare': result=compare(args.plan)
            else: result=run(args.plan,args.arm,args.live)
        print(json.dumps(result,sort_keys=True));return 2 if result.get('failure_class')=='DRIVER_FAILURE' or result.get('cleanup')=='UNPROVEN' else 0
    except Exception as exc:
        reason=str(exc) if isinstance(exc,h.Abort) and h.CODE.fullmatch(str(exc)) else 'BENCHMARK_CONTROLLER_FAILURE'
        print(json.dumps({'status':'BLOCKED','reason':reason}));return 2


if __name__=='__main__': sys.exit(main())
