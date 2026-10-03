"""B9 offline recording recovery and independent absence assessment.

No real system adapter, installation deletion, service action or activation.
Original resource and campaign journals remain immutable inputs/evidence.
"""
import hashlib
import json
import time
from . import protocol as p
from .campaign import RecordingCampaignGuard, canonical
from .real_journal import ResourceJournal, validate
from .policy import policy_hash

MAX_SCOPES=3
MAX_ROUNDS=3
MAX_SECONDS=10.0
RESOURCES=('workers','observers','descriptors','mounts','root','scope')
ACTIONS=('TERMINATE_SCOPE','REMOVE_OWNED_MOUNTS','REMOVE_OWNED_ROOT','REMOVE_OWNED_SCOPE')
BLOCKED=('SOCKET_RETIREMENT','LOCK_RETIREMENT','SERVICE_STOP_REMOVAL','INSTALLATION_REMOVAL')


def recipe_hash():
    return hashlib.sha256(canonical({'version':1,'policy':policy_hash(),'actions':ACTIONS,
        'resources':RESOURCES,'blocked':BLOCKED,'max_scopes':MAX_SCOPES,'max_rounds':MAX_ROUNDS,'deadline_seconds':MAX_SECONDS})).hexdigest()


def resource_identity(record):
    return {k:record[k] for k in ('owner','handle','run_id','policy','class','role','boot_id',
                                  'scope_device','scope_inode','root_device','root_inode')}


def make_plan(guard,journal):
    if type(guard) is not RecordingCampaignGuard or type(journal) is not ResourceJournal:
        raise p.BoundaryError('POLICY_REJECTED')
    context=guard.cleanup_context()  # never claim/resume campaign authorization
    expected=guard.expected
    recipe=recipe_hash()  # one authoritative source snapshot per plan validation
    if (expected['rollback_plan_sha256']!=recipe or hashlib.sha256(canonical(expected)).hexdigest()!=guard.digest or journal.policy!=expected['policy']
            or journal.owner!=expected['owner']):raise p.BoundaryError('POLICY_REJECTED')
    records=journal.load()  # strict original ledger, including RELEASED records
    if len(records)>MAX_SCOPES:raise p.BoundaryError('BOUNDS_EXCEEDED')
    for r in records:validate(r,journal.policy,journal.owner)
    identity={'campaign':expected['campaign'],'installation':expected['installation_sha256'],
              'enrollment':expected['enrollment'],'policy':expected['policy'],'contract_sha256':guard.digest,
              'claim':context['claim'],'rollback_sha256':recipe}
    return {'version':1,'binding':identity,'records':records,'recording_only':True}


class RecordingAbsenceObserver:
    """Separate read path, not executor outcomes; records actual fixture state.

    This is a recording of required independent facts, not a real kernel probe.
    No caller PID/path inspection or supervisor RPC exists.
    """
    def __init__(self,world):self.world=world;self.fail=set()
    def observe(self,plan,record):
        handle=record['handle']
        if handle in self.fail:raise p.BoundaryError('CLEANUP_INCOMPLETE')
        found=self.world.get(handle)
        if found is None:raise p.BoundaryError('CLEANUP_INCOMPLETE')  # missing != absent
        value=json.loads(canonical(found))
        p.keys(value,('binding','identity','states','launch_settled'))
        p.keys(value['states'],RESOURCES)
        if (value['binding']!=plan['binding'] or value['identity']!=resource_identity(record)
                or type(value['launch_settled']) is not bool
                or any(type(v) is not str or v not in ('PRESENT','ABSENT','UNKNOWN') for v in value['states'].values())):
            raise p.BoundaryError('CLEANUP_INCOMPLETE')
        # Neither journal label nor empty scope proves a lost pre-attach child,
        # in-flight observer/task or ambiguous descriptor closure.
        if not value['launch_settled']:value['states']['workers']='UNKNOWN'
        if record.get('collection') in ('PENDING','UNPROVEN'):
            value['states']['observers']='UNKNOWN';value['states']['descriptors']='UNKNOWN'
        return value

    def verify(self,plan):
        details=[]
        for r in plan['records']:
            try:
                obs=self.observe(plan,r)
                confirmed=all(v=='ABSENT' for v in obs['states'].values())
                details.append({'handle':r['handle'],'status':'CONFIRMED' if confirmed else 'UNPROVEN','states':obs['states']})
            except Exception:
                details.append({'handle':r['handle'],'status':'UNPROVEN','states':dict.fromkeys(RESOURCES,'UNKNOWN')})
        # No resources in a ledger is not proof of a complete installation
        # inventory. Full zero residual is never certified by this adapter.
        return {'version':1,'binding':plan['binding'],'source':'INDEPENDENT_RECORDING',
                'scoped_cleanup':'CONFIRMED' if details and all(v['status']=='CONFIRMED' for v in details) else 'UNPROVEN',
                'cleanup':'UNPROVEN','zero_residual':False,'qualifying':False,'details':details,
                'unobserved':list(BLOCKED),'reason':'B10_INVENTORY_REQUIRED'}


class RecordingRecoveryAdapter:
    """Fixed in-memory scoped intentions; no PID/path/command/system actions."""
    def __init__(self,world):self.world=world;self.events=[];self.fail=set();self.leave_residual=set()
    def perform(self,plan,record,action):
        if action not in ACTIONS:raise p.BoundaryError('POLICY_REJECTED')
        # Recheck identity at the mutation boundary, independently of the
        # executor's earlier observation; inode/scope/process substitution blocks.
        found=self.world.get(record['handle'])
        if not found or found['binding']!=plan['binding'] or found['identity']!=resource_identity(record):
            raise p.BoundaryError('CLEANUP_INCOMPLETE')
        states=found['states']
        if action=='TERMINATE_SCOPE' and (not found['launch_settled'] or states['scope']!='PRESENT' or not record['scope_inode']):
            raise p.BoundaryError('CLEANUP_INCOMPLETE')
        if action!='TERMINATE_SCOPE' and (record.get('collection') in ('PENDING','UNPROVEN')
                or any(states[k]!='ABSENT' for k in ('workers','observers','descriptors'))):raise p.BoundaryError('CLEANUP_INCOMPLETE')
        if action=='REMOVE_OWNED_ROOT' and states['mounts']!='ABSENT':raise p.BoundaryError('CLEANUP_INCOMPLETE')
        self.events.append((record['handle'],action))
        if action in self.fail:raise p.BoundaryError('BACKEND_FAILURE')
        if action in self.leave_residual:return
        states=found['states']
        if action=='TERMINATE_SCOPE':
            states['workers']='ABSENT'
            # Only fixture-recorded settled observers/descriptors can be absent.
            # No POSIX wait/reap or guessed FD closure is performed offline.
        elif action=='REMOVE_OWNED_MOUNTS':states['mounts']='ABSENT'
        elif action=='REMOVE_OWNED_ROOT':states['root']='ABSENT'
        else:states['scope']='ABSENT'


class RecordingRollback:
    def __init__(self,guard,journal,adapter,observer,*,clock=time.monotonic):
        if type(adapter) is not RecordingRecoveryAdapter or type(observer) is not RecordingAbsenceObserver:
            raise p.BoundaryError('POLICY_REJECTED')
        self.guard=guard;self.journal=journal;self.adapter=adapter;self.observer=observer;self.clock=clock

    def run(self):
        plan=make_plan(self.guard,self.journal)
        # Existing campaign lock held throughout. Append-only recovery rounds
        # permit explicit scoped cleanup retries, NEVER a new campaign ticket.
        round_number=next((n for n in range(MAX_ROUNDS) if not self.guard._exists('rollback-'+str(n)+'.json')),None)
        if round_number is None:raise p.BoundaryError('RECOVERY_REQUIRED')
        digest=hashlib.sha256(canonical(plan)).hexdigest()
        start=self.clock();prefix='rollback-'+str(round_number)
        self.guard._persist(prefix+'.json',{'version':1,'binding':plan['binding'],'plan_sha256':digest,'state':'INTENT'})
        outcomes=[];failed=False;index=0
        for r in plan['records']:
            for action in ACTIONS:
                if self.clock()-start>MAX_SECONDS:failed=True;break
                try:
                    self.guard._check()
                    # Detect journal replacement/content drift before every
                    # decision. Never rebind to a different recovery plan.
                    context=self.guard.cleanup_context()
                    if (self.journal.load()!=plan['records'] or context['claim']!=plan['binding']['claim']
                            or hashlib.sha256(canonical(self.guard.expected)).hexdigest()!=plan['binding']['contract_sha256']):
                        raise p.BoundaryError('JOURNAL_INVALID')
                    obs=self.observer.observe(plan,r);states=obs['states']
                    target={'TERMINATE_SCOPE':'workers','REMOVE_OWNED_MOUNTS':'mounts',
                            'REMOVE_OWNED_ROOT':'root','REMOVE_OWNED_SCOPE':'scope'}[action]
                    if states[target]=='ABSENT':continue  # independently absent, not a past SUCCESS label
                    if states[target]=='UNKNOWN':raise p.BoundaryError('CLEANUP_INCOMPLETE')
                    if action=='TERMINATE_SCOPE' and (states['scope']!='PRESENT' or not r['scope_inode']):raise p.BoundaryError('CLEANUP_INCOMPLETE')
                    if action!='TERMINATE_SCOPE' and any(states[k]!='ABSENT' for k in ('workers','observers','descriptors')):
                        raise p.BoundaryError('CLEANUP_INCOMPLETE')
                    if action=='REMOVE_OWNED_ROOT' and states['mounts']!='ABSENT':raise p.BoundaryError('CLEANUP_INCOMPLETE')
                    if action in ('REMOVE_OWNED_MOUNTS','REMOVE_OWNED_ROOT') and not r['root_inode']:raise p.BoundaryError('CLEANUP_INCOMPLETE')
                    if action=='REMOVE_OWNED_SCOPE' and not r['scope_inode']:raise p.BoundaryError('CLEANUP_INCOMPLETE')
                    marker=prefix+'-action-'+str(index);index+=1
                    self.guard._persist(marker+'.json',{'version':1,'plan_sha256':digest,'handle':r['handle'],'action':action,'state':'INTENT'})
                    self.adapter.perform(plan,r,action)
                    outcomes.append({'handle':r['handle'],'action':action,'result':'RECORDED'})
                except Exception:
                    failed=True;outcomes.append({'handle':r['handle'],'action':action,'result':'UNPROVEN'})
                    # Continue only fresh independently proven actions/resources.
        proof=self.observer.verify(plan)
        dirty=failed or proof['scoped_cleanup']!='CONFIRMED'
        result={'version':1,'binding':plan['binding'],'plan_sha256':digest,'round':round_number,
                'state':'FAILED_DIRTY' if dirty else 'SCOPED_RECORDING_CLEAN','outcomes':outcomes,
                'verification':proof,'admission_fenced':True,'execution_enabled':False}
        try:self.guard._persist(prefix+'-result.json',result)
        except Exception:raise p.BoundaryError('CLEANUP_INCOMPLETE') from None
        return result


def inventory_plan(guard,journal,inventory,observed):
    """B10 recording prerequisite; never enables installation removal."""
    from .inventory import prerequisite
    proof=prerequisite(inventory,observed,guard.expected)
    return {'recovery':make_plan(guard,journal),'inventory':proof,'removal_enabled':False}
