"""Bounded recording assessment using B8 snapshots and authenticated cleanup.

No campaign authority, kernel reads, launch, cleanup executor or qualification.
"""
import hashlib
import json
from . import protocol as p, security_proof as s
from .stress_gate import PreparedProbe, SELECTORS, FIXTURE_SHA256, PRECONDITIONS

FIELDS={'DEMAND':('selector','plan_sha256','runnable_tasks','allocation_bytes','fork_attempts'),
        'OUTCOME':('plan_sha256','state','exec_transition','exit_status','cause')}

def metadata(kind,value,x):
    from . import security_collection as c
    p.keys(value,c.CAPTURE_FIELDS);c.identity(value,x)
    if (type(value['schema_version']) is not int or value['schema_version']!=1
            or value['source']!='INDEPENDENT_RECORDING' or value['enforcement']!='UNPROVEN'
            or type(value['at_ns']) is not int or not x.started_ns<=value['at_ns']<=x.started_ns+s.MAX_CAPTURE_NS):
        raise p.BoundaryError('INVALID_REQUEST')
    data=value['data'];p.keys(data,FIELDS[kind])
    if not p.identifier(data['plan_sha256'],64):raise p.BoundaryError('POLICY_REJECTED')
    if kind=='DEMAND':
        if (data['selector'] not in SELECTORS or any(type(data[k]) is not int or not 0<=data[k]<=maximum
                for k,maximum in (('runnable_tasks',3),('allocation_bytes',96*1024*1024),('fork_attempts',16)))):
            raise p.BoundaryError('INVALID_REQUEST')
    elif (data['state'] not in ('COMPLETED','RESOURCE_TERMINATED','TIMEOUT','ABNORMAL','MISSING')
            or data['exec_transition'] not in ('RECORDED','UNPROVEN')
            or type(data['exit_status']) is not int or not -255<=data['exit_status']<=255
            or data['cause'] not in ('EXPECTED_COMPLETION','OOM_MATCHED','TIMEOUT','UNRELATED','MISSING')):
        raise p.BoundaryError('INVALID_REQUEST')
    return value


def plan_value(prepared,x):
    if (type(prepared) is not PreparedProbe or type(prepared.payload) is not bytes or len(prepared.payload)>4096
            or hashlib.sha256(prepared.payload).hexdigest()!=prepared.digest):raise p.BoundaryError('POLICY_REJECTED')
    try:plan=json.loads(prepared.payload,object_pairs_hook=p._pairs)
    except (ValueError,UnicodeError,RecursionError):raise p.BoundaryError('INVALID_REQUEST') from None
    argv=plan.get('argv') if type(plan) is dict else None
    selector=argv[1][2:] if type(argv) is list and len(argv)==2 and type(argv[1]) is str else None
    if selector not in SELECTORS:raise p.BoundaryError('POLICY_REJECTED')
    expected=s.probe_plan(x,selector)
    if not p.identifier(plan.get('seal'),64):raise p.BoundaryError('POLICY_REJECTED')
    expected.update(seal=plan['seal'],fixture_source_sha256=FIXTURE_SHA256,authorization='RECORDING_ONLY',
                    enforcement='UNPROVEN',containment={k:'INDEPENDENT_RECORDING' for k in PRECONDITIONS},execution_enabled=False)
    if prepared.payload!=json.dumps(expected,sort_keys=True,separators=(',',':')).encode():raise p.BoundaryError('POLICY_REJECTED')
    return plan,selector


def assess(x,prepared,report,cleanup='UNPROVEN'):
    from . import security_collection as c
    if cleanup not in ('CONFIRMED','UNPROVEN'):raise p.BoundaryError('INVALID_REQUEST')
    result={'schema_version':1,'completeness':'INCOMPLETE','recorded_assessment':'INCONCLUSIVE',
            'enforcement':'UNPROVEN','qualifying':False,'cleanup':cleanup,'cleanup_obligation':cleanup!='CONFIRMED',
            'reason':'EVIDENCE_MISSING','proof':None}
    try:
        _,kind=plan_value(prepared,x);c.validate_report(report,x)
        if not report['collector_closed'] or report['status'] in ('PENDING','REJECTED'):
            result['reason']='CAPTURE_INCOMPLETE';return result
        values=report['observations']
        demand=[i['value'] for i in values if i['kind']=='DEMAND']
        outcome=[i['value'] for i in values if i['kind']=='OUTCOME']
        records=[i['value'] for i in values if i['kind']=='PROOF_RECORD']
        if not demand or not outcome:return result
        demand=demand[0];outcome=outcome[0]
        if demand['data']['plan_sha256']!=prepared.digest or outcome['data']['plan_sha256']!=prepared.digest or demand['data']['selector']!=kind:
            raise p.BoundaryError('POLICY_REJECTED')
        pair=[v for v in records if v['kind']==kind and v['source']=='INDEPENDENT_RECORDING']
        phases={v['phase']:v for v in pair}
        if not {'BEFORE','AFTER'}<=set(phases):return result
        before,after=phases['BEFORE'],phases['AFTER']
        if not x.started_ns<=before['at_ns']<=demand['at_ns']<after['at_ns']<=outcome['at_ns']<=x.started_ns+s.MAX_PROBE_NS:
            raise p.BoundaryError('INVALID_REQUEST')
        data=demand['data'];exit=outcome['data'];a=after['data']
        if kind=='cpu':adequate=data['runnable_tasks']>=2 and not data['allocation_bytes'] and not data['fork_attempts'] and a['runnable_tasks']==data['runnable_tasks']
        elif kind=='memory':adequate=data['allocation_bytes']>x.limits['memory_limit_bytes'] and not data['fork_attempts']
        else:adequate=data['fork_attempts']>x.limits['max_processes'] and not data['allocation_bytes'] and a['created']<=data['fork_attempts']
        if not adequate:result['reason']='DEMAND_UNPROVEN';return result
        state=exit['state']
        if (exit['exec_transition']!='RECORDED' or (state=='COMPLETED' and (exit['cause']!='EXPECTED_COMPLETION' or exit['exit_status']!=0))
                or (state=='RESOURCE_TERMINATED' and (kind!='memory' or exit['cause']!='OOM_MATCHED' or exit['exit_status']==0))):
            result['reason']='EXECUTION_UNPROVEN';return result
        proof=s.evaluate(x,records,execution=state,cleanup=cleanup)['proofs'][kind]
        result['proof']=proof
        if proof['assessment']=='INCONCLUSIVE':result['reason']=proof['reason'];return result
        result['completeness']='COMPLETE' if cleanup=='CONFIRMED' else 'OBSERVATIONS_COMPLETE'
        result['reason']='CLEANUP_UNPROVEN' if cleanup!='CONFIRMED' else proof['reason']
        if cleanup=='CONFIRMED':result['recorded_assessment']=proof['assessment']
        return result
    except (p.BoundaryError,TypeError,ValueError,KeyError,RecursionError):
        result['reason']='EVIDENCE_INVALID';return result
