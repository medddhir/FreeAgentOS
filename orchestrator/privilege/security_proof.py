"""B8 preparation: bounded independent-observation contracts and pure evaluators.

No kernel operations, launching or readiness certification. Recordings exercise
proof criteria but NEVER establish real enforcement. No model/tool RPC imports.
"""
import json
from dataclasses import dataclass
from types import MappingProxyType
from . import protocol as p
from .evidence import BINDING, validate_binding
from .policy import resource_limits

SCHEMA=1
MAX_RECORD_BYTES=8192
MAX_RECORDS=24
MAX_BUFFER_BYTES=65536
MAX_CAPTURE_NS=10_000_000_000
MAX_PROBE_NS=5_000_000_000
MAX_FDS=256
MAX_GROUPS=16
MAX_PROCESSES=64
MAX_MOUNTS=32
MAX_RAW_BYTES=65536
KINDS=('identity','capabilities','fds','namespaces','filesystem','descendants','cpu','memory','pids')
SOURCES=('CONFIGURED','CHILD_REPORTED','INDEPENDENT_RECORDING')
# Samples are deliberately small summaries; raw status/mountinfo/paths stay private.
FIELDS=MappingProxyType({
 'identity':('uids','gids','groups'),
 'capabilities':('inheritable','permitted','effective','bounding','ambient','no_new_privs'),
 'fds':('open','unexpected','standard_safe'),
 'namespaces':('host','worker','inner_pid'),
 'filesystem':('root_matches_runtime','root_readonly','private_propagation','mounts_exact','proc_private','devices_exact','forbidden_absent'),
 'descendants':('created','contained','namespace_checked','population','pidfds_exited','scope_empty','reaped','released','cleanup_confirmed'),
 'cpu':('quota_us','period_us','elapsed_ns','usage_usec','periods','throttled_periods','throttled_usec','runnable_tasks','work_completed','cpus_available'),
 'memory':('limit_bytes','swap_bytes','peak_bytes','max_events','oom_events','oom_kills','work_completed','termination_requested'),
 'pids':('limit','peak','max_events','created','work_completed'),
})
BOOLS=frozenset(('standard_safe','no_new_privs','root_matches_runtime','root_readonly','private_propagation','mounts_exact','proc_private','devices_exact','forbidden_absent','contained','namespace_checked','pidfds_exited','scope_empty','reaped','released','cleanup_confirmed','work_completed','termination_requested'))
NAMESPACES=('mnt','pid','net','user')
CAPS=('inheritable','permitted','effective','bounding','ambient')

@dataclass(frozen=True)
class ProofExpectation:
    """Trusted registry/ledger facts; never task/model-selected values."""
    binding: object
    uid: int
    gid: int
    limits: object
    sample: str
    started_ns: int
    subject: str
    scope: tuple

    def __post_init__(self):
        validate_binding(self.binding)
        if (any(type(v) is not int or not 1<=v<2**31 for v in (self.uid,self.gid))
                or not p.identifier(self.sample) or not p.identifier(self.subject)
                or type(self.scope) is not tuple or len(self.scope)!=2 or any(type(v) is not int or not 1<=v<2**63 for v in self.scope) or type(self.started_ns) is not int or not 0<=self.started_ns<2**63):
            raise p.BoundaryError('POLICY_REJECTED')
        resource_limits(self.binding['class'],self.binding['role'],self.limits)
        if dict(self.limits)!=resource_limits(self.binding['class'],self.binding['role'],self.limits):
            raise p.BoundaryError('RESOURCE_LIMIT_INVALID')
        object.__setattr__(self,'binding',MappingProxyType(dict(self.binding)))
        object.__setattr__(self,'limits',MappingProxyType(dict(self.limits)))


def _numbers(value,max_items,*,maximum=2**63-1):
    if (type(value) is not list or len(value)>max_items
            or any(type(v) is not int or not 0<=v<=maximum for v in value)):
        raise p.BoundaryError('INVALID_REQUEST')


def _data(kind,value):
    p.keys(value,FIELDS[kind])
    for key,v in value.items():
        if key in ('uids','gids'):
            _numbers(v,4,maximum=2**31-1)
            if len(v)!=4:raise p.BoundaryError('INVALID_REQUEST')
        elif key=='groups':_numbers(v,MAX_GROUPS,maximum=2**31-1)
        elif key in ('open','unexpected'):
            _numbers(v,MAX_FDS,maximum=65535)
            if v!=sorted(set(v)):raise p.BoundaryError('INVALID_REQUEST')
        elif key in ('host','worker'):
            p.keys(v,NAMESPACES)
            if any(type(n) is not int or not 1<=n<2**63 for n in v.values()):raise p.BoundaryError('INVALID_REQUEST')
        elif key in BOOLS:
            if type(v) is not bool:raise p.BoundaryError('INVALID_REQUEST')
        elif type(v) is not int or not 0<=v<2**63:raise p.BoundaryError('INVALID_REQUEST')
    if kind=='fds' and (not set(value['unexpected'])<=set(value['open']) or value['unexpected']!=[v for v in value['open'] if v>2]):
        raise p.BoundaryError('INVALID_REQUEST')
    if kind=='cpu' and (value['throttled_periods']>value['periods'] or value['elapsed_ns']>MAX_PROBE_NS):raise p.BoundaryError('INVALID_REQUEST')
    if kind in ('descendants','pids') and any(value.get(k,0)>MAX_PROCESSES for k in ('created','population','peak','limit')):raise p.BoundaryError('BOUNDS_EXCEEDED')
    if kind=='descendants' and value['scope_empty']!=(value['population']==0):raise p.BoundaryError('INVALID_REQUEST')


def record(expectation,kind,source,phase,data,at_ns):
    return validate({'schema_version':SCHEMA,'binding':dict(expectation.binding),'sample':expectation.sample,'subject':expectation.subject,'scope':list(expectation.scope),
                     'kind':kind,'source':source,'phase':phase,'at_ns':at_ns,'data':data},expectation)


def validate(value,expectation):
    p.keys(value,('schema_version','binding','sample','subject','scope','kind','source','phase','at_ns','data'))
    if (type(value['schema_version']) is not int or value['schema_version']!=SCHEMA
            or value['binding']!=dict(expectation.binding) or value['sample']!=expectation.sample
            or value['subject']!=expectation.subject or value['scope']!=list(expectation.scope)
            or type(value['scope']) is not list or any(type(n) is not int for n in value['scope'])
            or type(value['kind']) is not str or value['kind'] not in KINDS or value['source'] not in SOURCES
            or value['phase'] not in ('BEFORE','DURING','AFTER') or type(value['at_ns']) is not int
            or not expectation.started_ns<=value['at_ns']<=expectation.started_ns+MAX_CAPTURE_NS):
        raise p.BoundaryError('INVALID_REQUEST')
    validate_binding(value['binding']);_data(value['kind'],value['data'])
    try:raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (ValueError,TypeError,RecursionError):raise p.BoundaryError('INVALID_REQUEST') from None
    if len(raw)>MAX_RECORD_BYTES:raise p.BoundaryError('BOUNDS_EXCEEDED')
    return value


class RecordBuffer:
    """Separate versioned B8 sidecar, NOT a bypass of B7 stdout/RPC limits.

    Inputs are trusted observer summaries or explicitly labeled recordings.
    No KERNEL source claim is accepted, and no live collector is activated here.
    """
    def __init__(self,expectation):self.expectation=expectation;self.records=[];self.size=0;self.failed=False
    def add(self,raw):
        if self.failed:raise p.BoundaryError('INVALID_STATE')
        try:
            if type(raw) is not bytes or not raw.endswith(b'\n') or len(raw)>MAX_RECORD_BYTES+1:raise p.BoundaryError('BOUNDS_EXCEEDED')
            value=json.loads(raw,object_pairs_hook=p._pairs);validate(value,self.expectation)
            if (len(self.records)>=MAX_RECORDS or self.size+len(raw)>MAX_BUFFER_BYTES
                    or any((r['kind'],r['source'],r['phase'])==(value['kind'],value['source'],value['phase']) for r in self.records)):
                raise p.BoundaryError('BOUNDS_EXCEEDED')
            if self.records and value['at_ns']<self.records[-1]['at_ns']:raise p.BoundaryError('INVALID_REQUEST')
            self.records.append(value);self.size+=len(raw)
        except (ValueError,TypeError,UnicodeError,RecursionError,p.BoundaryError):
            self.failed=True;self.records.clear();raise p.BoundaryError('INVALID_REQUEST') from None


def evaluate(expectation,records,*,execution='COMPLETED',cleanup='UNPROVEN'):
    """Assess recorded proof predicates; readiness/enforcement stay UNPROVEN.

    INDEPENDENT_RECORDING is a recording of required observer facts, not a
    provenance certificate. Stage31D must gather these via ownership-checked
    kernel access and authenticate the evidence separately.
    """
    result={'schema_version':SCHEMA,'enforcement':'UNPROVEN','cleanup_obligation':cleanup!='CONFIRMED','proofs':{}}
    if execution not in ('COMPLETED','RESOURCE_TERMINATED','TIMEOUT','ABNORMAL','MISSING') or cleanup not in ('CONFIRMED','UNPROVEN'):
        raise p.BoundaryError('INVALID_REQUEST')
    try:
        if type(records) is not list or len(records)>MAX_RECORDS:raise p.BoundaryError('BOUNDS_EXCEEDED')
        buf=RecordBuffer(expectation)
        for v in records:buf.add(json.dumps(v,separators=(',',':')).encode()+b'\n')
    except (p.BoundaryError,TypeError,ValueError,RecursionError):
        for kind in KINDS:result['proofs'][kind]={'assessment':'INCONCLUSIVE','level':'UNPROVEN','reason':'EVIDENCE_INVALID'}
        return result
    for kind in KINDS:
        values=[r for r in buf.records if r['kind']==kind]
        independent=[r for r in values if r['source']=='INDEPENDENT_RECORDING']
        status='INCONCLUSIVE';reason='INDEPENDENT_OBSERVATION_MISSING'
        level='RECORDED' if independent else 'CHILD_REPORTED' if any(r['source']=='CHILD_REPORTED' for r in values) else 'CONFIGURED' if values else 'UNPROVEN'
        by_phase={r['phase']:r['data'] for r in independent}
        if execution in ('TIMEOUT','ABNORMAL','MISSING'):reason='EXECUTION_UNPROVEN'
        elif independent:
            if any(r['source']=='CHILD_REPORTED' and r['phase'] in by_phase and r['data']!=by_phase[r['phase']] for r in values):
                reason='CLAIM_CONTRADICTS_OBSERVATION'
            else:
                if kind=='cpu' and {'BEFORE','AFTER'}<=set(by_phase):
                    times={r['phase']:r['at_ns'] for r in independent}
                    if by_phase['AFTER']['elapsed_ns']!=times['AFTER']-times['BEFORE']:
                        reason='TIME_WINDOW_MISMATCH'
                    else:status,reason=_assess(kind,by_phase,expectation,execution,cleanup)
                else:status,reason=_assess(kind,by_phase,expectation,execution,cleanup)
        result['proofs'][kind]={'assessment':status,'level':level,'reason':reason}
    return result


def _assess(kind,phases,x,execution,cleanup):
    data=phases.get('DURING');limits=x.limits
    if kind=='descendants':
        before=phases.get('DURING');after=phases.get('AFTER')
        if not before or not after:return 'INCONCLUSIVE','PAIRED_OBSERVATION_MISSING'
        if not before['namespace_checked'] or not after['namespace_checked']:return 'INCONCLUSIVE','NAMESPACE_MEMBERSHIP_UNPROVEN'
        if not before['contained'] or not after['contained']:return 'FAIL','CONTAINMENT_FAILED'
        if not before['created']:return 'INCONCLUSIVE','DESCENDANT_NOT_OBSERVED'
        ok=after['scope_empty'] and after['pidfds_exited'] and after['reaped'] and after['released'] and after['cleanup_confirmed'] and cleanup=='CONFIRMED'
        return ('PASS','RECORDED_TERMINATION_MATCH') if ok else ('INCONCLUSIVE','CLEANUP_UNPROVEN')
    if kind in ('cpu','memory','pids'):
        before=phases.get('BEFORE');after=phases.get('AFTER')
        if not before or not after:return 'INCONCLUSIVE','PAIRED_OBSERVATION_MISSING'
        delta=lambda k:after[k]-before[k]
        counters={'cpu':('usage_usec','periods','throttled_periods','throttled_usec'), 'memory':('max_events','oom_events','oom_kills'), 'pids':('max_events',)}[kind]
        if any(delta(k)<0 for k in counters):return 'INCONCLUSIVE','COUNTER_RESET_OR_MISMATCH'
        if kind=='cpu':
            if any(v['quota_us']!=limits['cpu_quota_us'] or v['period_us']!=limits['cpu_period_us'] for v in (before,after)):return 'FAIL','LIMIT_READBACK_MISMATCH'
            if execution!='COMPLETED' or not after['work_completed'] or after['cpus_available']<2 or after['runnable_tasks']<2 or not 2_000_000_000<=after['elapsed_ns']<=MAX_PROBE_NS:return 'INCONCLUSIVE','INSUFFICIENT_STRESS'
            budget=after['elapsed_ns']//1000*limits['cpu_quota_us']//limits['cpu_period_us']
            if delta('usage_usec')>budget*110//100+limits['cpu_quota_us'] or not delta('usage_usec'):return 'FAIL','CPU_ACCOUNTING_OUTSIDE_BOUND'
            return ('PASS','RECORDED_THROTTLING_MATCH') if delta('periods')>=10 and delta('throttled_periods')>0 and delta('throttled_usec')>0 else ('INCONCLUSIVE','ENFORCEMENT_EVENT_MISSING')
        if kind=='memory':
            if any(v['limit_bytes']!=limits['memory_limit_bytes'] or v['swap_bytes']!=limits['swap_limit_bytes'] for v in (before,after)):return 'FAIL','LIMIT_READBACK_MISMATCH'
            if after['peak_bytes']>limits['memory_limit_bytes']+4*1024*1024:return 'FAIL','MEMORY_BOUND_EXCEEDED'
            if after['termination_requested'] or not delta('max_events') or not delta('oom_events') or not delta('oom_kills'):return 'INCONCLUSIVE','ENFORCEMENT_EVENT_MISSING'
            return ('PASS','RECORDED_OOM_MATCH') if execution=='RESOURCE_TERMINATED' else ('INCONCLUSIVE','EXPECTED_RESOURCE_EXIT_MISSING')
        if any(v['limit']!=limits['max_processes'] for v in (before,after)):return 'FAIL','LIMIT_READBACK_MISMATCH'
        if after['peak']>limits['max_processes']:return 'FAIL','PID_BOUND_EXCEEDED'
        if execution!='COMPLETED' or not after['work_completed'] or not after['created']:return 'INCONCLUSIVE','INSUFFICIENT_STRESS'
        return ('PASS','RECORDED_PID_DENIAL_MATCH') if delta('max_events')>0 else ('INCONCLUSIVE','ENFORCEMENT_EVENT_MISSING')
    if not data:return 'INCONCLUSIVE','DURING_OBSERVATION_MISSING'
    if kind=='identity':ok=data['uids']==[x.uid]*4 and data['gids']==[x.gid]*4 and not data['groups']
    elif kind=='capabilities':ok=all(data[k]==0 for k in CAPS) and data['no_new_privs']
    elif kind=='fds':ok=data['open']==[0,1,2] and not data['unexpected'] and data['standard_safe']
    elif kind=='namespaces':ok=all(data['host'][k]!=data['worker'][k] for k in ('mnt','pid','net')) and data['host']['user']==data['worker']['user'] and data['inner_pid']==1
    elif kind=='filesystem':ok=all(data.values())
    else:raise p.BoundaryError('INVALID_REQUEST')
    return ('PASS','RECORDED_ISOLATION_MATCH') if ok else ('FAIL','OBSERVABLE_MISMATCH')


# Fixed lower validation limits within existing ceilings; production defaults
# and 180/current grace/240s lease remain untouched. No execution entrypoint.
PROBE_LIMITS=MappingProxyType({'cpu_quota_us':50000,'memory_limit_bytes':64*1024*1024,'max_processes':8})
PROBE_BOUNDS=MappingProxyType({'observe':(1000,1,0,0),'cpu':(3000,3,4*1024*1024,1_000_000_000),
                             'memory':(4000,1,96*1024*1024,24576),'pids':(4000,17,4*1024*1024,16)})


def probe_plan(expectation,kind):
    if kind not in PROBE_BOUNDS:raise p.BoundaryError('POLICY_REJECTED')
    limits=resource_limits(expectation.binding['class'],expectation.binding['role'],dict(PROBE_LIMITS))
    if dict(expectation.limits)!=limits:raise p.BoundaryError('POLICY_REJECTED')
    return {'schema_version':SCHEMA,'binding':dict(expectation.binding),'fixture':'FREEAGENTOS_SECURITY_V1',
            'argv':['freeagentos-security-probe','--'+kind],'limits':limits,
            'bounds':dict(zip(('wall_ms','processes','allocation_bytes','iterations'),PROBE_BOUNDS[kind])),
            'output_bytes':2048,'records':2,'authorization_gate_fd':3,'authorization':'REQUIRED_NOT_GRANTED',
            'required_containment':('OWNED_CGROUP','OWNED_PIDFD','IDENTITY_AND_CAPABILITY_DROP','PRIVATE_ROOTFS'),
            'executable_transition':'REQUIRES_B7_EQUIVALENT_CLOEXEC_AND_FIXTURE_CHANNEL'}
