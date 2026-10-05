"""Fixed classes and exact policy envelope; no runtime command from an RPC."""
from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from .protocol import BoundaryError
from . import protocol as wire
from .policy_sources import source_identity, _source_root, _read_source, _tree, _resource_literal
import os


# Parse source literals only; never import production execution.
def _literal(filename, name):
    try:fd=os.open(_source_root(),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    except OSError:raise BoundaryError('POLICY_REJECTED') from None
    try:return _resource_literal(_tree(_read_source(fd,'roles/'+filename)),name)
    finally:os.close(fd)


@dataclass(frozen=True)
class ExecutionClass:
    roles: tuple
    recipe: str
    identity: str
    executable_rule: str
    argv_rule: str
    cwd_rule: str
    limits: object


CLASSES=MappingProxyType({
 'MODEL_WORKER':ExecutionClass(('planner','coder','fixer','reviewer'),'MODEL','MODEL_UID',
        'REGISTERED_ADAPTER_AFTER_DROP','STRUCTURED_ADAPTER','SEALED_WORKSPACE',MappingProxyType(_literal('worker.py','WORKER_POLICY'))),
 'DETERMINISTIC_TESTER':ExecutionClass(('tester',),'TEST','TEST_UID','FIXED_VERIFICATION_RUNNER',
        'FIXED_TEST_ENTRY','TEST_COPY',MappingProxyType(_literal('sandbox.py','RESOURCE_POLICY'))),
 'RESEARCH_HELPER':ExecutionClass(('research:exa','research:dev_api','research:prompt','research:jina'),
        'RESEARCH','RESEARCH_UID','FIXED_RESEARCH_ACTION','VALIDATED_RESEARCH','REGISTERED_RUNTIME',MappingProxyType(_literal('worker.py','RESEARCH_POLICY'))),
})
RECIPES=MappingProxyType({
    'MODEL':('PRIVATE_PID','PRIVATE_MOUNT','CONTROLLER_READONLY','CGROUP_READONLY','BROKER_ONLY_FILES','NETWORK_GATEWAY'),
    'TEST':('PRIVATE_PID','PRIVATE_MOUNT','PRIVATE_NET','CHROOT','RUNTIME_READONLY','BOUNDED_TMPFS','TEST_COPY'),
    'RESEARCH':('PRIVATE_PID','PRIVATE_MOUNT','CONTROLLER_READONLY','CGROUP_READONLY','FIXED_RESEARCH_NETWORK'),
})
ENVIRONMENT=MappingProxyType({'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
TEXT_LIMITS=MappingProxyType(_literal('worker.py','TEXT_INFERENCE_LIMITS'))


def text_resource_limits(role, values):
    """Exact effective values, distinct from preparation's policy identity.

    Observe the existing profile as source data in the protected layer; never
    import production execution or accept a partial/in-envelope substitute.
    """
    if (type(values) is not dict or set(values)!=set(TEXT_LIMITS)
            or any(type(values[k]) is not int or values[k]!=v for k,v in TEXT_LIMITS.items())):
        raise BoundaryError('RESOURCE_LIMIT_INVALID')
    if resource_limits('MODEL_WORKER',role,values)!=values:
        raise BoundaryError('RESOURCE_LIMIT_INVALID')
    return dict(values)


def worker_environment(supplied):
    # Privileged code never inherits caller PATH, loader, shell or Python hooks.
    if type(supplied) is not dict:raise BoundaryError('INVALID_REQUEST')
    return dict(ENVIRONMENT)


def policy_hash():
    value={'version':wire.VERSION,'build':wire.BUILD,'operations':wire.OPERATIONS,'states':wire.STATES,
           'authentication':{'token_bits':256,'id_bits':128,'peer':'SO_PEERCRED','binding':'CONNECTION','file_mode':384,'parent_mode':448},
           'classes':{name:{**vars(c),'limits':dict(c.limits)} for name,c in CLASSES.items()},
           'recipes':dict(RECIPES),'path_rules':('EXACT_RELATIVE','NO_SYMLINK','SINGLE_LINK','PINNED_REGISTERED_ROOT'),
           'protocol_bounds':{'frame':wire.MAX_FRAME,'clients':wire.MAX_CLIENTS,'active':wire.MAX_ACTIVE,
                              'per_uid':wire.MAX_PER_UID,'entries':wire.MAX_ENTRIES,'requests':wire.MAX_REQUESTS,'rate':wire.MAX_RATE,'journal_bytes':wire.MAX_JOURNAL,'transport_timeout_ms':int(wire.TIMEOUT*1000)},
           'environment':dict(ENVIRONMENT),'authoritative_contract':source_identity()}
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def execution_class(name, role):
    if name not in CLASSES or role not in CLASSES[name].roles:raise BoundaryError('EXECUTION_CLASS_REJECTED')
    return CLASSES[name]


def resource_limits(name, role, values):
    c=execution_class(name,role)
    if type(values) is not dict or set(values)-set(c.limits):raise BoundaryError('RESOURCE_LIMIT_INVALID')
    result=dict(c.limits)
    fixed=('schema_version','cpu_period_us','swap_limit_bytes','termination_grace_seconds')
    for key,value in values.items():
        if type(value) is not int or value < 0 or value > c.limits[key] or (value==0 and key!='swap_limit_bytes'):
            raise BoundaryError('RESOURCE_LIMIT_INVALID')
        if key in fixed and value != c.limits[key]:raise BoundaryError('RESOURCE_LIMIT_INVALID')
        result[key]=value
    return result
