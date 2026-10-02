"""Fixed classes and exact policy envelope; no runtime command from an RPC."""
from dataclasses import dataclass
import ast
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from .protocol import BoundaryError
from . import protocol as wire


# Parse only literal constant assignments; never import production execution.
def _literal(filename, name):
    tree=ast.parse((Path(__file__).parents[1]/'roles'/filename).read_text())
    for statement in tree.body:
        if isinstance(statement,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in statement.targets):
            # Current policies use only integer constants and multiplication by MIB.
            def number(n):
                if isinstance(n,ast.Constant) and type(n.value) is int:return n.value
                if isinstance(n,ast.Name) and n.id=='MIB':return 1024*1024
                if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Mult):return number(n.left)*number(n.right)
                raise BoundaryError('POLICY_REJECTED')
            if not isinstance(statement.value,ast.Dict):raise BoundaryError('POLICY_REJECTED')
            return {ast.literal_eval(k):number(v) for k,v in zip(statement.value.keys,statement.value.values)}
    raise BoundaryError('POLICY_REJECTED')


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
           'environment':dict(ENVIRONMENT),'lease':{'base':180,'grace':60,'hard':240,'recent':30},
           'caps':{'read':8,'write':8,'planner_targets':4,'fixer_attempts':2},
           'linux_contract_sources':{path.name:hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(Path(__file__).parent.glob('*.py'))}}
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
