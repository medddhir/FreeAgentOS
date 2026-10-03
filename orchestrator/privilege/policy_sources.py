"""Bounded, non-executing identity of installed authoritative policy sources.

No caller/config/environment path. The service separately validates root-owned
package ancestry; clients use their installed package. Source-only wheels are
required: missing source never falls back to imported application objects.
"""
import ast
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import stat
from types import MappingProxyType
from .protocol import BoundaryError

MAX_SOURCE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
# FILE binds the complete dedicated policy module; AST binds only named top-level
# definitions plus module-level bindings/statements (including aliases). Names are also
# required in FILE mode, so empty/replaced modules cannot masquerade as policy.
AUTHORITATIVE = MappingProxyType({
    'roles/lease.py': ('FILE', ('BASE_SECONDS','GRACE_SECONDS','RECENT_SECONDS','HARD_SECONDS','hard_cap_seconds','ActivityLease')),
    'roles/activity.py': ('FILE', ('MAX_RECORD_BYTES','MAX_STREAM_BYTES','MAX_EVENTS','MAX_PENDING','ActivityCapture')),
    'roles/broker_telemetry.py': ('FILE', ('COUNTER_MAX','BrokerTelemetry')),
    'roles/broker_session.py': ('FILE', ('BrokerSession','prepare_session')),
    'roles/read_policy.py': ('FILE', ('MAX_READ_FILES','MAX_READ_BYTES','MAX_TOOL_CALLS','MAX_SESSION_BYTES','build_policy','validate_policy')),
    'roles/file_tools.py': ('FILE', ('MAX_MESSAGE_BYTES','FileTools','serve')),
    'roles/coding_units.py': ('FILE', ('MAX_UNITS','MAX_TARGET_FILES','MAX_CONTEXT_FILES','validate_planner_units','derive_explicit_units','local_context_packet')),
    'roles/intermediate_repair.py': ('FILE', ('repair_checkpoint','repair_targets','completed_repair_error')),
    'roles/repair_context.py': ('FILE', ('MAX_FAILURE_EVIDENCE','MAX_DIFF_BYTES','repair_packet')),
    'roles/research_execution.py': ('FILE', ('run_research_action','run_research_command')),
    'roles/sandbox.py': ('FILE', ('MIB','RESOURCE_POLICY','BoundedCapture','_start_cgroup','_stop_scope','_apply_child_limits','run_isolated')),
    'roles/worker.py': ('AST', ('MIB','WORKER_POLICY','RESEARCH_POLICY','POLICIES','_effective_policy',
                               '_read_worker_streams','_child_limits','_run_inner','_run_worker_impl')),
    'roles/planner.py': ('AST', ('PLANNER_TIMEOUT',)),
    'roles/coder.py': ('AST', ('CODER_TIMEOUT',)),
    'roles/fixer.py': ('AST', ('FIXER_TIMEOUT','fixer_node')),
    'roles/reviewer.py': ('AST', ('REVIEWER_TIMEOUT','machine_verification_error')),
    'roles/tester.py': ('AST', ('TEST_TIMEOUT','_is_test_file')),
    'graph.py': ('AST', ('MAX_FIX_ATTEMPTS','route_after_tester','tested_unit_node','route_after_fixer')),
    'roles/inspector.py': ('AST', ('EXCLUDED','MANIFESTS','SECRET_NAME','OPAQUE','safe_path','_parent_fd','_read')),
    'roles/integrity.py': ('AST', ('policy_summary','is_verification_file','check_baseline','changes','fingerprint')),
    'roles/preflight.py': ('AST', ('STATIC_REQUIRED','REQUIRED')),
    'roles/workspace.py': ('AST', ('MAX_FILES','MAX_BYTES','MAX_FILE_BYTES','SECRET_SUFFIXES','SECRET_PART',
                                  'OPAQUE','SKIP_DIRS','VERIFY_CONFIG','CONTROLLER_FILES','_sha','_controller_hashes','_verify_controller','_read_regular','_excluded','_inventory',
                                  '_load_verified_manifest','verify_execution_contract')),
})
# Explicit existing helper contract: no glob admitting arbitrary adjacent files.
PRIVILEGE_SOURCES = tuple('privilege/'+name+'.py' for name in (
    '__init__','backend','campaign','child','client','evidence','execution','inventory','isolation','journal','kernel',
    'linux','policy','policy_sources','protocol','real_journal','recording','rollback','sealed',
    'security','security_assembly','security_capture','security_collection','security_observe','security_proof','service','socket_state','stress_gate','supervisor','validation'))
NUMBERS = frozenset(('BASE_SECONDS','GRACE_SECONDS','RECENT_SECONDS','HARD_SECONDS',
                     'PLANNER_TIMEOUT','CODER_TIMEOUT','FIXER_TIMEOUT','REVIEWER_TIMEOUT','TEST_TIMEOUT','MAX_FIX_ATTEMPTS',
                     'MAX_READ_FILES','MAX_READ_BYTES','MAX_TOOL_CALLS','MAX_SESSION_BYTES','MAX_UNITS','MAX_TARGET_FILES',
                     'MAX_CONTEXT_FILES','MAX_RECORD_BYTES','MAX_STREAM_BYTES','MAX_EVENTS','MAX_PENDING','COUNTER_MAX',
                     'MAX_MESSAGE_BYTES','MAX_FAILURE_EVIDENCE','MAX_DIFF_BYTES','MAX_FILES','MAX_BYTES','MAX_FILE_BYTES'))


def _source_root():return Path(__file__).resolve().parents[1]


def _read_source(root_fd, relative):
    """Only code-owned allowlisted names; no symlink/file-type fallback."""
    if relative not in AUTHORITATIVE and relative not in PRIVILEGE_SOURCES:
        raise BoundaryError('POLICY_REJECTED')
    directory=os.dup(root_fd)
    try:
        parts=relative.split('/')
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            os.close(directory);directory=child
        fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=MAX_SOURCE_BYTES:
                raise BoundaryError('POLICY_REJECTED')
            chunks=[];remaining=MAX_SOURCE_BYTES+1
            while remaining:
                chunk=os.read(fd,min(remaining,65536))
                if not chunk:break
                chunks.append(chunk);remaining-=len(chunk)
            raw=b''.join(chunks);after=os.fstat(fd)
            identity=lambda i:(i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
            if len(raw)!=before.st_size or identity(before)!=identity(after):raise BoundaryError('POLICY_REJECTED')
            return raw
        finally:os.close(fd)
    except OSError:raise BoundaryError('POLICY_REJECTED') from None
    finally:os.close(directory)


def _tree(raw):
    try:return ast.parse(raw.decode('utf-8'))
    except (UnicodeError,SyntaxError,ValueError,RecursionError):raise BoundaryError('POLICY_REJECTED') from None


def _definitions(tree):
    result={}
    for node in tree.body:
        names=([node.name] if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) else
               [t.id for t in node.targets if isinstance(t,ast.Name)] if isinstance(node,ast.Assign) else [])
        for name in names:
            if name in result:raise BoundaryError('POLICY_REJECTED')
            result[name]=node
    return result


def _integer(node,definitions):
    if isinstance(node,ast.Constant) and type(node.value) is int:return node.value
    if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Mult):
        return _integer(node.left,definitions)*_integer(node.right,definitions)
    if isinstance(node,ast.Name) and node.id=='MIB':
        mib=definitions.get('MIB')
        if isinstance(mib,ast.Assign) and not any(isinstance(n,ast.Name) for n in ast.walk(mib.value)):
            return _integer(mib.value,{})
    raise BoundaryError('POLICY_REJECTED')


def _resource_literal(tree,name):
    definitions=_definitions(tree);node=definitions.get(name)
    if not isinstance(node,ast.Assign) or not isinstance(node.value,ast.Dict):raise BoundaryError('POLICY_REJECTED')
    value={}
    for key,entry in zip(node.value.keys,node.value.values):
        if not isinstance(key,ast.Constant) or type(key.value) is not str or key.value in value:raise BoundaryError('POLICY_REJECTED')
        number=_integer(entry,definitions)
        if not 0<=number<2**63:raise BoundaryError('POLICY_REJECTED')
        value[key.value]=number
    if not value:raise BoundaryError('POLICY_REJECTED')
    return value


MAX_ANALYSES = 64  # at most 16MiB source keys; only immutable digests retained


@lru_cache(maxsize=MAX_ANALYSES)
def _source_digest(relative, raw, rule, numeric_names):
    """Pure byte analysis, never cache a path/stat/FD or mutable AST/result.

    Caller must first securely read the current source. Exact bytes and the
    explicit validation contract are cache keys. Failures are not cached.
    """
    if relative not in AUTHORITATIVE and relative not in PRIVILEGE_SOURCES:
        raise BoundaryError('POLICY_REJECTED')
    if type(raw) is not bytes or not 0<len(raw)<=MAX_SOURCE_BYTES:
        raise BoundaryError('POLICY_REJECTED')
    tree=_tree(raw);mode,names=rule;definitions=_definitions(tree) if names else {}
    if any(name not in definitions for name in names):raise BoundaryError('POLICY_REJECTED')
    for name in names:
        expected=ast.Assign if name.isupper() else ast.ClassDef if name[0].isupper() else ast.FunctionDef
        if not isinstance(definitions[name],expected):raise BoundaryError('POLICY_REJECTED')
    for name in numeric_names:
        node=definitions[name]
        if not isinstance(node,ast.Assign) or not 0<_integer(node.value,definitions)<2**63:
            raise BoundaryError('POLICY_REJECTED')
    for name in set(names)&{'WORKER_POLICY','RESEARCH_POLICY','RESOURCE_POLICY'}:_resource_literal(tree,name)
    if mode=='AST':
        nodes=[n for n in tree.body if not isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))
               or n.name in names]
        raw=ast.dump(ast.Module(body=nodes,type_ignores=[]),include_attributes=False).encode()
    return hashlib.sha256(raw).hexdigest()


def source_identity():
    try:root=os.open(_source_root(),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    except OSError:raise BoundaryError('POLICY_REJECTED') from None
    try:
        total=0;result={}
        for relative in (*AUTHORITATIVE,*PRIVILEGE_SOURCES):
            raw=_read_source(root,relative);total+=len(raw)
            if total>MAX_TOTAL_BYTES:raise BoundaryError('POLICY_REJECTED')
            rule=AUTHORITATIVE.get(relative,('FILE',()))
            numeric_names=tuple(sorted(set(rule[1])&NUMBERS))
            result[relative]=_source_digest(relative,raw,rule,numeric_names)
        return {'binding_version':2,'sources':result}
    except (OSError,ValueError,RecursionError):raise BoundaryError('POLICY_REJECTED') from None
    finally:os.close(root)
