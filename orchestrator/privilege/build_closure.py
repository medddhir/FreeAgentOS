"""Reviewed immutable dependency graph, staging only; never a build certificate.

No discovery, imports of observed code, compiler invocation or authority. Graph
completeness is declared by a trusted reviewer; independently proving that graph
against imports/ELF metadata and a toolchain remains required for real use.
"""
from . import inventory as i, protocol as p, installed_identity as n
from .policy import policy_hash

VERSION=1
LAYOUT='UBUNTU24_X86_64_PY312_SUPERVISOR_V1'
MAX_EDGES=4096
CATEGORIES=('PACKAGE','RESOURCE','INTERPRETER','STDLIB','NATIVE','FIXTURE')
NATIVE_FILES=frozenset(('python_base/lib/libpython3.12.so.1.0',
                      'runtime/lib64/ld-linux-x86-64.so.2','runtime/lib/libc.so.6'))
PACKAGE_FILES=frozenset(('package/orchestrator/roles/__init__.py',))
ROOTS=frozenset(('venv/bin/python','runtime/bin/synthetic-worker','runtime/bin/security-probe'))


def category(path):
    if path in ROOTS:return 'INTERPRETER' if path.startswith('venv/') else 'FIXTURE'
    if path.startswith('package/'):return 'PACKAGE' if path.endswith('.py') else 'RESOURCE'
    if path in NATIVE_FILES or path.startswith(('runtime/lib/','runtime/lib64/')):return 'NATIVE'
    return 'STDLIB'


def validate(value,manifest,binding,provenance):
    """Strict graph closure and expected identities; not semantic closure proof."""
    p.keys(value,('version','layout','source_commit','policy','manifest_sha256','artifacts',
                  'roots','third_party','unresolved','provenance','verification'))
    n.validate_manifest(manifest)
    if (type(value['version']) is not int or value['version']!=VERSION or value['layout']!=LAYOUT
            or value['source_commit']!=binding['source_commit'] or value['policy']!=binding['policy']
            or value['policy']!=policy_hash() or value['manifest_sha256']!=i.digest(manifest)
            or value['provenance']!=provenance or value['third_party']!=[] or value['unresolved']!=[]
            or value['verification']!={'dependency_closure':'DECLARED','build':'UNPROVEN','reproducibility':'UNPROVEN'}):
        raise p.BoundaryError('POLICY_REJECTED')
    # This profile is supervisor-only stdlib, not the LangGraph controller venv.
    files={v['path']:v for v in manifest['nodes'] if v['type']=='file'}
    if not NATIVE_FILES|PACKAGE_FILES|n.REQUIRED_FILES<=files.keys():raise p.BoundaryError('POLICY_REJECTED')
    if any('site-packages' in path for path in files):raise p.BoundaryError('POLICY_REJECTED')
    artifacts=value['artifacts'];roots=value['roots']
    expected_roots=sorted(ROOTS|{path for path in files if path.startswith('package/')})
    if type(artifacts) is not list or len(artifacts)!=len(files) or roots!=expected_roots:
        raise p.BoundaryError('POLICY_REJECTED')
    graph={};edges=0
    for item in artifacts:
        p.keys(item,('path','category','sha256','requires'))
        path=item['path'];requires=item['requires']
        if (type(path) is not str or path not in files or path in graph
                or item['category']!=category(path) or item['sha256']!=files[path]['sha256']
                or type(requires) is not list or any(type(v) is not str or v not in files or v==path for v in requires)
                or requires!=sorted(set(requires))):raise p.BoundaryError('POLICY_REJECTED')
        edges+=len(requires)
        if edges>MAX_EDGES:raise p.BoundaryError('BOUNDS_EXCEEDED')
        graph[path]=requires
    if list(graph)!=sorted(files):raise p.BoundaryError('POLICY_REJECTED')
    seen=set();pending=list(roots)
    while pending:
        path=pending.pop()
        if path in seen:continue
        seen.add(path);pending.extend(graph[path])
    if seen!=set(files):raise p.BoundaryError('POLICY_REJECTED')
    for path,key in (('venv/bin/python','launcher_sha256'),('runtime/bin/synthetic-worker','synthetic_sha256'),
                     ('runtime/bin/security-probe','security_probe_sha256')):
        if files[path]['sha256']!=provenance[key]:raise p.BoundaryError('POLICY_REJECTED')
    return i.digest(value)


def preapproval_identity(plan,closure_sha256):
    """Acyclic immutable installation intent, excludes all mutable state bytes."""
    i.validate_plan(plan)
    if plan.get('phase')!='PRE_APPROVAL' or not p.identifier(closure_sha256,64):raise p.BoundaryError('POLICY_REJECTED')
    return i.digest({'version':VERSION,'binding':plan['binding'],'provenance':plan['provenance'],
                     'closure_sha256':closure_sha256,
                     'immutable':[e for e in plan['entries'] if e['category']=='IMMUTABLE']})


class StagingClosureRegistration(n.RecordingRegistration):
    """Existing receipt/registration persistence with mandatory fresh closure input.

    Separate preparation consumer; service and campaign authority are unchanged.
    """
    @staticmethod
    def candidate_prerequisite(tree,snapshot,closure,binding,provenance):
        """Fresh candidate assessment shared with receipt registration.

        Passing this gate alone is neither a receipt nor protected registration.
        """
        from .closure_verify import analyze
        analysis=analyze(tree,snapshot,closure,binding,provenance)
        if analysis['status']!='STATIC_METADATA_VERIFIED':raise p.BoundaryError('POLICY_REJECTED')
        return {'analysis':analysis,'qualified':False,'installed_observed':False,'execution_enabled':False}
    def _value(self,receipt,receipt_identity,observer,observed,contract,tree,snapshot,closure):
        digest=validate(closure,tree.manifest,observer.plan['binding'],observer.plan['provenance'])
        intent=preapproval_identity(observer.plan,digest)
        value=super()._value(receipt,receipt_identity,observer,observed,contract,tree,snapshot)
        from .closure_verify import analyze
        independent=analyze(tree,snapshot,closure,observer.plan['binding'],observer.plan['provenance'])
        value.update(closure=closure,closure_sha256=digest,preapproval_sha256=intent,independent_closure=independent)
        return value

    def verified_prerequisite(self,expected,receipt,receipt_identity,observer,observed,contract,tree,snapshot,closure):
        """Fresh analysis + fixed repeat build, never accepts caller PASS reports.

        No protected installation/campaign authority even when metadata matches.
        Builds occur only on this explicit preparation call, never publish/import.
        """
        from ..fixture_build import compare, check_binding
        analysis=self.candidate_prerequisite(tree,snapshot,closure,observer.plan['binding'],observer.plan['provenance'])['analysis']
        prov=observer.plan['provenance']
        builds=compare({'synthetic_worker.c':prov['synthetic_source_sha256'],'security_probe.c':prov['fixture_source_sha256']})
        check_binding(builds,prov)
        accepted=self.accept(expected,receipt,receipt_identity,observer,observed,contract,tree,snapshot,closure)
        return accepted|{'analysis':analysis,'builds':builds,'reproducibility':'UNPROVEN'}
