"""Source-bound export regressions; no target imports or native execution."""
import contextlib
import copy
import hashlib
import unittest
from unittest.mock import patch
from orchestrator.privilege import closure_verify as v, build_closure as c, protocol as p
from test_privilege_closure_verify import IndependentClosureCases, image


class ExportCases(unittest.TestCase):
    def cases(self):
        for name in sorted(x for x in dir(self) if x.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()
    @contextlib.contextmanager
    def fixture(self,service=b'good=1\n',child=b'from .service import good\n',extra=None):
        # Every source dependency is declared for these small fixtures. This is
        # not a supplied PASS: the existing analyzer must independently resolve.
        with IndependentClosureCases().fixture(service=service,child=child,extra=extra) as (_,args,closure,root):
            active={'package/orchestrator/privilege/'+name for name in ('service.py','child.py','__init__.py')}
            active.update('python_base/lib/python3.12/'+name for name in ('encodings/__init__.py','importlib/__init__.py','site.py'))
            active.update(extra or {})
            for item in closure['artifacts']:
                if item['path'] in active and item['path'].endswith('.py'):
                    item['requires']=sorted({x['path'] for x in closure['artifacts'] if x['path'].endswith('.py') and x['path']!=item['path']})
            yield args,closure,root
    def analyze(self,args,closure):return IndependentClosureCases().analyze(args,closure)
    def check(self,service,child,expected,extra=None):
        with self.fixture(service,child,extra) as (args,closure,root):
            result=self.analyze(args,closure)
            self.assertEqual(result['status'],expected,result['issues'])
            self.assertFalse(result['qualified'])
            if expected=='UNRESOLVED':
                with self.assertRaises(p.BoundaryError) as error:
                    c.StagingClosureRegistration.candidate_prerequisite(args[-2],args[-1],closure,args[2].plan['binding'],args[2].plan['provenance'])
                self.assertEqual(error.exception.code,'POLICY_REJECTED')
            else:
                proof=c.StagingClosureRegistration.candidate_prerequisite(args[-2],args[-1],closure,args[2].plan['binding'],args[2].plan['provenance'])
                self.assertFalse(proof['qualified']);self.assertFalse(proof['execution_enabled']);self.assertFalse(proof['installed_observed'])
            return result
    def case_builtin_boundary(self):
        for name in ('not_real','version'):
            result=self.check(b'good=1\n',('from sys import '+name+'\n').encode(),'UNRESOLVED')
            self.assertIn('IMPORT_ATTRIBUTE_UNRESOLVED:sys.'+name,result['issues'])
        self.check(b'good=1\n',b'import sys\n','STATIC_METADATA_VERIFIED')
        self.check(b'from sys import not_real as good\n',b'from .service import good\n','UNRESOLVED')
        self.check(b'import sys as builtin\ngood=builtin.not_real\n',b'from .service import good\n','UNRESOLVED')
    def case_module_binding_effects_and_dormant_scope(self):
        # Both review fixtures are parsed, never executed. check() also exercises
        # the real staging prerequisite's rejection/non-authority contract.
        result=self.check(b'good=1\ntry:\n    raise ValueError\nexcept ValueError as good:\n    pass\n',
                          b'from .service import good\n','UNRESOLVED')
        self.assertIn('IMPORT_ATTRIBUTE_UNRESOLVED:orchestrator.privilege.service.good',result['issues'])
        result=self.check(b'good=1\n__all__=("good",)\nother=(__all__ := ("absent",))\n',
                          b'from .service import *\n','UNRESOLVED')
        self.assertTrue(any('STAR_IMPORT_UNRESOLVED' in x for x in result['issues']))
        for effect in (b'other=((good := 2),)\n',b'other: "int"=(good := 2)\n',
                       b'def other(value=(good := 2)):\n    pass\n',
                       b'def other(value: (good := 2)):\n    pass\n',
                       b'if flag:\n    def other(value=(good := 2)):\n        pass\n',
                       b'other=lambda value=(good := 2): value\n',
                       b'other=[(good := 2) for local in (1,)]\n'):
            self.check(b'good=1\n'+effect,b'from .service import good\n','UNRESOLVED')
        for dormant in (b'def other():\n    good=(good := 2)\n',
                        b'def other():\n    try:\n        raise ValueError\n    except ValueError as good:\n        pass\n',
                        b'def other():\n    global good\n    good=2\n',
                        b'other=lambda: (good := 2)\n',
                        b'other=[good for good in (1,)]\n'):
            self.check(b'good=1\n'+dormant,b'from .service import good\n','STATIC_METADATA_VERIFIED')
    def case_nested_definition_rejection_and_dormant_scope(self):
        delete=b'class Other:\n    global good\n    del good\n'
        decorated=b'@erase\ndef other():\n    pass\n'
        erase=b'def erase(function):\n    global good\n    del good\n    return function\n'
        wrap=lambda header,body:header+b''.join(b'    '+line+b'\n' for line in body.splitlines())
        result=self.check(b'good=1\n'+wrap(b'if True:\n',delete),
                          b'from .service import good\n','UNRESOLVED')
        self.assertIn('IMPORT_ATTRIBUTE_UNRESOLVED:orchestrator.privilege.service.good',result['issues'])
        for header in (b'if True:\n',b'for item in (1,):\n',b'while False:\n',b'try:\n'):
            suffix=b'except ValueError:\n    pass\n' if header==b'try:\n' else b''
            for body in (delete,decorated,b'class Other(Base):\n    pass\n',
                         b'class Other(metaclass=Meta):\n    pass\n'):
                self.check(b'good=1\n'+erase+wrap(header,body)+suffix,
                           b'from .service import good\n','UNRESOLVED')
        replace=b'class Other:\n    global __all__\n    __all__=("absent",)\n'
        self.check(b'good=1\n__all__=("good",)\n'+wrap(b'if True:\n',replace),
                   b'from .service import *\n','UNRESOLVED')
        # Unsupported definitions in dormant function bodies are not evaluated
        # merely by defining the enclosing function.
        for body in (delete,decorated,wrap(b'if True:\n',delete),wrap(b'if True:\n',decorated)):
            self.check(b'good=1\n'+erase+wrap(b'def dormant():\n',body),
                       b'from .service import good\n','STATIC_METADATA_VERIFIED')
        self.check(b'good=1\nif True:\n    def dormant():\n        global good\n        del good\n',
                   b'from .service import good\n','STATIC_METADATA_VERIFIED')
        self.check(b'good=1\nif True:\n    class Other:\n        pass\n',
                   b'from .service import good\n','STATIC_METADATA_VERIFIED')
    def case_unused_definition_time_effects(self):
        hook='python_base/lib/python3.12/_export_hook.py'
        service='package/orchestrator/privilege/service.py'
        own_init='package/orchestrator/privilege/__init__.py'
        hook_source=b'import sys\ndef __getattr__(name):\n    del sys.modules["orchestrator.privilege.service"].good\n    return 1\n'
        def check(definition,expected='UNRESOLVED',star=False,deferred=False):
            source=b'good=1\nimport _export_hook\n'+(b'__all__=("good",)\n' if star else b'')+definition
            extra={hook:hook_source if not star else hook_source.replace(b'del sys.modules["orchestrator.privilege.service"].good',b'sys.modules["orchestrator.privilege.service"].__all__=("absent",)')}
            future='python_base/lib/python3.12/__future__.py'
            if deferred:
                source=b'from __future__ import annotations\n'+source;extra[future]=b'annotations=1\n'
            consumer=b'from .service import *\n' if star else b'from .service import good\n'
            # Precise declarations, not the blanket ExportCases fixture: good is
            # requested; the annotated/defaulted definition is deliberately not.
            with IndependentClosureCases().fixture(service=source,child=consumer,extra=extra) as (_,args,closure,root):
                rows={x['path']:x for x in closure['artifacts']}
                rows[service]['requires']=sorted([own_init,hook]+([future] if deferred else []))
                rows['package/orchestrator/privilege/child.py']['requires']=sorted([own_init,service])
                rows[hook]['requires']=[]
                if deferred:rows[future]['requires']=[]
                result=self.analyze(args,closure)
                self.assertEqual(result['status'],expected,result['issues'])
                self.assertFalse(result['qualified'])
                gate=lambda:c.StagingClosureRegistration.candidate_prerequisite(args[-2],args[-1],closure,args[2].plan['binding'],args[2].plan['provenance'])
                if expected=='UNRESOLVED':
                    with self.assertRaises(p.BoundaryError) as error:gate()
                    self.assertEqual(error.exception.code,'POLICY_REJECTED')
                    if star:self.assertTrue(any('STAR_IMPORT_UNRESOLVED' in x for x in result['issues']))
                    else:self.assertIn('IMPORT_ATTRIBUTE_UNRESOLVED:orchestrator.privilege.service.good',result['issues'])
                else:
                    accepted=gate()
                    for key in ('qualified','installed_observed','execution_enabled'):self.assertFalse(accepted[key])
        definitions=(b'def other(value: _export_hook.missing):\n    pass\n',
                     b'def other(value=_export_hook.missing):\n    pass\n',
                     b'def other(*, value=_export_hook.missing):\n    pass\n',
                     b'def other(value: _export_hook["missing"]):\n    pass\n',
                     b'def other(value=_export_hook["missing"]):\n    pass\n',
                     b'def other(value=_export_hook.missing()):\n    pass\n',
                     b'def other() -> _export_hook.missing:\n    pass\n',
                     b'def other(*args: _export_hook.missing, **kwargs: _export_hook.missing):\n    pass\n',
                     b'def other(value: (_export_hook.missing,), /):\n    pass\n',
                     b'other=lambda value=_export_hook.missing: value\n',
                     b'other=lambda *, value=_export_hook["missing"]: value\n',
                     b'@_export_hook.missing\ndef other():\n    pass\n',
                     b'class Other(_export_hook.missing):\n    pass\n',
                     b'class Other(metaclass=_export_hook.missing):\n    pass\n')
        # N2 uses the same precise unused-export fixture and admission checks.
        annotations=(b'other: _export_hook.missing = 1\n',
                     b'other: _export_hook.missing\n',
                     b'other: _export_hook["missing"] = 1\n',
                     b'other: (_export_hook.missing,) = 1\n')
        for definition in definitions+annotations:
            check(definition)
            nested=b'if True:\n'+b''.join(b'    '+line+b'\n' for line in definition.splitlines())
            check(nested)
        check(definitions[0],star=True)
        check(b'if True:\n    def other(value: _export_hook.missing):\n        pass\n',star=True)
        # Unsupported deferred annotation handling rejects conservatively, not
        # on a claim that __future__.annotations performs this eager lookup.
        check(definitions[0],deferred=True)
        for annotation in annotations:
            check(annotation,star=True)
            check(b'if True:\n'+b'    '+annotation,star=True)
        check(annotations[0],deferred=True)
        for definition in (b'other: "int" = 1\n',
                           b'other: ("int",) = good\n',
                           b'other: "int" = _export_hook\n',
                           b'def dormant():\n    other: _export_hook.missing = 1\n',
                           b'def other(value=1, *, option=(1,None)) -> "int":\n    pass\n',
                           b'class Other:\n    pass\n',
                           b'def dormant():\n    return _export_hook.missing\n',
                           b'other=lambda: _export_hook.missing\n',
                           b'def other(value=lambda: _export_hook.missing):\n    pass\n',
                           b'if True:\n    def dormant():\n        global good\n        del good\n',
                           b'other=lambda value=(lambda: _export_hook.missing): value\n'):
            check(definition,'STATIC_METADATA_VERIFIED')
    def case_definitions_assignments_aliases(self):
        for service in (b'good=1\n',b'good=(1,None,"text")\n',b'def good():\n    pass\n',b'class good:\n    pass\n',b'original=1\ngood=original\n',b'good: "int"=1\n',b'def good(value=1):\n    pass\n'):
            self.check(service,b'from .service import good\n','STATIC_METADATA_VERIFIED')
        self.check(b'good=1\n',b'from .service import absent\n','UNRESOLVED')
        self.check(b'good=missing\n',b'from .service import good\n','UNRESOLVED')
        extra={'python_base/lib/python3.12/_export_target.py':b'original=1\n'}
        self.check(b'from _export_target import original as good\n',b'from .service import good\n','STATIC_METADATA_VERIFIED',extra)
        self.check(b'import _export_target as target\ngood=target.original\n',b'from .service import good\n','STATIC_METADATA_VERIFIED',extra)
        self.check(b'from _export_target import absent as good\n',b'from .service import good\n','UNRESOLVED',extra)
        self.check(b'from absent_target import original as good\n',b'from .service import good\n','UNRESOLVED')
    def case_package_child_and_shadow(self):
        path='package/orchestrator/privilege/__init__.py'
        self.check(b'good=1\n',b'from . import service\n','STATIC_METADATA_VERIFIED')
        self.check(b'good=1\n',b'from . import absent\n','UNRESOLVED')
        self.check(b'good=1\n',b'from . import service\n','UNRESOLVED',{path:b'service=1\ndel service\n'})
        self.check(b'good=1\n',b'from . import service\n','UNRESOLVED',{path:b'if flag:\n    import other as service\n'})
        self.check(b'good=1\n',b'from orchestrator import fixture_build\n','STATIC_METADATA_VERIFIED',{'package/orchestrator/fixture_build.py':b'good=1\n'})
        self.check(b'good=1\n',b'from orchestrator import absent\n','UNRESOLVED')
    def case_package_import_is_not_attribute_publication(self):
        init='python_base/lib/python3.12/_export_pkg/__init__.py'
        child='python_base/lib/python3.12/_export_pkg/child.py'
        extra={init:b'',child:b'value=1\n'}
        ordinary=b'import _export_pkg\ngood=_export_pkg.child\n'
        imported=b'from _export_pkg import child as good\n'
        result=self.check(ordinary,b'from .service import good\n','UNRESOLVED',extra)
        self.assertIn('IMPORT_ATTRIBUTE_UNRESOLVED:orchestrator.privilege.service.good',result['issues'])
        result=self.check(imported,b'from .service import good\n','STATIC_METADATA_VERIFIED',extra)
        edges=result['derived']['package/orchestrator/privilege/service.py']
        self.assertIn(init,edges);self.assertIn(child,edges)
        self.assertIn(child,result['derived'])
        self.check(imported,b'from .service import good\n','UNRESOLVED',{init:b''})
        for alias in (b'import _export_pkg as pkg\ngood=pkg.child\n',
                      b'import _export_pkg\nalias=_export_pkg.child\ngood=alias\n',
                      b'from _export_pkg import child as imported\nimport _export_pkg\ngood=_export_pkg.child\n'):
            # Even a cached import-like positive cannot establish publication
            # for an attribute query. Cross-source import order is not simulated.
            self.check(alias,b'from .service import good\n','UNRESOLVED',extra)
        self.check(ordinary,b'from .service import good\n','STATIC_METADATA_VERIFIED',
                   {init:b'import _export_pkg.child as child\n',child:b'value=1\n'})
        self.check(b'from _export_pkg import *\ngood=child\n',b'from .service import good\n',
                   'STATIC_METADATA_VERIFIED',{init:b'__all__=("child",)\n',child:b'value=1\n'})
        self.check(ordinary,b'from .service import good\n','UNRESOLVED',
                   {init:b'__all__=("child",)\n',child:b'value=1\n'})
        self.check(ordinary,b'from .service import good\n','UNRESOLVED',
                   {init:b'from sys import not_real as child\n',child:b'value=1\n'})
        result=self.check(imported,b'from .service import good\n','UNRESOLVED',
                          {init:b'from .child import value as child\n',child:b'from _export_pkg import child as value\n'})
        self.assertTrue(any('EXPORT_CYCLE_UNRESOLVED' in x for x in result['issues']))
        # Namespace-package membership has the same import-only boundary.
        self.check(b'import orchestrator\ngood=orchestrator.fixture_build\n',b'from .service import good\n',
                   'UNRESOLVED',{'package/orchestrator/fixture_build.py':b'value=1\n'})
        with self.fixture(imported,b'from .service import good\n',extra) as (args,closure,root):
            self.assertEqual(self.analyze(args,closure)['status'],'STATIC_METADATA_VERIFIED')
            path=root/child;raw=path.read_bytes();path.unlink();path.write_bytes(raw);path.chmod(0o644)
            with self.assertRaises(p.BoundaryError):self.analyze(args,closure)
    def case_literal_all_and_actual_star(self):
        for value in (b'("good",)',b'["good"]'):
            self.check(b'good=1\n__all__='+value+b'\n',b'from .service import *\n','STATIC_METADATA_VERIFIED')
        extra={'python_base/lib/python3.12/_export_target.py':b'original=1\n'}
        self.check(b'from _export_target import original as good\n__all__=("good",)\n',b'from .service import *\n','STATIC_METADATA_VERIFIED',extra)
        self.check(b'good=1\n__all__=("good",)\n',b'from .service import *\nalias=good\n','STATIC_METADATA_VERIFIED')
        # Publication through an imported star is itself source verified.
        extra={'python_base/lib/python3.12/_export_target.py':b'original=1\n__all__=("original",)\n'}
        self.check(b'from _export_target import *\ngood=original\n',b'from .service import good\n','STATIC_METADATA_VERIFIED',extra)
        for declaration in (b'__all__=compute()\n',b'__all__="good"\n',b'__all__=("absent",)\n',b'__all__=("good","good")\n',b'__all__=(1,)\n',b'__all__=("good",)\n__all__+=("absent",)\n'):
            result=self.check(b'good=1\n'+declaration,b'from .service import *\n','UNRESOLVED')
            self.assertTrue(any('STAR_IMPORT_UNRESOLVED' in issue for issue in result['issues']))
        self.check(b'from sys import not_real as good\n__all__=("good",)\n',b'from .service import *\n','UNRESOLVED')
    def case_package_star_dependency_edges(self):
        init='python_base/lib/python3.12/_export_pkg/__init__.py'
        child='python_base/lib/python3.12/_export_pkg/child.py'
        service='package/orchestrator/privilege/service.py'
        own_init='package/orchestrator/privilege/__init__.py'
        @contextlib.contextmanager
        def precise(source=b'from _export_pkg import *\n',initializer=b'__all__=("child",)\n',include_child=True,extra=None):
            files={init:initializer};files.update(extra or {})
            if include_child:files[child]=b'value=1\n'
            # Use the underlying fixture directly, never ExportCases' blanket
            # source declarations. Reachability via the existing interpreter root
            # must not mask a missing importing-source edge.
            with IndependentClosureCases().fixture(service=source,child=b'import sys\n',extra=files) as (_,args,closure,root):
                rows={x['path']:x for x in closure['artifacts']}
                rows[service]['requires']=sorted([own_init,init])
                rows[init]['requires']=[]
                if include_child:
                    rows[child]['requires']=[init]
                    self.assertIn(child,rows['venv/bin/python']['requires'])
                yield args,closure,root,rows
        def admission(args,closure):
            return c.StagingClosureRegistration.candidate_prerequisite(args[-2],args[-1],closure,args[2].plan['binding'],args[2].plan['provenance'])
        with precise() as (args,closure,root,rows):
            result=self.analyze(args,closure)
            self.assertEqual(result['derived'][service],sorted([own_init,init,child]))
            self.assertEqual(result['derived'][init],[])
            self.assertIn(child,result['derived'])
            self.assertEqual(result['issues'],['DECLARED_EDGE_MISSING:'+service+':'+child])
            with self.assertRaises(p.BoundaryError) as error:admission(args,closure)
            self.assertEqual(error.exception.code,'POLICY_REJECTED')
            rows[service]['requires']=sorted([own_init,init,child])
            accepted=admission(args,closure)
            self.assertEqual(accepted['analysis']['status'],'STATIC_METADATA_VERIFIED')
            for key in ('qualified','installed_observed','execution_enabled'):self.assertFalse(accepted[key])
            path=root/child;raw=path.read_bytes();path.unlink()
            with self.assertRaises(p.BoundaryError):admission(args,closure)
            path.write_bytes(raw);path.chmod(0o644)
            with self.assertRaises(p.BoundaryError):admission(args,closure)
        for kwargs in ({'include_child':False},{'initializer':b'__all__=compute()\n'},
                       {'initializer':b'__all__=("absent",)\n'}):
            with precise(**kwargs) as (args,closure,root,rows):
                result=self.analyze(args,closure)
                self.assertEqual(result['status'],'UNRESOLVED')
                self.assertTrue(any('STAR_IMPORT_UNRESOLVED' in x for x in result['issues']))
                with self.assertRaises(p.BoundaryError):admission(args,closure)
        # A re-export changes the name, not the underlying module dependency.
        wrapper='python_base/lib/python3.12/_export_wrapper.py'
        with precise(b'from _export_wrapper import *\n',extra={wrapper:b'from _export_pkg import *\nrenamed=child\n__all__=("renamed",)\n'}) as (args,closure,root,rows):
            rows[service]['requires']=sorted([own_init,wrapper])
            rows[wrapper]['requires']=sorted([init,child])
            result=self.analyze(args,closure)
            self.assertEqual(result['derived'][service],sorted([own_init,wrapper,child]))
            self.assertEqual(result['derived'][wrapper],sorted([init,child]))
            self.assertEqual(result['issues'],['DECLARED_EDGE_MISSING:'+service+':'+child])
            with self.assertRaises(p.BoundaryError):admission(args,closure)
            rows[service]['requires']=sorted([own_init,wrapper,child])
            self.assertEqual(admission(args,closure)['analysis']['status'],'STATIC_METADATA_VERIFIED')
    def case_unsupported_publication(self):
        for service in (b'if flag:\n    good=1\n',b'good=1\nif flag:\n    good=2\n',b'good=1\ndel good\n',
                        b'good=1\ngood=2\n',b'good: int\n',b'good: not_real=1\n',b'good=later\nlater=1\n',
                        b'def good(value=later):\n    pass\nlater=1\n',b'good=1\ndef __getattr__(name):\n    return 1\n',
                        b'good=1\nif flag:\n    def __getattr__(name):\n        return 1\n',
                        b'good=1\nexec(code)\n',b'good=1\nglobals()["good"]=other\n',
                        b'good=1\nother=globals().pop("good")\n',b'@decorate\ndef good():\n    pass\n',
                        b'def good(value=unknown):\n    pass\n',b'good=1\nif flag:\n    from other import good\n'):
            self.check(service,b'from .service import good\n','UNRESOLVED')
        extra={'python_base/lib/python3.12/_export_target.py':b'good=2\n__all__=("good",)\n'}
        self.check(b'good=1\nfrom _export_target import *\n',b'from .service import good\n','UNRESOLVED',extra)
    def case_cycles_bounds_and_native(self):
        result=self.check(b'good=other\nother=good\n',b'from .service import good\n','UNRESOLVED')
        self.assertTrue(any('EXPORT_CYCLE_UNRESOLVED' in x for x in result['issues']))
        extra={'python_base/lib/python3.12/_export_target.py':b'from orchestrator.privilege.service import good as original\n'}
        self.check(b'from _export_target import original as good\n',b'from .service import good\n','UNRESOLVED',extra)
        chain=b'last=1\n'+b''.join(('alias'+str(k)+'='+('last' if k==0 else 'alias'+str(k-1))+'\n').encode() for k in range(v.MAX_EXPORT_DEPTH+2))
        self.check(chain,('from .service import alias'+str(v.MAX_EXPORT_DEPTH+1)+'\n').encode(),'UNRESOLVED')
        with patch.object(v,'MAX_EXPORT_QUERIES',1):self.check(b'good=1\n',b'from .service import good\n','UNRESOLVED')
        with self.fixture() as (args,closure,root),patch.object(v,'MAX_EXPORT_ENTRIES',0):
            with self.assertRaises(p.BoundaryError):self.analyze(args,closure)
        with patch.object(v,'MAX_ALL_NAMES',0):self.check(b'good=1\n__all__=("good",)\n',b'from .service import *\n','UNRESOLVED')
        extension='python_base/lib/python3.12/lib-dynload/_export_native.cpython-312-x86_64-linux-gnu.so'
        self.check(b'good=1\n',b'from _export_native import not_real\n','UNRESOLVED',{extension:image()})
    def case_cache_freshness_and_identity(self):
        with self.fixture() as (args,closure,root):
            original=v._Exports.proof;changed=[]
            def replace_after_proof(resolver,name,symbol,*rest,**kwargs):
                value=original(resolver,name,symbol,*rest,**kwargs)
                if name=='orchestrator.privilege.service' and symbol=='good' and value and not changed:
                    changed.append(True);source=root/'package/orchestrator/privilege/service.py'
                    raw=source.read_bytes();source.unlink();source.write_bytes(raw);source.chmod(0o644)
                return value
            with patch.object(v._Exports,'proof',replace_after_proof):
                with self.assertRaises(p.BoundaryError):self.analyze(args,closure)
            self.assertTrue(changed)  # positive cached proof cannot bypass final identity check
        with self.fixture() as (args,closure,root):
            self.assertEqual(self.analyze(args,closure)['status'],'STATIC_METADATA_VERIFIED')
            path='package/orchestrator/privilege/service.py';source=root/path
            raw=source.read_bytes();source.unlink();source.write_bytes(raw);source.chmod(0o644)
            with self.assertRaises(p.BoundaryError):self.analyze(args,closure)
        with self.fixture() as (args,closure,root):
            self.assertEqual(self.analyze(args,closure)['status'],'STATIC_METADATA_VERIFIED')
            path='package/orchestrator/privilege/service.py';source=root/path;source.write_bytes(b'absent=1\n')
            with self.assertRaises(p.BoundaryError):self.analyze(args,closure)
            # A newly reviewed manifest/snapshot must not reuse the old export.
            manifest=copy.deepcopy(args[-2].manifest);digest=hashlib.sha256(source.read_bytes()).hexdigest()
            next(row for row in manifest['nodes'] if row['path']==path)['sha256']=digest
            new=v.c.n.StagingDependencies(root,manifest)
            try:
                changed=list(args);changed[-2:]=new,new.capture();graph=copy.deepcopy(closure)
                graph['manifest_sha256']=v.i.digest(manifest)
                next(row for row in graph['artifacts'] if row['path']==path)['sha256']=digest
                self.assertEqual(self.analyze(changed,graph)['status'],'UNRESOLVED')
            finally:new.close()
    def case_dynamic_uncertainty_preserved(self):
        self.check(b'__import__(name)\n',b'import sys\n','UNRESOLVED')
        self.check(b'import ctypes\nctypes.CDLL(name)\n',b'import sys\n','UNRESOLVED')
        extra={'package/orchestrator/privilege/__init__.py':b'def __getattr__(name):\n    return None\n'}
        # Uncertain publication must not suppress analysis of an exact child.
        result=self.check(b'__import__(name)\n',b'from . import service\n','UNRESOLVED',extra)
        self.assertIn('package/orchestrator/privilege/service.py:DYNAMIC_IMPORT_UNRESOLVED',result['issues'])


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([ExportCases('cases')]))
    raise SystemExit(not result.wasSuccessful())
