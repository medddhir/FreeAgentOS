"""Independent metadata/fault contracts; never execute compiled fixtures."""
import contextlib
import copy
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
from orchestrator.privilege import closure_verify as v, installed_identity as n, protocol as p
from orchestrator import fixture_build as b
from test_privilege_installed_identity import InstalledIdentityCases
from test_privilege_build_closure import ClosureCases


def image(needed=(),interpreter=None,rpath=False):
    raw=bytearray(4096);raw[:16]=b'\x7fELF\x02\x01\x01'+b'\0'*9
    count=1+bool(needed or rpath)+bool(interpreter)
    struct.pack_into('<HHIQQQIHHHHHH',raw,16,2,62,1,0,64,0,0,64,56,count,0,0,0)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0,4096,4096,4096)
    cursor=120
    if needed or rpath:
        strings=b'\0';offsets=[]
        for name in needed:offsets.append(len(strings));strings+=name.encode()+b'\0'
        raw[1024:1024+len(strings)]=strings
        tags=[(5,0x400400),(10,len(strings))]+[(1,o) for o in offsets]+([(29,0)] if rpath else [])+[(0,0)]
        struct.pack_into('<IIQQQQQQ',raw,cursor,2,4,512,0x400200,0,len(tags)*16,len(tags)*16,8);cursor+=56
        for index,tag in enumerate(tags):struct.pack_into('<qQ',raw,512+index*16,*tag)
    if interpreter:
        blob=interpreter.encode()+b'\0';raw[2048:2048+len(blob)]=blob
        struct.pack_into('<IIQQQQQQ',raw,cursor,3,4,2048,0x400800,0,len(blob),len(blob),1)
    return bytes(raw)

class IndependentClosureCases(unittest.TestCase):
    def cases(self):
        for name in sorted(x for x in dir(self) if x.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()
    def reject(self,fn):
        with self.assertRaises((p.BoundaryError,OSError)):fn()
    @contextlib.contextmanager
    def fixture(self,service=b'from . import child\n',child=b'import sys\n',needed=(),extra=None,interpreter=None):
        with InstalledIdentityCases().fixture(closure=True) as (store,args,tree):
            original=args[-2].manifest
            updates={'package/orchestrator/privilege/service.py':service,'package/orchestrator/privilege/child.py':child}
            for path in v.c.ROOTS|v.c.NATIVE_FILES:updates[path]=image(needed if path=='venv/bin/python' else (),interpreter if path=='venv/bin/python' else None)
            for path in ('python_base/lib/python3.12/encodings/__init__.py','python_base/lib/python3.12/importlib/__init__.py','python_base/lib/python3.12/site.py'):updates[path]=b'import sys\n'
            updates.update(extra or {})
            for path,blob in updates.items():
                (tree/path).parent.mkdir(parents=True,exist_ok=True)
                (tree/path).write_bytes(blob);(tree/path).chmod(0o755 if path in v.c.ROOTS else 0o644)
            # Reconstruct reviewed exact tree and pinned observations after fixture setup.
            nodes=[]
            for file in sorted(tree.rglob('*')):
                path=str(file.relative_to(tree))
                if file.is_dir():file.chmod(0o755);nodes.append({'path':path,'type':'directory','mode':0o755,'sha256':None})
                else:nodes.append({'path':path,'type':'file','mode':file.stat().st_mode&0o777,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()})
            manifest={'version':1,'kind':'REVIEWED_STAGING_DEPENDENCIES','nodes':nodes}
            dep=n.StagingDependencies(tree,manifest);snapshot=dep.capture()
            changed=list(args);changed[-2:]=dep,snapshot
            # Independent analyzer fixture expectations, never a protected registration.
            changed[2].plan=copy.deepcopy(changed[2].plan)
            for path,key in (('venv/bin/python','launcher_sha256'),('runtime/bin/synthetic-worker','synthetic_sha256'),('runtime/bin/security-probe','security_probe_sha256')):
                changed[2].plan['provenance'][key]=next(x['sha256'] for x in nodes if x['path']==path)
            closure=ClosureCases().plan(changed)
            next(x for x in closure['artifacts'] if x['path']=='package/orchestrator/privilege/service.py')['requires']=['package/orchestrator/privilege/__init__.py','package/orchestrator/privilege/child.py']
            next(x for x in closure['artifacts'] if x['path']=='package/orchestrator/privilege/child.py')['requires']=['package/orchestrator/privilege/__init__.py']
            try:yield store,changed,closure,tree
            finally:dep.close()
    def analyze(self,args,closure):return v.analyze(args[-2],args[-1],closure,args[2].plan['binding'],args[2].plan['provenance'])
    def case_valid_and_missing_import_edges(self):
        with self.fixture() as (_,args,closure,tree):
            self.assertEqual(self.analyze(args,closure)['status'],'STATIC_METADATA_VERIFIED')
            broken=copy.deepcopy(closure)
            next(x for x in broken['artifacts'] if x['path'].endswith('/service.py'))['requires']=[]
            self.assertIn('DECLARED_EDGE_MISSING:',str(self.analyze(args,broken)['issues']))
        with self.fixture(child=b'import missing_dependency\n') as (_,args,closure,tree):
            self.assertIn('MISSING_MODULE:missing_dependency',self.analyze(args,closure)['issues'])
        with self.fixture(service=b'from . import absent\n') as (_,args,closure,tree):
            self.assertIn('IMPORT_ATTRIBUTE_UNRESOLVED:orchestrator.privilege.absent',self.analyze(args,closure)['issues'])
    def case_relative_dynamic_and_native_extension(self):
        names,issues=v.imports(b'from ..roles.lease import ActivityLease\n','orchestrator.privilege.service')
        self.assertIn(('orchestrator.roles.lease',False),names);self.assertFalse(issues)
        for source in (b'__import__(variable)',b'import importlib as m\nm.import_module(variable)',b'from importlib import import_module as f\nf(variable)',b'exec(value)'):
            self.assertTrue(v.imports(source,'x.y')[1])
        with self.fixture(child=b'__import__(variable)\n') as (_,args,closure,tree):self.assertIn('DYNAMIC_IMPORT_UNRESOLVED',str(self.analyze(args,closure)['issues']))
        # ELF extension metadata is inspected without dlopen/import.
        self.assertEqual(v.elf(image(('libc.so.6',)))['needed'],['libc.so.6'])
        extension='python_base/lib/python3.12/lib-dynload/_unit.cpython-312-x86_64-linux-gnu.so'
        with self.fixture(child=b'import _unit\n',extra={extension:image(('libc.so.6',))}) as (_,args,closure,tree):
            result=self.analyze(args,closure)
            self.assertIn(extension,result['native']);self.assertIn('DECLARED_EDGE_MISSING:',str(result['issues']))
    def case_native_membership_and_metadata(self):
        with self.fixture(needed=('libc.so.6',)) as (_,args,closure,tree):
            # Declared graph reachability alone doesn't prove ELF edge membership.
            next(x for x in closure['artifacts'] if x['path']=='venv/bin/python')['requires'].remove('runtime/lib/libc.so.6')
            # Keep the graph connected through another artifact; independent check still fails.
            next(x for x in closure['artifacts'] if x['path'].endswith('/child.py'))['requires']=['runtime/lib/libc.so.6']
            self.assertIn('DECLARED_EDGE_MISSING:',str(self.analyze(args,closure)['issues']))
        with self.fixture(needed=('foreign.so',)) as (_,args,closure,tree):self.assertIn('LIBRARY_UNRESOLVED:',str(self.analyze(args,closure)['issues']))
        with self.fixture(needed=('libc.so.6',),extra={'runtime/lib64/libc.so.6':image()}) as (_,args,closure,tree):
            self.assertIn('LIBRARY_UNRESOLVED:',str(self.analyze(args,closure)['issues']))
        with self.fixture(interpreter='/unapproved/loader') as (_,args,closure,tree):
            self.assertIn('LOADER_UNRESOLVED:',str(self.analyze(args,closure)['issues']))
        self.reject(lambda:v.elf(image(rpath=True)))
        for raw in (b'not elf',image()[:64],image()[:32]):self.reject(lambda:v.elf(raw))
        self.assertEqual(v.elf(image(interpreter='/unapproved/loader'))['interpreter'],'/unapproved/loader')
    def case_freshness_and_incomplete_prerequisite(self):
        with InstalledIdentityCases().fixture(closure=True) as (store,args,tree):
            closure=ClosureCases().plan(args);expected=store.publish(*args,closure)
            self.reject(lambda:store.verified_prerequisite(expected,*args,closure))
        with self.fixture() as (_,args,closure,tree):
            file=tree/'venv/bin/python';raw=file.read_bytes();file.unlink();file.write_bytes(raw);file.chmod(0o755)
            self.reject(lambda:self.analyze(args,closure))
    def case_inspection_bounds(self):
        with self.fixture() as (_,args,closure,tree):
            with patch.object(v,'MAX_AST_NODES',1):self.reject(lambda:self.analyze(args,closure))
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(b,'MAX_OUTPUT',32):self.reject(lambda:b._run([sys.executable,'-c','print("x"*100)'],cwd=temp))
            with patch.object(b,'COMMAND_SECONDS',.02):self.reject(lambda:b._run([sys.executable,'-c','import time;time.sleep(1)'],cwd=temp))
    def case_build_comparison_and_inputs(self):
        expected={name:v.i._fixture(name) for name in b.SOURCES}
        changed=expected.copy();changed['synthetic_worker.c']='f'*64
        self.reject(lambda:b.compare(changed))
        report=b.compare(expected)
        self.assertEqual(report['status'],'MATCHED');self.assertFalse(report['fixtures_executed']);self.assertFalse(report['qualified'])
        self.assertEqual(report['reproducibility'],'UNPROVEN')
        self.assertGreater(len(report['inputs']),10)
        provenance={
            'compiler_sha256':next(v['sha256'] for v in report['inputs'] if v['path']==report['compiler']),
            'build_recipe_sha256':v.i.digest(report['recipe']),'build_record_sha256':v.i.digest(report),
            'synthetic_source_sha256':expected['synthetic_worker.c'],'fixture_source_sha256':expected['security_probe.c'],
            'synthetic_sha256':report['fixtures']['synthetic_worker.c']['outputs'][0],
            'security_probe_sha256':report['fixtures']['security_probe.c']['outputs'][0]}
        self.assertFalse(b.check_binding(report,provenance)['qualified'])
        for key in provenance:
            changed=provenance.copy();changed[key]='f'*64;self.reject(lambda:b.check_binding(report,changed))
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp);(path/'outside').write_bytes(b'owned fixture')
            (path/'output').symlink_to(path/'outside')
            self.reject(lambda:b._output(temp,'output'))
        original=b._run;count=[]
        def different(argv,**kw):
            raw=original(argv,**kw)
            if '-o' in argv:
                count.append(1)
                if len(count)==2:
                    path=Path(kw['cwd'])/argv[-1];data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
            return raw
        with patch.object(b,'_run',side_effect=different):self.assertEqual(b.compare(expected)['status'],'DIFFERENT')
