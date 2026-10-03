"""Recording graph/receipt integration; no interpreter, compiler or fixture exec."""
import copy
import unittest
from pathlib import Path
from orchestrator.privilege import build_closure as c, inventory as i, protocol as p
from test_privilege_installed_identity import InstalledIdentityCases

class ClosureCases(unittest.TestCase):
    def cases(self):
        for name in sorted(v for v in dir(self) if v.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()
    def reject(self,fn):
        with self.assertRaises((p.BoundaryError,OSError)):fn()
    def plan(self,args):
        tree=args[-2];files={v['path']:v for v in tree.manifest['nodes'] if v['type']=='file'}
        roots=sorted(c.ROOTS|{v for v in files if v.startswith('package/')})
        return {'version':1,'layout':c.LAYOUT,'source_commit':args[2].plan['binding']['source_commit'],
                'policy':args[4]['policy'],'manifest_sha256':i.digest(tree.manifest),'roots':roots,
                'artifacts':[{'path':v,'category':c.category(v),'sha256':files[v]['sha256'],
                              'requires':sorted(set(files)-set(roots)) if v=='venv/bin/python' else []} for v in sorted(files)],
                'third_party':[],'unresolved':[],'provenance':args[2].plan['provenance'],
                'verification':{'dependency_closure':'DECLARED','build':'UNPROVEN','reproducibility':'UNPROVEN'}}
    def validate(self,plan,args):return c.validate(plan,args[-2].manifest,args[2].plan['binding'],args[2].plan['provenance'])
    def case_integrated_preapproval_receipt(self):
        with InstalledIdentityCases().fixture(closure=True) as (store,args,tree):
            plan=self.plan(args);sha=self.validate(plan,args)
            intent=c.preapproval_identity(args[2].plan,sha)
            approval=next(e for e in args[2].plan['entries'] if e['target']=='CAMPAIGN_ROOT/approval.json')
            self.assertFalse(approval['staged']);self.assertEqual(approval['applicability'],'CONDITIONAL')
            self.assertFalse((args[2].path/approval['slot']).exists())
            expected=store.publish(*args,plan);proof=store.accept(expected,*args,plan)
            self.assertFalse(proof['qualified']);self.assertFalse(proof['execution_enabled'])
            # Approval may now bind this frozen pre-approval receipt/intent, not vice versa.
            owner_review={'preapproval_sha256':intent,'receipt':args[1],'inventory_sha256':args[4]['inventory_sha256']}
            self.assertEqual(owner_review['preapproval_sha256'],intent)
            changed=copy.deepcopy(args[2].plan)
            changed['entries'][int(approval['slot'])]['sha256']='f'*64
            self.reject(lambda:c.preapproval_identity(changed,sha))  # no caller rewriting accounting
            self.assertEqual(self.validate(plan,args),sha)
    def case_mutable_separation_and_immutable_change(self):
        with InstalledIdentityCases().fixture(closure=True) as (store,args,tree):
            value=self.plan(args);original=self.validate(value,args)
            # Generated receipt, approval, attempt bytes are absent from closure schema.
            for key in ('receipt','approval','attempt','recovery'):
                changed=copy.deepcopy(value);changed[key]={'bytes':'changed'}
                self.reject(lambda:self.validate(changed,args))
            self.assertEqual(self.validate(value,args),original)
            changed=copy.deepcopy(value);manifest=copy.deepcopy(args[-2].manifest)
            name='python_base/lib/libpython3.12.so.1.0'
            next(n for n in manifest['nodes'] if n['path']==name)['sha256']='f'*64
            next(n for n in changed['artifacts'] if n['path']==name)['sha256']='f'*64
            changed['manifest_sha256']=i.digest(manifest)
            self.assertNotEqual(c.validate(changed,manifest,args[2].plan['binding'],args[2].plan['provenance']),original)
            (tree/name).write_bytes(b'replaced');self.reject(lambda:store.publish(*args,value))
    def case_rejection_matrix(self):
        with InstalledIdentityCases().fixture(closure=True) as (store,args,tree):
            value=self.plan(args)
            variants=[]
            for field,change in (('layout','OTHER'),('version',2),('source_commit','f'*40),('policy','f'*64),
                                 ('unresolved',['libmissing']),('third_party',['langgraph']),('roots',[])):
                changed=copy.deepcopy(value);changed[field]=change;variants.append(changed)
            changed=copy.deepcopy(value);changed['artifacts'].pop();variants.append(changed)
            changed=copy.deepcopy(value);changed['artifacts'][0]['requires']=['/usr/lib/foreign'];variants.append(changed)
            changed=copy.deepcopy(value);changed['verification']['reproducibility']='VERIFIED';variants.append(changed)
            changed=copy.deepcopy(value);changed['provenance']['compiler_sha256']='f'*64;variants.append(changed)
            for changed in variants:self.reject(lambda:self.validate(changed,args))
            for name in ('venv/bin/python','package/orchestrator/roles/__init__.py',
                         'python_base/lib/python3.12/socket.py','runtime/lib/libc.so.6'):
                changed=copy.deepcopy(value);manifest=copy.deepcopy(args[-2].manifest)
                manifest['nodes']=[v for v in manifest['nodes'] if v['path']!=name]
                changed['manifest_sha256']=i.digest(manifest)
                self.reject(lambda:c.validate(changed,manifest,args[2].plan['binding'],args[2].plan['provenance']))
    def case_bounds_layout_packaging(self):
        with InstalledIdentityCases().fixture(closure=True) as (store,args,tree):
            value=self.plan(args)
            from unittest.mock import patch
            with patch.object(c,'MAX_EDGES',0):self.reject(lambda:self.validate(value,args))
            (tree/'runtime/lib/unlisted.so').write_bytes(b'foreign');self.reject(lambda:store.publish(*args,value))
        from orchestrator.privilege import policy_sources as ps
        self.assertIn('privilege/build_closure.py',ps.PRIVILEGE_SOURCES)
        self.assertTrue(Path(c.__file__).is_file())
        self.assertIn('"orchestrator.privilege"',Path('pyproject.toml').read_text())
