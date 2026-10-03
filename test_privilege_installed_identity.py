"""B10 recording registration; temporary owned staging only, no installed state."""
import contextlib
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from orchestrator.privilege import installed_identity as n, inventory as i, protocol as p
from test_privilege_inventory import InventoryCases

class InstalledIdentityCases(unittest.TestCase):
    def cases(self):
        for name in sorted(v for v in dir(self) if v.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()
    def reject(self,fn):
        with self.assertRaises((p.BoundaryError,OSError)):fn()
    @contextlib.contextmanager
    def fixture(self,closure=False):
        with InventoryCases().fixture(phase="PRE_APPROVAL" if closure else "POST_APPROVAL") as (_,plan,observer,observed,contract),tempfile.TemporaryDirectory() as temp:
            base=Path(temp);base.chmod(0o700)
            tree=base/'tree';tree.mkdir(mode=0o700)
            blobs={}
            for e in plan['entries']:
                if '/package/orchestrator/' in e['target']:
                    path='package/orchestrator/'+e['target'].split('/package/orchestrator/')[1]
                    blobs[path]=(observer.path/e['slot']).read_bytes()
            fixtures=Path(i.__file__).parent/'fixtures'
            blobs.update({'package/orchestrator/privilege/fixtures/'+name:(fixtures/name).read_bytes() for name in ('security_probe.c','synthetic_worker.c')})
            blobs['package/orchestrator/privilege/validation.service']=Path(i.__file__).with_name('validation.service').read_bytes()
            blobs.update({name:b'recorded-executable-not-executed' for name in ('venv/bin/python','runtime/bin/synthetic-worker','runtime/bin/security-probe')})
            blobs['venv/pyvenv.cfg']=b'SYNTHETIC_NO_INTERPRETER';blobs['runtime/.freeagent-runtime']=b'FREEAGENTOS_MINIMAL_RUNTIME_V1\n'
            for name in n.REQUIRED_FILES:
                if name not in blobs:blobs[name]=b'SYNTHETIC_DEPENDENCY_NOT_EXECUTED'
            if closure:
                from orchestrator.privilege.build_closure import NATIVE_FILES, PACKAGE_FILES
                for name in NATIVE_FILES|PACKAGE_FILES:blobs[name]=b'SYNTHETIC_DECLARED_DEPENDENCY'
            dirs=set(n.RUNTIME_DIRS)
            for name in blobs:
                path=Path(name).parent
                while str(path)!='.':dirs.add(str(path));path=path.parent
            for name in sorted(dirs):
                (tree/name).mkdir(exist_ok=True);(tree/name).chmod(0o755)
            for name,raw in blobs.items():(tree/name).write_bytes(raw);(tree/name).chmod(0o755 if name in ('venv/bin/python','runtime/bin/synthetic-worker','runtime/bin/security-probe') else 0o644)
            manifest={'version':1,'kind':'REVIEWED_STAGING_DEPENDENCIES','nodes':sorted(
                [{'path':v,'type':'directory','mode':0o755,'sha256':None} for v in dirs]+
                [{'path':v,'type':'file','mode':0o755 if v in ('venv/bin/python','runtime/bin/synthetic-worker','runtime/bin/security-probe') else 0o644,'sha256':hashlib.sha256(raw).hexdigest()} for v,raw in blobs.items()],key=lambda v:v['path'])}
            dep=n.StagingDependencies(tree,manifest);snapshot=dep.capture()
            report=base/'report';report.mkdir(mode=0o700);proof=i.persist_record(report,plan,observed,contract)
            receipt=i.ReceiptStore(report);identity=receipt.publish(observer,observed,contract,proof)
            contract['qualified_target_sha256']='a'*64
            register=base/'registration';register.mkdir(mode=0o700);store=n.RecordingRegistration(register)
            if closure:
                store.close()
                from orchestrator.privilege.build_closure import StagingClosureRegistration
                store=StagingClosureRegistration(register)
            args=(receipt,identity,observer,observed,contract,dep,snapshot)
            try:yield store,args,tree
            finally:store.close();receipt.close();dep.close()
    def case_roundtrip_restart_and_redaction(self):
        with self.fixture() as (store,args,tree):
            expected=store.publish(*args);value=store.accept(expected,*args)
            self.assertFalse(value['qualified']);self.assertFalse(value['execution_enabled']);self.assertFalse(value['removal_enabled'])
            raw=(store.path/'registration.json').read_bytes();self.assertNotIn(b'SYNTHETIC-TEST-ONLY',raw)
            self.assertLess(len(raw),i.MAX_RECORD)
            self.reject(lambda:store.publish(*args));self.reject(lambda:n.RecordingRegistration(store.path))
            path=store.path;store.close();restart=n.RecordingRegistration(path)
            try:self.assertEqual(restart.accept(expected,*args),value)
            finally:restart.close()
    def case_profile_and_missing_membership(self):
        self.assertFalse(n.protected_profile((0,0,0o700,0o600))['qualified'])
        for value in ((os.getuid()+1,0,0o700,0o600),(0,1,0o700,0o600),(0,0,0o755,0o600),[0,0,0o700,0o600]):self.reject(lambda:n.protected_profile(value))
        with self.fixture() as (store,args,tree):
            manifest=InventoryCases().copy(args[-2].manifest);manifest['nodes']=[x for x in manifest['nodes'] if x['path']!='venv/bin/python']
            self.reject(lambda:n.validate_manifest(manifest))
            (tree/'venv/bin/python').unlink();self.reject(lambda:store.publish(*args))
            self.assertFalse((store.path/'registration.json').exists())
    def case_replacement_binding_and_unknown_file(self):
        with self.fixture() as (store,args,tree):
            expected=store.publish(*args)
            for field in ('owner','enrollment','policy','qualified_target_sha256','source_commit'):
                contract=args[4].copy();contract[field]='f'*len(contract[field]);changed=list(args);changed[4]=contract
                self.reject(lambda:store.accept(expected,*changed))
            file=tree/'venv/bin/python';raw=file.read_bytes();file.rename(tree/'venv/bin/original');file.write_bytes(raw);file.chmod(0o755)
            self.reject(lambda:store.accept(expected,*args))
        with self.fixture() as (store,args,tree):
            (tree/'runtime/token').write_bytes(b'SYNTHETIC_SECRET_MUST_NOT_BE_READ');self.reject(lambda:store.publish(*args))
    def case_ancestry_symlink_and_bounds(self):
        with self.fixture() as (store,args,tree):
            (tree/'venv/bin').chmod(0o777);self.reject(lambda:args[-2].capture());(tree/'venv/bin').chmod(0o755)
            file=tree/'venv/bin/python';file.unlink();file.symlink_to('/usr/bin/python3');self.reject(lambda:store.publish(*args))
        with self.fixture() as (store,args,tree):
            counter=iter((0,11));args[-2].clock=lambda:next(counter)
            self.reject(lambda:args[-2].capture())
        with self.fixture() as (store,args,tree):
            file=tree/'venv/bin/python'
            with file.open('wb') as out:out.truncate(n.MAX_FILE+1)
            self.reject(lambda:store.publish(*args))
    def case_persistence_faults_and_corruption(self):
        for boundary in (1,2,3):
            with self.fixture() as (store,args,tree):
                original=os.fsync;calls=[]
                def fault(fd):
                    calls.append(fd)
                    if len(calls)==boundary:raise OSError('recording fault')
                    return original(fd)
                with patch.object(n.os,'fsync',side_effect=fault):self.reject(lambda:store.publish(*args))
                self.assertTrue((store.path/('registration.json' if boundary==3 else 'registration.pending')).exists())
                self.reject(lambda:store.publish(*args))
        with self.fixture() as (store,args,tree):
            expected=store.publish(*args);path=store.path/'registration.json';path.write_bytes(b'{')
            self.reject(lambda:store.accept(expected,*args))
    def case_observation_to_registration_race(self):
        with self.fixture() as (store,args,tree):
            original=n._rename
            def replace(parent,source,target):
                (tree/'venv/bin/python').write_bytes(b'changed-after-last-check')
                return original(parent,source,target)
            with patch.object(n,'_rename',side_effect=replace):self.reject(lambda:store.publish(*args))
            self.assertTrue((store.path/'registration.json').exists())
    def case_b6_b9_recording_consumer(self):
        from test_privilege_campaign import CampaignGuardCases
        from orchestrator.privilege.rollback import registered_inventory_plan,recipe_hash
        from orchestrator.privilege.real_journal import ResourceJournal
        with self.fixture() as (store,args,tree),tempfile.TemporaryDirectory() as temp:
            f=CampaignGuardCases();expected=f.contract()
            expected.update({k:args[4][k] for k in ('owner','enrollment','policy','source_commit','package_sha256','runtime_sha256','installation_sha256','inventory_sha256','qualified_target_sha256')})
            expected['rollback_plan_sha256']=recipe_hash()
            registration_identity=store.publish(*args)
            with f.fixture(expected) as (directory,expected):
                guard=f.guard(directory,expected);Path(temp).chmod(0o700)
                journal=ResourceJournal(temp,expected['policy'],expected['owner'],uid=os.getuid())
                receipt,identity,observer,observed,_,dependencies,snapshot=args
                def plan():return registered_inventory_plan(guard,journal,observer.plan,observed,registration=store,
                    registration_identity=registration_identity,receipt=receipt,receipt_identity=identity,
                    observer=observer,dependencies=dependencies,dependency_observation=snapshot)
                try:
                    guard.claim();result=plan()
                    self.assertFalse(result['removal_enabled']);self.assertFalse(result['registration']['qualified'])
                    self.reject(guard.claim)
                    (tree/'python_base/lib/python3.12/json/__init__.py').unlink();self.reject(plan)
                finally:guard.close();journal.close()
    def case_masquerade_wrong_owner_and_manifest(self):
        import json
        with self.fixture() as (store,args,tree):
            expected=store.publish(*args);path=store.path/'registration.json'
            raw=path.read_bytes();value=json.loads(raw);value.update(kind='ROOT_INSTALLED',qualified=True,installed_observed=True)
            path.write_bytes(i.encode(value))
            forged={'identity':i._identity(path.stat()),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            self.reject(lambda:store.accept(forged,*args))
            # Corrupt/replaced evidence is retained, never restored automatically.
            self.assertNotEqual(path.read_bytes(),raw)
        with self.fixture() as (store,args,tree):
            dependencies=args[-2];dependencies.uid+=1;self.reject(lambda:store.publish(*args))
            dependencies.uid-=1
            manifest=InventoryCases().copy(dependencies.manifest)
            manifest['nodes'].append({'path':'runtime/bin/unapproved','type':'file','mode':0o755,'sha256':'a'*64})
            self.reject(lambda:n.validate_manifest(manifest))
            manifest=InventoryCases().copy(dependencies.manifest);manifest['nodes']*=n.MAX_NODES
            self.reject(lambda:n.validate_manifest(manifest))
    def case_registration_replacement_pending_and_write_fault(self):
        with self.fixture() as (store,args,tree):
            expected=store.publish(*args);path=store.path/'registration.json';path.rename(store.path/'original')
            path.symlink_to(store.path/'original');self.reject(lambda:store.accept(expected,*args))
        with self.fixture() as (store,args,tree):
            with patch.object(n.os,'write',side_effect=OSError('recording write fault')):self.reject(lambda:store.publish(*args))
            self.assertTrue((store.path/'registration.pending').exists());self.reject(lambda:store.publish(*args))
        with self.fixture() as (store,args,tree):
            path=tree.with_name('original-tree');tree.rename(path);tree.mkdir(mode=0o700)
            self.reject(lambda:store.publish(*args))
    def case_packaging(self):
        import tomllib
        from orchestrator.privilege import policy_sources
        meta=tomllib.loads(Path('pyproject.toml').read_text())
        self.assertIn('orchestrator.privilege',meta['tool']['setuptools']['packages'])
        self.assertIn('privilege/installed_identity.py',policy_sources.PRIVILEGE_SOURCES)
        self.assertIn('fixtures/*.c',meta['tool']['setuptools']['package-data']['orchestrator.privilege'])

    def case_anchor_mode_history_invalidates_registration(self):
        with self.fixture() as (store,args,tree):
            expected=store.publish(*args)
            tree.chmod(0o755);tree.chmod(0o700)
            self.reject(lambda:store.accept(expected,*args))
            self.assertTrue((store.path/'registration.json').exists())
        with self.fixture() as (store,args,tree):
            marker=tree/'unexpected';marker.write_bytes(b'synthetic');marker.unlink()
            self.reject(lambda:store.publish(*args))

    def case_constructor_descriptor_failure(self):
        with self.fixture() as (store,args,tree):
            fd=os.open(tree,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            actual=n.os.fstat
            def fault(value):
                if value==fd:raise OSError('recording fstat fault')
                return actual(value)
            with patch.object(n,'directory_fd',return_value=fd),patch.object(n.os,'fstat',side_effect=fault):
                self.reject(lambda:n.StagingDependencies(tree,args[-2].manifest))
            with self.assertRaises(OSError):os.fstat(fd)
