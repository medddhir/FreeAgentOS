"""B10 temporary synthetic inventory only; no enrollment or installed objects."""
import contextlib
import functools
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from orchestrator.privilege import inventory as i, protocol as p, policy_sources as ps
from orchestrator.privilege.policy import policy_hash

class InventoryCases(unittest.TestCase):
    def cases(self):
        for n in sorted(n for n in dir(self) if n.startswith('case_')):
            with self.subTest(case=n):getattr(self,n)()
    def reject(self,fn):
        with self.assertRaises((p.BoundaryError,OSError)):fn()
    def copy(self,value):return json.loads(i.encode(value))
    def identities(self):
        blob=b'recorded-executable-not-executed';sha=hashlib.sha256(blob).hexdigest()
        binding={k:'a'*64 for k in i.BINDING};binding.update(installation='b'*32,enrollment='c'*32,owner='d'*32,source_commit='e'*40,policy=policy_hash())
        build={k:sha for k in i.PROVENANCE};build.update(fixture_source_sha256=i._fixture('security_probe.c'),synthetic_source_sha256=i._fixture('synthetic_worker.c'))
        return binding,build,blob
    @contextlib.contextmanager
    def fixture(self):
        binding,build,blob=self.identities();plan=i.prepare(binding,build)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            fd=os.open(ps._source_root(),os.O_RDONLY|os.O_DIRECTORY)
            try:
                for e in plan['entries']:
                    if not e['staged']:continue
                    path=root/e['slot']
                    if e['type']=='directory':path.mkdir();path.chmod(e['mode']);continue
                    raw=b'{}'
                    if e['category']=='CREDENTIAL':raw=b'SYNTHETIC-TEST-ONLY-NOT-A-CREDENTIAL'.ljust(64,b'!')
                    elif e['sha256'] is not None:
                        if '/package/orchestrator/' in e['target']:raw=ps._read_source(fd,e['target'].split('/package/orchestrator/')[1])
                        elif '/fixtures/' in e['target']:raw=(Path(i.__file__).parent/'fixtures'/e['target'].rsplit('/',1)[1]).read_bytes()
                        elif e['target'].endswith('.service'):raw=Path(i.__file__).with_name('validation.service').read_bytes()
                        else:raw=blob
                    path.write_bytes(raw);path.chmod(e['mode'])
            finally:os.close(fd)
            observer=i.StagingInventory(root,plan)
            observed=observer.capture();contract={**binding,'mode':'RECORDING_ONLY','installation_sha256':i.digest({'installation':binding['installation']}),'inventory_sha256':i.digest({'plan':plan,'observed':observed})}
            try:yield root,plan,observer,observed,contract
            finally:observer.close()
    def case_complete_redacted_retained(self):
        with self.fixture() as (root,plan,obs,snapshot,contract):
            self.assertLessEqual(len(plan['entries']),i.MAX_ENTRIES)
            self.assertFalse(i.prerequisite(plan,snapshot,contract)['qualifying'])
            raw=i.encode(snapshot);self.assertNotIn(b'SYNTHETIC-TEST',raw)
            self.assertNotIn(b'NOT-A-CREDENTIAL',i.encode(plan))
            for e,v in zip(plan['entries'],snapshot['observations']):
                if e['category']=='CREDENTIAL':self.assertIsNone(v['sha256'])
            removal=i.removal_plan(plan,snapshot,contract)
            self.assertFalse(removal['removal_enabled'])
            for e,s in zip(plan['entries'],removal['steps']):
                if e['category']=='RETAINED':self.assertEqual(s['action'],'RETAIN')
            self.assertFalse(snapshot['installed_observed']);self.assertFalse(snapshot['qualifying'])
    def case_missing_foreign_duplicate_and_identity(self):
        with self.fixture() as (root,plan,obs,snapshot,contract):
            (root/'foreign').write_bytes(b'unrelated');self.reject(obs.capture);(root/'foreign').unlink()
            entry=next(e for e in plan['entries'] if e['type']=='file' and e['staged']);path=root/entry['slot'];path.unlink();self.reject(obs.capture)
            for key in ('owner','policy','enrollment','source_commit'):
                changed=self.copy(contract);changed[key]='f'*len(changed[key]);self.reject(lambda:i.prerequisite(plan,snapshot,changed))
            duplicate=self.copy(plan);duplicate['entries'].append(duplicate['entries'][0]);self.reject(lambda:i.validate_plan(duplicate))
    def case_modes_types_symlink_replacement(self):
        with self.fixture() as (root,plan,obs,snapshot,contract):
            e=next(e for e in plan['entries'] if e['type']=='file' and e['staged']);path=root/e['slot'];raw=path.read_bytes()
            path.chmod(0o666);self.reject(obs.capture);path.chmod(e['mode'])
            uid=obs.uid;obs.uid+=1;self.reject(obs.capture);obs.uid=uid
            path.unlink();path.symlink_to('/dev/null');self.reject(obs.capture);path.unlink();path.mkdir();self.reject(obs.capture);path.rmdir()
            path.write_bytes(raw);path.chmod(e['mode']);self.reject(lambda:obs.recheck(snapshot))
    def case_source_executable_provenance_and_oversize(self):
        with self.fixture() as (root,plan,obs,snapshot,contract):
            for suffix in ('security-probe','security_probe.c','compiler.identity','build.record'):
                e=next(e for e in plan['entries'] if e['target'].endswith(suffix));path=root/e['slot'];raw=path.read_bytes()
                path.write_bytes(b'altered');self.reject(obs.capture);path.write_bytes(raw);path.chmod(e['mode'])
            e=next(e for e in plan['entries'] if e['target'].endswith('capture.json'));(root/e['slot']).write_bytes(b'x'*(i.MAX_FILE+1));self.reject(obs.capture)
            binding,build,_=self.identities();build['fixture_source_sha256']='0'*64;self.reject(lambda:i.prepare(binding,build))
    def case_planned_or_partial_cannot_authorize(self):
        with self.fixture() as (root,plan,obs,snapshot,contract):
            self.reject(lambda:i.prerequisite(plan,plan,contract))
            for field,value in (('kind','ROOT_INSTALLED'),('installed_observed',True),('qualifying',True),('version',2)):
                changed=self.copy(snapshot);changed[field]=value;self.reject(lambda:i.prerequisite(plan,changed,contract))
            changed=self.copy(snapshot);changed['observations'].pop();self.reject(lambda:i.prerequisite(plan,changed,contract))
            changed=self.copy(contract);changed['mode']='REAL_VALIDATION';self.reject(lambda:i.prerequisite(plan,snapshot,changed))
    def case_persistence_interrupted_and_restart(self):
        with self.fixture() as (root,plan,obs,snapshot,contract),tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o700);i.persist_record(tmp,plan,snapshot,contract)
            self.assertEqual(i.load_record(tmp,contract)['observed'],snapshot)
            self.reject(lambda:i.persist_record(tmp,plan,snapshot,contract))
            path=Path(tmp)/'inventory.json';path.write_bytes(b'{');self.reject(lambda:i.load_record(tmp,contract))
        with self.fixture() as (root,plan,obs,snapshot,contract),tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o700)
            with patch.object(i.os,'fsync',side_effect=OSError('recording fault')):self.reject(lambda:i.persist_record(tmp,plan,snapshot,contract))
            self.assertTrue((Path(tmp)/'inventory.json').exists());self.reject(lambda:i.persist_record(tmp,plan,snapshot,contract))
    def case_bound_mutation_and_parent_replacement(self):
        with self.fixture() as (root,plan,obs,snapshot,contract):
            obs.plan['entries'][0]['slot']='../unrelated';self.reject(obs.capture)
        with self.fixture() as (root,plan,obs,snapshot,contract):
            saved=root.with_name(root.name+'-saved');root.rename(saved);root.mkdir(mode=0o700)
            try:self.reject(obs.capture)
            finally:root.rmdir();saved.rename(root)
        with self.fixture() as (root,plan,obs,snapshot,contract):
            e=next(e for e in plan['entries'] if e['type']=='file' and e['category']=='CREDENTIAL')
            path=root/e['slot'];path.write_bytes(b'unknown');self.reject(obs.capture)
    def case_b6_b9_interface(self):
        from test_privilege_campaign import CampaignGuardCases
        from orchestrator.privilege.rollback import inventory_plan
        from orchestrator.privilege.real_journal import ResourceJournal
        with self.fixture() as (root,plan,obs,snapshot,contract):
            f=CampaignGuardCases();expected=f.contract();expected.update({k:contract[k] for k in ('owner','enrollment','policy','source_commit','package_sha256','runtime_sha256','installation_sha256','inventory_sha256')})
            from orchestrator.privilege.rollback import recipe_hash
            expected['rollback_plan_sha256']=recipe_hash()
            with f.fixture(expected) as (directory,expected),tempfile.TemporaryDirectory() as tmp:
                Path(tmp).chmod(0o700);guard=f.guard(directory,expected)
                journal=ResourceJournal(tmp,expected['policy'],expected['owner'],uid=os.getuid())
                try:
                    guard.claim();value=inventory_plan(guard,journal,plan,snapshot)
                    self.assertFalse(value['removal_enabled']);self.assertFalse(value['inventory']['qualifying'])
                    self.reject(guard.claim)
                    partial=self.copy(snapshot);partial['observations'].pop()
                    self.reject(lambda:inventory_plan(guard,journal,plan,partial))
                finally:guard.close();journal.close()
    def case_packaging_and_parser_cache(self):
        import tomllib
        metadata=tomllib.loads(Path('pyproject.toml').read_text());data=metadata['tool']['setuptools']['package-data']['orchestrator.privilege']
        self.assertIn('validation.service',data);self.assertIn('fixtures/*.c',data)
        self.assertIn('privilege/inventory.py',ps.PRIVILEGE_SOURCES)
        from test_privilege_rollback import RollbackCases
        original=ps._tree
        with patch.object(ps,'_tree',functools.lru_cache(maxsize=64)(original)) as cached:
            self.assertEqual(cached(b'x=1').body[0].value.value,1);self.assertEqual(cached(b'x=2').body[0].value.value,2)
            self.reject(lambda:cached(b'x='));self.assertEqual(cached.cache_info().maxsize,64)
        self.assertIs(ps._tree,original)
