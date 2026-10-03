"""B9 offline fake recovery: no service, process or kernel mutation."""
import contextlib
import functools
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from orchestrator.privilege import rollback as r, protocol as p
from orchestrator.privilege.real_journal import ResourceJournal
from test_privilege_campaign import CampaignGuardCases

class RollbackCases(unittest.TestCase):
    def cases(self):
        # Parsing is pure and readers never mutate the AST. Cache exact source
        # bytes only for this recording table; every policy call still securely
        # reads, validates and hashes sources. Different bytes cannot reuse ASTs.
        from orchestrator.privilege import policy_sources
        from orchestrator.privilege.policy import policy_hash
        expected_policy=policy_hash()
        parsed=functools.lru_cache(maxsize=64)(policy_sources._tree)
        try:
            with patch.object(policy_sources,'_tree',parsed):
                self.assertEqual(policy_hash(),expected_policy)
                self.assertNotEqual(parsed(b'value=1').body[0].value.value,
                                    parsed(b'value=2').body[0].value.value)
                self.reject(lambda:parsed(b'value='))
                for name in sorted(n for n in dir(self) if n.startswith('case_')):
                    with self.subTest(case=name):getattr(self,name)()
        finally:parsed.cache_clear()

    @contextlib.contextmanager
    def fixture(self,released=False):
        f=CampaignGuardCases();expected=f.contract();expected['rollback_plan_sha256']=r.recipe_hash()
        with f.fixture(expected) as (path,expected),tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);base.chmod(0o700);journal=ResourceJournal(base,expected['policy'],expected['owner'],uid=os.getuid())
            record={'handle':'a'*32,'run_id':'c'*32,'owner':expected['owner'],'policy':expected['policy'],
                'state':'RELEASED' if released else 'FAILED_DIRTY','cleanup':'CONFIRMED' if released else 'UNPROVEN',
                'class':'MODEL_WORKER','role':'coder','boot_id':'recording-boot','scope_inode':10,'scope_device':1,
                'root_inode':11,'root_device':1,'started_ns':1,'collection':'NONE'}
            journal.save([record]);guard=f.guard(path,expected);guard.claim()
            plan=r.make_plan(guard,journal)
            world={record['handle']:{'binding':plan['binding'],'identity':r.resource_identity(record),
                'launch_settled':True,'states':{k:'ABSENT' if k in ('observers','descriptors') else 'PRESENT' for k in r.RESOURCES}}}
            actor=r.RecordingRecoveryAdapter(world);observer=r.RecordingAbsenceObserver(world)
            executor=r.RecordingRollback(guard,journal,actor,observer)
            try:yield executor,guard,journal,actor,observer,record,path,base
            finally:guard.close();journal.close()

    def reject(self,fn):
        with self.assertRaises(p.BoundaryError):fn()

    def case_offline_and_released(self):
        for released in (False,True):
            with self.fixture(released) as (ex,g,j,actor,obs,record,path,base):
                before=(base/'resources.json').read_bytes();attempt=(path/'consumed.json').read_bytes()
                value=ex.run();self.assertEqual(value['verification']['scoped_cleanup'],'CONFIRMED')
                self.assertFalse(value['verification']['zero_residual']);self.assertFalse(value['verification']['qualifying'])
                self.assertEqual(value['verification']['cleanup'],'UNPROVEN');self.assertTrue(value['admission_fenced'])
                self.assertEqual([a for h,a in actor.events],list(r.ACTIONS))
                self.assertEqual(before,(base/'resources.json').read_bytes());self.assertEqual(attempt,(path/'consumed.json').read_bytes())
                self.reject(g.claim)
                second=ex.run();self.assertEqual(len(actor.events),4);self.assertEqual(second['round'],1)

    def case_binding_and_corrupt_journal(self):
        for key in ('campaign','installation','enrollment','policy'):
            with self.fixture() as (ex,g,j,actor,obs,record,*_):
                actor.world[record['handle']]['binding'][key]='9'*64
                value=ex.run();self.assertEqual(value['state'],'FAILED_DIRTY');self.assertFalse(actor.events)
        with self.fixture() as (ex,g,j,actor,obs,record,path,base):
            (base/'resources.json').write_bytes(b'{');self.reject(ex.run);self.assertFalse(actor.events)
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            g.expected['rollback_plan_sha256']='0'*64;self.reject(ex.run);self.assertFalse(actor.events)

    def case_scope_pid_and_inode_substitution(self):
        for key in ('scope_inode','root_inode','boot_id','owner'):
            with self.fixture() as (ex,g,j,actor,obs,record,*_):
                actor.world[record['handle']]['identity'][key]=99
                value=ex.run();self.assertEqual(value['state'],'FAILED_DIRTY');self.assertFalse(actor.events)
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            actor.world[record['handle']]['launch_settled']=False
            self.assertEqual(ex.run()['state'],'FAILED_DIRTY');self.assertFalse(actor.events)
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            original=actor.perform
            def race(plan,record,action):
                actor.world[record['handle']]['identity']['scope_inode']+=1
                return original(plan,record,action)
            with patch.object(actor,'perform',side_effect=race):self.assertEqual(ex.run()['state'],'FAILED_DIRTY')
            self.assertFalse(actor.events)

    def case_action_failures_and_false_success(self):
        for action in r.ACTIONS:
            with self.fixture() as (ex,g,j,actor,obs,record,*_):
                actor.fail.add(action);value=ex.run()
                self.assertEqual(value['state'],'FAILED_DIRTY');self.assertFalse(value['verification']['zero_residual'])
                actor.fail.clear();again=ex.run();self.assertEqual(again['verification']['scoped_cleanup'],'CONFIRMED')
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            actor.leave_residual.add('TERMINATE_SCOPE');value=ex.run()
            self.assertEqual(value['state'],'FAILED_DIRTY');self.assertEqual(len(actor.events),1)
            self.assertIn('PRESENT',value['verification']['details'][0]['states'].values())

    def case_unknown_observers_and_descriptor_evidence(self):
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            record['collection']='PENDING';j.save([record])
            value=ex.run();self.assertEqual(value['state'],'FAILED_DIRTY')
            self.assertEqual(actor.events,[(record['handle'],'TERMINATE_SCOPE')])
            self.assertEqual(value['verification']['details'][0]['states']['descriptors'],'UNKNOWN')
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            actor.world[record['handle']]['states']['observers']='UNKNOWN'
            self.assertEqual(ex.run()['state'],'FAILED_DIRTY')

    def case_persistence_interruption_and_resume(self):
        with self.fixture() as (ex,g,j,actor,obs,record,path,base):
            original=g._persist
            def interrupt(name,value):
                original(name,value)
                if '-action-' in name:raise KeyboardInterrupt()
            with patch.object(g,'_persist',side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):ex.run()
            self.assertFalse(actor.events);self.assertTrue((path/'rollback-0.json').exists())
            value=ex.run();self.assertEqual(value['round'],1);self.assertEqual(value['verification']['scoped_cleanup'],'CONFIRMED')
            self.reject(g.claim)
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            original=g._persist
            def fail_result(name,value):
                if name.endswith('-result.json'):raise OSError('private persistence failure')
                return original(name,value)
            with patch.object(g,'_persist',side_effect=fail_result):self.reject(ex.run)
            self.assertEqual(ex.run()['verification']['scoped_cleanup'],'CONFIRMED')

    def case_observer_failure_deadline_and_bounds(self):
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            obs.fail.add(record['handle']);self.assertEqual(ex.run()['state'],'FAILED_DIRTY');self.assertFalse(actor.events)
            obs.fail.clear()
            self.assertEqual(ex.run()['verification']['scoped_cleanup'],'CONFIRMED')
            ex.run();self.reject(ex.run)  # explicit finite recovery rounds
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            values=iter((0,11));ex.clock=lambda:next(values,11)
            self.assertEqual(ex.run()['state'],'FAILED_DIRTY');self.assertFalse(actor.events)
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            records=[]
            for n in range(4):records.append({**record,'handle':format(n,'032x')})
            j.save(records);self.reject(ex.run);self.assertFalse(actor.events)

    def case_independent_attempts(self):
        with self.fixture() as (ex,g,j,actor,obs,record,*_):
            second={**record,'handle':'e'*32,'run_id':'f'*32};j.save([record,second]);plan=r.make_plan(g,j)
            actor.world[second['handle']]={'binding':plan['binding'],'identity':r.resource_identity(second),
                'launch_settled':True,'states':{k:'ABSENT' if k in ('observers','descriptors') else 'PRESENT' for k in r.RESOURCES}}
            obs.fail.add(record['handle'])
            value=ex.run();self.assertEqual(value['state'],'FAILED_DIRTY')
            self.assertEqual([a for h,a in actor.events if h==second['handle']],list(r.ACTIONS))
            self.assertEqual(value['verification']['details'][0]['status'],'UNPROVEN')
            self.assertEqual(value['verification']['details'][1]['status'],'CONFIRMED')
