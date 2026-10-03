"""Temporary recording approval fixtures only. No real approval or campaign."""
import contextlib
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from orchestrator.privilege import campaign as c, protocol as p
from orchestrator.privilege.policy import policy_hash
from orchestrator.privilege.recording import RecordingDriver
from orchestrator.privilege.stress_gate import PreparedProbe

class CampaignGuardCases(unittest.TestCase):
    def cases(self):
        for name in sorted(n for n in dir(self) if n.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()

    def contract(self):
        value={k:hashlib.sha256(k.encode()).hexdigest() for k in c.DIGESTS}
        value.update(version=1,mode='RECORDING_ONLY',source_commit='e'*40,valid_from=100,valid_until=200,
                     campaign='a'*32,owner='b'*32,enrollment='c'*32,policy=policy_hash(),fixture_source_sha256=c.FIXTURE_SHA256,
                     probe_plans={k:hashlib.sha256(k.encode()).hexdigest() for k in ('cpu','memory','pids')})
        return value

    def write(self,path,value):
        path.write_bytes(c.canonical(value));path.chmod(0o600)

    @contextlib.contextmanager
    def fixture(self,contract=None):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);path.chmod(0o700);contract=contract or self.contract()
            info=path.stat()
            self.write(path/'approval.json',{'version':1,'owner_review':'d'*32,'contract':contract,
                'storage':{'device':info.st_dev,'inode':info.st_ino,'uid':os.getuid(),'gid':os.getgid()}})
            yield path,contract

    def reject(self,fn,code=None):
        with self.assertRaises(p.BoundaryError) as caught:fn()
        if code:self.assertEqual(caught.exception.code,code)

    def guard(self,path,expected):return c.RecordingCampaignGuard(path,expected,clock=lambda:150)

    def case_claim_and_restart(self):
        with self.fixture() as (path,expected):
            gate=self.guard(path,expected)
            try:
                ticket=gate.claim();self.assertFalse(ticket.execution_enabled)
                self.assertTrue((path/'reserved.json').exists());self.assertTrue((path/'consumed.json').exists())
                self.reject(gate.claim,'RECOVERY_REQUIRED')
                self.assertEqual(gate.cleanup_context()['attempt_state'],'CONSUMED')
                self.assertFalse(gate.cleanup_context()['retry_authorized'])
            finally:gate.close()
            gate=self.guard(path,expected)
            try:self.reject(gate.claim,'RECOVERY_REQUIRED');self.assertFalse(gate.cleanup_context()['execution_enabled'])
            finally:gate.close()

    def case_linux_auth_is_not_owner_approval(self):
        from test_privilege_probe import ProbeContractCases
        from orchestrator.privilege.client import ControllerClient
        fixture=ProbeContractCases()
        with fixture.endpoint(True) as (server,enrollment,engine,backend),fixture.linux_client_profile():
            client=ControllerClient(server.path,enrollment,0,os.getgid(),linux_validation=True)
            try:
                self.assertEqual(client.probe()['mode'],'LINUX')
                with tempfile.TemporaryDirectory() as tmp:
                    Path(tmp).chmod(0o700)
                    self.reject(lambda:self.guard(tmp,self.contract()))
                self.assertFalse(backend.driver.events);self.assertFalse(engine.records)
            finally:client.close()

    def case_concurrent(self):
        with self.fixture() as (path,expected):
            barrier=threading.Barrier(2);results=[]
            def claim():
                barrier.wait();gate=None
                try:gate=self.guard(path,expected);gate.claim();results.append('OK')
                except p.BoundaryError as error:results.append(error.code)
                finally:
                    if gate:gate.close()
            threads=[threading.Thread(target=claim) for _ in range(2)]
            for t in threads:t.start()
            for t in threads:t.join(3);self.assertFalse(t.is_alive())
            self.assertEqual(results.count('OK'),1)
            self.assertIn(next(v for v in results if v!='OK'),('SOCKET_BUSY','RECOVERY_REQUIRED'))

    def case_binding_and_prerequisites(self):
        with self.fixture() as (path,expected):
            for key in (*c.IDS,*c.DIGESTS,'source_commit'):
                changed=json.loads(c.canonical(expected));changed[key]='9'*len(changed[key])
                self.reject(lambda:self.guard(path,changed))
            for key in ('rollback_plan_sha256','inventory_sha256','qualified_target_sha256','build_provenance_sha256'):
                changed=json.loads(c.canonical(expected));changed.pop(key)
                self.reject(lambda:self.guard(path,changed))
            changed=json.loads(c.canonical(expected));changed['probe_plans']['cpu']='9'*64
            self.reject(lambda:self.guard(path,changed))
            changed=json.loads(c.canonical(expected));changed['mode']='REAL_VALIDATION'
            self.reject(lambda:self.guard(path,changed))
            for mode in (True,{'linux_validation':True},'LINUX'):
                changed=json.loads(c.canonical(expected));changed['mode']=mode
                self.reject(lambda:self.guard(path,changed))
            gate=c.RecordingCampaignGuard(path,expected,clock=lambda:200)
            try:self.reject(gate.claim,'POLICY_REJECTED');self.assertFalse((path/'reserved.json').exists())
            finally:gate.close()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o700)
            self.reject(lambda:self.guard(tmp,self.contract()))

    def case_crash_boundaries(self):
        # Injection after each successful durable operation models abrupt loss;
        # no callback exists before both records have been persisted/verified.
        for boundary in ('before_slot','after_reserved','after_consumed'):
            with self.fixture() as (path,expected):
                gate=self.guard(path,expected);original=gate._persist
                def persist(name,value):
                    if boundary=='before_slot':raise OSError('private failure')
                    original(name,value)
                    if name==('reserved.json' if boundary=='after_reserved' else 'consumed.json'):raise OSError('private failure')
                with patch.object(gate,'_persist',side_effect=persist):self.reject(gate.claim)
                self.reject(gate.claim,'RECOVERY_REQUIRED');gate.close()
                again=self.guard(path,expected)
                try:
                    if boundary=='before_slot':
                        # No slot and no campaign effect: explicitly NOT_ATTEMPTED.
                        self.assertFalse((path/'reserved.json').exists());again.claim()
                    else:
                        self.reject(again.claim,'RECOVERY_REQUIRED')
                        self.assertEqual(again.cleanup_context()['attempt_state'],'RESERVED' if boundary=='after_reserved' else 'CONSUMED')
                finally:again.close()

    def case_partial_corrupt_and_replacement(self):
        for raw in (b'',b'{',b'{}',b'{"version":1,"version":1}',b'x'*(c.MAX_BYTES+1)):
            with self.fixture() as (path,expected):
                (path/'reserved.json').write_bytes(raw);(path/'reserved.json').chmod(0o600)
                gate=self.guard(path,expected)
                try:self.reject(gate.claim,'RECOVERY_REQUIRED');self.reject(gate.cleanup_context)
                finally:gate.close()
                self.assertEqual((path/'reserved.json').read_bytes(),raw)
        with self.fixture() as (path,expected):
            gate=self.guard(path,expected);gate.claim()
            original=(path/'reserved.json').read_bytes();(path/'reserved.json').rename(path/'old')
            (path/'reserved.json').write_bytes(original);(path/'reserved.json').chmod(0o600)
            self.reject(gate.cleanup_context,'JOURNAL_INVALID');gate.close()
        with self.fixture() as (path,expected):
            gate=self.guard(path,expected)
            (path/'approval.json').rename(path/'old');self.write(path/'approval.json',json.loads((path/'old').read_bytes()))
            self.reject(gate.claim,'POLICY_REJECTED');gate.close()

    def case_filesystem_checks(self):
        for target in ('approval.json','campaign.lock'):
            with self.fixture() as (path,expected):
                if target=='campaign.lock':self.write(path/target,{})
                (path/target).rename(path/'foreign');(path/target).symlink_to(path/'foreign')
                self.reject(lambda:self.guard(path,expected))
        for mode in (0o644,0o666):
            with self.fixture() as (path,expected):
                (path/'approval.json').chmod(mode);self.reject(lambda:self.guard(path,expected))
        with self.fixture() as (path,expected):
            path.chmod(0o755);self.reject(lambda:self.guard(path,expected))
        with self.fixture() as (path,expected):
            gate=self.guard(path,expected)
            (path/'campaign.lock').rename(path/'old');self.write(path/'campaign.lock',{})
            self.reject(gate.claim,'JOURNAL_INVALID');gate.close()
        with self.fixture() as (path,expected):
            gate=self.guard(path,expected)
            with patch('os.fsync',side_effect=OSError('private fsync failure')):self.reject(gate.claim)
            self.assertTrue((path/'reserved.json').exists());gate.close()
            again=self.guard(path,expected)
            try:self.reject(again.claim,'RECOVERY_REQUIRED')
            finally:again.close()

    def case_durability_and_storage_binding(self):
        for boundary in range(1,7):
            with self.fixture() as (path,expected):
                gate=self.guard(path,expected);original=os.fsync;calls=[]
                def sync(fd):
                    calls.append(fd)
                    if len(calls)==boundary:raise OSError('private persistence failure')
                    return original(fd)
                with patch('os.fsync',side_effect=sync):self.reject(gate.claim)
                self.assertIsNone(gate.issued);self.assertTrue((path/'reserved.json').exists());gate.close()
                again=self.guard(path,expected)
                try:self.reject(again.claim,'RECOVERY_REQUIRED');self.assertIsNone(again.issued)
                finally:again.close()
        with self.fixture() as (path,expected),tempfile.TemporaryDirectory() as tmp:
            other=Path(tmp);other.chmod(0o700)
            (other/'approval.json').write_bytes((path/'approval.json').read_bytes());(other/'approval.json').chmod(0o600)
            self.reject(lambda:self.guard(other,expected),'POLICY_REJECTED')
        with self.fixture() as (path,expected):
            gate=self.guard(path,expected)
            original=os.write;once=[]
            def partial(fd,raw):
                if once:raise OSError('private partial write')
                once.append(fd);return original(fd,raw[:3])
            with patch('os.write',side_effect=partial):self.reject(gate.claim)
            self.assertEqual((path/'reserved.json').stat().st_size,3);self.reject(gate.cleanup_context);gate.close()

    def case_strict_types_permissions_and_expiry(self):
        with self.fixture() as (path,expected):
            for key,value in (('version',2),('version',True),('rollback_plan_sha256',None),('valid_from','100'),('valid_until',10000)):
                bad=json.loads(c.canonical(expected));bad[key]=value
                self.reject(lambda:self.guard(path,bad))
            bad=json.loads(c.canonical(expected));bad['probe_plans']['cpu']=[]
            self.reject(lambda:self.guard(path,bad))
            bad=json.loads(c.canonical(expected));bad['extra']=True
            self.reject(lambda:self.guard(path,bad))
            with patch('os.getuid',return_value=os.getuid()+1):self.reject(lambda:self.guard(path,expected))
            with patch('os.getgid',return_value=os.getgid()+1):self.reject(lambda:self.guard(path,expected))
        for times in ((150,200),(150,150,200)):
            with self.fixture() as (path,expected):
                clock=iter(times);gate=c.RecordingCampaignGuard(path,expected,clock=lambda:next(clock))
                try:
                    self.reject(gate.claim,'POLICY_REJECTED');self.assertIsNone(gate.issued)
                    self.assertTrue((path/'reserved.json').exists());self.reject(gate.claim,'RECOVERY_REQUIRED')
                finally:gate.close()
        with self.fixture() as (path,expected):
            os.link(path/'approval.json',path/'hardlink')
            self.reject(lambda:self.guard(path,expected))

    def case_recording_interface_only(self):
        from test_privilege_security_proof import SecurityProofCases
        from test_privilege_security_assembly import SecurityAssemblyCases
        expected=self.contract();x=SecurityProofCases().expectation()
        identity=dict(x.binding);identity.update(owner=expected['owner'],policy=expected['policy'],executable_sha256=expected['executable_sha256'])
        x=dataclasses.replace(x,binding=identity,limits=dict(x.limits))
        prepared,_=SecurityAssemblyCases().fixture(x,'cpu');raw=prepared.payload
        expected['probe_plans']['cpu']=prepared.digest
        with self.fixture(expected) as (path,expected):
            gate=self.guard(path,expected);ticket=gate.claim();driver=RecordingDriver()
            try:
                self.assertEqual(gate.recording_probe(ticket,prepared,x,driver),raw)
                self.reject(lambda:gate.recording_probe(ticket,prepared,x,driver))
                self.reject(lambda:gate.recording_probe(ticket,prepared,x,object()),'POLICY_REJECTED')
                self.reject(lambda:gate.recording_probe(dataclasses.replace(ticket,execution_enabled=True),prepared,x,driver),'POLICY_REJECTED')
                self.assertEqual(list(driver.events),[(None,'STRESS_PREPARATION_RECORDING')])
                self.assertFalse(driver.resources)
            finally:gate.close()
            again=self.guard(path,expected)
            try:self.reject(lambda:again.recording_probe(ticket,prepared,x,driver))
            finally:again.close()
