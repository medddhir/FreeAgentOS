"""B11 strict PROBE projection; temporary IPC and recording backend only."""
import contextlib
import os
import unittest
from unittest.mock import Mock, patch
from orchestrator.privilege import protocol as p
from orchestrator.privilege.client import ControllerClient
from orchestrator.privilege.supervisor import LocalServer, Supervisor
from orchestrator.privilege.security import Enrollment, validate_socket
from test_privilege import PrivilegeCases
from test_privilege_complete import LinuxCompleteCases


class ProbeContractCases(unittest.TestCase):
    def cases(self):
        for name in ('simulation','linux','projection','backend_rejection','handshake','opt_in','no_enforcement'):
            with self.subTest(case=name):getattr(self,'case_'+name)()

    def rejected(self, call, code='INVALID_REQUEST'):
        with self.assertRaises(p.BoundaryError) as caught:call()
        self.assertEqual(caught.exception.code,code)

    @contextlib.contextmanager
    def endpoint(self,linux=False):
        with PrivilegeCases().fixture() as (base,e,roots,journal,fake,engine):
            with contextlib.ExitStack() as stack:
                backend=fake
                if linux:
                    backend,driver,*_=stack.enter_context(LinuxCompleteCases().fixture())
                    engine=Supervisor(e,roots,backend,journal,linux_validation=True)
                server=LocalServer(base/'probe.sock',engine).start()
                try:yield server,e,engine,backend
                finally:server.close()

    @contextlib.contextmanager
    def linux_client_profile(self):
        # No root service/profile is installed. Test-only substitution checks the
        # requested production socket profile, then validates actual temporary
        # 0700/0600 fixture. Root peer identity is mocked, never certified.
        def fixture_socket(path,uid,gid,**kw):
            self.assertEqual((uid,gid,kw),(0,os.getgid(),{'parent_mode':0o750,'socket_mode':0o660}))
            validate_socket(path,os.getuid(),os.getgid())
        with patch('orchestrator.privilege.client.validate_socket',side_effect=fixture_socket), \
             patch('orchestrator.privilege.client.peer_credentials',return_value=(1,0,os.getgid())):
            yield

    def case_simulation(self):
        with self.endpoint() as (server,e,engine,backend):
            client=ControllerClient(server.path,e,os.getuid(),os.getgid())
            try:
                self.assertEqual(client.probe(),{'schema_version':1,'mode':'SIMULATED',
                                                'readiness':'UNPROVEN','enforcement':'UNPROVEN'})
                self.assertFalse(engine.records);self.assertFalse(backend.resources)
            finally:client.close()

    def case_linux(self):
        with self.endpoint(True) as (server,e,engine,backend),self.linux_client_profile():
            with patch.object(backend.driver,'qualify',side_effect=AssertionError('PROBE must not qualify')):
                client=ControllerClient(server.path,e,0,os.getgid(),linux_validation=True)
                try:
                    self.assertEqual(client.probe(),{'schema_version':1,'mode':'LINUX',
                                                    'readiness':'UNPROVEN','enforcement':'UNPROVEN'})
                    self.assertFalse(backend.driver.events);self.assertFalse(engine.records)
                finally:client.close()

    def case_projection(self):
        for mode in ('SIMULATED','LINUX'):
            valid=p.probe_record(mode)
            other='LINUX' if mode=='SIMULATED' else 'SIMULATED'
            invalid=[None,[],{}, {'mode':mode,'enforcement':'UNPROVEN'},
                     {**valid,'mode':other},{**valid,'mode':'UNKNOWN'},
                     {**valid,'schema_version':True},{**valid,'schema_version':2},
                     {**valid,'schema_version':'1'},{**valid,'schema_version':1.0},
                     {**valid,'extra':'configured'},{**valid,'readiness':'READY'},
                     {**valid,'readiness':None},{**valid,'enforcement':'VERIFIED'},
                     {**valid,'enforcement':'CONFIRMED'},{**valid,'enforcement':True},
                     {**valid,'observed_kernel':True}]
            invalid.extend({k:v for k,v in valid.items() if k!=field} for field in valid)
            client=object.__new__(ControllerClient);client.mode=mode
            for bad in invalid:
                with self.subTest(mode=mode,shape=type(bad).__name__):
                    client._rpc=Mock(return_value=bad)
                    self.rejected(client.probe)
            client._rpc=Mock(return_value=valid)
            self.assertEqual(client.probe(),valid)

    def case_backend_rejection(self):
        for linux in (False,True):
            with self.endpoint(linux) as (server,e,engine,backend):
                expected='LINUX' if linux else 'SIMULATED'
                other='SIMULATED' if linux else 'LINUX'
                request={'version':1,'seq':1,'op':'PROBE','args':{'probe':'BOUNDARY_V1'}}
                for bad in (p.probe_record(other),{**p.probe_record(expected),'enforcement':'VERIFIED'},
                            {**p.probe_record(expected),'readiness':'READY'}):
                    with patch.object(backend,'probe',return_value=bad):
                        self.rejected(lambda:engine.dispatch(request,'a'*32,(1,e.uid,e.gid)))
                self.assertFalse(engine.records)

    def case_handshake(self):
        # Both mode mismatches are rejected at HELLO, before PROBE. The separate
        # projection table proves malicious later response mismatches also fail.
        with self.endpoint(True) as (server,e,engine,backend):
            self.rejected(lambda:ControllerClient(server.path,e,os.getuid(),os.getgid()),'POLICY_REJECTED')
        with self.endpoint() as (server,e,engine,backend),self.linux_client_profile():
            self.rejected(lambda:ControllerClient(server.path,e,0,os.getgid(),linux_validation=True),'POLICY_REJECTED')
        with self.endpoint() as (server,e,engine,backend):
            wrong=Enrollment(e.enrollment_id,e.uid,e.gid,'e'*64)
            self.rejected(lambda:ControllerClient(server.path,wrong,os.getuid(),os.getgid()),'AUTH_FAILED')
            with patch('orchestrator.privilege.client.policy_hash',return_value='f'*64):
                self.rejected(lambda:ControllerClient(server.path,e,os.getuid(),os.getgid()),'POLICY_REJECTED')
            self.assertFalse(engine.records)

    def case_opt_in(self):
        for bad in (1,'true',None,[]):
            with patch('orchestrator.privilege.client.socket.socket',side_effect=AssertionError('must reject before connecting')):
                self.rejected(lambda:ControllerClient('/not-used',None,0,0,linux_validation=bad),'POLICY_REJECTED')
        self.rejected(lambda:ControllerClient('/not-used',None,1234,1234,linux_validation=True),'PEER_NOT_ALLOWED')
        with self.assertRaises(p.BoundaryError):p.validate_response(p.response(1,'OK',p.probe_record('LINUX'))|{'version':2},1)

    def case_no_enforcement(self):
        with LinuxCompleteCases().fixture() as (backend,driver,*_):
            self.assertEqual(backend.probe()['readiness'],'UNPROVEN')
            self.assertEqual(backend.probe()['enforcement'],'UNPROVEN')
            driver.qualified=True  # configured/read-only prerequisite state is not proof
            self.assertEqual(backend.probe()['enforcement'],'UNPROVEN')
            self.assertFalse(driver.events)
