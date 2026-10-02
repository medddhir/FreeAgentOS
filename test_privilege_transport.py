"""B3 temporary IPC + recording driver; no privileged kernel operations."""
import contextlib
import os
import secrets
import socket
import struct
import time
import unittest
from unittest.mock import Mock, patch
from orchestrator.privilege import protocol as p
from orchestrator.privilege.policy import policy_hash
from orchestrator.privilege.supervisor import LocalServer, Supervisor
from orchestrator.privilege.journal import Journal
from test_privilege import PrivilegeCases
from test_privilege_complete import LinuxCompleteCases


class TransportLifetimeCases(unittest.TestCase):
    def cases(self):
        for name in ('quiet_hard_cap','base_without_progress','disconnect','expiry','shutdown',
                     'handshake','partial','frame_deadline','identity'):
            with self.subTest(case=name):getattr(self,'case_'+name)()

    def eventually(self, predicate):
        until=time.monotonic()+2
        while not predicate() and time.monotonic()<until:time.sleep(.01)
        self.assertTrue(predicate())

    @contextlib.contextmanager
    def live(self):
        # Actual protocol/authentication with the existing complete Linux
        # lifecycle, exclusively over RecordingDriver and temporary journals.
        with PrivilegeCases().fixture() as (base,e,roots,control,_,__):
            roots.register('validation',base/'work',os.getuid())
            with LinuxCompleteCases().fixture() as (backend,driver,journal,clock,entry):
                engine=Supervisor(e,roots,backend,control,linux_validation=True)
                server=LocalServer(base/'quiet.sock',engine,clock=lambda:clock[0]/1e9).start()
                wire=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                try:
                    wire.connect(str(server.path));greeting=p.receive(wire)
                    seq=[0]
                    def rpc(op,args):
                        seq[0]+=1
                        p.send(wire,{'version':p.VERSION,'seq':seq[0],'op':op,'args':args})
                        return p.validate_response(p.receive(wire),seq[0])
                    rpc('HELLO',{'enrollment':e.enrollment_id,'token':e.token,
                        'challenge':greeting['data']['challenge'],'build':p.BUILD,'policy':policy_hash()})
                    result=rpc('CREATE',{'run_id':secrets.token_hex(16),'slot':'validation',
                        'class':'MODEL_WORKER','role':'coder','limits':{}})
                    h=result['handle'];rpc('START',{'handle':h})
                    yield wire,rpc,seq,h,engine,backend,driver,clock,server
                finally:wire.close();server.close()

    def case_quiet_hard_cap(self):
        with self.live() as (wire,rpc,seq,h,engine,b,d,clock,server):
            lease=b.leases[h];started=lease.started_ns
            broker=Mock();broker.telemetry.last_success_ns=started+179_000_000_000
            b.observe_progress(h,broker)
            clock[0]=started+180_000_000_000
            self.eventually(lambda:lease.granted)
            self.assertEqual(lease.deadline_ns,started+240_000_000_000)
            # Stay quiet beyond the actual former one-second idle deadline;
            # the 180/240s lease window itself uses fake monotonic time.
            time.sleep(p.TIMEOUT+.15)
            self.assertEqual(seq[0],3);self.assertEqual(b.records[h]['state'],'RUNNING')
            clock[0]=started+239_000_000_000
            self.assertEqual(rpc('STATUS',{'handle':h})['state'],'RUNNING')
            self.assertEqual(lease.deadline_ns,started+240_000_000_000)
            before=list(engine.log);clock[0]=started+240_000_000_000
            self.eventually(lambda:b.records[h]['state']=='TERMINATED')
            self.assertEqual(list(engine.log),before)  # monitor, not RPC dispatch
            self.assertIn((h,'CGROUP_KILL_OWNED'),d.events)
            self.assertEqual(rpc('STATUS',{'handle':h})['state'],'TERMINATED')
            self.assertEqual(rpc('RELEASE',{'handle':h})['state'],'RELEASED')
            self.assertEqual(seq[0],6);self.assertLess(seq[0],p.MAX_REQUESTS)

    def case_base_without_progress(self):
        with self.live() as (_,rpc,seq,h,engine,b,d,clock,server):
            lease=b.leases[h];deadline=lease.base_ns
            clock[0]=179_000_000_000;rpc('STATUS',{'handle':h})
            self.assertIsNone(lease.last_ns)
            clock[0]=deadline;self.eventually(lambda:b.records[h]['state']=='TERMINATED')
            self.assertFalse(lease.granted);self.assertEqual(lease.deadline_ns,deadline)

    def case_disconnect(self):
        with self.live() as (wire,_,__,h,engine,b,d,clock,server):
            wire.close();self.eventually(lambda:engine.records[h]['state']=='RELEASED')
            self.assertFalse(d.resources)

    def case_expiry(self):
        with self.live() as (wire,rpc,seq,h,engine,b,d,clock,server):
            # Requests do not slide the absolute connection deadline.
            clock[0]=int((p.AUTHENTICATED_LIFETIME-1)*1e9)
            rpc('STATUS',{'handle':h})
            clock[0]=int(p.AUTHENTICATED_LIFETIME*1e9)
            self.eventually(lambda:engine.records[h]['state']=='RELEASED')
            self.eventually(lambda:not server.channels)
            self.assertFalse(d.resources)

    def case_shutdown(self):
        with self.live() as (wire,_,__,h,engine,b,d,clock,server):
            started=time.monotonic();server.close()
            self.assertLess(time.monotonic()-started,1)
            self.assertFalse(any(t.is_alive() for t in server.threads))
            self.assertEqual(engine.records[h]['state'],'RELEASED')
            # Avoid closing the fixture's parent FD twice.
            server.close=lambda:None

    def case_handshake(self):
        with PrivilegeCases().fixture() as (base,e,roots,j,backend,engine):
            with patch.object(p,'TIMEOUT',.05):
                server=LocalServer(base/'stall.sock',engine).start()
                wire=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                try:
                    wire.connect(str(server.path));p.receive(wire)
                    self.eventually(lambda:not server.channels)
                    self.assertEqual(p.receive(wire)['code'],'TRANSPORT_FAILURE')
                    self.assertFalse(engine.records)
                finally:wire.close();server.close()

    def case_partial(self):
        for prefix in (b'\x00',struct.pack('!I',20)+b'{'):
            with self.subTest(prefix_length=len(prefix)):
                with self.live() as (wire,_,__,h,engine,b,d,clock,server):
                    with patch.object(p,'TIMEOUT',.05):
                        wire.sendall(prefix)
                        self.eventually(lambda:engine.records[h]['state']=='RELEASED')
                    self.assertFalse(d.resources)
                    self.assertEqual(p.receive(wire)['code'],'TRANSPORT_FAILURE')

    def case_frame_deadline(self):
        # First-byte idle wait has a separate clock; header+body share one
        # real monotonic deadline, unaffected by packet count/trickle traffic.
        class Wire:
            def __init__(self):self.timeouts=[];self.parts=[b'\0',b'\0\0\x02',b'{}']
            def settimeout(self,value):self.timeouts.append(value)
            def recv(self,count):return self.parts.pop(0)
        wire=Wire()
        with patch.object(p.time,'monotonic',side_effect=[0,.25,.75]):
            self.assertEqual(p.receive(wire,idle_deadline=600,clock=lambda:0),{})
        self.assertEqual(wire.timeouts,[p.IDLE_POLL,.75,.25])
        wire=Wire()
        with patch.object(p.time,'monotonic',side_effect=[0,.25,1.01]):
            with self.assertRaisesRegex(p.BoundaryError,'TRANSPORT_FAILURE'):
                p.receive(wire,idle_deadline=600,clock=lambda:0)
        wire=Wire();wire.parts=[b'']
        with self.assertRaisesRegex(p.BoundaryError,'TRANSPORT_FAILURE'):
            p.receive(wire,idle_deadline=600,clock=lambda:0)

    def case_identity(self):
        # B2 hashes protocol sources, not just copied runtime bounds.
        from test_privilege_policy_identity import PolicyIdentityCases
        with PolicyIdentityCases().fixture() as root:
            before=policy_hash();path=root/'privilege/protocol.py'
            text=path.read_text();self.assertIn('AUTHENTICATED_LIFETIME = 600.0',text)
            path.write_text(text.replace('AUTHENTICATED_LIFETIME = 600.0','AUTHENTICATED_LIFETIME = 599.0'))
            self.assertNotEqual(before,policy_hash())
        self.assertEqual(p.MAX_FRAME,16384);self.assertEqual(p.MAX_REQUESTS,128)
        self.assertEqual(p.MAX_RATE,32);self.assertEqual(p.MAX_CLIENTS,8)
