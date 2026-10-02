"""Typed controller-only integration seam; no production runtime cutover."""
from dataclasses import dataclass
import secrets
import socket
from . import protocol as p
from .policy import policy_hash, resource_limits
from .security import peer_credentials, validate_socket


@dataclass(frozen=True)
class Sandbox:
    handle: str


class ControllerClient:
    def __init__(self, path, enrollment, server_uid, server_gid):
        self.enrollment=enrollment
        self.channel=None;self.seq=0;self._handles=set()
        try:
            validate_socket(path,server_uid,server_gid)
            channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.channel=channel
            channel.settimeout(p.TIMEOUT);channel.connect(str(path))
            if peer_credentials(channel)[1:]!=(server_uid,server_gid):raise p.BoundaryError('PEER_NOT_ALLOWED')
            greeting=p.validate_response(p.receive(channel),0)
            p.keys(greeting,('challenge',))
            if not p.identifier(greeting['challenge']):raise p.BoundaryError('INVALID_REQUEST')
            hello=self._rpc('HELLO',{'enrollment':enrollment.enrollment_id,'token':enrollment.token,
                                   'challenge':greeting['challenge'],'build':p.BUILD,'policy':policy_hash()})
            p.keys(hello,('build','policy','mode'))
            if hello!={'build':p.BUILD,'policy':policy_hash(),'mode':'SIMULATED'}:raise p.BoundaryError('POLICY_REJECTED')
        except p.BoundaryError:
            self.close();raise
        except OSError:
            self.close();raise p.BoundaryError('TRANSPORT_FAILURE') from None

    def _rpc(self, op, args):
        if self.channel is None:raise p.BoundaryError('TRANSPORT_FAILURE')
        self.seq+=1
        request=p.validate_request({'version':p.VERSION,'seq':self.seq,'op':op,'args':args})
        p.send(self.channel,request)
        return p.validate_response(p.receive(self.channel),self.seq)

    def _handle(self, sandbox):
        if type(sandbox) is not Sandbox or sandbox.handle not in self._handles:
            raise p.BoundaryError('UNKNOWN_HANDLE')
        return sandbox.handle

    def _snapshot(self, value):
        p.keys(value,('handle','state','class','role','mode','enforcement','cleanup'))
        if (not p.identifier(value['handle']) or any(type(value[k]) is not str for k in ('state','class','role','mode','enforcement','cleanup')) or value['state'] not in p.STATES
                or value['mode']!='SIMULATED' or value['enforcement']!='UNPROVEN'
                or value['cleanup'] not in ('SIMULATED','UNPROVEN')):raise p.BoundaryError('INVALID_REQUEST')
        from .policy import execution_class
        execution_class(value['class'],value['role'])
        return value

    def create_sandbox(self, slot, execution, role, *, limits=None):
        # Controller generates IDs; no task/model argument can supply run_id.
        resource_limits(execution,role,{} if limits is None else limits)
        value=self._snapshot(self._rpc('CREATE',{'run_id':secrets.token_hex(16),'slot':slot,
               'class':execution,'role':role,'limits':{} if limits is None else limits}))
        self._handles.add(value['handle']);return Sandbox(value['handle'])

    def _operation(self, op, sandbox):
        value=self._snapshot(self._rpc(op,{'handle':self._handle(sandbox)}))
        if value['handle']!=sandbox.handle:raise p.BoundaryError('INVALID_REQUEST')
        return value

    def start_sandbox(self, sandbox):return self._operation('START',sandbox)
    def status(self, sandbox):return self._operation('STATUS',sandbox)
    def terminate(self, sandbox):return self._operation('TERMINATE',sandbox)
    def release(self, sandbox):return self._operation('RELEASE',sandbox)
    def probe(self):
        result=self._rpc('PROBE',{'probe':'BOUNDARY_V1'})
        if result!={'mode':'SIMULATED','enforcement':'UNPROVEN'}:raise p.BoundaryError('INVALID_REQUEST')
        return result

    def close(self):
        if self.channel is not None:self.channel.close();self.channel=None
        self._handles.clear()
