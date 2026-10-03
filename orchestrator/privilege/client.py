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
    def __init__(self, path, enrollment, server_uid, server_gid, *, linux_validation=False):
        if type(linux_validation) is not bool:raise p.BoundaryError('POLICY_REJECTED')
        self.mode='LINUX' if linux_validation is True else 'SIMULATED'
        if self.mode=='LINUX' and server_uid!=0:raise p.BoundaryError('PEER_NOT_ALLOWED')
        self.enrollment=enrollment
        self.channel=None;self.seq=0;self._handles=set();self._bindings={}
        try:
            validate_socket(path,server_uid,server_gid,parent_mode=0o750 if self.mode=='LINUX' else 0o700,socket_mode=0o660 if self.mode=='LINUX' else 0o600)
            channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.channel=channel
            channel.settimeout(p.TIMEOUT);channel.connect(str(path))
            if peer_credentials(channel)[1:]!=(server_uid,server_gid):raise p.BoundaryError('PEER_NOT_ALLOWED')
            greeting=p.validate_response(p.receive(channel),0)
            p.keys(greeting,('challenge',))
            if not p.identifier(greeting['challenge']):raise p.BoundaryError('INVALID_REQUEST')
            hello=self._rpc('HELLO',{'enrollment':enrollment.enrollment_id,'token':enrollment.token,
                                   'challenge':greeting['challenge'],'build':p.BUILD,'policy':policy_hash()})
            p.keys(hello,('build','policy','mode'))
            if hello!={'build':p.BUILD,'policy':policy_hash(),'mode':self.mode}:raise p.BoundaryError('POLICY_REJECTED')
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
                or value['mode']!=self.mode or value['enforcement']!='UNPROVEN'
                or value['cleanup'] not in (('CONFIRMED','UNPROVEN') if self.mode=='LINUX' else ('SIMULATED','UNPROVEN'))):raise p.BoundaryError('INVALID_REQUEST')
        from .policy import execution_class
        execution_class(value['class'],value['role'])
        return value

    def create_sandbox(self, slot, execution, role, *, limits=None):
        # Controller generates IDs; no task/model argument can supply run_id.
        resource_limits(execution,role,{} if limits is None else limits)
        run_id=secrets.token_hex(16)
        value=self._snapshot(self._rpc('CREATE',{'run_id':run_id,'slot':slot,
               'class':execution,'role':role,'limits':{} if limits is None else limits}))
        if value['class']!=execution or value['role']!=role:raise p.BoundaryError('INVALID_REQUEST')
        self._handles.add(value['handle'])
        self._bindings[value['handle']]={'run_id':run_id,'class':execution,'role':role}
        return Sandbox(value['handle'])

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
        return p.validate_probe(result,self.mode)

    def collect_synthetic(self,sandbox):
        if self.mode!='LINUX':raise p.BoundaryError('POLICY_REJECTED')
        handle=self._handle(sandbox)
        result=self._rpc('COLLECT',{'handle':handle})
        from .evidence import validate, BINDING, empty
        p.keys(result,tuple(empty({k:None for k in BINDING})))
        identity={k:result[k] for k in BINDING}
        expected={'handle':handle,'policy':policy_hash(),**self._bindings[handle]}
        if any(identity[k]!=v for k,v in expected.items()):raise p.BoundaryError('POLICY_REJECTED')
        return validate(result,identity)

    def collect_security(self,sandbox,expectation):
        """Retrieve one frozen B8 capture; never activate a collector/worker.

        The trusted controller supplies its expected registry/ownership binding.
        No raw cursor/file/path/PID API and no automatic retries or polling.
        """
        import hashlib
        import json
        import time
        from . import security_collection as c, security_proof as s
        if self.mode!='LINUX' or type(expectation) is not s.ProofExpectation:raise p.BoundaryError('POLICY_REJECTED')
        handle=self._handle(sandbox)
        expected={'handle':handle,'policy':policy_hash(),**self._bindings[handle]}
        if any(expectation.binding[k]!=v for k,v in expected.items()):raise p.BoundaryError('POLICY_REJECTED')
        if self.seq+1+c.MAX_PAGES>p.MAX_REQUESTS:raise p.BoundaryError('BOUNDS_EXCEEDED')
        started=time.monotonic_ns();meta=self._rpc('SECURITY_OPEN',{'handle':handle})
        p.keys(meta,c.META_FIELDS)
        if (type(meta['schema_version']) is not int or meta['schema_version']!=c.VERSION or meta['enforcement']!='UNPROVEN'
                or meta['binding']!=dict(expectation.binding) or not p.identifier(meta['snapshot'])
                or not p.identifier(meta['cursor']) or not p.identifier(meta['sha256'],64)
                or type(meta['pages']) is not int or not 1<=meta['pages']<=c.MAX_PAGES
                or type(meta['total_bytes']) is not int or not 1<=meta['total_bytes']<=s.MAX_BUFFER_BYTES
                or meta['pages']!=(meta['total_bytes']+c.PAGE_BYTES-1)//c.PAGE_BYTES):raise p.BoundaryError('INVALID_REQUEST')
        seen=getattr(self,'_security_seen',set())
        if meta['snapshot'] in seen:raise p.BoundaryError('INVALID_REQUEST')
        seen.add(meta['snapshot']);self._security_seen=seen  # <=128 bounded connection requests
        raw=bytearray();cursor=meta['cursor'];cursors={cursor}
        for index in range(meta['pages']):
            if time.monotonic_ns()-started>c.VIEW_NS:raise p.BoundaryError('TRANSPORT_FAILURE')
            page=self._rpc('SECURITY_PAGE',{'handle':handle,'snapshot':meta['snapshot'],'cursor':cursor})
            raw.extend(c.decode_page(page,meta,index,dict(expectation.binding)))
            if len(raw)>s.MAX_BUFFER_BYTES:raise p.BoundaryError('BOUNDS_EXCEEDED')
            cursor=page['next_cursor']
            if cursor is not None:
                if cursor in cursors:raise p.BoundaryError('INVALID_REQUEST')
                cursors.add(cursor)
        if time.monotonic_ns()-started>c.VIEW_NS or len(raw)!=meta['total_bytes'] or hashlib.sha256(raw).hexdigest()!=meta['sha256']:
            raise p.BoundaryError('INVALID_REQUEST')
        try:value=json.loads(raw,object_pairs_hook=p._pairs)
        except (ValueError,TypeError,UnicodeError,RecursionError):raise p.BoundaryError('INVALID_REQUEST') from None
        return c.validate_report(value,expectation)

    def begin_security_assessment(self,sandbox,expectation,prepared):
        """Freeze authenticated recording inputs; no launch or cleanup action."""
        from . import security_assembly as a, security_collection as c
        import time
        a.plan_value(prepared,expectation)
        pending=getattr(self,'_assessments',{})
        now=time.monotonic_ns()
        for key,v in list(pending.items()):
            if now>v[0].started_ns+c.VIEW_NS:pending.pop(key)
        handle=self._handle(sandbox)
        if handle in pending or len(pending)>=8:raise p.BoundaryError('BOUNDS_EXCEEDED')
        report=self.collect_security(sandbox,expectation)
        if any(v['value']['at_ns']>time.monotonic_ns() for v in report['observations']):raise p.BoundaryError('INVALID_REQUEST')
        seen=getattr(self,'_assessment_samples',set())
        sample=(handle,expectation.sample,expectation.subject)
        if sample in seen:raise p.BoundaryError('INVALID_REQUEST')
        seen.add(sample);self._assessment_samples=seen
        pending[handle]=(expectation,prepared,report);self._assessments=pending
        return a.assess(expectation,prepared,report)

    def finish_security_assessment(self,sandbox):
        """Final result requires authenticated ownership-bound release proof.

        STATUS is observer-only; caller must separately request normal cleanup.
        Pending input never becomes a kernel qualification certificate.
        """
        from . import security_assembly as a, security_collection as c
        import time
        handle=self._handle(sandbox);pending=getattr(self,'_assessments',{})
        value=pending.get(handle)
        if value is None:raise p.BoundaryError('INVALID_STATE')
        x,prepared,report=value
        if time.monotonic_ns()>x.started_ns+c.VIEW_NS:
            pending.pop(handle);raise p.BoundaryError('INVALID_STATE')
        status=self.status(sandbox)
        if (status['class'],status['role'])!=(x.binding['class'],x.binding['role']):raise p.BoundaryError('POLICY_REJECTED')
        confirmed=status['state']=='RELEASED' and status['cleanup']=='CONFIRMED' and status['mode']=='LINUX'
        result=a.assess(x,prepared,report,'CONFIRMED' if confirmed else 'UNPROVEN')
        if status['state']=='RELEASED':pending.pop(handle)
        return result

    def close(self):
        if self.channel is not None:self.channel.close();self.channel=None
        self._handles.clear();self._bindings.clear()
        if hasattr(self,'_security_seen'):self._security_seen.clear()
        if hasattr(self,'_assessments'):self._assessments.clear()
        if hasattr(self,'_assessment_samples'):self._assessment_samples.clear()
