"""Identity provenance boundary, independent of selection and authorization.

The installed Anthropic gateway exposes dispatch headers, but Claude Code does
not forward them through our NDJSON interface. The optional private gateway
channel is controller-only. Never ingest worker/model claims as gateway evidence.
"""
from roles.model_profiles import REGISTRY, requested_identity

# Vocabulary for evidence strength, not assertions that these channels exist.
EVIDENCE_LEVELS = ("REQUESTED_CONFIG", "ROUTER_DISPATCH", "UPSTREAM_REPORTED", "UNAVAILABLE")


def _unavailable(profile):
    return {"requested_profile_id": profile.profile_id, "adapter_id": profile.adapter_id,
            "requested_model_id": profile.model_id or (
                "NOT_APPLICABLE" if profile.roles == frozenset(("researcher",)) else "CLIENT_DEFAULT"),
            "requested_evidence": "REQUESTED_CONFIG",
            "routed_provider_id": "UNAVAILABLE", "routed_model_id": "UNAVAILABLE",
            "routed_evidence": "UNAVAILABLE", "served_model_id": "UNAVAILABLE",
            "served_evidence": "UNAVAILABLE",
            "attribution_status": "GATEWAY_SESSION_BINDING_UNAVAILABLE"}


def attribution_for(role):
    """Derive requested identity from controller scope; do not read transport."""
    identity = requested_identity(role)
    return _unavailable(REGISTRY[identity["model_profile_id"]])


def safe_attribution(value):
    """Project only implemented provenance. No echoed/claimed route is trusted.

    Future request-bound gateway instrumentation needs its own authenticated
    ingestion boundary; syntax or an evidence label cannot grant provenance.
    """
    if not isinstance(value, dict) or not isinstance(value.get("requested_profile_id"), str):
        return {}
    profile = REGISTRY.get(value["requested_profile_id"])
    if profile is None:
        return {}
    expected = _unavailable(profile)
    return expected if all(value.get(key) == item for key, item in expected.items()) else {}

# Controller-only channel; deliberately separate from requested-model identity.
import contextvars
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
from contextlib import contextmanager

SOCKET = '/run/freeagentos-attribution/gateway.sock'
GATEWAY_UID = 1000
_transport = contextvars.ContextVar('gateway_attribution_transport', default=None)
_ID = re.compile(r'[a-f0-9]{32}')
_TAG = re.compile(r'[a-f0-9]{64}')
_IDENTIFIER = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}')


def _identifier(value):
    return (isinstance(value,str) and _IDENTIFIER.fullmatch(value) is not None
            and '://' not in value and re.search(r'bearer|secret|token|password|^sk-|^gsk_',value,re.I) is None)


def route_observation(payload, session_id):
    """Only call for a response read from the verified private gateway peer.

    This validates structure, not origin. Model stdout is never an input here.
    """
    unavailable={'routed_provider_id':'UNAVAILABLE','routed_model_id':'UNAVAILABLE',
                 'routed_evidence':'UNAVAILABLE','route_status':'UNAVAILABLE','routes':[]}
    if (not isinstance(payload,dict) or payload.get('status')!='COMPLETE'
            or type(payload.get('version')) is not int or payload.get('version')!=1 or payload.get('session_id')!=session_id):
        return unavailable
    requests=payload.get('requests');count=payload.get('request_count')
    if (not isinstance(requests,list) or type(count) is not int or not 1<=count<=64
            or count!=len(requests)):
        return unavailable
    routes=set()
    for i,request in enumerate(requests,1):
        if (not isinstance(request,dict) or type(request.get('ordinal')) is not int or request.get('ordinal')!=i or request.get('closed') is not True
                or not isinstance(request.get('attempts'),list) or not 1<=len(request['attempts'])<=16):
            return unavailable
        previous=0
        for attempt in request['attempts']:
            if not isinstance(attempt,dict): return unavailable
            ordinal=attempt.get('ordinal');provider=attempt.get('provider_id');model=attempt.get('model_id')
            if (type(ordinal) is not int or not previous<ordinal<=65535
                    or attempt.get('outcome') not in ('COMPLETED','COMMITTED','FAILED','CANCELED')
                    or not _identifier(provider) or not _identifier(model)):
                return unavailable
            previous=ordinal;routes.add((provider,model))
            if len(routes)>32: return unavailable
    pairs=[{'provider_id':p,'model_id':m} for p,m in sorted(routes)]
    single=len(pairs)==1
    return {'routed_provider_id':pairs[0]['provider_id'] if single else 'UNAVAILABLE',
            'routed_model_id':pairs[0]['model_id'] if single else 'UNAVAILABLE',
            'routed_evidence':'ROUTER_DISPATCH',
            'route_status':'SINGLE_ROUTE' if single else 'MULTIPLE_ROUTES','routes':pairs}


class GatewaySession:
    """No retry or execution dependency; private IPC failures only lose evidence."""
    def __init__(self,path=SOCKET,uid=GATEWAY_UID):
        self.path=Path(path);self.uid=uid;self.session_id=secrets.token_hex(16);self.token=None

    def _exchange(self,op):
        parent=self.path.parent.lstat();info=self.path.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=self.uid or stat.S_IMODE(parent.st_mode)!=0o700
                or not stat.S_ISSOCK(info.st_mode) or info.st_uid!=self.uid or stat.S_IMODE(info.st_mode)!=0o600):
            raise ValueError('ATTRIBUTION_PEER_INVALID')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
            channel.settimeout(0.25);channel.connect(str(self.path))
            import struct
            pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid!=self.uid: raise ValueError('ATTRIBUTION_PEER_INVALID')
            channel.sendall(json.dumps({'op':op,'session_id':self.session_id},separators=(',',':')).encode()+b'\n')
            raw=bytearray()
            while not raw.endswith(b'\n'):
                chunk=channel.recv(16385-len(raw))
                if not chunk or len(raw)+len(chunk)>16384: raise ValueError('ATTRIBUTION_BOUNDS')
                raw.extend(chunk)
            return json.loads(raw)

    def begin(self):
        try:
            result=self._exchange('register')
            if result.get('status')=='REGISTERED' and isinstance(result.get('token'),str) and _TAG.fullmatch(result['token']):
                self.token=result['token']
        except Exception: pass

    def finish(self):
        try:
            payload=self._exchange('finish')
            return route_observation(payload if self.token else None,self.session_id)
        except Exception: return route_observation(None,self.session_id)
        finally: self.token=None

    @contextmanager
    def scope(self):
        token=_transport.set({'session_id':self.session_id,'token':self.token} if self.token else None)
        try: yield
        finally: _transport.reset(token)


def current_transport():
    value=_transport.get()
    return dict(value) if value else None


def transport_environment(transport):
    """Reserved transport headers override inherited aliases, never prompts."""
    environment=dict(os.environ)
    if (not isinstance(transport,dict) or not isinstance(transport.get('session_id'),str)
            or not _ID.fullmatch(transport['session_id']) or not isinstance(transport.get('token'),str)
            or not _TAG.fullmatch(transport['token'])):
        return environment
    headers=[]
    for line in environment.get('ANTHROPIC_CUSTOM_HEADERS','').splitlines():
        name=line.partition(':')[0].strip().lower()
        if name not in ('x-freeagentos-attribution-session','x-freeagentos-attribution-token'):
            headers.append(line)
    headers.extend(['X-FreeAgentOS-Attribution-Session: '+transport['session_id'],
                    'X-FreeAgentOS-Attribution-Token: '+transport['token']])
    environment['ANTHROPIC_CUSTOM_HEADERS']='\n'.join(headers)
    return environment


def safe_gateway_observation(value):
    """Output whitelist, NOT an attestation API; source is the outer controller."""
    empty=route_observation(None,'')
    if not isinstance(value,dict) or value.get('routed_evidence')!='ROUTER_DISPATCH': return empty
    pairs=value.get('routes')
    if not isinstance(pairs,list) or not 1<=len(pairs)<=32: return empty
    normalized=[]
    for pair in pairs:
        if not isinstance(pair,dict) or not _identifier(pair.get('provider_id')) or not _identifier(pair.get('model_id')): return empty
        normalized.append({'provider_id':pair['provider_id'],'model_id':pair['model_id']})
    if len({(p['provider_id'],p['model_id']) for p in normalized})!=len(normalized): return empty
    single=len(normalized)==1
    expected={'routed_evidence':'ROUTER_DISPATCH','routes':normalized,
              'route_status':'SINGLE_ROUTE' if single else 'MULTIPLE_ROUTES',
              'routed_provider_id':normalized[0]['provider_id'] if single else 'UNAVAILABLE',
              'routed_model_id':normalized[0]['model_id'] if single else 'UNAVAILABLE'}
    return expected if all(value.get(key)==item for key,item in expected.items()) else empty
