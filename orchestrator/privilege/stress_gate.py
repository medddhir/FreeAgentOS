"""B8 recording-only stress preparation. No executable or gate FD is activated.

B6 must provide an owner-approved campaign verifier, durable attempt accounting,
artifact provenance and independent containment observations before a real
launcher integration can exist. Linux authentication is not that authority.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from .linux import secure_open
from types import MappingProxyType
from . import protocol as p, security_proof as s
from .evidence import binding
from .policy import policy_hash
from .recording import RecordingDriver

FIXTURE_SHA256='75ecfc5404dbf831f2c9ba3b6ae6fa6e53ddb53172dd52f5997e6ff0228293fe'
SELECTORS=('cpu','memory','pids')

def verify_fixture():
    root=os.open(Path(__file__).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fd=secure_open(root,'fixtures/security_probe.c')
        try:raw=os.read(fd,16385)
        finally:os.close(fd)
    except OSError:raise p.BoundaryError('POLICY_REJECTED') from None
    finally:os.close(root)
    if len(raw)>16384 or hashlib.sha256(raw).hexdigest()!=FIXTURE_SHA256:
        raise p.BoundaryError('POLICY_REJECTED')
    return FIXTURE_SHA256
PRECONDITIONS=('OWNED_CGROUP','OWNED_PIDFD','IDENTITY_AND_CAPABILITY_DROP','PRIVATE_ROOTFS')

@dataclass(frozen=True)
class RecordingApproval:
    """Test-only authorization, deliberately not accepted by any real driver.

    Constructed by deterministic test controller, never RPC/config/model input.
    A matching object is not proof of owner approval or kernel enforcement.
    """
    identity: object
    selector: str
    seal: str
    def __post_init__(self):
        from .evidence import validate_binding
        validate_binding(dict(self.identity))
        if self.selector not in SELECTORS or not p.identifier(self.seal,64):raise p.BoundaryError('POLICY_REJECTED')
        object.__setattr__(self,'identity',MappingProxyType(dict(self.identity)))

@dataclass(frozen=True)
class PreparedProbe:
    payload: bytes
    digest: str


def prepare(record,entry,source,expectation,selector,approval,preconditions,driver):
    # No bool/config flag can turn a Linux driver into an approved campaign.
    if type(driver) is not RecordingDriver or type(approval) is not RecordingApproval:
        raise p.BoundaryError('POLICY_REJECTED')
    if type(expectation) is not s.ProofExpectation or selector not in SELECTORS:
        raise p.BoundaryError('POLICY_REJECTED')
    identity=binding(record,entry)
    if (not entry.validation or record['state']!='CREATED' or identity['policy']!=policy_hash()
            or dict(expectation.binding)!=identity or dict(approval.identity)!=identity
            or approval.selector!=selector or approval.seal!=source.seal.verification_sha256
            or type(preconditions) is not dict or set(preconditions)!=set(PRECONDITIONS)
            or any(v!='INDEPENDENT_RECORDING' for v in preconditions.values())):
        raise p.BoundaryError('POLICY_REJECTED')
    # Revalidate pinned artifact; original CREATE snapshot ingestion remains the
    # only authority for sealed bytes. No path or argv supplied by a caller.
    fixture_digest=verify_fixture()
    entry.verify()
    proof=driver.prove(record)
    if proof!={'scope':True,'root':True}:raise p.BoundaryError('CLEANUP_INCOMPLETE')
    plan=s.probe_plan(expectation,selector)
    plan.update(seal=approval.seal,fixture_source_sha256=fixture_digest,authorization='RECORDING_ONLY',enforcement='UNPROVEN',
                containment=dict(preconditions),execution_enabled=False)
    raw=json.dumps(plan,sort_keys=True,separators=(',',':')).encode()
    if len(raw)>4096:raise p.BoundaryError('BOUNDS_EXCEEDED')
    return PreparedProbe(raw,hashlib.sha256(raw).hexdigest())


def deliver(prepared,expected,driver):
    """Recording launch-preparation sink, never a real child launcher.

    Compare the complete checked envelope, not just a copied selector/argv.
    No descriptor allocation, process creation or stress gate write exists.
    """
    if (type(driver) is not RecordingDriver or type(prepared) is not PreparedProbe
            or type(expected) is not PreparedProbe or prepared!=expected
            or len(prepared.payload)>4096 or hashlib.sha256(prepared.payload).hexdigest()!=prepared.digest):
        raise p.BoundaryError('POLICY_REJECTED')
    driver._step(None,'STRESS_PREPARATION_RECORDING')
    return prepared.payload
