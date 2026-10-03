"""B6 recording-only owner contract and durable one-attempt gate.

No approval issuer, activation, RPC, campaign runner or reset API. Production
owner approval requires separately reviewed root-protected installation and
B9/B10/B12 prerequisites; no real approval can be consumed by this adapter.
"""
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time
from types import MappingProxyType
from . import protocol as p
from .policy import policy_hash
from .security import directory_fd
from .stress_gate import PreparedProbe, FIXTURE_SHA256

VERSION=1
MAX_BYTES=8192
MAX_VALIDITY_SECONDS=3600
DIGESTS=('policy','package_sha256','runtime_sha256','executable_sha256','fixture_source_sha256',
         'build_recipe_sha256','toolchain_sha256','build_provenance_sha256','installation_sha256',
         'qualified_target_sha256','action_plan_sha256','rollback_plan_sha256','inventory_sha256')
IDS=('campaign','owner','enrollment')
FIELDS=('version','mode','source_commit','valid_from','valid_until','probe_plans',*IDS,*DIGESTS)


def canonical(value):
    try:raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
    except (ValueError,TypeError,RecursionError):raise p.BoundaryError('JOURNAL_INVALID') from None
    if len(raw)>MAX_BYTES:raise p.BoundaryError('BOUNDS_EXCEEDED')
    return raw


def validate_contract(value):
    p.keys(value,FIELDS)
    if (type(value['version']) is not int or value['version']!=VERSION or value['mode'] not in ('RECORDING_ONLY','REAL_VALIDATION')
            or not p.identifier(value['source_commit'],40) or any(not p.identifier(value[k]) for k in IDS)
            or any(not p.identifier(value[k],64) for k in DIGESTS)
            or value['fixture_source_sha256']!=FIXTURE_SHA256 or value['policy']!=policy_hash()
            or any(type(value[k]) is not int or not 0<=value[k]<2**63 for k in ('valid_from','valid_until'))
            or not 0<value['valid_until']-value['valid_from']<=MAX_VALIDITY_SECONDS):
        raise p.BoundaryError('POLICY_REJECTED')
    p.keys(value['probe_plans'],('cpu','memory','pids'))
    if any(not p.identifier(v,64) for v in value['probe_plans'].values()) or len(set(value['probe_plans'].values()))!=3:raise p.BoundaryError('POLICY_REJECTED')
    canonical(value)
    return value

@dataclass(frozen=True)
class RecordingAttempt:
    campaign: str
    installation: str
    contract_sha256: str
    claim: str
    probe_plans: object
    execution_enabled: bool=False


class RecordingCampaignGuard:
    """Temporary unprivileged adapter; never usable by a Linux stress launcher.

    Expected contract comes from deterministic reviewed policy, not RPC input.
    Private same-UID storage models future root-owned administrator storage; it
    cannot defend against malicious code running as the storage owner/root.
    """
    def __init__(self,directory,expected,*,clock=time.time):
        validate_contract(expected)
        if expected['mode']!='RECORDING_ONLY':raise p.BoundaryError('POLICY_REJECTED')
        self.expected=json.loads(canonical(expected));self.digest=hashlib.sha256(canonical(expected)).hexdigest()
        self.path=Path(directory);self.uid=os.getuid();self.gid=os.getgid();self.clock=clock
        self.fd=None;self.lock_fd=None;self.blocked=False;self.closed=False;self.issued=None
        try:
            self.fd=directory_fd(self.path,self.uid);self.parent=os.fstat(self.fd)
            self.lock_fd=os.open('campaign.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,0o600,dir_fd=self.fd)
            self.lock_info=self._private(self.lock_fd)
            try:fcntl.flock(self.lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise p.BoundaryError('SOCKET_BUSY') from None
            os.fsync(self.lock_fd);os.fsync(self.fd)
            self._check();self.approval,self.approval_info=self._read('approval.json')
            p.keys(self.approval,('version','owner_review','contract','storage'))
            p.keys(self.approval['storage'],('device','inode','uid','gid'))
            storage={'device':self.parent.st_dev,'inode':self.parent.st_ino,'uid':self.uid,'gid':self.gid}
            if self.approval['storage']!=storage or any(type(v) is not int for v in self.approval['storage'].values()):raise p.BoundaryError('POLICY_REJECTED')
            if (type(self.approval['version']) is not int or self.approval['version']!=VERSION
                    or not p.identifier(self.approval['owner_review']) or self.approval['contract']!=self.expected):
                raise p.BoundaryError('POLICY_REJECTED')
        except BaseException as error:
            self.close()
            if isinstance(error,p.BoundaryError) or not isinstance(error,Exception):raise
            raise p.BoundaryError('JOURNAL_INVALID') from None

    @staticmethod
    def _identity(info):return (info.st_dev,info.st_ino,info.st_ctime_ns,info.st_size)

    def _private(self,fd):
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=self.uid or info.st_gid!=self.gid
                or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>MAX_BYTES):
            raise p.BoundaryError('JOURNAL_INVALID')
        return info

    def _check(self):
        if self.closed:raise p.BoundaryError('INVALID_STATE')
        check=directory_fd(self.path,self.uid)
        try:
            if (os.fstat(check).st_dev,os.fstat(check).st_ino)!=(self.parent.st_dev,self.parent.st_ino):raise p.BoundaryError('JOURNAL_INVALID')
            held=self._private(self.lock_fd);named=os.stat('campaign.lock',dir_fd=self.fd,follow_symlinks=False)
            if self._identity(held)!=self._identity(named) or self._identity(held)!=self._identity(self.lock_info):raise p.BoundaryError('JOURNAL_INVALID')
        finally:os.close(check)

    def _read(self,name):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
        try:
            info=self._private(fd);raw=os.read(fd,MAX_BYTES+1);after=self._private(fd)
            named=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            if len(raw)!=info.st_size or len(raw)>MAX_BYTES or self._identity(info)!=self._identity(after) or self._identity(info)!=self._identity(named):raise p.BoundaryError('JOURNAL_INVALID')
            try:value=json.loads(raw,object_pairs_hook=p._pairs)
            except (ValueError,UnicodeError,RecursionError):raise p.BoundaryError('JOURNAL_INVALID') from None
            return value,info
        finally:os.close(fd)

    def _exists(self,name):
        try:os.stat(name,dir_fd=self.fd,follow_symlinks=False);return True
        except FileNotFoundError:return False

    def _persist(self,name,value):
        # Atomic exclusive slot allocation is the point of no automatic retry.
        # Append-only: partial writes remain evidence; no replace/unlink/reset.
        raw=canonical(value)
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            os.fsync(self.fd)  # durable intent before writing/consuming authority
            view=memoryview(raw)
            while view:
                count=os.write(fd,view)
                if count<=0:raise p.BoundaryError('BACKEND_FAILURE')
                view=view[count:]
            os.fsync(fd);os.fsync(self.fd)
            info=self._private(fd);named=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            if self._identity(info)!=self._identity(named):raise p.BoundaryError('JOURNAL_INVALID')
        finally:os.close(fd)

    def _authority(self):
        validate_contract(self.expected)
        self._check();approval,info=self._read('approval.json')
        if (approval!=self.approval or approval['contract']!=self.expected
                or hashlib.sha256(canonical(self.expected)).hexdigest()!=self.digest
                or self._identity(info)!=self._identity(self.approval_info)):raise p.BoundaryError('POLICY_REJECTED')
        now=self.clock()
        if not self.expected['valid_from']<=now<self.expected['valid_until']:raise p.BoundaryError('POLICY_REJECTED')

    def claim(self):
        """Reserve and consume before returning any recording campaign context."""
        if self.blocked:raise p.BoundaryError('RECOVERY_REQUIRED')
        try:
            self._authority()
            if self._exists('reserved.json') or self._exists('consumed.json'):raise p.BoundaryError('RECOVERY_REQUIRED')
            base={'version':VERSION,'campaign':self.expected['campaign'],'installation':self.expected['installation_sha256'],
                  'contract_sha256':self.digest,'claim':secrets.token_hex(16)}
            self._persist('reserved.json',{**base,'state':'RESERVED'})
            self._authority()
            _,reserved_info=self._read('reserved.json')
            self._persist('consumed.json',{**base,'state':'CONSUMED','reservation_identity':list(self._identity(reserved_info))})
            self._authority();self._state()  # validate exact pair before returning
            self.blocked=True
            self.issued=RecordingAttempt(base['campaign'],base['installation'],self.digest,base['claim'],MappingProxyType(dict(self.expected['probe_plans'])))
            return self.issued
        except BaseException as error:
            self.blocked=True
            if isinstance(error,p.BoundaryError) or not isinstance(error,Exception):raise
            raise p.BoundaryError('RECOVERY_REQUIRED') from None

    def _state(self):
        values=[];reserved_identity=None
        for name,state in (('reserved.json','RESERVED'),('consumed.json','CONSUMED')):
            if not self._exists(name):continue
            value,info=self._read(name);p.keys(value,('version','campaign','installation','contract_sha256','claim','state'),('reservation_identity',) if state=='CONSUMED' else ())
            if state=='RESERVED':reserved_identity=list(self._identity(info))
            elif (type(value.get('reservation_identity')) is not list or len(value['reservation_identity'])!=4
                    or any(type(v) is not int or not 0<=v<2**64 for v in value['reservation_identity'])
                    or value['reservation_identity']!=reserved_identity or reserved_identity is None):raise p.BoundaryError('JOURNAL_INVALID')
            if (type(value['version']) is not int or value['version']!=VERSION or value['state']!=state
                    or value['campaign']!=self.expected['campaign'] or value['installation']!=self.expected['installation_sha256']
                    or value['contract_sha256']!=self.digest or not p.identifier(value['claim'])):
                raise p.BoundaryError('JOURNAL_INVALID')
            values.append(value)
        if not values or values[0]['state']!='RESERVED' or len(values)==2 and values[0]['claim']!=values[1]['claim']:
            raise p.BoundaryError('RECOVERY_REQUIRED')
        return values[-1]

    def cleanup_context(self):
        """Read-only identity for later scoped cleanup, NEVER another attempt."""
        try:
            self._check();state=self._state()
            return {'campaign':state['campaign'],'installation':state['installation'],'claim':state['claim'],
                    'attempt_state':state['state'],'execution_enabled':False,'retry_authorized':False}
        except Exception as error:
            if isinstance(error,p.BoundaryError):raise
            raise p.BoundaryError('RECOVERY_REQUIRED') from None

    def recording_probe(self,attempt,prepared,expectation,driver):
        try:return self._recording_probe(attempt,prepared,expectation,driver)
        except BaseException as error:
            self.issued=None  # failure stops this recording campaign, not a retry
            if isinstance(error,p.BoundaryError) or not isinstance(error,Exception):raise
            raise p.BoundaryError('RECOVERY_REQUIRED') from None

    def _recording_probe(self,attempt,prepared,expectation,driver):
        """Consumed guard -> fixed B8 recording adapter; never real stress launch."""
        from .recording import RecordingDriver
        from .stress_gate import deliver
        if attempt is not self.issued or type(attempt) is not RecordingAttempt or type(prepared) is not PreparedProbe or type(driver) is not RecordingDriver:
            raise p.BoundaryError('POLICY_REJECTED')
        from .security_assembly import plan_value
        plan,selector=plan_value(prepared,expectation)
        if (plan['binding']['owner']!=self.expected['owner'] or plan['binding']['policy']!=self.expected['policy']
                or plan['binding']['executable_sha256']!=self.expected['executable_sha256']):raise p.BoundaryError('POLICY_REJECTED')
        self._authority();state=self._state()
        if (state['state']!='CONSUMED' or attempt.execution_enabled is not False
                or (attempt.campaign,attempt.installation,attempt.contract_sha256,attempt.claim)!=
                   (state['campaign'],state['installation'],self.digest,state['claim'])
                or dict(attempt.probe_plans)!=self.expected['probe_plans'] or prepared.digest not in attempt.probe_plans.values()):
            raise p.BoundaryError('POLICY_REJECTED')
        if attempt.probe_plans[selector]!=prepared.digest:raise p.BoundaryError('POLICY_REJECTED')
        try:
            self._persist('probe-'+selector+'.json',{'version':VERSION,'campaign':attempt.campaign,
                          'contract_sha256':self.digest,'claim':attempt.claim,'plan_sha256':prepared.digest})
            return deliver(prepared,prepared,driver)
        except Exception as error:
            if isinstance(error,p.BoundaryError):raise
            raise p.BoundaryError('RECOVERY_REQUIRED') from None

    def close(self):
        self.closed=True;self.issued=None
        failure=False
        for name in ('lock_fd','fd'):
            fd=getattr(self,name,None)
            if fd is not None:
                setattr(self,name,None)
                try:os.close(fd)
                except OSError:failure=True
        if failure:raise p.BoundaryError('CLEANUP_INCOMPLETE')
