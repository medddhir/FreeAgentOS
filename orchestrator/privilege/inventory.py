"""B10 fixed installation inventory, temporary staging only; no installer/removal.

Plans extend validation.bundle_manifest. Staging observations are not installed
root identities, approval, enforcement or cleanup proof. No credential bytes are
read, hashed, returned or exported. No production adapter exists.
"""
import hashlib
import json
import os
import stat
from pathlib import Path
from . import protocol as p
from .policy import policy_hash
from .policy_sources import AUTHORITATIVE, PRIVILEGE_SOURCES, _source_root, _read_source
from .security import directory_fd
from .validation import bundle_manifest

VERSION=1
MAX_ENTRIES=192  # fixed rollback audit family adds 42 entries to the prior 98
MAX_FILE=4*1024*1024
MAX_TOTAL=32*1024*1024
MAX_RECORD=256*1024
BINDING=('installation','enrollment','owner','source_commit','policy','package_sha256','runtime_sha256')
PROVENANCE=('synthetic_sha256','security_probe_sha256','fixture_source_sha256','synthetic_source_sha256',
            'compiler_sha256','build_recipe_sha256','build_record_sha256','launcher_sha256')


def encode(value):
    try:raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
    except (ValueError,TypeError,RecursionError):raise p.BoundaryError('JOURNAL_INVALID') from None
    if len(raw)>MAX_RECORD:raise p.BoundaryError('BOUNDS_EXCEEDED')
    return raw


def digest(value):return hashlib.sha256(encode(value)).hexdigest()


def _fixture(name):
    # Fixed bundled resources only, not an arbitrary caller path.
    root=os.open(Path(__file__).parent/'fixtures',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=root)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not 0<info.st_size<=MAX_FILE:raise p.BoundaryError('POLICY_REJECTED')
            raw=os.read(fd,MAX_FILE+1)
            if (_identity(os.fstat(fd))!=_identity(info) or len(raw)!=info.st_size
                    or _identity(os.stat(name,dir_fd=root,follow_symlinks=False))!=_identity(info)):raise p.BoundaryError('POLICY_REJECTED')
            return hashlib.sha256(raw).hexdigest()
        finally:os.close(fd)
    finally:os.close(root)


def prepare(binding,provenance,dynamic=()):
    p.keys(binding,BINDING);p.keys(provenance,PROVENANCE)
    if (any(not p.identifier(binding[k],40 if k=='source_commit' else 32 if k in ('installation','enrollment','owner') else 64) for k in BINDING)
            or any(not p.identifier(v,64) for v in provenance.values()) or binding['policy']!=policy_hash()
            or provenance['fixture_source_sha256']!=_fixture('security_probe.c')
            or provenance['synthetic_source_sha256']!=_fixture('synthetic_worker.c')):raise p.BoundaryError('POLICY_REJECTED')
    manifest=bundle_manifest(binding['package_sha256'],binding['runtime_sha256'],provenance['synthetic_sha256'])
    entries=[]
    def add(target,kind,mode,category,sha=None,staged=True,applicability="REQUIRED"):
        limit=8192 if target.startswith(('RECOVERY_ROOT/','CAMPAIGN_ROOT/')) else 2048 if target.endswith(('supervisor.sock.owner.json','supervisor.sock.pending')) else 65 if category=='CREDENTIAL' else 65536 if target.startswith('OWNED_B8/') else 2048 if target.startswith('OWNED_B7/') else 8192 if target.endswith(('/approval.json','/reserved.json','/consumed.json')) else 262144 if target.endswith(('/resources.json','/state.json','/inventory.json','/receipt.json')) else 262144 if '/pending-' in target else MAX_FILE
        entries.append({'slot':format(len(entries),'03d'),'target':target,'type':kind,'mode':mode,
                        'category':category,'applicability':applicability,'sha256':sha,'staged':staged,'max_bytes':limit,'installed_uid':'ENROLLED_UID' if target.startswith('ENROLLED_PRIVATE_CLIENT/') else 0,'installed_gid':'ENROLLED_GID' if target.startswith('/run/') or target.startswith('ENROLLED_PRIVATE_CLIENT/') else 0})
    for item in manifest['entries']:
        source=item['source'];kind='directory' if source.endswith('directory') or source in ('package','runtime','kernel-delegated-domain') else 'file'
        category='CREDENTIAL' if source=='private-token' else 'RUNTIME' if source=='kernel-delegated-domain' else 'RETAINED' if source in ('state-directory','resource-journal-directory','control-journal-directory') else 'IMMUTABLE'
        add(item['target'],kind,item['mode'],category,item['sha256'] if kind=='file' else None,source!='kernel-delegated-domain')
    add('/etc/freeagentos-stage31d/verification.json','file',0o600,'RETAINED')
    add('/etc/freeagentos-stage31d/install-manifest.json','file',0o600,'RETAINED')
    add('/var/lib/freeagentos-stage31d/input','directory',0o700,'RUNTIME',staged=False)
    add('/opt/freeagentos-supervisor/venv/bin/python','file',0o755,'IMMUTABLE',provenance['launcher_sha256'])
    add('/opt/freeagentos-supervisor/runtime/bin/security-probe','file',0o755,'IMMUTABLE',provenance['security_probe_sha256'])
    for name,key in (('security_probe.c','fixture_source_sha256'),('synthetic_worker.c','synthetic_source_sha256')):
        add('/opt/freeagentos-supervisor/fixtures/'+name,'file',0o644,'IMMUTABLE',provenance[key])
    for name,key in (('compiler.identity','compiler_sha256'),('build.recipe','build_recipe_sha256'),('build.record','build_record_sha256')):
        add('/opt/freeagentos-supervisor/provenance/'+name,'file',0o600,'IMMUTABLE',provenance[key])
    fd=os.open(_source_root(),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for name in (*AUTHORITATIVE,*PRIVILEGE_SOURCES):
            raw=_read_source(fd,name)
            add('/opt/freeagentos-supervisor/package/orchestrator/'+name,'file',0o644,'IMMUTABLE',hashlib.sha256(raw).hexdigest())
    finally:os.close(fd)
    # Logical client location is enrolled private storage, never caller paths.
    add('ENROLLED_PRIVATE_CLIENT/token','file',0o600,'CREDENTIAL')
    for name,kind,mode,category,staged in (
        ('supervisor.sock','socket',0o660,'RUNTIME',False),('supervisor.sock.lock','file',0o600,'RUNTIME',True),
        ('supervisor.sock.owner.json','file',0o600,'RETAINED',True),('supervisor.sock.pending','file',0o600,'RETAINED',False),
        ('supervisor.sock.retired','socket',0o660,'RUNTIME',False)):
        add('/run/freeagentos-stage31d/'+name,kind,mode,category,staged=staged)
    # Logical protected roots are registered by the future installation, not RPC paths.
    for name in ('approval.json','campaign.lock','reserved.json','consumed.json'):
        add('CAMPAIGN_ROOT/'+name,'file',0o600,'RETAINED',applicability='CONDITIONAL' if name in ('reserved.json','consumed.json') else 'REQUIRED')
    for selector in ('cpu','memory','pids'):
        add('CAMPAIGN_ROOT/probe-'+selector+'.json','file',0o600,'RETAINED',applicability='CONDITIONAL')
    for round_id in range(3):
        for name in ([f'rollback-{round_id}.json',f'rollback-{round_id}-result.json']+
                     [f'rollback-{round_id}-action-{action}.json' for action in range(12)]):
            add('RECOVERY_ROOT/'+name,'file',0o600,'RETAINED',applicability='CONDITIONAL')
    for target in ('/var/lib/freeagentos-stage31d/journal/resources.json',
                   '/var/lib/freeagentos-stage31d/control/state.json'):
        add(target,'file',0o600,'RETAINED')
    for name in ('inventory.json','receipt.json','receipt.lock','receipt.pending'):
        add('INVENTORY_ROOT/'+name,'file',0o600,'RETAINED',applicability='CONDITIONAL')
    # B7/B8 capture is owned in-memory state; no existing persistence pathname.
    for n in range(3):
        add('OWNED_B7/'+str(n),'file',0o600,'RETAINED',staged=False,applicability='CONDITIONAL')
        add('OWNED_B8/'+str(n),'file',0o600,'RETAINED',staged=False,applicability='CONDITIONAL')
    # Only the two existing journal atomic-write families admit variable names.
    if type(dynamic) not in (list,tuple) or len(dynamic)>MAX_ENTRIES or any(type(v) is not str for v in dynamic) or len(set(dynamic))!=len(dynamic):raise p.BoundaryError('BOUNDS_EXCEEDED')
    for member in dynamic:
        import re
        if type(member) is not str or re.fullmatch(r'(journal|control)/pending-[0-9a-f]{32}',member) is None:raise p.BoundaryError('PATH_REJECTED')
        add('/var/lib/freeagentos-stage31d/'+member,'file',0o600,'RETAINED')
    for n in range(3):
        # Runtime ledger IDs supply eventual identity; labels do not prove absence.
        add('OWNED_SCOPE/'+str(n),'directory',0o700,'RUNTIME',staged=False)
        add('OWNED_ROOT/'+str(n),'directory',0o700,'RUNTIME',staged=False)
    if len(entries)>MAX_ENTRIES:raise p.BoundaryError('BOUNDS_EXCEEDED')
    return {'version':VERSION,'kind':'PLANNED','binding':dict(binding),'provenance':dict(provenance),
            'entries':entries,'dynamic':list(dynamic),'authority':False,'qualifying':False,'build_reproducible':'UNPROVEN',
            'evidence_limits':{'campaign_records':3,'rollback_files':42,'capture_bytes':65536,'resource_journal_bytes':262144}}


def validate_plan(plan):
    p.keys(plan,('version','kind','binding','provenance','entries','dynamic','authority','qualifying','build_reproducible','evidence_limits'))
    expected=prepare(plan['binding'],plan['provenance'],plan['dynamic'])
    if encode(plan)!=encode(expected):raise p.BoundaryError('POLICY_REJECTED')
    return digest(plan)


def _identity(info):
    return {'device':info.st_dev,'inode':info.st_ino,'ctime_ns':info.st_ctime_ns,'size':info.st_size,
            'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}


class StagingInventory:
    """Read-only observation of exact flat slots under a private temporary root.

    No filesystem discovery outside registered root; no recursive deletion.
    Unknown entries, missing objects and replacement fail closed. Credentials
    use metadata only. FD pinning protects validation against path replacement.
    """
    def __init__(self,directory,plan):
        self.plan=json.loads(encode(plan));self.plan_hash=validate_plan(self.plan);self.uid=os.getuid();self.gid=os.getgid()
        self.path=Path(directory);self.fd=directory_fd(self.path,self.uid);self.parent=os.fstat(self.fd)
    def check(self):
        fd=directory_fd(self.path,self.uid)
        try:
            if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)!=(self.parent.st_dev,self.parent.st_ino):raise p.BoundaryError('JOURNAL_INVALID')
        finally:os.close(fd)
    def capture(self):
        self.check();plan=json.loads(encode(self.plan))
        if digest(plan)!=self.plan_hash:raise p.BoundaryError('POLICY_REJECTED')
        expected={e['slot'] for e in plan['entries'] if e['staged']}
        present=set(os.listdir(self.fd))
        required={e['slot'] for e in plan['entries'] if e['staged'] and e['applicability']=='REQUIRED'}
        if not required<=present or not present<=expected:raise p.BoundaryError('JOURNAL_INVALID')
        observations=[];total=0
        for e in plan['entries']:
            if not e['staged'] or e['slot'] not in present:
                observations.append({'slot':e['slot'],'status':'UNOBSERVED','identity':None,'sha256':None});continue
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
            if e['type']=='directory':flags|=os.O_DIRECTORY
            fd=os.open(e['slot'],flags,dir_fd=self.fd)
            try:
                before=os.fstat(fd)
                if (before.st_uid!=self.uid or before.st_gid!=self.gid or stat.S_IMODE(before.st_mode)!=e['mode']
                        or not (stat.S_ISDIR(before.st_mode) if e['type']=='directory' else stat.S_ISREG(before.st_mode))
                        or e['type']=='file' and before.st_nlink!=1 or before.st_size>e['max_bytes']):raise p.BoundaryError('JOURNAL_INVALID')
                if e['type']=='directory' and os.listdir(fd):raise p.BoundaryError('JOURNAL_INVALID')
                if e['category']=='CREDENTIAL' and before.st_size not in (64,65):raise p.BoundaryError('JOURNAL_INVALID')
                sha=None
                if e['type']=='file' and e['category']!='CREDENTIAL':
                    raw=os.read(fd,MAX_FILE+1);total+=len(raw)
                    if len(raw)!=before.st_size or total>MAX_TOTAL:raise p.BoundaryError('BOUNDS_EXCEEDED')
                    sha=hashlib.sha256(raw).hexdigest()
                    if e['sha256'] is not None and sha!=e['sha256']:raise p.BoundaryError('POLICY_REJECTED')
                after=os.fstat(fd);named=os.stat(e['slot'],dir_fd=self.fd,follow_symlinks=False)
                if _identity(before)!=_identity(after) or _identity(before)!=_identity(named):raise p.BoundaryError('JOURNAL_INVALID')
                observations.append({'slot':e['slot'],'status':'STAGING_OBSERVED','identity':_identity(before),'sha256':sha})
            finally:os.close(fd)
        self.check()
        return {'version':VERSION,'kind':'STAGING_OBSERVED','plan_sha256':self.plan_hash,'binding':plan['binding'],
                'observations':observations,'qualifying':False,'installed_observed':False}
    def recheck(self,previous):
        current=self.capture()
        if encode(current)!=encode(previous):raise p.BoundaryError('JOURNAL_INVALID')
        return current
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


def prerequisite(plan,observed,contract):
    """B6/B9 recording input only; no ticket or real-removal eligibility."""
    identity=validate_plan(plan)
    p.keys(observed,('version','kind','plan_sha256','binding','observations','qualifying','installed_observed'))
    if (type(observed['version']) is not int or observed['version']!=VERSION or observed['kind']!='STAGING_OBSERVED' or observed['plan_sha256']!=identity
            or observed['binding']!=plan['binding'] or observed['qualifying'] is not False or observed['installed_observed'] is not False
            or contract.get('mode')!='RECORDING_ONLY' or contract.get('inventory_sha256')!=digest({'plan':plan,'observed':observed})
            or any(contract.get(k)!=plan['binding'][k] for k in ('enrollment','owner','policy','source_commit','package_sha256','runtime_sha256'))
            or contract.get('installation_sha256')!=digest({'installation':plan['binding']['installation']})):
        raise p.BoundaryError('POLICY_REJECTED')
    entries=plan['entries'];values=observed['observations']
    if type(values) is not list or len(values)!=len(entries):raise p.BoundaryError('JOURNAL_INVALID')
    for e,v in zip(entries,values):
        p.keys(v,('slot','status','identity','sha256'))
        if v['slot']!=e['slot'] or v['status'] not in ('STAGING_OBSERVED','UNOBSERVED'):raise p.BoundaryError('JOURNAL_INVALID')
        if v['status']=='UNOBSERVED' and e['staged'] and e['applicability']=='REQUIRED':raise p.BoundaryError('JOURNAL_INVALID')
        if v['status']=='STAGING_OBSERVED' and not e['staged']:raise p.BoundaryError('JOURNAL_INVALID')
        if v['status']=='STAGING_OBSERVED':
            p.keys(v['identity'],('device','inode','ctime_ns','size','uid','gid','mode'))
            if (any(type(n) is not int or n<0 or n>=2**63 for n in v['identity'].values()) or v['identity']['mode']!=e['mode'] or v['identity']['uid']!=os.getuid() or v['identity']['gid']!=os.getgid()
                    or v['identity']['inode']==0 or v['identity']['size']>e['max_bytes']
                    or e['type']=='file' and e['category']!='CREDENTIAL' and not p.identifier(v['sha256'],64)
                    or e['category']=='CREDENTIAL' and v['sha256'] is not None
                    or e['sha256'] is not None and v['sha256']!=e['sha256']):raise p.BoundaryError('JOURNAL_INVALID')
        elif v['identity'] is not None or v['sha256'] is not None:raise p.BoundaryError('JOURNAL_INVALID')
    return {'inventory_sha256':digest({'plan':plan,'observed':observed}),'source':'RECORDING_STAGING','qualifying':False,'execution_enabled':False,'removal_enabled':False}


def removal_plan(plan,observed,contract):
    prerequisite(plan,observed,contract)
    # No actual delete/revoke/service implementation. Retained evidence survives.
    return {'version':VERSION,'inventory_sha256':digest({'plan':plan,'observed':observed}),'execution_enabled':False,'removal_enabled':False,
            'steps':[{'slot':e['slot'],'action':'RETAIN' if e['category']=='RETAINED' else 'AWAIT_INDEPENDENT_CLEANUP_AND_INSTALLED_IDENTITY',
                      'credential_revocation_required':e['category']=='CREDENTIAL'} for e in plan['entries']],
            'reason':'REAL_INSTALLATION_AND_B9_PROOF_REQUIRED',
            'ordering':['STOP_ADMISSION','INDEPENDENT_SCOPE_CLEANUP','VERIFY_ABSENCE','REVOKE_CLIENT_AND_SERVER_TOKENS',
                        'REMOVE_HASH_AND_INODE_MATCHED_IMMUTABLE_FILES','REMOVE_EMPTY_OWNED_DIRECTORIES','RETAIN_RECOVERY_EVIDENCE']}


def persist_record(directory,plan,observed,contract):
    """Exclusive append-only staging report; interrupted files remain evidence."""
    prerequisite(plan,observed,contract)
    raw=encode({'plan':plan,'observed':observed});fd=directory_fd(Path(directory),os.getuid())
    try:
        out=os.open('inventory.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
        try:
            offset=0
            while offset<len(raw):
                n=os.write(out,raw[offset:])
                if n<=0:raise p.BoundaryError('BACKEND_FAILURE')
                offset+=n
            os.fsync(out)
            identity=_identity(os.fstat(out))
        finally:os.close(out)
        os.fsync(fd)
        return {'identity':identity,'sha256':hashlib.sha256(raw).hexdigest()}
    finally:os.close(fd)


def load_record(directory,contract):
    fd=directory_fd(Path(directory),os.getuid())
    try:
        child=os.open('inventory.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
        try:
            before=os.fstat(child)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid()
                    or before.st_gid!=os.getgid() or stat.S_IMODE(before.st_mode)!=0o600
                    or not 0<before.st_size<=MAX_RECORD):raise p.BoundaryError('JOURNAL_INVALID')
            raw=os.read(child,MAX_RECORD+1)
            named=os.stat('inventory.json',dir_fd=fd,follow_symlinks=False)
            if _identity(before)!=_identity(named) or _identity(before)!=_identity(os.fstat(child)) or len(raw)!=before.st_size:
                raise p.BoundaryError('JOURNAL_INVALID')
        finally:os.close(child)
    finally:os.close(fd)
    try:value=json.loads(raw,object_pairs_hook=p._pairs)
    except (ValueError,UnicodeError,RecursionError):raise p.BoundaryError('JOURNAL_INVALID') from None
    if encode(value)!=raw:raise p.BoundaryError('JOURNAL_INVALID')
    p.keys(value,('plan','observed'));prerequisite(value['plan'],value['observed'],contract)
    return value


class ReceiptStore:
    """Recording-only immutable receipt publication in protected registered storage.

    Production requires root-owned 0700 storage/0600 files, with the receipt
    identity held by a separate protected installation registration. A same-UID
    staging owner can replace all evidence: these tests do not establish that
    production trust boundary. No receipt grants authority or removal eligibility.
    """
    def __init__(self,directory):
        import fcntl
        self.path=Path(directory);self.fd=None;self.lock=None
        self.fd=directory_fd(self.path,os.getuid())
        try:
            self.parent=os.fstat(self.fd)
            self.lock=os.open('receipt.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,0o600,dir_fd=self.fd)
            info=os.fstat(self.lock)
            self._safe(info)
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.lock_identity=_identity(info)
            self.check()
        except BaseException:
            self.close();raise
    @staticmethod
    def _safe(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid()
                or info.st_gid!=os.getgid() or stat.S_IMODE(info.st_mode)!=0o600):
            raise p.BoundaryError('JOURNAL_INVALID')
    def check(self):
        fd=directory_fd(self.path,os.getuid())
        try:
            if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)!=(self.parent.st_dev,self.parent.st_ino):raise p.BoundaryError('JOURNAL_INVALID')
            if _identity(os.stat('receipt.lock',dir_fd=fd,follow_symlinks=False))!=self.lock_identity:raise p.BoundaryError('JOURNAL_INVALID')
        finally:os.close(fd)
    def _read(self,name):
        child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
        try:
            before=os.fstat(child);self._safe(before)
            if not 0<before.st_size<=MAX_RECORD:raise p.BoundaryError('BOUNDS_EXCEEDED')
            raw=os.read(child,MAX_RECORD+1)
            if (len(raw)!=before.st_size or _identity(os.fstat(child))!=_identity(before)
                    or _identity(os.stat(name,dir_fd=self.fd,follow_symlinks=False))!=_identity(before)):
                raise p.BoundaryError('JOURNAL_INVALID')
            return raw,_identity(before)
        finally:os.close(child)
    def _pending_absent(self):
        try:os.stat('receipt.pending',dir_fd=self.fd,follow_symlinks=False)
        except FileNotFoundError:return
        raise p.BoundaryError('JOURNAL_INVALID')
    def publish(self,observer,observed,contract,record_proof):
        self.check();self._pending_absent()
        observer.recheck(observed)
        record=load_record(self.path,contract)
        if encode(record)!=encode({'plan':observer.plan,'observed':observed}):raise p.BoundaryError('POLICY_REJECTED')
        raw,identity=self._read('inventory.json')
        p.keys(record_proof,('identity','sha256'))
        if record_proof!={'identity':identity,'sha256':hashlib.sha256(raw).hexdigest()}:raise p.BoundaryError('JOURNAL_INVALID')
        for name in ('receipt.json','receipt.pending'):
            try:os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            except FileNotFoundError:continue
            raise p.BoundaryError('JOURNAL_INVALID')
        receipt={'version':1,'kind':'STAGING_RECEIPT','binding':observer.plan['binding'],
                 'inventory_sha256':digest(record),'record_sha256':hashlib.sha256(raw).hexdigest(),
                 'record_identity':identity,'directory':{'device':self.parent.st_dev,'inode':self.parent.st_ino},
                 'qualifying':False,'installed_observed':False}
        payload=encode(receipt)
        out=os.open('receipt.pending',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            offset=0
            while offset<len(payload):
                n=os.write(out,payload[offset:])
                if n<=0:raise p.BoundaryError('BACKEND_FAILURE')
                offset+=n
            os.fsync(out)
        finally:os.close(out)
        # Persist the pending intent before publication. Failure retains evidence.
        os.fsync(self.fd);self.check()
        from .socket_state import _rename
        try:_rename(self.fd,'receipt.pending','receipt.json')  # Linux RENAME_NOREPLACE
        except p.BoundaryError:raise p.BoundaryError('JOURNAL_INVALID') from None
        os.fsync(self.fd)
        published,saved=self._read('receipt.json')
        if published!=payload:raise p.BoundaryError('JOURNAL_INVALID')
        return {'identity':saved,'sha256':hashlib.sha256(payload).hexdigest()}
    def accept(self,expected,observer,observed,contract):
        self.check();self._pending_absent()
        p.keys(expected,('identity','sha256'))
        raw,identity=self._read('receipt.json')
        if identity!=expected['identity'] or hashlib.sha256(raw).hexdigest()!=expected['sha256']:raise p.BoundaryError('JOURNAL_INVALID')
        try:value=json.loads(raw,object_pairs_hook=p._pairs)
        except (ValueError,UnicodeError,RecursionError):raise p.BoundaryError('JOURNAL_INVALID') from None
        p.keys(value,('version','kind','binding','inventory_sha256','record_sha256','record_identity','directory','qualifying','installed_observed'))
        if (encode(value)!=raw or type(value['version']) is not int or value['version']!=1
                or value['kind']!='STAGING_RECEIPT' or value['binding']!=observer.plan['binding']
                or value['directory']!={'device':self.parent.st_dev,'inode':self.parent.st_ino}
                or value['qualifying'] is not False or value['installed_observed'] is not False):raise p.BoundaryError('POLICY_REJECTED')
        record=load_record(self.path,contract);record_raw,record_identity=self._read('inventory.json')
        if (record_identity!=value['record_identity'] or hashlib.sha256(record_raw).hexdigest()!=value['record_sha256']
                or digest(record)!=value['inventory_sha256']
                or encode(record)!=encode({'plan':observer.plan,'observed':observed})):raise p.BoundaryError('JOURNAL_INVALID')
        observer.recheck(observed)  # Receipts never substitute for fresh artifact reads.
        self.check()
        return prerequisite(observer.plan,observed,contract)|{'receipt_sha256':expected['sha256'],'freshly_rechecked':True}
    def close(self):
        if self.lock is not None:os.close(self.lock);self.lock=None
        if self.fd is not None:os.close(self.fd);self.fd=None
