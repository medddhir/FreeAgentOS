"""B10 recording registration; no installed publisher or production authority.

Only an administrator-owned future adapter may qualify protected installation.
This adapter accepts exact reviewed staging dependency manifests, never RPC paths.
"""
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import time
from . import inventory as i, protocol as p
from .policy_sources import AUTHORITATIVE, PRIVILEGE_SOURCES
from .security import directory_fd
from .linux import secure_open
from .socket_state import _rename

VERSION=1
MAX_NODES=1024
MAX_FILE=16*1024*1024
MAX_TOTAL=128*1024*1024
MAX_SECONDS=10
# No caller-selected production UID/GID/mode; staging does not use this profile.
PROTECTED_PROFILE=(0,0,0o700,0o600)
REQUIRED_FILES=frozenset({'venv/bin/python','venv/pyvenv.cfg',
    'runtime/.freeagent-runtime','runtime/bin/synthetic-worker','runtime/bin/security-probe',
    'package/orchestrator/privilege/validation.service',
    'package/orchestrator/privilege/fixtures/security_probe.c',
    'package/orchestrator/privilege/fixtures/synthetic_worker.c'}|
    {'package/orchestrator/'+name for name in (*AUTHORITATIVE,*PRIVILEGE_SOURCES)}|
    {'python_base/lib/python3.12/'+name for name in ('json/__init__.py','pathlib.py','argparse.py','threading.py',
                                           'socket.py','hashlib.py','ast.py','ctypes/__init__.py')})
RUNTIME_DIRS=frozenset('runtime/'+n for n in ('tmp','run','home','dev','workspace','proc'))


def protected_profile(value):
    """Pure future contract check, not an observation/authority certificate."""
    if type(value) is not tuple or any(type(v) is not int for v in value) or value!=PROTECTED_PROFILE:
        raise p.BoundaryError('POLICY_REJECTED')
    return {'profile':'ROOT_PROTECTED_REQUIRED','qualified':False}


def validate_manifest(value):
    p.keys(value,('version','kind','nodes'))
    nodes=value['nodes']
    if (type(value['version']) is not int or value['version']!=VERSION or value['kind']!='REVIEWED_STAGING_DEPENDENCIES'
            or type(nodes) is not list or not 1<=len(nodes)<=MAX_NODES):raise p.BoundaryError('POLICY_REJECTED')
    names=set();files=set();directories=set()
    for node in nodes:
        p.keys(node,('path','type','mode','sha256'))
        name=node['path']
        if (type(name) is not str or not 1<=len(name)<=240 or '\\' in name
                or any(part in ('','.','..','token','credentials','.env') for part in name.split('/'))
                or any(re.fullmatch(r'[A-Za-z0-9_+-][A-Za-z0-9_.+-]*',part) is None for part in name.split('/') if part!='.freeagent-runtime')
                or name.split('/')[0] not in ('package','runtime','venv','python_base') or name in names
                or node['type'] not in ('file','directory') or type(node['mode']) is not int
                or node['mode'] not in (0o644,0o755) or node['type']=='directory' and node['mode']!=0o755
                or (not p.identifier(node['sha256'],64) if node['type']=='file' else node['sha256'] is not None)):
            raise p.BoundaryError('PATH_REJECTED')
        if node['type']=='file' and not (name in REQUIRED_FILES or name in ('package/orchestrator/roles/__init__.py','python_base/lib/libpython3.12.so.1.0') or
                re.fullmatch(r'(venv|python_base)/lib/python3\.12/[A-Za-z0-9_.+/-]+\.(py|so|pyc)',name) or
                re.fullmatch(r'venv/lib/python3\.12/site-packages/[A-Za-z0-9_.+-]+\.dist-info/(METADATA|WHEEL|RECORD)',name) or
                re.fullmatch(r'runtime/(lib|lib64)/[A-Za-z0-9_.+/-]+\.so(?:\.[0-9]+)*',name)):
            raise p.BoundaryError('PATH_REJECTED')
        if node['type']=='file' and (name.endswith(('.key','.pem')) or name.split('/')[-1] in ('approval.json','consumed.json','reserved.json')):
            raise p.BoundaryError('PATH_REJECTED')
        names.add(name);(files if node['type']=='file' else directories).add(name)
    if not REQUIRED_FILES<=files or not RUNTIME_DIRS<=directories:raise p.BoundaryError('POLICY_REJECTED')
    for name in names:
        if '/' in name and name.rsplit('/',1)[0] not in directories:raise p.BoundaryError('PATH_REJECTED')
    if [n['path'] for n in nodes]!=sorted(names):raise p.BoundaryError('POLICY_REJECTED')
    return i.digest(value)


class StagingDependencies:
    """Pinned temporary installation tree. No imports, ldd, discovery or exec.

    python_base models the registered external base prefix (reference /usr),
    not new files installed inside a venv. Manifest comes from trusted build review; it cannot prove dependency closure
    or build reproducibility. Every directory is checked against exact children.
    """
    def __init__(self,directory,manifest,*,clock=time.monotonic):
        self.manifest=json.loads(i.encode(manifest));self.manifest_hash=validate_manifest(self.manifest)
        self.path=Path(directory);self.uid=os.getuid();self.gid=os.getgid();self.clock=clock
        self.fd=None
        try:
            self.fd=directory_fd(self.path,self.uid);self.anchor=os.fstat(self.fd)
        except BaseException:
            self.close();raise
    def check(self):
        fd=directory_fd(self.path,self.uid)
        try:
            if i._identity(os.fstat(fd))!=i._identity(self.anchor):raise p.BoundaryError('JOURNAL_INVALID')
        finally:os.close(fd)
    def capture(self):
        self.check()
        if validate_manifest(self.manifest)!=self.manifest_hash:raise p.BoundaryError('POLICY_REJECTED')
        started=self.clock();total=0;rows=[];fds={'':os.dup(self.fd)}
        def bounded():
            if self.clock()-started>MAX_SECONDS:raise p.BoundaryError('BOUNDS_EXCEEDED')
        try:
            expected={'' : set()}
            for node in self.manifest['nodes']:
                name=node['path'];parent,_,base=name.rpartition('/')
                expected.setdefault(parent,set()).add(base)
                if node['type']=='directory':expected.setdefault(name,set())
            # Parents precede children because canonical lexicographic order is fixed.
            for node in self.manifest['nodes']:
                bounded();name=node['path'];parent,_,base=name.rpartition('/')
                fd=secure_open(fds[parent],base,os.O_RDONLY|(os.O_DIRECTORY if node['type']=='directory' else 0))
                try:
                    before=os.fstat(fd)
                    if (before.st_dev!=self.anchor.st_dev or before.st_uid!=self.uid or before.st_gid!=self.gid
                            or stat.S_IMODE(before.st_mode)!=node['mode']
                            or not (stat.S_ISDIR(before.st_mode) if node['type']=='directory' else stat.S_ISREG(before.st_mode))
                            or node['type']=='file' and (before.st_nlink!=1 or before.st_size>MAX_FILE)):
                        raise p.BoundaryError('POLICY_REJECTED')
                    digest=None
                    if node['type']=='file':
                        h=hashlib.sha256();read=0
                        while True:
                            bounded();raw=os.read(fd,65536)
                            if not raw:break
                            read+=len(raw);total+=len(raw)
                            if read>MAX_FILE or total>MAX_TOTAL:raise p.BoundaryError('BOUNDS_EXCEEDED')
                            h.update(raw)
                        digest=h.hexdigest()
                        if read!=before.st_size or digest!=node['sha256']:raise p.BoundaryError('POLICY_REJECTED')
                    if i._identity(os.fstat(fd))!=i._identity(before):raise p.BoundaryError('JOURNAL_INVALID')
                    rows.append({'path':name,'identity':i._identity(before),'sha256':digest})
                    if node['type']=='directory':fds[name]=fd;fd=None
                finally:
                    if fd is not None:os.close(fd)
            # Recheck all ancestry and file identities after traversal.
            for row in rows:
                bounded();parent,_,base=row['path'].rpartition('/')
                if i._identity(os.stat(base,dir_fd=fds[parent],follow_symlinks=False))!=row['identity']:raise p.BoundaryError('JOURNAL_INVALID')
            for name,fd in fds.items():
                bounded()
                with os.scandir(fd) as entries:
                    actual=set()
                    for item in entries:
                        if len(actual)>=MAX_NODES:raise p.BoundaryError('BOUNDS_EXCEEDED')
                        actual.add(item.name)
                if actual!=expected[name]:raise p.BoundaryError('POLICY_REJECTED')
            self.check()
            value={'version':VERSION,'kind':'STAGING_DEPENDENCIES','manifest_sha256':self.manifest_hash,
                   'anchor':i._identity(self.anchor),'nodes':rows,'bytes':total,'qualified':False}
            i.encode(value);return value
        finally:
            for fd in fds.values():os.close(fd)
    def recheck(self,value):
        current=self.capture()
        if i.encode(current)!=i.encode(value):raise p.BoundaryError('JOURNAL_INVALID')
        return current
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


class RecordingRegistration(i.ReceiptStore):
    """No real publisher, configurable root profile, approval or credential path.

    Reuses receipt protected FD, permanent lock, bounded reads and identity checks.
    Expected record identity must be retained externally across restart; this
    temporary adapter cannot establish root-protected registration provenance.
    """
    def _value(self,receipt,receipt_identity,observer,observed,contract,tree,snapshot):
        proof=receipt.accept(receipt_identity,observer,observed,contract)
        tree.recheck(snapshot)
        if not p.identifier(contract.get('qualified_target_sha256'),64):raise p.BoundaryError('POLICY_REJECTED')
        # Tie the service's approved executables to inventory, not just tree names.
        for name,key in (('venv/bin/python','launcher_sha256'),('runtime/bin/synthetic-worker','synthetic_sha256'),
                         ('runtime/bin/security-probe','security_probe_sha256')):
            node=next(n for n in tree.manifest['nodes'] if n['path']==name)
            if node['sha256']!=observer.plan['provenance'][key]:raise p.BoundaryError('POLICY_REJECTED')
        for entry in observer.plan['entries']:
            if '/package/orchestrator/' in entry['target']:
                name='package/orchestrator/'+entry['target'].split('/package/orchestrator/')[1]
                if next(n for n in tree.manifest['nodes'] if n['path']==name)['sha256']!=entry['sha256']:raise p.BoundaryError('POLICY_REJECTED')
        for name,key in (('security_probe.c','fixture_source_sha256'),('synthetic_worker.c','synthetic_source_sha256')):
            node=next(n for n in tree.manifest['nodes'] if n['path']=='package/orchestrator/privilege/fixtures/'+name)
            if node['sha256']!=observer.plan['provenance'][key]:raise p.BoundaryError('POLICY_REJECTED')
        marker=next(n for n in tree.manifest['nodes'] if n['path']=='runtime/.freeagent-runtime')
        if marker['sha256']!=hashlib.sha256(b'FREEAGENTOS_MINIMAL_RUNTIME_V1\n').hexdigest():raise p.BoundaryError('POLICY_REJECTED')
        unit=next(n for n in tree.manifest['nodes'] if n['path']=='package/orchestrator/privilege/validation.service')
        expected_unit=next(e for e in observer.plan['entries'] if e['target'].endswith('.service'))
        if unit['sha256']!=expected_unit['sha256']:raise p.BoundaryError('POLICY_REJECTED')
        return {'version':VERSION,'kind':'RECORDING_REGISTRATION','binding':observer.plan['binding'],
                'inventory_sha256':proof['inventory_sha256'],'receipt':receipt_identity,
                'provenance':observer.plan['provenance'],'target_sha256':contract['qualified_target_sha256'],
                'manifest':tree.manifest,'dependencies':snapshot,'qualified':False,'installed_observed':False,
                'execution_enabled':False,'removal_enabled':False,
                'required_protection':{'uid':0,'gid':0,'directory_mode':0o700,'file_mode':0o600}}
    def publish(self,*args):
        self.check();value=self._value(*args);raw=i.encode(value)
        for name in ('registration.json','registration.pending'):
            try:os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            except FileNotFoundError:continue
            raise p.BoundaryError('JOURNAL_INVALID')
        fd=os.open('registration.pending',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            offset=0
            while offset<len(raw):
                n=os.write(fd,raw[offset:])
                if n<=0:raise p.BoundaryError('BACKEND_FAILURE')
                offset+=n
            os.fsync(fd)
        finally:os.close(fd)
        os.fsync(self.fd);self.check()
        # Fresh observations immediately before commit; races invalidate acceptance.
        if i.encode(self._value(*args))!=raw:raise p.BoundaryError('JOURNAL_INVALID')
        _rename(self.fd,'registration.pending','registration.json');os.fsync(self.fd)
        published,identity=self._read('registration.json')
        if published!=raw:raise p.BoundaryError('JOURNAL_INVALID')
        if i.encode(self._value(*args))!=raw:raise p.BoundaryError('JOURNAL_INVALID')
        self.check()
        return {'identity':identity,'sha256':hashlib.sha256(raw).hexdigest()}
    def accept(self,expected,*args):
        self.check();p.keys(expected,('identity','sha256'))
        try:os.stat('registration.pending',dir_fd=self.fd,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise p.BoundaryError('JOURNAL_INVALID')
        raw,identity=self._read('registration.json')
        if expected!={'identity':identity,'sha256':hashlib.sha256(raw).hexdigest()}:raise p.BoundaryError('JOURNAL_INVALID')
        value=self._value(*args)
        if raw!=i.encode(value):raise p.BoundaryError('POLICY_REJECTED')
        self.check()
        return {'registration_sha256':expected['sha256'],'source':'RECORDING_STAGING',
                'qualified':False,'execution_enabled':False,'removal_enabled':False}
