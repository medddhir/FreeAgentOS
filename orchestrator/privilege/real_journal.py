"""Versioned cleanup-only Linux resource ledger; no host scanning."""
import json
import os
import secrets
import stat
from .protocol import BoundaryError, MAX_ENTRIES, MAX_JOURNAL, STATES, identifier, _pairs
from .security import directory_fd
from .policy import execution_class

FIELDS={'handle','run_id','owner','state','class','role','policy','boot_id',
        'scope_inode','scope_device','root_inode','root_device','started_ns','cleanup'}


def validate(record,policy,owner):
    if type(record) is not dict or set(record)-{'collection'}!=FIELDS:raise BoundaryError('JOURNAL_INVALID')
    if 'collection' in record and (type(record['collection']) is not str or record['collection'] not in ('NONE','PENDING','CLOSED','UNPROVEN')):raise BoundaryError('JOURNAL_INVALID')
    if record.get('collection') in ('PENDING','UNPROVEN') and record['state']=='RELEASED':raise BoundaryError('JOURNAL_INVALID')
    if (any(not identifier(record[k]) for k in ('handle','run_id','owner')) or record['owner']!=owner
            or record['policy']!=policy or type(record['state']) is not str or record['state'] not in STATES
            or type(record['boot_id']) is not str or not 1<=len(record['boot_id'])<=64
            or type(record['cleanup']) is not str or record['cleanup'] not in ('PENDING','CONFIRMED','NEVER_ALLOCATED','UNPROVEN')):
        raise BoundaryError('JOURNAL_INVALID')
    if record['state']=='RELEASED' and record['cleanup'] not in ('CONFIRMED','NEVER_ALLOCATED'):raise BoundaryError('JOURNAL_INVALID')
    for field in ('scope_inode','scope_device','root_inode','root_device','started_ns'):
        if type(record[field]) is not int or not 0<=record[field]<2**63:raise BoundaryError('JOURNAL_INVALID')
    if record['cleanup']=='NEVER_ALLOCATED' and (record['state']!='RELEASED' or any(record[k] for k in ('root_inode','scope_inode','started_ns'))):raise BoundaryError('JOURNAL_INVALID')
    if record['cleanup']=='NEVER_ALLOCATED' and record.get('collection','NONE')!='NONE':raise BoundaryError('JOURNAL_INVALID')
    try:execution_class(record['class'],record['role'])
    except (BoundaryError,TypeError):raise BoundaryError('JOURNAL_INVALID') from None


class ResourceJournal:
    def __init__(self,directory,policy,owner,*,uid=0):
        if not identifier(policy,64) or not identifier(owner):raise BoundaryError('JOURNAL_INVALID')
        self.fd=directory_fd(directory,uid);self.uid=uid;self.policy=policy;self.owner=owner

    def load(self):
        try:fd=os.open('resources.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=self.fd)
        except FileNotFoundError:return []
        try:
            info=os.fstat(fd)
            if (info.st_uid!=self.uid or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1
                    or not stat.S_ISREG(info.st_mode) or info.st_size>MAX_JOURNAL):raise BoundaryError('JOURNAL_INVALID')
            raw=os.read(fd,MAX_JOURNAL+1)
        finally:os.close(fd)
        try:
            data=json.loads(raw,object_pairs_hook=_pairs)
            if (type(data) is not dict or set(data)!= {'version','policy','owner','entries'}
                    or type(data['version']) is not int or data['version']!=2
                    or data['policy']!=self.policy or data['owner']!=self.owner):raise BoundaryError('JOURNAL_INVALID')
            entries=data['entries']
            if type(entries) is not list or len(entries)>MAX_ENTRIES:raise BoundaryError('JOURNAL_INVALID')
            for r in entries:validate(r,self.policy,self.owner)
            if len({r['handle'] for r in entries})!=len(entries):raise BoundaryError('JOURNAL_INVALID')
            return entries
        except (ValueError,TypeError,UnicodeError,RecursionError):raise BoundaryError('JOURNAL_INVALID') from None

    def save(self,records):
        if type(records) is not list or len(records)>MAX_ENTRIES:raise BoundaryError('BOUNDS_EXCEEDED')
        for r in records:validate(r,self.policy,self.owner)
        if len({r['handle'] for r in records})!=len(records):raise BoundaryError('JOURNAL_INVALID')
        raw=json.dumps({'version':2,'policy':self.policy,'owner':self.owner,'entries':records},sort_keys=True,separators=(',',':')).encode()
        if len(raw)>MAX_JOURNAL:raise BoundaryError('BOUNDS_EXCEEDED')
        name='pending-'+secrets.token_hex(16)
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'wb',closefd=False) as out:out.write(raw);out.flush()
            os.fsync(fd)
            os.replace(name,'resources.json',src_dir_fd=self.fd,dst_dir_fd=self.fd);os.fsync(self.fd)
        finally:
            os.close(fd)
            try:os.unlink(name,dir_fd=self.fd)
            except FileNotFoundError:pass

    def close(self):os.close(self.fd)


def recovery_actions(record,policy,owner,proof):
    """Require descriptor/inode proof from the trusted driver, never names alone."""
    validate(record,policy,owner)
    if record['state']=='RELEASED':return ()
    if type(proof) is not dict or set(proof)!={'scope','root'} or any(type(v) is not bool for v in proof.values()) or not all(proof.values()):
        raise BoundaryError('CLEANUP_INCOMPLETE')
    return ('TERMINATE_OWNED_SCOPE','VERIFY_EMPTY','REAP_CHILD_IF_OWNED','REMOVE_OWNED_ROOT','REMOVE_OWNED_SCOPE','MARK_RELEASED')
