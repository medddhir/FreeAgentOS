"""Atomic bounded private ownership journal. Never a host cleanup scanner."""
import json
import os
from pathlib import Path
import secrets
import stat
from .protocol import BoundaryError, MAX_ENTRIES, MAX_JOURNAL, STATES, identifier
from .security import directory_fd

FIELDS={'handle','run_id','connection','uid','gid','owner','state','class','role','policy'}


def validate_record(r, policy):
    if (type(r) is not dict or set(r)!=FIELDS or any(not identifier(r[k]) for k in ('handle','run_id','connection','owner'))
            or type(r['uid']) is not int or type(r['gid']) is not int or not 0<=r['uid']<2**31 or not 0<=r['gid']<2**31
            or type(r['state']) is not str or r['state'] not in STATES or r['policy']!=policy):
        raise BoundaryError('JOURNAL_INVALID')
    from .policy import execution_class
    try:execution_class(r['class'],r['role'])
    except (BoundaryError,TypeError):raise BoundaryError('JOURNAL_INVALID') from None


class Journal:
    def __init__(self, directory, policy):
        self.fd=directory_fd(directory,os.getuid())
        self.policy=policy

    def load(self):
        try:fd=os.open('state.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
        except FileNotFoundError:return []
        except OSError:raise BoundaryError('JOURNAL_INVALID') from None
        try:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid()
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>MAX_JOURNAL):raise BoundaryError('JOURNAL_INVALID')
            raw=os.read(fd,MAX_JOURNAL+1)
        finally:os.close(fd)
        try:
            from .protocol import _pairs
            value=json.loads(raw,object_pairs_hook=_pairs)
            if type(value) is not dict or set(value)!= {'version','policy','entries'} or type(value['version']) is not int or value['version']!=1 or value['policy']!=self.policy:
                raise BoundaryError('JOURNAL_INVALID')
            records=value['entries']
            if type(records) is not list or len(records)>MAX_ENTRIES:raise BoundaryError('JOURNAL_INVALID')
            for r in records:validate_record(r,self.policy)
            if len({r['handle'] for r in records})!=len(records):raise BoundaryError('JOURNAL_INVALID')
            return records
        except (ValueError,TypeError,RecursionError,BoundaryError):raise BoundaryError('JOURNAL_INVALID') from None

    def save(self, records):
        if len(records)>MAX_ENTRIES:raise BoundaryError('BOUNDS_EXCEEDED')
        for r in records:validate_record(r,self.policy)
        raw=json.dumps({'version':1,'policy':self.policy,'entries':records},sort_keys=True,separators=(',',':')).encode()
        if len(raw)>MAX_JOURNAL:raise BoundaryError('BOUNDS_EXCEEDED')
        name='pending-'+secrets.token_hex(16)
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
            try:
                os.fchmod(fd,0o600)
                with os.fdopen(fd,'wb',closefd=False) as out:out.write(raw);out.flush()
                os.fsync(fd)
            finally:os.close(fd)
            os.replace(name,'state.json',src_dir_fd=self.fd,dst_dir_fd=self.fd);os.fsync(self.fd)
        finally:
            try:os.unlink(name,dir_fd=self.fd)
            except FileNotFoundError:pass

    def close(self):os.close(self.fd)
