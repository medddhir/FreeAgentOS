"""Descriptor-rooted ingestion of externally verified controller snapshots."""
from dataclasses import dataclass
import hashlib
import json
import os
import stat
from types import MappingProxyType
from .linux import secure_open
from .protocol import BoundaryError, identifier, _pairs
from .policy import CLASSES

MAX_FILES=20000
MAX_BYTES=1024*1024*1024
MAX_FILE=128*1024*1024
MAX_MANIFEST=4*1024*1024


def relative_name(name):
    if (type(name) is not str or not 1<=len(name.encode())<=256 or '\\' in name or '\0' in name
            or any(p in ('','.','..') for p in name.split('/')) or name.split('/')[0]=='.git'):
        raise BoundaryError('PATH_REJECTED')
    return name


@dataclass(frozen=True)
class Seal:
    files: object
    verification_sha256: str

    @classmethod
    def from_verification(cls, raw, expected):
        """Caller supplies the external controller manifest and its trusted digest.

        Never opens source_repo/workspace_repo strings inside that manifest.
        Those paths are deliberately irrelevant to this privileged boundary.
        """
        if type(raw) is not bytes or len(raw)>MAX_MANIFEST or not identifier(expected,64) or hashlib.sha256(raw).hexdigest()!=expected:
            raise BoundaryError('POLICY_REJECTED')
        try:manifest=json.loads(raw,object_pairs_hook=_pairs)
        except (ValueError,UnicodeError,RecursionError):raise BoundaryError('POLICY_REJECTED') from None
        if (type(manifest) is not dict or type(manifest.get('schema_version')) is not int or manifest['schema_version']!=1
                or manifest.get('worker_resource_policy')!=dict(CLASSES['MODEL_WORKER'].limits)
                or manifest.get('research_resource_policy')!=dict(CLASSES['RESEARCH_HELPER'].limits)
                or manifest.get('resource_policy')!=dict(CLASSES['DETERMINISTIC_TESTER'].limits)):
            raise BoundaryError('POLICY_REJECTED')
        files=manifest.get('source_inventory')
        if type(files) is not dict or not 1<=len(files)<=MAX_FILES:raise BoundaryError('BOUNDS_EXCEEDED')
        for name,digest in files.items():
            relative_name(name)
            if not identifier(digest,64):raise BoundaryError('POLICY_REJECTED')
        directories={'/'.join(name.split('/')[:i]) for name in files for i in range(1,len(name.split('/')))}
        if len(directories)+len(files)>22000:raise BoundaryError('BOUNDS_EXCEEDED')
        # File/dir conflicts cannot be admitted.
        if any('/'.join(name.split('/')[:i]) in files for name in files for i in range(1,len(name.split('/')))):
            raise BoundaryError('PATH_REJECTED')
        return cls(MappingProxyType(dict(files)),expected)


class SnapshotSource:
    """Root opened once by trusted registration; path renames cannot redirect it."""
    def __init__(self, root_fd, seal):
        if type(seal) is not Seal or not stat.S_ISDIR(os.fstat(root_fd).st_mode):raise BoundaryError('PATH_REJECTED')
        self.fd=os.dup(root_fd);os.set_inheritable(self.fd,False);self.seal=seal

    def copy_into(self, destination_fd):
        """Destination is a newly allocated helper-private directory FD.

        Destination must be empty. No source path, symlink or metadata is copied.
        Hash the bytes actually written; concurrent inode writes cannot cause
        admission of bytes differing from the controller seal.
        """
        if os.listdir(destination_fd):raise BoundaryError('INVALID_STATE')
        total=0
        for name,digest in sorted(self.seal.files.items()):
            source=secure_open(self.fd,name)
            parent=os.dup(destination_fd)
            try:
                info=os.fstat(source)
                if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_FILE:raise BoundaryError('PATH_REJECTED')
                for component in name.split('/')[:-1]:
                    try:os.mkdir(component,0o700,dir_fd=parent)
                    except FileExistsError:pass
                    nxt=secure_open(parent,component,os.O_RDONLY|os.O_DIRECTORY);os.close(parent);parent=nxt
                out=os.open(name.split('/')[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400,dir_fd=parent)
                try:
                    check=hashlib.sha256();count=0
                    while block:=os.read(source,65536):
                        count+=len(block);total+=len(block)
                        if count>MAX_FILE or total>MAX_BYTES:raise BoundaryError('BOUNDS_EXCEEDED')
                        check.update(block)
                        view=memoryview(block)
                        while view:
                            written=os.write(out,view)
                            if written<=0:raise BoundaryError('BACKEND_FAILURE')
                            view=view[written:]
                    if check.hexdigest()!=digest:raise BoundaryError('POLICY_REJECTED')
                    os.fchmod(out,0o400);os.fsync(out)
                finally:os.close(out)
            finally:os.close(source);os.close(parent)
        os.fsync(destination_fd)
        return {'files':len(self.seal.files),'bytes':total,'seal':self.seal.verification_sha256}

    def close(self):os.close(self.fd)
