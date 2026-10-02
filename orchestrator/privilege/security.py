"""Peer, private-file and FD-rooted registration checks; no model inputs."""
from dataclasses import dataclass, field
import hmac
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
from .protocol import BoundaryError, identifier


@dataclass(frozen=True)
class Enrollment:
    enrollment_id: str
    uid: int
    gid: int
    token: str = field(repr=False)

    def __post_init__(self):
        if (not identifier(self.enrollment_id) or not identifier(self.token,64)
                or type(self.uid) is not int or type(self.gid) is not int
                or not 0 <= self.uid <= 2**31-1 or not 0 <= self.gid <= 2**31-1):
            raise BoundaryError('AUTH_FAILED')

    def authenticate(self, peer, value):
        if peer[1:] != (self.uid,self.gid):raise BoundaryError('PEER_NOT_ALLOWED')
        if not hmac.compare_digest(self.token,value):raise BoundaryError('AUTH_FAILED')


def peer_credentials(channel):
    try:
        if channel.family != socket.AF_UNIX or not hasattr(socket,'SO_PEERCRED'):
            raise BoundaryError('PEER_NOT_ALLOWED')
        return struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    except (OSError,struct.error):raise BoundaryError('PEER_NOT_ALLOWED') from None


def directory_fd(path, uid, mode=0o700):
    raw=str(path)
    path=Path(path)
    if raw != str(path) or '..' in path.parts or not path.is_absolute():raise BoundaryError('PATH_REJECTED')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            next_fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=next_fd
        info=os.fstat(fd)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode:raise BoundaryError('PATH_REJECTED')
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_file(path, uid):
    parent=directory_fd(Path(path).parent,uid)
    try:
        fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        try:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=uid
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384):
                raise BoundaryError('PATH_REJECTED')
            return os.read(fd,16385)
        finally:os.close(fd)
    finally:os.close(parent)


def create_token(path):
    """Explicit caller storage API, used only with temporary test fixtures here."""
    parent=directory_fd(Path(path).parent,os.getuid())
    token=secrets.token_hex(32)
    try:
        fd=os.open(Path(path).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        try:
            os.fchmod(fd,0o600);os.write(fd,(token+'\n').encode());os.fsync(fd)
        finally:os.close(fd)
    finally:os.close(parent)
    return token


def load_token(path):
    raw=private_file(path,os.getuid())
    try:value=raw.decode('ascii').rstrip('\n')
    except UnicodeError:raise BoundaryError('AUTH_FAILED') from None
    if not identifier(value,64):raise BoundaryError('AUTH_FAILED')
    return value


def validate_socket(path, uid, gid, parent_mode=0o700, socket_mode=0o600):
    # Fixture profile: 0700/0600. Future enrolled-group profile: 0750/0660.
    if (parent_mode,socket_mode) not in ((0o700,0o600),(0o750,0o660)):
        raise BoundaryError('PATH_REJECTED')
    parent=directory_fd(Path(path).parent,uid,parent_mode)
    try:
        info=os.stat(Path(path).name,dir_fd=parent,follow_symlinks=False)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=uid or info.st_gid!=gid
                or stat.S_IMODE(info.st_mode)!=socket_mode):raise BoundaryError('PATH_REJECTED')
    finally:os.close(parent)


class RegisteredRoots:
    """Administrative FD anchors. Protocol accepts slot names, never host paths.

    Component-wise O_NOFOLLOW walking is for simulation/caller-owned regular
    files only. There is no privileged-mount fallback; that backend is absent.
    """
    def __init__(self):self._roots={}

    def register(self, slot, path, uid):
        import re
        if not isinstance(slot,str) or re.fullmatch('[a-z][a-z0-9_-]{0,31}',slot) is None or slot in self._roots or len(self._roots)>=16:
            raise BoundaryError('PATH_REJECTED')
        fd=directory_fd(path,uid)
        self._roots[slot]=(Path(path),fd,uid)

    def check(self, slot):
        if slot not in self._roots:raise BoundaryError('PATH_REJECTED')
        path,fd,uid=self._roots[slot]
        opened=directory_fd(path,uid)
        try:
            current=os.fstat(opened);saved=os.fstat(fd)
            if (current.st_dev,current.st_ino)!=(saved.st_dev,saved.st_ino):raise BoundaryError('PATH_REJECTED')
        finally:os.close(opened)
        return os.dup(fd)

    def open_file(self, slot, relative):
        if type(relative) is not str or not relative or len(relative)>256 or '\\' in relative or '\0' in relative:
            raise BoundaryError('PATH_REJECTED')
        parts=relative.split('/')
        if any(part in ('','.','..') for part in parts):raise BoundaryError('PATH_REJECTED')
        fd=self.check(slot)
        try:
            for part in parts[:-1]:
                nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                os.close(fd);fd=nxt
            child=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            info=os.fstat(child)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
                os.close(child);raise BoundaryError('PATH_REJECTED')
            return child
        except OSError:raise BoundaryError('PATH_REJECTED') from None
        finally:os.close(fd)

    def close(self):
        for _,fd,_ in self._roots.values():os.close(fd)
        self._roots.clear()
