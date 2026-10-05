"""Owned text job resources, not admission or an installed model adapter.

An immutable input and an initially empty output are owned by one backend job.
No request/response bytes travel through generic RPC or prompt argv. The
recording driver exercises these same resources without launching anything.
"""
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
import secrets
import stat
import struct
import time
from types import MappingProxyType
from . import protocol as p

MAX_INPUT = 48 * 1024
MAX_OUTPUT = 64 * 1024
MAX_HEADER = 4096
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _identity(fd):
    try:s = os.fstat(fd);inheritable = os.get_inheritable(fd)
    except (OSError, TypeError):raise p.BoundaryError('POLICY_REJECTED') from None
    if not stat.S_ISREG(s.st_mode) or inheritable:
        raise p.BoundaryError('POLICY_REJECTED')
    return (s.st_dev, s.st_ino)


def _write(fd, raw):
    # Each successful write consumes at least one byte; finite byte budget.
    offset = 0
    while offset < len(raw):
        n = os.pwrite(fd, raw[offset:], offset)
        if n <= 0:raise p.BoundaryError('BACKEND_FAILURE')
        offset += n


def _frame(header, payload):
    raw = p.encode(header)
    if len(raw) > MAX_HEADER:raise p.BoundaryError('BOUNDS_EXCEEDED')
    return struct.pack('!I', len(raw)) + raw + payload


def _read(fd, limit, identity):
    try:return _read_resource(fd,limit,identity)
    except (OSError,TypeError,ValueError):raise p.BoundaryError('POLICY_REJECTED') from None


def _read_resource(fd, limit, identity):
    if _identity(fd) != identity:raise p.BoundaryError('POLICY_REJECTED')
    if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & SEALS != SEALS:
        raise p.BoundaryError('POLICY_REJECTED')
    size = os.fstat(fd).st_size
    if not 4 < size <= 4 + MAX_HEADER + limit:raise p.BoundaryError('BOUNDS_EXCEEDED')
    raw = os.pread(fd, size + 1, 0)
    if len(raw) != size:raise p.BoundaryError('BACKEND_FAILURE')
    length = struct.unpack('!I', raw[:4])[0]
    if not 0 < length <= MAX_HEADER or 4 + length > size:
        raise p.BoundaryError('INVALID_REQUEST')
    header = p.decode(raw[4:4+length]);payload = raw[4+length:]
    if len(payload) > limit:raise p.BoundaryError('BOUNDS_EXCEEDED')
    return header, payload


@dataclass(frozen=True)
class TextResponse:
    job_id: str
    request_sha256: str
    response_sha256: str
    payload: bytes
    # Data only; not execution, model provenance or cleanup evidence.


class TextJob:
    def __init__(self, plan, record, entry, limits, *, clock=time.monotonic_ns):
        from ..roles.worker import TextInferencePlan, prepare_text_inference, WorkerBoundaryError, TEXT_INFERENCE_PROFILE, TEXT_INFERENCE_BOUNDS
        from .execution import ApprovedExecution
        from .policy import text_resource_limits
        if (MAX_INPUT != TEXT_INFERENCE_BOUNDS['request_bytes']
                or MAX_OUTPUT != TEXT_INFERENCE_BOUNDS['response_bytes']):
            raise p.BoundaryError('POLICY_REJECTED')
        if (type(plan) is not TextInferencePlan or type(entry) is not ApprovedExecution
                or type(record) is not dict or not {'policy','handle','owner','run_id'} <= set(record)
                or entry.validation or entry.execution != 'MODEL_WORKER'):
            raise p.BoundaryError('POLICY_REJECTED')
        # Reject before allocating any text descriptor. The observed policy
        # identity digest above/below is a separate domain from these values.
        effective=text_resource_limits(entry.role,limits)
        if effective['max_output_bytes']!=MAX_OUTPUT:
            raise p.BoundaryError('RESOURCE_LIMIT_INVALID')
        self.limits=MappingProxyType(effective)
        self.role=entry.role
        self.clock=clock  # trusted lifecycle/test clock, never adapter input
        self.started_ns=self.deadline_ns=self.response_observed_ns=None
        try:
            if type(plan.request) is not bytes or not 0 < len(plan.request) <= MAX_INPUT:
                raise ValueError()
            request = json.loads(plan.request, object_pairs_hook=p._pairs)
            checked = prepare_text_inference(request, runtime_sha256=plan.runtime_sha256,
                executable_sha256=plan.executable_sha256, invocation=plan.invocation,
                credential_reference=plan.credential_reference, policy_sha256=plan.policy_sha256)
            if checked != plan or plan.policy_sha256 != record['policy'] or plan.executable_sha256 != entry.executable.digest:
                raise ValueError()
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, WorkerBoundaryError):
            raise p.BoundaryError('POLICY_REJECTED') from None
        # Fresh job identity is issued here, independently of supplied invocation.
        self.job_id = secrets.token_hex(16)
        self.binding = p.encode({'version': 1, 'job': self.job_id,
            'handle': record['handle'], 'owner': record['owner'], 'backend_run': record['run_id'], 'run': request['run'],
            'profile': request['profile'], 'text_profile': TEXT_INFERENCE_PROFILE, 'phase': request['phase'],
            'contract': request['contract'], 'snapshot': request['base_snapshot'],
            'request': plan.request_sha256, 'invocation': plan.invocation,
            'plan': plan.binding_sha256, 'runtime_declared': plan.runtime_sha256,
            'executable_declared': plan.executable_sha256,
            'executable_observed': entry.executable.digest,
            'effective_limits': effective})
        try:runtime = os.fstat(entry.runtime_fd)
        except (OSError, TypeError):raise p.BoundaryError('POLICY_REJECTED') from None
        if not stat.S_ISDIR(runtime.st_mode) or os.get_inheritable(entry.runtime_fd):
            raise p.BoundaryError('POLICY_REJECTED')
        self.runtime_fd = entry.runtime_fd
        self.runtime_identity = (runtime.st_dev, runtime.st_ino)
        self.input_fd = self.output_fd = None
        self.response_read_fd = self.response_write_fd = None
        self.delivered = self.completed = self.collected = False
        self.close_failed = False
        try:
            self.input_fd = os.memfd_create('freeagent-text-input', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self.output_fd = os.memfd_create('freeagent-text-output', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self.input_identity = _identity(self.input_fd);self.output_identity = _identity(self.output_fd)
            _write(self.input_fd, _frame({'binding': _sha(self.binding), 'job': self.job_id, 'bytes': len(plan.request), 'sha256': plan.request_sha256}, plan.request))
            fcntl.fcntl(self.input_fd, fcntl.F_ADD_SEALS, SEALS)
            # Sealing forbids writes even through retained duplicates. Reopen
            # read-only as well, so the child receives no writable access right.
            old = self.input_fd
            readonly = os.open('/proc/self/fd/'+str(old), os.O_RDONLY|os.O_CLOEXEC)
            self.input_fd = readonly
            try:os.close(old)
            except OSError:
                self.close_failed = True
                raise p.BoundaryError('CLEANUP_INCOMPLETE') from None
            self.response_read_fd, self.response_write_fd = os.pipe2(os.O_CLOEXEC)
            info = os.fstat(self.response_write_fd)
            self.pipe_identity = (info.st_dev, info.st_ino)
        except Exception:
            try:self.close()
            except p.BoundaryError:
                failure=p.BoundaryError('CLEANUP_INCOMPLETE')
                failure.owned_text_job=self
                raise failure from None
            raise p.BoundaryError('BACKEND_FAILURE') from None

    def configuration(self):
        """Legacy recording/capture identity, not the adapter handoff schema.

        output_fd is controller-only storage. Text ABI v2 exposes input_fd and
        response_write_fd, never this writable result memfd. V1 child unchanged.
        """
        if self.input_fd is None or self.output_fd is None:raise p.BoundaryError('INVALID_STATE')
        return {'version': 1, 'job': self.job_id, 'binding': _sha(self.binding),
                'input': self.input_fd, 'output': self.output_fd}

    def verify_owner(self, record, entry):
        try:self._verify_owner(record, entry)
        except (OSError, TypeError, KeyError, AttributeError):
            raise p.BoundaryError('POLICY_REJECTED') from None

    def _verify_owner(self, record, entry):
        binding = p.decode(self.binding)
        if (binding['job'] != self.job_id or binding['handle'] != record['handle']
                or binding['owner'] != record['owner'] or binding['backend_run'] != record['run_id']
                or entry.validation or binding['executable_observed'] != entry.executable.digest):
            raise p.BoundaryError('POLICY_REJECTED')
        runtime = os.fstat(entry.runtime_fd)
        if (runtime.st_dev, runtime.st_ino) != self.runtime_identity:
            raise p.BoundaryError('POLICY_REJECTED')

    def verify_descriptors(self):
        from .text_handoff import verify_descriptors
        verify_descriptors({'fds': [None]*6 + [self.input_fd, self.response_write_fd],
            'text': {'input_identity': list(self.input_identity),
                     'output_identity': list(self.pipe_identity)}})

    def begin_execution(self, started_ns):
        if (self.started_ns is not None or type(started_ns) is not int
                or not 0<=started_ns<2**63-self.limits['wall_timeout_seconds']*1000000000):
            raise p.BoundaryError('INVALID_STATE')
        self.started_ns=started_ns
        self.deadline_ns=started_ns+self.limits['wall_timeout_seconds']*1000000000

    def verify_limits(self, role, limits):
        from .policy import text_resource_limits
        checked=text_resource_limits(role,limits)
        if role!=self.role or checked!=dict(self.limits) or p.decode(self.binding)['effective_limits']!=checked:
            raise p.BoundaryError('RESOURCE_LIMIT_INVALID')
        return checked

    def close_response_reader(self):
        fd = self.response_read_fd
        self.response_read_fd = None
        if fd is not None:
            try:os.close(fd)
            except OSError:self.close_failed = True

    def verify_response_reader(self):
        try:
            info=os.fstat(self.response_read_fd)
            if (not stat.S_ISFIFO(info.st_mode) or (info.st_dev,info.st_ino)!=self.pipe_identity
                    or fcntl.fcntl(self.response_read_fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY):
                raise p.BoundaryError('POLICY_REJECTED')
        except (OSError,TypeError,ValueError):raise p.BoundaryError('POLICY_REJECTED') from None

    def close_response_writer(self):
        fd = self.response_write_fd
        self.response_write_fd = None
        if fd is not None:
            try:os.close(fd)
            except OSError:
                self.close_failed = True
                raise p.BoundaryError('CLEANUP_INCOMPLETE') from None

    def accept_response(self, frame, *, exit_code, eof, observed_ns):
        """Owned collector only: EOF AND exact zero direct-child outcome.

        Adapter COMPLETE is validated later and cannot replace process outcome.
        Controller capture is never exposed as an adapter descriptor.
        """
        if (not self.delivered or self.completed or type(exit_code) is not int
                or exit_code != 0 or eof is not True or self.started_ns is None
                or type(observed_ns) is not int or not self.started_ns<=observed_ns<self.deadline_ns):
            raise p.BoundaryError('INVALID_STATE')
        if type(frame) is not bytes or not 4 < len(frame) <= 4+MAX_HEADER+self.limits['max_output_bytes']:
            raise p.BoundaryError('BOUNDS_EXCEEDED')
        length=struct.unpack('!I',frame[:4])[0]
        if not 0 < length <= MAX_HEADER or 4+length >= len(frame):
            raise p.BoundaryError('INVALID_REQUEST')
        header=p.decode(frame[4:4+length]);payload=frame[4+length:]
        expected={'binding':_sha(self.binding),'job':self.job_id,
                  'request':p.decode(self.binding)['request'],'status':'COMPLETE',
                  'bytes':len(payload),'sha256':_sha(payload)}
        if (type(header) is not dict or len(payload)>self.limits['max_output_bytes'] or type(header.get('bytes')) is not int
                or header!=expected):raise p.BoundaryError('POLICY_REJECTED')
        if _identity(self.output_fd) != self.output_identity or os.fstat(self.output_fd).st_size:
            raise p.BoundaryError('POLICY_REJECTED')
        _write(self.output_fd, frame)
        fcntl.fcntl(self.output_fd, fcntl.F_ADD_SEALS, SEALS)
        self.response_observed_ns=observed_ns
        self.completed = True

    def deliver(self, configuration):
        self.verify_limits(self.role,dict(self.limits))
        if (type(configuration) is not dict or set(configuration) != {'version','job','binding','input','output'}
                or any(type(configuration[k]) is not int for k in ('version','input','output'))
                or self.delivered or self.started_ns is None or configuration != self.configuration()):
            raise p.BoundaryError('POLICY_REJECTED')
        try:runtime = os.fstat(self.runtime_fd)
        except (OSError, TypeError):raise p.BoundaryError('POLICY_REJECTED') from None
        if (runtime.st_dev, runtime.st_ino) != self.runtime_identity:
            raise p.BoundaryError('POLICY_REJECTED')
        header, raw = _read(self.input_fd, MAX_INPUT, self.input_identity)
        expected = {'binding': _sha(self.binding), 'job': self.job_id, 'bytes': len(raw), 'sha256': _sha(raw)}
        if type(header) is not dict or type(header.get('bytes')) is not int or header != expected or _sha(raw) != p.decode(self.binding)['request']:
            raise p.BoundaryError('POLICY_REJECTED')
        if _identity(self.output_fd) != self.output_identity or os.fstat(self.output_fd).st_size != 0:
            raise p.BoundaryError('POLICY_REJECTED')
        self.delivered = True
        return raw

    def finish_recording(self, payload, *, success=True):
        """Synthetic adapter fixture only; not model provenance or authority."""
        if not self.delivered or self.completed:raise p.BoundaryError('INVALID_STATE')
        observed=self.clock()
        if type(observed) is not int or not self.started_ns<=observed<self.deadline_ns:
            raise p.BoundaryError('INVALID_STATE')
        if type(payload) is not bytes or not 0 < len(payload) <= self.limits['max_output_bytes'] or type(success) is not bool:
            raise p.BoundaryError('BOUNDS_EXCEEDED')
        if _identity(self.output_fd) != self.output_identity or os.fstat(self.output_fd).st_size != 0:
            raise p.BoundaryError('POLICY_REJECTED')
        _write(self.output_fd, _frame({'binding': _sha(self.binding), 'job': self.job_id,
            'request': p.decode(self.binding)['request'], 'status': 'COMPLETE' if success else 'ERROR',
            'bytes': len(payload), 'sha256': _sha(payload)}, payload))
        fcntl.fcntl(self.output_fd, fcntl.F_ADD_SEALS, SEALS)
        self.response_observed_ns=observed  # recording clock, NOT observed child timing
        self.completed = True

    def collect(self):
        if (not self.completed or self.collected or self.started_ns is None
                or type(self.response_observed_ns) is not int
                or not self.started_ns<=self.response_observed_ns<self.deadline_ns):
            raise p.BoundaryError('INVALID_STATE')
        header, raw = _read(self.output_fd, self.limits['max_output_bytes'], self.output_identity)
        expected = {'binding': _sha(self.binding), 'job': self.job_id,
            'request': p.decode(self.binding)['request'], 'status': 'COMPLETE',
            'bytes': len(raw), 'sha256': _sha(raw)}
        if type(header) is not dict or not raw or type(header.get('bytes')) is not int or header != expected:
            raise p.BoundaryError('POLICY_REJECTED')
        self.collected = True
        return TextResponse(self.job_id, expected['request'], _sha(raw), raw)

    def close(self):
        for name in ('input_fd', 'output_fd', 'response_read_fd', 'response_write_fd'):
            fd = getattr(self, name, None)
            setattr(self, name, None)  # ambiguous close must not retry a reused FD
            if fd is not None:
                try:os.close(fd)
                except OSError:self.close_failed = True
        if self.close_failed:raise p.BoundaryError('CLEANUP_INCOMPLETE')
