"""TI-JOB-1 descriptor ABI, not admission or an installed model adapter.

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
    def __init__(self, plan, record, entry):
        from ..roles.worker import TextInferencePlan, prepare_text_inference, WorkerBoundaryError, TEXT_INFERENCE_PROFILE
        if type(plan) is not TextInferencePlan or entry.validation or entry.execution != 'MODEL_WORKER':
            raise p.BoundaryError('POLICY_REJECTED')
        try:
            if type(plan.request) is not bytes or not 0 < len(plan.request) <= MAX_INPUT:
                raise ValueError()
            request = json.loads(plan.request, object_pairs_hook=p._pairs)
            checked = prepare_text_inference(request, runtime_sha256=plan.runtime_sha256,
                executable_sha256=plan.executable_sha256, invocation=plan.invocation,
                credential_reference=plan.credential_reference, policy_sha256=plan.policy_sha256)
            if checked != plan or plan.policy_sha256 != record['policy'] or plan.executable_sha256 != entry.executable.digest:
                raise ValueError()
        except (ValueError, TypeError, UnicodeError, RecursionError, WorkerBoundaryError):
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
            'executable_observed': entry.executable.digest})
        runtime = os.fstat(entry.runtime_fd)
        if not stat.S_ISDIR(runtime.st_mode) or os.get_inheritable(entry.runtime_fd):
            raise p.BoundaryError('POLICY_REJECTED')
        self.runtime_fd = entry.runtime_fd
        self.runtime_identity = (runtime.st_dev, runtime.st_ino)
        self.input_fd = self.output_fd = None
        self.delivered = self.completed = self.collected = False
        self.close_failed = False
        try:
            self.input_fd = os.memfd_create('freeagent-text-input', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self.output_fd = os.memfd_create('freeagent-text-output', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self.input_identity = _identity(self.input_fd);self.output_identity = _identity(self.output_fd)
            _write(self.input_fd, _frame({'binding': _sha(self.binding), 'job': self.job_id, 'bytes': len(plan.request), 'sha256': plan.request_sha256}, plan.request))
            fcntl.fcntl(self.input_fd, fcntl.F_ADD_SEALS, SEALS)
        except Exception:
            self.close()
            raise

    def configuration(self):
        """Internal two-resource ABI; never changes the six-FD child schema.

        Future enrolled adapter maps request to read-only FD 3 and response to
        FD 4, with fixed --broker-job JOB argv. Today only RecordingDriver uses
        this mapping; LinuxDriver has no admitted producer for it.
        """
        if self.input_fd is None or self.output_fd is None:raise p.BoundaryError('INVALID_STATE')
        return {'version': 1, 'job': self.job_id, 'binding': _sha(self.binding),
                'input': self.input_fd, 'output': self.output_fd}

    def verify_owner(self, record, entry):
        binding = p.decode(self.binding)
        if (binding['job'] != self.job_id or binding['handle'] != record['handle']
                or binding['owner'] != record['owner'] or binding['backend_run'] != record['run_id']
                or entry.validation or binding['executable_observed'] != entry.executable.digest):
            raise p.BoundaryError('POLICY_REJECTED')
        runtime = os.fstat(entry.runtime_fd)
        if (runtime.st_dev, runtime.st_ino) != self.runtime_identity:
            raise p.BoundaryError('POLICY_REJECTED')

    def deliver(self, configuration):
        if (type(configuration) is not dict or set(configuration) != {'version','job','binding','input','output'}
                or any(type(configuration[k]) is not int for k in ('version','input','output'))
                or self.delivered or configuration != self.configuration()):
            raise p.BoundaryError('POLICY_REJECTED')
        runtime = os.fstat(self.runtime_fd)
        if (runtime.st_dev, runtime.st_ino) != self.runtime_identity:
            raise p.BoundaryError('POLICY_REJECTED')
        header, raw = _read(self.input_fd, MAX_INPUT, self.input_identity)
        expected = {'binding': _sha(self.binding), 'job': self.job_id, 'bytes': len(raw), 'sha256': _sha(raw)}
        if header != expected or _sha(raw) != p.decode(self.binding)['request']:
            raise p.BoundaryError('POLICY_REJECTED')
        if _identity(self.output_fd) != self.output_identity or os.fstat(self.output_fd).st_size != 0:
            raise p.BoundaryError('POLICY_REJECTED')
        self.delivered = True
        return raw

    def finish_recording(self, payload, *, success=True):
        """Synthetic adapter fixture only; not model provenance or authority."""
        if not self.delivered or self.completed:raise p.BoundaryError('INVALID_STATE')
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_OUTPUT or type(success) is not bool:
            raise p.BoundaryError('BOUNDS_EXCEEDED')
        if _identity(self.output_fd) != self.output_identity or os.fstat(self.output_fd).st_size != 0:
            raise p.BoundaryError('POLICY_REJECTED')
        _write(self.output_fd, _frame({'binding': _sha(self.binding), 'job': self.job_id,
            'request': p.decode(self.binding)['request'], 'status': 'COMPLETE' if success else 'ERROR',
            'bytes': len(payload), 'sha256': _sha(payload)}, payload))
        fcntl.fcntl(self.output_fd, fcntl.F_ADD_SEALS, SEALS)
        self.completed = True

    def collect(self):
        if not self.completed or self.collected:raise p.BoundaryError('INVALID_STATE')
        header, raw = _read(self.output_fd, MAX_OUTPUT, self.output_identity)
        expected = {'binding': _sha(self.binding), 'job': self.job_id,
            'request': p.decode(self.binding)['request'], 'status': 'COMPLETE',
            'bytes': len(raw), 'sha256': _sha(raw)}
        if header != expected:raise p.BoundaryError('POLICY_REJECTED')
        self.collected = True
        return TextResponse(self.job_id, expected['request'], _sha(raw), raw)

    def close(self):
        for name in ('input_fd', 'output_fd'):
            fd = getattr(self, name, None)
            setattr(self, name, None)  # ambiguous close must not retry a reused FD
            if fd is not None:
                try:os.close(fd)
                except OSError:self.close_failed = True
        if self.close_failed:raise p.BoundaryError('CLEANUP_INCOMPLETE')
