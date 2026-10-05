"""Text ABI v2 construction/collection. No admission or runtime provisioning.

FD 3: sealed read-only request frame; FD 4: write-only response pipe.
The controller owns the pipe reader and result storage. Retained adapter pipe
duplicates can withhold EOF, never enlarge controller storage or prove success.
"""
import fcntl
import os
import select
import stat
import threading
import time
from .protocol import BoundaryError
from .text_job import MAX_HEADER, MAX_OUTPUT

MAX_FRAME = 4 + MAX_HEADER + MAX_OUTPUT
CLEANUP_SECONDS = 2


def configuration(entry, limits, fds, job=None):
    from .child import validate_configuration
    c = dict(version=1, **{'class': entry.execution}, role=entry.role,
             uid=entry.uid, gid=entry.gid, job_id=entry.job_id,
             validation=entry.validation, fds=list(fds), limits=limits)
    if job is not None:
        if entry.validation or entry.execution != 'MODEL_WORKER':
            raise BoundaryError('POLICY_REJECTED')
        c['limits']=job.verify_limits(entry.role,limits)
        if job.started_ns is None:raise BoundaryError('INVALID_STATE')
        job.verify_descriptors()
        c.update(version=2, job_id=job.job_id,
                 text={'abi': 2, 'job': job.job_id,
                       'binding': job.configuration()['binding'],
                       'started_ns': job.started_ns, 'deadline_ns': job.deadline_ns,
                       'input_identity': list(job.input_identity),
                       'output_identity': list(job.pipe_identity)})
        c['fds'].extend((job.input_fd, job.response_write_fd))
    # Preserve v1 parent behavior: the child is its existing validation point.
    return validate_configuration(c) if job is not None else c


def verify_descriptors(c, *, complete=False):
    """Checks inherited objects before privileged setup, not caller path names."""
    try:
        request, response = c['fds'][6:]
        ri, ro = os.fstat(request), os.fstat(response)
        if (not stat.S_ISREG(ri.st_mode) or not stat.S_ISFIFO(ro.st_mode)
                or [ri.st_dev, ri.st_ino] != c['text']['input_identity']
                or [ro.st_dev, ro.st_ino] != c['text']['output_identity']
                or fcntl.fcntl(request, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                or fcntl.fcntl(response, fcntl.F_GETFL) & os.O_ACCMODE != os.O_WRONLY):
            raise BoundaryError('POLICY_REJECTED')
        from .text_job import SEALS, MAX_INPUT
        if (fcntl.fcntl(request, fcntl.F_GET_SEALS) & SEALS != SEALS
                or not 4 < ri.st_size <= 4 + MAX_HEADER + MAX_INPUT):
            raise BoundaryError('POLICY_REJECTED')
        if complete:
            # The helper descriptors remain six fixed roles. No alias of an
            # I/O resource may masquerade as a directory, executable or receipt.
            predicates=(stat.S_ISDIR,stat.S_ISDIR,stat.S_ISDIR,
                        stat.S_ISREG,stat.S_ISFIFO,stat.S_ISFIFO)
            modes=(os.O_RDONLY,)*5+(os.O_WRONLY,)
            seen={(ri.st_dev,ri.st_ino),(ro.st_dev,ro.st_ino)}
            for fd,predicate,mode in zip(c['fds'][:6],predicates,modes):
                info=os.fstat(fd)
                if (not predicate(info.st_mode)
                        or (info.st_dev,info.st_ino) in seen
                        or fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE!=mode):
                    raise BoundaryError('POLICY_REJECTED')
                seen.add((info.st_dev,info.st_ino))
    except (OSError, ValueError, TypeError, KeyError):
        raise BoundaryError('POLICY_REJECTED') from None


def exec_contract(c):
    """Constructed argv/environment, NOT observed exec or model evidence."""
    from .execution import FLAGS
    from .policy import worker_environment
    argv = ['freeagentos-worker', '--synthetic'] if c['validation'] else [
        'freeagentos-worker', *FLAGS[c['class']], c['job_id']]
    environment = worker_environment({})
    environment.update(HOME='/home', TMPDIR='/tmp')
    if c.get('version',1) == 2:
        # Enrolled ELF adapter ABI, not the prepared Claude CLI/prompt argv.
        environment = {'PATH': '/usr/bin:/bin', 'HOME': '/home',
                       'TMPDIR': '/tmp', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    return argv, environment


def map_descriptors(c):
    """Collision-safe fixed mapping after dropping privileges; no extra FDs.

    Duplicate every survivor before overwriting 3/4. Failure closes temporary
    duplicates and aborts exec; the owned child must exit, not retry setup.
    """
    verify_descriptors(c)
    copies = []
    try:
        for fd in (c['fds'][3], c['fds'][5], *c['fds'][6:]):
            copies.append(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10))
        executable, receipt, request, response = copies
        os.dup2(request, 3, inheritable=True)
        os.dup2(response, 4, inheritable=True)
        for fd in (request,response):
            copies.remove(fd)  # ambiguous close must not retry its number
            os.close(fd)
        keep = {3, 4, executable, receipt}
        for name in os.listdir('/proc/self/fd'):
            fd = int(name)
            if fd > 2 and fd not in keep:
                try: os.close(fd)
                except OSError as e:
                    # proc enumeration may include its already-closed reader.
                    import errno
                    if e.errno != errno.EBADF: raise
        copies.clear()  # ownership of exec/receipt transfers to ChildRoutine
        return executable, receipt
    except (OSError, ValueError, TypeError):
        raise BoundaryError('BACKEND_FAILURE') from None
    finally:
        for fd in copies:
            try: os.close(fd)
            except OSError: pass  # child aborts; never a cleanup proof


class TextCollector:
    """Owned pipe + direct child outcome; bounded EOF collection, no claims.

    Same thread/select lifecycle as SyntheticCollector. This is wired but not
    admitted on Linux; tests inject read/select/child operations, never launch.
    """
    def __init__(self, job, child, *, clock=None):
        self.job, self.child, self.clock = job, child, job.clock if clock is None else clock
        self.stop = threading.Event()
        self.thread = None
        self.close_failed = False
        self.error = None

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True,
                                       name='freeagentos-text-collector')
        self.thread.start()

    def _run(self):
        raw = bytearray()
        try:
            self.job.verify_response_reader()
            fd = self.job.response_read_fd
            os.set_blocking(fd, False)
            if self.job.deadline_ns is None:raise BoundaryError('INVALID_STATE')
            maximum = 4 + MAX_HEADER + self.job.limits['max_output_bytes']
            eof = False
            while True:
                if self.stop.is_set(): raise BoundaryError('INVALID_STATE')
                observed=self.clock()
                remaining = (self.job.deadline_ns-observed)/1000000000
                if remaining <= 0: raise BoundaryError('BACKEND_FAILURE')
                outcome=self.child.poll()
                # Reobserve time AFTER poll: a slow outcome observation cannot
                # qualify a response using an earlier pre-deadline timestamp.
                if eof and outcome is not None:
                    self.job.accept_response(bytes(raw),exit_code=outcome,eof=True,observed_ns=self.clock())
                    break
                if not eof and select.select([fd], [], [], min(.05, remaining))[0]:
                    try: block = os.read(fd, min(4096, maximum + 1 - len(raw)))
                    except BlockingIOError: continue
                    if not block: eof = True
                    else: raw.extend(block)
                    if len(raw) > maximum: raise BoundaryError('BOUNDS_EXCEEDED')
                elif eof:
                    self.stop.wait(min(.05, remaining))
        except Exception as e:
            self.error = e.code if isinstance(e, BoundaryError) else 'BACKEND_FAILURE'
        finally:
            self.job.close_response_reader()
            self.close_failed = self.job.close_failed

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(CLEANUP_SECONDS)
            if self.thread.is_alive():
                self.close_failed = True
                raise BoundaryError('CLEANUP_INCOMPLETE')
        if self.close_failed: raise BoundaryError('CLEANUP_INCOMPLETE')
