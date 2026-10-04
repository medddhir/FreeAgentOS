"""Development-only fixed export-group profiler; never a production runner.

Use the established controller interpreter. No target setting, cache replacement,
source discovery, hook imports, or qualification result is provided here.
"""
import contextlib
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

MAX_RECORDS = 16384
MAX_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 1024
RESERVED_RECORDS = 512
RESERVED_BYTES = 512 * 1024
MAX_LABEL = 100
MAX_DEPTH = 64
MAX_AGG_CALLS = 1000000
MAX_AGG_KEYS = 128
MAX_OUTPUT = 16384
GROUP_SECONDS = 180  # diagnostic containment, never a production lease override
ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / '.venv-orchestrator/bin/python3'


class Recorder:
    def __init__(self, fd):
        self.fd = fd
        self.records = self.bytes = self.ids = 0
        self.stack = []
        self.case = None
        self.totals = {}
        self.error = None
        self.io_ns = 0

    def emit(self, value, terminal=False):
        if self.error and not terminal:
            return  # preserve test/finalizer behavior; reject diagnostics afterward
        schemas = {
            'START': {'v','event','kind','label','id','parent','monotonic_ns'},
            'END': {'v','event','kind','label','id','parent','monotonic_ns','duration_ns','cpu_ns','outcome'},
            'AGGREGATE': {'v','event','kind','label','case','calls','duration_ns','cpu_ns','max_ns','failures'},
        }
        if (set(value) != schemas.get(value.get('event')) or value.get('v') != 1
                or value.get('kind') not in ('GROUP','CASE','FIXTURE','SETUP','TEARDOWN','PHASE','HASH_OR_READ')
                or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', value.get('label',''))):
            self.error = 'SIDECAR_SCHEMA'
            return
        raw = (json.dumps(value, separators=(',', ':'), allow_nan=False) + '\n').encode()
        record_limit = MAX_RECORDS if terminal else max(0, MAX_RECORDS-RESERVED_RECORDS)
        byte_limit = MAX_BYTES if terminal else max(0, MAX_BYTES-RESERVED_BYTES)
        if (len(raw) > MAX_RECORD_BYTES or self.records >= record_limit
                or self.bytes + len(raw) > byte_limit):
            self.error = 'SIDECAR_BOUND'
            return
        started = time.monotonic_ns()
        try:
            position = 0
            for _ in range(32):
                written = os.write(self.fd, raw[position:])
                if written <= 0:
                    raise OSError()
                position += written
                if position == len(raw):
                    break
            if position != len(raw):
                raise OSError()
            self.bytes += len(raw)
            self.records += 1
        except OSError:
            self.error = 'SIDECAR_WRITE_FAILED'
        finally:
            self.io_ns += time.monotonic_ns() - started

    @contextlib.contextmanager
    def span(self, kind, label):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', label) or len(self.stack) >= MAX_DEPTH:
            raise ValueError('DIAGNOSTIC_LABEL_OR_DEPTH')
        if kind in ('PHASE', 'SETUP', 'TEARDOWN') or kind == 'FIXTURE' and not label.startswith('rhs_'):
            key_label = 'rhs' if label.startswith('rhs_') else label
            start, cpu = time.monotonic_ns(), time.process_time_ns()
            failed = False
            try:
                yield
            except BaseException:
                failed = True
                raise
            finally:
                self.accumulate(kind+'.'+key_label, time.monotonic_ns()-start,
                                time.process_time_ns()-cpu, failed)
            return
        self.ids += 1
        identity = self.ids
        parent = self.stack[-1] if self.stack else None
        start = time.monotonic_ns()
        cpu = time.process_time_ns()
        self.emit(dict(v=1, event='START', kind=kind, label=label, id=identity,
                       parent=parent, monotonic_ns=start), terminal=kind in ('CASE','GROUP'))
        self.stack.append(identity)
        outcome = 'RETURN'
        try:
            yield
        except BaseException:
            outcome = 'RAISE'
            raise
        finally:
            self.stack.pop()
            end = time.monotonic_ns()
            self.emit(dict(v=1, event='END', kind=kind, label=label, id=identity,
                           parent=parent, monotonic_ns=end, duration_ns=end-start,
                           cpu_ns=time.process_time_ns()-cpu, outcome=outcome), terminal=kind in ('CASE','GROUP'))

    def wrap(self, function, label):
        @functools.wraps(function)
        def measured(*args, **kwargs):
            with self.span('PHASE', label):
                return function(*args, **kwargs)
        return measured

    def accumulate(self, label, duration, cpu, failed):
        key = (self.case, label)
        if key not in self.totals and len(self.totals) >= MAX_AGG_KEYS:
            self.error = self.error or 'AGGREGATE_BOUND'
            return
        value = self.totals.setdefault(key, [0, 0, 0, 0, 0])
        if value[0] >= MAX_AGG_CALLS:
            self.error = self.error or 'AGGREGATE_BOUND'
            return
        value[0] += 1
        value[1] += duration
        value[2] += cpu
        value[3] = max(value[3], duration)
        value[4] += int(failed)

    def flush(self):
        # At most MAX_AGG_KEYS terminal records; flush each case, never grow
        # keys with the number of repeated observations or source identities.
        for (case, label), (calls, duration, cpu, maximum, failures) in sorted(self.totals.items(), key=str):
            self.emit(dict(v=1, event='AGGREGATE', kind='HASH_OR_READ', label=label,
                           case=case, calls=calls, duration_ns=duration,
                           cpu_ns=cpu, max_ns=maximum, failures=failures), terminal=True)
        self.totals.clear()

    def aggregate(self, function, label):
        @functools.wraps(function)
        def measured(*args, **kwargs):
            start, cpu = time.monotonic_ns(), time.process_time_ns()
            failed = False
            try:
                return function(*args, **kwargs)
            except BaseException:
                failed = True
                raise
            finally:
                self.accumulate(label, time.monotonic_ns()-start,
                                time.process_time_ns()-cpu, failed)
        return measured

    def fixture(self, factory, label):
        @functools.wraps(factory)
        @contextlib.contextmanager
        def measured(*args, **kwargs):
            manager = factory(*args, **kwargs)
            with self.span('FIXTURE', label):
                with self.span('SETUP', label):
                    value = manager.__enter__()
                try:
                    yield value
                except BaseException:
                    with self.span('TEARDOWN', label):
                        suppressed = manager.__exit__(*sys.exc_info())
                    if not suppressed:
                        raise
                else:
                    with self.span('TEARDOWN', label):
                        manager.__exit__(None, None, None)
        return measured


def identity(pid):
    with open(f'/proc/{pid}/stat', 'rb') as file:
        raw = file.read(4097)
    if len(raw) > 4096:
        raise ValueError('PROCESS_IDENTITY_BOUND')
    fields = raw[raw.rfind(b')')+2:].split()
    return dict(pid=pid, start_ticks=int(fields[19]), pgid=int(fields[2]),
                session=int(fields[3]))


@contextlib.contextmanager
def owned_process(process):
    """Only our Popen(start_new_session=True) child; never a PID input API."""
    try:
        yield
    finally:
        try:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)
            else:
                process.wait(timeout=2)
        finally:
            process.stdout.close()


def child(directory):
    # Test modules and analyzer are trusted development code; staged sources are
    # parsed by their existing fixtures, never imported or executed.
    sys.path.insert(0, str(ROOT))
    from unittest.mock import patch
    from test_privilege_exports import ExportCases
    from test_privilege_closure_verify import IndependentClosureCases
    from test_privilege_installed_identity import InstalledIdentityCases
    from test_privilege_inventory import InventoryCases
    from orchestrator.privilege import closure_verify as v, build_closure as c
    from orchestrator.privilege import installed_identity as n, inventory as i
    from orchestrator.privilege import policy as p, policy_sources as ps
    fd = os.open(directory/'timing.jsonl', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    recorder = Recorder(fd)
    baseline_fds = set(os.listdir('/proc/self/fd'))
    started = time.monotonic_ns()
    status = 'FAIL'
    error_type = None
    try:
        with contextlib.ExitStack() as patches, recorder.span('GROUP', 'ExportCases.cases'):
            for cls, label in ((InventoryCases, 'inventory'), (InstalledIdentityCases, 'installed'),
                               (IndependentClosureCases, 'independent')):
                patches.enter_context(patch.object(cls, 'fixture', recorder.fixture(cls.fixture, label)))
            # Unique fixed-fixture RHS fingerprint distinguishes loop subcases
            # without recording bytes. No staged module is imported.
            original_rhs = ExportCases.ordinary_rhs_fixture
            @contextlib.contextmanager
            def rhs_fixture(self, rhs, **kwargs):
                label = 'rhs_'+hashlib.sha256(rhs).hexdigest()[:32]+'_star'+str(int(kwargs.get('star', False)))
                with recorder.fixture(original_rhs, label)(self, rhs, **kwargs) as value:
                    yield value
            patches.enter_context(patch.object(ExportCases, 'ordinary_rhs_fixture', rhs_fixture))
            for owner, name, label in ((InventoryCases, 'identities', 'identity_construction'),
                                       (i, 'prepare', 'inventory_plan'),
                                       (i.StagingInventory, 'capture', 'inventory_capture'),
                                       (n.StagingDependencies, 'capture', 'dependency_capture'),
                                       (n.StagingDependencies, 'recheck', 'dependency_recheck')):
                patches.enter_context(patch.object(owner, name, recorder.wrap(getattr(owner, name), label)))
            for owner, name, label in ((ps, '_read_source', 'source_read'),
                                       (ps, '_source_digest', 'source_policy_parse_hash'),
                                       (i, 'digest', 'json_identity_hash'),
                                       (p, 'source_identity', 'source_identity')):
                patches.enter_context(patch.object(owner, name, recorder.aggregate(getattr(owner, name), label)))
            prerequisite_depth = 0
            original_analyze = v.analyze
            original_gate = c.StagingClosureRegistration.candidate_prerequisite
            def analyze(*args, **kwargs):
                label = 'analysis_prerequisite' if prerequisite_depth else 'analysis_explicit'
                return recorder.wrap(original_analyze, label)(*args, **kwargs)
            def gate(*args, **kwargs):
                nonlocal prerequisite_depth
                with recorder.span('PHASE', 'candidate_prerequisite'):
                    prerequisite_depth += 1
                    try:
                        return original_gate(*args, **kwargs)
                    finally:
                        prerequisite_depth -= 1
            patches.enter_context(patch.object(v, 'analyze', analyze))
            patches.enter_context(patch.object(c.StagingClosureRegistration, 'candidate_prerequisite', staticmethod(gate)))
            for name in sorted(x for x in dir(ExportCases) if x.startswith('case_')):
                function = getattr(ExportCases, name)
                def measured(self, fn=function, label=name):
                    previous = recorder.case
                    recorder.case = label
                    try:
                        with recorder.span('CASE', label):
                            return fn(self)
                    finally:
                        recorder.flush()
                        recorder.case = previous
                patches.enter_context(patch.object(ExportCases, name, measured))
            ExportCases().cases()  # actual complete group, unchanged membership
        status = 'PASS'
    except BaseException as error:
        error_type = type(error).__name__  # no raw assertion/source/credential text
    finally:
        recorder.flush()
        remaining_fds = sorted(set(os.listdir('/proc/self/fd'))-baseline_fds)
        summary = dict(status=status, error_type=error_type, recorder_error=recorder.error,
                       elapsed_ns=time.monotonic_ns()-started, records=recorder.records,
                       sidecar_bytes=recorder.bytes, sidecar_write_ns=recorder.io_ns,
                       unexpected_fd_numbers=remaining_fds)
        os.close(fd)
    if recorder.error or remaining_fds:
        summary['status'] = 'FAIL'
    report = directory/'child-result.json'
    descriptor = os.open(report, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as file:
        json.dump(summary, file, sort_keys=True)
    return 0 if summary['status'] == 'PASS' else 1


def main():
    if Path(sys.prefix).absolute() != ROOT/'.venv-orchestrator':
        raise RuntimeError('ESTABLISHED_CONTROLLER_REQUIRED')
    if len(sys.argv) == 3 and sys.argv[1] == '--child':
        directory = Path(sys.argv[2])
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError('PRIVATE_DIAGNOSTIC_DIRECTORY_REQUIRED')
        return child(directory)
    if len(sys.argv) != 1:
        raise RuntimeError('FIXED_GROUP_ONLY')
    directory = Path(tempfile.mkdtemp(prefix='freeagent-export-timing-'))
    directory.chmod(0o700)
    fixtures = directory/'fixtures'
    fixtures.mkdir(mode=0o700)
    env = os.environ.copy()
    env['TMPDIR'] = str(fixtures)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    started = time.monotonic_ns()
    process = subprocess.Popen([str(PYTHON), str(Path(__file__).resolve()), '--child', str(directory)],
                               cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    with owned_process(process):
        launch = identity(process.pid)
        fd = os.open(directory/'launch.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as file:
            json.dump(dict(launch=launch, monotonic_ns=started, diagnostic_seconds=GROUP_SECONDS), file)
            file.flush()
            os.fsync(file.fileno())
        output = bytearray()
        timed_out = False
        overflow = False
        os.set_blocking(process.stdout.fileno(), False)
        deadline = time.monotonic()+GROUP_SECONDS
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                for key, _ in selector.select(0.1):
                    try:
                        block = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(key.fileobj)
                    elif len(output)+len(block) > MAX_OUTPUT:
                        overflow = True
                        break
                    else:
                        output.extend(block)
                if overflow:
                    break
    summary = dict(directory=str(directory), launch=launch, exit_code=process.returncode,
                   elapsed_ns=time.monotonic_ns()-started, timed_out=timed_out,
                   output_overflow=overflow, captured_bytes=len(output),
                   fixture_directory_empty=not any(fixtures.iterdir()), reaped=True,
                   output_pipe_closed=process.stdout.closed)
    fd = os.open(directory/'launch-result.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as file:
        json.dump(summary, file, sort_keys=True)
    print(json.dumps(summary, sort_keys=True))
    return 0 if process.returncode == 0 and not timed_out and not overflow and summary['fixture_directory_empty'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
