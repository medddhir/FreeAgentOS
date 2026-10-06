"""Fixed development-only four-path fixture profiler; no production activation."""
import contextlib
import functools
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import time
from unittest.mock import patch
from devtools.export_timing import Recorder, identity

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / '.venv-orchestrator/bin/python3'
TEST = 'test_intermediate_repair.IntermediateRepairTests.test_unauthorized_repair_paths_block'
OUTER_SECONDS = 4 * (150 + 2 * 130 + 20) + 60
MAX_CAPTURE = 65536
LABELS = frozenset(('fixture_setup','fixture_cleanup','workspace_prepare','workspace_git',
                    'validation_discovery','validation_testing','sandbox_launch_wait',
                    'sandbox_wait','rollback','cleanup'))


def cpu():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return (own.ru_utime + own.ru_stime, children.ru_utime + children.ru_stime)


class Measurements:
    def __init__(self, recorder):
        self.recorder = recorder
        self.totals = {}
        self.stack = []
        self.error = None
        self.launches = []
        self.owned_runs = []

    def wrap(self, fn, label):
        if label not in LABELS:
            raise ValueError('PROFILE_LABEL')
        @functools.wraps(fn)
        def measured(*args, **kwargs):
            try:
                start = time.monotonic_ns(); before = cpu()
            except Exception:
                self.error = 'PROFILE_DIAGNOSTIC_FAILED'
                return fn(*args, **kwargs)
            frame = [0]
            self.stack.append(frame); failed = False
            try:
                return fn(*args, **kwargs)
            except BaseException:
                failed = True
                raise
            finally:
                elapsed = time.monotonic_ns() - start
                self.stack.pop()
                if self.stack:
                    self.stack[-1][0] += elapsed
                try:
                    after = cpu()
                    total = self.totals.setdefault(label, dict(calls=0, elapsed_ns=0,
                        exclusive_instrumented_ns=0, self_cpu_seconds=0.0,
                        reaped_children_cpu_seconds=0.0, exceptions=0))
                    if total['calls'] >= 1000000:
                        raise ValueError('PROFILE_CALL_BOUND')
                    total['calls'] += 1; total['elapsed_ns'] += elapsed
                    total['exclusive_instrumented_ns'] += max(0, elapsed-frame[0])
                    total['self_cpu_seconds'] += max(0, after[0]-before[0])
                    total['reaped_children_cpu_seconds'] += max(0, after[1]-before[1])
                    total['exceptions'] += int(failed)
                    self.recorder.accumulate('PHASE.'+label,elapsed,
                        int(max(0,after[0]-before[0])*1e9),failed)
                except Exception:
                    self.error = 'PROFILE_DIAGNOSTIC_FAILED'
        return measured

    @contextlib.contextmanager
    def patches(self, targets):
        with contextlib.ExitStack() as stack:
            for owner, name, label in targets:
                stack.enter_context(patch.object(owner,name,self.wrap(getattr(owner,name),label)))
            yield


def save(directory, name, value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    if len(raw)>65536:
        raise ValueError('PROFILE_SUMMARY_BOUND')
    fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw)


def child(directory):
    import unittest
    import test_intermediate_repair as fixture
    from roles import workspace, sandbox
    graph=fixture.graph
    fd=os.open(directory/'timing.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    recorder=Recorder(fd);m=Measurements(recorder)
    # No arbitrary project setting, test discovery, model launch or alternate test path.
    targets=[(fixture.IntermediateRepairTests,'setUp','fixture_setup'),
             (unittest.TestCase,'doCleanups','fixture_cleanup'),
             (graph,'prepare_workspace_node','workspace_prepare'),
             (workspace,'run_git','workspace_git'),
             (graph,'discovery_baseline_node','validation_discovery'),
             (graph,'tested_unit_node','validation_testing'),
             (graph,'rollback_node','rollback'),(graph,'finish_workspace','cleanup'),
             (sandbox,'_run_isolated_in_area','sandbox_launch_wait')]
    original_prepare=graph.prepare_workspace_node
    def prepare(*args,**kwargs):
        value=original_prepare(*args,**kwargs)
        try:
            path=value.get('run_dir')
            if path:
                p=Path(path);st=p.lstat()
                if len(m.owned_runs)<4:
                    m.owned_runs.append({'path':str(p),'device':st.st_dev,'inode':st.st_ino})
        except Exception:m.error='PROFILE_OWNERSHIP_OBSERVATION_FAILED'
        return value
    original_wait=sandbox._read_bounded
    def wait(proc,*args,**kwargs):
        try:
            if len(m.launches)<12:m.launches.append(identity(proc.pid))
        except Exception:m.error='PROFILE_IDENTITY_UNAVAILABLE'
        return original_wait(proc,*args,**kwargs)
    original_invoke=fixture.IntermediateRepairTests.invoke
    invocations=0
    def invoke(*args,**kwargs):
        nonlocal invocations
        invocations+=1
        if invocations>4:
            m.error='PROFILE_INVOCATION_BOUND'
            return original_invoke(*args,**kwargs)
        with recorder.span('CASE','invoke_'+str(invocations)):
            return original_invoke(*args,**kwargs)
    started=time.monotonic_ns();before=cpu()
    try:
        with patch.object(graph,'prepare_workspace_node',prepare), \
                patch.object(sandbox,'_read_bounded',m.wrap(wait,'sandbox_wait')), \
                patch.object(fixture.IntermediateRepairTests,'invoke',invoke), \
                m.patches(targets),recorder.span('GROUP','four_path_repair'):
            suite=unittest.defaultTestLoader.loadTestsFromName(TEST)
            result=unittest.TextTestRunner(verbosity=2).run(suite)
        status='PASS' if result.wasSuccessful() else 'FAIL'
    finally:
        try:recorder.flush()
        finally:os.close(fd)
    after=cpu()
    save(directory,'phase-result.json',dict(status=status,tests=result.testsRun,
        failures=len(result.failures),errors=len(result.errors),elapsed_seconds=(time.monotonic_ns()-started)/1e9,
        self_cpu_seconds=after[0]-before[0],reaped_children_cpu_seconds=after[1]-before[1],
        phases=m.totals,diagnostic_error=m.error or recorder.error,
        invocations=invocations,diagnostic_records=recorder.records,diagnostic_bytes=recorder.bytes,diagnostic_io_ns=recorder.io_ns,
        launch_identity=identity(os.getpid()),sandbox_launches=m.launches,
        owned_runs=[{**x,'currently_absent':not Path(x['path']).exists()} for x in m.owned_runs],
        cpu_limits='RUSAGE_CHILDREN includes only reaped children and descendants whose CPU was propagated on wait; late reaping charges the wait interval. No cgroup CPU or all-descendant accounting.',
        timing_limits='Elapsed/CPU phase totals overlap. exclusive_instrumented_ns subtracts directly nested wrapped intervals only; remaining time includes uninstrumented work and waits. No host-cause attribution.'))
    return 0 if status=='PASS' and not(m.error or recorder.error) else 1


def main():
    directory=Path(sys.argv[2]).resolve(strict=True)
    st=directory.lstat()
    if not directory.is_dir() or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o700:
        raise ValueError('PRIVATE_PROFILE_DIRECTORY_REQUIRED')
    if sys.argv[1]=='--child':return child(directory)
    if sys.argv[1]!='--run':raise ValueError('PROFILE_MODE')
    save(directory,'invocation.json',{'test':TEST,'argv':[str(PYTHON),'-m','devtools.repair_timing','--child',str(directory)],'outer_seconds':OUTER_SECONDS,'capture_bytes':MAX_CAPTURE,'cwd':str(ROOT),'budget_basis':'4*(150 discovery + 2*130 testing +20 collection)+60 setup/collection; diagnostic bound, not complete worst-case guarantee for unbounded fixture Git setup.'})
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1'
    start=time.monotonic();proc=subprocess.Popen([str(PYTHON),'-m','devtools.repair_timing','--child',str(directory)],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    output=bytearray();reason=None
    try:
        save(directory,'launch.json',identity(proc.pid))
        os.set_blocking(proc.stdout.fileno(),False)
        with selectors.DefaultSelector() as select:
            select.register(proc.stdout,selectors.EVENT_READ)
            eof=False
            while not eof or proc.poll() is None:
                if time.monotonic()-start>=OUTER_SECONDS:reason='TIMEOUT';break
                for key,_ in select.select(0.1):
                    try:part=os.read(key.fd,4096)
                    except BlockingIOError:continue
                    if not part:select.unregister(proc.stdout);eof=True;break
                    if len(output)+len(part)>MAX_CAPTURE:
                        output.extend(part[:MAX_CAPTURE-len(output)]);reason='OUTPUT_BOUND';break
                    output.extend(part)
                if reason:break
    except BaseException:
        reason='PROFILE_COLLECTION_FAILED'
        raise
    finally:
        if proc.poll() is None:
            try:os.killpg(proc.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=3)
        else:proc.wait()
        proc.stdout.close()
        fd=os.open(directory/'profile.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(output)
        save(directory,'wrapper-result.json',dict(exit_code=proc.returncode,reason=reason,
            elapsed_seconds=time.monotonic()-start,capture_bytes=len(output),direct_child_reaped=True,
            direct_pid_currently_absent=not Path('/proc/'+str(proc.pid)).exists()))
    return 0 if proc.returncode==0 and reason is None else 1

if __name__=='__main__':sys.exit(main())
