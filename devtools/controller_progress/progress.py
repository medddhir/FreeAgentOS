"""Bounded private unittest observations; never test or authority evidence."""
import atexit
import contextlib
import json
import os
from pathlib import Path
import re
import stat
import time
import types
import unittest

MAX_RECORDS = 16384
MAX_BYTES = 4*1024*1024
RESERVE_RECORDS = 1024
RESERVE_BYTES = 512*1024
MAX_RECORD_BYTES = 1024
MAX_DETAIL_TEXT = 256
MAX_DETAIL_FRAMES = 8


def failure_detail(test_id, error):
    """Metadata and an existing string argument only; never repr/str objects.

    No locals, environment, source lines, chained exceptions or absolute paths.
    This does not prove that an assertion's own message contains no private data.
    """
    kind, exception, tb = error
    name = kind.__name__
    if type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', name):
        name = 'UNAVAILABLE_TYPE'
    identifier = test_id if type(test_id) is str else 'UNAVAILABLE_LABEL'
    identifier = re.sub(r'[^A-Za-z0-9_.<>-]', '_', identifier[:160])
    args = BaseException.args.__get__(exception)
    has_message = type(args) is tuple and len(args) == 1 and type(args[0]) is str
    message = args[0][:MAX_DETAIL_TEXT] if has_message else ''
    frames = []
    frame_trimmed = False
    for _ in range(MAX_DETAIL_FRAMES):
        if type(tb) is not types.TracebackType:
            break
        code = tb.tb_frame.f_code
        filename = os.path.basename(code.co_filename)
        frame_trimmed = frame_trimmed or len(filename)>48 or len(code.co_name)>48
        frames.append('%s:%d in %s' % (filename[:48],
                                      tb.tb_lineno, code.co_name[:48]))
        tb = tb.tb_next
    trace = '\n'.join(frames)
    return dict(test_id=identifier, exception_type=name, message=message,
                message_omitted=not has_message, traceback=trace[:MAX_DETAIL_TEXT],
                truncated=(type(test_id) is str and len(test_id)>160
                           or has_message and len(args[0])>MAX_DETAIL_TEXT
                           or len(trace)>MAX_DETAIL_TEXT or frame_trimmed or tb is not None))

class Progress:
    def __init__(self, directory, filename='progress.jsonl'):
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('PRIVATE_PROGRESS_DIRECTORY_REQUIRED')
        self.directory=directory
        if filename not in ('progress.jsonl', 'runner-timing.jsonl'):
            raise ValueError('PROGRESS_FILENAME_INVALID')
        self.fd=os.open(directory/filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        self.count=self.bytes=self.sequence=self.write_ns=0
        self.error=None
    def event(self,event,label,outcome=None,identity=None,terminal=False,detail=None):
        if not isinstance(label,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}',label):label='UNAVAILABLE_LABEL'
        value=dict(version=1,event=event,label=label,outcome=outcome,identity=identity,monotonic_ns=time.monotonic_ns())
        if detail is not None:
            value['detail']=dict(detail)
            # Fit encoded JSON, including Unicode escaping, within the existing
            # record bound. At most eighteen halvings of two <=256-char fields.
            value['detail']['truncated']=bool(value['detail']['truncated'])
            for key in ('traceback','message'):
                while len((json.dumps(value,separators=(',',':'))+'\n').encode())>MAX_RECORD_BYTES and value['detail'][key]:
                    value['detail']['truncated']=True
                    text=value['detail'][key]
                    value['detail'][key]=text[:len(text)//2]
        raw=(json.dumps(value,separators=(',',':'))+'\n').encode()
        if self.error and not terminal:return False
        if len(raw)>MAX_RECORD_BYTES or self.count >= MAX_RECORDS-(0 if terminal else RESERVE_RECORDS) or self.bytes+len(raw)>MAX_BYTES-(0 if terminal else RESERVE_BYTES):
            self.error=self.error or 'PROGRESS_BOUND';return False
        start=time.monotonic_ns()
        try:
            offset=0
            for _ in range(32):
                n=os.write(self.fd,raw[offset:])
                if n<=0:raise OSError()
                offset+=n
                if offset==len(raw):break
            if offset!=len(raw):raise OSError()
            self.count+=1;self.bytes+=len(raw);return True
        except OSError:self.error=self.error or 'PROGRESS_WRITE_FAILED';return False
        finally:self.write_ns+=time.monotonic_ns()-start
    def finish(self):
        self.event('PROCESS_END','controller_unittest',terminal=True)
        value=dict(diagnostic_error=self.error,records=self.count,bytes=self.bytes,write_ns=self.write_ns)
        fd=os.open(self.directory/'progress-result.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as file:json.dump(value,file)
        os.close(self.fd)
        # Separate bounded publication: the timestamp follows result publication
        # and progress FD closure, but does not claim interpreter/process exit.
        try:
            raw=(json.dumps(dict(event='OBSERVER_SHUTDOWN_COMPLETE',
                                monotonic_ns=time.monotonic_ns()))+'\n').encode()
            fd=os.open(self.directory/'observer-shutdown.json',
                       os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as file:file.write(raw)
        except Exception:
            pass  # Optional observation cannot replace unittest's outcome.


class RunnerTiming(Progress):
    """One launch, fixed events; at most 32 records / 32 KiB, no polling."""
    def __init__(self, directory):
        super().__init__(directory, 'runner-timing.jsonl')
    def record(self, event, value=None):
        if event not in ('DEADLINE_CREATED', 'STDOUT_EOF', 'CHILD_EXIT_OBSERVED',
                         'TIMEOUT_DECISION', 'SIGTERM_ATTEMPT', 'SIGKILL_ATTEMPT',
                         'WAIT_COMPLETE', 'RUNNER_CLASSIFIED'):
            return
        if value is not None and type(value) not in (int, float):return
        if self.count >= 32 or self.bytes >= 32768:return
        self.event(event, 'controller_runner', identity=value, terminal=True)
    def close(self):
        os.close(self.fd)

def instrument(recorder):
    """Delegate discovery/results/subtest contexts; preserve exceptions and return values."""
    original_start=unittest.TextTestResult.startTest
    original_stop=unittest.TextTestResult.stopTest
    outcomes={}
    def event(*args,**kwargs):
        try:return recorder.event(*args,**kwargs)
        except Exception:
            recorder.error=recorder.error or 'PROGRESS_DIAGNOSTIC_FAILED'
            return False
    def failure(test,error,state):
        try:
            label=test.id()
            detail=failure_detail(label,error)
            # Detail consumes normal capacity, never terminal reservations.
            event('FAILURE_DETAIL',label,state,detail=detail)
        except Exception:
            recorder.error=recorder.error or 'PROGRESS_DIAGNOSTIC_FAILED'
    def start(result,test):
        outcomes[id(test)]='UNAVAILABLE'
        event('TEST_START',test.id())
        return original_start(result,test)
    def stop(result,test):
        try:return original_stop(result,test)
        finally:event('TEST_END',test.id(),outcomes.pop(id(test),'UNAVAILABLE'),terminal=True)
    unittest.TextTestResult.startTest=start
    unittest.TextTestResult.stopTest=stop
    for name,status in [('addSuccess','PASS'),('addFailure','FAIL'),('addError','ERROR'),('addSkip','SKIP'),('addExpectedFailure','EXPECTED_FAILURE'),('addUnexpectedSuccess','UNEXPECTED_SUCCESS')]:
        original=getattr(unittest.TextTestResult,name)
        def observed(result,test,*args,fn=original,state=status):
            outcomes[id(test)]=state
            if state in ('FAIL','ERROR','EXPECTED_FAILURE') and args:
                failure(test,args[0],state)
            return fn(result,test,*args)
        setattr(unittest.TextTestResult,name,observed)
    sub_original=unittest.TestCase.subTest
    @contextlib.contextmanager
    def subtest(test,msg=unittest.case._subtest_msg_sentinel,**params):
        label=params.get('case','subcase')
        recorder.sequence+=1
        identity=recorder.sequence
        event('SUBCASE_START',label,identity=identity)
        try:
            with sub_original(test,msg,**params):yield
        finally:event('SUBCASE_END',label,'CONTEXT_EXIT',identity,terminal=True)
    unittest.TestCase.subTest=subtest
    sub_result=unittest.TextTestResult.addSubTest
    def result_sub(result,test,subtest,error):
        state='PASS' if error is None else 'FAIL' if issubclass(error[0],test.failureException) else 'ERROR'
        if error is not None:
            outcomes[id(test)]=state
            failure(test,error,state)
        event('SUBCASE_RESULT','subcase',state,terminal=True)
        return sub_result(result,test,subtest,error)
    unittest.TextTestResult.addSubTest=result_sub

def install(directory):
    recorder=Progress(directory)
    raw=Path('/proc/self/stat').read_bytes()[:4096];fields=raw[raw.rfind(b')')+2:].split()
    identity=dict(pid=os.getpid(),ppid=os.getppid(),start_ticks=int(fields[19]),pgid=os.getpgrp(),session=os.getsid(0),monotonic_ns=time.monotonic_ns())
    fd=os.open(directory/'unittest-launch.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as file:json.dump(identity,file);file.flush();os.fsync(file.fileno())
    recorder.event('PROCESS_START','controller_unittest')
    instrument(recorder)
    atexit.register(recorder.finish)
