"""Bounded private unittest observations; never test or authority evidence."""
import atexit
import contextlib
import json
import os
from pathlib import Path
import re
import stat
import time
import unittest

MAX_RECORDS = 16384
MAX_BYTES = 4*1024*1024
RESERVE_RECORDS = 1024
RESERVE_BYTES = 512*1024
MAX_RECORD_BYTES = 1024

class Progress:
    def __init__(self, directory):
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('PRIVATE_PROGRESS_DIRECTORY_REQUIRED')
        self.directory=directory
        self.fd=os.open(directory/'progress.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        self.count=self.bytes=self.sequence=self.write_ns=0
        self.error=None
    def event(self,event,label,outcome=None,identity=None,terminal=False):
        if not isinstance(label,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}',label):label='UNAVAILABLE_LABEL'
        value=dict(version=1,event=event,label=label,outcome=outcome,identity=identity,monotonic_ns=time.monotonic_ns())
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

def instrument(recorder):
    """Delegate discovery/results/subtest contexts; preserve exceptions and return values."""
    original_start=unittest.TextTestResult.startTest
    original_stop=unittest.TextTestResult.stopTest
    outcomes={}
    def start(result,test):
        outcomes[id(test)]='UNAVAILABLE'
        recorder.event('TEST_START',test.id())
        return original_start(result,test)
    def stop(result,test):
        try:return original_stop(result,test)
        finally:recorder.event('TEST_END',test.id(),outcomes.pop(id(test),'UNAVAILABLE'),terminal=True)
    unittest.TextTestResult.startTest=start
    unittest.TextTestResult.stopTest=stop
    for name,status in [('addSuccess','PASS'),('addFailure','FAIL'),('addError','ERROR'),('addSkip','SKIP'),('addExpectedFailure','EXPECTED_FAILURE'),('addUnexpectedSuccess','UNEXPECTED_SUCCESS')]:
        original=getattr(unittest.TextTestResult,name)
        def observed(result,test,*args,fn=original,state=status):
            outcomes[id(test)]=state
            return fn(result,test,*args)
        setattr(unittest.TextTestResult,name,observed)
    sub_original=unittest.TestCase.subTest
    @contextlib.contextmanager
    def subtest(test,msg=unittest.case._subtest_msg_sentinel,**params):
        label=params.get('case','subcase')
        recorder.sequence+=1
        identity=recorder.sequence
        recorder.event('SUBCASE_START',label,identity=identity)
        try:
            with sub_original(test,msg,**params):yield
        finally:recorder.event('SUBCASE_END',label,'CONTEXT_EXIT',identity,terminal=True)
    unittest.TestCase.subTest=subtest
    sub_result=unittest.TextTestResult.addSubTest
    def result_sub(result,test,subtest,error):
        state='PASS' if error is None else 'FAIL' if issubclass(error[0],test.failureException) else 'ERROR'
        if error is not None:outcomes[id(test)]=state
        recorder.event('SUBCASE_RESULT','subcase',state,terminal=True)
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
