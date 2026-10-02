"""Bounded synthetic-only pipe evidence. Claims are not kernel enforcement proof."""
import json
import os
import select
import threading
import time
from . import protocol as p

MAX_OUTPUT=2048
MAX_RECORD=1024
MAX_RECORDS=2
MAX_RECEIPT=64
COLLECTION_SECONDS=10.0
FIXTURE='FREEAGENTOS_SYNTHETIC_V2'
BINDING=('handle','run_id','owner','policy','class','role','executable_sha256')
CLAIMS=('uid','gid','pid','pid_ns','mount_ns','capabilities_clear','no_new_privs','host_root_visible')
REASONS=('PENDING','COMPLETE','OUTPUT_MISSING','OUTPUT_TRUNCATED','OUTPUT_INVALID',
         'OUTPUT_OVERSIZED','OUTPUT_CONTRADICTORY','EXEC_FAILED','RECEIPT_INVALID',
         'COLLECTION_TIMEOUT','COLLECTION_CLOSED','COLLECTOR_FAILURE','COLLECTOR_CLOSE_FAILED',
         'COMPLETION_MISSING','EXIT_NONZERO','EVIDENCE_UNAVAILABLE')


def validate_binding(value):
    p.keys(value,BINDING)
    for k in ('handle','run_id','owner'):
        if not p.identifier(value[k]):raise p.BoundaryError('INVALID_REQUEST')
    for k in ('policy','executable_sha256'):
        if not p.identifier(value[k],64):raise p.BoundaryError('POLICY_REJECTED')
    from .policy import execution_class
    execution_class(value['class'],value['role'])
    return value


def binding(record,entry):
    return validate_binding({**{k:record[k] for k in BINDING if k!='executable_sha256'},
                             'executable_sha256':entry.executable.digest})


def empty(identity):
    return {'schema_version':1,**identity,'status':'UNAVAILABLE','reason':'EVIDENCE_UNAVAILABLE',
            'launcher_ready':False,'receipt_eof':False,'output_eof':False,'executable_transition':'UNPROVEN',
            'completion':'UNPROVEN','exit_status':'UNAVAILABLE','output_bytes':0,'record_count':0,
            'child_claims':{},'enforcement':'UNPROVEN','collector_closed':True}


def validate(value,identity):
    validate_binding(identity)
    expected=empty(identity);p.keys(value,tuple(expected))
    if (type(value['schema_version']) is not int or value['schema_version']!=1
            or any(type(value[k]) is not type(v) or value[k]!=v for k,v in identity.items())
            or value['enforcement']!='UNPROVEN' or value['status'] not in ('PENDING','VALID','INCOMPLETE','REJECTED','UNAVAILABLE')
            or value['reason'] not in REASONS or value['completion'] not in ('SUCCESS','UNPROVEN')
            or value['executable_transition'] not in ('FIXTURE_STARTED','UNPROVEN')
            or value['exit_status'] not in ('ZERO','NONZERO','UNAVAILABLE')
            or any(type(value[k]) is not bool for k in ('launcher_ready','receipt_eof','output_eof','collector_closed'))
            or type(value['output_bytes']) is not int or not 0<=value['output_bytes']<=MAX_OUTPUT+1
            or type(value['record_count']) is not int or not 0<=value['record_count']<=MAX_RECORDS):
        raise p.BoundaryError('INVALID_REQUEST')
    claims=value['child_claims']
    if claims:
        p.keys(claims,CLAIMS)
        if any(type(claims[k]) is not int or not 0<=claims[k]<2**63 for k in CLAIMS[:5]) or any(type(claims[k]) is not bool for k in CLAIMS[5:]):
            raise p.BoundaryError('INVALID_REQUEST')
    elif type(claims) is not dict:raise p.BoundaryError('INVALID_REQUEST')
    transition=value['executable_transition']=='FIXTURE_STARTED'
    success=value['completion']=='SUCCESS'
    if (transition and (not value['launcher_ready'] or not value['receipt_eof'] or not claims or value['record_count']<1)
            or bool(claims)!=transition
            or success!=(value['status']=='VALID')
            or success and (not transition or value['exit_status']!='ZERO' or value['record_count']!=2
                            or value['reason']!='COMPLETE' or not value['collector_closed'] or not value['output_eof'])
            or value['status'] in ('REJECTED','UNAVAILABLE') and (claims or transition or success)
            or value['status']=='INCOMPLETE' and value['reason'] not in ('OUTPUT_MISSING','COLLECTION_TIMEOUT','COLLECTION_CLOSED','COMPLETION_MISSING','EXIT_NONZERO')
            or value['status']=='REJECTED' and value['reason'] not in ('OUTPUT_OVERSIZED','OUTPUT_TRUNCATED','OUTPUT_INVALID','OUTPUT_CONTRADICTORY','EXEC_FAILED','RECEIPT_INVALID','COLLECTOR_FAILURE','COLLECTOR_CLOSE_FAILED')
            or value['status']=='PENDING' and (value['reason']!='PENDING' or value['collector_closed'] or claims or value['record_count'] or value['exit_status']!='UNAVAILABLE')
            or value['status']=='UNAVAILABLE' and (value['reason']!='EVIDENCE_UNAVAILABLE' or value['record_count'] or value['output_bytes'])):
        raise p.BoundaryError('INVALID_REQUEST')
    return value


def classify(identity,output,receipt,*,output_eof,receipt_eof,exit_code,reason=None):
    r=empty(identity);r.update(status='INCOMPLETE',reason=reason or 'COMPLETION_MISSING',
        output_bytes=min(len(output),MAX_OUTPUT+1),receipt_eof=receipt_eof,output_eof=output_eof,
        exit_status='UNAVAILABLE' if exit_code is None else 'ZERO' if exit_code==0 else 'NONZERO')
    if receipt in (b'EXEC_READY\n',b'EXEC_READY\nEXEC_FAILED\n'):r['launcher_ready']=True
    if len(output)>MAX_OUTPUT:reason='OUTPUT_OVERSIZED'
    elif receipt==b'EXEC_READY\nEXEC_FAILED\n':reason='EXEC_FAILED'
    elif receipt not in (b'',b'EXEC_READY\n'):reason='RECEIPT_INVALID'
    elif output and not output.endswith(b'\n'):reason='OUTPUT_TRUNCATED'
    parsed=[]
    if reason not in ('OUTPUT_OVERSIZED','EXEC_FAILED','RECEIPT_INVALID','OUTPUT_TRUNCATED'):
        try:
            lines=output.splitlines()
            if len(lines)>MAX_RECORDS or any(not line or len(line)>MAX_RECORD for line in lines):raise ValueError()
            for index,line in enumerate(lines):
                v=json.loads(line,object_pairs_hook=p._pairs)
                fields=('schema_version','fixture','event')+CLAIMS if index==0 else ('schema_version','fixture','event')
                p.keys(v,fields)
                if (type(v['schema_version']) is not int or v['schema_version']!=2 or v['fixture']!=FIXTURE
                        or v['event']!=('STARTED' if index==0 else 'COMPLETED')):raise ValueError()
                if index==0:
                    for k in CLAIMS[:5]:
                        if type(v[k]) is not int or not 0<=v[k]<2**63:raise ValueError()
                    if any(type(v[k]) is not bool for k in CLAIMS[5:]):raise ValueError()
                parsed.append(v)
        except (ValueError,UnicodeError,TypeError,RecursionError,p.BoundaryError):reason='OUTPUT_INVALID';parsed=[]
    if parsed and not r['launcher_ready']:reason='OUTPUT_CONTRADICTORY'
    rejected=reason in ('OUTPUT_OVERSIZED','OUTPUT_TRUNCATED','OUTPUT_INVALID','OUTPUT_CONTRADICTORY','EXEC_FAILED','RECEIPT_INVALID','COLLECTOR_FAILURE','COLLECTOR_CLOSE_FAILED')
    if rejected:r.update(status='REJECTED',reason=reason)
    else:
        r['record_count']=len(parsed)
        if parsed and receipt_eof:
            r['child_claims']={k:parsed[0][k] for k in CLAIMS};r['executable_transition']='FIXTURE_STARTED'
        if len(parsed)==2 and output_eof and receipt_eof and exit_code==0 and reason is None:
            r.update(status='VALID',completion='SUCCESS',reason='COMPLETE')
        elif exit_code is not None and exit_code!=0:r['reason']='EXIT_NONZERO'
        elif not parsed:r['reason']=reason or 'OUTPUT_MISSING'
    return validate(r,identity)


class SyntheticCollector:
    """Owns stdout + retained CLOEXEC receipt FD; no PID/path/command input.

    Direct owned Popen exit is observed; identity comes from the trusted ledger
    and approved registry, never from worker output. No worker lease is renewed.
    """
    def __init__(self,identity,child,receipt_fd,*,clock=time.monotonic):
        self.identity=dict(identity);validate(empty(self.identity),self.identity)
        self.child=child;self.stream=child.stdout;self.receipt_fd=receipt_fd;self.clock=clock
        self.stop=threading.Event();self.lock=threading.Lock();self.close_failed=False
        self.result=empty(identity);self.result.update(status='PENDING',reason='PENDING',collector_closed=False,launcher_ready=True)
        self.thread=None

    def start(self):
        self.thread=threading.Thread(target=self._run,daemon=True,name='freeagentos-synthetic-collector')
        self.thread.start();return self

    def _run(self):
        output=bytearray();receipt=bytearray(b'EXEC_READY\n');eof=set();reason=None;exit_code=None
        try:
            stdout=self.stream.fileno();fds={stdout:'stdout',self.receipt_fd:'receipt'}
            for fd in fds:os.set_blocking(fd,False)
            deadline=self.clock()+COLLECTION_SECONDS
            while True:
                exit_code=self.child.poll()
                if len(eof)==2 and exit_code is not None:break
                if self.stop.is_set():reason='COLLECTION_CLOSED';break
                remaining=deadline-self.clock()
                if remaining<=0:reason='COLLECTION_TIMEOUT';break
                ready=select.select([fd for fd in fds if fd not in eof],[],[],min(.05,remaining))[0]
                for fd in ready:
                    target=output if fds[fd]=='stdout' else receipt
                    maximum=MAX_OUTPUT if fds[fd]=='stdout' else MAX_RECEIPT
                    try:raw=os.read(fd,min(4096,maximum+1-len(target)))
                    except BlockingIOError:continue
                    if not raw:eof.add(fd);continue
                    target.extend(raw)
                    if len(target)>maximum:
                        reason='OUTPUT_OVERSIZED' if fds[fd]=='stdout' else 'RECEIPT_INVALID';break
                if reason:break
            result=classify(self.identity,bytes(output),bytes(receipt),output_eof=stdout in eof,
                            receipt_eof=self.receipt_fd in eof,exit_code=exit_code,reason=reason)
        except Exception:
            result=empty(self.identity);result.update(status='REJECTED',reason='COLLECTOR_FAILURE')
        failed=False
        try:self.stream.close()
        except Exception:failed=True
        fd=self.receipt_fd;self.receipt_fd=None
        if fd is not None:
            try:os.close(fd)
            except Exception:failed=True
        if failed:
            self.close_failed=True;result=empty(self.identity)
            result.update(status='REJECTED',reason='COLLECTOR_CLOSE_FAILED',collector_closed=False)
        with self.lock:self.result=result

    def snapshot(self):
        with self.lock:
            value={**self.result,'child_claims':dict(self.result['child_claims'])}
        return validate(value,self.identity)

    def close(self):
        self.stop.set()
        if self.thread is not None:self.thread.join(timeout=1)
        else:
            failed=False
            try:self.stream.close()
            except Exception:failed=True
            fd=self.receipt_fd;self.receipt_fd=None
            if fd is not None:
                try:os.close(fd)
                except Exception:failed=True
            self.close_failed=failed
            result=empty(self.identity)
            result.update(status='REJECTED' if failed else 'INCOMPLETE',
                          reason='COLLECTOR_CLOSE_FAILED' if failed else 'COLLECTION_CLOSED',
                          launcher_ready=True,collector_closed=not failed)
            with self.lock:self.result=result
        if self.thread is not None and self.thread.is_alive() or self.close_failed:
            raise p.BoundaryError('CLEANUP_INCOMPLETE')
