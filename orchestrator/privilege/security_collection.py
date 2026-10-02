"""Owned, bounded B8 capture tasks and read-only snapshot projection.

No kernel reads on import; no public capture/stress activation operation.
Capture completeness is never executable completion or enforcement proof.
"""
import base64
import hashlib
import json
import secrets
import threading
import time
from . import protocol as p, security_proof as s

VERSION=1
PAGE_BYTES=6144
MAX_PAGES=11
VIEW_NS=s.MAX_CAPTURE_NS
JOIN_SECONDS=1.0
CAPTURE_FIELDS=('schema_version','source','enforcement','binding','sample','subject','scope','at_ns','data')
RESOURCE_FIELDS={
 'cpu':('quota_us','period_us','usage_usec','periods','throttled_periods','throttled_usec'),
 'memory':('limit_bytes','swap_bytes','peak_bytes','max_events','oom_events','oom_kills'),
 'pids':('limit','peak','max_events'),
}
REPORT_FIELDS=('schema_version','binding','sample','subject','scope','started_ns','status','reason','observations','collector_closed','enforcement')
META_FIELDS=('schema_version','binding','snapshot','cursor','pages','total_bytes','sha256','enforcement')
PAGE_FIELDS=('schema_version','binding','snapshot','index','pages','total_bytes','sha256','chunks','next_cursor','enforcement')


def identity(value,x):
    if (value['binding']!=dict(x.binding) or value['sample']!=x.sample or value['subject']!=x.subject
            or value['scope']!=list(x.scope) or type(value['scope']) is not list
            or any(type(v) is not int for v in value['scope'])):
        raise p.BoundaryError('POLICY_REJECTED')


def observation(value,x):
    p.keys(value,('kind','value'))
    kind=value['kind'];v=value['value']
    if kind=='PROOF_RECORD':s.validate(v,x)
    else:
        if kind not in ('ISOLATION','RESOURCES','CONTAINMENT'):raise p.BoundaryError('INVALID_REQUEST')
        p.keys(v,CAPTURE_FIELDS);identity(v,x)
        if (type(v['schema_version']) is not int or v['schema_version']!=1 or v['enforcement']!='UNPROVEN'
                or v['source'] not in ('OWNED_KERNEL_READ','INDEPENDENT_RECORDING')
                or type(v['at_ns']) is not int or not x.started_ns<=v['at_ns']<=x.started_ns+s.MAX_CAPTURE_NS):
            raise p.BoundaryError('INVALID_REQUEST')
        if kind=='ISOLATION':
            p.keys(v['data'],s.KINDS[:5])
            for name,data in v['data'].items():s._data(name,data)
        elif kind=='CONTAINMENT':s._data('descendants',v['data'])
        else:
            p.keys(v['data'],RESOURCE_FIELDS)
            for name,data in v['data'].items():
                p.keys(data,RESOURCE_FIELDS[name])
                if any(type(n) is not int or not 0<=n<2**63 for n in data.values()):raise p.BoundaryError('INVALID_REQUEST')
            if v['data']['cpu']['throttled_periods']>v['data']['cpu']['periods'] or v['data']['pids']['peak']>s.MAX_PROCESSES:
                raise p.BoundaryError('INVALID_REQUEST')
    raw=canonical(value)
    if len(raw)>s.MAX_RECORD_BYTES:raise p.BoundaryError('BOUNDS_EXCEEDED')
    return value


def canonical(value):
    try:return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
    except (TypeError,ValueError,RecursionError):raise p.BoundaryError('INVALID_REQUEST') from None


def validate_report(value,x):
    p.keys(value,REPORT_FIELDS);identity(value,x)
    if (type(value['schema_version']) is not int or value['schema_version']!=VERSION
            or type(value['started_ns']) is not int or value['started_ns']!=x.started_ns
            or value['status'] not in ('PENDING','CAPTURED','INCOMPLETE','REJECTED')
            or type(value['reason']) is not str or value['reason'] not in p.CODES or type(value['collector_closed']) is not bool
            or value['enforcement']!='UNPROVEN' or type(value['observations']) is not list
            or len(value['observations'])>s.MAX_RECORDS):raise p.BoundaryError('INVALID_REQUEST')
    seen=set();last=x.started_ns
    for item in value['observations']:
        observation(item,x);v=item['value']
        key=(item['kind'],v.get('kind'),v['source'],v.get('phase'))
        if key in seen or v['at_ns']<last:raise p.BoundaryError('INVALID_REQUEST')
        seen.add(key);last=v['at_ns']
    claims=[i['value'] for i in value['observations'] if i['kind']=='PROOF_RECORD']
    for v in claims:
        if v['source']=='CHILD_REPORTED' and any(other['source']=='INDEPENDENT_RECORDING' and other['kind']==v['kind']
                and other['phase']==v['phase'] and other['data']!=v['data'] for other in claims):
            raise p.BoundaryError('INVALID_REQUEST')
    if value['status']=='CAPTURED' and (not value['collector_closed'] or value['reason']!='OK'
            or [v['kind'] for v in value['observations']]!=['ISOLATION','RESOURCES','CONTAINMENT']):
        raise p.BoundaryError('INVALID_REQUEST')
    if value['status'] in ('INCOMPLETE','REJECTED') and value['reason']=='OK':raise p.BoundaryError('INVALID_REQUEST')
    if value['status']=='PENDING' and (value['collector_closed'] or value['reason']!='OK'):raise p.BoundaryError('INVALID_REQUEST')
    if value['status']=='REJECTED' and (value['observations'] or value['reason'] not in ('INVALID_REQUEST','POLICY_REJECTED','BOUNDS_EXCEEDED')):
        raise p.BoundaryError('INVALID_REQUEST')
    if len(canonical(value))>s.MAX_BUFFER_BYTES:raise p.BoundaryError('BOUNDS_EXCEEDED')
    return value


class CaptureTask:
    """Inert reservation until registered/durable intent is saved by backend.

    Reader factories are trusted code only, never RPC-selected. Each read has
    existing fixed recipe bounds. Cancellation is a request, not absence proof.
    """
    def __init__(self,x,factory,*,clock=time.monotonic_ns):
        if type(x) is not s.ProofExpectation:raise p.BoundaryError('POLICY_REJECTED')
        self.x=x;self.factory=factory;self.clock=clock;self.lock=threading.RLock()
        self.cancel=threading.Event();self.done=threading.Event();self.thread=None;self.reader=None
        self.close_failed=False;self.started=False
        self.report={'schema_version':VERSION,'binding':dict(x.binding),'sample':x.sample,'subject':x.subject,
            'scope':list(x.scope),'started_ns':x.started_ns,'status':'PENDING','reason':'OK',
            'observations':[],'collector_closed':False,'enforcement':'UNPROVEN'}

    def start(self):
        if self.started:raise p.BoundaryError('INVALID_STATE')
        self.started=True
        self.thread=threading.Thread(target=self._run,name='freeagentos-owned-b8-capture',daemon=True)
        try:self.thread.start()
        except Exception:
            if self.thread.ident is None:self.done.set()
            else:self.close_failed=True
            self._fail('BACKEND_FAILURE');raise p.BoundaryError('BACKEND_FAILURE') from None

    def _fail(self,reason):
        with self.lock:
            if self.close_failed:reason='CLEANUP_INCOMPLETE'
            self.report['status']='REJECTED' if reason in ('INVALID_REQUEST','POLICY_REJECTED','BOUNDS_EXCEEDED') else 'INCOMPLETE'
            self.report['reason']=reason
            if self.report['status']=='REJECTED':self.report['observations']=[]

    def _check(self):
        if self.cancel.is_set():raise p.BoundaryError('INVALID_STATE')
        if not self.x.started_ns<=self.clock()<=self.x.started_ns+s.MAX_CAPTURE_NS:raise p.BoundaryError('TRANSPORT_FAILURE')

    def _run(self):
        captured=False
        try:
            self._check()
            # Backend reservation is already present before the factory can
            # allocate a reader. The reader's own driver reservation precedes FDs.
            self.reader=self.factory()
            for kind,method in (('ISOLATION','isolation'),('RESOURCES','resources'),('CONTAINMENT','containment')):
                self._check();item={'kind':kind,'value':getattr(self.reader,method)()};self._check()
                observation(item,self.x)
                with self.lock:
                    candidate=json.loads(canonical(self.report));candidate['observations'].append(item)
                    validate_report(candidate,self.x);self.report=candidate
            self._check()
            with self.lock:
                if self.close_failed:raise p.BoundaryError('CLEANUP_INCOMPLETE')
                captured=True  # publication waits for successful reader close
        except p.BoundaryError as error:self._fail(error.code)
        except Exception:self._fail('BACKEND_FAILURE')
        finally:
            if self.reader is not None:
                try:self.reader.close()
                except Exception:self.close_failed=True;self._fail('CLEANUP_INCOMPLETE')
            with self.lock:
                self.report['collector_closed']=not self.close_failed
                if captured and self.report['status']=='PENDING':
                    if self.cancel.is_set():self.report.update(status='INCOMPLETE',reason='INVALID_STATE')
                    else:self.report['status']='CAPTURED'
            self.done.set()

    def close(self):
        self.cancel.set();failed=self.close_failed
        if self.thread is not None and self.thread.ident is not None:
            try:self.thread.join(JOIN_SECONDS)
            except Exception:failed=True
            if self.thread.is_alive():failed=True
        # Independently attempt reader closure even if joining failed. Never
        # cancel a thread by an injected exception or re-use numeric FDs.
        if self.reader is not None:
            try:self.reader.close()
            except Exception:failed=True
        if not self.done.is_set() and self.started:failed=True
        if failed:
            self.close_failed=True;self._fail('CLEANUP_INCOMPLETE')
            with self.lock:self.report['collector_closed']=False
            raise p.BoundaryError('CLEANUP_INCOMPLETE')
        with self.lock:
            self.report['collector_closed']=True
            if self.report['status']=='PENDING':self.report.update(status='INCOMPLETE',reason='INVALID_STATE')

    def snapshot(self):
        with self.lock:return validate_report(json.loads(canonical(self.report)),self.x)


class SnapshotPages:
    """Immutable one-use cursor chain. Owned/authenticated by Supervisor.

    One view per connection, at most MAX_CLIENTS total, 10s fixed expiry.
    No background allocation, file reads, worker activation or lease renewal.
    """
    def __init__(self,clock=time.monotonic_ns):self.clock=clock;self.views={}
    def discard(self,connection=None,handle=None):
        for key,v in list(self.views.items()):
            if key==connection or v['binding']['handle']==handle:self.views.pop(key)
    def expire(self):
        now=self.clock()
        for key,v in list(self.views.items()):
            if now>v['expires']:self.views.pop(key)
    def open(self,connection,peer,report,x):
        self.expire();validate_report(report,x)
        if not x.started_ns<=self.clock()<=x.started_ns+s.MAX_CAPTURE_NS:raise p.BoundaryError('INVALID_STATE')
        self.views.pop(connection,None)
        if len(self.views)>=p.MAX_CLIENTS:raise p.BoundaryError('BOUNDS_EXCEEDED')
        raw=canonical(report);count=(len(raw)+PAGE_BYTES-1)//PAGE_BYTES
        v={'snapshot':secrets.token_hex(16),'cursor':secrets.token_hex(16),'binding':dict(x.binding),
           'peer':peer[1:],'index':0,'pages':count,'total_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
           'expires':min(self.clock()+VIEW_NS,x.started_ns+s.MAX_CAPTURE_NS),'raw':raw}
        self.views[connection]=v
        return {k:v[k] for k in ('binding','snapshot','cursor','pages','total_bytes','sha256')}|{'schema_version':VERSION,'enforcement':'UNPROVEN'}
    def page(self,connection,peer,handle,snapshot,cursor):
        self.expire();v=self.views.get(connection)
        if v is None or v['peer']!=peer[1:] or v['binding']['handle']!=handle or v['snapshot']!=snapshot or v['cursor']!=cursor:
            raise p.BoundaryError('UNKNOWN_HANDLE')
        index=v['index'];block=v['raw'][index*PAGE_BYTES:(index+1)*PAGE_BYTES]
        encoded=base64.b64encode(block).decode('ascii')
        next_cursor=secrets.token_hex(16) if index+1<v['pages'] else None
        result={k:v[k] for k in ('binding','snapshot','pages','total_bytes','sha256')}|{
            'schema_version':VERSION,'enforcement':'UNPROVEN','index':index,
            'chunks':[encoded[i:i+256] for i in range(0,len(encoded),256)],'next_cursor':next_cursor}
        v['index']+=1;v['cursor']=next_cursor
        if next_cursor is None:self.views.pop(connection)
        return result


def decode_page(value,meta,index,binding):
    p.keys(value,PAGE_FIELDS)
    if (value['schema_version']!=VERSION or type(value['schema_version']) is not int or value['enforcement']!='UNPROVEN'
            or type(value['index']) is not int or value['index']!=index or value['binding']!=binding
            or any(type(value[k]) is not type(meta[k]) or value[k]!=meta[k] for k in ('snapshot','pages','total_bytes','sha256'))
            or type(value['chunks']) is not list or not 1<=len(value['chunks'])<=32
            or any(type(c) is not str or not 1<=len(c)<=256 for c in value['chunks'])
            or (index+1<meta['pages'] and not p.identifier(value['next_cursor']))
            or (index+1==meta['pages'] and value['next_cursor'] is not None)):
        raise p.BoundaryError('INVALID_REQUEST')
    try:raw=base64.b64decode(''.join(value['chunks']),validate=True)
    except (ValueError,UnicodeError):raise p.BoundaryError('INVALID_REQUEST') from None
    expected=min(PAGE_BYTES,meta['total_bytes']-index*PAGE_BYTES)
    if len(raw)!=expected:raise p.BoundaryError('INVALID_REQUEST')
    return raw
