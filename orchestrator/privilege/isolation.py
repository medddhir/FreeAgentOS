"""Complete owned Linux lifecycle over an explicitly supplied kernel driver.

Production operations require a future root-owned installation permit. The
recording driver exercises identical orchestration without kernel mutations.
"""
import os
import ast
from pathlib import Path
import secrets
import threading
import time
from . import protocol as p
from .policy import resource_limits
from .real_journal import recovery_actions
from .execution import ExecutionRegistry
from ..roles.lease import ActivityLease, BASE_SECONDS, HARD_SECONDS, NS

def role_base(execution,role,policy):
    if execution!='MODEL_WORKER':return policy['wall_timeout_seconds']
    if role in ('coder','fixer'):return BASE_SECONDS
    name=role.upper()+'_TIMEOUT'
    tree=ast.parse((Path(__file__).parents[1]/'roles'/(role+'.py')).read_text())
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in node.targets):
            if isinstance(node.value,ast.Constant) and type(node.value.value) is int:return node.value.value
    raise p.BoundaryError('POLICY_REJECTED')


class LinuxBackend:
    simulation_only=False
    def __init__(self,registry,sources,driver,journal,*,clock=time.monotonic_ns,validation_grace=False):
        if type(registry) is not ExecutionRegistry or set(registry.entries)!=set(sources):raise p.BoundaryError('POLICY_REJECTED')
        if type(validation_grace) is not bool or validation_grace and any(not e.validation for e in registry.entries.values()):raise p.BoundaryError('POLICY_REJECTED')
        self.validation_grace=validation_grace
        self.registry=registry;self.sources=dict(sources);self.driver=driver;self.journal=journal
        self.owner=journal.owner;self.clock=clock;self.lock=threading.RLock()
        self.records={r['handle']:r for r in journal.load()};self.processes={};self.leases={};self.bindings={}
        self.stop=threading.Event();self.monitor=None
        self.security_tasks={};self.security_reports={}
        self.recovery_required=any(r['state']!='RELEASED' for r in self.records.values())

    def _save(self):self.journal.save(list(self.records.values()))
    def _record(self,handle):
        if handle not in self.records:raise p.BoundaryError('UNKNOWN_HANDLE')
        return self.records[handle]
    def owns(self,handle,owner):return owner==self.owner and handle in self.records and self.records[handle]['state']!='RELEASED'
    def cleaned(self,handle,owner):return self.cleanup_proof(handle,owner) in ('NEVER_ALLOCATED','OWNED_CLEANED')

    def cleanup_proof(self,handle,owner):
        r=self.records.get(handle)
        if handle in self.security_tasks:return 'UNPROVEN'
        if owner!=self.owner or r is None or r['owner']!=owner or r['state']!='RELEASED' or r['cleanup'] not in ('CONFIRMED','NEVER_ALLOCATED'):return 'UNPROVEN'
        if not self.driver.absent(r):return 'UNPROVEN'
        return 'NEVER_ALLOCATED' if r['cleanup']=='NEVER_ALLOCATED' else 'OWNED_CLEANED'

    def _dirty(self,r):
        r['state']='FAILED_DIRTY';r['cleanup']='UNPROVEN';self.recovery_required=True
        try:self._save()
        except Exception:pass  # durable intent remains; admission is fenced

    def create(self,handle,run_id,slot,execution,role,limits):
        with self.lock:
            if self.recovery_required:raise p.BoundaryError('RECOVERY_REQUIRED')
            if not p.identifier(handle) or not p.identifier(run_id):raise p.BoundaryError('INVALID_REQUEST')
            if handle in self.records or any(r['run_id']==run_id for r in self.records.values()):raise p.BoundaryError('INVALID_STATE')
            if len(self.records)>=p.MAX_ENTRIES or sum(r['state']!='RELEASED' for r in self.records.values())>=p.MAX_ACTIVE:
                raise p.BoundaryError('BOUNDS_EXCEEDED')
            entry=self.registry.bind(slot,execution,role);policy=resource_limits(execution,role,limits)
            r={'handle':handle,'run_id':run_id,'owner':self.owner,'state':'CREATING','class':execution,'role':role,
               'policy':self.journal.policy,'boot_id':self.driver.boot_id,'scope_inode':0,'scope_device':0,
               'root_inode':0,'root_device':0,'started_ns':0,'cleanup':'PENDING','collection':'NONE'}
            self.records[handle]=r;self._save()  # intent BEFORE every resource allocation
            try:
                self.driver.qualify()
                identity=self.driver.allocate(r,policy)
                r.update(identity);self._save()  # root/scope inode proof BEFORE setup
                self.driver.snapshot(r,self.sources[slot]);self.bindings[handle]=(entry,policy)
                r['state']='CREATED';self._save()
            except Exception:
                r['state']='FAILED_DIRTY';self.recovery_required=True;self._save()
                raise p.BoundaryError('BACKEND_FAILURE') from None
            return self.status(handle)

    def start(self,handle):
        with self.lock:
            r=self._record(handle)
            if self.recovery_required or r['state']!='CREATED':raise p.BoundaryError('INVALID_STATE')
            entry,policy=self.bindings[handle]
            try:
                entry.verify();started=self.clock();r['started_ns']=started;self._save()
                self.processes[handle]=self.driver.launch(r,entry,policy)
                # Existing role-specific worker constants remain authoritative.
                base=role_base(r['class'],r['role'],policy)
                self.leases[handle]=ActivityLease(base,r['role'],'model' if r['class']=='MODEL_WORKER' else 'research',True,policy['wall_timeout_seconds'],started)
                r['state']='RUNNING';self._save()
            except Exception:
                # Even failure to persist RUNNING must not leave the launcher live.
                self._dirty(r)
                try:self.driver.terminate(r,self.processes.get(handle))
                except Exception:pass  # driver keeps unresolved owned child/FDs
                self._dirty(r)
                raise p.BoundaryError('BACKEND_FAILURE') from None
            self._start_monitor()

    def _start_monitor(self):
        if self.monitor is None:
            self.monitor=threading.Thread(target=self._watch,name='freeagentos-owned-deadlines',daemon=True);self.monitor.start()

    def _watch(self):
        while not self.stop.wait(.05):
            try:self.enforce()
            except Exception:
                # Fence new admission; retain dirty ledger. Never erase failures.
                self.recovery_required=True

    def observe_progress(self,handle,broker):
        # Internal trusted broker object only; no public protocol progress flag.
        with self.lock:
            self.leases[handle].observe(broker=broker)

    def enforce(self):
        with self.lock:
            now=self.clock()
            from .security_proof import MAX_CAPTURE_NS
            for h,(x,report) in list(self.security_reports.items()):
                if now>x.started_ns+MAX_CAPTURE_NS:self.security_reports.pop(h)
            for handle,lease in list(self.leases.items()):
                r=self._record(handle)
                task=self.security_tasks.get(handle)
                if task is not None and (task.close_failed or now>task.x.started_ns+MAX_CAPTURE_NS and not task.done.is_set()):
                    self._dirty(r)
                if self.driver.collection_failed(handle):self._dirty(r)
                if r['state']=='FAILED_DIRTY' and handle in self.processes:
                    # Keep attempting only the owned scope after transient kill
                    # failures. Admission stays fenced; dirty never implies clean.
                    try:self._finish_security(r)
                    finally:self.driver.terminate(r,self.processes.get(handle))
                    continue
                if r['state']!='RUNNING':continue
                if not self.driver.running(r,self.processes[handle]):
                    # Exit of namespace init is insufficient: kill/drain leftovers.
                    self.terminate(handle);continue
                entry=self.bindings.get(handle,(None,None))[0]
                # Explicit synthetic-only validation coordinator. A successful
                # descriptor read, not worker output, supplies broker telemetry.
                if (self.validation_grace and entry is not None and entry.validation
                        and lease.last_ns is None and lease.base_ns-NS<=now<lease.base_ns):
                    self.driver.validation_read(r)
                    from types import SimpleNamespace
                    lease.observe(broker=SimpleNamespace(telemetry=SimpleNamespace(last_success_ns=self.clock())))
                lease.extend(now)
                if now>=lease.deadline_ns:self.terminate(handle)

    def running(self,handle):
        with self.lock:
            r=self._record(handle)
            return r['state']=='RUNNING' and self.driver.running(r,self.processes[handle])

    def status(self,handle):
        with self.lock:
            r=self._record(handle)
            return {'handle':handle,'state':r['state'],'class':r['class'],'role':r['role'],
                    'mode':'LINUX','enforcement':'UNPROVEN','cleanup':'CONFIRMED' if self.cleaned(handle,self.owner) else 'UNPROVEN'}

    def collect(self,handle):
        with self.lock:
            r=self._record(handle)
            entry=self.bindings.get(handle,(None,None))[0]
            if entry is not None and not entry.validation:raise p.BoundaryError('POLICY_REJECTED')
            return self.driver.collect(r)

    def begin_security_capture(self,handle,expectation):
        """Controller-internal validation seam, NOT a transport operation.

        It only observes an existing approved synthetic execution. Neither this
        method nor retrieval starts a worker, stress mode or production adapter.
        """
        from .security_collection import CaptureTask
        from .security_proof import ProofExpectation, MAX_CAPTURE_NS
        from .evidence import binding
        with self.lock:
            r=self._record(handle);entry,limits=self.bindings[handle]
            if (self.recovery_required or r['state']!='RUNNING' or not entry.validation
                    or r.get('collection','NONE')!='NONE' or type(expectation) is not ProofExpectation
                    or expectation.binding!=binding(r,entry) or (expectation.uid,expectation.gid)!=(entry.uid,entry.gid)
                    or dict(expectation.limits)!=limits or expectation.scope!=(r['scope_device'],r['scope_inode'])
                    or not expectation.started_ns<=self.clock()<=expectation.started_ns+MAX_CAPTURE_NS):
                raise p.BoundaryError('POLICY_REJECTED')
            if len(self.security_tasks)>=p.MAX_ACTIVE:raise p.BoundaryError('BOUNDS_EXCEEDED')
            task=CaptureTask(expectation,lambda:self.driver.security_reader(r,entry,expectation),clock=self.clock)
            self.security_tasks[handle]=task  # reservation BEFORE durable intent/factory/thread
            r['collection']='PENDING'
            try:self._save();task.start()
            except Exception:
                self._dirty(r)
                try:task.close()
                except Exception:r['collection']='UNPROVEN'
                raise p.BoundaryError('BACKEND_FAILURE') from None

    def security_evidence(self,handle):
        from .evidence import binding
        from .security_proof import MAX_CAPTURE_NS
        with self.lock:
            r=self._record(handle)
            if r['state']=='RELEASED':raise p.BoundaryError('INVALID_STATE')
            entry=self.bindings[handle][0]
            if not entry.validation:raise p.BoundaryError('POLICY_REJECTED')
            task=self.security_tasks.get(handle)
            value=(task.x,task.snapshot()) if task is not None else self.security_reports.get(handle)
            if value is None:raise p.BoundaryError('INVALID_STATE')
            x,report=value
            if (x.binding!=binding(r,entry) or x.scope!=(r['scope_device'],r['scope_inode'])
                    or (x.uid,x.gid)!=(entry.uid,entry.gid) or dict(x.limits)!=self.bindings[handle][1]):
                raise p.BoundaryError('POLICY_REJECTED')
            if not x.started_ns<=self.clock()<=x.started_ns+MAX_CAPTURE_NS:raise p.BoundaryError('INVALID_STATE')
            return x,report

    def _finish_security(self,r):
        handle=r['handle'];task=self.security_tasks.get(handle)
        if task is None:
            if r.get('collection') in ('PENDING','UNPROVEN'):raise p.BoundaryError('CLEANUP_INCOMPLETE')
            return
        try:
            task.close()
            if handle in getattr(self.driver,'close_errors',set()):
                task.close_failed=True;task._fail('CLEANUP_INCOMPLETE')
                with task.lock:task.report['collector_closed']=False
                raise p.BoundaryError('CLEANUP_INCOMPLETE')
            self.security_reports[handle]=(task.x,task.snapshot())
            r['collection']='CLOSED';self._save()
            self.security_tasks.pop(handle)
        except Exception:
            r['collection']='UNPROVEN';self._dirty(r)
            raise p.BoundaryError('CLEANUP_INCOMPLETE') from None

    def terminate(self,handle):
        with self.lock:
            r=self._record(handle)
            if r['state'] not in ('CREATED','RUNNING','TERMINATING','TERMINATED'):raise p.BoundaryError('INVALID_STATE')
            if r['state']=='TERMINATED':return
            r['state']='TERMINATING';failed=False
            try:self._save()
            except Exception:failed=True
            try:self._finish_security(r)
            except Exception:failed=True
            try:self.driver.terminate(r,self.processes.get(handle))
            except Exception:failed=True
            if failed:
                self._dirty(r);raise p.BoundaryError('CLEANUP_INCOMPLETE') from None
            r['state']='TERMINATED'
            try:self._save()
            except Exception:
                self._dirty(r);raise p.BoundaryError('CLEANUP_INCOMPLETE') from None

    def cleanup(self,handle):
        with self.lock:
            r=self._record(handle)
            if r['state']=='RELEASED':return
            if r['state']=='FAILED_DIRTY':raise p.BoundaryError('RECOVERY_REQUIRED')
            self.terminate(handle)
            try:
                self.driver.remove(r)
                if not self.driver.absent(r):raise p.BoundaryError('CLEANUP_INCOMPLETE')
                r['state']='RELEASED';r['cleanup']='CONFIRMED';self._save()
                self.processes.pop(handle,None);self.bindings.pop(handle,None);self.leases.pop(handle,None)
                self.security_reports.pop(handle,None)
            except Exception:
                self._dirty(r)
                raise p.BoundaryError('CLEANUP_INCOMPLETE') from None

    def disconnect(self,handles):
        # v1 uses persistent connection ownership, no reconnect semantics.
        for handle in tuple(handles):
            if self.owns(handle,self.owner):self.cleanup(handle)

    def reconcile_control(self,records):
        # A controller-ledger intent can precede the resource-ledger intent.
        # Missing resource record is clean ONLY if both exact owned names are
        # absent. Never infer absence from a lost/corrupt ledger alone.
        with self.lock:
            for old in records:
                if old['owner']!=self.owner:raise p.BoundaryError('JOURNAL_INVALID')
                if old['handle'] in self.records:continue
                if old['handle'] in self.security_tasks:raise p.BoundaryError('CLEANUP_INCOMPLETE')
                if not self.driver.absent(old):raise p.BoundaryError('CLEANUP_INCOMPLETE')
                self.records[old['handle']]={'handle':old['handle'],'run_id':old['run_id'],'owner':self.owner,
                    'state':'RELEASED','class':old['class'],'role':old['role'],'policy':self.journal.policy,
                    'boot_id':self.driver.boot_id,'scope_inode':0,'scope_device':0,'root_inode':0,'root_device':0,
                    'started_ns':0,'cleanup':'NEVER_ALLOCATED'}
            self._save()

    def recover(self):
        with self.lock:
            pending=[r for r in self.records.values() if r['state']!='RELEASED']
            plans=[]
            try:
                for r in pending:
                    self._finish_security(r)
                    plans.append((r,recovery_actions(r,self.journal.policy,self.owner,self.driver.prove(r))))
                for r,actions in plans:
                    never_allocated=self.driver.absent(r) and not any(r[k] for k in ('root_inode','scope_inode','started_ns'))
                    self.driver.recover(r,actions)
                    if not self.driver.absent(r):raise p.BoundaryError('CLEANUP_INCOMPLETE')
                    r['state']='RELEASED';r['cleanup']='NEVER_ALLOCATED' if never_allocated else 'CONFIRMED'
                    try:self._save()
                    except Exception:
                        self._dirty(r);raise p.BoundaryError('CLEANUP_INCOMPLETE') from None
                    self.processes.pop(r['handle'],None);self.leases.pop(r['handle'],None);self.bindings.pop(r['handle'],None)
                self.recovery_required=False
            except Exception:
                self.recovery_required=True
                for r in pending:
                    if r['state']!='RELEASED':r['state']='FAILED_DIRTY';r['cleanup']='UNPROVEN'
                try:self._save()
                except Exception:pass
                raise p.BoundaryError('CLEANUP_INCOMPLETE') from None

    def close(self):
        self.stop.set()
        if self.monitor:self.monitor.join(timeout=2)
        failed=False
        with self.lock:
            for handle in list(self.security_tasks):
                try:self._finish_security(self._record(handle))
                except Exception:failed=True
        if failed:raise p.BoundaryError('CLEANUP_INCOMPLETE')

    def probe(self):return p.probe_record('LINUX')
