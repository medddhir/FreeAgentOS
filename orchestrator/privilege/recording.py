"""Explicit test driver; records kernel intentions, never simulates proof of enforcement."""
from collections import deque
from dataclasses import dataclass
import os
from .protocol import BoundaryError
from .kernel import scope_name
from .child import ChildRoutine

@dataclass
class RecordedProcess:
    handle: str
    active: bool=True
    closed: bool=False

class RecordingCalls:
    def __init__(self,events,handle):self.events=events;self.handle=handle
    def perform(self,operation,config):self.events.append((self.handle,operation))

class RecordingDriver:
    def __init__(self):
        self.boot_id='recording-boot';self.events=deque(maxlen=2048);self.resources={};self.next_inode=1;self.fail=None
    def _step(self,handle,name):
        self.events.append((handle,name))
        if self.fail==name:raise RuntimeError('private injected exception must be sanitized')
    def qualify(self):self._step(None,'QUALIFY_READONLY')
    def allocate(self,r,limits):
        name=scope_name(r)
        if name in self.resources:raise BoundaryError('INVALID_STATE')
        self._step(r['handle'],'ALLOCATE')
        identity={'scope_inode':self.next_inode,'scope_device':1,'root_inode':self.next_inode+1,'root_device':1}
        self.next_inode+=2;self.resources[name]={'identity':identity,'owner':r['owner'],'process':None}
        return identity
    def snapshot(self,r,source):self._step(r['handle'],'SNAPSHOT_FD_SEAL')
    def launch(self,r,entry,limits):
        self._step(r['handle'],'LAUNCH')
        c={'version':1,'class':entry.execution,'role':entry.role,'uid':entry.uid,'gid':entry.gid,
           'job_id':entry.job_id,'validation':entry.validation,'fds':[3,4,5,6,7,8],'limits':limits}
        ChildRoutine(RecordingCalls(self.events,r['handle'])).run(c)
        process=RecordedProcess(r['handle']);self.resources[scope_name(r)]['process']=process;return process
    def running(self,r,process):
        if process.handle!=r['handle']:raise BoundaryError('UNKNOWN_HANDLE')
        return process.active
    def terminate(self,r,process=None):
        self._step(r['handle'],'CGROUP_KILL_OWNED')
        if process:
            if process.handle!=r['handle']:raise BoundaryError('UNKNOWN_HANDLE')
            process.active=False;process.closed=True
        self._step(r['handle'],'VERIFY_EMPTY')
    def remove(self,r):
        self._step(r['handle'],'REMOVE_OWNED')
        self.resources.pop(scope_name(r),None)
    def absent(self,r):return scope_name(r) not in self.resources
    def prove(self,r):
        self._step(r['handle'],'PROVE_OWNERSHIP')
        found=self.resources.get(scope_name(r))
        if found is None:return {'scope':True,'root':True}
        return {'scope':found['owner']==r['owner'] and found['identity']['scope_inode']==r['scope_inode'],
                'root':found['owner']==r['owner'] and found['identity']['root_inode']==r['root_inode']}
    def recover(self,r,actions):
        found=self.resources.get(scope_name(r))
        self.terminate(r,found['process'] if found else None);self.remove(r)
    def close(self):pass
