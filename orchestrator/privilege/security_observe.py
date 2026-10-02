"""Pure bounded projection of fixed proc/cgroup observations. No host access.

Input acquisition must be by the later authenticated owned-kernel observer,
NOT from the worker pipe. These parsers establish shape, never provenance.
Raw paths/content are not retained; all outputs are bounded integers/booleans.
"""
from . import protocol as p
from .security_proof import MAX_RAW_BYTES, MAX_FDS, MAX_GROUPS, MAX_MOUNTS, NAMESPACES


def _lines(raw,maximum=128):
    if type(raw) is not bytes or not raw.endswith(b'\n') or len(raw)>MAX_RAW_BYTES:raise p.BoundaryError('INVALID_REQUEST')
    try:lines=raw.decode('ascii').splitlines()
    except UnicodeError:raise p.BoundaryError('INVALID_REQUEST') from None
    if len(lines)>maximum or any(len(v)>4096 for v in lines):raise p.BoundaryError('BOUNDS_EXCEEDED')
    return lines


def number(v,base=10):
    if type(v) is not str or not v or len(v)>20 or any(c not in ('0123456789abcdefABCDEF' if base==16 else '0123456789') for c in v):raise p.BoundaryError('INVALID_REQUEST')
    n=int(v,base)
    if not 0<=n<2**63:raise p.BoundaryError('INVALID_REQUEST')
    return n


def status(raw):
    required=('Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','NSpid')
    values={}
    for line in _lines(raw):
        key,sep,value=line.partition(':')
        if key in required:
            if not sep or key in values:raise p.BoundaryError('INVALID_REQUEST')
            values[key]=value.split()
    if set(values)!=set(required):raise p.BoundaryError('INVALID_REQUEST')
    if (len(values['Uid'])!=4 or len(values['Gid'])!=4 or len(values['Groups'])>MAX_GROUPS
            or not 1<=len(values['NSpid'])<=8 or any(len(values[k])!=1 for k in required[3:9])):
        raise p.BoundaryError('INVALID_REQUEST')
    identity={'uids':[number(v) for v in values['Uid']],'gids':[number(v) for v in values['Gid']],
              'groups':[number(v) for v in values['Groups']]}
    caps=dict(zip(('inheritable','permitted','effective','bounding','ambient'),(number(values[k][0],16) for k in required[3:8])))
    nnp=number(values['NoNewPrivs'][0])
    if nnp not in (0,1):raise p.BoundaryError('INVALID_REQUEST')
    caps['no_new_privs']=bool(nnp)
    return identity,caps,number(values['NSpid'][-1])


def fds(names,*,standard_safe=False):
    if type(standard_safe) is not bool:raise p.BoundaryError('INVALID_REQUEST')
    if type(names) is not list or len(names)>MAX_FDS:raise p.BoundaryError('BOUNDS_EXCEEDED')
    values=sorted(number(v) for v in names)
    if len(set(values))!=len(values) or any(v>65535 for v in values):raise p.BoundaryError('INVALID_REQUEST')
    return {'open':values,'unexpected':[v for v in values if v>2],'standard_safe':standard_safe}


def namespace_comparison(host,worker,inner_pid):
    for value in (host,worker):
        p.keys(value,NAMESPACES)
        if any(type(n) is not int or not 1<=n<2**63 for n in value.values()):raise p.BoundaryError('INVALID_REQUEST')
    if type(inner_pid) is not int or not 1<=inner_pid<2**31:raise p.BoundaryError('INVALID_REQUEST')
    return {'host':dict(host),'worker':dict(worker),'inner_pid':inner_pid}


TARGETS=frozenset(('/','/tmp','/run','/home','/dev','/workspace','/proc'))
DEVICES={'null':(1,3),'zero':(1,5),'random':(1,8),'urandom':(1,9)}


def filesystem(raw,*,root,runtime,proc_device,host_proc_device,devices,forbidden_absent):
    """Fixed observer stat identities; no arbitrary host mount/path arguments."""
    mounts={};private=True
    for line in _lines(raw,MAX_MOUNTS):
        fields=line.split();
        if len(fields)<10 or fields.count('-')!=1:raise p.BoundaryError('INVALID_REQUEST')
        dash=fields.index('-')
        if dash<6 or len(fields)!=dash+4:raise p.BoundaryError('INVALID_REQUEST')
        point=fields[4]
        if point in mounts or '\\' in point:raise p.BoundaryError('INVALID_REQUEST')
        private &= not any(v.startswith(('shared:','master:','propagate_from:')) for v in fields[6:dash])
        mounts[point]=(set(fields[5].split(',')),fields[dash+1])
    for pair in (root,runtime):
        if type(pair) is not tuple or len(pair)!=2 or any(type(v) is not int or not 1<=v<2**63 for v in pair):raise p.BoundaryError('INVALID_REQUEST')
    if (any(type(v) is not int or not 1<=v<2**63 for v in (proc_device,host_proc_device))
            or type(forbidden_absent) is not bool or type(devices) is not dict or len(devices)>16):raise p.BoundaryError('INVALID_REQUEST')
    valid_devices=set(devices)==set(DEVICES)
    for name,metadata in devices.items():
        p.keys(metadata,('character','major','minor','mode'))
        if type(metadata['character']) is not bool or any(type(metadata[k]) is not int or not 0<=metadata[k]<2**32 for k in ('major','minor','mode')):raise p.BoundaryError('INVALID_REQUEST')
        valid_devices &= name in DEVICES and metadata['character'] and (metadata['major'],metadata['minor'])==DEVICES.get(name) and metadata['mode']==0o666
    root_options=mounts.get('/',(set(),''))[0];proc_options,proc_kind=mounts.get('/proc',(set(),''))
    return {'root_matches_runtime':root==runtime,'root_readonly':{'ro','nosuid'}<=root_options,
            'private_propagation':private,'mounts_exact':set(mounts)==TARGETS,
            'proc_private':proc_kind=='proc' and {'nosuid','nodev','noexec'}<=proc_options and proc_device!=host_proc_device,
            'devices_exact':bool(valid_devices),'forbidden_absent':forbidden_absent}


def counters(raw,required):
    values={}
    for line in _lines(raw,32):
        pair=line.split()
        if len(pair)!=2 or pair[0] in values:raise p.BoundaryError('INVALID_REQUEST')
        values[pair[0]]=number(pair[1])
    if not set(required)<=set(values):raise p.BoundaryError('INVALID_REQUEST')
    return {k:values[k] for k in required}


def cpu(quota,stat):
    fields=_lines(quota,1)
    if len(fields)!=1 or len(fields[0].split())!=2:raise p.BoundaryError('INVALID_REQUEST')
    q,period=(number(v) for v in fields[0].split())
    values=counters(stat,('usage_usec','nr_periods','nr_throttled','throttled_usec'))
    return {'quota_us':q,'period_us':period,'usage_usec':values['usage_usec'],
            'periods':values['nr_periods'],'throttled_periods':values['nr_throttled'],'throttled_usec':values['throttled_usec']}


def scalar(raw):
    lines=_lines(raw,1)
    if len(lines)!=1:return number('')
    return number(lines[0])


def memory(limit,swap,peak,events):
    values=counters(events,('max','oom','oom_kill'))
    return {'limit_bytes':scalar(limit),'swap_bytes':scalar(swap),
            'peak_bytes':scalar(peak),'max_events':values['max'],
            'oom_events':values['oom'],'oom_kills':values['oom_kill']}


def pids(limit,peak,events):
    return {'limit':scalar(limit),'peak':scalar(peak),
            'max_events':counters(events,('max',))['max']}
