"""Fixed unprivileged repeat builds. Never execute outputs or grant authority."""
import hashlib
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from .privilege import protocol as p, inventory as i
from .privilege.linux import secure_open

COMPILER='/usr/bin/cc'
FLAGS=('-static','-O2')
SOURCES=('synthetic_worker.c','security_probe.c')
MAX_OUTPUT=65536
MAX_TOOL_BYTES=64*1024*1024
MAX_INPUTS=192
MAX_INPUT_TOTAL=128*1024*1024
COMMAND_SECONDS=20
MAX_CAMPAIGN_SECONDS=120
SEARCH_ROOTS=('/usr/bin/','/usr/lib/','/usr/libexec/gcc/x86_64-linux-gnu/13/','/usr/include/')


def _run(argv,*,cwd,clock=time.monotonic):
    """Private compiler adapter; callers in this module supply fixed argv only."""
    child=subprocess.Popen(argv,cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},
                           close_fds=True,start_new_session=True)
    raw=bytearray();start=clock();failure=False
    try:
        os.set_blocking(child.stdout.fileno(),False)
        with selectors.DefaultSelector() as poll:
            poll.register(child.stdout,selectors.EVENT_READ)
            while poll.get_map():
                if clock()-start>=COMMAND_SECONDS:raise p.BoundaryError('BOUNDS_EXCEEDED')
                for _,_ in poll.select(.05):
                    block=os.read(child.stdout.fileno(),4096)
                    if not block:poll.unregister(child.stdout);break
                    raw.extend(block)
                    if len(raw)>MAX_OUTPUT:raise p.BoundaryError('BOUNDS_EXCEEDED')
            child.wait(timeout=max(.001,COMMAND_SECONDS-(clock()-start)))
        if child.returncode:raise p.BoundaryError('BACKEND_FAILURE')
        return bytes(raw)
    except BaseException:
        failure=True;raise
    finally:
        # Exact helper-created build process group only; no public PID interface.
        if failure:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            except OSError:failure=True
        try:child.wait(timeout=2)
        finally:child.stdout.close()


def trusted_input(path):
    """Fixed compiler-derived paths, root-owned immutable ancestry, no aliases."""
    path=Path(path).resolve(strict=True)
    if not any(str(path).startswith(root) for root in SEARCH_ROOTS):raise p.BoundaryError('POLICY_REJECTED')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=nxt
            info=os.fstat(fd)
            if info.st_uid!=0 or info.st_mode&0o022:raise p.BoundaryError('POLICY_REJECTED')
        file=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
        try:
            before=os.fstat(file)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022 or not 0<before.st_size<=MAX_TOOL_BYTES:raise p.BoundaryError('POLICY_REJECTED')
            digest=hashlib.sha256();count=0
            while True:
                raw=os.read(file,65536)
                if not raw:break
                count+=len(raw)
                if count>MAX_TOOL_BYTES:raise p.BoundaryError('BOUNDS_EXCEEDED')
                digest.update(raw)
            if i._identity(before)!=i._identity(os.fstat(file)) or i._identity(before)!=i._identity(os.stat(path.name,dir_fd=fd,follow_symlinks=False)):raise p.BoundaryError('JOURNAL_INVALID')
            return {'path':str(path),'sha256':digest.hexdigest(),'identity':i._identity(before)}
        finally:os.close(file)
    finally:os.close(fd)


def _output(directory,name):
    root=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    fd=None
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=root)
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_gid!=os.getgid()
                or before.st_nlink!=1 or before.st_mode&0o022 or not 0<before.st_size<=i.MAX_FILE):
            raise p.BoundaryError('POLICY_REJECTED')
        chunks=[];size=0
        while True:
            raw=os.read(fd,65536)
            if not raw:break
            size+=len(raw)
            if size>i.MAX_FILE:raise p.BoundaryError('BOUNDS_EXCEEDED')
            chunks.append(raw)
        if (size!=before.st_size or i._identity(os.fstat(fd))!=i._identity(before)
                or i._identity(os.stat(name,dir_fd=root,follow_symlinks=False))!=i._identity(before)):
            raise p.BoundaryError('JOURNAL_INVALID')
        return b''.join(chunks)
    finally:
        if fd is not None:os.close(fd)
        os.close(root)


def compare(expected):
    """Reviewed fixture source hashes required; no caller argv/path/build flags."""
    p.keys(expected,SOURCES)
    if any(not p.identifier(v,64) for v in expected.values()):raise p.BoundaryError('POLICY_REJECTED')
    from .privilege.closure_verify import elf
    start=time.monotonic();inputs={};total=0
    def remember(path):
        nonlocal total
        value=trusted_input(path);name=value['path']
        if name not in inputs:
            total+=value['identity']['size'];inputs[name]=value
        if len(inputs)>MAX_INPUTS or total>MAX_INPUT_TOTAL or time.monotonic()-start>MAX_CAMPAIGN_SECONDS:raise p.BoundaryError('BOUNDS_EXCEEDED')
        return value
    compiler=remember(COMPILER)['path']
    with tempfile.TemporaryDirectory(prefix='freeagent-fixture-comparison-') as temp:
        root=Path(temp);root.chmod(0o700)
        for name in ('cc1','as','ld'):
            found=_run([compiler,'-print-prog-name='+name],cwd=temp).decode('ascii').strip()
            # GCC may return the fixed utility name, not an absolute path.
            if found==name and name in ('as','ld'):found='/usr/bin/'+name
            remember(found)
        for name in ('libc.a','libgcc.a','libgcc_eh.a','crt1.o','crti.o','crtn.o','crtbeginT.o','crtend.o'):
            found=_run([compiler,'-print-file-name='+name],cwd=temp).decode('ascii').strip()
            if found==name:raise p.BoundaryError('POLICY_REJECTED')
            remember(found)
        version=hashlib.sha256(_run([compiler,'--version'],cwd=temp)).hexdigest()
        specs=hashlib.sha256(_run([compiler,'-dumpspecs'],cwd=temp)).hexdigest()
        source_root=os.open(Path(__file__).parent/'privilege'/'fixtures',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        results={}
        try:
            for name in SOURCES:
                fd=secure_open(source_root,name)
                try:
                    before=os.fstat(fd);raw=os.read(fd,16385)
                    if len(raw)>16384 or len(raw)!=before.st_size or i._identity(before)!=i._identity(os.fstat(fd)) or hashlib.sha256(raw).hexdigest()!=expected[name]:raise p.BoundaryError('POLICY_REJECTED')
                finally:os.close(fd)
                source=root/name;source.write_bytes(raw);source.chmod(0o600)
                headers=_run([compiler,'-M',name],cwd=temp).decode('ascii').replace('\\\n',' ')
                # Fixed fixture names; dependency whitespace escaping is unsupported.
                if ':' not in headers or '\\' in headers:raise p.BoundaryError('POLICY_REJECTED')
                for header in headers.split(':',1)[1].split():
                    if header!=name:remember(header)
                outputs=[]
                for round_id in range(2):
                    if time.monotonic()-start>MAX_CAMPAIGN_SECONDS:raise p.BoundaryError('BOUNDS_EXCEEDED')
                    output='output-'+str(round_id)
                    _run([compiler,*FLAGS,name,'-o',output],cwd=temp)
                    blob=_output(temp,output)
                    metadata=elf(blob)
                    if metadata!={'interpreter':None,'needed':[]}:raise p.BoundaryError('POLICY_REJECTED')
                    outputs.append(hashlib.sha256(blob).hexdigest())
                results[name]={'source_sha256':expected[name],'outputs':outputs,
                               'status':'REPEATABLE_IN_RECORDED_ENVIRONMENT' if outputs[0]==outputs[1] else 'DIFFERENT_OUTPUTS'}
        finally:os.close(source_root)
        for name,value in inputs.items():
            if trusted_input(name)!=value:raise p.BoundaryError('JOURNAL_INVALID')
        report={'version':1,'recipe':{'flags':list(FLAGS),'sources':list(SOURCES)},'compiler':compiler,
                'compiler_version_sha256':version,'compiler_specs_sha256':specs,'inputs':list(inputs.values()),
                'fixtures':results,'status':'MATCHED' if all(v['outputs'][0]==v['outputs'][1] for v in results.values()) else 'DIFFERENT',
                'reproducibility':'UNPROVEN','fixtures_executed':False,'qualified':False}
        i.encode(report);return report


def check_binding(report,provenance):
    """Compare freshly produced build observations; no caller authority claim."""
    if (report.get('version')!=1 or report.get('status')!='MATCHED' or report.get('qualified') is not False
            or report.get('fixtures_executed') is not False or report.get('reproducibility')!='UNPROVEN'
            or report.get('recipe')!={'flags':list(FLAGS),'sources':list(SOURCES)}):
        raise p.BoundaryError('POLICY_REJECTED')
    try:
        compilers=[v for v in report['inputs'] if v['path']==report['compiler']]
        if (len(compilers)!=1 or compilers[0]['sha256']!=provenance['compiler_sha256']
                or i.digest(report['recipe'])!=provenance['build_recipe_sha256']
                or i.digest(report)!=provenance['build_record_sha256']):raise p.BoundaryError('POLICY_REJECTED')
        for name,key,source in (('synthetic_worker.c','synthetic_sha256','synthetic_source_sha256'),
                               ('security_probe.c','security_probe_sha256','fixture_source_sha256')):
            fixture=report['fixtures'][name]
            if (fixture['source_sha256']!=provenance[source] or fixture['outputs']!=[provenance[key]]*2
                    or fixture['status']!='REPEATABLE_IN_RECORDED_ENVIRONMENT'):
                raise p.BoundaryError('POLICY_REJECTED')
    except (KeyError,TypeError):raise p.BoundaryError('POLICY_REJECTED') from None
    return {'build':'REPEATABLE_IN_RECORDED_ENVIRONMENT','reproducibility':'UNPROVEN','qualified':False}
