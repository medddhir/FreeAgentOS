"""One fixed host-to-private-staging candidate, never an installed authority.

Only Ubuntu 24.04 amd64 CPython 3.12 paths are considered. Missing imports and
unsupported static semantics remain findings, not excuses to execute code.
All deadlines are cooperative; filesystem reads need future containment.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from . import fixture_build as build
from .privilege import build_closure as c, closure_verify as v
from .privilege import installed_identity as n, inventory as i, protocol as p
from .privilege.linux import secure_open
from .privilege.policy import policy_hash

STDLIB=Path('/usr/lib/python3.12')
NATIVE=Path('/usr/lib/x86_64-linux-gnu')
PACKAGE=Path(__file__).parent
MODULE=re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z')


def _read(root,relative,*,system=False):
    """Pinned, no-follow read; a registered fixed root, never an RPC path."""
    root=Path(root)
    if not root.is_absolute():raise p.BoundaryError('PATH_REJECTED')
    anchor=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    fd=None
    try:
        for part in root.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=anchor)
            os.close(anchor);anchor=child
            info=os.fstat(anchor)
            if (info.st_uid not in (0,os.getuid()) or system and info.st_uid!=0
                    or info.st_mode&0o022):raise p.BoundaryError('POLICY_REJECTED')
        parent=os.fstat(anchor)
        if system and (parent.st_uid!=0 or parent.st_mode&0o022):raise p.BoundaryError('POLICY_REJECTED')
        # Absence is only a discovery finding. This lookup grants no read;
        # existing objects still require race-safe openat2 below the pinned root.
        os.stat(relative,dir_fd=anchor,follow_symlinks=False)
        fd=secure_open(anchor,relative)
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_mode&0o022
                or system and before.st_uid!=0 or not 0<=before.st_size<=n.MAX_FILE):
            raise p.BoundaryError('POLICY_REJECTED')
        raw=bytearray()
        while True:
            block=os.read(fd,65536)
            if not block:break
            raw.extend(block)
            if len(raw)>n.MAX_FILE:raise p.BoundaryError('BOUNDS_EXCEEDED')
        check=secure_open(anchor,relative)
        try:
            if (i._identity(before)!=i._identity(os.fstat(fd))
                    or i._identity(before)!=i._identity(os.fstat(check))
                    or len(raw)!=before.st_size):raise p.BoundaryError('JOURNAL_INVALID')
        finally:os.close(check)
        return bytes(raw)
    finally:
        if fd is not None:os.close(fd)
        os.close(anchor)


class Candidate:
    """Owns only its newly created private temporary tree; no activation method.

    AST/ELF derivation generates graph candidates. Existing independent analyze
    re-reads the staged bytes and checks the graph. Neither result proves loader
    behavior, protected installation, or complete semantics of dynamic Python.
    """
    def __init__(self,source_commit):
        if not p.identifier(source_commit,40):raise p.BoundaryError('POLICY_REJECTED')
        self.temp=tempfile.TemporaryDirectory(prefix='freeagent-concrete-bundle-')
        self.path=Path(self.temp.name);self.path.chmod(0o700)
        self.files={};self.edges={};self.findings=set();self.started=time.monotonic()
        self.tree=None;self.commit=source_commit
        try:self._assemble()
        except BaseException:self.close();raise
    def _add(self,path,raw):
        if path in self.files:
            if self.files[path]!=raw:raise p.BoundaryError('JOURNAL_INVALID')
            return
        if (len(self.files)>=n.MAX_NODES or sum(map(len,self.files.values()))+len(raw)>n.MAX_TOTAL
                or time.monotonic()-self.started>build.MAX_CAMPAIGN_SECONDS):raise p.BoundaryError('BOUNDS_EXCEEDED')
        self.files[path]=raw;self.edges[path]=set()
    def _module(self,name):
        if not MODULE.fullmatch(name):return None
        if name in v.BUILTINS or name=='orchestrator':return None
        rel=name.replace('.','/')
        if name.startswith('orchestrator.'):
            root=PACKAGE;rel=rel[len('orchestrator/'):];prefix='package/orchestrator/';system=False
        else:root=STDLIB;prefix='python_base/lib/python3.12/';system=True
        found=[]
        for suffix in ('.py','/__init__.py'):
            try:raw=_read(root,rel+suffix,system=system)
            except FileNotFoundError:continue
            except p.BoundaryError as error:
                if error.code!='PATH_REJECTED':raise
                self.findings.add('SOURCE_PATH_REJECTED:'+prefix+rel+suffix);continue
            found.append((prefix+rel+suffix,raw))
        if not found and system and '.' not in name:
            ext='lib-dynload/'+name+'.cpython-312-x86_64-linux-gnu.so'
            try:found.append((prefix+ext,_read(root,ext,system=True)))
            except FileNotFoundError:pass
        if len(found)>1:raise p.BoundaryError('POLICY_REJECTED')
        if not found:return None
        path,raw=found[0];self._add(path,raw);return path
    def _assemble(self):
        os_release=_read('/usr/lib','os-release',system=True).decode('utf-8')
        if 'ID=ubuntu\n' not in os_release or 'VERSION_ID="24.04"' not in os_release or os.uname().machine!='x86_64':
            raise p.BoundaryError('POLICY_REJECTED')
        # Package/version database and ELF metadata identify inputs without
        # running the target interpreter. Runtime version itself remains unproven.
        _read(STDLIB,'__future__.py',system=True)
        inspector=build.trusted_input('/usr/bin/dpkg-query')
        versions=build._run([inspector['path'],'-W','-f=${Package} ${Version}\n',
                             'python3.12-minimal','libpython3.12-stdlib'],cwd=self.path).decode('ascii')
        if (len(versions.splitlines())!=2 or any(not line.split()[1].startswith('3.12.') for line in versions.splitlines())):
            raise p.BoundaryError('POLICY_REJECTED')
        interpreter=_read('/usr/bin','python3.12',system=True)
        v.elf(interpreter)
        self.inputs={'distribution_sha256':hashlib.sha256(os_release.encode()).hexdigest(),
            'interpreter_sha256':hashlib.sha256(interpreter).hexdigest(),
            'package_versions':versions.splitlines(),'architecture':'x86_64',
            'runtime_version':'UNPROVEN','metadata_inspector':inspector}
        self._add('venv/bin/python',interpreter)
        self._add('venv/pyvenv.cfg',b'home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12\n')
        self._add('runtime/.freeagent-runtime',b'STAGING_ONLY_UBUNTU24_PY312_SUPERVISOR_V1\n')
        self._add('python_base/lib/libpython3.12.so.1.0',_read(NATIVE,'libpython3.12.so.1.0',system=True))
        for path in sorted(n.REQUIRED_FILES|c.PACKAGE_FILES):
            if path.startswith('package/'):
                self._add(path,_read(PACKAGE,path[len('package/orchestrator/'):]))
            elif path.startswith('python_base/lib/python3.12/'):
                self._add(path,_read(STDLIB,path[len('python_base/lib/python3.12/'):],system=True))
        expected={name:hashlib.sha256(self.files['package/orchestrator/privilege/fixtures/'+name]).hexdigest() for name in build.SOURCES}
        outputs={};self.builds=build.compare(expected,_artifacts=outputs)
        for name,target in (('synthetic_worker.c','synthetic-worker'),('security_probe.c','security-probe')):
            if name not in outputs:raise p.BoundaryError('POLICY_REJECTED')
            self._add('runtime/bin/'+target,outputs[name])
        pending=set(v.ENTRYPOINTS);seen=set()
        while pending:
            name=min(pending);pending.remove(name)
            if name in seen:continue
            seen.add(name);path=self._module(name)
            if path is None:
                if name not in v.BUILTINS and name!='orchestrator':self.findings.add('UNRESOLVED_MODULE:'+name)
                continue
            for count in range(1,len(name.split('.'))):
                parent='.'.join(name.split('.')[:count]);target=self._module(parent)
                if target and target!=path:self.edges[path].add(target);pending.add(parent)
            if not path.endswith('.py'):continue
            if len(self.files[path])>v.MAX_PY_BYTES:
                self.findings.add('SOURCE_ANALYSIS_BOUND:'+path);continue
            names,issues=v.imports(self.files[path],name,path.endswith('/__init__.py'))
            self.findings.update(path+':'+issue for issue in issues)
            for dependency,attribute in names:
                target=self._module(dependency)
                if target:
                    if target!=path:self.edges[path].add(target)
                    pending.add(dependency)
                elif not attribute and dependency not in v.BUILTINS and dependency!='orchestrator':
                    self.findings.add('UNRESOLVED_MODULE:'+dependency)
        # Native basenames come solely from bounded ELF metadata, searched only
        # in the fixed Ubuntu multiarch layout. No ldd or target binary execution.
        self._add('runtime/lib64/ld-linux-x86-64.so.2',_read(NATIVE,'ld-linux-x86-64.so.2',system=True))
        done=set()
        while True:
            paths=sorted(path for path in self.files if (path in c.ROOTS or '.so' in path) and path not in done)
            if not paths:break
            for path in paths:
                done.add(path)
                try:metadata=v.elf(self.files[path])
                except p.BoundaryError:self.findings.add('ELF_UNSUPPORTED:'+path);continue
                if metadata['interpreter']:
                    target=v.INTERPRETERS.get(metadata['interpreter'])
                    if target:self.edges[path].add(target)
                    else:self.findings.add('LOADER_UNRESOLVED:'+path)
                for library in metadata['needed']:
                    if not re.fullmatch(r'[A-Za-z0-9_+.-]+\.so(?:\.[0-9]+)*',library):raise p.BoundaryError('POLICY_REJECTED')
                    target='runtime/lib64/'+library if library=='ld-linux-x86-64.so.2' else 'runtime/lib/'+library
                    if target not in self.files:
                        # Ubuntu SONAME symlinks are resolved to one immutable
                        # regular artifact by the existing tool-input validator.
                        identity=build.trusted_input(NATIVE/library)
                        source=Path(identity['path']);raw=_read(source.parent,source.name,system=True)
                        if hashlib.sha256(raw).hexdigest()!=identity['sha256']:raise p.BoundaryError('JOURNAL_INVALID')
                        self._add(target,raw)
                    if target!=path:self.edges[path].add(target)
        nodes={}
        for path,raw in self.files.items():
            nodes[path]={'path':path,'type':'file','mode':0o755 if path in c.ROOTS else 0o644,'sha256':hashlib.sha256(raw).hexdigest()}
            parent=Path(path).parent
            while str(parent)!='.':
                key=parent.as_posix();nodes[key]={'path':key,'type':'directory','mode':0o755,'sha256':None};parent=parent.parent
        for path in n.RUNTIME_DIRS:nodes[path]={'path':path,'type':'directory','mode':0o755,'sha256':None}
        self.manifest={'version':1,'kind':'REVIEWED_STAGING_DEPENDENCIES','nodes':[nodes[k] for k in sorted(nodes)]}
        n.validate_manifest(self.manifest)
        for node in self.manifest['nodes']:
            dest=self.path/node['path']
            if node['type']=='directory':dest.mkdir(exist_ok=True);dest.chmod(node['mode'])
            else:
                fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,node['mode'])
                with os.fdopen(fd,'wb') as file:file.write(self.files[node['path']])
                dest.chmod(node['mode'])
        hashes={path:hashlib.sha256(raw).hexdigest() for path,raw in self.files.items()}
        self.provenance={'synthetic_sha256':hashes['runtime/bin/synthetic-worker'],
            'security_probe_sha256':hashes['runtime/bin/security-probe'],
            'synthetic_source_sha256':expected['synthetic_worker.c'],'fixture_source_sha256':expected['security_probe.c'],
            'compiler_sha256':next(x['sha256'] for x in self.builds['inputs'] if x['path']==self.builds['compiler']),
            'build_recipe_sha256':i.digest(self.builds['recipe']),'build_record_sha256':i.digest(self.builds),
            'launcher_sha256':hashes['venv/bin/python']}
        self.binding={'source_commit':self.commit,'policy':policy_hash()}
        # Interpreter runtime profile explicitly requires the staged base and
        # all selected stdlib files/config; this is graph reachability, not proof.
        self.edges['venv/bin/python'].update(path for path in self.files if not path.startswith('package/') and path not in c.ROOTS)
        self.closure={'version':1,'layout':c.LAYOUT,**self.binding,'manifest_sha256':i.digest(self.manifest),
            'artifacts':[{'path':path,'category':c.category(path),'sha256':hashes[path],'requires':sorted(self.edges[path])} for path in sorted(self.files)],
            'roots':sorted(c.ROOTS|{path for path in self.files if path.startswith('package/')}),
            'third_party':[],'unresolved':[],'provenance':self.provenance,
            'verification':{'dependency_closure':'DECLARED','build':'UNPROVEN','reproducibility':'UNPROVEN'}}
        self.tree=n.StagingDependencies(self.path,self.manifest)
        self.snapshot=self.tree.capture()
        self.analysis=v.analyze(self.tree,self.snapshot,self.closure,self.binding,self.provenance)
    def prerequisite(self):
        """Fresh existing verifier gate; no receipt/credentials/authority invented."""
        return c.StagingClosureRegistration.candidate_prerequisite(
            self.tree,self.snapshot,self.closure,self.binding,self.provenance)
    def close(self):
        if self.tree is not None:self.tree.close();self.tree=None
        self.temp.cleanup()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
