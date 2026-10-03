"""Independent static staging analysis; no target imports, loader or fixture exec.

Conservative CPython3.12/x86_64 profile. Unsupported dynamic/platform imports
remain unresolved. Results describe metadata analysis, never runtime authority.
"""
import ast
import hashlib
import os
import struct
import time
from . import protocol as p, inventory as i, build_closure as c
from .linux import secure_open

MAX_AST_NODES=100000
MAX_PY_BYTES=256*1024
MAX_DYNAMIC=4096
MAX_STRINGS=1024*1024
ENTRYPOINTS=('orchestrator.privilege.service','orchestrator.privilege.child','encodings','importlib','site')
PREFIXES=('package/','python_base/lib/python3.12/','venv/lib/python3.12/')
# Fixed profile expectations, not discovered by importing the target interpreter.
# Actual CPython build support must independently match this profile before use.
BUILTINS=frozenset(('sys','builtins','_io','_thread','posix','time','errno','_signal',
                   'marshal','gc','atexit','_imp','_warnings','_weakref','_abc','itertools'))
LIBDIRS=('python_base/lib','runtime/lib','runtime/lib64')
INTERPRETERS={'/lib64/ld-linux-x86-64.so.2':'runtime/lib64/ld-linux-x86-64.so.2',
              '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2':'runtime/lib64/ld-linux-x86-64.so.2'}


def syntax(raw):
    if type(raw) is not bytes or len(raw)>MAX_PY_BYTES:raise p.BoundaryError('BOUNDS_EXCEEDED')
    try:tree=ast.parse(raw.decode('utf-8'))
    except (ValueError,UnicodeError,SyntaxError,RecursionError):raise p.BoundaryError('POLICY_REJECTED') from None
    nodes=[]
    for node in ast.walk(tree):
        if len(nodes)>=MAX_AST_NODES:raise p.BoundaryError('BOUNDS_EXCEEDED')
        nodes.append(node)
    return tree,nodes


def imports(raw,module,package=False):
    _,nodes=syntax(raw)
    names=[];unresolved=[];aliases={}
    for node in nodes:
        if isinstance(node,ast.Import):
            for alias in node.names:
                names.append((alias.name,False));aliases[alias.asname or alias.name]=alias.name
        elif isinstance(node,ast.ImportFrom):
            parts=module.split('.') if package else module.split('.')[:-1]
            if node.level:
                if node.level>len(parts):unresolved.append('RELATIVE_IMPORT_ESCAPE');continue
                parts=parts[:len(parts)-node.level+1]
                base='.'.join(parts+([node.module] if node.module else []))
            else:base=node.module or ''
            if not base:unresolved.append('IMPORT_BASE_MISSING');continue
            names.append((base,False))
            for alias in node.names:
                if alias.name=='*':unresolved.append('STAR_IMPORT_UNRESOLVED')
                else:
                    names.append((base+'.'+alias.name,True))  # may be an attribute
                    aliases[alias.asname or alias.name]=base+'.'+alias.name
        elif isinstance(node,ast.Call):
            fn=node.func
            parts=[]
            while isinstance(fn,ast.Attribute):parts.append(fn.attr);fn=fn.value
            dotted='.'.join([fn.id,*reversed(parts)]) if isinstance(fn,ast.Name) else ''
            first,_,tail=dotted.partition('.')
            resolved=aliases.get(first,first)+('.'+tail if tail else '')
            if resolved in ('__import__','builtins.__import__','importlib.import_module'):
                if (len(node.args)==1 and not node.keywords and isinstance(node.args[0],ast.Constant)
                        and type(node.args[0].value) is str and not node.args[0].value.startswith('.')):
                    names.append((node.args[0].value,False))
                else:unresolved.append('DYNAMIC_IMPORT_UNRESOLVED')
            elif resolved in ('importlib.util.spec_from_file_location','importlib.util.module_from_spec') or resolved.endswith(('.load_module','.exec_module')):
                unresolved.append('DYNAMIC_IMPORT_UNRESOLVED')
            elif resolved in ('ctypes.CDLL','ctypes.PyDLL') and not (node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value is None):
                unresolved.append('DYNAMIC_NATIVE_UNRESOLVED')
            elif resolved in ('eval','exec','builtins.eval','builtins.exec'):
                unresolved.append('DYNAMIC_CODE_UNRESOLVED')
    return sorted(set(names)),sorted(set(unresolved))


def elf(raw):
    """ELF64 LE x86_64 PT_INTERP/DT_NEEDED; rejects unsupported search semantics."""
    if type(raw) is not bytes or not 64<=len(raw)<=c.n.MAX_FILE:raise p.BoundaryError('POLICY_REJECTED')
    def unpack(fmt,offset):
        size=struct.calcsize(fmt)
        if offset<0 or offset+size>len(raw):raise p.BoundaryError('POLICY_REJECTED')
        return struct.unpack_from(fmt,raw,offset)
    if raw[:7]!=b'\x7fELF\x02\x01\x01':raise p.BoundaryError('POLICY_REJECTED')
    h=unpack('<HHIQQQIHHHHHH',16)
    if h[0] not in (2,3) or h[1]!=62 or h[2]!=1 or h[7]!=64 or h[8]!=56 or not 0<h[9]<=128:raise p.BoundaryError('POLICY_REJECTED')
    loads=[];dynamic=None;interpreter=None
    def region(offset,size):
        if offset<0 or size<0 or offset+size>len(raw):raise p.BoundaryError('POLICY_REJECTED')
        return raw[offset:offset+size]
    def string(blob,offset=0):
        if not 0<=offset<len(blob):raise p.BoundaryError('POLICY_REJECTED')
        end=blob.find(b'\0',offset)
        if end<0 or end-offset>240:raise p.BoundaryError('POLICY_REJECTED')
        try:return blob[offset:end].decode('ascii')
        except UnicodeError:raise p.BoundaryError('POLICY_REJECTED') from None
    for index in range(h[9]):
        typ,flags,off,addr,_,size,mem,align=unpack('<IIQQQQQQ',h[4]+index*56)
        region(off,size)
        if size>mem:raise p.BoundaryError('POLICY_REJECTED')
        if typ==1:loads.append((addr,off,size))
        elif typ==2:
            if dynamic is not None or size%16 or size//16>MAX_DYNAMIC:raise p.BoundaryError('POLICY_REJECTED')
            dynamic=(off,size)
        elif typ==3:
            if interpreter is not None or not 1<=size<=241:raise p.BoundaryError('POLICY_REJECTED')
            blob=region(off,size);interpreter=string(blob)
            if blob!=interpreter.encode()+b'\0':raise p.BoundaryError('POLICY_REJECTED')
    if not loads:raise p.BoundaryError('POLICY_REJECTED')
    tags={};needed=[]
    if dynamic:
        terminated=False
        for off in range(dynamic[0],sum(dynamic),16):
            tag,value=unpack('<qQ',off)
            if tag==0:terminated=True;break
            if tag in (0x6ffffefa,0x6ffffefb,0x6ffffefc,0x7ffffffd,0x7fffffff):raise p.BoundaryError('POLICY_REJECTED')
            if tag==1:needed.append(value)
            elif tag in (5,10,15,29,0x7ffffffb):
                if tag in tags:raise p.BoundaryError('POLICY_REJECTED')
                tags[tag]=value
        if not terminated or 15 in tags or 29 in tags or tags.get(0x7ffffffb,0)&0x800:
            raise p.BoundaryError('POLICY_REJECTED')  # RPATH/RUNPATH/NODEFLIB unsupported
        if needed:
            if 5 not in tags or not 0<tags.get(10,0)<=MAX_STRINGS:raise p.BoundaryError('POLICY_REJECTED')
            candidates=[off+tags[5]-addr for addr,off,size in loads if addr<=tags[5] and tags[5]+tags[10]<=addr+size]
            if len(candidates)!=1:raise p.BoundaryError('POLICY_REJECTED')
            table=region(candidates[0],tags[10]);needed=[string(table,v) for v in needed]
    if len(needed)>128 or len(set(needed))!=len(needed) or any('/' in v or not v or v in ('.','..') for v in needed):raise p.BoundaryError('POLICY_REJECTED')
    return {'interpreter':interpreter,'needed':sorted(needed)}


def analyze(tree,snapshot,closure,binding,provenance):
    """Fresh FD-bound source/ELF observations compared to declared graph edges."""
    closure_sha=c.validate(closure,tree.manifest,binding,provenance);tree.recheck(snapshot)
    files={v['path']:v for v in tree.manifest['nodes'] if v['type']=='file'}
    declared={v['path']:set(v['requires']) for v in closure['artifacts']}
    modules={};unresolved=set();derived={};native={};started=tree.clock();total=0
    def read(path):
        nonlocal total
        if tree.clock()-started>c.n.MAX_SECONDS:raise p.BoundaryError('BOUNDS_EXCEEDED')
        fd=secure_open(tree.fd,path)
        try:
            before=os.fstat(fd);chunks=[];size=0
            while True:
                block=os.read(fd,65536)
                if not block:break
                size+=len(block);total+=len(block)
                if size>c.n.MAX_FILE or total>c.n.MAX_TOTAL or tree.clock()-started>c.n.MAX_SECONDS:raise p.BoundaryError('BOUNDS_EXCEEDED')
                chunks.append(block)
            raw=b''.join(chunks)
            if i._identity(before)!=i._identity(os.fstat(fd)) or hashlib.sha256(raw).hexdigest()!=files[path]['sha256']:raise p.BoundaryError('JOURNAL_INVALID')
            return raw
        finally:os.close(fd)
    for path in files:
        for prefix in PREFIXES:
            if path.startswith(prefix):
                relative=path[len(prefix):]
                if relative.startswith('lib-dynload/'):relative=relative[len('lib-dynload/'):]
                if relative.endswith('.py'):name=relative[:-3].replace('/','.');package=name.endswith('.__init__');name=name.removesuffix('.__init__')
                elif relative.endswith(('.cpython-312-x86_64-linux-gnu.so','.abi3.so','.so')):
                    name=relative.split('.')[0].replace('/','.');package=name.endswith('.__init__');name=name.removesuffix('.__init__')
                else:continue
                if name in modules:unresolved.add('AMBIGUOUS_MODULE:'+name)
                else:modules[name]=(path,package)
    def resolve(name,attribute=False):
        if name in BUILTINS:return None
        if name=='orchestrator':return None  # one explicit namespace package
        found=modules.get(name)
        if found is None:
            if attribute:
                base,_,symbol=name.rpartition('.')
                if base in BUILTINS:return None
                parent=modules.get(base)
                exports=set()
                if parent and parent[0].endswith('.py'):
                    parent_tree,_=syntax(read(parent[0]))
                    for node in parent_tree.body:
                        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):exports.add(node.name)
                        elif isinstance(node,ast.Assign):exports.update(t.id for t in node.targets if isinstance(t,ast.Name))
                        elif isinstance(node,ast.AnnAssign) and isinstance(node.target,ast.Name):exports.add(node.target.id)
                        elif isinstance(node,(ast.Import,ast.ImportFrom)):
                            exports.update(a.asname or a.name.split('.')[0] for a in node.names)
                if symbol not in exports:unresolved.add('IMPORT_ATTRIBUTE_UNRESOLVED:'+name)
            else:unresolved.add('MISSING_MODULE:'+name)
            return None
        # Importing a child executes every non-namespace parent __init__.
        for count in range(1,len(name.split('.'))):
            parent='.'.join(name.split('.')[:count])
            if parent!='orchestrator' and (parent not in modules or not modules[parent][1]):unresolved.add('MISSING_PACKAGE:'+parent)
            elif parent in modules:pending.add(parent)
        pending.add(name);return found[0]
    pending=set(ENTRYPOINTS);seen=set()
    while pending:
        module=pending.pop()
        if module in seen:continue
        seen.add(module)
        found=modules.get(module)
        if found is None:unresolved.add('MISSING_MODULE:'+module);continue
        path,package=found;edges=set()
        for count in range(1,len(module.split('.'))):
            parent='.'.join(module.split('.')[:count])
            if parent=='orchestrator':continue
            info=modules.get(parent)
            if info is None or not info[1]:unresolved.add('MISSING_PACKAGE:'+parent)
            else:edges.add(info[0]);pending.add(parent)
        raw=read(path)
        if path.endswith('.py'):
            names,issues=imports(raw,module,package)
            unresolved.update(path+':'+v for v in issues)
            for name,attribute in names:
                target=resolve(name,attribute)
                if target:edges.add(target)
        derived[path]=edges
    # Every native artifact, not just declared/reachable executable edges.
    for path in files:
        if path.endswith('.so') or '.so.' in path or path in c.ROOTS:
            try:metadata=elf(read(path))
            except p.BoundaryError:unresolved.add('ELF_UNSUPPORTED:'+path);continue
            edges=set();native[path]=metadata
            if metadata['interpreter']:
                loader=INTERPRETERS.get(metadata['interpreter'])
                if loader not in files:unresolved.add('LOADER_UNRESOLVED:'+path)
                else:edges.add(loader)
            for library in metadata['needed']:
                candidates=[d+'/'+library for d in LIBDIRS if d+'/'+library in files]
                if len(candidates)!=1:unresolved.add('LIBRARY_UNRESOLVED:'+path+':'+library)
                else:edges.add(candidates[0])
            derived.setdefault(path,set()).update(edges)
    for path,edges in derived.items():
        for target in edges-declared[path]:unresolved.add('DECLARED_EDGE_MISSING:'+path+':'+target)
    tree.recheck(snapshot)
    result={'version':1,'closure_sha256':closure_sha,'snapshot_sha256':i.digest(snapshot),
            'status':'UNRESOLVED' if unresolved else 'STATIC_METADATA_VERIFIED',
            'issues':sorted(unresolved),'derived':{k:sorted(v) for k,v in sorted(derived.items())},
            'native':native,'runtime_loader':'UNPROVEN','qualified':False}
    i.encode(result);return result
