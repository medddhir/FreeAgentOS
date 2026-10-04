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
EXPORT_RULE_VERSION=7
MAX_EXPORT_DEPTH=32
MAX_EXPORT_ENTRIES=16384
MAX_EXPORT_QUERIES=32768
MAX_ALL_NAMES=1024
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
    return _imports(nodes,module,package)


def _imports(nodes,module,package):
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
                if alias.name=='*':names.append((base+'.*',True))
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


def _import_base(node,module,package):
    parts=module.split('.') if package else module.split('.')[:-1]
    if node.level:
        if node.level>len(parts):return None
        parts=parts[:len(parts)-node.level+1]
        return '.'.join(parts+([node.module] if node.module else [])) or None
    return node.module or None


class _Exports:
    """Per-observation source proofs, not runtime imports or native evidence.

    Cache keys include rule, manifest digest and pinned observation identity.
    An allowed module name never supplies evidence about its attributes.
    Unsupported mutation/publication remains unproven; no target code runs.
    """
    def __init__(self,modules,files,snapshot,read,module,unresolved,bounded):
        self.modules=modules;self.files=files;self.read=read;self.module=module
        self.unresolved=unresolved;self.bounded=bounded
        self.identities={row['path']:tuple(sorted(row['identity'].items())) for row in snapshot['nodes']}
        self.indexes={};self.cache={};self.imported={};self.positions={};self.entries=0;self.queries=0;self.stored_nodes=0
    def _key(self,name):
        found=self.modules.get(name)
        if found is None or not found[0].endswith('.py'):return None
        path=found[0]
        return (EXPORT_RULE_VERSION,path,self.files[path]['sha256'],self.identities[path])
    def _index(self,name):
        key=self._key(name)
        if key is None:return None
        if key in self.indexes:return self.indexes[key]
        path=key[1];raw=self.read(path)
        if len(raw)>MAX_PY_BYTES:
            self.unresolved.add('SOURCE_ANALYSIS_BOUND:'+path);self.indexes[key]=None
            self.imported[key]=([],[]);return None
        tree,nodes=syntax(raw)
        self.imported[key]=_imports(nodes,name,self.modules[name][1])
        bindings={};unsafe=set();stars=[];tainted=False;positions={}
        def bind(symbol,value):
            self.entries+=1
            if self.entries>MAX_EXPORT_ENTRIES:raise p.BoundaryError('BOUNDS_EXCEEDED')
            # Retain only immediate expressions, not function/class bodies.
            expressions=[x for x in value[1:] if x is not None] if value[0]=='expression' else value[2] if value[0]=='definition' else []
            self.stored_nodes+=sum(1 for expression in expressions for _ in ast.walk(expression))
            if self.stored_nodes>MAX_AST_NODES:raise p.BoundaryError('BOUNDS_EXCEEDED')
            if symbol in bindings:unsafe.add(symbol)
            bindings[symbol]=value;positions[symbol]=position
        def effects(node,*,eager_expression=False):
            # Module-evaluated effects only. Function bodies remain dormant;
            # executable class bodies and implicit decorators are rejected.
            nonlocal tainted
            pending=[(node,eager_expression)]
            while pending:
                current,eager=pending.pop()
                self.bounded()
                # Defaults/annotations may invoke hooks before any export is
                # requested. Demand-driven proof of the definition is too late.
                if eager and isinstance(current,(ast.Call,ast.Attribute,ast.Subscript)):
                    tainted=True
                if isinstance(current,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                    unsafe.add(current.name)
                    if current.decorator_list or isinstance(current,ast.ClassDef) and not plain_class(current):
                        tainted=True
                    pending.extend((value,True) for value in immediate(current));continue
                if isinstance(current,ast.Lambda):
                    pending.extend((value,True) for value in current.args.defaults)
                    pending.extend((x,True) for x in current.args.kw_defaults if x is not None)
                    continue  # body writes belong to the dormant lambda scope
                if isinstance(current,ast.ExceptHandler) and current.name:
                    # CPython binds then clears this string-valued target.
                    unsafe.add(current.name)
                if isinstance(current,ast.NamedExpr):
                    unsafe.add(current.target.id)
                    pending.append((current.value,eager));continue
                if isinstance(current,ast.comprehension):
                    # Iteration targets are comprehension-local; named expressions
                    # in evaluated iterables/filters still affect the outer scope.
                    pending.append((current.iter,eager));pending.extend((x,eager) for x in current.ifs);continue
                if isinstance(current,ast.Import):unsafe.update(a.asname or a.name.split('.')[0] for a in current.names)
                if isinstance(current,ast.ImportFrom):
                    if any(a.name=='*' for a in current.names):unsafe.add('__getattr__')
                    unsafe.update(a.asname or a.name for a in current.names)
                if isinstance(current,ast.Name) and isinstance(current.ctx,(ast.Store,ast.Del)):unsafe.add(current.id)
                pending.extend((value,eager) for value in ast.iter_child_nodes(current))
        def immediate(node):
            values=list(node.decorator_list)
            if isinstance(node,ast.ClassDef):
                return values+list(node.bases)+[x.value for x in node.keywords]
            values+=list(node.args.defaults)+[x for x in node.args.kw_defaults if x is not None]
            values += [x.annotation for x in (*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs) if x.annotation is not None]
            values += [x.annotation for x in (node.args.vararg,node.args.kwarg) if x and x.annotation is not None]
            if node.returns is not None:values.append(node.returns)
            return values
        def plain_class(node):
            return not node.bases and not node.keywords and all(
                isinstance(x,ast.Pass) or isinstance(x,ast.Expr) and isinstance(x.value,ast.Constant) for x in node.body)
        for position,node in enumerate(tree.body):
            self.bounded()
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                evaluated=immediate(node)
                for value in evaluated:effects(value,eager_expression=True)
                valid=not node.decorator_list and not getattr(node,'type_params',[])
                if node.decorator_list:tainted=True
                if isinstance(node,ast.ClassDef):
                    plain=plain_class(node)
                    if not plain:tainted=True
                    valid=valid and plain
                else:
                    if any(isinstance(x,ast.Call) for value in evaluated for x in ast.walk(value)):tainted=True
                bind(node.name,('definition',valid,evaluated))
            elif isinstance(node,ast.Assign):
                effects(node.value)
                if any(isinstance(x,ast.Call) for x in ast.walk(node.value)):tainted=True
                for target in node.targets:
                    if isinstance(target,ast.Name):bind(target.id,('expression',node.value))
                    else:effects(target);tainted=True
            elif isinstance(node,ast.AnnAssign):
                if node.value is not None:effects(node.value)
                # Module annotation evaluation is not demand-driven publication.
                # Deferred semantics remain unsupported/conservatively rejected.
                effects(node.annotation,eager_expression=True)
                if any(isinstance(x,ast.Call) for value in (node.value,node.annotation) if value for x in ast.walk(value)):tainted=True
                if isinstance(node.target,ast.Name):bind(node.target.id,('expression',node.value,node.annotation))
                else:effects(node);tainted=True
            elif isinstance(node,ast.Import):
                for alias in node.names:
                    bind(alias.asname or alias.name.split('.')[0],('module',alias.name if alias.asname else alias.name.split('.')[0],alias.name))
            elif isinstance(node,ast.ImportFrom):
                base=_import_base(node,name,self.modules[name][1])
                for alias in node.names:
                    if alias.name=='*':stars.append((base,position))
                    else:bind(alias.asname or alias.name,('import',base,alias.name))
            elif isinstance(node,ast.Pass) or isinstance(node,ast.Expr) and isinstance(node.value,ast.Constant):pass
            else:
                effects(node)
                # Unknown module-scope calls/attribute writes can mutate globals;
                # do not infer publication through globals(), hooks or exec.
                if any(isinstance(x,(ast.Call,ast.Attribute,ast.Subscript)) for x in ast.walk(node)):tainted=True
        if {'__getattr__','__dir__'} & (bindings.keys()|unsafe):tainted=True
        result=(bindings,unsafe,stars,tainted)
        self.positions[key]=positions;self.indexes[key]=result;return result
    def source_imports(self,name):
        self._index(name)
        return self.imported[self._key(name)]
    def _expression(self,node,name,depth,visiting,position):
        self.queries+=1;self.bounded()
        if depth>MAX_EXPORT_DEPTH or self.queries>MAX_EXPORT_QUERIES:
            self.unresolved.add('EXPORT_ANALYSIS_BOUND:'+name);return None
        if isinstance(node,ast.Constant):return ('VALUE',None)
        if isinstance(node,(ast.List,ast.Tuple,ast.Set)):
            return ('VALUE',None) if all(self._expression(x,name,depth+1,visiting,position) for x in node.elts) else None
        if isinstance(node,ast.Dict):
            return ('VALUE',None) if all(k is not None and self._expression(k,name,depth+1,visiting,position)
                and self._expression(v,name,depth+1,visiting,position) for k,v in zip(node.keys,node.values)) else None
        if isinstance(node,ast.UnaryOp) and isinstance(node.op,(ast.UAdd,ast.USub)) and isinstance(node.operand,ast.Constant) and type(node.operand.value) in (int,float,complex):return ('VALUE',None)
        if isinstance(node,ast.Name):
            value=self.proof(name,node.id,depth+1,visiting)
            index=self._index(name);positions=self.positions.get(self._key(name),{})
            if node.id in positions:
                return value if positions[node.id]<position else None
            if index and index[2] and all(at<position for _,at in index[2]):return value
            return None
        if isinstance(node,ast.Attribute):
            base=self._expression(node.value,name,depth+1,visiting,position)
            if base and base[0]=='MODULE':
                if base[1]==name and self.positions[self._key(name)].get(node.attr,position)>=position:return None
                return self.proof(base[1],node.attr,depth+1,visiting)
        return None
    def proof(self,name,symbol,depth=0,visiting=frozenset(),*,import_child=False):
        self.queries+=1;self.bounded()
        if type(symbol) is not str or not symbol.isidentifier() or len(symbol)>128:return None
        if depth>MAX_EXPORT_DEPTH or self.queries>MAX_EXPORT_QUERIES:
            self.unresolved.add('EXPORT_ANALYSIS_BOUND:'+name);return None
        key=self._key(name)
        # Exact child membership supports import syntax, never an ordinary
        # attribute expression. No global import-order/publication simulation.
        if import_child and name=='orchestrator' and name+'.'+symbol in self.modules and self.module(name+'.'+symbol):
            return ('MODULE',name+'.'+symbol)
        if key is None:return None  # builtin/frozen/native attribute evidence absent
        query=(key,symbol,import_child)
        if query in visiting:
            self.unresolved.add('EXPORT_CYCLE_UNRESOLVED:'+name+'.'+symbol);return None
        if query in self.cache:return self.cache[query]
        visiting=visiting|{query};index=self._index(name)
        if index is None:return None
        bindings,unsafe,stars,tainted=index;value=None
        if tainted or symbol in unsafe:return None
        binding=bindings.get(symbol)
        # A star binding is accepted only when its literal publication is fully
        # verified. Do not let a later/unresolved star shadow a known name.
        candidates=[]
        for base,_ in stars:
            names=self.star(base,depth+1,visiting) if base else None
            if names is None:return None
            if symbol in names:candidates.append(base)
        if binding and candidates:return None
        if binding:
            kind=binding[0]
            at=self.positions[key][symbol]
            if kind=='expression':
                value=self._expression(binding[1],name,depth+1,visiting,at)
                if len(binding)>2 and not self._expression(binding[2],name,depth+1,visiting,at):value=None
            elif kind=='module':
                if self.module(binding[2]) and self.module(binding[1]):value=('MODULE',binding[1])
            elif kind=='import':
                if binding[1] and self.module(binding[1]):value=self.proof(binding[1],binding[2],depth+1,visiting,import_child=True)
            elif kind=='definition':
                if binding[1] and all(self._expression(x,name,depth+1,visiting,at) for x in binding[2]):value=('VALUE',None)
        elif stars:
            # Unknown/dynamic star publication may shadow an earlier binding.
            if len(candidates)==1:value=self.proof(candidates[0],symbol,depth+1,visiting,import_child=True)
        elif import_child and self.modules[name][1]:
            child=name+'.'+symbol
            if child in self.modules and self.module(child):value=('MODULE',child)
        self.cache[query]=value;return value
    def star(self,name,depth=0,visiting=frozenset()):
        self.queries+=1;self.bounded()
        if depth>MAX_EXPORT_DEPTH or self.queries>MAX_EXPORT_QUERIES:
            self.unresolved.add('EXPORT_ANALYSIS_BOUND:'+str(name));return None
        index=self._index(name) if name else None
        if index is None:return None
        bindings,unsafe,stars,tainted=index
        binding=bindings.get('__all__')
        if tainted or '__all__' in unsafe or not binding or binding[0]!='expression':return None
        if self.proof(name,'__all__',depth+1,visiting) is None:return None
        node=binding[1]
        if not isinstance(node,(ast.List,ast.Tuple)) or len(node.elts)>MAX_ALL_NAMES:return None
        names=[]
        for item in node.elts:
            if not isinstance(item,ast.Constant) or type(item.value) is not str or not item.value.isidentifier() or len(item.value)>128:return None
            names.append(item.value)
        if len(set(names))!=len(names):return None
        if not all(self.proof(name,symbol,depth+1,visiting,import_child=True) for symbol in names):return None
        return tuple(names)


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
    def bounded():
        if tree.clock()-started>c.n.MAX_SECONDS:raise p.BoundaryError('BOUNDS_EXCEEDED')
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
    pending=set(ENTRYPOINTS);seen=set()
    def member(name):
        if name in BUILTINS or name=='orchestrator':return True
        found=modules.get(name)
        if found is None:return False
        # Importing a child executes every non-namespace parent __init__.
        for count in range(1,len(name.split('.'))):
            parent='.'.join(name.split('.')[:count])
            if parent!='orchestrator' and (parent not in modules or not modules[parent][1]):
                unresolved.add('MISSING_PACKAGE:'+parent);return False
            elif parent in modules:pending.add(parent)
        pending.add(name);return True
    exports=_Exports(modules,files,snapshot,read,member,unresolved,bounded)
    def resolve(name,attribute=False,origin=None):
        if attribute:
            base,_,symbol=name.rpartition('.')
            if symbol=='*':
                names=exports.star(base) if member(base) else None
                targets={modules[base][0]} if base in modules else set()
                if names is None:
                    unresolved.add(origin+':STAR_IMPORT_UNRESOLVED')
                else:
                    # Import-star's verified from-list can import package
                    # children. Inspection/queueing is not a graph edge: bind
                    # resolved module objects (including aliases) to the caller.
                    for exported in names:
                        value=exports.proof(base,exported,import_child=True)
                        if value and value[0]=='MODULE' and value[1] in modules:
                            targets.add(modules[value[1]][0])
                return targets
            # Even uncertain publication may attempt an exact child import.
            # Keep inspecting its source dependencies; queuing is not export
            # proof and must not hide earlier dynamic-import/code findings.
            if name in modules:member(name)
            value=exports.proof(base,symbol,import_child=True) if member(base) else None
            if value is None:
                unresolved.add('IMPORT_ATTRIBUTE_UNRESOLVED:'+name);return set()
            # Exact child imports load the child. Aliases are supplied by their
            # separately checked parent imports, not invented native attributes.
            if value==('MODULE',name) and name in modules:return {modules[name][0]}
            return {modules[base][0]} if base in modules else set()
        if not member(name):unresolved.add('MISSING_MODULE:'+name);return set()
        return {modules[name][0]} if name in modules else set()
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
        if path.endswith('.py'):
            names,issues=exports.source_imports(module)
            unresolved.update(path+':'+v for v in issues)
            for name,attribute in names:
                targets=resolve(name,attribute,path)
                # The strict graph forbids self edges. A module importing its
                # own package is not an omitted distinct dependency.
                edges.update(targets-{path})
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
    if sum(map(len,derived.values()))>c.MAX_EDGES:raise p.BoundaryError('BOUNDS_EXCEEDED')
    for path,edges in derived.items():
        for target in edges-declared[path]:unresolved.add('DECLARED_EDGE_MISSING:'+path+':'+target)
    tree.recheck(snapshot)
    result={'version':1,'export_rule_version':EXPORT_RULE_VERSION,'closure_sha256':closure_sha,'snapshot_sha256':i.digest(snapshot),
            'status':'UNRESOLVED' if unresolved else 'STATIC_METADATA_VERIFIED',
            'issues':sorted(unresolved),'derived':{k:sorted(v) for k,v in sorted(derived.items())},
            'native':native,'runtime_loader':'UNPROVEN','qualified':False}
    i.encode(result);return result
