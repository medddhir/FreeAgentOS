"""Deterministic Stage31D installation/validation DATA ONLY; executes nothing."""
import hashlib
import json
from pathlib import Path
from .policy import policy_hash
from .protocol import VERSION, BUILD, BoundaryError, identifier

PHASES=('PREFLIGHT','TEMPORARY_INSTALL','SERVICE_START','AUTHENTICATED_HELLO','AUTH_REJECTION',
        'CREATE','SYNTHETIC_START','NAMESPACE_PROOF','ROOTFS_PROOF','IDENTITY_PROOF','CAPABILITY_PROOF',
        'CGROUP_PROOF','RESOURCE_PROOF','DESCENDANT_PROOF','PIDFD_PROOF','HARD_CAP_PROOF',
        'DISCONNECT_PROOF','RESTART_RECOVERY_PROOF','TERMINATE','RELEASE','CLEANUP_PROOF',
        'SERVICE_REMOVAL','ZERO_RESIDUAL_PROOF')
ROLLBACK=('STOP_ACCEPTING','TERMINATE_OWNED_SCOPES','VERIFY_EMPTY','REAP_OWNED_CHILDREN',
          'VERIFY_PRIVATE_NAMESPACES_GONE','REMOVE_OWNED_ROOTS','REMOVE_OWNED_SCOPES',
          'UNLINK_OWNED_SOCKET_INODE','REMOVE_TEMPORARY_UNIT','REMOVE_HASH_MATCHED_INSTALL_FILES',
          'PRESERVE_FAILED_DIRTY_LEDGER','VERIFY_ZERO_RESIDUALS')


def bundle_manifest(package_digest,runtime_digest,synthetic_digest):
    """Hashes identify administrator-reviewed artifacts, not moving downloads."""
    if any(not identifier(v,64) for v in (package_digest,runtime_digest,synthetic_digest)):
        raise BoundaryError('POLICY_REJECTED')
    unit=Path(__file__).with_name('validation.service').read_bytes()
    entries=[
      ('/opt/freeagentos-supervisor','package',0o755,package_digest,'immutable private supervisor venv/package'),
      ('/opt/freeagentos-supervisor/runtime','runtime',0o755,runtime_digest,'traversable read-only runtime root with no home/credentials'),
      ('/opt/freeagentos-supervisor/runtime/bin/synthetic-worker','synthetic',0o755,synthetic_digest,'fixed harmless ELF fixture'),
      ('/etc/systemd/system/freeagentos-stage31d.service','unit',0o644,hashlib.sha256(unit).hexdigest(),'temporary validation unit'),
      ('/etc/freeagentos-stage31d','registry-directory',0o700,None,'private administrator registry'),
      ('/etc/freeagentos-stage31d/admin.json','registry',0o600,None,'versioned paths/identities/hash binding'),
      ('/etc/freeagentos-stage31d/permit.json','permit',0o600,None,'explicit administrator synthetic-only authority'),
      ('/etc/freeagentos-stage31d/enrollment','enrollment-directory',0o700,None,'peer identity and separate token storage'),
      ('/etc/freeagentos-stage31d/enrollment/enrollment.json','enrollment',0o600,None,'UID/GID/build/policy; no token'),
      ('/etc/freeagentos-stage31d/enrollment/token','private-token',0o600,None,'private secret; never bundled in Git or report'),
      ('/var/lib/freeagentos-stage31d','state-directory',0o700,None,'disposable owned roots and ledgers'),
      ('/var/lib/freeagentos-stage31d/resources','owned-root-directory',0o700,None,'only helper-created rootfs/workspace directories'),
      ('/var/lib/freeagentos-stage31d/journal','resource-journal-directory',0o700,None,'resource ledger v2'),
      ('/var/lib/freeagentos-stage31d/control','control-journal-directory',0o700,None,'protocol ownership ledger v1'),
      ('/sys/fs/cgroup/system.slice/freeagentos-stage31d.service','kernel-delegated-domain',0o700,None,'kernel membership checked; only helper-owned children'),
      ('/run/freeagentos-stage31d','runtime-directory',0o750,None,'root/enrolled-GID; restricted socket parent'),
    ]
    return {'schema_version':1,'protocol_version':VERSION,'build':BUILD,'policy_hash':policy_hash(),
            'authorization':'REQUIRED_NOT_GRANTED','entries':[{'target':p,'source':s,'owner':0,
             'group':'ENROLLED_GID' if p=='/run/freeagentos-stage31d' else 0,'mode':m,
             'sha256':h,'purpose':purpose} for p,s,m,h,purpose in entries],
            'generated_identity_rule':'hash generated non-secret registry at preparation; credentials remain private and unhashed in public evidence',
            'phases':list(PHASES),'rollback':list(ROLLBACK),
            'synthetic_scopes':['HARD_CAP','CONTROLLER_DISCONNECT','SUPERVISOR_RESTART'],
            'attempt_limit':1,'scope_limit':3,'automatic_retry':False}


def validate_residuals(value):
    if type(value) is not dict or set(value)!= {'workers','scopes','mounts','dirty'}:
        raise BoundaryError('INVALID_REQUEST')
    if any(type(value[k]) is not int or value[k]<0 or value[k]>128 for k in ('workers','scopes','mounts')) or type(value['dirty']) is not bool:
        raise BoundaryError('INVALID_REQUEST')
    return value=={'workers':0,'scopes':0,'mounts':0,'dirty':False}


def rollback_targets(records,owner):
    """Only verified ledger IDs. Never returns PIDs or arbitrary mount paths."""
    if not identifier(owner) or type(records) is not list or len(records)>128:raise BoundaryError('JOURNAL_INVALID')
    targets=[]
    for r in records:
        if type(r) is not dict or set(r)!= {'owner','handle','owned'} or r['owner']!=owner or not identifier(r['handle']) or r['owned'] is not True:
            raise BoundaryError('CLEANUP_INCOMPLETE')
        targets.append(r['handle'])
    return tuple(targets)


def simulation_report(successful_phases):
    """Pure plan completeness check, never privileged evidence."""
    if tuple(successful_phases)!=PHASES:raise BoundaryError('INVALID_STATE')
    return {'status':'PLAN_VALIDATED','privileged_executed':False,'phase_count':len(PHASES),'active_isolation':'UNPROVEN'}


def prepare_bundle(directory,package_digest,runtime_digest,synthetic_digest,uid,gid,worker_uid,worker_gid,verification_raw):
    """Prepare an administrator review bundle in a private staging directory.

    No privileged installation/phase execution. Secret files remain separate;
    return contains only safe manifest metadata. Existing directories refuse.
    """
    import os
    import secrets
    from .service import prepare_enrollment
    from .security import directory_fd
    from .sealed import Seal
    if worker_uid==uid:raise BoundaryError('POLICY_REJECTED')
    for v in (uid,gid,worker_uid,worker_gid):
        if type(v) is not int or not 1<=v<2**31:raise BoundaryError('POLICY_REJECTED')
    manifest=bundle_manifest(package_digest,runtime_digest,synthetic_digest)
    verification_hash=hashlib.sha256(verification_raw).hexdigest()
    Seal.from_verification(verification_raw,verification_hash)
    permit={'version':1,'policy':policy_hash(),'purpose':'STAGE31D_SYNTHETIC_VALIDATION','administrator_enabled':True}
    permit_raw=json.dumps(permit,sort_keys=True,separators=(',',':')).encode()
    admin={'version':1,'policy':policy_hash(),'owner':secrets.token_hex(16),
           'enrollment':'/etc/freeagentos-stage31d/enrollment','permit_hash':hashlib.sha256(permit_raw).hexdigest(),
           'root':'/var/lib/freeagentos-stage31d/resources',
           'cgroup':'/sys/fs/cgroup/system.slice/freeagentos-stage31d.service',
           'journal':'/var/lib/freeagentos-stage31d/journal','control_journal':'/var/lib/freeagentos-stage31d/control',
           'socket':'/run/freeagentos-stage31d/supervisor.sock','runtime':'/opt/freeagentos-supervisor/runtime',
           'launcher':'/opt/freeagentos-supervisor/venv/bin/python',
           'worker':'/opt/freeagentos-supervisor/runtime/bin/synthetic-worker',
           'workspace':'/var/lib/freeagentos-stage31d/input','manifest':'/etc/freeagentos-stage31d/verification.json',
           'manifest_hash':verification_hash,'worker_uid':worker_uid,'worker_gid':worker_gid}
    # Permit is inert data here, NOT installed authority. No root service runs.
    fd=directory_fd(directory,os.getuid())
    try:
        if os.listdir(fd):raise BoundaryError('INVALID_STATE')
        os.mkdir('enrollment',0o700,dir_fd=fd)
        prepare_enrollment(Path(directory)/'enrollment',uid,gid)
        artifacts={'admin.json':json.dumps(admin,sort_keys=True,separators=(',',':')).encode(),
                   'permit.json':permit_raw,'verification.json':verification_raw,
                   'validation.service':Path(__file__).with_name('validation.service').read_bytes()}
        manifest['generated_artifacts']={name:hashlib.sha256(raw).hexdigest() for name,raw in artifacts.items()}
        artifacts['install-manifest.json']=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
        for name,raw in artifacts.items():
            out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
            try:
                with os.fdopen(out,'wb',closefd=False) as stream:stream.write(raw);stream.flush()
                os.fsync(out)
            finally:os.close(out)
        os.fsync(fd)
        return {'status':'PREPARED_NOT_INSTALLED','protocol_version':VERSION,'policy_hash':policy_hash(),
                'scope_limit':3,'attempt_limit':1,'credential_material_printed':False}
    finally:os.close(fd)


def prepare_text_inference_plan(request, *, runtime_sha256, executable_sha256,
                                invocation, credential_reference):
    """Preparation identity only; no activation or credential resolution.

    Policy observation stays in this existing preparation layer. The worker
    receives a digest as non-authoritative data and never imports this layer.
    Runtime/executable identities remain declarations, not installed proof.
    This source/policy identity is distinct from worker cleanup evidence's
    effective resource-policy dictionary digest, despite the shared field name.
    """
    from ..roles.worker import prepare_text_inference
    return prepare_text_inference(request, runtime_sha256=runtime_sha256,
        executable_sha256=executable_sha256, invocation=invocation,
        credential_reference=credential_reference, policy_sha256=policy_hash())
