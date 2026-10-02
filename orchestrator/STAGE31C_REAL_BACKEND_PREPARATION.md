# Stage 3.1C — completed real Linux backend preparation

Preparation is implemented and deterministically testable. **No real backend
operation has been executed privileged.** Stage3.1D remains **BLOCKED and NOT
AUTHORIZED**; the focused B1/B4 repair below does not resolve the other readiness
blockers. Production isolation is not verified;
`run_worker()`, attribution, bootstrap, doctor, permissions and numerical
resource/lease policies remain unchanged. No verified tag is created.

## IMPLEMENTED / STATICALLY VERIFIED / READ_ONLY_PROBED

Implemented: descriptor snapshot ingestion, enrolled executable/argv binding,
child setup, fixed rootfs recipes, owned cgroup operations, pidfd identity,
independent deadline monitor, resource journal/recovery, authenticated service
composition, enrollment preparation, installation manifest and validation plan.

Statically verified: bounded operation schemas; no RPC paths/PIDs/executable/
argv/environment/mount tuples; fixed execution classes; class/role/resource
validation; root-owned registrations; child identity/capability drop before
exec; private FD closure; recovery only against exact owned resources.

Read-only/unprivileged probes: openat2 traversal/symlink/magic-link/mount-crossing
rejection; executable hash changes; source descriptor replacement races;
platform/cgroup prerequisites. Availability is not enforcement proof.

NOT YET EXECUTED PRIVILEGED: namespace/mount/chroot/device/cgroup writes, identity
and capability drop, service activation, actual deadlines and crash recovery.
Those require owner-authorized Stage3.1D in a disposable validation machine.

## LINUX_BACKEND / LIFECYCLE

`isolation.LinuxBackend` implements create/start/status/running/terminate/cleanup/
recover. Same state vocabulary as protocol v1: CREATING, CREATED, RUNNING,
TERMINATING, TERMINATED, RELEASED, FAILED_DIRTY. Intent is durable before allocation;
resource inode identity is durable before snapshot/setup. Invalid transitions,
reused run IDs and dirty-state reuse reject. Maximum records128, active16;
protocol supervisor additionally enforces two active scopes per enrolled UID.

FakeBackend remains the ordinary simulation backend. Supervisor accepts Linux
only through a trusted constructor flag plus exact backend type, never an RPC.
Service selects LinuxDriver from root-owned installation registry; tests supply
RecordingDriver. The older LinuxIsolationBackend qualification facade and
OwnedCgroup primitive remain blocked compatibility seams, not active alternatives.
All imports are inert. Normal production workers do not import this package.

## SECURE_PATH_RESOLUTION / FD_MODEL / WORKSPACE_SNAPSHOT

`sealed.Seal.from_verification` checks the trusted external verification manifest
SHA256, source_inventory and existing worker/research/test policies. It ignores
host source/workspace strings. A trusted registration opens the workspace once;
SnapshotSource retains that CLOEXEC root FD. Root/parent/path replacement cannot
redirect the descriptor. openat2 uses BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV
below that anchor. Unsupported primitives reject; no realpath fallback.

The helper creates an exclusive private destination and copies only sealed
regular single-link files. It hashes the bytes actually written against the
external inventory, with file/byte/directory budgets. A concurrent source inode
write cannot admit differing bytes. Copy failure leaves a dirty owned resource;
no partial snapshot is launched. Source metadata, symlinks, .git pointer and
credentials are not projected implicitly. Current source snapshot bounds are
20,000 files,1GiB total,128MiB/file; directories plus files bounded22,000.
Tester copy remains separately capped by its existing192MiB/20,000-entry policy.

Source/runtime/executable/root descriptors are supervisor-owned and CLOEXEC.
Only trusted launcher setup temporarily receives them through pass_fds. Before
untrusted FD exec it closes every FD above2 except the approved ELF FD and setup
receipt; both remaining descriptors close on exec. No privileged directory FD
reaches the worker. No ancillary FDs accepted from RPC.

## EXECUTION_REGISTRY / FINAL_ARGV / ENVIRONMENT_POLICY

ExecutionRegistry is immutable and enrolled by slot. Every entry binds class,
role, root-owned executable FD/device/inode/SHA256, minimal runtime FD, opaque job
ID and exclusive non-root worker UID/GID. In-place executable changes reject.
Runtime contents must be root-owned, not writable by other users, with no
symlinks/special files/hardlinks, and carry the minimal-runtime marker. Fixed
mount targets must be directories. Installation parents must be root-owned and
not group/world-writable. ELF FD exec avoids shebang/CLOEXEC ambiguity.

Fixed class contracts:

| Class | Final variable binding | Filesystem | Identity |
|---|---|---|---|
| MODEL_WORKER | `--broker-job <enrolled opaque job>` | broker-only workspace access | enrolled exclusive model UID/GID |
| DETERMINISTIC_TESTER | `--verification-job <enrolled opaque job>` | private test copy | enrolled exclusive tester UID/GID |
| RESEARCH_HELPER | `--research-job <enrolled opaque job>` | runtime only | enrolled exclusive research UID/GID |

These are approved adapter contracts, not a production worker cutover. Future
adapter enrollment must prove it understands its job interface and broker
contract. Stage3.1D service enrolls only the hashed static synthetic ELF with
fixed `--synthetic`; it cannot launch a model/provider. No RPC argv/executable/
interpreter/flags API. Arguments are tuples/arrays and never shell-parsed.

Worker environment is fixed PATH=/usr/bin:/bin, LANG=C.UTF-8, private HOME=/home,
TMPDIR=/tmp and existing bytecode setting. Caller LD_*, PYTHONPATH, PYTHONINSPECT,
BASH_ENV, shell hooks, certificate overrides and provider variables are absent.
Credential delivery is deliberately outside this privilege protocol; future
broker delivery must not copy the controller environment.

## CHILD_LAUNCHER / IDENTITY_DROP_ORDER / CAPABILITY_DROP

Fresh trusted interpreter `-I -m orchestrator.privilege.child` avoids unsafe
threaded Python preexec_fn. Its inherited descriptors/configuration are fixed
supervisor-generated data, bounded16KiB, strict duplicate-free JSON.

Order: parent durable START intent → paused launcher/pidfd → attach launcher to
owned cgroup → release pipe barrier → unshare mount/PID (private network for
validation/tester) → fork PID namespace init → private mount propagation → fixed
rootfs/runtime/scratch → minimal dev/proc → chroot and cwd → RLIMITs → clear ambient
and bounding capabilities → clear groups → GID → UID → clear all capability sets
→ no_new_privs → close privileged FDs → FD exec approved ELF. Ordered composition
is exercised with injected RecordingCalls; identity syscalls are mocked.

Namespace init verification requires PID1; the trusted outer launcher waits and
is also contained in the owned cgroup. No model/client code executes as root.
No_new_privs also applies through the unit; child clears all capabilities rather
than forwarding the helper's bounding set. Setup CAP_SYS_ADMIN remains broad and
is restricted to root-owned reviewed code, never a general command interface.

## MOUNT_RECIPES / DEVICE_POLICY / ROOTFS_MODEL

Only recipe-owned source FDs and fixed targets: minimal enrolled runtime bind,
readonly/nosuid remount; private tmpfs tmp/run/home/dev/workspace; namespace-local
proc. Tester gets a bounded private writable copy. Model/research receive no
direct project projection, preserving broker-only filesystem access. No host
home, credential directory, Docker socket, GPU or block device projection.

Exactly four character devices: null(1,3),zero(1,5),random(1,8),urandom(1,9).
Parameters are code-owned. All mounts exist only in the owned child namespace.
After its entire cgroup is empty, no helper/worker retains namespace FDs; kernel
namespace destruction removes projections. Recovery does not scan/unmount host
mount tables. Stage3.1D must verify this actual destruction and zero residuals.
Reserved worker identities must have no unrelated processes/users capable of
retaining namespace FDs. Chroot is one layer, never the entire boundary.

## CGROUP_V2 / PIDFD

Read-only qualification: filesystem magic, owned/delegated directory, cpu/memory/
pids availability, subtree enablement and cgroup.kill file. Fixed reason codes:
CGROUP_V2_UNAVAILABLE, DELEGATION_UNPROVEN, CONTROLLER_MISSING,
CONTROLLERS_DISABLED, CGROUP_KILL_UNAVAILABLE. Enforcement always UNPROVEN.

Root entrypoint verifies kernel cgroup membership ends in the exact validation
unit's `/supervisor` leaf before pinning/restricting its parent delegated domain.
Only that empty domain may enable the three required controllers. Per-run scope
name is `fa-<installation owner>-<opaque handle>`. Fixed ceilings are independently
validated: memory.max,swap.max=0,pids.max,cpu.max. Attach only the helper-created,
unreaped child, never a protocol PID. Kill uses cgroup.kill; verify exact populated0
before removal. No unsafe PID enumeration fallback.

Pidfd retains launcher identity; direct child exit still triggers whole-scope
termination. Missing pidfd support fails qualification. Recovery never uses a
persisted PID: durable scope inode/device, private registration, boot identity
and owned name bind cleanup. Foreign or ambiguous identities remain dirty.

## LEASE_SUPERVISION / DISCONNECT_BEHAVIOR

ActivityLease is reused from production, with BASE180/GRACE60/HARD240/recent30;
planner/reviewer bases are read from their existing source constants. Research/
tester policies retain their current ceilings. Monotonic start is before setup;
bounded launcher setup receipt is independently limited10 seconds. Supervisor
monitor runs without client requests. Only trusted broker telemetry can grant
existing one-shot grace. Failure retries only the known owned dirty scope;
admission remains fenced until verified recovery.

For the explicitly synthetic validation service only, a successful supervisor
read of one sealed fixture byte at179 seconds supplies trusted local broker-like
telemetry. It uses no worker/model output and no new RPC. This exercises real
existing240-second hard-cap semantics without changing production values.
Normal backend construction does not enable this test coordinator.

Protocol v1 uses a persistent authenticated connection. Its close/EOF/crash/
transport timeout is terminal: cleanup that connection's scopes; no reconnect or
ownership transfer. Future validation client must poll STATUS under the existing
bounded transport timeout, including while waiting for the hard-cap test. A
short transient RPC connection is not the supported ownership model. Monitor
continues even when controller requests cease; cgroup unit kill is an additional
service-death containment layer.

## REAL_RESOURCE_JOURNAL / RECOVERY

ResourceJournal v2: private root-owned0700 directory, regular single-link0600
atomic/fsynced file; max128 records/256KiB; strict versions/keys/types/IDs/policy.
Only owner/run/handle/class/role/state/boot/time/scope+root inode/device/cleanup.
No prompt/output/token/environment/file contents. Existing protocol ownership
journal remains v1. Both ledgers retain their separate responsibilities.

Before recovery validate all pending records and all FD/inode/absence proofs.
Then kill owned scope, prove empty, reap owned child if retained, remove private
root and exact scope, mark RELEASED. Root-private exclusive names plus durable
creation intent cover crash before inode update. New-boot matching scope is
ambiguous and rejected. A protocol-only intent is reconciled only after exact
scope/root absence proof. Corruption/foreign ownership fails closed without a
host-wide scanner, PID kill or mount scan. Dirty records are never erased to
claim cleanup. Resource allocations failed midway are retained for recovery.

## SERVICE_ENTRYPOINT / AUTH_ENROLLMENT / INSTALL_MANIFEST

`python -I -m orchestrator.privilege.service --admin <root-private registry>
--permit <root-private permit>` is prepared, NOT run. It requires EUID0, immutable
root-owned installed package/parents, strict root-private configuration,
root-private enrollment/token/journals, exact policy/version and administrator
synthetic-only permit hash. Source-contract hashes participate in HELLO policy
identity. Stale installations fail closed. Socket parent0750 root/enrolled-GID,
socket0660, SO_PEERCRED+UID/GID+separate token+connection challenge. Client must
explicitly request Linux validation mode; default simulation behavior unchanged.

prepare_enrollment only writes into an empty caller-owned0700 staging directory,
returns non-secret metadata, and stores separate0600 token. No current machine
was enrolled. Administrator must securely deliver a separate0600 client token to
the enrolled user; no token/hash/token prefix enters evidence or Git.

validation.bundle_manifest receives reviewed package/runtime/synthetic hashes,
adds unit hash/protocol/build/policy and exact target/owner/group/mode/purpose.
`validation.prepare_bundle` writes a private NON-INSTALLED staging bundle with
admin/permit/verification/unit and private enrollment artifacts. It returns only
safe metadata; existing staging contents refuse. Generated non-secret registry
hashes are bound when staging; secret material is
never put in a public bundle. Paths use /opt,/etc,/var/lib,/run and the delegated
validation unit, never a developer checkout. Normal install.sh remains non-root.

## SYSTEMD_TEMPLATE

`validation.service` is a review-only packaged resource, not installed/enabled.
Delegate=cpu memory pids and DelegateSubgroup=supervisor keep manager processes out
of the scope-creation domain. This matches Ubuntu24.04 systemd255;
[upstream v255 directive specification](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.resource-control.xml).
Capabilities: SYS_ADMIN(namespaces/mount),SYS_CHROOT,SETUID/SETGID,SETPCAP,
MKNOD(minimal devices),CHOWN(disposable tmpfs),DAC_OVERRIDE(sealed enrolled input).
No ambient capabilities. NoNewPrivileges, readonly system/home, private tmp/mounts,
AF_UNIX-only transport, restricted namespace kinds, kernel protection and
control-group KillMode apply. ProtectControlGroups is omitted because it would
block delegated writes. ReadWritePaths includes cgroups, but code only admits the
kernel-verified service domain. This is synthetic validation hardening, not a
production model-network unit; compatibility remains for Stage3.1D to prove.

## WSL2_READINESS / NATIVE_UBUNTU_REQUIREMENTS

Current read-only observations: Ubuntu24.04 x86_64 WSL2 kernel6.6.87.2, cgroup v2
cpu/memory/pids visible, namespace paths/pidfd API detectable. PID1 is codex in the
current execution context. Systemd/delegation/privileged enforcement are not
proved here: WSL2 readiness PARTIAL. Use a separately authorized disposable native
Ubuntu24.04 VM first; native qualification REQUIRES_MACHINE. Doctor stays
UNPROVEN regardless of implementation files.

## STAGE31D_EXACT_VALIDATION_PLAN / ROLLBACK

One authorization covers one bounded validation campaign, **three sequential
synthetic scopes**, no retries: hard-cap, controller-disconnect, supervisor-restart.
One scope cannot both finish by hard cap and remain live for crash/disconnect tests.
No project/model/provider/gateway is used. Plan data has attempt_limit1/scope_limit3.

1. Preflight disposable Ubuntu24.04 VM/systemd255/x86_64; untouched production;
   reserved enrolled user and exclusive worker UID; matching reviewed hashes;
   namespace/openat2/pidfd/cgroup.kill/controllers. Abort before install if absent.
2. Stage reviewed supervisor venv/package with pinned dependencies (no system
   Python), copied interpreter executable and minimal runtime. Compile the fixed
   `fixtures/synthetic_worker.c` using `cc -static -O2`; hash ELF. Runtime contains
   only marker, bin/synthetic-worker and empty proc/dev/tmp/run/home/workspace.
   Its root is root-owned0755, non-writable by workers, so the dropped UID can
   traverse the isolated filesystem. Private staging/journals/tokens remain0700/0600.
   No shared host root/home bindings. Stage a tiny externally sealed input file.
3. Prepare enrollment in empty private staging; record public identity; deliver
   token privately. Create administrator registry+hashed permit and resource/
   control journal directories from the manifest. Do not overwrite existing paths.
4. Install only the temporary named unit and reviewed hash-matching artifact
   paths; start once. Verify owner/modes, Unix-only socket and exact HELLO policy.
5. Enrolled unprivileged client tests authenticated HELLO and wrong-token/peer
   rejection. No secrets/frames printed. Persistent client polls STATUS.
6. Scope1 CREATE/START: collect bounded synthetic JSON proof from its private
   pipe, verify UID/GID non-root, PID1/namespace inode changes, capability sets0,
   NNP, no host root. Inspect owned scope limits/process membership and pidfd.
   Fixture forks one harmless descendant. Trusted read coordinator provides grace;
   prove independent termination at existing240-second ceiling, empty scope and
   RELEASE. Never substitute EXEC_READY for successful worker exec/proof.
7. Scope2 CREATE/START then crash/close the client. Prove owned descendant kill,
   RELEASE/empty state and zero residuals for that scope.
8. Scope3 CREATE/START then terminate only the validation service's trusted main
   process in a controlled crash. Restart once as a recovery phase (not worker
   retry). Prove resource ledger recovery, no worker resurrection, empty scopes,
   no retained private mounts. Admission fails if ownership is ambiguous.
9. Execute TERMINATE/RELEASE where applicable, stop validation service, verify
   owned scope population0 and worker/pidfd reaping. Private namespaces vanish;
   verify rootfs paths are not mounts. Remove only inode/hash-matching owned roots,
   scopes, socket, unit and installation artifacts. Preserve FAILED_DIRTY ledger
   and installation if cleanup cannot be proven. Check workers0/scopes0/mounts0.
10. Remove temporary privilege enrollment/client token through explicit reviewed
    paths after clean proof. Preserve bounded safe evidence. No broad cleanup
    command, arbitrary PID kill, umount-a, pkill or host cgroup scan is permitted.

The ordered23-phase plan and rollback target validator are data-only, no privileged
executor exposed. The future owner-authorized operator performs these
explicit steps on the validation machine. No phase was executed in Stage3.1C.

## TESTS / SECURITY REVIEW

Compact regression tables exercise descriptor replacement, source symlink/hash
rejection, argv immutability, FD close set, environment, ordered child composition,
resource bounds, deadline monitor, disconnect, lifecycle transitions, atomic
journal/parser/secret rejection, ownership recovery, service refusal, deterministic
manifest and foreign rollback rejection. Existing simulation/authentication tests
remain applicable. Full trusted runner includes historical isolation fixtures;
new real-backend tests use only recording calls, mocks and unprivileged probes.

Security call-site inventory is generated from the complete privilege package
and stored below. No shell=True/os.system/eval/pickle/unsafe YAML. ast.literal_eval
in policy parses repository-owned constants only. No arbitrary RPC executable,
path, environment, mount pair, cgroup or PID. Tokens are never logged. Production
kernel behavior remains unverified until Stage3.1D.

| Call site | Primitive | Reachability and justification |
|---|---|---|
| `orchestrator/privilege/backend.py:110` | `Popen` | Existing fixed synthetic direct-child test fixture; owned Popen/pidfd only; never an RPC PID. |
| `orchestrator/privilege/backend.py:117` | `pidfd_open` | Existing fixed synthetic direct-child test fixture; owned Popen/pidfd only; never an RPC PID. |
| `orchestrator/privilege/backend.py:25` | `pidfd_send_signal` | Existing fixed synthetic direct-child test fixture; owned Popen/pidfd only; never an RPC PID. |
| `orchestrator/privilege/backend.py:29` | `kill` | Existing fixed synthetic direct-child test fixture; owned Popen/pidfd only; never an RPC PID. |
| `orchestrator/privilege/child.py:101` | `unshare` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:110` | `_mount` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:112` | `_mount` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:113` | `_mount` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:115` | `_mount` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:119` | `fchown` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:123` | `chown` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:124` | `chown` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:127` | `mknod` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:128` | `_mount` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:130` | `chroot` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:159` | `execve` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:55` | `mount` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:70` | `fchown` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/child.py:83` | `fchown` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/journal.py:59` | `fchmod` | Restricts owned staging/temporary files to0600/0400, not a system installation. |
| `orchestrator/privilege/kernel.py:139` | `_write` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/kernel.py:149` | `_write` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/kernel.py:187` | `Popen` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/kernel.py:192` | `_write` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/kernel.py:200` | `_write` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/kernel.py:214` | `_write` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:138` | `pidfd_open` | Helper-created unreaped child identity; mocked in new lifecycle tests. |
| `orchestrator/privilege/linux.py:202` | `_write` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:207` | `_write` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:216` | `_write` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:286` | `unshare` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:303` | `prctl` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:310` | `prctl` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:311` | `prctl` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:312` | `setgid` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:312` | `setgroups` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:312` | `setuid` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:319` | `capset` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:320` | `prctl` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |
| `orchestrator/privilege/linux.py:44` | `syscall` | Read-only openat2 path resolution; exercised on disposable files. |
| `orchestrator/privilege/real_journal.py:62` | `fchmod` | Restricts owned staging/temporary files to0600/0400, not a system installation. |
| `orchestrator/privilege/sealed.py:97` | `fchmod` | Restricts owned staging/temporary files to0600/0400, not a system installation. |
| `orchestrator/privilege/security.py:77` | `fchmod` | Restricts owned staging/temporary files to0600/0400, not a system installation. |
| `orchestrator/privilege/service.py:135` | `fchmod` | Temp enrollment mode0600, or future kernel-verified delegated domain; no live enrollment. |
| `orchestrator/privilege/service.py:95` | `fchmod` | Temp enrollment mode0600, or future kernel-verified delegated domain; no live enrollment. |
| `orchestrator/privilege/supervisor.py:151` | `chown` | Permit-gated future service/child setup; mocked/recorded in Stage3.1C; not executed privileged. |

No umount/raw os.kill/syscall kill sites exist in the new backend. Cgroup writes
are confined to kernel.LinuxDriver._write and the still-disabled legacy
linux.OwnedCgroup._write. Journal/enrollment writes are private atomic local
files. FD-based exec is approved ELF only. The C fixture reads bounded operational
proc metadata and forks a single harmless descendant; it has only been compiled,
never run. No mount/cgroup/model/provider RPC fields were added.

## Focused B1/B4 repair: cleanup proof and launcher containment

This repair changes only cleanup proof and failed-launch containment. Stage3.1D
remains BLOCKED, NOT AUTHORIZED. No privileged backend operation was executed;
production worker integration, leases, attribution, and installation are unchanged.

### B1 — explicit ownership-bound cleanup evidence

`cleanup_proof(handle, owner)` returns `NEVER_ALLOCATED`, `OWNED_CLEANED`, or
`UNPROVEN`. `CREATING` is no longer an exception permitting release. Simulation
absence requires the same backend owner and a complete instance allocation ledger;
a lost allocation record does not establish absence. Simulation results remain
`SIMULATED`, never real enforcement evidence.

Linux release requires a confirmed resource-journal outcome plus exact owned
root/scope absence and no retained launcher/descriptor uncertainty. The version-2
private resource journal additionally records `NEVER_ALLOCATED` as a cleanup
outcome; public cleanup remains `CONFIRMED`/`UNPROVEN`. Released records with
unconfirmed journal cleanup are invalid. A missing resource intent is reconciled
only after checking the exact owned names. Partial allocations are cleaned by
owned recovery, then checked absent. Release is idempotent only with positive
proof. Failed/ambiguous cleanup stays `FAILED_DIRTY`/`UNPROVEN`, fences admission,
and preserves durable intent even when updating the journal fails.

### B4 — ownership before pidfd and independent cleanup steps

The driver reserves an opaque ownership entry before Popen, then retains its
helper-created direct child before acquiring pidfd or attaching to the owned
cgroup. Parent-only launch descriptors are tracked from their first allocation.
Preparation, spawn, pidfd acquisition, attachment, configuration/barrier/receipt,
FD closure, and post-launch controller/resource-journal failures all enter bounded
owned cleanup. No external PID/path/command interface was added.

Scope kill/drain, pidfd/direct-child kill/reap, each pipe closure, pidfd closure and each
parent launch-FD closure are attempted independently. A wait error cannot skip
other cleanup. Unreaped children and failed pipe closures retain their ownership
entry. A numeric FD is never blindly retried after an ambiguous Linux close error:
the descriptor may already have been released/reused. That uncertainty remains
sticky dirty evidence, blocks remove/absence proof, and requires independently
established recovery rather than claiming success. Exception details are not
returned. Resource-journal start intent predates launch; registration/persistence
failure attempts containment and retains `FAILED_DIRTY`/`UNPROVEN` plus admission
fencing.

A restarted driver cannot infer disappearance of a possibly unattached launcher
from an empty cgroup. Unsettled start intent in CREATED/FAILED_DIRTY without an
owned process reference or same-instance termination proof fails recovery closed.
No host PID scan is used. This may require later operator-owned quiescence proof;
that separate recovery/operator work is not implemented by this milestone.

### Deterministic evidence and limits

`test_privilege_cleanup.py` fault-injects missing cleanup proof, genuine
never-allocation, partial allocation, cleanup/persistence failures, idempotent
release, FD preparation, registration before spawn, pidfd/inherit/attach/config/
receipt failures, wait failure, scope/pipe/pidfd/FD closure failure, ownership
mismatch, and restarted ambiguous launch intent. Linux operations and Popen are
mocked; recording-driver recovery is not real-kernel enforcement certification.
Focused privilege regressions and the repository-required freeagent-test results
are recorded in the completion report. Initial socket regressions were blocked
by the tool sandbox and rerun with temporary sockets outside that restriction.
The full existing suite includes its historical production isolation fixtures;
it does not activate the new Linux backend or authorize Stage3.1D.

Remaining consolidated blockers: B2 authoritative external policy binding;
B3 transport idle/request budget; B5 stale socket recovery; B6 executable
single-campaign guard; B7 bounded synthetic stdout evidence; B8 complete security
proof observables; B9 standalone operator rollback/recovery; B10 install/client
credential/evidence inventory; B11 Linux PROBE contract; B12 disposable target and
real kernel enforcement qualification. No exported reviewer snapshot was changed.

The 18 new fault cases use two compact unittest contract tables, matching the
existing suite pattern and preserving the runner's 64 KiB capture bound. An initial
full run passed unittest (533 tests) but was correctly rejected by freeagent-test
for output overflow. Two standalone table discovery entries (520 tests) also
exceeded the bound. The final tables run through the existing foundation entry
(unchanged discovery count), just like the other privilege tables; no assertions
or cases were removed. The final runner result is the authoritative check.

Final verification: focused cleanup/launcher plus existing privilege/Linux
regressions PASS (5 contract groups, including 18 new fault cases).
freeagent-test: 518 tests in 224.378s; RESULT=PASS; EXIT_CODE=0. Final diff
review and git diff --check passed. These are deterministic preparation checks,
not privileged kernel validation. Stage3.1D remains BLOCKED / NOT AUTHORIZED.

## Focused B2 repair — authoritative policy identity binding

B2 is repaired in preparation mode. B1/B4 remain preserved. Stage3.1D remains
BLOCKED and NOT AUTHORIZED; no new privileged backend operation is exercised.

### Policy contract and exact authorities

The old copied lease/cap summary is removed. `policy_sources.source_identity()`
adds binding version2 to `policy_hash()`. Its immutable allowlist names41 source
files:22 authoritative application-policy files and19 existing/helper-contract
files (including the binding implementation). No directory glob, configuration,
workspace path, runtime journal, credential, or generated digest is an input.

| Rule | Authoritative source and bound behavior |
|---|---|
| Base180s, grace60s, hard240s, recent30s | `roles/lease.py`: constants, `hard_cap_seconds`, complete `ActivityLease`; coder/fixer + model + streaming + base180 eligibility; trusted pre-deadline progress; once-only decision; hard deadline clamp. |
| Progress eligibility inputs | Complete dedicated `roles/activity.py`, `broker_telemetry.py`, `broker_session.py`; selected `worker._read_worker_streams` and inner/outer resource/lease execution. |
| Role and execution deadlines | Planner90, Coder180, Fixer180, Reviewer90, Tester130 assignments in their role files; `research_execution.py` action deadlines50/30/30/40; worker/research/test wall ceilings240/60/150; helper role-base/deadline behavior in `privilege/isolation.py`. These distinct role requests and resource ceilings are not conflated. |
| Read/write/Planner/context/tool limits | Dedicated `read_policy.py`, `file_tools.py`, `coding_units.py`: shared eight-file read/write ceiling, Planner three units/four targets, eight context files/24KiB packet/8KiB per file,128 tool calls and256KiB session budget; enforcement, authorization narrowing and validation, not only numbers. |
| Resource limits | `worker.py` MIB/WORKER_POLICY/RESEARCH_POLICY/POLICIES and enforcement functions; complete dedicated `sandbox.py`, including RESOURCE_POLICY, capture, copy, cgroup and child rlimit enforcement. Helper independently bounded selection remains in hashed `privilege/policy.py`. The integer multiplier is parsed from authoritative MIB source, not a copied multiplier. |
| Fixer/repair | `graph.py` MAX_FIX_ATTEMPTS plus route_after_tester/tested_unit_node/route_after_fixer; Fixer timeout and complete fixer_node (including its separate literal attempt guard and accounting); complete dedicated intermediate_repair.py and bounded repair_context.py. Global two-attempt and intermediate checkpoint/permission rules are bound in all current enforcement locations. |
| Permission dependencies | Selected inspector path/descriptor reader and filtering definitions; integrity protected-file/baseline/change/fingerprint rules; Tester test-file classification; selected workspace inventory, secret exclusions, manifest/controller identity and execution-contract validation; preflight required-capability definitions. |
| Existing supervisor policy | Explicit19 privilege Python files: protocol/bounds, peer/token/connection authentication, socket validation, fixed classes/argv/environment, paths/sealing, mounts/devices/identity/capability drop, resources, leases, state/recovery/cleanup and B1/B4 fixes. |

The complete fixed map and required definition names are in `policy_sources.py`.
Dedicated policy modules use whole-source SHA256. Mixed application modules bind
only allowlisted definitions plus module-level bindings/control flow, using
position-free AST serialization; this also catches later deadline rebinding.
Unrelated graph finalization/build functions, general CLI/UI/bootstrap, benchmarks,
provider selection and attribution implementation are not added to this contract.
Selected Fixer function bodies conservatively include their static prompt literals;
changing those literals can invalidate identity, but no live prompt is read.
New policy dependencies must be explicitly reviewed and added to the allowlist;
this is a policy compatibility contract, not arbitrary transitive application
attestation or a proof that changed code is safe.

### Trust, bounds and packaging

Root is the filesystem package containing `privilege/policy_sources.py`, resolved
from that module's `__file__`; it is not cwd, HOME, environment, CLI or RPC input.
The existing service package/ancestor ownership checks remain mandatory. A
privileged installation must be root-owned/non-writable by enrolled users and
immutable while active; development/client checkouts are not privileged authority.
No production application module is imported/executed to derive this identity.

Reads use pinned directory FDs, no-follow directories/final files, CLOEXEC,
regular single-link file checks, maximum256KiB per source and4MiB total, and
before/after file identity/size/time checks. Parsing requires valid UTF-8/Python,
required non-duplicated definitions of the expected kind, supported bounded
positive numeric assignments and bounded literal resource dictionaries. Missing,
unreadable, malformed, oversized or symlinked sources raise POLICY_REJECTED;
there is no fallback to copied literals or imported module values.

The existing setuptools package declarations already include orchestrator,
orchestrator.roles and orchestrator.privilege Python sources. Normal unpacked
wheel installation is required; stripped-source/pyc-only or zip-only layouts fail
closed. Controller and helper must use matching source/extraction contracts;
Python AST representation differences across interpreter versions may reject
compatibility rather than silently asserting equivalence. Use matching reviewed
Python versions for a privileged installation.

Hashing a binding implementation's static source does not read/execute its own
result. No generated identity is embedded in any hashed source, so this is not a
circular or self-referential digest computation.

### Compatibility and old journals

Both controller HELLO and supervisor policy validation use the same policy_hash.
Different policy identities reject with POLICY_REJECTED. Existing enrollment,
permit/registry and journal identity checks remain in force. Old policy-bound
controller/resource journals reject JOURNAL_INVALID under the new identity; they
are not rewritten, deleted, relabeled or automatically migrated. Preserve old
matching code/policy and journals for separately reviewed, owner-authorized cleanup
of their resources. Do not bypass mismatch by editing journal hashes. This
milestone implements no migration or operator recovery/installation workflow.

### Deterministic tests and package evidence

`test_privilege_policy_identity.py` provides eight compact contract cases,
including25 isolated source mutations of lease values, eligibility, once-only and
pre-deadline behavior, worker deadline consumption, role/research deadlines,
read/write/tool/Planner/resource caps and graph/Fixer/intermediate repair rules.
Stable unchanged inputs and excluded application/runtime files are checked.
Missing/invalid/duplicate/oversized/symlink/unreadable source fixtures fail closed.
Temporary fake-backend client/supervisor agreement and mismatch rejection are
checked. Both temporary journal formats remain byte-for-byte unchanged on mismatch.
A source fixture containing a top-level exception is parsed but never executed;
an isolated import confirms no production application module is loaded by hashing.
The tables run through the existing foundation entry to preserve runner bounds.

A real offline wheel was built from a disposable allowlisted source copy with
existing pinned setuptools68.1.2/wheel0.42.0 (no dependency install, no global Python
mutation). All41 required policy sources were present. Its unpacked installed
package computed exactly the checkout identity, with zero production application
module imports. Temporary build/package files were removed. The first attempt
using the controller venv failed because that venv lacks setuptools; the successful
build used the already-installed matching pinned build tools instead.

Remaining consolidated blockers: B3 transport idle/request budget; B5 stale socket
recovery; B6 executable single-campaign guard; B7 bounded synthetic stdout evidence;
B8 complete security proof observables; B9 standalone operator rollback/recovery;
B10 install/client credential/evidence inventory; B11 Linux PROBE contract; B12
qualified disposable target/real kernel enforcement. No exported snapshot, service,
production rule, lease/resource value, gateway or production integration changed.

Final verification: six focused policy/privilege/Linux/B1/B4 regression groups
passed (17.983s). The final code tree passed `bin/freeagent-test`:518 tests in
299.463s, RESULT=PASS, EXIT_CODE=0. Final diff inspection found only the binding
implementation, its focused tests/foundation wiring and this documentation.
No new-backend privileged validation or model/provider generation was executed.

## Focused B3 repair — transport lifetime and independent supervision

IMPLEMENTED / STATICALLY REVIEWED / DETERMINISTIC IPC VERIFIED only;
NOT YET EXECUTED PRIVILEGED. Stage3.1D remains NOT AUTHORIZED. B1/B2/B4
remain intact. Production worker integration is unchanged.

### Timing contract and bounded design

Previously every `receive()` began a one-second timer even before an
authenticated idle client transmitted its first byte. Sub-second STATUS
polling could exhaust the128-request connection budget before the240-second
worker hard cap. Disconnect cleanup could then mask independent enforcement.

`protocol.receive()` now has two explicit internal modes. Handshake/client
response mode retains the one-second complete-frame deadline. Authenticated
server mode waits for the first byte without consuming a request, checking
shutdown and a fixed absolute connection deadline every100ms. EOF immediately
fails transport. From the first received byte, header AND body share one
one-second deadline, capped by remaining connection lifetime. Further packets
never reset it. Size/schema/duplicate-field validation remain unchanged.

Authenticated connections expire600 seconds after successful authentication,
regardless of silence, STATUS, START or other traffic. This ten-minute ceiling
allows bounded setup, a240-second worker, observation and release without
keepalives, while at most eight clients occupy transport slots. It is a
transport bound, not a worker lease, diagnostic lease override or renewable
heartbeat. A worker started near connection expiry can be cleaned before its
full lease; operators must begin early enough to fit the intended observation
window. No automatic reconnect or ownership transfer exists.

Unchanged bounds:16KiB frames,128 total requests (including HELLO),32
post-authentication requests per rolling second, eight connected clients,
16 active sandboxes/two per UID,128 journal entries. Rate, sequence/replay,
peer/token/challenge authentication and handle ownership validation remain
unchanged. Request/write/response waits remain bounded. Shutdown sets the stop
event and shuts down accepted sockets, interrupting idle/frame receives; the
existing connection-finally path performs owned cleanup. Socket recovery and
operator rollback remain outside this repair.

The existing `LinuxBackend._watch()` independently calls `enforce()` every50ms.
It is neither driven nor renewed by socket reads/STATUS. Its authoritative
ActivityLease remains180-second base, current trusted-progress grace eligibility
and one-shot decision,240-second hard cap. Transport uses monotonic seconds;
worker leases use monotonic nanoseconds. Injected test clocks are internal
constructor arguments, never protocol/config input. No model/provider heartbeat.

### Evidence and limits

`test_privilege_transport.py` adds nine compact cases to the existing foundation
table. Temporary authenticated AF_UNIX fixtures use the complete backend with
RecordingDriver only. A quiet connection survives the former real one-second
idle deadline and fake-clock base/grace/hard-cap window; independent monitor
termination occurs with no TERMINATE/keepalive dispatch. Only six requests are
needed through final STATUS/RELEASE. STATUS neither supplies progress nor renews
the lease. Without trusted progress the worker ends at180 seconds.

Other cases cover actual EOF cleanup, absolute lifetime expiry despite activity,
responsive shutdown, pre-authentication silence, partial header/body stalls,
shared non-resetting frame deadline, EOF framing, unchanged transport bounds
and B2 identity sensitivity to the new lifetime source. Existing privilege
regressions exercise request/client/rate/resource limits, replay, unauthorized
handles and auth; B2 regressions exercise client agreement/mismatch and
byte-preserving rejection of old policy-bound journals. Both modified contract
sources are already in B2's fixed source allowlist; no old journal is migrated.

These tests establish protocol behavior and recorded cleanup/deadline intent.
Fake-clock/recording evidence does not prove kernel scheduling, real cgroup
termination, namespace enforcement or privileged crash recovery. Active
isolation remains UNPROVEN and needs separately authorized validation.

Remaining consolidated blockers: B5 stale socket recovery; B6 executable
single-campaign guard; B7 bounded synthetic stdout evidence; B8 complete security
proof observables; B9 standalone operator rollback/recovery; B10 install/client
credential/evidence inventory; B11 Linux PROBE contract; B12 qualified disposable
target/real kernel enforcement. No Stage3.1D execution is authorized.

Final checks: six focused transport/privilege/complete-backend/B1/B4/B2 groups
PASS (31.905s); existing lease regressions40 tests PASS (3.176s).
`bin/freeagent-test`:518 tests in304.474s, RESULT=PASS, EXIT_CODE=0.
Final diff inspection found only protocol/server transport changes, the focused
test table/foundation wiring and this document. Initial focused failures were
fixture registration/time-unit errors corrected without altering production
policy or weakening validation. No real new-backend kernel operations executed.

## Focused B5 repair — ownership-bound socket cleanup/recovery

IMPLEMENTED / STATICALLY REVIEWED / TEMPORARY IPC TESTED only. Stage3.1D is
NOT AUTHORIZED. No installed/root service or production worker cutover occurred.

### Authority, proof and concurrency

`socket_state.SocketState` is internal to deterministic LocalServer startup and
close, not an RPC, tool/model API, general rollback executor or directory scanner.
The registered socket parent is pinned with existing component-wise no-follow
directory validation. Simulation uses owner-only0700; the future service uses
root-owned0750, with enrolled clients unable to write it. Its canonical parent
identity is rechecked against the pinned directory; bind/connect use the Linux
`/proc/self/fd/<parent-fd>/<name>` address because AF_UNIX lacks bindat/connectat.

A0600 single-link regular `<socket>.lock` is opened no-follow/CLOEXEC and held
with nonblocking exclusive flock through listener lifetime/cleanup. It is never
unlinked: removing lock files would create a second-lock/ABA startup race. Busy
lock returns SOCKET_BUSY without touching the socket. Lock pathname identity,
file owner/group/mode and directory identity are rechecked. Cooperating startup
and recovery paths cannot retire one another's listener. Private/root-owned
parent write exclusion is mandatory: advisory locking is not protection from a
compromised process with the supervisor's own UID/root authority.

A bounded0600 atomic `<socket>.owner.json` record binds schema1, current policy
hash, backend installation owner, enrollment ID, socket basename, parent
device/inode, expected socket UID/GID/mode, phase, socket device/inode/ctime and
observed owner/group/mode. No token, prompt, environment or model data is stored.
Initial PREPARING intent precedes bind; BOUND identity is captured immediately
after bind and after permission setup; READY is persisted after listen/timeout
setup. Capture cannot switch to a different inode. Required files/socket are
no-follow, single-link, type/owner/mode validated; reads are capped at2048 bytes
with strict fields/types/duplicate rejection. No missing/mismatched record is
synthesized. Both policies and the new module are bound by B2's explicit source
allowlist (now42 files); old-policy socket/control/resource records remain
rejected without rewriting, deleting or relabeling them.

### Inactivity and retirement

Only an exact BOUND/READY record/socket identity match plus the lifetime lock
allows an inactivity probe. A bounded local connect must return ECONNREFUSED.
Successful connect returns SOCKET_ACTIVE; timeout, permission errors, backlog
ambiguity and all other outcomes block. No credentials/RPC/model are sent.
Free lock or parent ownership alone is never inactivity/ownership proof.

After probe the parent, lock and full socket identity are rechecked. An O_PATH,
no-follow, CLOEXEC FD pins the inode. Linux renameat2(RENAME_NOREPLACE) retires
only that basename to fixed `<socket>.retired`; the moved inode/type is compared
to the pinned FD before descriptor-relative unlink. A replacement raced into
the source name is not deleted: it is restored only if that name is vacant,
otherwise retained and blocked. Foreign/replacement inode, symlink, regular file
or unrelated socket is never accepted. No insecure rename fallback exists.
The final unlink relies on the mandatory trusted-parent writer exclusion and
lifetime lock; hostile same-UID/root writes are outside that authority model.

Normal close is idempotent and closes listener, joins/shuts down clients,
attempts exact owned retirement and independently closes lock/parent FDs. Any
failed step is reported SOCKET_RECOVERY_BLOCKED; repeated close preserves that
blocked result without retrying deletion. Constructor failure cleanup only
targets a socket bound by that constructor. Future service teardown retains
socket failure while continuing existing backend cleanup, rather than letting
a socket error skip it. This is not a new general rollback executor.

### Ambiguous windows / operator intervention

Crash before durable bound identity, PREPARING without sufficient proof,
missing/nonmatching socket, replacement parent, unsafe metadata, active listener,
policy/enrollment/installation mismatch, pending atomic write or interrupted
retirement all fail closed. `<socket>.pending` or `<socket>.retired` leftovers
are retained, not automatically deleted/reconciled. A crash after rename before
clean-ledger persistence may therefore require separately reviewed operator
intervention. These deliberately ambiguous states are not certified clean.
Completed proven stale READY/BOUND recovery removes the exact inactive socket,
persists CLEAN, and allows subsequent startup. No service installation or
operator recovery command is implemented here.

### Deterministic evidence and remaining scope

`test_privilege_socket.py` supplies13 compact cases: post-bind chmod/listen/
timeout/persistence/setup failures; normal/repeated close; early unproven bind;
proven stale restart; listener outliving its lock; file/symlink/socket/parent
replacement; unsafe owner/mode/missing/policy evidence; concurrent startup;
unlink and atomic-write failures; injected rename race; descriptor closure
despite another close error; byte-preserved mismatch rejection. Process-death
is simulated by closing owned listener/lock FDs while bypassing normal unlink.
No installed daemon crash or privileged kernel enforcement is claimed.

Remaining blockers B6–B12 are unchanged: single-campaign guard, bounded stdout
evidence, complete proof observables, operator rollback/recovery, install/client
inventory, Linux PROBE contract and qualified real-kernel target/validation.
Transport limits,180-second base/current grace/240-second hard cap, attribution,
production integration and existing cleanup/resource policy are unchanged.

Verification: seven focused B5/B3/privilege/complete-backend/B1/B4/B2 groups
PASS (60.051s); final B5 table with private-file group/mode and atomic-persistence
failure coverage PASS (9.988s). Final `bin/freeagent-test`:518 tests in304.197s,
RESULT=PASS, EXIT_CODE=0. Final diff reviewed as B5-only. The initial active-case
failure exposed constructor cleanup attempting pre-existing ownership; cleanup
was restricted to resources bound by the current constructor. No installed
service, privileged backend, model/provider call or Stage3.1D action occurred.

## Focused B11 repair — explicit Linux validation PROBE compatibility

IMPLEMENTED / DETERMINISTIC CONTRACT VALIDATION only. Stage3.1D remains
NOT AUTHORIZED. No service configuration/activation, provisioning or production
worker integration changed. B1–B5 remain intact.

### Exact contract

Request remains protocol1 PROBE with exactly `{"probe":"BOUNDARY_V1"}`.
No new operation, parameter, executable, path or kernel probe is exposed.
The successful response envelope still uses protocol1, matching sequence and
code OK. Its data must have exactly these four fields:

```json
{"schema_version":1,"mode":"SIMULATED","readiness":"UNPROVEN","enforcement":"UNPROVEN"}
```

An explicitly opted-in Linux-validation client instead requires exactly:

```json
{"schema_version":1,"mode":"LINUX","readiness":"UNPROVEN","enforcement":"UNPROVEN"}
```

Schema version is an actual integer1 (boolean/float/string versions rejected).
Other values are exact strings; unknown/missing fields, unsupported schema,
unexpected mode or any READY/VERIFIED/CONFIRMED/observed-kernel claim are rejected
with INVALID_REQUEST. The old unversioned two-field record is rejected rather
than ambiguously accepted. No compatibility fallback broadens acceptance.

Mode denotes backend class only. Readiness and observed enforcement are separate
fields and remain UNPROVEN in both modes. This endpoint performs no qualification,
resource allocation, synthetic launch, cgroup/mount mutation or model/provider
work. Configured or read-only prerequisite state cannot change these fields.
PROBE cannot certify real-kernel isolation; future live evidence requires a
separate reviewed contract, not relabeling this record.

`protocol.probe_record` constructs the fixed values; `validate_probe` enforces
exact shape/types/values. Fake/synthetic backend and LinuxBackend both use the
same builder. Supervisor validates against its independently selected mode
before returning a record; ControllerClient validates against its authenticated
expected mode again. This catches contradictory backend records and later
response substitution, independently of HELLO mode matching.

### Opt-in, trust and compatibility

`linux_validation` must be an actual boolean. Only explicit True selects Linux
client mode; nonboolean substitutes reject before connecting. The existing
root-server UID requirement,0750/0660 socket profile, SO_PEERCRED, enrollment/token,
challenge, policy agreement and connection-owned handles are unchanged. Ordinary
simulation clients require SIMULATED at HELLO and PROBE. Opted-in Linux clients
require LINUX at both; simulation cannot masquerade as Linux. Future service
configuration already chooses LinuxBackend with `linux_validation=True`; that
service and its installation path were not changed or executed.

B2 already hashes every changed contract source. Client/helper policy identity
changes together; old bound enrollment/socket/control/resource records reject
under their existing checks, with no rewriting, deletion, relabeling or migration.
Frame/transport/client/request/rate/resource bounds and180-second base/current
grace/240-second hard cap are unchanged. Doctor active isolation stays UNPROVEN.

### Tests and limitations

`test_privilege_probe.py` adds seven compact cases: valid simulation and opted-in
Linux records; bidirectional HELLO/PROBE mode mismatch; missing/extra/malformed/
contradictory fields and schema/wire version; backend-level rejection of false
readiness/enforcement; invalid opt-in; authentication/policy rejection; configured
backend state not becoming enforcement proof. Existing B1–B5 and doctor regressions
are retained. Tests use temporary IPC, fake/RecordingDriver objects and pure
projection fixtures. The Linux client fixture mocks root peer/socket profile
while separately checking requested0750/0660 values and the actual temporary
0700/0600 socket; this is NOT a real root service/authentication certification.
No driver qualification or privileged execution is used to obtain PROBE results.

Remaining consolidated blockers: B6 single-campaign guard; B7 bounded stdout
evidence; B8 complete proof observables; B9 standalone operator rollback/recovery;
B10 install/client inventory; B12 qualified disposable real-kernel target and
validation. B5's documented ambiguous crash windows still require operator
intervention. No Stage3.1D execution or readiness authorization is implied.

Verification: focused seven-case PROBE table PASS (8.156s); nine affected
PROBE/B1–B5/doctor regression groups PASS (41.722s). Final `bin/freeagent-test`:
518 tests in328.062s, RESULT=PASS, EXIT_CODE=0. Final diff inspected as B11-only.
No privileged backend, installed service, model/provider or benchmark executed.


## B7 — Bounded synthetic proof collection (preparation only)

Baseline `fbbea7b1f0d6a9ab25cb7a1b3aee4c50287c10ab`, branch main. No
separate Engineering HQ handoff or repository AGENTS.md was present; this
stage document and the owner's supplied instructions define the scope.
B1–B5/B11 remain preserved. Stage3.1D is NOT AUTHORIZED. Nothing here installs,
enrolls, qualifies or activates the privileged backend.

### Implemented collection contract

`evidence.py` owns bounded classification and asynchronous stdout/receipt draining.
`LinuxDriver.launch` transfers the exact owned stdout stream and setup receipt
read descriptor only for an approved registry entry with `validation=True`.
The registered executable digest, helper handle, controller-generated run ID,
backend owner, policy identity, execution class and role are controller/helper
facts; the child cannot supply these bindings. `LinuxDriver.collect` validates
against its immutable launch binding. Backend and Supervisor cross-check ledger
identity; authenticated connection/peer handle ownership is checked before access.
The client retains its generated run/class/role binding and revalidates the result.

Protocol v1 adds one narrow `COLLECT {handle}` operation and the typed
`ControllerClient.collect_synthetic(Sandbox)` method. It takes no paths, PIDs,
commands, durations or raw requests. Only explicitly opted-in Linux-validation
clients/supervisors accept it; ordinary simulation rejects it. RecordingDriver
returns INVALID_STATE rather than manufacturing pipe observations. An unavailable
or never-collected run stays unavailable; supervisor restart cannot recover an
in-memory observation and does not invent it. This is a retrieval seam, not a
campaign executor, installer or production worker cutover.

Result schema_version1 is strict and additive to existing STATUS/PROBE contracts:
identity fields `handle, run_id, owner, policy, class, role, executable_sha256`;
fixed `status, reason`; booleans `launcher_ready, receipt_eof, output_eof,
collector_closed`; fixed `executable_transition, completion, exit_status`;
bounded `output_bytes, record_count`; `child_claims`; and `enforcement=UNPROVEN`.
Statuses are PENDING, VALID, INCOMPLETE, REJECTED, UNAVAILABLE. Reasons are the
fixed allowlist in evidence.py; malformed/contradictory success records reject.
No raw pipe data, private output, environment, token or arbitrary exception is
returned or journaled.

Bounds: 2048 stdout bytes plus one overflow sentinel; two JSONL records,1024 bytes
per record;64 receipt bytes plus one overflow sentinel;10 seconds absolute
monotonic collection time after launcher readiness,50ms maximum select interval;
1 second bounded collector join on cleanup. No caller selects these limits.
Streams are nonblocking and drained together. Overflow/truncation/malformed data
reject; full pipes cannot cause unbounded buffering. stdout/receipt are closed
independently when collection stops. At most16 active sandbox collectors and128
retained per-instance proof/binding entries are possible under existing admission
limits. Wire frame16KiB/request128/rate32/clients8 and600s connection bounds remain.
Collection retrieves a snapshot without waiting for exit or renewing any deadline.

### Signals and their limits

The fixed C fixture now emits schema_version2 `FREEAGENTOS_SYNTHETIC_V2` STARTED,
with strictly typed bounded child claims. Its existing approved `--synthetic`
mode still forks a harmless descendant and waits indefinitely for owned deadline
termination. `--synthetic-complete` is a fixed unprivileged test-only mode emitting
COMPLETED then exiting zero; it is NOT available through RPC/ApprovedExecution.
No execution-class argv, privileged mount recipe or production lease is changed.

The launcher writes EXEC_READY before exec. The parent consumes exactly that
bounded record, allowing partial pipe reads, then transfers the close-on-exec
receipt reader. A validated launcher error can append EXEC_FAILED; it never logs
raw exceptions. EXEC_READY proves setup reached the exec attempt, not successful
exec. Receipt EOF alone can mean successful CLOEXEC transition OR launcher death:
it is NEVER sufficient positive exec evidence. Valid approved fixture STARTED
output plus readiness and receipt EOF produces `FIXTURE_STARTED`; these are
owned-channel observations, not an independent kernel executable attestation.
SUCCESS requires both fixed records, both EOFs, observed zero exit of the owned
Popen and closed collector. Transition without COMPLETED/zero exit remains
UNPROVEN completion. EXEC_FAILED, malformed or conflicting data rejects claims.
Fixture UID/GID, namespace IDs, capabilities/no_new_privs and host visibility
remain CHILD CLAIMS. They cannot set enforcement READY/VERIFIED; B8 must supply
independently observed security facts. B11 PROBE and doctor active isolation
remain UNPROVEN. Production180s base/current grace/240s hard cap are unchanged;
10s collection expiration is NOT a worker lease override.

### Failure, ownership and compatibility

Timeout, EOF, overflow, malformed output or collector stop produces an explicit
bounded incomplete/rejected record; it never releases worker ownership. Existing
owned scope/pidfd termination/reaping and durable resource intents remain required.
Receipt/stdout close failures are retained in `close_errors`; absence/removal
cannot certify clean with unresolved collectors. Independent supervision fences
FAILED_DIRTY and attempts only owned termination. One collector/descriptor failure
cannot skip other child/pipe/scope descriptor cleanup. Ambiguous numeric close is
not retried after possible FD reuse. Real-resource journal cleanup stays UNPROVEN
on unresolved cleanup; no simulation result is promoted to kernel proof.

B2 binds the added evidence source plus changed contract modules. Client/helper
must install matching code; old policy-bound journals/enrollment/socket records
continue rejecting without rewriting, deletion or relabeling. Required Python
sources and the fixed C fixture remain package artifacts under existing packaging.
No credentials or runtime evidence are copied into Git.

### Deterministic verification and remaining work

Tests cover strict schemas/bindings, valid two-record completion, readiness then
exec failure, transition without completion, missing/truncated/malformed/oversized/
duplicate/contradictory output, full pipe drain/timeout/child exit, collector stop,
independent descriptor close, dirty journal/fencing, retained evidence and swapped
executable digest rejection; typed local IPC covers mode/connection ownership and
policy/run mismatch. Fault injection mocks every privileged Linux operation.
A compiler builds only the fixed fixture into a disposable temporary directory;
finite execution/exec-error/pipe fixtures perform no isolation, identity change,
cgroup/mount operation, provider/model or project work. Existing B1–B5/B11
regressions remain required. Executable verification results are recorded below.

These tests establish bounded parsing/draining, ownership projection, observed
local fixture exit and simulated cleanup behavior. They do NOT establish real
namespace/mount/cgroup enforcement, privileged child setup, real hard-cap timing,
service crash cleanup or zero privileged residuals. Those require separately
owner-authorized real-kernel validation. B7 collection preparation is implemented;
remaining blockers are B6 campaign guard, B8 independent security observables,
B9 standalone operator rollback/recovery, B10 installation/client inventory and
B12 qualified disposable real-kernel target/validation. B5 ambiguous crash windows
remain fail-closed operator cases. Stage3.1D readiness is NOT claimed.

Verification: focused B7/B1–B5/B11 eight-group regression run PASS (EvidenceCases,
CleanupProofCases, LauncherContainmentCases, LinuxCompleteCases, PolicyIdentityCases,
TransportLifetimeCases, SocketRecoveryCases, ProbeContractCases). Final expanded
B7 nine-case table PASS. Required `bin/freeagent-test`:518 tests in344.182s,
RESULT=PASS, EXIT_CODE=0. `git diff --check` PASS; final source/test/document diff
reviewed as B7-only. Static review found no shell execution, unsafe deserialization,
arbitrary command/path/PID RPC or raw environment forwarding introduced. Tests
used disposable local IPC and unprivileged finite fixtures, recording backends
and mocked LinuxDriver primitives; the privileged backend was not activated.

## B8 — Security observables and resource proof preparation

Baseline `05a2f4b7c73e650da3c5c346eaf2af18d9bb1c7b`, main, initially clean;
no newer implementation, separate Engineering HQ handoff or repository AGENTS.md
was found. This section and the owner's supplied instructions are authoritative.
This is source preparation and deterministic/unprivileged testing ONLY.
Stage3.1D remains BLOCKED and NOT AUTHORIZED. No kernel qualification, privileged
backend activation, stress execution, service/enrollment or production integration.

### Status and exact remaining B8 gap

IMPLEMENTED: bounded security-record schema, strict pure raw-observation parsers,
owned read-only capture recipe, fixed finite C probes, immutable probe plans,
isolation/resource/termination evaluators and fault-injection recordings.
STATICALLY VERIFIED / DETERMINISTICALLY TESTED: the predicates and fail-closed
recording behavior described below. REAL ENFORCEMENT remains UNPROVEN.

B8 is PARTIAL rather than resolved: the current approved launcher still uses
`--synthetic`, closes all non-standard FDs on exec, and accepts B7's original
fixture schema. It does NOT deliver the new private stress authorization gate
or execute security-probe modes. No authenticated B8 sidecar retrieval adapter
or live-origin certification is connected to Supervisor/COLLECT. CPU runnable
work/affinity and completed-work observations still need the trusted runtime
assembler alongside these fixed kernel counters. These are explicit preparation
integration gaps; no owner may treat this code as an end-to-end validation path.
A follow-up B8-only change must bind a fixed registered probe selector, gate,
owned completion/exit observations and strict authenticated sidecar projection
without implementing a campaign or widening arbitrary command/path/PID APIs.
B6, B9, B10 and B12 are unchanged. Stage3.1D readiness is NOT claimed.

### Modules and trust separation

`security_proof.py` defines version1 expectations/records, a bounded fail-closed
buffer, pure evaluators and fixed plans. Every record binds B7's handle/run/owner/
policy/class/role/executable digest, plus a fresh sample ID, helper-owned opaque
subject ID, scope device/inode and monotonic sample window. Required sources are
explicitly hashed by B2, included automatically as Python package files; the
new C fixture uses the existing fixtures/*.c package-data rule. Old policy-bound
journals/enrollment/socket records remain rejected, never rewritten/relabelled.
No production policy value, lease, grace behavior or transport limit changed.

Levels CONFIGURED, CHILD_REPORTED and INDEPENDENT_RECORDING cannot imply live
provenance. PASS means the supplied recording satisfies the proof predicate,
NOT that this machine is isolated. Evaluator `enforcement` is always UNPROVEN;
its `level=RECORDED` cannot become ENFORCEMENT_PROVEN. Configured-only and
child-only evidence is INCONCLUSIVE. KERNEL/VERIFIED labels supplied to the
record buffer are rejected. A future trusted authenticated live-capture adapter
must establish provenance before any real certification is possible.

`security_observe.py` projects only fixed proc/status, namespace, descriptor,
mount/device and cgroup data into bounded summaries. Parsers do not establish
provenance. Raw proc text, paths, environment, credentials or IPC are not kept.
`security_capture.py` is inert on import and never called against a live backend
here. Its private factory requires an exact qualified LinuxDriver, installation
permit/policy, boot identity, owned launcher pidfd, approved validation artifact,
matching run identity and owned scope inode/device. The normal constructor refuses.
It accepts no RPC PID/path/command/FD, installs nothing, writes nothing and kills
nothing. Future use must be separately authorized and scoped to a registered run.

The reader pins /proc and the owned scope with CLOEXEC FDs. Candidate host PIDs
come only from bounded owned cgroup membership. Proc directory, start ticks and
pidfd are checked before/after capture; immutable executable inode/device/hash
select the actual approved PID-namespace init, not the trusted outer Python
launcher. Host namespace reference is the supervisor's pre-child namespace,
not a fabricated native-host/WSL equivalence. Fixed proc exe/root/ns/fd links
are deliberately followed only beneath a pinned owned process; generic path
traversal/symlink following is not exposed. Root is compared to the approved
runtime FD; forbidden paths use pinned no-follow directory walks. Devices are
stat-only, never opened/created. Descriptor and membership races fail closed.

Scope/process/observer ownership remains live across collection. PIDfd acquisition
and cleanup use descriptor references, never protocol PIDs. ExitStack attempts all
closes after failures; ambiguous close sets driver.close_errors and retains dirty
cleanup obligations. No ambiguous numeric FD is retried. Resource reads return
UNPROVEN summaries, not configured-limit enforcement claims. Missing cgroup files
(e.g. pids.peak) or permissions/exit races cannot be replaced by guessed values.

### Required independent proof predicates

| Proof | Required independent observations / evaluation | Inconclusive or failure |
|---|---|---|
| Identity | Owned executable proc/status: real/effective/saved/filesystem UID and GID all equal enrolled dropped identities; supplementary groups empty | Missing/stale/mismatched record inconclusive; wrong identity/group FAIL |
| Capabilities/NNP | CapInh,CapPrm,CapEff,CapBnd,CapAmb all0 and NoNewPrivs1 from owned proc/status | Child aggregate boolean insufficient; nonzero capability or NNP0 FAIL |
| FD closure | Bounded owned proc/fd inventory exactly0,1,2; stdin/stdout pipes and stderr the minimal null device; no privileged directory/socket/file descriptor | Numbers alone insufficient; extra/missing/unsafe descriptors FAIL |
| Namespaces | Pinned host/worker inode comparison: mount/PID/network different, user namespace same as the current fixed recipe; independently read inner PID1 | Identifier alone insufficient; wrong comparison/PID FAIL |
| Filesystem | Root inode/device matches registered runtime; root ro/nosuid; no shared/master propagation; exact fixed mount targets; private proc device/PID namespace; exact four character devices; forbidden root/config/state/Docker paths absent | Missing field inconclusive; wrong mount/root/device/exposure FAIL |
| Descendants | Compare private PID-namespace proc membership against owned scope membership, not just scope population. Pin seen members' pidfds; observe descendants before termination; afterwards scope empty, pidfds exited, owned launcher reaped, RELEASED/confirmed absence | Unchecked namespace membership inconclusive; observed escape FAIL; incomplete release/reap/absence inconclusive and cleanup remains due |
| CPU | Same owned scope's cpu.max readback; paired cpu.stat deltas; independent >=2 runnable tasks/available CPUs and >=2s bounded work; >=10 periods, positive nr_throttled/throttled_usec; usage positive and <=quota-time budget plus explicit accounting tolerance | Readback or usage bound mismatch FAIL; counter reset, weak demand, absent throttling or time mismatch inconclusive |
| Memory | Same owned scope memory.max/swap.max/peak and paired memory.events; max,oom,oom_kill increase; owned resource-terminated execution with no prior termination request; peak within limit+4MiB accounting margin | Readback/peak mismatch FAIL; SIGKILL/exit alone, requested termination, absent OOM counters or wrong outcome inconclusive |
| PIDs | Same owned scope pids.max, independently observed peak and paired pids.events.max increase; bounded fork fixture completion and observed children | Readback/peak mismatch FAIL; child EAGAIN claim alone or no denial event inconclusive |

Every proof's valid/missing/malformed/contradictory/source-only cases are tested.
Contradictory child/independent records remain INCONCLUSIVE rather than picking a
favorable version. Negative/reset counters, old timestamps, subject/scope/run/
policy/executable mismatch, duplicates or invalid schemas invalidate the bounded
record set; no partial valid subset can qualify it. Resource intent is distinguished
from unexpected execution: RESOURCE_TERMINATED is acceptable for the memory
predicate only with independent OOM counters and no requested kill. TIMEOUT,
ABNORMAL and MISSING never pass; each retains cleanup obligations. Fixture output
and observed exit must be bound together by the still-missing runtime assembler.

### Explicit evidence bounds and B7 compatibility

B7 remains schema1 / fixture schema2,2048 stdout bytes,1024 per record,two records,
64 receipt bytes,10s collection. Its COLLECT/PROBE interfaces are untouched.
Full B8 independent observations do not fit that child channel; this stage adds
an EXPLICIT separate prepared sidecar schema1:8192 bytes per JSONL record,24
records,65536 aggregate bytes,10s absolute monotonic sample window. Required
independent raw reads are capped at65536 bytes per capture and500ms; status<=128
lines, mounts<=32, supplementary groups<=16, FDs<=256, tracked processes<=64.
Executable verification reads<=32MiB under the same deadline; no arbitrary asset
or host scan. Capture-owned descriptors remain CLOEXEC and explicitly closed.
The sidecar is NOT currently an RPC response or a bypass around B7; future
transport must retain16KiB frames and bounded per-record retrieval, with strict
live provenance. A child cannot populate the independent sidecar through stdout.

### Fixed probe recipes and authorization gap

`security_probe.c` accepts only --observe/--cpu/--memory/--pids. No free numeric,
path, executable or environment parameters. `probe_plan` emits these exact argv
values only, with binding and AUTHORIZATION_REQUIRED_NOT_GRANTED. Plans select
existing allowed lower validation limits: CPU50000/100000, memory64MiB/swap0,
PIDs8; production defaults and180s/current grace/240s hard cap are unchanged.
This lower test envelope must be separately authorized with the future fixture
and owned execution, and MUST NOT become production defaults.

| Fixture | Explicit bounds |
|---|---|
| observe | No stress, no fork/allocation; two tiny fixed records; completed immediately; only mode run unprivileged in tests |
| cpu | Parent+at most2 children; each<=1,000,000,000 iterations and3s monotonic work; parent5s alarm; at most1s gate wait |
| memory | One process, one<=96MiB buffer,<=24576 page touches and4s work;5s alarm; expected owned64MiB OOM outcome |
| pids | At most16 fork attempts, parent+at most16 children (owned PIDs8 ceiling applies); each<=400 short sleeps/4s;5s alarm; reap every successfully created child |

Output for every probe remains<=2048 bytes/two fixed records. Stress modes refuse
without fixed FIFO gateFD3, one G byte after<=1s poll, non-root identity, namespace
PID1 and NNP/no-effective-capability guard. This CHILD refusal guard is not a
containment proof or authentication substitute; the trusted future launcher must
independently validate the owned cgroup/readbacks before releasing the gate.
Current launcher closes FD3 and offers no stress mode, so plans are NON-EXECUTABLE
END TO END. No stress probe was launched in this milestone. Unexpected alarm,
fork/allocation/setup/exec failure cannot be reclassified as enforcement success;
owned scope cleanup is still mandatory. No automatic retries or campaign added.

### Review and verification limits

Tests use deterministic recorded observations, pure parsers, recording descriptor/
cgroup/pidfd behavior, acquisition/closure failure injection and a disposable
compiled --observe fixture only. Import guards prohibit kernel reads on import.
No real supervisor/service, namespaces, mounts/chroot, UID/GID/capability mutation,
cgroups, enrollment, kernel qualification, model/provider or benchmark occurred
through this preparation code. Existing production run_worker and Stage2 evidence
remain unchanged. Doctor active isolation is UNPROVEN. B1–B5/B7/B11 regressions
and repository-required freeagent-test remain mandatory; results follow below.

Static review: new Python code uses no subprocess/shell/kill/mount/chroot/UID-drop
operation. os.open/dup/stat/scandir/pread/read are fixed descriptor-owned read-only
recipes; pidfd_open/select are observational, never kill APIs; os.close is scoped
cleanup. The C stress fixture has finite fixed fork/malloc/CPU/clock/alarm/wait
primitives behind the unactivated gate; no arbitrary command, PID/path interface,
network or provider. Test subprocess calls compile fixed source and run --observe
only. No privileged code was installed or given authority.

Additional B8 integration gate: the capture context must be registered with the
backend's release/absence checks before activation. The current private reader
sets close_errors on ambiguous closure, but successful live observer lifetimes
are not registered in LinuxDriver's resource ledger. In particular, its pinned
private-proc mount and descendant pidfds must be closed before certifying final
zero residuals. This code is NOT an authorization to bypass B1 cleanup proof;
no live reader was issued here. Root/cgroup snapshot sampling and final lifecycle
assembly need complete recording syscall coverage in that follow-up, not just
isolated parser/projection tests. These gaps keep B8 and Stage3.1D blocked.

Verification: final B8 eleven-case table PASS; nine affected regression groups
(SecurityProofCases, EvidenceCases, CleanupProofCases, LauncherContainmentCases,
LinuxCompleteCases, PolicyIdentityCases, TransportLifetimeCases, SocketRecoveryCases,
ProbeContractCases) PASS in58.530s total. Required bin/freeagent-test:518 tests
in322.280s, RESULT=PASS, EXIT_CODE=0. Python compilation and git diff --check PASS.
Final diff reviewed as B8-only. These are executable checks of the preparation
portion, not real-kernel qualification or completion of the integration gaps.
No verified tag, Stage3.1D readiness claim or execution authorization.
