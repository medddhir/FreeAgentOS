# Stage 3.1C real backend preparation — PARTIAL

This checkpoint adds audited preparation primitives, not a complete activated
Linux isolation backend. Production `run_worker`, simulation transport, policy
hash, protocol v1, doctor, bootstrap and attribution acceptance are unchanged.
No privileged operation was executed through the new code. No installation
bundle is ready to authorize. Do not proceed to privileged validation yet.

## LINUX_BACKEND

`privilege/linux.py` is separate from FakeBackend. Imports perform no kernel
operation. LinuxIsolationBackend exposes read-only readiness; prepare/start
always reject with RECOVERY_REQUIRED. The existing supervisor rejects its type.
Neither RPC nor user config selects it. This is an intentional activation fence,
not an implementation of namespace/rootfs enforcement.

## SYSCALLS_AND_BINARIES

Implemented calls: lazy libc syscall 437 (x86_64 openat2), os.pidfd_open,
select readiness, open/read/write/mkdir/rmdir via administrator-owned directory
FDs. No external binaries, subprocess, shell, raw kill, mount, umount,
chroot or mknod occur in new code. ChildSetup additionally implements libc
unshare and ordered prctl/capset/setgroups/setgid/setuid calls behind child-only
and rootfs-ready guards. Tests mock unshare and never execute these changes.
Cgroup filesystem writes exist behind an unconditional mutation rejection.
Pidfd opens identify only a supplied helper-child object; no public PID input.
The constructor API is administrative/internal and is not an RPC.

Primary specifications: [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html)
and [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## SECURE_PATH_RESOLUTION / FD_MODEL

secure_open only accepts exact relative components, with BENEATH, NO_SYMLINKS,
NO_MAGICLINKS and NO_XDEV. Single-link regular files/directories only. No create
or write flags; special files rejected. Missing syscall/platform guarantees
reject PATH_REJECTED without realpath fallback. NO_XDEV is below an enrolled
anchor; acquiring the anchor across normal filesystem mounts needs separate
administrator verification. All returned FDs are CLOEXEC and caller-owned.
Executable records retain FD/inode/device/hash and require root ownership,
non-group/world-writability and executable mode. Hash validation detects
in-place modification but does not prove immutable inode contents during exec;
root-owned immutable installation and safe FD exec remain required.

## WORKSPACE_SNAPSHOT

NOT IMPLEMENTED. The existing protocol CREATE supplies a slot; START only a
handle. Existing RegisteredRoots pins directories but does not copy/hash a
sealed manifest into a helper-owned snapshot. Pinned files prevent path
substitution, not concurrent writes to inode contents. Do not bind a mutable
controller workspace into a privileged recipe. Required work: bounded manifest
registration and verified copy through openat2 FDs into private helper storage;
verify external verification hashes before admission. No path arguments added
to RPC to bypass this gap.

## MOUNT_RECIPES / DEVICE_POLICY / ROOTFS_MODEL

Immutable logical recipe registry: model (sealed workspace, readonly runtime,
private scratch/proc); tester (test copy and private network additionally);
research (runtime/scratch/proc). Devices limited to null, zero, random, urandom.
No host mount pairs, arbitrary devices or Docker/GPU sockets. Actual recipe
construction, device preparation and mounts are NOT implemented. Existing
model worker has broker-only file access, mount/PID isolation and controller
readonly projection; new model recipe must preserve broker mediation and must
not grant direct writable workspace access. Chroot alone is never sufficient.

## IDENTITY_DROP_ORDER / CAPABILITY_DROP

Ordered plan: attach paused child to owned cgroup; establish mount/PID context;
private propagation; fixed rootfs; chroot plus chdir; clear bounding/ambient
capabilities while privileged; clear supplementary groups; set GID; set UID;
clear all capsets; no_new_privs; close privileged FDs; exec approved class.
ChildSetup implements namespace and identity/capability syscalls, but the
ROOTFS_READY admission stage is deliberately unreachable. PID namespace fork,
mount/rootfs and execution remain plan labels. Need a reviewed single-thread
child launcher; Python preexec_fn in a multithreaded service is unsuitable.
No user/model/client code may execute before all drop assertions succeed.
Supervisor setup capabilities and minimal bounding set remain unqualified.

## EXECUTION_REGISTRY / ENVIRONMENT_POLICY

Fixed execution classes inherited from Stage 3.1B; root-owned pinned executable
primitive added. No executable/argv/mount/env selection through protocol.
Role-specific final argv construction and FD exec are NOT implemented. Fixed
PATH/HOME/LANG and Python bytecode setting use existing worker_environment;
caller LD_*, PYTHONPATH, BASH_ENV and provider variables are not inherited.
Credential delivery is unresolved; never copy the controller environment.

## CGROUP_V2 / PIDFD

OwnedCgroup models scope creation beneath a pinned administrative subtree;
fixed memory.max, memory.swap.max=0, pids.max, cpu.max; paused-child attach;
cgroup.kill, bounded cgroup.events population read, empty-only removal. Limits
are validated against existing policy. No PID enumeration fallback. All
mutations are blocked. Delegated subtree acquisition, filesystem-type/ownership
qualification and controller enabling remain to implement. No claim that any
caller-supplied FD is already a qualified production cgroup root.
OwnedPidfd implements direct-child identity/readiness and CLOEXEC. Real descendant
termination must use cgroup.kill, not direct-child termination alone.

## LEASE_SUPERVISION / DISCONNECT_BEHAVIOR

Deadline uses monotonic time, base180/grace60/hard240. Grace requires a trusted
boolean, which must originate in authenticated recent broker activity; model
output is insufficient. Connection-bound ownership from Stage 3.1B is preserved:
a disconnected controller is terminal, not reconnectable. Deadline computes
expiry but no independent monitor/event loop invokes owned scope kill yet.
Research/tester role deadlines must be mapped separately before activation.

## REAL_RESOURCE_JOURNAL / RECOVERY

Existing versioned bounded private atomic journal is unchanged. New pure recovery
planner requires exact fields/version/policy/boot identity/opaque handle/recipe
and rejects raw PIDs or paths. Actions: verify ownership, kill scope, verify
empty, reap owned pidfd, remove private root/scope, mark released. This does not
prove ownership across restart: needs root-private ledger, cgroup inode/boot
registration and durable pre-create records, not names alone. Real resource
journal persistence and executable recovery are NOT implemented. No host scans.

## SERVICE_ENTRYPOINT / SYSTEMD_TEMPLATE / INSTALL_MANIFEST / AUTH_ENROLLMENT

NOT ADDED: incomplete backend must not be advertised as an installable service.
Existing temporary token/enrollment contracts remain; no current enrollment.
Future reviewed administrator bundle must contain root-owned immutable package
under /opt/freeagentos-supervisor, root-owned0600 enrollment/policy registry
under /etc/freeagentos-supervisor, root-private0700 journal under
/var/lib/freeagentos-supervisor, and restricted enrolled-group0750 runtime /
0660 Unix socket. Client secret needs a separate private0600 user delivery file.
No development checkout paths or credentials in a bundle. A systemd template
must audit required CAP_SYS_ADMIN/CHROOT/SETUID/SETGID/SETPCAP, delegation,
mount-namespace visibility, and cleanup across service termination. Do not
blindly enable ProtectControlGroups or RestrictNamespaces against required
operations. Privilege installation remains separate from install.sh.

## WSL2_READINESS / NATIVE_UBUNTU_REQUIREMENTS

Read-only observed: Ubuntu24.04.4 x86_64, WSL2 kernel6.6.87.2; cpu/memory/pids
controllers listed; namespace entries and Python pidfd APIs present. PID1 is
`codex`, not systemd in this execution context. No delegated subtree or mount
capability proved. WSL2 validation readiness: PARTIAL. Native Ubuntu requires
a separate machine; WSL results are not proof. doctor remains UNPROVEN.

## VALIDATION AND SECURITY REVIEW

Compact test table checks import inertness, actual unprivileged openat2 paths,
symlink/traversal rejection, missing syscall failure, FD inheritance, immutable
recipes, identity/drop ordering as plans, ceilings, deadlines, recovery rejection,
executable mutation detection and permanent activation fence. These do not
substitute for all requested real-backend security tests. Existing full test
runner includes historical isolation fixtures; new-code tests perform no
privileged kernel mutations. No original Stage2 evidence is touched.

## STAGE31D_EXACT_VALIDATION_PLAN

Prerequisite: complete and review snapshot/argv/child-launcher/identity/capability/
mount/cgroup qualification, independent supervision and durable recovery first.
Until then Stage3.1D is BLOCKED; do not authorize installation of this checkpoint.
After readiness: use a disposable VM (native Ubuntu first, WSL separately), no
projects/models/providers/gateway. Explicitly install temporary root-owned service
and enrolled unprivileged test client. Test authorized handshake, wrong peer/token;
synthetic child namespace IDs, mount/rootfs visibility, UID/GID and all capability
sets; exact cgroup limits and descendant membership; pidfd identity; scoped kill;
real existing180+60/240 lease; controller disconnect; supervisor crash/restart
recovery. Check all mounts/cgroups/processes gone. Remove temporary unit/package/
enrollment/journal/runtime only after cleanup proof; preserve bounded test facts.
Never host-wide kill/unmount or erase a dirty ledger to claim clean rollback.

Next preparation checkpoint must complete these named gaps before one separately
authorized Stage3.1D validation. This milestone is PARTIAL, not production-ready.
