# Stage 3.1A — secure production privilege boundary design

Status: design reviewed against source; not an implemented or qualified boundary.
Parent: `e66a0f10bd99d78232d8fc8334a952bf8f875b3b`.
No provider dispatches were made. No services, helpers, privilege probes,
model requests or machine changes are
part of this milestone. Stage 3.0D bootstrap remains non-root and unchanged.

## CURRENT_PRIVILEGED_OPERATIONS

Source references are function names, which remain useful when line numbers move.

| Source/function | Operation and phase | Privilege and preservation requirement | Potential substitute |
| --- | --- | --- | --- |
| `worker._run_worker_impl` | `unshare --mount --pid --fork --kill-child=SIGKILL`, before spawn; private propagation | CAP_SYS_ADMIN in appropriate owning user namespace; PID init/reaping and mount isolation required | User namespace potentially permits this; not qualified |
| `worker._child_limits` | `os.unshare(CLONE_NEWNS)`; libc mount private propagation, read-only cgroup and controller bind/remount; before exec | CAP_SYS_ADMIN; prevents control-plane/cgroup mutation by worker | User namespace plus fixed mounts, pending parity tests |
| `sandbox._start_cgroup`, called by worker and tester | Mount cgroup2, create scope, write/read back memory.max, memory.swap.max, memory.oom.group, pids.max, cpu.max, require cgroup.kill; before spawn | Mount requires CAP_SYS_ADMIN; cgroup writes require filesystem authorization/delegation, not simply a special capability | Proper systemd delegation can remove root cgroup writes, not prove complete boundary |
| `worker._child_limits`, `sandbox._apply_child_limits` | Move own child into cgroup.procs before exec; setrlimit CPU/NPROC/NOFILE/FSIZE/CORE (tester also AS) | Own downward rlimits generally unprivileged; cgroup attach needs scope permissions | Helper-owned spawn barrier or clone into scoped cgroup; do not expose ATTACH_PID |
| `worker._run_inner` | `setpriv --bounding-set=-all --no-new-privs` before broker/model exec | Dropping bounding capabilities uses CAP_SETPCAP as appropriate; setting no_new_privs is unprivileged | Explicit child setup followed by audited irreversible drop |
| `sandbox._run_isolated_in_area` | `unshare --mount --net --pid`, private propagation, proc mounting; before target tests | CAP_SYS_ADMIN; test network isolation and namespace init required | User namespace potentially, not currently proven |
| `sandbox._setup_and_exec` | /usr and Python venv read-only mounts, bounded tmpfs roots/scratch; before tests | CAP_SYS_ADMIN; fixed runtime projection and bounded disk/inodes required | Rootless mounts may support parts; runtime compatibility unproven |
| `sandbox._safe_copy`, `_setup_and_exec` | Bounded single-link regular-file copy, ownership to 65534, private permissions; before tests | Ordinary copy/chmod on owned files needs no root; changing owner needs CAP_CHOWN, traversal may need DAC privilege | User ID mappings/caller-owned staging, not drop-in parity |
| `sandbox._setup_and_exec` | mknod null/zero/random/urandom, fixed major/minor; before tests | CAP_MKNOD plus mount/device policy; current four devices required by runtime | Fixed device projection may remove capability; validate first |
| `sandbox._setup_and_exec` | `/usr/sbin/chroot --userspec=65534:65534`, clean env; before tests | CAP_SYS_CHROOT, CAP_SETUID/CAP_SETGID; non-root test process required | Namespaced mapped UID/chroot potentially |
| `sandbox._stop_scope`, worker/sandbox finally paths | SIGTERM of trusted process group/members; cgroup.kill; reap and assert zero members; during termination | CAP_KILL for cross-UID signals; cgroup.kill needs scope authority; numeric PIDs currently internal | pidfds plus helper-owned cgroup, scoped termination |
| `worker._cleanup_outer_scope` | Reap invocation's validated scope from /sys/fs/cgroup if namespace init dies; cleanup | Scope authority, cross-UID termination; cleanup fallback required | Supervisor holds cgroup FD, not public scope paths |
| `sandbox.run_isolated` finally | Reclaim nobody-owned test tree with chown/chmod and symlink-resistant removal; cleanup | CAP_CHOWN, sometimes CAP_DAC_OVERRIDE for traversal; limited to own temporary tree | Destroy private mounts/FD-owned helper tree, never reclaim arbitrary user paths |
| `workspace.prepare_workspace` and verification artifacts; `broker_session.BrokerSession` | Copy, hash, chmod 0700/0400 and bind 0600 broker socket | No intrinsic root requirement on caller-owned paths; root today is inherited execution context | Remain unprivileged, preserving external manifest and file-policy checks |
| `preflight.check_host` | Existing active tests invoke both privileged paths | Requires their privileges; not a read-only doctor check | Future fixed helper self-test, never arbitrary probe program |

`research_execution.run_research_action` uses the common worker path with fixed
research actions. It must not become a generic privileged curl/shell launcher.
Inspector, Planner orchestration, policy construction, verification decisions,
model profiles, attribution IPC, parsing, evidence projection and promotion
need no root. Git operations must never run as root on a user repository.

Important present distinction: model workers drop capabilities but do not call
setuid/setgid in `worker.py`. In today's root development context their UID can
remain 0. Target tests explicitly run as UID 65534. The new boundary must use
non-root identities for every model, research and repository-code process.
Current model file access is enforced by sealed broker capabilities, not a full
model chroot. Target tests have the separate networkless chroot. Do not describe
these as identical isolation mechanisms or claim kernel-exploit protection.

## ROOTLESS_FEASIBILITY

No unprivileged namespace/delegation probe was executed. Full rootless parity is
UNPROVEN, including on the reference Ubuntu host. Rootless mechanisms can cover
parts; they are not grounds to remove a guarantee.

| Guarantee | Classification for this implementation plan | Evidence/condition |
| --- | --- | --- |
| Sealed file broker, exact relative paths, hidden/verification exclusion, resource policy selection | ROOTLESS_PRESERVABLE | Deterministic unprivileged code; separate model UID still required |
| Output caps, monotonic lease calculation, rlimit reductions, structured argv | ROOTLESS_PRESERVABLE | No root inherently needed; trustworthy success source must remain isolated |
| Private PID/mount/network namespaces, runtime read-only mounts | UNPROVEN | User namespaces can confer namespace-scoped capabilities; Ubuntu policy and host configuration can restrict them |
| cgroup memory/CPU/PID limits and cgroup.kill | UNPROVEN | Requires actual controller delegation and membership containment, not merely a user scope name |
| Cross-UID chroot/test ownership and fixed device preparation | REQUIRES_PRIVILEGED_HELPER | Current path uses host UID 65534 and privileged filesystem operations; mapped-UID replacement not validated |
| Cross-UID worker creation and crash cleanup independent of caller | REQUIRES_PRIVILEGED_HELPER | Chosen dedicated identities and service supervisor; rootless alternative remains research |
| Full existing preflight and cleanup evidence parity | UNPROVEN | Must pass isolated security tests before production use |

A systemd user scope alone is not proof of delegated writable controllers or
protection against another same-UID process moving workers. Bubblewrap-style
containment may replace some setup code, but adding a new runtime without
parity evidence is outside this milestone. Do not disable Ubuntu user-namespace
restrictions, add broad file capabilities, or use weaker fallbacks.

## ARCHITECTURE_OPTIONS

| Option | Assessment |
| --- | --- |
| Narrow root-owned Unix daemon | Strong supervision, authenticated local channel, scoped cleanup; persistent parser/privilege exposure requires very small audited code |
| One-shot privileged helper | Smaller idle surface; orphan supervision and authenticated teardown become harder; custom setuid parsing unacceptable |
| sudo/polkit helper | Interactive authorization possible; repeated process setup/environment complexity; never allow sudo Python from user venv or arbitrary CLI |
| System service with unprivileged client | Root-owned deployment/versioning, cgroup delegation, restart cleanup and revocation; depends on working service manager |
| Fully rootless/delegated | Least root code; parity, userns policy, cross-UID protection and WSL/systemd behavior currently unproven |
| Hybrid | Potential later reduction of privileges; two interchangeable backends too much for initial qualification |

## SELECTED_ARCHITECTURE

Choose one narrow root-owned supervisor daemon managed as an explicitly installed
system service, accessed through a restricted local Unix socket. This combines
the daemon and service options. The privileged supervisor persists for active
runs; socket activation while idle may be added later, not a requirement.
No setuid binary, sudoers rule, custom polkit policy, or privileged user Python.
The first implementation has one backend; rootless parity can be qualified later.

The supervisor performs fixed isolation setup, cross-UID launch, enforcement and
cleanup only. It never imports the user's Python package, executes a private
claude-free wrapper as root, parses model text, runs project Git, decides a coding
plan, verifies task semantics or selects a provider. Fixed trusted native helper
code is preferable to a privileged Python environment with user import hooks;
implementation language/dependencies require review before Stage 3.1B.

Per-run privileged setup children handle mount operations; the long-lived
supervisor has a smaller role. Trusted broker/activity processing runs in a
separate unprivileged service identity, not in the root parser. Dedicated model
and tester identities are different from controller and broker identities.
Allocate non-login per-active-run identities from a bounded administrator-owned
pool; never reuse an identity until all its processes are reaped. A shared
unprivileged UID across concurrent runs is insufficient.

## TRUST_BOUNDARY

Trusted: root-owned helper and policy registry, bounded parser, kernel,
authorized deterministic controller, sealed policy validation, isolated broker
and lease evaluator. Untrusted: all model/project/prompt/tool content, user
workspace files, runtime/user launcher bytes, environmental input.
The controller owns authorization; the helper enforces fixed policy envelopes.
A chosen model/profile never changes read/write/new-file rights, resource class,
lease, verification access or sandbox behavior.

UID authentication does not establish that a particular Python script is honest.
An attacker controlling the controller's account can impersonate a controller;
this is an explicit residual risk, not solved by hashing an interpreter or by
storing a token in the same user's home. Even an authorized hostile caller must
not obtain host root operations. Model processes use a different UID and cannot
access the helper socket, session capability, broker policy or controller state.

## RPC_PROTOCOL

Proposed v1, local AF_UNIX SOCK_SEQPACKET, strict typed records plus separately
validated SCM_RIGHTS FDs. No public filesystem path, PID, argv, shell text,
mount pair, raw environment, UID selector or cgroup name. Reject duplicate JSON
keys, unknown fields, trailing data, wrong types/booleans-as-integers and unknown
versions/operations. Data/prompts never pass through the privileged parser.

Envelope: `protocol_version=1`, request sequence, fixed operation, opaque
controller run_id (128-bit random correlation), and session authorization over
the authenticated connection. Helper-generated sandbox_id is distinct and
bound to UID, connection and registered run. IDs contain no path/task meaning.
No arbitrary child identifiers supplied by client.

Exact public operation set:

| Operation | Allowed inputs and result |
| --- | --- |
| HELLO | Supported version/build compatibility and enrolled installation ID; challenge/response; no spawn |
| CREATE | Registered workspace slot, role enum, fixed execution class MODEL/TEST/RESEARCH/PROBE, approved runtime ID, sealed policy digest/validated policy transfer; helper creates scope/root and opaque handle |
| START | Handle plus typed execution selector (role/profile or fixed research action); bounded unprivileged delivery-channel FDs; one start only |
| STATUS | Handle; safe fixed lifecycle/evidence snapshot only |
| TERMINATE | Handle; fixed CANCEL category; terminate only this run, no signal or PID parameter |
| RELEASE | Handle; terminate/reap if needed, remove owned mounts/scope/tree; idempotent tombstone result |
| PROBE | Fixed built-in no-model parity probe ID; same isolation backend, no caller code |

CREATE and START form a strict NEW -> PREPARED -> RUNNING -> STOPPING ->
REAPED -> RELEASED state machine. Failure yields FAILED or CLEANUP_UNPROVEN.
Registration of workspace slots and unprivileged copy-in is a connection-bound
CREATE subprotocol, not an RPC for root to open a supplied path. Accept only
already-open caller-authorized directories from the enrolled workspace root;
provenance/identity must match connection registration. The unprivileged
ingester checks accessibility as the caller, never uses root to read user FDs.
Copy regular single-link files with existing budgets and controller exclusions;
reject changed identity/content and snapshot substitution. Helper-owned private
snapshots eliminate mutable-parent mount races. No bind of a mutable host
project into a privileged setup child.

Execution parameters are consumed/validated by the unprivileged worker agent
only after isolation, identity drop and closure of privileged FDs. MODEL builds
the existing structured command from an approved adapter contract; TEST runs
only the registered verification runner; RESEARCH uses existing four action
shapes; PROBE uses fixed helper fixtures. No free-form launch operation. A
user-owned executable, if allowed by registration, runs only after irreversible
UID/capability drop, never during helper setup or health handshake.

Bounds: control record <=16 KiB, nesting <=4, strings <=256 bytes, <=8 FDs per
record, no stream buffers in root parser; sealed file-policy channel <=existing
128 KiB worker request budget, existing read/write cap 8 and planner cap 4.
Preserve current file/message/output caps, not invented smaller production
limits. Maximum 2 active runs per enrolled UID and 16 total pending admission;
reject excess, never relax per-run limits. Fixed admin admission limits may be
revisited separately. Handshake/setup deadline 5s, rate limit 32 control RPC/s
per session; no deadline resets from traffic. These new protocol limits require
deterministic qualification, not a claim about current behavior.

Responses: OK, UNAUTHORIZED, PROTOCOL_MISMATCH, POLICY_MISMATCH,
INVALID_REQUEST, BOUNDS_EXCEEDED, RESOURCE_UNAVAILABLE, STATE_CONFLICT,
NOT_FOUND, SETUP_FAILED, CLEANUP_UNPROVEN. No arbitrary exception strings.
Transport/evidence channels are separately bounded; stdout/stderr never appear
in root RPC logs. ERROR cannot be projected as successful enforcement.

## PATH_SECURITY

Root-owned registry contains runtime/policy roots and workspace slot metadata;
client config and model text cannot add helper roots. Open anchor directories
once with O_DIRECTORY|O_CLOEXEC and pin device/inode identities. Use openat2
RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS for child paths;
NO_XDEV within snapshots except explicitly preinstalled runtime mount roots.
Reject absolute/.././ aliases and duplicate separators in policy paths just as
today. Fail closed if required kernel resolution primitives are unavailable;
realpath prefix checking alone is insufficient.

Every final file uses O_NOFOLLOW, fstat regular-file/nlink=1 checks and bounded
copy with pre/post identity validation. Directory FDs alone do not freeze
mutable directory contents: copy-in is unprivileged and verified, then helper
seals its own snapshot before launch. No root chown/chmod follows project paths.
No root archive extraction, Git filters, hooks, package builds or symlink walks.
Cleanup uses pinned helper-owned directories, never recursively traverses a
caller path. Mount FDs/namespace handles remain supervisor-private.

## PROCESS_SECURITY

The helper creates the process and pidfd, retains namespace-init and cgroup
handles, and never accepts attach/kill PID requests. Spawn stays blocked until
scope assignment is read back and required controls enforced; no uncontrolled
fork/exec interval. Use clone3(CLONE_INTO_CGROUP) if supported, otherwise an
explicit trusted child barrier before any untrusted code. Required fallback
must be demonstrated, not assume clone3 is enabled everywhere.

pidfd identifies direct owned processes without PID reuse; cgroup.kill covers
descendants. No numeric PID from telemetry is accepted for later actions.
Close all helper, registry, namespace, socket and cgroup FDs before model/test
exec; retain only allowlisted data/stdio/relay FDs. Distinct UIDs, restricted
proc views and no dumpability prevent ptrace and same-UID credential/FD access
from worker to controller/broker. Parent-death signal plus verified parent
identity is defense in depth, never the sole descendant cleanup guarantee.

## CGROUP_SECURITY

System manager delegates a dedicated subtree to the service, not the normal
controller. Root-owned supervisor manages fixed per-run leaves, with management
processes outside constrained leaves and no-internal-process conflicts resolved.
Use existing mounted hierarchy; do not reconfigure the host hierarchy or create
arbitrary private cgroup mounts just because the client requests them.
The worker sees no writable scope/ancestor interface and cannot migrate out.
Administrative registry pins delegation root and allowed controllers.

Enforce exact WORKER_POLICY, RESEARCH_POLICY or RESOURCE_POLICY and their hashes;
no client numeric resource override in v1. Existing permitted shorter deadlines
can be represented only by approved fixed role/probe selectors. Coder/Fixer
180s base, one 60s grace, 240s hard cap; current Planner/Reviewer/research/test
limits remain their source-defined values. Fixer global attempts remain 2 in
the controller. All policy copies/version hashes must match before admission.

Trusted unprivileged broker/lease agent owns successful-operation progress.
An inherited one-way private channel from that isolated agent reports only
validated success sequence/timestamp; helper binds its peer/FD to the broker
it spawned. No public GRANT_GRACE, generic heartbeat or model-text activity.
The agent applies the existing ActivityLease recent-success rule, supervisor
enforces its bounded decision and independently rejects >240s. Disconnect
never earns grace. Helper liveness/connection monitoring is cleanup policy,
not trusted progress. This separation must pass existing lease tests unchanged.

## MOUNT_SECURITY

Fixed MODEL, TEST, RESEARCH and PROBE mount recipes, not raw mount options.
Retain model read-only controller/runtime projection and read-only cgroup view;
keep model network transport available to the configured loopback gateway.
Test recipe retains network namespace isolation, private PID/proc, read-only
runtime, bounded tmpfs and disposable test workspace, no host homes/secrets or
controller verification internals. Fixed four device nodes only. Kernel
recursive read-only behavior for nested mounts must be tested; remounting only
the top mount is not assumed sufficient. Propagation is private before binds.

External verification manifest/runner live outside the worker-visible surface.
The unprivileged controller/broker validates the same exact file policy and
identities; privileged setup never treats prompt declarations as mount policy.
Broker-mediated mutations reach only the controller-approved snapshot; model
UID has no direct project-write permissions. Model client executable/runtime
projection must cover real loader, node/client, TLS/DNS and credential transport
needs without mounting the caller's whole home. Compatibility is UNPROVEN until
isolated no-generation fixture tests; do not weaken isolation to make a wrapper
work. Do not expose helper or attribution control socket inside worker mounts.

## CAPABILITY_MODEL

CAP_SYS_ADMIN is broad (namespace/mount administration), not a narrow sandbox
capability. Limit it to fixed setup children; do not place it on a general
interpreter or client executable. Setup additionally needs CAP_SYS_CHROOT,
CAP_SETUID, CAP_SETGID and CAP_CHOWN; CAP_MKNOD only if fixed device creation is
retained. CAP_SETPCAP may be needed for bounding-set drop; CAP_DAC_OVERRIDE is
restricted to helper-owned cleanup, never user snapshot reads. Supervisor may
need CAP_KILL for cross-UID direct signaling; owned cgroup.kill is the primary
whole-tree primitive. No network-admin, ptrace or arbitrary resource-raising
capability is justified by inspected code. A final minimum set is contingent on
syscall/parity tests; do not declare exact operational capability sufficiency
from this design alone.

Before any user/runtime/model/test code: clear supplementary groups, set fixed
per-run GID/UID, clear permitted/effective/inheritable/ambient capabilities,
drop bounding set, set securebits/no_new_privs, verify identity and masks,
close privileged FDs, apply rlimits, then exec. No UID 0 model process allowed.
No credential/environment handling in privileged code beyond opaque bounded
channel forwarding; unprivileged adapter agent applies explicit allowlist.
Reject LD_PRELOAD/LD_LIBRARY_PATH, PYTHONPATH/PYTHONHOME, BASH_ENV/ENV and
unregistered executable search paths for trusted processes. Do not inherit the
root daemon's environment into workers. Provider credentials and attribution
transport values are ephemeral worker-only inputs, never RPC metadata/logs.

## INSTALLATION_MODEL

Separate explicit administrator-approved installation, never Stage 3.0D default.
Future command names are undecided. Admin installs reviewed pinned helper and
registry under root-owned directories, executable 0755 without setuid, private
registry 0600, service definitions 0644 and root-owned parent directories.
No user-writable interpreter, library or upgrade path may enter privileged TCB.
User bootstrap does not install services, create identities or alter cgroups.

Root-owned socket directory 0750 and socket 0660 restricted to enrolled access
group; SO_PEERCRED and enrollment UID/GID checked on every connection. Separate
per-controller random >=256-bit token plus nonce/version handshake, retained
in private 0700 runtime dir/0600 file or controller FD; bind session to connection
and kernel peer. Validate daemon UID 0 on client side. Tokens are additional
authentication, not route/session IDs and not defense against the same UID.
Prevent worker UID/group membership in access group. Revocation disables
admission and terminates that enrollment's active runs. Group membership alone
does not permit arbitrary operations. Never chmod 777 or add sudoers wildcards.

## VERSION_COMPATIBILITY

HELLO reports fixed helper build ID, protocol major/minor, policy digest and
supported fixed features. Controller declares exact supported major and
required features; reject unsupported major, missing features or policy hash
mismatch before CREATE. Initial v1 requires matched tested controller/helper
build pair; no permissive downgrade. Upgrade is explicit/admin-owned, drains
active runs or terminates them with confirmed cleanup before replacement.
Doctor reports installed/authorized/compatible separately from active proof.

## FAILURE_MODEL

| Event | Fail-closed response |
| --- | --- |
| Missing helper, enrollment or capability | Block before worker spawn; no direct-root or weaker backend fallback |
| Malformed/oversized RPC, unauthorized peer, replay, stale handle | Reject/close; do not operate on filesystem/PIDs; admission rate bounds |
| Protocol/build/policy mismatch | Reject before CREATE; no implicit downgrade |
| Setup partially fails | Kill/reap owned children; tear down only pinned created artifacts; CLEANUP_UNPROVEN if any step fails |
| Worker exits/crashes/times out | Preserve safe result/resource evidence, scoped termination/reaping, no automatic retry |
| Controller disappears/socket closes | Stop owning session's workers, collect safe final evidence/tombstone; no lease extension |
| Helper/supervisor crash | Service restart supervisor reaps registered scoped runs before admission; never assume init death killed all descendants |
| Host reboot | Volatile mounts/processes gone; validate boot ID, remove only proven helper-owned stale metadata; no previous-run capability reuse |
| Partial cleanup/stale mount or scope | Quarantine that run, deny UID reuse/new admission where isolation cannot be proven; no broad host scanner |

## CRASH_CLEANUP

Service lifecycle uses its own delegated subtree and kernel membership evidence.
Service teardown must kill the entire service-owned delegated subtree (the
future service must qualify control-group kill behavior, not just main-PID
termination). A supervised watchdog enforces restart/admission fencing. If
service-manager-wide failure can leave live workers beyond their hard cap,
qualification fails; a working service supervisor is a prerequisite, not an
optional convenience. No claim that a daemon's finally block survives SIGKILL.
A root-private bounded journal records boot ID, helper-generated run handles,
owned cgroup identity and setup phase before spawn; no credentials/user paths.
Startup GC touches only registry/journal-owned subtree and private roots,
validates FD identities, performs cgroup.kill and waits for populated=0/reaping,
then unmounts private namespace targets and removes scope/tree. No glob matching
all /tmp or host cgroups. Unknown artifacts are quarantined, not deleted.

Per-run namespace init reaps children. Supervisor watches pidfds, connection
EOF and monotonic deadline, with bounded IPC inactivity detection for abandoned
sessions. Parent-death signaling is supplemental; delayed cleanup cannot be
reported CONFIRMED. Test idle/daemon crash/restart and repeated release; persist
safe tombstones briefly for idempotency, bounded TTL/storage. Attribution
finish/retrieval remains in unprivileged common run_worker lifecycle after
worker cleanup; helper cannot manufacture ROUTER_DISPATCH or served identity.

## DOCTOR_INTEGRATION

Read-only default doctor: helper binary/parent ownership and mode, service/socket
presence and mode, authenticated no-spawn HELLO, protocol/build/policy match,
enrollment and delegation visibility. No model requests or implicit setup.
Explicit future `doctor --isolation-probe` (name provisional) may invoke only
fixed PROBE, creating/removing a scoped sandbox. It must report mutations and
cleanup separately from default doctor. Probe tests network denial, private
mount/PID/proc behavior, non-root UID/caps, read-only controller/cgroup surfaces,
resource enforcement and scoped cgroup.kill, and malicious filesystem fixtures.
Only successful parity evidence may replace active UNPROVEN warnings. A healthy
socket/version handshake alone never proves sandbox or cgroup enforcement.

## WSL2_NOTES

Observed kernel: `6.6.87.2-microsoft-standard-WSL2`; current root development
path has prior qualified behavior, not qualification of this new daemon.
Native Ubuntu 24.04 and WSL2 are separate test targets. WSL2 service-manager
availability, delegated controllers, cgroup.kill, user namespace policy,
openat2/pidfd/clone3 support and shutdown behavior must be proved. Require the
service-manager/delegation prerequisites; no insecure WSL-only fallback.
Keep helper state/runtime on the Linux filesystem, not shared Windows mounts.
Windows-host administrator/kernel compromise is outside this boundary. WSL2
support is PARTIAL/design-only until explicit isolated validation.

## THREAT_MODEL

| Attack | Current exposure | Proposed defense | Remaining risk |
| --- | --- | --- | --- |
| Malicious repository | Target code runs inside test jail; hostile paths supplied to copier | Caller-privilege copy-in, bounded FD-safe snapshot; no root Git/hooks | Kernel/runtime bugs, denial of service within bounds |
| Repository prompt injection | Models consume sanitized but untrusted context | No model RPC channel; sealed policy/typed controller selections | Controller/model may make poor permitted edits |
| Malicious model output | Tool requests and stream parser attacker input | Isolated unprivileged model/broker agents, caps dropped, helper handles only fixed metadata | Agent/parser bugs must not cross UID boundary |
| Hostile tool args | Broker validates paths/content | Existing exact policy unchanged; helper never accepts tool strings | Broker implementation remains TCB |
| Other local user | Shared kernel/filesystem | Root-owned registry, socket ACL/SO_PEERCRED, per-enrollment auth, private roots | Privileged host administrators outside threat boundary |
| Another same-UID process | Can often read controller memory/files and impersonate it | Distinct worker/broker UIDs, no helper arbitrary authority; scoped ownership | Controller-account compromise cannot be cryptographically excluded |
| Stale controller | Old policy/handle reuse | Build/policy handshake, connection-bound handles, sequence/replay checks | Authorized stale client can cause bounded admission failures |
| Symlink/TOCTOU | Mutable source files/directories | openat2 anchor FDs, unprivileged snapshot, identity checks, no raw path mounts | Race detection may deny legitimate concurrent editing |
| PID reuse | Current supervisor uses internal numeric IDs | Helper-created pidfds/cgroup handles, no public PID API | pidfd direct process is not whole-tree containment |
| Protocol downgrade | Future older helper could accept less restrictive rules | Exact major/build/policy match, no fallback | Admin may install an unsafe version deliberately |
| Helper version mismatch | Different enforcement copies | Fail before CREATE; explicit upgrade/drain | Installer/version implementation needs audit |
| Oversized/malformed RPC | New privileged parser exposure | Fixed schemas, message/FD/count/deadline/rate bounds; no raw exception logs | Native parser defects remain serious |
| Cgroup escape | Worker may attempt migration or scope deletion | No writable cgroup/ancestor view; fixed service-owned scope and membership before exec | Kernel exploit/host admin mutation |
| Mount escape | Malicious source submount, cwd/FD outside root | Fixed copied roots, private propagation, nested read-only proof, close FDs | Loader/runtime dependencies require careful projection |
| Env injection | Current attribution starts from os.environ copy | Clean trusted helper environment; unprivileged explicit allowlist; no user interpreter as root | User runtime can intentionally misuse its own granted credentials |

Security objective: the model requests work; deterministic unprivileged
controller decides policy; helper enforces narrow approved isolation. Helper
never interprets model intent. Non-root inference must not be confused with
full kernel-exploit containment or protection from the controller account owner.

## STAGE31B_IMPLEMENTATION_PLAN

1. Implement bounded pure protocol/state/policy tests first, reject arbitrary
   exec/path/PID/mount/environment fields. Separate privileged operations from
   unprivileged task/broker processing; no production backend switch.
2. Implement root-owned supervisor in isolated development deployment with
   exact enrollment/peer checks, FD handling, identities and scope setup.
   Do not load source checkout/user venv while privileged.
3. Prove path-race, hardlink, malicious runtime, FD leakage, cross-UID/model RPC,
   PID reuse, cgroup escape, nested mounts, protocol/version/overflow and crash
   cleanup tests using synthetic processes only. Explicitly validate capability
   masks and no UID 0 untrusted exec at every error path.
4. Adapt common run_worker/run_isolated through a single authenticated client;
   preserve existing evidence validators, lease, broker caps, attribution finish
   and repair policy. Real direct-root execution remains unchanged until parity
   is proved and an explicit transition is approved; no silent backend fallback.
5. Validate native Ubuntu and WSL2 separately, including service restart/reboot
   semantics. Keep incomplete support blocked; document least privileges from
   actual syscall evidence. No model required for initial security validation.
6. Design separately approved administrator installation/upgrade/revocation,
   then doctor handshake and explicit fixed no-model probe. Only after tests and
   review permit a production integration transition, not in Stage 3.1A.

### Static design review checklist

PASS (design constraints, not executable enforcement): no public raw command,
PID, mount pair, chown target or cgroup config; exact operation/role/policy enums;
no model-to-helper transport; only registered FD-rooted snapshots/runtimes;
peer credentials plus enrollment/token; version/build/policy match; bounded
requests; supervisor-owned process/cgroup/mount handles and cleanup; no root
model; grace only from isolated broker success; no requested/routed/served
identity conflation. Remaining proof gates are explicitly in Stage 3.1B.

### Kernel reference basis

[cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html):
delegation is constrained by controller availability and hierarchy rules;
cgroup membership is not an arbitrary kill handle. Design requires verified
owned scope controls and emptiness before removal.
[openat2 manual](https://man7.org/linux/man-pages/man2/openat2.2.html) documents
FD-rooted resolution constraints; these supplement rather than replace snapshot
identity validation.
[pidfd_open manual](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
documents process-handle semantics; it does not provide descendant containment.
[user namespaces manual](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
describes namespace-scoped capabilities, not a guarantee that host cgroup
permissions or distribution policy allow full rootless parity.
