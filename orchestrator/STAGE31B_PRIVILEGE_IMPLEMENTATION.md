# Stage 3.1B — privilege protocol and supervisor, simulation only

Parent: `97253342de0433d5c1202bfeaebcf1433d076a54`.
This is a non-installed development implementation. No privileged backend,
service entrypoint, cgroup/mount operation, sudo integration or production
cutover exists. No model/client/provider is executed by this package. Doctor
continues to report active isolation as unproven. Existing run_worker,
run_isolated, broker, model profiles, attribution and bootstrap are unchanged.

## Modules

- `protocol.py`: strict versioned JSON, bounded length-prefixed Unix framing,
  fixed error vocabulary and exact request/response envelopes.
- `security.py`: enrollment, SO_PEERCRED, private token API, socket modes and
  registered directory FD anchors; no project path in an RPC.
- `policy.py`: immutable execution classes/recipes and resource ceilings, clean
  synthetic environment, canonical SHA256 policy compatibility identity.
- `backend.py`: fake resource ownership and ordered operations; explicit optional
  harmless fixed Python process fixture with literal argv and pidfd mechanics.
- `journal.py`: private atomic bounded ownership journal and strict recovery input.
- `supervisor.py`: connection-owned state machine, admission, dispatch, recovery
  and temporary authenticated local transport fixture. No executable daemon.
- `client.py`: typed unprivileged controller integration seam. No public raw RPC.

The Python package is included in project metadata for user-space installation.
This does not install a privileged component. Future privilege installation
must use reviewed root-owned code/interpreter/dependencies, never the user's
venv or checkout as a privileged import/exec source. No compiled component is
introduced; selecting a real setup implementation remains a Stage 3.1C gate.

## Protocol v1

AF_UNIX SOCK_STREAM only. Each record is a 4-byte unsigned big-endian byte length
followed by exactly that many UTF-8 JSON bytes. Maximum frame 16,384 bytes,
string value 256 UTF-8 bytes, key 64 bytes, object/list count 32, nesting depth 4,
nonnegative integer <=2^63-1. Strict versions/sequences reject bool-as-int,
unknown fields/operations, duplicate JSON keys, malformed/nonfinite data and
trailing JSON. No pickle, code evaluation, arbitrary object decoding or TCP.
Read deadlines cover the entire header/body, not an indefinitely reset
per-byte timeout. Connect/write/read use bounded 1-second fixture deadlines.
EOF/error closes the connection and cleans its authenticated owned resources.

Request: `{version:1, seq:N, op:<enum>, args:<exact schema>}`.
Response: `{version:1, seq:N, code:<fixed code>, data:<validated object>}`.
Error data must be empty. Responses cannot echo input, exceptions or credentials.
The client validates both envelope and operation-specific successful data.

| Operation | Exact args | Effect |
| --- | --- | --- |
| HELLO | enrollment, token, challenge, build, policy | First request, seq 1; authenticate connection and pin compatibility |
| CREATE | run_id, slot, class, role, limits | Register durable ownership intent, fake namespace/recipe/scope creation |
| START | handle | Start only the predefined synthetic class implementation; once |
| STATUS | handle | Fixed safe snapshot; detect direct synthetic child exit |
| TERMINATE | handle | Terminate owned synthetic process/scope, no caller PID/signal |
| RELEASE | handle | Terminate if necessary, cleanup ownership ledger; idempotent tombstone |
| PROBE | probe=BOUNDARY_V1 | Explicit SIMULATED/UNPROVEN fixture observation, not active proof |

There are no argv, executable, env, path, mount, cgroup name, UID-selection,
PID, shell, provider or prompt fields. Such fields are rejected. Socket location,
enrollment and root registration are trusted in-process fixture construction
inputs, not configuration accepted from the model or public RPC.
The low-level client `_rpc` is private and used only by the typed client and
adversarial tests. Production model/tool modules neither import nor invoke the
privilege package. No prompt/task parameter can select a run ID.

SCM_RIGHTS delivery channels from the design are deliberately not enabled.
The current stream transport never requests ancillary data, inherits no such
FDs into synthetic workers, and accepts only named pre-registered slots. Safe
production FD provisioning and role/model task delivery require separately
reviewed implementation; inventing a mount/path RPC to bypass this is forbidden.

## Authentication and ownership

Server validates real SO_PEERCRED UID/GID against one immutable Enrollment.
Enrollment ID is a random 128-bit identifier; token is separate random 256-bit
material (constant-time comparison, excluded from repr/logs). Server sends a
fresh 128-bit challenge, required in the first HELLO. Each connection gets a
new private ownership ID; subsequent strict increasing sequences prevent
replay on that connection. No session takeover, ownership transfer or reattach
API exists. Second authenticated connection cannot control the first's handles.

Client validates the socket's pinned parent traversal, Unix type, owner/group,
0600 mode and 0700 parent for fixture use, then checks server SO_PEERCRED.
Security utility also models the future restricted-group 0750/0660 filesystem
profile; current LocalServer uses private same-user fixtures only. Production
root enrollment, group management and installation are not performed.
Filesystem/token checks are not proof that same-UID code is honest. Account
compromise remains the explicit Stage 3.1A residual risk. Distinct production
model/broker/controller UIDs are mandatory future validation, not simulated
proof. No root model is ever launched; optional fixed Python fixtures may run
under the test runner's UID and make no privileged or inference calls.

Token storage API creates a single exclusive 0600 O_NOFOLLOW file in an existing
owned 0700 directory, fsyncs and closes it. Existing files are never overwritten.
Reads require owner, mode, regular single-link file and strict token length.
Only temporary test tokens are created here. No installation token, credential
migration, token hash/prefix in telemetry or environment dump exists.

## Policy and execution classes

Security policy identity uses canonical sorted JSON SHA256 over version/build,
operation/state enums, authentication properties, transport/journal bounds,
class roles, executable/argv/cwd rules, filesystem recipes, identity classes,
resource ceilings, clean environment, exact-relative/no-symlink/single-link
rules, 180+60/240 lease constants and 8/8/4 file/target and 2-repair caps.
Policy literal values are derived from existing production policy assignments
using AST parsing of known constants, without importing/executing runtime code.
`ast.literal_eval` is restricted to dictionary-key literals; there is no eval
or exec of input. Future privileged installation must use root-owned copies.
Admission rejects build or policy mismatch; journal pins the admitted digest.

| Class | Roles | Rules |
| --- | --- | --- |
| MODEL_WORKER | planner, coder, fixer, reviewer | Registered adapter after privilege drop; structured adapter argv; sealed workspace; MODEL recipe/identity; existing WORKER_POLICY ceilings |
| DETERMINISTIC_TESTER | tester | Fixed verification runner/entry; disposable test copy; TEST recipe/identity; existing RESOURCE_POLICY ceilings |
| RESEARCH_HELPER | four existing research action roles | Fixed research action, validated action argv, registered runtime; RESEARCH recipe/identity; existing RESEARCH_POLICY ceilings |

These are immutable descriptors and validators, not production launch recipes
that have been proven to work. START has no arbitrary command args. FakeBackend
records namespace/rootfs/mount recipe/cgroup/identity steps. Optional
SyntheticProcessBackend executes only one hardcoded `python -I -c` fixture
using sys.executable, no shell, close_fds=True, no privileged directory FD,
DEVNULL stdin/stderr, and fixed clean environment. Its constructor-only literal
argument list exercises spaces, quotes, semicolons, substitution strings,
backticks and newlines, which are never interpreted as shell syntax. These
fixture values never enter RPC/journal/supervisor logs. No user command code
or caller environment is passed to that child.

Environment for synthetic children is limited to fixed PATH=/usr/bin:/bin,
HOME=/nonexistent, LANG=C.UTF-8 and PYTHONDONTWRITEBYTECODE=1. Caller variables,
including loader/Python/shell injection variables and provider secrets, are
stripped. RPC has no environment field. Production credential/task transport
and its allowlist must be implemented only in the unprivileged execution agent,
not by adding raw environments to the privileged parser.

Resource overrides may lower positive limits only; unknown fields, booleans,
negative/zero invalid values, overflow or above-ceiling values fail. Schema,
CPU period, swap and termination grace fields are fixed. No resource ceiling
or production lease is changed. Fake limits are recorded, not kernel-enforced.
ActivityLease/grace arbitration and real hard-deadline supervision are not
implemented by fake progress events and remain Stage 3.1C integration gates.
No RPC can request grace or turn process/connection activity into trusted broker
success. Production lease behavior remains in the unchanged production path.

## Paths, FDs and process handles

Registered roots are constructor/admin-owned slots, capped at 16. Walk absolute
anchor components with directory FDs, O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC, reject
aliases and traversal, require final owned 0700 directory. Reopen and compare
saved device/inode before using a slot; replaced workspace root fails closed.
For simulation regular-file checks, walk components using pinned FDs, reject
symlinks, aliases, absolute names, special files and multiple hard links.
All opened root/file FDs are explicitly closed and never passed to workers.

This is not an openat2 implementation or a claim that FD walking alone freezes
an attacker-mutated subtree. There is no privileged mount/copy backend to fall
back to realpath. Stage 3.1C must prove caller-privilege ingestion, sealed snapshot
copying, openat2/identity safety and race-resistant mount projection before any
privileged backend can be enabled. `Supervisor` rejects all backend types other
than the two explicit synthetic classes; there is no weak kernel fallback.

Public Sandbox carries an opaque helper-generated 128-bit handle. Client tracks
its own handles; supervisor checks connection/UID/GID ownership independently.
Run IDs are independently minted inside create_sandbox; no run_id argument is
exposed. Handle collisions are rejected, never overwrite ownership. No raw PID
is accepted or journaled. ProcessHandle wraps only the fixture's owned Popen and
pidfd where supported. pidfd signaling is preferred; unreaped owned direct-child
Popen fallback is for fixtures only and is not proof of descendant containment.
Cleanup closes pidfds and stdio. Fake cgroups/namespaces are bounded ledger
entries, not actual kernel handles. No worker inherits privileged FDs.

## Lifecycle, journal and recovery

States: CREATING -> CREATED -> RUNNING -> TERMINATING -> TERMINATED -> RELEASED.
Natural child exit can move RUNNING to TERMINATED. RELEASE terminates first when
needed. Failures yield FAILED_DIRTY; START/reuse is blocked, only cleanup/recovery
is permitted. RELEASE is idempotent after success. Unknown/cross-connection
handles fail. Admission is fenced while recovery is required.

Private journal has version, policy digest and exact records containing only
handle/run/connection IDs, enrollment UID/GID, backend ownership tag, lifecycle,
class and role. No host/project paths, PID, prompts, output, environment, tokens
or headers. It uses 0600 exclusive staging, fsync, atomic replacement and parent
fsync through a pinned 0700 directory FD. Input is capped at 256 KiB/128 records;
unknown fields, duplicate keys/handles, incorrect policy, bad IDs/classes/modes,
symlink/hardlink and malformed data fail closed before recovery actions.

Ownership intent is saved before fake resource creation. Ordered failure injection
models partial setup/termination/cleanup. Disconnect cleans only that connection's
owned resources. Recovery first validates every pending record against backend
ownership before taking any action; foreign/unknown resources block rather than
scan or infer ownership. Simulated supervisor restart reuses the independently
owned fake ledger and its ownership tag; all resources are cleaned before new
admission. A fresh unrelated fake backend cannot claim the old journal's resources.

A bounded completed-resource tombstone permits retry if physical fake cleanup
succeeded but the final journal write failed. Backend resources absent without
such owned proof cannot be reported cleaned. Cleanup failure retains FAILED_DIRTY
and admission fencing; restoring the backend and retrying recovery is explicit.
No host-wide scan, automatic retry of a workload, stale-PID kill or arbitrary
recursive host cleanup occurs. Real boot/namespace/cgroup recovery ownership,
independent watchdog and hard-cap behavior remain unvalidated until Stage 3.1C.

Bounds: 8 connected clients, 16 active sandboxes globally, 2 per UID, 128 total
journal/tracked handles (including released tombstones), 128 requests per
connection, 32 control requests/second, 256 retained fixed-category log/backend
events. Exhaustion returns fixed rejection; it never allocates an unlimited
registry. Tombstones are not silently evicted to permit run ID reuse. Current
single-enrollment fixture is deliberately smaller than a multi-user service.
Logs contain only fixed operation/code and validated opaque handle or null.
Authentication/parser errors never log raw request bytes or exception text.

## Testing and static security review

The compact PrivilegeCases table is included in existing FoundationTests, keeping
full trusted suite output bounded. It exercises strict HELLO/versions/types and
framing/EOF/deadline; tokens/peers/private storage; paths/symlinks/hardlinks/root
replacement; classes/environment/resource bounds; state/ownership/concurrency;
partial backend and journal failure; disconnect/restart/dirty recovery; temporary
real Unix transport, replay and client exhaustion; literal argv/direct-child
pidfd mechanics; and unchanged production imports/installer/doctor.
No skipped kernel enforcement is advertised as PASS: every successful fake
snapshot/probe says mode=SIMULATED, enforcement=UNPROVEN, and cleanup=SIMULATED
only when the owned fake ledger has been cleaned. It never returns the production
ENFORCED/CONFIRMED resource evidence shape or attribution/model identity fields.

Review the entire package: no shell=True, os.system, dynamic eval/exec, pickle,
unsafe YAML, user-controlled command, raw PID RPC, mount pair, cgroup path,
world-writable socket/state, token log or caller environment forwarding.
Only backend.py contains subprocess launch, a fixed synthetic snippet and owned
Popen operations. Backend methods cannot be selected by untrusted class objects.
No model/tool module imports the client; no direct kernel operation is present.
Python methods are not a sandbox against code already controlling the trusted
process; real UID/FD separation is explicitly deferred, not replaced by naming.

## Stage 3.1C gates

Separately authorize an isolated validation environment; do not install on the
production host by treating this fixture as a ready daemon. Implement and review
root-owned backend/runtime registration, safe FD copy-in/task channels, openat2,
real namespace/mount/chroot/identity/capability drops, cgroup membership barrier,
independent deadlines/lease-agent authentication, real persistent resource
identity/journal recovery, service crash containment and enrollment/revocation.
Prove real enforcement with synthetic processes, malicious filesystem and crash
fixtures on native Ubuntu and WSL2 separately. Keep production execution unchanged
until parity/security review and explicit cutover approval. No model is needed
for initial privilege validation; no privilege installation is done here.

## Verification record

Final focused run: 3 grouped tests in 12.074 seconds, PASS (privilege cases,
foundation including doctor/bootstrap, and existing attribution). The privilege
table has 14 contract groups and is also executed within the foundation table.
Full trusted suite: 518 tests in 237.841 seconds, RESULT=PASS, exit 0. Its existing
production-isolation fixtures remain unchanged; the new backend executes no
real mount/cgroup/namespace operations. Offline wheel build with pinned
setuptools 68.1.2 / wheel 0.42.0 passed and included every privilege module.
The controller runtime venv intentionally lacks build tooling; wheel verification
used the existing disposable pinned build environment instead of mutating it.
Static package inspection and AST checks found no dynamic eval/exec, shell
subprocess, raw PID syscall, privileged kernel call, unsafe decoder or token log.
