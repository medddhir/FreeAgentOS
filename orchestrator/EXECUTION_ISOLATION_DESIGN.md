# Execution isolation design

## Trusted task entrypoint

`bin/freeagent-run --repo /path/to/clean/git/root --task "..."` is the sole
supported user-facing task command. It invokes `orchestrator/cli.py`, which
calls the production LangGraph directly. The retired `freeagent-code` command
exits with an error; historical runner snapshots are non-executable backups
outside `bin`. `freeagent-test` is an internal test runner and does not alone
provide task verification. Model, research, and target workers are internal
components. No CLI flag skips preflight, containment, tests, review, or
integrity checks.

The CLI accepts explicit integrity permissions for new files, deletions, and
test edits. Its input is parsed as data, and the repository must be a clean Git
root. The default output reports final status, trace, source, workspace,
research, changed paths, test and review outcomes, integrity, repair attempts,
and promotion patch. `--json` emits a bounded summary; task text is represented
by a digest and length, and raw model output and environment data are omitted.
Exit codes are 0 VERIFIED, 1 UNVERIFIED, 2 BLOCKED, 3 invalid input, 4
controller failure, 130 SIGINT, and 143 SIGTERM. Only the final graph state can
produce exit 0.

The CLI traps SIGINT and SIGTERM, letting worker launchers kill their process
trees and remove their controller-named cgroup scopes. It then removes only the
active run directory it created. Startup recovery scans a bounded number of
FreeAgentOS-named directories and deletes only empty workspaces with a 0600
controller ownership marker from a dead process. Populated or unproven stale
workspaces are retained for review. VERIFIED patches remain in separate
promotion artifacts; source repositories are never changed automatically.

Planner failures expose fixed error codes and a bounded response shape through
the trusted CLI. The diagnostic records the worker exit, response length,
recognized outer JSON fields, parse state, timeout, truncation, and cleanup
state. It never returns raw model text or provider errors. Invalid structured
output remains blocked, including wrong field types and extra fields. The
retained `result`-field JSON fallback is accepted only when it conforms to the
same Planner schema. The previous live `planner:error` had only generic error
reporting and its cleaned workspace contains no recoverable response.

## Threat model

Target source, prompts, project tests, package scripts and test configuration are
untrusted. They may try to rewrite the controller, forge the test result, read
credentials, modify the source checkout, reach outside the run directory, or
use symlinks and traversal paths, or exhaust CPU, memory, processes, disk and
output. The controller process, its workspace manager, manifest, test runner
and integrity code are trusted. Kernel vulnerabilities and hostile root
operators are out of scope.

## Chosen boundary

Each run receives a private copy under a controller-owned temporary directory.
Dirty source checkouts, included-file symlinks, hard links and special files
block workspace creation. Excluded generated and credential-path directories
are not traversed. The source checkout is never edited by graph nodes. The
snapshot omits VCS internals, virtual environments, generated trees, common
secret/credential paths, private-key/database file types, and files containing
recognized credential material. Coder and Fixer run Claude Code in
`--restricted`/`--bare` mode with only the controller's bounded stdio file tools
and no native file tools, Bash, hooks, project settings, or extra directories.
Their working directory is the run
copy. The verifier and its manifest live in a sibling controller directory
outside that file-tool root. A hash of the workspace's `.git` pointer is in the
external manifest and is checked before verifier Git operations.

Tests run against a second copy. A private mount/network/PID namespace builds a
small chroot with read-only system/runtime mounts, a writable test copy and the
controller-owned `freeagent-test` runner. `/root`, `/home`, `/run` and host
temporary data are absent. The process runs as the unprivileged `nobody` account;
network access is disabled. Namespace or chroot setup failure blocks the run.

The namespace init creates a private cgroup v2 mount and one FreeAgentOS-owned
scope per test execution. The test runner and all descendants join the scope
before execution. The controller gives the namespace a finite lease, sends
SIGTERM to remaining processes, waits one second, then uses `cgroup.kill`.
`unshare --kill-child=SIGKILL` is the outer fail-safe if namespace init itself
dies. A run can verify only after the scope is empty and removed. The outer
launcher has its own emergency timeout and blocks if inner cleanup evidence is
missing. The runner and launcher drain output incrementally into fixed-size
buffers; neither buffers unbounded child output.

## Controller-owned resource policy

The external manifest includes the exact controller resource policy and the
verifier compares it to its compiled policy on every read. Target files cannot
raise limits. Current defaults are: 150-second wall lease, 120 CPU seconds,
50% of one CPU cgroup quota, 512 MiB cgroup memory, no swap, 16 cgroup PIDs,
128 open files, 128 MiB per file, 64 KiB captured output, and a 256 MiB test
workspace tmpfs. Additional writable tmpfs mounts have separate finite sizes.
The copy into the test filesystem is limited to 20,000 files and 192 MiB.
RLIMIT_AS also bounds a single process to 384 MiB. Each successful sandbox
result records enforced controls, timeout, force-kill, resource hits, output
truncation, cleanup status and remaining process count. Missing required cgroup
controls, namespace privileges or cleanup proof block verification; the
controller reports unavailable controls instead of silently running outside
the boundary.

## Verification contract and discovery

The external manifest binds workspace ID, source HEAD and safe source-file
fingerprints, policy flags, verifier source hash, test inventory/config hashes,
test runner hash, and workspace Git baseline. The Tester rechecks the manifest
and control source hashes before and after executing tests. Target-side edits to
test files, runner/configuration, orchestration or policy are denied by the
existing integrity policy and selectively rolled back where safe.

Before planning, the trusted runner executes the baseline suite in the chroot and
records its recognized discovered-test count. Final verification must pass and
must not discover fewer tests. Unrecognized output is recorded as unattested and
cannot produce VERIFIED. This is conservative: test frameworks without a stable
count parser remain unsupported until a deterministic adapter is added. Test
file and test-configuration inventories are also hashed and compared, so the
count is a secondary signal rather than the only discovery control. The count
comes from the final recognized framework summary; a hostile test process can
still print misleading output, so this does not claim framework-independent
proof of test execution.

## Patch and promotion

No graph node applies changes to the source checkout. VERIFIED runs produce a
patch and per-path source-baseline metadata in a separate artifact directory.
The artifact is promotion-ready only when the source HEAD and captured safe-file
inventory still match. A later promotion command must check those hashes and
`git apply --check`; it must stop on drift or conflicts. Promotion is a separate
explicit action and is not part of this milestone.

## Host prerequisites and limits

The selected design requires `unshare`, `mount`, `chroot`, a working mount and
network namespace, writable private cgroup v2 mount with memory, PID and CPU
controllers, `cgroup.kill`, and permission to run the isolated test process as `nobody`.
It fails closed when any prerequisite is missing. Dependencies not included in
the safe run snapshot may make a target suite unavailable; no network is exposed
to target tests. This boundary is not a general container runtime or a defense
against kernel exploits.

The production graph returns no changes to the source automatically. A
promotion artifact includes the source HEAD, a safe-file inventory digest, a
patch digest and the changed paths. Regression tests check the artifact against
the source with `git apply --check`. Dirty source trees are blocked so the
artifact has an unambiguous base. Promotion still requires a separate explicit
operation.

## Verification record

On 2026-09-28, the isolation baseline `freeagent-test` ran 81 deterministic tests and returned
`RESULT=PASS`, exit code 0. The production graph suite covers normal coding,
calculator, repair, API grounding and rollback flows. Isolation attacks cover
controller and manifest writes, workspace traversal and symlink escapes,
network access, verifier replacement, test/config tampering, test deletion,
workspace Git-pointer replacement, secret-file exclusion, and cleanup. A live
provider was not called for this milestone.

The resource milestone subsequently ran 95 deterministic tests successfully,
including infinite loops, ignored SIGTERM, background and multilevel
descendants, PID explosion, memory pressure, output flood, file descriptor
exhaustion, file size and tmpfs growth. A live provider was not called.

## Host preflight and model workers

After workspace preparation, the graph runs a deterministic host preflight
before baseline tests, Inspector, Planner, or any model-driven edit. It checks
Linux, required binaries, cgroup v2 controllers, and then exercises the exact
target sandbox and model-worker scope with tiny trusted fixtures. Required
failures route directly to the finalizer with BLOCKED status. The preflight
packet is written outside the workspace with mode 0600 and its hash is checked
before model execution and verification. The manifest binds the required
capability list and both resource policies; a mismatch blocks the run.

Planner, Coder, Fixer and Reviewer now launch the model CLI through a reusable
worker runner. The orchestrator stays outside the worker cgroup. Each call gets
a private mount/PID namespace and a FreeAgentOS-owned cgroup v2 scope. The
worker retains network access for the configured model gateway; Coder/Fixer
retain their existing restricted file tools and no shell access. The worker
child sees the cgroup mount read-only in a nested mount namespace and executes
with an empty capability bounding set and no-new-privileges. A deterministic
fixture verifies it cannot rewrite `cgroup.procs` or its own limits. The worker
also sees the FreeAgentOS controller tree through a read-only bind mount, while
the isolated target workspace remains writable for the restricted file tools.
An adversarial fixture checks that opening the controller resource policy for
writing fails inside the worker. The worker scope limits wall time to the
role's existing timeout (maximum 240 seconds),
CPU to one core and 180 CPU seconds, memory to 1536 MiB with no swap, PIDs to
64, open files to 256, file size to 128 MiB, and captured output to 256 KiB.
It sends SIGTERM then `cgroup.kill`, verifies zero remaining processes, and
returns machine-readable cleanup and resource evidence. A missing or uncertain
boundary blocks model execution. Fixer attempts remain capped at two.

## Execution classes

Model workers (Planner, Coder, Fixer, Reviewer) use the controller-owned model
cgroup policy. They retain access to the local model gateway, have read-only
access to the controller tree, and return bounded output and cleanup evidence.

Research workers use the same scoped runner with a separate 60-second maximum
policy: one CPU core, 50 CPU seconds, 1024 MiB memory, no swap, 32 processes,
128 file descriptors, 64 MiB file size, and 512 KiB total captured output.
Network access remains available for Exa and Jina. Only exact controller-owned
`exa-intel`, `dev-intel`, and `prompt-intel` actions and the fixed HTTPS Jina
curl action can be dispatched. Output streams share a fixed capture budget;
overflow, timeout, resource hits, or unproven cleanup block research. The
external manifest binds this policy and the three controller-owned scripts.

Target workers execute tests and builds in the separate unprivileged,
networkless namespace sandbox with its existing 512 MiB/16 PID policy. Target
output, resource events, and process cleanup are externally verified before
the graph can report VERIFIED.

Controller-only Git metadata, snapshot, integrity, and patch commands use a
fixed `/usr/bin/git` launcher with no shell, a 64 MiB streaming output ceiling,
finite timeouts, process-group cleanup, disabled hooks/fsmonitor, and no global
Git configuration. These calls never accept a model-selected executable; path
arguments are passed as literal pathspecs where relevant. The production
subprocess audit leaves only this launcher and the proven model/target scope
launchers as direct `Popen` sites.

## Model-worker timing observations

The model-worker controller measures scope setup, process spawn, process
runtime, cleanup, total elapsed time, and each output stream's first byte with
monotonic clocks. Stream byte counts and a bounded output capture distinguish
`PROCESS_STARTED_NO_OUTPUT`, `STDERR_BEFORE_STDOUT`,
`FIRST_OUTPUT_BEFORE_TIMEOUT`, and `NORMAL_COMPLETE`. A failed launch reports
`PROCESS_NEVER_STARTED`. The graph also records bounded elapsed time for each
role. CLI JSON and human output include only allowlisted numeric, boolean, and
fixed-category evidence; model responses and environment values are omitted.

Immediately before a production `claude-free` call, the controller makes an
optional unauthenticated loopback `GET /health` with a 750 ms deadline. The
probe sends no model request and does not affect execution success. A healthy
local gateway proves only that the health endpoint answered; it does not prove
the model request arrived or identify upstream latency. No safe request-arrival
event is currently available to the controller, so this field reports
`UNAVAILABLE` rather than inferring an upstream failure.

## Stage 1 bounded coding units

The existing Planner still makes one structured call and returns at most five
steps plus one to three explicit coding units. Each strict unit contains a goal
and target files; numeric step mappings are not part of the production contract.
The current unit goal defines its implementation objective, and every Coder
receives the full bounded plan as supporting context. Stage 1.1 prose compaction remains only for legacy
deterministic fixtures; production Planner output must contain explicit units.
There is no additional planning model. Each unit gets a fresh
existing 180-second Coder worker lease; research runs once and its packet is
reused. The Coder receives Inspector's bounded repository facts and at most
24 KiB of local context read through Inspector's safe regular-file reader.
Each explicit unit may hint at up to four normalized implementation paths.
The controller validates tracked targets or authorized new source paths before
Coder starts. Targets are context hints, never permissions. Safe current
workspace contents of target files precede related Inspector files in context;
oversized content is marked incomplete. Numeric prompt/context counts are
recorded without retaining raw prompt or source text in diagnostics.
Obvious secret paths and contents are excluded. Restricted file tools remain
available for additional inspection.
Injected context also skips data, fixture, upload, and generated source paths
and files marked as generated. This filtering limits prompt exposure; it is
was not a complete workspace secret boundary while native Read, Glob, and Grep
remained available. Stage 1.5 below replaces that tool surface with explicit
controller-owned read capabilities. Content filtering remains heuristic.

The existing isolated Tester runs after every unit. Standard unittest or
pytest summaries yield a numeric failure/error count. An intermediate unit
may continue only if its count does not increase, its test discovery and
integrity evidence remain valid, and any explicit user-owned path restriction
passes. Unknown counts block continuation. Planner steps can identify relevant
files for context, but cannot create an exclusive path allowlist. Without an
explicit user restriction, the existing global integrity policy applies.
Per-unit path fingerprints distinguish new edits from prior unit changes;
they are evidence only, not restorable checkpoints. The final unit follows
the normal Tester and one final Reviewer. A rejected final review ends
UNVERIFIED because a repair could not be promoted without a second review.
Tester-driven Fixer attempts remain globally capped at two. No partial set
of units can become VERIFIED.
Controller guards reject more than three supplied units and a third direct
Fixer attempt. Integrity and sandbox failures take precedence over a PASS
test marker, so intermediate failures cannot reach Reviewer. Reviewer checks
machine evidence before its model call, and Finalizer checks complete unit,
test, integrity, discovery, and sandbox evidence before promotion. The
controller manifest now binds the unit-derivation module as well.

A separate global run deadline is deferred. A 900-second ceiling could expire
while the current independently bounded Planner, three Coders, two Fixers,
Tester calls, and final Reviewer are all legitimately running. This stage
retains the established per-worker leases and cleanup rules.

The installed Claude Code help documents `--output-format stream-json` for
`--print`, with optional partial message events. Coder still uses its current
single final stdout mode. A future progress-only adapter would incrementally
parse bounded NDJSON records, retain allowlisted event types, monotonic event
times and coarse tool categories, and discard tool arguments, source text,
model messages, and raw events immediately. It must identify a final result
separately and preserve bounded streaming, cgroup cleanup, and fail-closed
parse behavior before production adoption. No streaming switch is part of
Stage 1.3.


### Stage 1.4: bounded evidence-driven repair

Fixer keeps its restricted file tools, 180-second lease and two-attempt global
cap. Before a worker starts, the controller verifies the execution contract and
builds a repair packet from current Git evidence and completed unit history.
It includes the baseline and per-unit failure counts, bounded unittest/pytest
failure identifiers (24 identifiers, 180 characters each), exception categories,
and at most 4 KiB of sanitized secondary test output. Unknown formats remain
UNKNOWN; identifiers are diagnostic data and never select files or grant access.
The structured packet has an independent 8 KiB ceiling. Tester extracts this
evidence before trimming human diagnostics: the scan is limited to 64 KiB
(the sandbox capture ceiling), 4096 lines and 2048 characters per line. Cut
records, control characters and ambiguous parameter values never become test
identifiers. Identifier characters are ASCII, so the 180-character limit also
limits bytes. Incomplete scans are reported, not presented as complete evidence.

Current changed implementation files take priority over completed-unit targets
and related Inspector files. The unchanged context reader enforces eight files,
8 KiB per file and 24 KiB aggregate, with no-follow, single-link regular-file
checks and existing secret/data/generated exclusions. Authorized new files
require controller policy and current Git provenance. A separately bounded
8 KiB cumulative implementation diff compares safe current files to HEAD;
omitted/truncated files are reported. After rollback it describes current files,
while test evidence explicitly refers to the latest execution. This filtering
alone did not enforce the native Read/Glob/Grep boundary. Stage 1.5 applies the
same path and content exclusions to the replacement file tools.
Controller-authorized deleted files are identified separately, with no stale
baseline contents injected or automatic recreation. Unauthorized deletion blocks
context construction. A deleted README is omitted by the repair reader; the
shared Coder reader's default behavior is unchanged.

Only numeric context metrics and the attempt number enter CLI resource evidence.
Prompts, source contents, test payloads and diffs are not added to CLI diagnostics.
Final repair Tester checkpoints reuse the existing change-count, fingerprint,
enforced-file and global integrity gates. A repair record updates final machine
history and carries the Fixer attempt identity, so a successful repair can reach
the sole final Reviewer. It does not erase previous unit failure progression.
No Planner, Coder decomposition, model policy or streaming behavior changes. Safe
streaming activity telemetry remains a later option if targeted repair context
proves insufficient in a normal-WSL live evaluation.

### Stage 1.5: file-tool read policy and read-surface hardening

The source audit identified the following production read surfaces before
implementation. This classification separates trusted verification/runtime
reads from data that is exposed to model workers; no ambiguous production
filesystem adapter was found.

| Class | Existing boundary | Authorization and treatment |
| --- | --- | --- |
| Controller-only trusted reads | `cli._repo`, `workspace._inventory`, manifest/controller hashing and cleanup, `integrity` Git/fingerprint/rollback, preflight and sandbox/worker cgroup/proc metadata | Controller-selected inputs; not worker tools. Existing identity, fingerprint, output, regular-file and isolation checks remain. |
| Worker-requested reads | Coder/Fixer native Read/Glob/Grep, and Edit's implicit file reads | Removed. Five controller stdio tools now use the same exact file capabilities; native tools cannot provide a second path. |
| Automatically constructed context | `coding_units.local_context_packet`, `repair_context.repair_packet/_diff`, Planner Inspector facts, Reviewer evidence | Shared read exclusions on source context; bounded current workspace contents and diff retained. Reviewer test/diff excerpts are sanitized. No prior Coder transcripts. |
| Controller Inspector | Tracked path discovery and `_read`, dependency/source metadata extraction | Broader filtered tracked-file visibility, including public tests and dependency manifests. Data/generated/runtime paths are excluded before enumeration. Manifests go only to the existing allowlisted metadata parser; auth URLs yield empty versions, never raw context. |
| Verification/test infrastructure | Tester discovery, protected tests/configuration, fingerprints, isolated test copy and `bin/freeagent-test` | This must read verification inputs and execute tests. It remains controller-owned and uses the existing networkless unprivileged target sandbox, not the model file capability list. Historical smoke scripts are not model tools or the production entrypoint. |
| External research input | `research_execution` fixed binary dispatch, `dev-intel`/`prompt-intel` constant public indexes, Exa/Jina response streams | Existing bounded research runner and evidence validator. Research output and failure strings never select authorized local paths. |

`read_policy.py` builds a separate, sealed capability list for each Coder or
Fixer call. Coder candidates are validated unit hints and related Inspector
files; Fixer candidates come from the existing current Git/repair constructor.
Tracked provenance is mandatory for existing files; new files require the
controller's literal new-file permission and an explicit unit path or current
controller-observed repair provenance. Failure text and model transcripts are
not inputs. Up to eight safe files, including README when space permits, can
be authorized per call. An existing source outside this list stays unreadable.
Protected tests require explicit controller test-change permission; verification
internals remain inaccessible to file tools even when that change flag exists.
Dependency facts reach workers through Inspector rather than raw manifests.

The shared layer reuses Inspector path rules, secret/generated exclusions,
file classifications, current Git evidence and the fd-relative no-follow reader.
It checks membership before opening contents. Every component is opened without
following symlinks; final files must be single-link regular files, and root
device/inode identity is bound at policy construction. Control/non-ASCII paths,
noncanonical paths, traversal, host paths, special files, credential stores,
databases and generated/data/upload/fixture directories are denied. Current
contents are screened again on every read, including enumeration and Edit's
implicit reads. Authorized deletions do not inject baseline contents or permit
automatic recreation. Authorized new files become readable after safe creation.

`file_tools.py` exposes only read_file, glob_files, grep_files, edit_file and
write_file over bounded newline-delimited JSON-RPC stdio. The transport follows
the [MCP stdio specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
and its initialization/tools lifecycle. Read returns at most 8 KiB per chunk;
the safe reader's existing 64 KiB file ceiling remains. Glob matches only the
capability list, never walks the repository. Grep is a literal substring search
only within authorized files. Search returns at most 64 records and a bounded
8 KiB packet. The session caps tool calls at 128 and successful returned data
at 256 KiB; incoming records are capped at 64 KiB. Oversized records close the
channel, and denied operations return only fixed codes, with no attempted path,
file contents or exception text. Atomic no-follow writes reuse the same path
capabilities; they do not replace the existing post-edit integrity gates.

Coder/Fixer explicitly configure this single server with a hashed policy in
controller-constructed arguments. The tools cannot edit its configuration or
controller code; both modules are bound into the verification manifest. The
server is a descendant of the existing bounded CLI worker, so CPU/memory/PID,
lease, output and tree-cleanup controls still apply. Python isolated mode (`-I`)
excludes workspace modules, `PYTHONPATH` and user startup hooks from the server's
import surface. Native tools are disabled;
strict MCP configuration rejects inherited servers. Restricted/bare mode,
disabled slash commands and a supplied static system prompt suppress repository
settings, hooks, skill discovery and default repository prompt enumeration.
Planner and Reviewer expose no file server and no native tools. Their roles,
schemas, model choices and call ceilings are unchanged.

This is enforcement at the file-tool API boundary, not a new OS jail for model
CLI internals. The installed trusted runtime and its configured authentication
bootstrap still read their own runtime inputs; those are never file-tool query
targets. Unknown sensitive strings inside an otherwise authorized source file
are not guaranteed to be detected by heuristic content filtering. Non-ASCII
paths, files larger than the existing read ceiling and tasks requiring more
than the bounded authorized surface can block safely. Real Claude-to-tool
integration remains for the independent normal-WSL retest; deterministic tests
cover policy construction, real stdio dispatch, role command configuration,
cross-unit current content and cgroup-contained descendant cleanup. No streaming,
global deadline, restorable checkpoint or new model role is introduced.

## Stage 1.6 — safe model-worker activity telemetry

Local contract evidence: installed Claude Code **2.1.284**, `claude --help`
(`--output-format stream-json`, print mode, `--verbose`,
`--no-session-persistence`) and its locally installed SDK/event schemas.
The wrapper forwards arguments with `exec claude "$@"`; no provider calls were
used to inspect this contract. Print streaming emits newline-delimited JSON:
`system/init`, `assistant.message.content` tool-use blocks (`id`, `name`,
`input`), `user.message.content` tool-result blocks (`tool_use_id`, optional
`is_error`), and a terminal `result` envelope (`subtype`, `is_error`, `result`).
Other documented structural notices are counted but not interpreted as work.
Synthetic fixtures exercise this installed contract; live compatibility remains
unmeasured until the next separately authorized run.

Coder and Fixer request stream-json/verbose with session persistence disabled.
Planner and Reviewer retain strict final-JSON mode. `roles/activity.py` consumes
stdout incrementally **inside the existing worker supervisor**. Stderr is still
drained without retaining text. Only fixed-category counters, controller
monotonic durations, final-result presence and a fixed activity status cross the
supervisor boundary. Raw stream records, reasoning/text blocks, input arguments,
result bodies, paths and unknown tool names never enter worker state, CLI JSON,
logs or evidence. Existing Planner/Reviewer structured outputs are unaffected.

Exact broker MCP identifiers map to Read/Glob/Grep/Edit/Write categories.
Unknown tools count as unknown; their names are not reported. Tool results are
correlated using bounded ephemeral invocation IDs, discarded at completion.
Only recognized invocation/result events and the final envelope advance the
safe progress clock. Assistant text, thinking and structural notices do not.
Counts describe **observed CLI events**, not proof of useful edits or broker
execution. They cannot grant access or extend a lease.

Bounds: 64 KiB per NDJSON record, 256 KiB total stdout (also the unchanged
combined worker stdout/stderr ceiling), 512 records/counters, 128 blocks per
message and pending invocations, 128 characters per ephemeral ID. Duration
metadata is clamped to the existing 10,000,000 ms diagnostic ceiling. There is
no transcript/event list. Duplicate JSON keys, nonfinite values, partial records,
malformed objects, unpaired results, a missing final envelope, pending tools on
success, or events after the final envelope prevent completion. Execution exit
0 alone is insufficient: only a terminal `result/subtype=success`,
`is_error=false`, string `result` and no pending invocation permit completion.
The result string is discarded and replaced with `MODEL_WORKER_COMPLETED`.
Invalid/missing/error final transport maps an otherwise-zero process exit to
65. Wall timeout remains 124; nonzero exits, output/resource failures and
cleanup/integrity failures retain their existing precedence and machine gates.

Broker counters are **not collected** in production: the current stdio MCP
channel has no separate controller-authenticated counter transport. CLI events
and a tool result's text must not be presented as authoritative broker counters,
denials or errors. `tool_error_events` records structural `is_error` only.
No broker policy, capabilities, session budgets or tools changed. A future
counter channel would need provenance and lifecycle enforcement before any
correlation invariant could be claimed.

This stage adds no model call, role, retry or activity-aware timeout. Coder and
Fixer wall leases remain 180 seconds; model resource policy, global two-attempt
Fixer cap, per-unit tests, final review and promotion requirements are unchanged.

### Stage 1.7 — authenticated broker outcomes

Coder/Fixer MCP configuration is validated and rebound by the worker supervisor
before CLI launch. A request-only stdio relay forwards to one bounded local Unix
socket session. The supervisor executes the existing `FileTools` policy decisions
and owns counters in memory; the CLI has no outcome-update or telemetry API.
The broker thread starts after process spawn, avoiding a fork with a live thread.
The CLI and relay retain the existing worker cgroup, limits and capability drop.
The trusted broker is controller code, with unchanged file/read/message/session
bounds, not an additional model process. Shutdown closes the channel, joins the
thread, removes its socket, and retains only a finite counter snapshot in evidence.
Timeout, nonzero exit and missing streamed final result preserve that snapshot.

`broker` and `activity` are separate evidence objects. Stream observations may
omit or duplicate lifecycle events; equality is not an acceptance requirement.
Counts saturate at 65535. Only five fixed tool categories and ten fixed outcome
reasons survive projection. `READ_DENIED` combines authorization, protected paths
and secret-content policy. `FILE_UNAVAILABLE` combines missing/unsafe files,
symlinks, hardlinks and special files. Those causes cannot be distinguished by
existing policy errors, so telemetry does not claim otherwise. Glob/Grep skips of
unreadable candidates remain internal filtering, not failed MCP requests.
Unexpected exceptions use fixed `BROKER_INTERNAL` metadata and sanitized errors.
No requests, paths, contents, exception text, or raw events are telemetry records.
This adds no model call, retry, activity-aware grace, or timeout change.

### Stage 1.8 — test-coherent slices and intermediate repair

The same single Planner call is instructed to choose behaviorally coherent,
prerequisite-first slices, including coupled files needed to leave each slice
independently testable. The strict explicit-unit schema remains unchanged:
one to three units, at most four validated target-file hints each. Behavioral
coupling is planning guidance, not a filename heuristic or a grant of authority.

Only an otherwise machine-valid intermediate failure-count increase opens a
`REPAIR_REQUIRED` checkpoint. The controller records the original pre-unit count,
post-Coder count, unit index and global attempt count. One Fixer call may consume
an existing global attempt; its retest must reach or improve on the original
pre-unit count. An unrecovered increase blocks, without another repair of that
checkpoint. Timeouts, invalid evidence and integrity failures cannot proceed.
The global budget remains two Fixer calls, shared with subsequent/final repairs.

Intermediate repair candidates are narrowed to the current unit's validated
implementation targets (legacy implementation-file hints when no explicit targets
exist), intersected with any controller-exclusive ownership. The existing file
policy still validates permissions and unsafe file types. The Fixer adapter only
removes paths from that policy. Tester, cumulative fingerprints, change budget,
protected/verification checks and unit-local changed-path checks all still run.
Earlier workspace changes are retained; no baseline restart or tree restore is
introduced. Final review/verification independently rejects incomplete or failed
intermediate repair state. The existing original `unit_progress` evidence is
preserved; bounded `repair_progress` separately records successful repair tests.
CLI exposes only bounded counts/status for the checkpoint, alongside existing
bounded unit history. No worker telemetry, limits, provider or timeout changes.


### Stage 1.9 — separate repository specification reads from writes

Before this stage the broker's single `files` capability governed Read, Glob,
Grep, Edit and Write. Selected implementation context and README could therefore
be writable, while public tests and dependency manifests were normally denied.
Secret/generated/unsafe files and external paths were already excluded.

Schema 2 retains `files` as the READ_ONLY_CAPABILITY surface and adds an explicit
`write_files` WRITE_CAPABILITY subset. Controller adapters select both; requests,
search results, failure evidence and model prose cannot update either. Edit and
Write reject non-write members before opening their contents. Native deletion
and filesystem tools remain unavailable. Legacy schema 1 is rejected rather than
reinterpreted as broad write permission.

The union remains at most eight files; write authority never increases. Existing
validated unit implementation targets receive write priority (exclusive ownership
still intersects them). Related Inspector-selected source is read-only. Final
repair write selection is limited to cumulative changed files and validated unit
implementation hints; intermediate repair further intersects current-unit targets,
while retaining bounded read-only specification context. No repair routing changes.

After writable targets, the read adapter considers root README.md, at most two
tracked public tests, at most two safe root manifests/test configurations, and
bounded unit/Inspector context. It reads current workspace files, not baseline
copies. Other documentation is eligible only when controller-selected, not through
recursive Markdown discovery. Public test/configuration exceptions apply to user
source repositories; controller-owned tests and verification remain inaccessible.
Public tests remain immutable unless separately authorized by the existing explicit
test-edit policy, which this stage does not enable. External hidden suites are
outside the workspace and never selected. Tracked evidence is required for read-only
additions; approved new implementation files retain the existing new-file policy.

All candidates and subsequent accesses retain ASCII normalized-relative path,
secret path/content, no-follow parent/file, single-link regular-file, generated
content and root-identity checks. Files above 64 KiB are rejected, individual read
responses remain 8 KiB, searches remain 64 results, and session budgets remain
128 calls/256 KiB. Coder and repair injected context limits remain unchanged.
Glob/Grep enumerate/search only the read surface and cannot grant writes. Telemetry
retains the existing categorical READ_DENIED/FILE_UNAVAILABLE evidence without
request-derived details; no new path or secret diagnostic is introduced.

Installed local CLI help confirms `--tools ""` disables native tools and
`--strict-mcp-config` restricts server loading; production additionally retains
`--restricted`, `--bare`, disabled slash commands and exactly five allowed broker
MCP tools. Previous unknown stream-event names were intentionally discarded, so
those individual events cannot be identified retrospectively. An unknown event
counter alone proves neither an unsafe tool nor a harmless internal mechanism.
No live probe, provider change, prompt change, timeout change or extra model call
is part of this stage.


### Stage 1.10 — one-shot activity-aware Coder/Fixer wall grace

Coder/Fixer retain a 180-second base wall lease. At base expiry the supervisor
may continue the SAME process once, for up to 60 additional seconds, with an
absolute 240-second execution cap (a stricter controller wall ceiling still wins).
No rolling deadline, retry, additional model call or Fixer attempt is introduced.
Other roles, research workers, non-streaming fixtures and shorter explicit worker
leases retain their existing deadlines. Planner/Reviewer are unchanged.

Qualification requires a successful recognized operation completed in the fixed
30-second interval preceding the base deadline: [150s, 180s). The broker records
its success timestamp using the controller monotonic clock in supervisor memory;
requests, denials and internal errors alone do not qualify. Read/Glob/Grep/Edit/
Write success all qualify. The pipe loop samples this private timestamp so a poll
straddling expiry retains previously observed pre-deadline progress. The worker
cannot supply or overwrite this timestamp or the lease decision.

When a broker session exists it is authoritative: stream activity cannot override
missing/stale broker success. Only if no broker exists, the fallback is a completed,
successful recognized tool lifecycle parsed by ActivityCapture and stamped by the
controller at receipt. Invocation alone, unknown tools, assistant text, reasoning,
system/status events and model-supplied times never qualify. Invalid/truncated
stream telemetry suppresses grace. No raw content or new tool names are retained.

The outer namespace watchdog allows the potential hard cap plus the existing
10-second setup/cleanup allowance, so it cannot prematurely kill a valid grace
continuation. The inner supervisor still enforces the conditional base deadline
and absolute hard cap, then invokes the same mandatory cgroup cleanup. User
interruption propagates immediately through existing finally/cleanup paths.
CPU time/quota, memory, PIDs, FDs, file size and stdout/stderr/stream limits are
unchanged; grace only changes eligible wall time. Successful completion during
grace follows normal Tester routing; timeout still produces CODER_TIMEOUT or
FIXER_TIMEOUT. Incomplete, malformed, over-limit or unclean workers cannot pass.

Worker/CLI evidence contains only bounded lease timings/booleans and a fixed
progress-source enum. last_trusted_progress_ms identifies the qualifying
pre-base-deadline completion, not model-provided data. Broker counters and public
stream telemetry retain their existing projections; timestamp tracking is private.
Tests inject clocks and synthetic worker/broker events rather than multi-minute
sleeps or provider requests. Read/write capability policy, context selection,
decomposition, prompts, intermediate repair routing and global Fixer max=2 remain
unchanged.


### Stage 1.10a — explicit unit-goal contract alignment

The production goal validator is shared by Planner normalization and explicit
unit derivation. Its ordered rules are unchanged: goal must be a string; strip()
must leave nonempty text; the ORIGINAL string must contain at most 300 Python
Unicode characters; and the stripped text must match the existing recognized
implementation-action classifier. Successful normalization strips only outer
whitespace. There is no explicit minimum beyond nonblank/action recognition
(the shortest accepted action-only strings are Add/Fix, three characters).
There is no independent newline, control-character, Unicode, duplicate-goal or
Unicode-normalization check. Those values remain subject to the same length and
action-placement rules. Missing goal/target_files or unknown fields instead fail
UNIT_SCHEMA_INVALID before goal validation. No production explicit goal is sliced.

UNIT_GOAL_INVALID now carries one fixed controller-only reason:
GOAL_NOT_STRING, GOAL_EMPTY, GOAL_TOO_LONG or GOAL_NO_IMPLEMENTATION_ACTION.
Planner diagnostics/CLI expose only these enums, never the rejected value, a
fragment, exception text, or a unit-specific secret. The previous generic live
error cannot establish which branch fired; no retrospective cause is invented.

The structured schema already had minLength=1/maxLength=300. It now also requests
a portable, stricter GENERATION SUBSET: leading strip-compatible whitespace,
an ASCII case-insensitive recognized action verb, followed by whitespace/end.
The existing verb list is shared with the unchanged controller regex. This avoids
nonportable inline regex flags and Python/ECMAScript Unicode word-boundary
assumptions. It intentionally does not describe every legacy action placement:
forged/direct inputs still face the original broader controller contract, not a
newly loosened validator. Ordinary Unicode outcome text after the verb is allowed.
Unknown fields, unit counts and target-file constraints remain strict.

Planner instructions publish the raw 300-character limit, request concise
verb-first, preferably single-line behavioral outcomes, and place detailed
requirements in plan_steps/target_files. Test coherence, coupled-file grouping,
prerequisite-first ordering, one to three units, four target hints and the single
Planner call remain unchanged. There is no retry or semantic truncation. Stage
1.10 leases, Coder/Fixer prompts, read/write capabilities, broker/activity policy,
intermediate repair routing and resource/verification controls are unaffected.

### Stage 1.11 — descriptive capability-aware tool contract

Before this stage, Coder/Fixer prompts named the controlled tools and a bounded
authorized surface, but did not list the final read/write capabilities or
explain exact Edit/Write argument semantics and denial handling. Target/context
hints were not a complete description of the broker's capabilities.

Both roles now receive a compact descriptive contract derived from the exact
sealed MCP policy sent to the broker, after any intermediate Fixer narrowing.
It contains only validated relative readable/writable paths and creation-approved
paths, each bounded by existing eight-file capability lists and 180-character
safe paths. It never contains the root, controller location, identity or digest,
denied candidates, policy source or secret-filter internals. The contract enters
only the existing prompt; diagnostics retain the existing prompt character count.
The broker capability object remains authoritative, not descriptive prompt text.

Read/Glob/Grep operate only on authorized current files. Grep is literal, not
regex; search queries are bounded printable ASCII. Edit requires an existing
writable/readable file and one nonempty unique old_text match. Write supports
whole-file replacement on an authorized existing file or creation on an explicitly
approved new path. Every string argument is limited to 8192 UTF-8 bytes; therefore
a large whole-file Write can be INVALID_REQUEST even when a small Edit succeeds.
There is no evidence that the prior live Write denials were caused by a blanket
existing-file restriction: that restriction does not exist. The contract forbids
authorization retries, aliases, traversal and tool switching to bypass denials.

Controller-owned broker telemetry adds denials_by_tool: sparse counts under only
Read/Glob/Grep/Edit/Write and the existing finite reason enum, saturated at 65535.
Protocol failures without an identified tool remain in aggregate reasons; internal
errors retain the existing error counters, rather than being called denials.
No request strings, paths, arguments, contents or exceptions enter this projection.
Existing CLI evidence sanitization reuses safe_broker; no parallel telemetry path
or model-supplied counters are added. Broker session authenticity, progress timing,
policy decisions, context selection, decomposition, resource limits, lease behavior
and model-call ceilings are unchanged. Deterministic tests exercise real broker
operations and synthetic role calls; no provider calls are used.

### Stage 1.12 — capability contract audit and clarification

The Stage 1.11 live result supplied for this audit has 13 Read.READ_DENIED and
three Write.READ_DENIED, no INVALID_REQUEST, and no broker internal errors.
These categorical counters do not retain request paths, arguments, or model
text. They cannot establish which paths were requested, whether requests were
repeated, or whether a path alias was used. No live call was made during this
audit; reduced live friction remains an empirical question.

The audited path is `build_policy` -> sealed `file_tool_flags` ->
`capability_contract` -> Coder/Fixer `-p` -> worker `prepare_session` ->
controller-owned `BrokerSession` -> `FileTools` -> exact membership and safe
fd-relative reads/writes -> `BrokerTelemetry`. The session replaces only the
MCP transport configuration, preserving the final prompt and validated policy.
Intermediate Fixer narrowing precedes contract generation. Prompt, failure,
research and model text never feed authorization. Graph routing preserves the
unit guards, controller Tester, and global two-Fixer-attempt limit.

| Failure class | Audit finding |
| --- | --- |
| 1. Final paths missing from prompt | Not reproduced: both roles derive the contract from the exact final sealed policy. |
| 2. Placement/ambiguity | Confirmed: the Stage 1.11 contract followed task, plan, facts and file context. It did not explicitly describe the context/tool-surface difference. |
| 3. Display/request representation | Manifest paths already match broker membership strings. The missing instruction was to copy them exactly as workspace-relative strings; absolute and leading `./` aliases are intentionally denied. |
| 4. Context mistaken for writable targets | Context blocks and related-file hints do not identify tool permissions. Explicit read-only/existing-write/new-path lists now distinguish them. |
| 5. Existing/new behavior | Existing authorized files support both Edit and Write. New approved paths require creation before Read/Edit; a creation-approved path may already exist from prior work. |
| 6. Later context suggests inaccessible paths | Reproduced: injected file candidates and broker read selection differ. README/public tests/manifests consume broker slots ahead of related sources. With eight slots, an injected source can be outside the tool list. Facts, diff headers and failure locations can also mention unlisted paths. |
| 7. Glob/Grep follow-up | Result path fields are already filtered by current authorized reads. Grep line text can mention unlisted files; those references are data, not capabilities. No further filtering or access grant is needed. |
| 8. Canonicalization rejection | No broker/manifest mismatch found. Exact membership precedes opening; aliases remain denied without normalization. |
| 9. Coder/Fixer divergence | Both use the same contract helper; Fixer narrowing is reflected. Both had the late placement issue. |
| 10. Regression coverage | Existing tests already checked final sealed lists and real operations, not just presence. Missing cases were relay preservation, alias behavior, context excluded by the read cap, and embedded discovery references. |
| 11. Irrelevant context | Up to eight injected files plus broader bounded hints can encourage browsing. Necessity of individual live context files cannot be established from counters. Selection and context budgets remain unchanged. |
| 12. Whole-file Write documentation | Replacement of an authorized existing file is legitimate. Live READ_DENIED does not imply an Edit-only restriction or an oversized argument (INVALID_REQUEST). Prefer bounded Edit for focused changes; retain Write replacement support. |

A deterministic fixture reproduces both the context/tool-surface difference and
`file.py` success versus `./file.py`/absolute-path denial. These are evidence for
clarifying the contract, not proof of the precise cause of all live denials.
Read.READ_DENIED covers exact membership/classification rejection and content
rejection (including oversized content). Write.READ_DENIED can arise at write
membership or an existing file's implicit authorized read. The worker receives
the fixed FILE_TOOL_DENIED response, so it cannot infer the internal cause.
This response and safe categorical telemetry remain unchanged.

The general fix places one shared contract before task/context data. Compact
JSON arrays separate readable files, read-only files, writable existing files,
and creation-approved paths. The contract explains exact relative arguments,
non-authorizing context/references, the new-file lifecycle, bounded Edit and
Write replacement, and stopping denied probes. Read/Edit/Write MCP descriptions
agree with these semantics. A short final rule points back to the lists without
duplicating them. No denied-probe cache is added: repeated identical requests
were not established, and caching failures could obscure current-content changes.

Regression tests capture both final role commands, compare their manifests to
the authenticated supervisor policy after relay replacement, and exercise real
broker reads/edits/writes and denials. They also cover the capped context mismatch,
exact paths and denied aliases, partitioning/new-file lifecycle, and discovery
record paths versus embedded references. Existing authorization, telemetry and
lease tests remain applicable. Authorization derivation, path normalization,
content filtering, context selection, tools/schemas, caps, resource limits,
180+60/240-second lease, trusted-progress rules, two-attempt Fixer limit and the
420-second trusted self-suite budget are unchanged. No provider/model call,
benchmark special case, permission expansion or security exception is introduced.

One later controlled live retest is recommended to measure denial counts,
successful edits, completion and timeout under the unchanged caps/lease. This
local audit cannot prove model compliance or live denial reduction. Keep raw
paths, arguments, model text and secrets out of telemetry.

#### Stage 1.12 reconciliation with the independent sanitized audit

The independent candidate in `/root/omnirush-freeagentos-stage112` was inspected
read-only, file by file; none of its files or patches were copied wholesale.
The existing real-repository candidate's early contract placement, explicit
read-only/existing-write/new-path partitions, exact relative path instructions,
Edit/Write semantics and regression coverage remain in place. The shared
capability/context-coherence diagnosis is supported by executable fixtures.
Precise live denied paths and repeated-identical probes still cannot be recovered
from categorical counters alone. In particular, Write.READ_DENIED can also arise
from the implicit read of an existing writable file after its contents change;
the counts alone do not prove every Write attempted a non-write member.

| Area/file | Reconciliation decision |
| --- | --- |
| `read_policy.py`: exact sealed policy | Already covered for the contract; extract a shared validated decoder for context consumers. Sealing and authority are unchanged. |
| `read_policy.py`: repository facts | Missing and justified. Project known Inspector fields only, filtering every structured path/source field to final readable membership. Reuse Inspector identifier/version sanitizers and its bounded valid-JSON budget. Prefer this strict projection to preserving arbitrary scalar fields or extra record keys. |
| `read_policy.py`: candidate ordering | Different implementation preferred: retain selection unchanged. README/tests/manifests can displace related sources at the eight-file cap, but removing unlisted structured hints/context resolves coherence without reallocating grants or assuming sources are more useful than specification files. |
| `coder.py` | Missing and justified: seal policy before worker context construction; filter active related files, prior changed-file hints, and facts to it. Fail closed before the worker when any active target lacks write membership, including unsupported creation targets. This prevents silently incomplete units and does not grant permission. |
| `coding_units.py` | Missing and justified: worker FILE blocks use `read_authorized` with the final policy and root identity. Filter summary test locations as well as file candidates. Legacy controller-only callers retain their bounded existing behavior. |
| `fixer.py` | Missing and justified: derive candidates with the existing controller packet, seal/narrow the policy, then rebuild the packet for injection against the final policy. The first packet is never supplied to the model. No additional worker/model call is added. |
| `repair_context.py` | Different implementation preferred: filter candidates before constructing both FILE blocks and the diff, not just the context and evidence lists. Filter changed/deleted path hints and context-summary locations to the same final list. |
| `file_tools.py`: tool descriptions | Mostly already covered; also state that Glob/Grep results grant no write access. Tool names/schemas and authorization decisions remain unchanged. |
| `file_tools.py`: denial feedback | Missing and justified: return `FILE_TOOL_DENIED:<SAFE_FIXED_REASON>`. Reuse the exact existing telemetry reason mapping, including INVALID_REQUEST and TOOL_BUDGET/SESSION_BUDGET; unknown/sanitized errors use BROKER_INTERNAL. Preserve isError, denied/error counters, budgets, session lifecycle and trusted-success timing. No request or exception text is returned. |
| `test_contract.py` / `test_file_read_policy.py` | Extend the preserved real-repo regressions with final context/facts/unit coherence, narrowed Fixer diff/evidence, pre-worker target rejection and categorical-feedback privacy. Preserve bounded table-driven output. |
| `test_worker_resource.py` | Update four existing mocked no-broker fixtures to mock the new sealed-policy decoder alongside their already mocked flags/contract; these tests still exercise the worker timeout/cleanup boundary. Production policy decoding is never bypassed. |

Coherence is guaranteed for controller-generated structured repository path
fields, actionable unit metadata, prior changed-file hints, injected FILE blocks,
context-summary locations, repair candidate/change/deletion lists and diff file
headers. Every such readable path belongs to the final sealed read list; active
Coder targets must belong to its write list. New-file paths retain their explicit
creation/lifecycle semantics. Original task/plan/research, implementation source
text, test identifiers and sanitized failure excerpts remain non-authorizing data;
they can naturally mention unlisted paths. Their text is not parsed into grants,
and the contract and diagnostic heading explicitly distinguish it from actionable
file capabilities. It is neither possible nor useful to interpret every textual
reference as a capability.

The Astra implementation's unfiltered Fixer diff, unfiltered context-summary
locations and permissive unknown fact fields were not adopted. Nor were its
older late contract placement or removal of the existing real-repo regression
coverage. No denial circuit breaker, raw-manifest policy change, alias acceptance,
read-order change, capability expansion, cap/lease change, model retry/call,
telemetry path storage or benchmark-specific logic is introduced. Authorization
selection remains byte-for-byte unchanged; denied activity still cannot update
the controller-authenticated success timestamp used by the lease.

#### Stage 1.13 — Mutation Capability Compliance

The persistent Stage 1.12 live counters validate the read-context improvement:
Read succeeded 24/25 times, versus 7/20 in Stage 1.11. Mutation friction remains:
Edit succeeded 2/11 times and Write 0/3; all 13 total denials were READ_DENIED.
These private categorical counters cannot establish historical requested paths,
aliases, repeated probes, or whether an implicit read rejected changed contents.
There were no broker internal errors. No live model was called for this audit.

The deterministic trace exposes an interface gap. Both roles seal the controller
policy before the capability contract and broker session. The contract partitions
read-only, existing writable and creation-approved paths, but the former MCP
Read/Edit/Write path schemas accepted any string. Tool descriptions gave no
session-specific path choices. Task/source text remained non-authorizing and
could suggest other files. Edit calls require_write before reading the existing
file and matching old_text; Write calls require_write before creating/replacing,
and replacement also reads the current file. The write-membership check formerly
reported READ_DENIED, indistinguishable from its implicit read failures.

The supplied task wording permits implementation additions generally, whereas
the live unit has two existing targets and zero approved new targets. General
permission does not select a creation path. The evidence JSON retains only task
length/hash, so that wording is supplied by the operator, not recovered from the
JSON. The contract and Write description now explicitly state NEW FILE CREATION:
NONE whenever the sealed new_files list is empty.

| Alternative | Decision and evidence |
| --- | --- |
| More prompt wording only | Insufficient: Stage 1.12 already supplies explicit capability partitions. Add only the empty-creation statement shared with the actual tool interface. |
| Controller-generated tool path enums | Adopt: MCP inputSchema is JSON Schema. Read advertises exactly files; Write exactly write_files (existing plus approved new); Edit existing write_files, including approved new paths after safe creation. Each list is bounded by the unchanged eight-file cap. |
| READ_ONLY/WRITABLE FILE labels | Defer: existing contract already partitions these paths, and schemas constrain the argument at tool selection without changing context format. |
| Fixed mutation-denial reasons | Adopt existing WRITE_DENIED for write-membership/path rejection. READ_DENIED remains for failed reads, including implicit reads. Match errors remain EDIT_MATCH_INVALID. No new telemetry taxonomy or path storage. |
| Repeated-denial suppression | Defer: historical repeated identical requests cannot be established; categorical feedback and constrained schemas are the smaller change. |
| Blame model/provider without a change | Unsupported as the sole diagnosis: free-form path schemas are a reproducible orchestration gap. Actual provider compliance/efficiency remains a live question. |

The common MCP server constructs descriptors from its validated session policy,
not prompt/model output. Descriptor copies cannot mutate policy or another
session. Empty capabilities use a string schema with not:{} (reject every value),
not an invalid empty enum or fake sentinel path; descriptions say no authorized
paths. Approved creation makes that path available to Edit; sessions with approved
new paths advertise tools.listChanged and emit notifications/tools/list_changed
when a successful Write changes Edit availability. The next tools/list returns
the updated descriptor. No authority is added by that lifecycle transition.

Protocol references: [MCP 2025-06-18 tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools),
[JSON Schema enum](https://json-schema.org/understanding-json-schema/reference/enum),
and [empty/false schema semantics](https://json-schema.org/understanding-json-schema/basics).
Official exact-page reading was used after the discovery helper failed. Local
Draft 4 and Draft 2020-12 validators accepted the generated schemas and rejected
unlisted/alias/absolute/traversal paths in 108 validation cases; no dependency was
added to production or the test runtime.

Schemas are descriptive constraints, never authority. Even when ignored or forged,
the existing broker predicates reject read-only/unapproved paths and aliases.
Content, inode/root identity, symlink/hardlink/special-file protections still run.
Categorical responses retain FILE_TOOL_DENIED:<SAFE_FIXED_REASON>, isError and
safe bounded telemetry. Discovery cannot grant mutation rights. Authorization
selection, caps, worker calls, Fixer attempts, leases, trusted-progress rules and
the 420-second trusted suite budget are unchanged.

Deterministic regressions capture both final role policies, exercise their actual
broker operations, test descriptor isolation, empty creation and approved creation
with MCP list-change notification, and bypass/forge schemas to prove the broker
still denies. They distinguish membership, match and implicit-content-read errors
without retaining request data in telemetry. One controlled Stage 1.13 live run
is needed to measure actual client/provider enum compliance, denial friction and
completion. If capabilities are coherent and denials low but the unchanged
240-second hard cap is still reached, move to model/provider routing and worker
efficiency rather than further permission tuning.

## Stage 2.1 — Worker Completion & Model/Provider Diagnostics

Stage 1 permission tuning is closed. The persistent Stage 1.13 live evidence
shows 11 authenticated broker requests and successes, zero denials/errors,
including two successful Edits. The parser observed 43 events, no parser errors,
no final result, 40,725 stdout bytes (below the bound), and no stderr bytes.
The last broker success was 74,970 ms; process runtime including cleanup was
180,607 ms (a 105,637 ms gap). The reported role runtime of approximately
180,764 ms includes additional overhead. No grace was appropriate: progress was
outside the unchanged thirty-second recency window. No resource hits occurred.
Old evidence cannot reveal last non-tool activity, upstream termination or EOF.

### Local runtime trace and limits of attribution

Coder/Fixer seal file policy, prepare the capability contract, and launch
claude-free in print stream-json/verbose mode without session persistence.
worker.py enters the existing namespace/cgroup boundary, replaces the MCP
configuration with the supervisor-owned broker relay, starts the client, and
drains stdout and stderr independently. The lease trusts supervisor broker
success first. ActivityCapture consumes bounded NDJSON; it discards message text,
thinking, tool arguments/results and raw records. The controller waits for process
exit, not merely an envelope. Scope cleanup follows; timeout takes precedence.
An otherwise-zero exit without a valid successful result becomes exit 65.
Coder/Fixer then block on nonzero exit before controller testing/promotion.

The result contract is a Claude Code client envelope, not an exact sentence the
model must produce. Any string result is accepted in a successful envelope with
no pending tool invocation. Text alone cannot complete the worker. A valid result
while the process remains alive still times out; synthetic workers prove this.
The existing parser supports assistant/user, system, result, tool_progress,
tool_use_summary and rate_limit_event. Unknown types, malformed/truncated records
and events after final result still fail closed. None of those failures was
reported in Stage 1.13. Partial-token/SSE events are not requested by the current
command; NDJSON observation does not reveal upstream token timing.

Read-only integration inspection found the installed Claude Code 2.1.284 native
binary and the claude-free shell launcher. The launcher forwards argv with exec,
loads its credential internally (not inspected), sets ANTHROPIC_BASE_URL to the
loopback gateway, and does not choose a model. No client was executed for audit.
The running gateway image is ghcr.io/tashfeenahmed/freellmapi:latest. Only compiled
integration source was read: routes/anthropic.js, services/anthropic-map.js,
providers/base.js and timeout/routing-related excerpts. No environment, database,
credential file, request log or raw response was read. Current installed source
does not prove which image/settings/model served the historical run.

The gateway translates OpenAI-style tool calls into Anthropic tool_use blocks;
tool_calls maps to tool_use, length to max_tokens, and stop/default to end_turn.
Its Anthropic stream emits message_delta, message_stop and closes the response
after the upstream generator finishes. Errors after stream commitment emit an
error event and end the response. The shared SSE reader returns on [DONE], or
accepts EOF after finish_reason; abrupt EOF without either is an error. However,
finish_reason alone is remembered without immediately ending the read loop.
An upstream which sends a terminal reason but leaves its connection open could
therefore delay completion. Byte keepalives can also satisfy the read watchdog
without useful model output. Configurable stall timeouts default to ninety
seconds, can be disabled, and first-byte budgets depend on provider chat timeout.
These are plausible failure mechanisms, not a diagnosis of the historical call.
Gateway fallback/retries already exist independently of FreeAgentOS; this stage
adds none and changes neither gateway nor model selection.

Dynamic MCP schema updates are not a credible explanation of this particular
post-Edit gap: sealed new_files was empty, no Write occurred, listChanged was
false, and the update/notification branch only runs after successful Write in
sessions with approved new paths. Existing deterministic protocol tests cover
that separate creation lifecycle. Discovery and mutation authorization are intact.

### Additive safe observation

activity records fixed event_type_counts (including UNKNOWN, never the unknown
name), last_valid_stream_event_ms, last_non_tool_event_ms/type,
result_event_observed and result_category (UNOBSERVED/SUCCESS/ERROR/OTHER).
Observed result and accepted final_result_seen remain distinct: invalid result
envelopes cannot become successful completion. Diagnostic timestamps/counters use
the existing monotonic clock and bounds. Recognition/acceptance rules are unchanged.

worker evidence adds a projected completion object captured BEFORE cleanup:
stdout_eof_before_cleanup, stderr_eof_before_cleanup,
process_alive_at_observation_end; stdout_idle_ms, stderr_idle_ms,
valid_stream_idle_ms and broker_success_idle_ms; and fixed state PROCESS_EXITED,
ALIVE_WITH_RESULT, ALIVE_AFTER_STDOUT_EOF or ALIVE_NO_RESULT. Idle durations are
observations, not new timeout thresholds; null means no corresponding observation.
provider_completion_observed is explicitly UNAVAILABLE because upstream SSE is
outside this parser. Killing the scope cannot fabricate pre-cleanup EOF. CLI
projection permits only these bounded fields. No raw model data is persisted.
No new event category grants progress or grace; lease.py remains unchanged.

### Minimal future controller-owned model profiles

All model roles currently use claude-free without --model. Inspector is local
and deterministic; Researcher uses bounded research commands rather than a model
worker. Planner/Reviewer use JSON schema output, Coder/Fixer streaming/tool mode.
Claude client defaults/environment and gateway family mapping/catalog routing
choose the actual provider/model. Default gateway family mappings are auto;
configured runtime values and actual historical served model were not inspected.
Unknown/disabled concrete pins can resolve to auto in the installed gateway, so
a future strict router must verify resolved model identity, not assume a requested
identifier guarantees it. Loopback health alone proves no request completion.

Stage 2.2 should introduce a small immutable controller registry of execution
model profiles, separate from worker.py's resource policy_profile. Each profile
contains an allowlisted adapter identifier, model identifier, role suitability,
context-capacity class, free/cost/local classification and controller-validated
compatibility booleans: supports_tools, supports_streaming,
supports_dynamic_tool_schema, supports_long_agent_session,
supports_structured_result. Unknown profiles/extra security fields fail closed.
Compatibility must come from controlled tests/operator-reviewed registry entries,
never model assertions. A fixed command builder inserts only adapter/model
selection and preserves the same sealed capabilities, tool flags, sandbox,
limits, verification and trust policy. Credentials remain outside profile/state.
Do not overload resource policy_profile or let profiles supply arbitrary argv,
executables, environment, tool grants, limits, retries or leases.

FreeAgentOS Auto can then select a fast structured Planner, strongest compatible
tool-capable Coder/Fixer, and an independent Reviewer with validated served-model
identity. Inspector stays local; Researcher's current approved tool transport stays
independent of model authorization. Preserve the legacy default first; do not
switch production models or add fallback calls in this milestone. No profile
implementation or routing change is made now; the architecture is ready for a
small separately tested Stage 2.2 implementation.

Recommend exactly one separately approved live diagnostic under the unchanged
model, sealed policy and 180+60/240-second lease. Measure these projected fields,
successful broker timing, result/EOF and liveness through natural exit or timeout.
If available, correlate only fixed gateway request-phase/terminal categories and
durations through a separately privacy-reviewed collector; never collect payloads
or logs. Existing worker fields alone cannot distinguish client waiting from
provider silence, hidden reasoning, gateway retries or a missing SSE terminator.
Do not infer automatic completion from inactivity or successful edits.

## Stage 2.2 — Role-Aware Model Profiles & Compatibility Registry

The Stage 2.1 live diagnostic completed the Coder path: successful tool calls,
accepted success result, both pipe EOFs and process exit in about 34 seconds.
Its public failure count regressed and the controller routed to Fixer. Fixer had
no result/EOF, remained alive and timed out at the base lease with stale trusted
progress. This disproves a permanent completion-detection failure; it does not
establish upstream served identity or explain session variability/quality.
Stage 1 permissions and Stage 2.1 completion/lease decisions remain intact.

### Current selection and implemented foundation

Planner, Coder, Fixer and Reviewer use a common model_command builder. Its default
argv is byte-for-byte equivalent to their previous construction, including print,
output format, sealed MCP flags, permission flags and prompt position. The launcher
claude-free forwards argv to installed Claude Code 2.1.284 and sets the loopback
Anthropic-compatible gateway URL/authentication. Its credential file was not read.
The installed binary contains the --model <model> CLI option; no Claude process
or model request was executed for this audit. Without explicit selection, client
defaults/config and inherited ANTHROPIC_MODEL/family-model environment settings
may influence requested identity; gateway family mappings/catalog routing determine
the actual upstream choice. Runtime configuration/credentials were not inspected.

roles/model_profiles.py defines three controller-owned profiles in a read-only
registry with frozen records and immutable role sets:

| Profile | Adapter | Requested model | Suitable roles |
| --- | --- | --- | --- |
| claude-free-default | claude-code-freellmapi | CLIENT_DEFAULT (no --model) | Planner, Coder, Fixer, Reviewer |
| claude-free-auto | claude-code-freellmapi | auto (explicit --model auto) | Planner, Coder, Fixer, Reviewer |
| research-tools | bounded-research-tools | NOT_APPLICABLE | Researcher |

The auto identifier is grounded in the installed gateway's existing model route.
The opt-in profile is not a different-provider adapter or a quality improvement
claim. No specific catalog model, local model or Astra provider is fabricated.
Researcher remains its real bounded Exa/dev/prompt/Jina action dispatcher; Inspector
remains deterministic and has no model profile. Future adapters require a real
implementation and compatibility evidence, not merely a new metadata entry.

Auto is deterministic controller resolution: each role maps to its configured
profile, otherwise the legacy default above. The optional trusted API is
build_graph(model_profiles={"coder": "claude-free-auto"}); the CLI equivalent is
--model-profile coder=claude-free-auto, repeatable for distinct roles (at most five).
ROLE=auto selects that role's default. Unknown/duplicate/malformed/incompatible
selections fail with fixed safe codes before workspace/model work. CLI behavior
without this optional flag is unchanged. No state field or model response can
select a profile: configuration is copied, validated and captured by the graph,
then scoped with a ContextVar for each node. Scope resets on exceptions and is
isolated across graph invocations/threads. No global mutable routing state,
adaptive score, live-history selection, model retry or fallback is introduced.

### Compatibility, identity and security separation

Profiles contain only identity, role suitability, compatibility booleans,
context/cost/availability classes. Current context capacity is UNKNOWN; cost and
availability are CONFIGURED, not claims of current quota or availability. The
booleans describe the installed client/adapter interface contract, including
result envelopes, streaming and tools. They are controller declarations grounded
in deterministic protocol tests and live completion evidence, not model claims
or guarantees about every auto-routed provider's quality/long-session performance.

Planner/Reviewer require structured results and result envelopes. Coder/Fixer
require tools, streaming, dynamic tool schemas, result envelopes and agent-session
support. Researcher requires its bounded-tools adapter and role suitability, not
fictional model abilities. Validate all roles, including defaults, when building
the graph and again during command construction/execution. Unsupported adapters
and role/profile pairs fail closed. The worker checks that actual explicit model
arguments agree with the selected profile before launching; it does not obtain
requested identity from stdout or environment.

The outer worker adds model_selection with exact registry-derived
model_profile_id, adapter_id, requested_model_id and compatibility=VALIDATED.
CLIENT_DEFAULT explicitly means the controller supplied no model identifier.
served_model_id is always UNAVAILABLE: a requested pin/auto name cannot establish
what the gateway served, and current gateway pin resolution can itself degrade to
auto. Planner and CLI projections whitelist exact registered identity tuples,
discard extra keys and reject spoofed served/requested identity. No credentials,
prompt, model text, tool arguments, paths or provider payloads are retained here.
Research workers expose their actual non-model transport profile in the same form.

Model profiles are structurally separate from worker resource policy_profile.
They cannot contain grants, security flags, resource/lease overrides, environment,
arbitrary argv, executables or credential data. The builder changes only explicit
model selection; read/write/new policy and MCP flags are supplied unchanged by
the existing controller. Sandbox/cgroup and worker/role timeouts remain unchanged;
selection never enters authorization derivation or trusted-progress decisions.
Fixer attempts remain two; Coder/Fixer retain 180 seconds plus at most one trusted
60-second grace, with a 240-second absolute cap. The trusted suite retains its
420-second timeout and 64 KiB output cap.

Regressions exercise immutable lookup, default/unknown/incompatible selection,
every role capability requirement, frozen records, real role command/policy
comparisons (including approved creation), broker denials, resource/lease equality,
state/prompt injection resistance, concurrent graph scopes, exception reset,
outer evidence projection and CLI configuration/privacy. Existing Stage 1 tests
are unchanged. Registry fixtures are synthetic tests, not production adapters;
no live generation is used. One grouped test entry preserves bounded verbose
output while executing all new behavioral cases.

Do not A/B the legacy and explicit-auto profiles as if they guaranteed different
models. A useful later comparison needs one separately approved compatible
catalog profile with independently established served identity, identical
controller capability/leases, and exactly one default versus one candidate run.
Compare completion/result/EOF, broker friction, public-test change and latency.
Next milestone: validate one real coding/fixing model profile and served-identity
evidence, then perform that bounded comparison; no automatic fallback yet.

## Stage 2.3 — one catalog-backed qualification candidate

This milestone leaves default selection, authorization, resource policy, leases
and fallback behavior unchanged. `claude-free-gpt-oss-120b` is opt-in and limited
to Coder/Fixer. Its concrete selector is `openai/gpt-oss-120b`. The local enabled
Groq catalog row declares tools and 131072 tokens of context; an enabled route
and configured credential exist. These are configuration observations, not proof
of usable credentials, available quota, served identity or model performance.
Compatibility and qualification remain CONFIGURED. Adapter session capabilities
are declarations; the particular model's long-session reliability is unverified.
Planner/Reviewer structured-output compatibility is deliberately not claimed.

### Installed chain, inspected without generation or credential values

The installed `claude-free` launcher forwards `"$@"` to Claude Code. Installed
Claude Code 2.1.284 supports `--model <model>` with aliases or full identifiers.
The controller's immutable profile supplies that argument; task/model text does
not select it. The current default supplies no flag (CLIENT_DEFAULT).

In the running FreeLLMAPI container, `services/anthropic-map.js` resolves Claude
families through `anthropic_model_map`. The inspected default/opus/sonnet/haiku
mapping is auto for each. Concrete enabled catalog IDs can instead resolve to a
model row. Unknown/disabled IDs degrade to auto, so client acceptance of a string
alone proves nothing. `services/model-groups.js` currently enables model groups
unconditionally; do not infer its effective behavior from the stored toggle.
The Anthropic route uses a strict logical-model group chain when one is viable;
provider dispatch/health/quota can still affect execution. A preferred-row route
can otherwise use broader fallback. This gateway behavior is pre-existing;
FreeAgentOS adds no fallback or retry.

The configured Groq adapter is OpenAI-compatible. `providers/openai-compat.js`
forwards the selected model identifier, tools and streaming flag upstream.
Anthropic tool conversion preserves input_schema, including dynamic path enums.
Other locally configured tool-capable selectors observed include
`codestral-latest` and `nvidia/nemotron-3-super-120b-a12b:free`; no additional
profiles or qualification sessions are added for them.

### Attribution boundary

The Anthropic route emits the requested model in message_start/non-stream model
fields. X-Routed-Via identifies the gateway's selected route, not authenticated
upstream identity, and is not exposed in Claude Code NDJSON. The gateway's
`lib/served-model.js` observer is used in its OpenAI proxy route, not the inspected
Anthropic route; its nullable drift record also cannot distinguish matching from
missing identity. No raw request/log rows were consulted. Consequently all
FreeAgentOS served_model_id values remain UNAVAILABLE. No identity match is
claimed. Default auto may already choose the candidate; actual upstream
distinctness is UNPROVEN until trustworthy attribution is available.

Safe requested identity now includes registry-derived
qualification_status=CONFIGURED; projection rejects spoofed verification or
served identity, discards extra fields and still accepts older evidence tuples.
No raw upstream headers/payloads, credentials or model transcripts are retained.

### Exactly one future, separately authorized smoke

Default description (no catalog probe, no generation):

    /root/agent-stack/bin/freeagent-qualify-model --profile claude-free-gpt-oss-120b

Only after separate operator authorization:

    /root/agent-stack/bin/freeagent-qualify-model --profile claude-free-gpt-oss-120b --live

The live command rechecks the exact enabled Groq row through a read-only database
connection and emits only a readiness boolean internally. If unavailable it fails
closed before generation. This cannot eliminate routing changes between check
and dispatch, or establish served identity. It creates one synthetic Git fixture,
uses the normal controller workspace/manifest and host preflight, seals a policy
with one existing writable file and zero creation paths, and starts exactly one
Coder worker. No Planner, Fixer, Reviewer or fallback model call is made. The
worker gets the same production sandbox, cgroup, resource policy and 180-second
lease with at most one trusted 60-second grace and 240-second absolute cap.

The worker must perform one authorized Read and one Edit, produce a successful
result event, reach stdout/stderr EOF and exit with confirmed cleanup; the
controller checks the exact synthetic change and removes its workspace. Output
contains bounded existing safe evidence plus fixed qualification categories,
never paths or content. SESSION_SMOKE_PASS verifies only that short Coder tool
loop. It does not verify Fixer repair quality, long sessions, served identity or
upstream distinctness. It cannot by itself justify a distinct-model shipment A/B.
No live invocation is part of deterministic testing.

Tests execute actual fixture/workspace/sealed broker operations with the model
worker mocked, reject incomplete completion evidence, verify default dry-run and
stale catalog gating, and compare both candidate roles against the default under
identical read/write/new, resource and lease state. Existing Stage 1 tests remain
unchanged. Live attribution and this one smoke precede any shipment comparison.

## Stage 2.4 — explicit attribution levels and installed-path limitation

The qualification output now separates requested_profile_id/requested_model_id,
routed_provider_id/routed_model_id, and served_model_id under identity_attribution.
Evidence vocabulary is fixed: REQUESTED_CONFIG, ROUTER_DISPATCH,
UPSTREAM_REPORTED, UNAVAILABLE. Requested identity is derived from the immutable
controller profile scope. All routed/served fields and their evidence levels
currently remain UNAVAILABLE, with the fixed status
GATEWAY_SESSION_BINDING_UNAVAILABLE. This is an observed transport limitation,
not a model-selection failure. No worker stdout, result envelope, echoed model,
header-shaped model output or claimed evidence category can upgrade provenance.
The projection accepts only the currently implemented registry-derived tuple,
drops extra data and rejects claimed routed/served values. Profiles, commands,
capability policy, resources and leases are unaffected.

### Read-only installed source audit

The gateway is a separately installed service: image
`ghcr.io/tashfeenahmed/freellmapi:latest`, container
`freellmapi-freellmapi-1`. Its only mounted destination is the data volume at
/app/server/data, not an approved development source checkout. No service source,
configuration, data, image or deployment was modified. No traffic logs or request
rows were read, and no generation was invoked. Source references below are to
the installed /app/server/dist tree, rather than files owned by this repository.

* routes/anthropic.js:418 copies the client body.model into requestedModel
  (default auto); :419 strips an initial claude/ only for routing.
  services/anthropic-map.js resolveAnthropicModel maps families and exact enabled
  catalog selectors. The current anthropic_model_map setting is absent; its
  source-defined effective default/opus/sonnet/haiku values are all auto.
  CLIENT_DEFAULT is a FreeAgentOS configuration label (no --model flag), not
  evidence of the literal HTTP body model chosen internally by Claude Code.
* routes/anthropic.js:536 builds a strict logical-model group chain when viable;
  :599 invokes routeRequest. services/router.js:1235 returns platform/modelId,
  selected provider and internal routing state. The gateway therefore knows the
  actual outbound route for every attempt, including Auto and concrete pins.
  Auto depends on runtime availability, budget, health and session affinity;
  catalog configuration alone cannot identify the next selected route.
* routes/anthropic.js:625 and :802 pass route.modelId to the selected provider.
  providers/openai-compat.js:253 and :367 put that value in the outbound model
  argument. A successful dispatch is router evidence, not proof of served model.
* OpenAI-compatible success handling retains native upstream model metadata in
  its JSON/chunks. However, error tool-call rescue at :284 and :396 synthesizes
  model=modelId. A generic model field at this adapter boundary is consequently
  insufficient without provenance identifying native versus synthesized data.
* routes/anthropic.js:692 sets the non-stream response model=requestedModel;
  :765 sets streaming message_start model=ctx.requestedModel. Neither is upstream
  identity. :822 captures finish_reason; :970 translates it to Anthropic
  tool_use/max_tokens/end_turn and emits message_stop. These completion markers
  provide completion evidence, not identity evidence.
* routes/anthropic.js:698 and :757 emit X-Routed-Via from the actual selected
  route.platform/route.modelId. lib/header-value.js sanitizes/limits the combined
  string to 256 characters. This is useful dispatch evidence at the HTTP response
  boundary; it is not served identity, is not an all-attempt trace and may be
  truncated. Streaming headers are committed only at first meaningful output,
  after invisible pre-commit failover. They cannot identify every outbound attempt.
* Anthropic logRequest calls supply routed platform/model but served_model=null.
  The lib/served-model.js observer is used in routes/proxy.js, not this Anthropic
  path. It records drift only; NULL conflates matching, missing and placeholder
  identities. Existing requests/request_attempts analytics lack a controller
  nonce/session correlation column. Time-window/client-agent matching would
  falsely attribute concurrent/background calls and is deliberately not used.
* claude-free fixes ANTHROPIC_BASE_URL to the loopback gateway and forwards argv
  unchanged. FreeAgentOS receives Claude Code NDJSON, not gateway HTTP headers;
  activity.py deliberately discards session IDs and payloads. No authenticated,
  request-bound bridge from X-Routed-Via to this controller is implemented.

Result: routed identity is available within the gateway/HTTP boundary but is not
currently attributable to a FreeAgentOS session. Served identity is unavailable
at this gateway boundary. Running the existing smoke does not repair that missing
bridge. No header interception proxy, raw NDJSON persistence or heuristic database
polling is introduced merely to work around it.

### Smallest proposed separate gateway patch — NOT applied

Accurate controller-visible attribution needs a separately approved gateway
change plus a small controller consumer. The proposed contract is:

1. Bind requests to one controller-generated, unpredictable qualification nonce.
   Carry it as a dedicated metadata header, never prompt/model text. Installed
   Claude Code binary contains ANTHROPIC_CUSTOM_HEADERS and --session-id support;
   this is a potential injection surface, not verified header propagation. Verify
   the chosen surface against a synthetic local HTTP fixture before deployment.
   Do not use shared IP, timestamps or requested selector as a session binding.
2. At the existing dispatch callback, project only catalog-validated provider and
   concrete model identifiers for each outbound attempt. Record fixed attempt
   outcome categories; distinguish dispatch from a completed/committed response.
   A session can contain several model requests/routes, so retain a bounded set
   with explicit overflow/incompleteness rather than claiming one route for it.
3. At the native upstream response ingestion point, separately capture only the
   model identifier, before gateway echo/normalization/rescue. Accept only an
   approved non-secret identifier from a controller/gateway allowlist. Synthetic
   rescue, placeholders, absent or inconsistent identifiers remain UNAVAILABLE.
   Native provider metadata may be UPSTREAM_REPORTED, not hardware attestation.
   Do not reuse the existing drift-only NULL convention or infer a match.
4. Publish only those fixed fields through a controller-only, request-bound
   local channel (for example a root-owned bounded spool with restrictive ACLs,
   TTL and exact nonce binding). It must exclude keys/key labels, URLs, request
   bodies, prompts, content, headers, exceptions and session identifiers from
   public output. Worker/model claims cannot populate this channel. A public
   unauthenticated diagnostics endpoint is not an acceptable substitute.
5. Verify fresh source, nonce, session completeness and schema at the controller
   boundary. Only then may the projector emit ROUTER_DISPATCH/UPSTREAM_REPORTED.
   Missing/malformed/stale/overflow evidence reports UNAVAILABLE. Do not change
   model routing, weights, preferences, fallback, authentication or completion.

This is a patch specification, not a fake implemented adapter or an authorization
request to mutate the installed service. Until separately approved instrumentation
exists, safe_attribution intentionally cannot accept even plausible routed claims.
Default and candidate would need the same instrumentation. Route distinctness
requires bound observations of both sessions (potentially sets of routes), not
one configured pin compared with a guessed default or one candidate smoke alone.

### Qualification and deterministic verification

The Stage 2.3 command remains non-live by default; --live remains explicit opt-in
and is not run in this milestone. Its future safe output adds the fixed identity
fields above alongside existing result category, EOF flags, process state,
cleanup status, broker counts and short-session compatibility result. A later
separately authorized smoke can still verify Read/Edit/completion, but its current
attribution fields will remain UNAVAILABLE. It cannot establish distinctness or
long-session/Fixer quality. Do not infer an A/B comparison is ready from a smoke
pass. No automatic retry, fallback, extra role call or profile is added.

New grouped deterministic cases check exact evidence enums, echoed/claimed/raw
metadata rejection, field separation, default/candidate policy and resource
identity, unchanged lease behavior, selection independence and non-live default.
Existing Stage 2.3 profile tests and Stage 1 tests remain unchanged.
