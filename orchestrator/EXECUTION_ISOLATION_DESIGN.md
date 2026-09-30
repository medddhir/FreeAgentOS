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
`--restricted` mode with only Read/Glob/Grep/Edit/Write tools and no Bash, hooks,
project settings, or extra directories. Their working directory is the run
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
not a complete workspace secret boundary because Coder still has restricted
Read, Glob, and Grep tools. Protecting every file-tool read requires a
separate tool-layer policy review.

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
is not a complete secret boundary for all restricted Read/Glob/Grep operations.
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
