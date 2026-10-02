# Stage 2.9B one-shot attribution diagnostic

`bin/freeagent-attribution-diagnostic --expected-controller <exact-HEAD>` defaults
to dry preparation. `--live` is a separate explicit opt-in and must not be used
until the operator authorizes exactly one session. No qualification or benchmark
is executed by this harness.

The existing qualification command lacks a persistent one-shot guard, uses an
Edit/semantic smoke, and aggregates task qualification. This diagnostic uses
common production workspace/preflight, sealed read policy, profile command builder
and `run_worker()`, without modifying those components. Its only task is one Read
of a tiny disposable README followed by a result. Write/new-file capabilities are
empty. No Planner, Reviewer, Researcher, Fixer, tests or promotion step follows it.
Preflight itself uses the normal trusted local Python probes; these do not call a
model or provider.

Normal completion is preferred. There is no external shortened deadline: killing
the controller would risk skipping finish or losing its result, and substituting
a shorter worker lease would distort the normal lifecycle. The invocation uses
Coder's unchanged 180-second base, existing one-time grace rules, 240-second hard
cap and default resources. A naturally occurring timeout is reported honestly.

Dry preparation verifies the exact expected controller commit, clean worktree,
Stage 2.9A checkpoint ancestry/tag, profile compatibility, gateway health and the
production client's private socket ownership/mode/peer validation. A finish IPC
operation for a fresh never-registered correlation verifies protocol availability
without provisioning a session or dispatching a request. Dry preparation creates
and removes the dedicated synthetic source fixture and production snapshot,
checks preflight and the exact read-only manifest, and constructs but never runs
the model command. It does not create an evidence reservation.

Disposable source: `/tmp/freeagentos-evals/stage29-attribution-diagnostic`.
The production workspace manager makes a separate isolated snapshot and removes
it on exit. Only this invocation's exclusively created source is removed. Existing
source directories abort rather than being deleted or reused.

Live evidence: `/root/freeagentos-benchmarks/evidence/stage29-attribution-diagnostic`.
The directory is exclusively created (0700) immediately before `run_worker()` and
is the durable single-launch reservation. Its absence means no live reservation;
its existence always blocks another launch, including crashes or evidence loss.
`attempt.json` (0600, fsynced) initially records NOT_RUN/RESERVED before launching.
After trusted worker evidence is returned it records ATTEMPTED only when actual
inner process spawn is established; PROCESS_NEVER_STARTED records NOT_RUN.
Missing spawn proof records UNPROVEN, never a fabricated attempt or permission to
retry. While a launch is unresolved, RESERVED must be read as an unresolved launch
reservation, not proof that no process has started. There is no automatic retry or
guard reset. A crash before final evidence therefore requires operator review.

Final `result.json` is written after fixture/snapshot cleanup is checked. It
contains the nested Stage 2.9A diagnostics and existing trusted route projection,
requested profile/model, fixed worker/attempt states, safe lease/timing fields,
cleanup status and bounded remaining-process count. No worker output, command,
prompt, headers, token, IPC frame or provider payload is persisted. Files and
correlation values are not included in the live output.

DIAGNOSTICS_VALIDATED means observable lifecycle categories are coherent and
cleanup is confirmed. It does not mean route identity, model quality, semantic
qualification or production verification. Registration/IPC failure and incomplete
route evidence can validate telemetry while route identity remains unavailable.
Contradictory diagnostic/route claims fail validation. Served identity is always
UNAVAILABLE. This session cannot recover historical Stage 2.8 attribution.

After a clean committed preparation, use the default command once for dry
validation with that commit; only a later explicit authorization permits adding
`--live` to that same pinned command. No new verified tag is created here.
