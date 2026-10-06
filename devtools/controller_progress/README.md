# One-invocation controller progress

Development-only `sitecustomize` observes the actual established controller
`python3 -m unittest discover` child, requiring the fixed repository cwd,
controller virtual environment and a parent cmdline containing the exact
controller runner path. Explicit developer launch supplies a private 0700
progress directory through FREEAGENT_CONTROLLER_PROGRESS_DIR and prepends this
fixed source directory to PYTHONPATH. The injection removes both its activation
and its own PYTHONPATH entry before descendant launches. It does not alter the
production runner, copied-target reporting, runtime selection or qualification.
These checks are developer diagnostic scoping, not a new authorization gate.

TextTestResult callbacks delegate original results and retain test outcomes.
TestCase.subTest contexts delegate their original context manager, adding bounded
labels only. SUBCASE_END means context exit; SUBCASE_RESULT records unittest's
actual outcome separately. Failure exceptions and assertions are not suppressed
by the observer. Only validated labels are recorded, never parameters, raw errors
or source. Unmatched starts indicate unfinished observed intervals, not a hang.

Nested synthetic unittest runs are also observed. In the historical completed
invocation `/tmp/freeagent-required-progress-tn8gzr8a` (required.log SHA-256
`6f32220d199c48a988bd60dc9c14afef491a68075fca4d8897ead69f4c5eb9fc`),
`test_controller_progress.py:ControllerProgressTests.test_actual_unittest_results_and_subcases`
deliberately runs four nested cases producing PASS, FAIL, ERROR and SKIP. The
observer therefore records **564 test intervals**, whereas the authoritative
controller unittest summary reports **560 tests in 388.010 seconds**, OK,
RESULT=PASS, EXIT_CODE=0. These figures belong only to that completed invocation.
The observed TEST_END
totals (561 PASS, one FAIL, one ERROR, one SKIP) are not controller-suite failure
counts; nested fixture outcomes must not be interpreted as failed required
verification. Use the original unittest summary and runner RESULT/EXIT_CODE for
that decision. Diagnostic completion is a separate check.

The latest attempt, `/tmp/freeagent-extractor-observer-required-arsc6smt`,
returned RESULT=TIMEOUT, EXIT_CODE=124 at the unchanged 420-second runner
deadline (wrapper wall 420.520149 seconds). It has no authoritative unittest
count or final duration. Its 564 starts/563 ends include nested fixtures and
cannot substitute for that missing summary. PROCESS_END and progress-result.json
were absent; this attempt cannot establish completed observer shutdown.
The unfinished trusted-entrypoint interval is an observation, not a new defect
or evidence of a hang. The historical completed figures above remain historical.

Failure/error callbacks now emit an immediate private `FAILURE_DETAIL` before
delegating unchanged to the original unittest result method. Expected failures
and failing subtests also get details; subtests use the parent test identity.
Exception type, a sole exact-string exception argument (at most 256 characters),
and at most eight filename/function/line frames (256 characters total) are
recorded. No locals, environment, source lines, exception chains, absolute
traceback paths or arbitrary argument-object `repr`/`str` dumps are collected.
Non-string or multi-argument messages are explicitly omitted. Test identities
are bounded/sanitized; oversized text and frames have `truncated=true`. Encoded
JSON is fitted to the unchanged 1,024-byte record limit, including Unicode
escaping, so the retained text may be shorter than the character caps.

Details consume normal capacity, never the reserved terminal allowance.
Exhaustion or write failure can omit details; existing diagnostic-error reporting
and terminal outcome attempts remain. Diagnostic exceptions are caught without
replacing original unittest outcomes. Failure text is the assertion's existing
string, which can itself contain private data: private storage and these bounds
are not content sanitization or a credential-absence/memory-erasure guarantee.
Inspect/redact before exporting any diagnostic text. A detail is auxiliary
evidence, not an authoritative suite count or qualification verdict.

Deferred robustness concerns: event writes can partially succeed before an
OSError; the current fixed classification is PROGRESS_WRITE_FAILED and record/
byte counters advance only on complete writes. A partial JSONL suffix is not a
complete record, and later terminal writes cannot be assumed to restore framing.
No partial-write event was demonstrated in the recorded suite evidence. Also,
event/detail callback exceptions are caught, but observation setup, subcase
sequence bookkeeping and shutdown are not all inside those catch boundaries.
Broader observation-failure containment is a deferred review item, not a claim
that ordinary outcomes were corrupted in an observed run. Neither item has been
implemented here; bounds, activation, unittest delegation and deadlines remain
unchanged.

The recorded `group_intervals` labels `installed_identity_preparation`,
`independent_closure` and `source_bound_exports` originate in
`test_foundation.py:FoundationTests.test` (the corresponding `self.subTest(case=...)`
blocks), not `export_timing.py`. The observer's `instrument().subtest` wrapper
emits SUBCASE_START/SUBCASE_END with one sequence identity per context. The local
summary pairs matching identities and labels and subtracts monotonic timestamps.
These are inclusive context durations, including nested fixture setup, execution
and teardown; CONTEXT_EXIT alone is not an outcome or enforcement proof. They
are auxiliary diagnostics and do not determine required-suite PASS.

Limits: 16,384 records, 4 MiB, 1,024 bytes per record. Normal events reserve 1,024
records/512 KiB for ends/outcomes/terminal summaries. Recorder failures remain
separate from test classification. Absolute exhaustion or storage failure can
still prevent terminal JSONL delivery. A separate private result records normal
observer shutdown; termination may bypass atexit, so its absence is unproven.
The launcher records its own result and observed child launch identity independently.
Synchronous recording/clock overhead and altered Python startup are real timing
limitations. Output remains outside the published compact unittest transcript.

Focused checks: `.venv-orchestrator/bin/python3 -m unittest test_controller_progress -v`.
No dependency installs or test downloads. The documented existing
FREEAGENT_PYTEST_FIXTURE_PYTHON prerequisite remains required. The required run
must use bin/freeagent-test unchanged and compare selected sources before/after.
No proof of independent dependency/read-set attestation, historical cleanup,
protected installation or enforcement is provided. B10 PARTIAL; Stage31D not
authorized. Required verification may be cleared only by an actual passing run.

Development shutdown timing uses the same private activation directory. Only
`controller_entrypoint()` in its own controller root can create
`runner-timing.jsonl`; foreign/copy contexts ignore the diagnostic setting.
The optional recorder loads trusted development source, not project-selected
code. It records deadline creation (with the exact monotonic deadline), observed
stdout EOF and child exit, timeout decisions, signal attempts, wait completion
and final classification. It is limited to 32 fixed records / 32 KiB, within the
existing 1,024-byte record bound. No repeat polling or transcript output is added.
Diagnostic exceptions are contained; classification and termination remain owned
by the unchanged runner decisions. A missing record remains an observation gap.

`observer-shutdown.json` is one exclusive private bounded record whose timestamp
is taken after progress-result publication and progress-FD closure. It is not
proof of interpreter exit, stdout EOF or kernel cleanup. Publication failure
cannot change a unittest outcome. Runner signal events denote attempts; wait
completion denotes reaping, and observed exit is timestamped when noticed,
not when the kernel first exited. Clock calls, synchronous private file writes
and trusted-module loading add overhead. No source, argv, environment values,
credentials or object dumps are recorded. No required-suite attempt has been
performed for this diagnostic change; required verification remains BLOCKED.
