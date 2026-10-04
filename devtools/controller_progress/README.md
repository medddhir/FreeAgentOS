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
