# Fixed export-group development timing

This tool is diagnostic preparation only. It neither qualifies execution nor
changes the production runner, assurance rules, source reads, or test membership.
Invoke with the established controller interpreter:

```
/root/agent-stack/.venv-orchestrator/bin/python3 /root/agent-stack/devtools/export_timing.py
```

The fixed child invokes `ExportCases().cases()` and delegates each instrumented
operation to its original implementation. Staged source-only hook modules are
not imported. There is no target-project diagnostic switch or selectable group.
Private temporary fixture storage is separate from the repository. The parent
records child PID/start ticks/group/session, reaps its owned child and closes its
output descriptor independently of wait failure. None of this establishes absence
of descendants or resources from an earlier invocation with unknown identities.

The JSONL sidecar permits 16,384 records, 4 MiB total, 1,024 bytes per record,
100-character fixed-format labels and 64 nested spans. Aggregate bookkeeping has
128 keys and 1,000,000 calls. Captured process output is bounded to 16 KiB. A
180-second development containment deadline does not alter the required suite's
420-second deadline or any worker policy. Sidecar failure stops recording without
skipping original operations/finalizers; the diagnostic result then fails.

Spans distinguish cases, source-fingerprint-labelled RHS subcases, fixture setup
and teardown, identity construction, inventory planning/capture, dependency
capture/recheck, explicit analysis and prerequisite-triggered fresh analysis.
Nested intervals are inclusive and must not be added as disjoint costs. Source
read/hash leaf timings are accumulated separately; no observation is replaced by
a cached diagnostic result. Reports contain no source text or raw exception text.

## Single authorized observation

The invocation on the pending N3-S1 tree at baseline
`48e44687fb0c4a0bcc9fa2ad96061080c2d717b0` wrote private evidence under
`/tmp/freeagent-export-timing-au_blwn0`. It completed in 56.879 seconds parent wall
time (56.699 seconds child group time). No test exception was reported, but the
recorder reached its 16,384-record limit: diagnostic exit 1, `SIDECAR_BOUND`.
No retry or limit increase was made. Seventeen of eighteen case ends were
recorded; the last case's missing end is a recording limitation, not evidence
that it hung. Final source-read/hash aggregates and group-end events are missing.

Captured setup intervals: 277 independent fixtures, 39.384 seconds wall and
34.945 seconds process CPU; median 0.136 seconds, p95 0.183, maximum 0.445.
Explicit analysis: 252 calls, 5.406 seconds; prerequisite analysis: 268 calls,
5.828 seconds. Prerequisite analysis is included in prerequisite spans; dependency
and inventory phases overlap setup. Thus fixture preparation dominates captured
intervals, but precise hashing versus filesystem versus scheduling costs remain
unresolved. The longest captured case, comprehension shadowing, took 12.039
seconds; this is aggregate case work, not proof of an anomalous individual test.

The sidecar wrote 2,457,668 bytes; measured write calls cost 0.180 seconds.
Serialization, clocks, wrappers, fingerprinting and bookkeeping add unisolated
overhead. There is no controlled uninstrumented comparison. Private TMPDIR and
unrecorded host contention also limit comparison with historical runs.

The owned child was reaped, its pipe closed, its PID subsequently absent, and the
owned fixture directory empty. No unexpected descriptor numbers remained in the
child's final inventory. These are current invocation observations, not proof of
historical cleanup or global zero residuals. The three pending N3-S1 file hashes
remained unchanged. Required verification remains BLOCKED and was not rerun.

## Recommendation after the first, incomplete invocation (superseded)

Reduce nested diagnostic event volume and reserve terminal records within the
existing record/byte bounds. Keep every case/subcase boundary and aggregate nested
phase costs per case, including source-read/hash totals before the next case.
Acceptance requires all eighteen case ends and the group end, complete summaries,
no sidecar-bound failure, unchanged witnesses/assertions/fresh observations and
unchanged pending source hashes. A further timed invocation requires separate
authorization. No test optimization is justified by missing leaf measurements.

## Completed bounded profile

The follow-up correction aggregates repeated PHASE, SETUP and TEARDOWN intervals
and nested fixture lifetimes; only case/group and fingerprinted RHS subcase
boundaries emit individual events. Aggregate keys are bounded to 128 per case,
then flushed and cleared. Every call still executes its original operation.
Counts, inclusive wall/process CPU durations, maximum duration and exception
counts are emitted per case. Expected negative-path exceptions are not test
failures. CASE/GROUP outcomes separately describe whether the test returned.
Normal events leave 512 records and 512 KiB reserved for terminal events and
summaries. True exhaustion or I/O failure still rejects diagnostics; reservation
cannot guarantee delivery after storage failure or exhaustion of the absolute
bound. The independent child result distinguishes recorder failure from test
exceptions. No production transcript or runtime setting was changed.

Seven focused harness tests passed via
`.venv-orchestrator/bin/python3 -m unittest test_export_timing -v` (0.010s),
including recording exhaustion with retained case/group exception ends, fresh
call delegation, aggregate flushing, short writes and independent pipe closure.

One authorized invocation of the command above produced private evidence at
`/tmp/freeagent-export-timing-dayvf2lu`: group RETURN/PASS, 18/18 case RETURN,
111 RHS subcase completions, exit 0, 61.114 seconds group wall and 55.424 seconds
process CPU, 61.362 seconds wrapper wall. Recording used 644 records and 127,681
bytes, no recorder error or output overflow. Final source-read/hash summaries
were complete. Its sidecar SHA-256 is
`a2f4581589d0012fa2c6853b8ebdbb0e5c7782b22bd3ab88565a1db8e3023239`.

Inclusive breakdown: 305 independent fixture setups 45.308s; nested installed
setups 37.569s; nested inventory setups 12.654s. Explicit analysis 280 calls
6.783s; prerequisite fresh analysis 296 calls 7.061s. Identity construction
305 calls 0.906s; inventory planning 1,220 calls 7.929s; inventory capture 610
calls 4.209s; dependency capture 1,756 calls 14.206s; dependency recheck 1,145
calls 10.130s. Leaf timings: source reads 206,682 calls 3.981s; source-policy
parse/hash 189,297 calls 1.275s; source identity 3,321 calls 6.267s; JSON identity
hash 9,239 calls 3.527s. Parent/child phases overlap and these totals are not
additive. Fixture lifetime includes the yielded test body, so lifetime totals
must not be described as setup. Subtracting nested installed setup from independent
setup gives only the outer layer's elapsed residual (7.739s), not pure exclusive
CPU or an isolated operation cost.

The repeated setup is `IndependentClosureCases.fixture` nesting
`InstalledIdentityCases.fixture` and `InventoryCases.fixture`: each invocation
stages an inventory, copies package bytes into a fresh dependency tree, captures
identities and publishes synthetic receipts, then rewrites the tree for the
individual export witness and reconstructs pinned metadata. All 305 independent
setups remained independent. The largest setup was 0.363s, so the evidence points
to accumulated preparation rather than a single demonstrated stall. The largest
case was comprehension shadowing (13.499s); unused definition-time effects took
11.669s. No exact file-write versus persistence cost was separately instrumented.

Measured sidecar writes cost 0.004670s; serialization, wrapping, clock calls and
per-call bookkeeping are not separately controlled. No timing comparison proves
the original required timeout cause. Preflight saw no matching test jobs or known
fixture mounts/directories; unknown historical identities prevent retrospective
cleanup proof. The child PID/group/session 1947956, start ticks 20132839, was
reaped; its pipe closed, fixture directory empty, PID absent and unexpected FD
inventory empty. Three pending N3-S1 hashes remained unchanged.

No safe test optimization is established by these inclusive measurements alone:
removing intermediate captures or borrowing receipts/proofs would change the
fresh-observation contract. The next recommended action is one separately
authorized required-suite diagnostic run with bounded private case-start/end
progress, unchanged test membership, deadlines and capture limits. Acceptance:
progress identifies any interrupted test by recorded start without end; final
outcome and cleanup are retained; no sidecar overflow; unchanged source binding;
required RESULT=PASS is still necessary to clear the gate. No required-suite run
or optimization occurred here. B10 remains PARTIAL and Stage31D unauthorized.
