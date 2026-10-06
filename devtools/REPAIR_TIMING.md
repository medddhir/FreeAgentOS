# Fixed four-path repair timing (development only)

Run with the established interpreter, from the repository:

```
.venv-orchestrator/bin/python3 -m devtools.repair_timing --run <fresh-private-0700-directory>
```

This profiles only
`test_intermediate_repair.IntermediateRepairTests.test_unauthorized_repair_paths_block`.
It delegates the existing fixture, its four subcases, graph operations and cleanup
unchanged. There is no production activation or target-controlled selection.
ExitStack restores patches; diagnostic aggregation failures do not replace wrapped
returns/exceptions. A diagnostic failure is reported separately from unittest.

The finite outer diagnostic budget is 1780s: four invocations, each allowing the
existing 150s discovery and up to two 130s tester calls, plus 20s collection per
invocation and 60s setup/collection. This is not a complete fixture worst-case
proof: its initial subprocess.run Git setup has no explicit timeout, and graph
Git calls have their own limits. Inner deadlines/quotas remain untouched. Outer
expiry/overflow terminates/reaps the owned harness process group; it does not
establish cleanup of all separately sessioned sandbox descendants.

Reuse export_timing.Recorder's 16384-record/4MiB bounds, 1024-byte records and
512-record/512KiB terminal reservations. Ten fixed aggregation labels, at most
four owned workspaces/twelve sandbox launch observations, four case intervals,
one group interval, and at most ten aggregate records produce at most twenty
sidecar records; summary and stdout capture are separately bounded at 64KiB.
Repeated Git/wait operations aggregate rather than recording every read/hash.
No source contents, environments or exception messages enter timing summaries.

Phase elapsed and CPU totals are inclusive and overlap: do not sum them.
Exclusive instrumented elapsed subtracts only directly nested wrapped intervals,
not all filesystem/Git/kernel work. RUSAGE_SELF includes process CPU, potentially
other existing threads. RUSAGE_CHILDREN charges reaped child CPU when waited and
can include propagated descendants; it is neither live-child nor cgroup accounting.
Unobserved descendants and host wait/contending workloads are not measured.
Synchronous clocks/rusage/dictionary aggregation and private writes add overhead;
sidecar io_ns measures only recorder writes. Import/startup/wrapper collection sit
outside measured unittest group time. Mocked accounting tests are not kernel proof.

The prepare observer retains only paths/device/inode identities of workspaces
returned by production preparation; post-test absence is scoped evidence only.
Recorded process births/groups do not prove historical or global cleanup.
Source identities and log hashes are recorded externally, not a qualification.
No retry or required-suite execution is built into this harness.
