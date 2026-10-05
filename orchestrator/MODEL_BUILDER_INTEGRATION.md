# Smallest real-model builder integration

2026-10-05. Design inspected at `ce6fed1c613ccd359cb16b36e0de91480dfcaa5c`,
`main`, initially clean. No application imports, providers, agent launches,
tests, installations or generated projects were executed. This document is a
plan, not authorization. FreeAgentOS builds software generally; websites are
its first bounded profile. Local preparation/export has no FreeAgentOS fee;
third-party inference can have costs and availability limits.

## Data and authority path

```text
Trusted confirmed brief + pinned guidance + owned snapshot
  -> bounded request (guidance/context are data)
  -> synthetic response now / contained provider transport later
  -> UNTRUSTED text envelope
  -> strict proposal parser + entire-batch validation + fresh base binding
  -> trusted FileTools(website_policy), four fixed paths only
  -> fresh Session snapshot -> protected structural checks -> user revision
  -> new snapshot/checks -> exclusive Session.export -> PREPARATION_ONLY

Separate authorities, neither granted by proposal text:
  generated-code execution -> existing execution qualification [disabled]
  preview/browser launch -> website.launch_live [always rejects]
```

The next implementation supplies synthetic provider responses only. Its PASS
will mean deterministic proposal processing, never a live model qualification.

## Existing-component reality

References are repository-relative files/functions, not upstream guarantees.

| Component / source | Implemented behavior | Qualification / missing seam |
|---|---|---|
| `foundation.py:Configuration`, `local_endpoint`, `adapter_environment`, `discover_launcher` | Controller-selected launcher (default `claude-free`), loopback HTTP/HTTPS endpoint, optional named environment credential reference mapped to ANTHROPIC_AUTH_TOKEN | Configuration is not credential delivery/revocation or transport qualification; no credential values inspected here |
| `roles/model_profiles.py:REGISTRY`, `model_command`, `command_identity` | Fixed role/profile choices and command identity. Coder/fixer use stream-json; planner/reviewer use JSON with a schema. Registry labels CONFIGURED | No website proposal profile; coder cannot accept `schema=`. Capability flags do not qualify a served model |
| `roles/worker.py:run_worker`, `_run_worker_impl`, `_run_inner`, `_validate_evidence` | CLI subprocess tree, namespace/cgroup controls, bounded streams, cleanup validation, optional gateway attribution | A tool-capable agent process, not text-only HTTP. No normal-user supervisor handoff; cannot bypass its controls to obtain text |
| `roles/planner.py:_shape`, `planner_node`; `roles/read_policy.py:no_file_tool_flags` | Existing schema-output envelope handling and a no-tools/restricted/bare/strict-empty-MCP command configuration | Reuse the transport pattern, not the planner's planning schema or permissive compatibility parsing as the proposal validator |
| `roles/activity.py:ActivityCapture`; `roles/model_attribution.py:GatewaySession`, `safe_attribution`, `route_observation` | Bounded Claude Code NDJSON metadata; private request-bound route observations where available | NDJSON result is not upstream HTTP/SSE or proof of successful writes. Requested, routed and served identities remain distinct |
| `roles/coder.py:coder_node`; `roles/broker_session.py:prepare_session`, `BrokerSession` | Existing model makes brokered tool calls under a sealed policy; stdout is implementation summary | Does not return a validated website file-change proposal; worker success is not independent project acceptance |
| `graph.py:build_website_graph`; `website.py:workflow_graph`, `RecordedAdapter` | LangGraph scaffold/code/revise/check/export path | Exact RecordedAdapter type gate; no variable-response adapter. Do not smuggle live calls into a recording |
| `website.py:Session`, `Snapshot`, `guidance`; `roles/file_tools.py:FileTools`, `_write`; `roles/read_policy.py:website_policy` | Owned 0700 staging, root identities, bounded broker writes, protected checks, fresh snapshots, exclusive fixed export, pinned guidance hashes | Recorded preparation qualified for documented source/installed runtimes; same-user broker safety is not hostile-process isolation |
| `website.py:launch_live`, `preview`; `cli.py:_recorded_website` | Every live launch rejects EXECUTION_QUALIFICATION_UNPROVEN; preview DISABLED; CLI reports recorded/model_calls NONE | These statements must remain true for the recorded CLI. New synthetic adapter evidence needs its own honest status |
| `privilege/build_closure.py:StagingClosureRegistration.candidate_prerequisite` | Fresh STATIC_METADATA_VERIFIED required, otherwise POLICY_REJECTED; even success is qualified=False, installed_observed=False, execution_enabled=False | B10 protected publication/credentials and real integration incomplete; staging cannot enable a supervisor |

`STAGE25_ROUTE_ATTRIBUTION_HANDOFF.md` records external FreeLLMAPI server 0.2.1,
image revision label `e4a47f203dba3b610dc180f628d3e821abbaf564` and compiled
installation evidence, explicitly not a verified gateway source commit. The
tracked worker knows health HTTP and CLI environment wiring; no general
inference HTTP client is implemented here. Historical gateway/client evidence
must not be described as newly qualified or pinned production source. The
activity parser identifies the Claude Code 2.1.284 NDJSON contract; this
inspection did not identify today's installed executable bytes.

Worker model defaults (`roles/worker.py:WORKER_POLICY`) are wall ceiling 240s,
CPU time 180s, CPU quota/period 100000/100000 microseconds, memory 1536 MiB,
swap 0, processes 64, descriptors 256, file size 128 MiB and output 256 KiB.
`coder_node` requests 180s; `roles/lease.py` can grant one 60s progress grace
only for eligible streaming coder/fixer calls. Outer emergency time also
includes collection/termination allowance. These are worker lifecycle limits,
not model tokens, gateway request counts, price caps or end-to-end application
latency guarantees. No monetary/token cap was found in the inspected transport.

## What can be reused and what must change

The catalog in `WEBSITE_V1.md` already accounts for gateway/framework/browser
candidates. Reuse LangGraph, existing provider-command construction, FileTools,
website policy, guidance, Session snapshots/checks/export. Impeccable selection
is pinned at `e103efe779e2dd01274dabae83531fef00bf2563` with license/notices and
hash checks (`website.py:guidance`); it supplies design text, no tools or rights.
Defer LiteLLM and external coding/orchestration agents: no missing capability
here requires another gateway or framework. Their catalog entries are
candidates, not executable integrations or verified license/provenance claims.

The website is not an arbitrary generator yet. `Session.checks` parses HTML,
requires exactly one title/h1/button with confirmed text, exactly one local CSS
link and JS script, rejects certain attributes/URLs/elements, and requires all
four files nonempty. This permits variable HTML layout, CSS, JS and README
within those constraints; it does not require the recorded template verbatim.
It is neither comprehensive HTML security analysis nor JS/CSS functional,
network or rendering verification. Exported source is untrusted software.

Reuse blockers are concrete: `workflow_graph` exact-type restriction,
RecordedAdapter tuple recordings and sequential immediate writes, hard-coded
`recorded=True` in checks/evidence, and recorded CLI `model_calls=NONE`.
Introduce a separately named proposal adapter and shared trusted application
seam; keep the RecordedAdapter and recorded CLI behavior intact. Do not label
synthetic proposals as provider-produced. Checks are controller structural
results; adapter provenance belongs in separately bound evidence and export
status must remain PREPARATION_ONLY. Any change to evidence shape/contract must
update exact equality checks in `Session.export` consistently and retain tests
against forged evidence; provenance must not be taken from the response.

## Single next implementation milestone

**Synthetic provider-response website proposal adapter, end to end through the
existing graph, revision, broker, checks and complete export.** No live provider
wiring or new CLI command is necessary for this increment. Likely scoped files:
`website.py`, a narrow proposal parser module, `graph.py`'s existing website
factory seam, focused proposal tests and website documentation. Ordinary coding
profiles, supervisor code, worker policy and recorded CLI stay unchanged.

Proposed strict response contract, version 1 (new design, not existing support):

```json
{"version":1,"run":"controller-issued","profile":"website-static-v1",
 "phase":"code","contract":"controller-issued","base_snapshot":"sha256",
 "files":[{"path":"index.html","text":"complete UTF-8 file contents"}]}
```

All metadata must exactly match the controller request. It is correlation, not
an authorization token; fresh Session identity and snapshot comparison grant
application eligibility. Code requires exactly the four allowed files;
revision requires 1..4 unique allowed paths and actual changed bytes. Operations
are full replacements only; no commands, deletes, tool requests, limits,
credentials, URLs as transport destinations, or success/evidence fields. This
is separate from ordinary coding profiles.

Validation before any write:

1. Enforce raw response at most 64 KiB, UTF-8, one JSON object, no markdown or
   trailing material, duplicate keys, unknown fields, non-finite numbers or
   wrong scalar types. Bound nesting/collection work; use schema-shaped limits
   rather than recursive arbitrary-object traversal.
2. Validate all bindings and exactly permitted paths; each text at most 8,192
   UTF-8 bytes, total resulting project at most 32,768 bytes, at most four writes.
   Check existing content policy for every replacement and retained file. Do
   not relax benign-wording restrictions to accommodate generated text.
3. Revalidate the base snapshot/root; construct the complete proposed immutable
   file set in memory and run the same protected structural rules against it,
   before the first broker write. Keep proposed-byte checks distinct from
   `Session.checks`, which requires an actual fresh filesystem snapshot. Reuse
   a shared pure structural predicate instead of inventing forged Snapshot
   equality. Recheck actual snapshot/checks after brokered application.
4. Apply only via FileTools(website_policy) under trusted coder/fixer role.
   Recheck binding at phase boundaries. Never instantiate rights from JSON.

Proposed request cap: 48 KiB including metadata, bounded brief/guidance and at
most the 32 KiB current project. This is a separate proposal-request limit,
not a silent increase to RecordedAdapter's existing 8 KiB context cap. No more
than two synthetic responses per run (one code, one revision), no automatic
retry/repair loop. Raw schema-output transport remains under the worker's
existing 256 KiB capture ceiling; proposal extraction then enforces 64 KiB.
Whole-file data plus JSON escaping may exceed this cap and must reject, not
truncate. Tests must establish these bounds before future live use.

Batch validation is not atomic filesystem application: each broker write is
atomic individually. A later write/root/check/export failure retains an
incomplete run; stop, no subsequent phase or success/export receipt, fixed safe
failure code and truthful NOT_CREATED/RETAINED/UNPROVEN observation. Do not
silently rollback, delete artifacts or reuse the failed run. A partial export
must never be reported complete. Successful synthetic status should explicitly
say synthetic proposal preparation, provider_calls=0, structural=PASS,
functional/browser/execution=UNPROVEN, preview=DISABLED. No model success claim
or response-provided provenance survives as check evidence.

Acceptance criteria:

- Synthetic success produces non-template supported code plus meaningful user
  revision, fresh bound snapshots and exact-byte four-file export/receipt.
- Entire invalid batch causes zero proposal writes: duplicate/unknown fields,
  forbidden paths, traversal, wrong run/phase/contract/base, overbounds, invalid
  content, malformed JSON and structural rejection.
- Injected mid-write failure retains partial artifacts honestly and cannot
  advance/export; root replacement and stale/foreign snapshots still reject.
- Guidance/proposal attempts to grant tools, limits or approval fail; forged
  checks/status cannot export. All live launches continue to reject.
- Existing `test_website.py`, `test_website_cli.py`, broker/read-policy/snapshot
  regressions retain behavior; added synthetic provider tests exercise graph
  application, not only parser constants. Use the documented pytest fixture
  and required freeagent-test/source binding in the implementation milestone.
  Synthetic PASS is not live qualification; no calls are authorized here.

## Applicable gates and future live authorization

Text parsing and controller-side allowed writes do **not** invoke B10's
supervisor gate. The qualified recorded path proves those components can
operate without root; this new adapter still needs deterministic verification.
Obtaining text through the existing Claude CLI does invoke `run_worker` and its
containment/evidence checks even when tools are disabled. No naked subprocess,
retired `bin/freeagent-code`, or ordinary-user fallback is acceptable. A normal
user cannot currently obtain equivalent worker controls through the unfinished
supervisor. B10 protected installed identities/dependency publication and
credential lifecycle, then real worker/supervisor integration and qualification,
are concrete dependencies of that future route, not of synthetic parsing.

For a later explicit owner-authorized live experiment, propose reusing the
schema JSON transport shape used by planner with `no_file_tool_flags`, an exact
controller-selected configured planner-compatible profile, empty MCP, no
project working directory and a bounded supplied snapshot context. Keep
transport role planner separate from broker application role coder/fixer;
never falsely select coder structured-output capability. Do not call
`planner_node` to interpret a website proposal. Resolve envelope formats once,
strictly, before the proposal validator. Review exact launcher/client bytes,
no-tool behavior, cancellation and credential exposure first; flags do not
turn a CLI into inherently text-only trusted transport.

Proposed later authorization must name account/runtime/launcher/gateway/profile,
credential **reference** and data disclosure, explicitly permit worker setup,
and approve exactly one run: at most two logical invocations, 60s each without
streaming grace, no retries, one code/one revision, response/request bounds above.
Reuse existing worker quotas; label outer cleanup allowances separately. These
are proposed limits, not new policy or permission. A CLI can issue multiple
upstream requests internally: two invocations are not a two-provider-call bound.
A reviewed gateway/client enforcement seam must cap actual upstream attempts
and output tokens before an exact-call budget can be claimed.

Proposed spending allowance: zero paid expenditure, user-supplied explicitly
non-billable route, at most 4,096 output tokens per upstream request and two
upstream attempts total. Current source does not implement those token/request
or price guarantees. If the route cannot enforce the reviewed bounds, live
qualification remains blocked pending a separate cost/attempt authorization and
budget-control decision; timeouts alone cannot prevent billing after dispatch.
Credentials stay in controller transport memory via the existing named reference,
never prompt/project/proposal/export/log data. Verify credential delivery and
scope without printing values; no production configuration changes are assumed.

Generated-code execution remains a separate qualified-backend action. Preview
and browser launches require their own fixed runtime, network, resource,
filesystem and cleanup contracts and explicit future authorization. A text
response, structural PASS, export or installed recorded CLI success supplies
none of those qualifications. B10 remains PARTIAL; Stage31D unauthorized.

Material unresolved decisions: exact live account/backend and launcher bytes;
whether the configured planner-compatible gateway delivers the required schema
envelope; enforceable upstream attempt/token/free-route budgets; credential
provisioning/revocation; and scope of later functional/browser acceptance. None
blocks the synthetic proposal increment, and none is resolved by this plan.

## Implemented synthetic proposal preparation — 2026-10-05

The synthetic-only seam is now `website.py:SyntheticProposalAdapter(code,
revision)`, holding exactly two finite byte responses. There is no callback,
provider transport or live command. Trusted controller/test code creates a
`Session(brief, owned_parent, preparation="synthetic")` and binds both responses
to its run, contract and expected phase snapshots; the existing website graph
reads and verifies the actual snapshots at each phase. Future contained live
transport would obtain each response after `proposal_request(session, phase)`
and then reuse `validate_proposal` and the trusted application/check sequence;
no live adapter is enabled by the current graph type allowlist.

Version 1 uses exactly the response fields illustrated above and exactly
`path`/`text` entry fields. The file operation is full replacement implicitly;
any operation/tool/command/authority/status field rejects. UTF-8 bytes only,
64 KiB response, at most three structural nesting levels and six containers,
four unique paths, 8,192 bytes/file and 32,768 bytes/project. Duplicate JSON
keys, floats/nonfinite values, booleans as version, unsupported encodings and
unpaired escaped surrogates reject. `proposal_request` is bounded to 48 KiB;
recorded context limits are unchanged. Code supplies all four files; revision
supplies 1..4 replacements and changes actual bytes. No retry is provided.

`structural_checks` is the unchanged shared HTML/nonempty-file predicate,
used on the complete merged proposed bytes before writes and again by
`Session.checks` on an actual fresh snapshot. Policy content filtering covers
all replacements and retained bytes. Broker writes remain individually atomic,
not a batch transaction. Failure blocks further adapter phases; a synthetic
export additionally requires completed revision/application, so structural
PASS on partial retained files cannot suffice. `ProposalError` distinguishes
VALIDATION/APPLICATION and exposes fixed safe evidence with observed RETAINED
or UNPROVEN, cleanup_attempted false and no live qualification. No artifacts
are deleted or rolled back.

Synthetic graph status is SYNTHETIC_PREPARATION_COMPLETE, model_calls NONE,
recorded false, synthetic true; snapshot-bound structural checks and the
PREPARATION_ONLY export receipt remain non-qualifying. Recorded default Session,
CLI, checks and receipts remain compatible. JS/CSS are not interpreted, rendered
or proven network-safe; unsupported structural HTML rejects. This is not a
sandbox for executing exported files. No B10, provider or launch gate changed.
Verification results will be recorded after the single authorized required run.

### Verification evidence — BLOCKED on required verification

Focused checks passed: 58 proposal/website/CLI/read-policy tests in 26.584s,
plus 16 graph/model-profile/controller-progress tests in 13.923s. The new eight
proposal cases passed, including partial-revision structural PASS being unable
to export a failed run.

Exactly one required `bin/freeagent-test` attempt used the established runtime,
the documented existing pytest/package fixtures and the unchanged development
progress observer. Actual discovery command:
`.venv-orchestrator/bin/python3 -m unittest discover`. Result: **580 tests,
356.119s, one failure; RESULT=FAIL, EXIT_CODE=1**, wrapper 357.445813897s.
No outer timeout or output truncation. Sole failure: the unchanged
`test_resource_sandbox.py:204` disk-ceiling fixture returned its six-second inner
TIMEOUT/124 instead of ENOSPC text. Its preceding cleanup assertion passed.
This does not demonstrate proposal-code causation or resolve historical timing
uncertainty. No retry, fixture/enforcement correction or limit change followed.

Private evidence directory: `/tmp/freeagent-synthetic-proposal-required-oalas0qw`.
Required-log SHA-256:
`bf82421b392cbb48d74305d3bd84e565912d9201a16769f772dc8e948cd826b0`.
Selected before/after manifest SHA-256 (identical, 180 files):
`6e76895ac27c82821c92897bbf17a26dfc12c0511456a6184446ce29baa1a0a8`.
Progress SHA-256:
`be52a42b0b48a0ba2543dcb118b11aad281dc530c01cdb4d073f8ad7e2fbb459`.
All selected bytes matched through the invocation. Selection covers tracked
Python/native/config/lock/bin/guidance files and relevant new proposal test and
integration/website docs; not every data artifact, runtime dependency or read.
These result paragraphs are subsequent documentation-only additions.
Observer: 584 completed intervals (includes nested synthetic unittest fixtures),
no unmatched intervals, diagnostic_error null, 3,676 records / 532,353 bytes.
The original 580-test unittest summary determines suite failure; observer totals
are not controller failure counts. Runner direct child reaped and its launch
PID currently absent; bounded current scanning found no matching verification
jobs. This is not independent historical descendant/resource absence proof.
Implementation remains **unverified by the required contract**, uncommitted and
unstaged. Synthetic-only scope; B10 PARTIAL; STAGE31D_AUTHORIZED: NO.


### Current required verification with bounded disk phases — 2026-10-05

Following the independently reviewed proposal source and the separately
approved diagnostic markers, exactly one further required invocation passed:
`/root/agent-stack/bin/freeagent-test`, cwd `/root/agent-stack`; actual discovery
command `/root/agent-stack/.venv-orchestrator/bin/python3 -m unittest discover`.
Authoritative result: **584 tests, 352.793 seconds, OK, RESULT=PASS,
EXIT_CODE=0**. Wrapper duration: 354.968686007 seconds. Captured runner output:
8,869 bytes, no timeout or output truncation. The unchanged runner retains its
420-second deadline and 64 KiB capture rejection; wrapper timing is not an exact
measurement of runner deadline headroom. The six-second inner disk deadline,
workload, backing checks, quotas and cleanup assertions were preserved.

Activation used the existing development observer via
`PYTHONPATH=/root/agent-stack/devtools/controller_progress` and
`FREEAGENT_CONTROLLER_PROGRESS_DIR=/tmp/freeagent-proposal-phases-required-f0fcwppr`.
Existing documented test prerequisites were
`FREEAGENT_PYTEST_FIXTURE_PYTHON=/tmp/freeagent-rpt1-pytest-u56y3cq4/venv/bin/python3`
and
`FREEAGENT_PACKAGE_FIXTURE_PYTHON=/tmp/freeagent-package-runtime-s05jvirn/venv/bin/python3`.
No dependency acquisition, runtime replacement or live provider call occurred.
Normal inherited umask was preserved. Ten affected policy-identity/packaging
checks passed before the invocation (6.891 seconds).

Private evidence directory: `/tmp/freeagent-proposal-phases-required-f0fcwppr`.
Required-log SHA-256:
`f061e732df099a62589934e454c1c5b4fa9f8681a1fc8052a07921dbf6836520`.
Selected source-before/source-after SHA-256 (identical):
`3f4446ca79feb63a04eb75d812ca8d90ae290d93466ce02e95a8a5420185e517`.
Progress SHA-256:
`c1ae8589b8bc944b7c07e4ae24af1cabe241e2a73716a0f00b7a6fc2a4d922ad`.
Invocation/configuration identity:
`2e18076b614dcf8b2682d08e9c64645e7b5a9c6d08320121828f54ae838beb33`.
Coverage manifest identity:
`7f36e5d92c1c56943c307dce92724ce1a1eccf3ec465635a52a3e248a022ddc9`.

The 181-file selection covers tracked Python/TOML/lock/C sources, bin/ and
website guidance, plus the explicit proposal documents and new proposal/phase
tests. This extends the earlier 180-file selection with `test_disk_phases.py`.
`coverage.json` enumerates included and excluded tracked paths. It excludes
other untracked/ignored material, installed/editable dependency bytes,
interpreter/base binaries and actual runtime read-set evidence. This is
selected-source binding, not independent dependency/read-set attestation.
All selected bytes also matched current files before these result-only
additions to this document and WEBSITE_V1.md. Proposal implementation/tests
matched the independently reviewed snapshot; documentation before this run
also matched that snapshot. No implementation/test edits followed the run.

Observer completion: 588 matched test intervals (includes four intentional
nested synthetic cases), 3,705 records / 536,432 bytes, diagnostic_error null,
no unmatched test or subcase intervals, PROCESS_END recorded. Intentional
nested FAIL/ERROR/SKIP outcomes are not controller-suite failures; the original
584-test summary and runner markers determine PASS. Synchronous observer and
phase-marker overhead was not independently isolated.

Disk phase evidence remained CHILD_REPORTED, authority NONE: 18 records;
reservations 1–4 completed, reservation 5 returned ENOSPC, then its bounded
fallback returned ENOSPC. Every observed before-marker had an after-marker;
last record was demand 5 write_error/ENOSPC, reporting 268,427,264 covered bytes.
Observed workspace availability was 268,427,264 bytes before and zero after.
CPU delta was 201,008 microseconds (126,560 system); 3/4 periods throttled.
Memory current/peak were 269,512,704 / 285,868,032 bytes; observed reclaim,
memory-event and pressure deltas were zero. Before/after sampling cannot exclude
unobserved transient behavior or establish historical timeout causation.
Diagnostic bounds remain 40 records / 8,192 bytes; conservative worst case is
32 records / 6,144 bytes. No allocation/enforcement correction was made.

Existing disk cleanup/full-space/resource-hit assertions passed. Runner and
unittest recorded PIDs were absent afterward, owned launch groups were empty,
and bounded self mount observations found no matching fixture mounts. No
unowned cgroups were inspected or mutated. These current observations do not
prove historical cleanup or global descendant absence.

Current deterministic preparation verification passed; the earlier required
failure and unresolved historical timing/cleanup limitations remain recorded
above. Work remains uncommitted/unstaged; live model, execution, functional and
browser qualification remain unproven. B10 PARTIAL; STAGE31D_AUTHORIZED: NO.
