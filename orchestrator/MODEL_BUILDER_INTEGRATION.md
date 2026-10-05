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


## Fixed text-inference preparation and admission — 2026-10-05

`roles/worker.py:prepare_text_inference` now prepares one declared invocation
of `text-inference-v1`. It accepts only the existing website request shape,
checks bounded fields/collections before serialization, produces canonical
sorted compact UTF-8 JSON (48 KiB maximum), and hashes it before any send.
The immutable plan binds request, invocation ID, declared executable/runtime
digests, credential reference, authoritative policy identity and the complete
fixed profile identity. These declared hashes are not observed runtime proof.
No request is sent, no credential is read and no authority is granted by a plan.
The worker/profile sources are included in source-bound policy identity; old
policy-bound records are not silently treated as identities for this change.

The reserved executable is `/runtime/bin/claude-free`, with fixed existing
no-file-tool flags, permission mode, JSON output and object-schema arguments;
request text occupies only the final prompt data argument. This intended path
is not an installed, sealed, pinned or qualified executable. Existing configured
`claude-free-default` describes the intended compatibility profile, not served
model identity or qualification. Client flags remain compatibility requests,
not independently enforced restrictions. The proposal validator remains the
separate mandatory whole-response validator before any broker writes; this
milestone does not connect the plan to workflow application or a live adapter.

Fixed resource configuration reuses worker policy/lease contracts: 60 seconds
with no progress grace, 1-second termination grace, CPU quota/period 100000/
100000 microseconds, CPU time 60 seconds, memory 1536 MiB, swap zero, processes
64, descriptors 256, file-size 128 MiB and response capture 64 KiB. Overrides
for this profile reject. Request serialization/field bounds and admission
rejection are active local controls. Resource/response limits are prepared
configuration: this profile never enters the existing execution lifecycle yet.
At most one CLI invocation is specified per plan; currently zero launches are
possible. Durable consumption of a future invocation ticket is not implemented,
and plans are reusable data, not one-shot authority. Upstream request counts,
retries, tokens and cost remain unenforced; CLI-invocation limits do not cap them.

`text_inference_environment` constructs only fixed PATH, HOME, LANG, LC_ALL and
loopback ANTHROPIC_BASE_URL values. It never copies `os.environ` or resolves a
credential reference. ANTHROPIC_AUTH_TOKEN is the sole additionally declared
credential delivery key, but no delivery producer exists for this profile.
References use the existing configuration naming contract; credential values
never enter plan requests or evidence through this code. Existing ordinary
worker environment behavior is unchanged; it is not used for this profile.

Mandatory requirements: protected runtime identity; exclusion of caller
repository and unrelated secrets; narrow credential provisioning; independent
file/tool/command restrictions; applicable qualified activation; and bound
cancellation/cleanup. Neither Linux authentication, staging registration,
recording approval, model output, an evidence dictionary nor a boolean satisfies
these requirements. There is no legitimate existing positive-admission producer
for them. Consequently public `run_worker`, `_run_worker_impl` and `_run_inner`
reject both this profile and its reserved executable before gateway health,
credential environment delivery, cgroup setup or subprocess launch, using the
fixed `TEXT_INFERENCE_QUALIFICATION_UNPROVEN` error. Cleanup remains UNPROVEN in
that generic rejection evidence; no cleanup is claimed or needed as a result
of a launch that never occurred. Direct commands under ordinary profiles retain
their existing lifecycle except the new reserved executable cannot evade this
gate by switching its profile label.

Deterministic tests exercise actual Session request production, canonical
binding, bounded malformed inputs, synthetic environment leakage prevention,
fixed argv, changed declared identities, all three admission entry points,
forged/staging/stale claims, override rejection, no lease grace, existing cleanup
evidence rejection and ordinary-worker delegation. No positive admission test
was added: no existing legitimate authority seam can supply it. Synthetic
claims cannot become a production bypass. Existing worker cancellation tests
remain required regressions; they do not prove cancellation for a sealed
text-inference runtime that has not been implemented.

Single next integration dependency: implement the protected text-inference
provisioning/evidence producer inside the existing worker/supervisor handoff,
with independently checked runtime visibility and action restrictions, scoped
credential delivery, exact invocation consumption and cleanup/cancellation
binding. B10 protected publication/credential and real consumer integration
remain prerequisites where applicable. No parallel launcher or weaker ordinary-
user fallback is proposed. Only after that producer, runtime/launcher identity,
gateway egress/data disclosure and enforceable provider budgets are reviewed
could a separately authorized one-invocation live qualification be proposed.
This milestone does not authorize it. B10 PARTIAL; STAGE31D_AUTHORIZED: NO.


### Verification result — BLOCKED, 2026-10-05

Focused synthetic/affected checks passed: 42 tests in 9.635 seconds, followed
by seven final admission-guard/ordinary-worker checks in 0.437 seconds. Exactly
one required `/root/agent-stack/bin/freeagent-test` invocation then ran the
established controller runtime (`-m unittest discover`) with the unchanged
progress observer, documented existing pytest/package fixtures and disk-phase
diagnostics. Authoritative result: **589 tests in 342.765 seconds,
FAILED (failures=2), RESULT=FAIL, EXIT_CODE=1**. Wrapper 343.917844654 seconds.
No required deadline timeout occurred, but **OUTPUT_TRUNCATED=true**: failure
assertions printed the enlarged worker source and exceeded the preserved 64 KiB
capture bound. Overflow remains fail-closed; no reporting limit was changed.

Demonstrated implementation regression: `prepare_text_inference` imports
`privilege.policy` from production `roles/worker.py`. Existing
`test_privilege.py:PrivilegeCases` static isolation assertion and
`test_privilege_complete.py:LinuxCompleteCases.case_production` prohibit the
privilege dependency in production roles/worker source. The retained log
contains the production traceback at test_privilege_complete.py:221;
the observer identifies both failed foundation subcases (`privilege/static`
and `linux_complete/production`). The earlier full traceback was lost to capture
truncation and is not reconstructed here. This is a code-boundary defect, not
an environment failure or a reason to weaken those assertions. The smallest
next correction is to place authoritative privileged identity preparation on
its existing preparation side of the boundary and pass only non-authoritative
bound plan data to the worker. Do not introduce a fake qualified producer or
change the admission rejection. No correction or verification retry followed
this failed required attempt; work remains uncommitted/unstaged and UNVERIFIED.

Evidence: `/tmp/freeagent-text-inference-required-lrj2mj02`.
Required-log SHA-256:
`603df43d823d717cc7966ae688a4890dc3103678dc53761b1ce652868347768e`.
Source-before/source-after SHA-256 (identical):
`63e415f869397548474c67b2c988645c4d56ee724904dfc4a69483df5b403b6f`.
Progress SHA-256:
`f65001a057fe81036276022850bfeaceab4456306da23f1c77739b9d68127594`.
Invocation/configuration SHA-256:
`b47b43915c92a2fcc0a0771d83ae2d9fb5fcad582f66118b1a6f88248ea7da45`.
The exact activation config is in invocation.json: fixed observer PYTHONPATH,
private progress directory, existing FREEAGENT_PYTEST_FIXTURE_PYTHON and
FREEAGENT_PACKAGE_FIXTURE_PYTHON; no runtime replacement or download. Bounds
remain 420 seconds / 64 KiB and six seconds for the inner disk fixture.

All 182 selected files matched before/after and current files before these
result-only additions. Selection is tracked Python/TOML/lock/C, bin/ and
website guidance, explicit proposal documents and new text-inference tests;
coverage.json enumerates included/excluded paths. It excludes other untracked/
ignored material, installed/editable dependency bytes, base interpreter,
credentials/runtime state and actual read-set. It is not independent
attestation. No implementation/test changes followed the required attempt.
Observer completed 593 matched test intervals (four are intentional nested
synthetic fixtures), 3,745 records / 542,074 bytes, diagnostic_error null;
975 matched subcase intervals and PROCESS_END recorded. Nested intentional
outcomes are not controller-suite failure counts. The disk fixture passed.
Recorded runner/unittest PIDs were absent afterward, owned launch groups empty,
and no matching fixture mounts were observed. No unowned cgroups were inspected.
Historical cleanup/timeout causation and global descendant absence remain
unproven. B10 PARTIAL; STAGE31D_AUTHORIZED: NO. No live text-inference activation,
provider call, credential read or qualification is claimed.


### Separation correction — current preparation, 2026-10-05

The failed required attempt above remains historical evidence. Its two
unchanged separation assertions are `test_privilege.py:PrivilegeCases.static`
(no `privilege` dependency in production role modules) and
`test_privilege_complete.py:LinuxCompleteCases.case_production` (same worker
boundary). The retained latter assertion printed a 35,177-character escaped
worker source line; the log also retained a 21,323-character partial prior
source dump. This is concrete evidence of traceback verbosity exceeding the
64 KiB capture boundary, rather than inference from the overflow marker alone.
The first complete traceback was not retained. Reporting has not been changed:
fix the boundary failures, then check the unchanged bounded runner once.

Current code removes the policy import entirely from production worker code.
`privilege.validation:prepare_text_inference_plan` observes the existing current
`policy_hash()` in the existing preparation layer and delegates to
`roles.worker:prepare_text_inference` with that digest as data. This is a
one-way preparation dependency; the worker does not load the preparation layer,
directly, indirectly, lazily or through a proxy. The worker validates the digest
as exactly 64 lowercase hexadecimal characters and includes it in the canonical
invocation binding. A caller may construct equivalent declared data, but that
cannot satisfy admission. No policy observer was moved into another production
module, and no new positive-evidence producer or activation seam was added.

The closed website request schema, bounded canonical JSON, fixed argv/profile,
reference-only credential metadata, environment allowlist and pre-launch
rejection remain in the worker. All three worker entry points reject the fixed
profile or reserved executable before environment delivery, resource setup or
launch; caller-provided hashes, stale/forged claims and booleans do not change
that decision. Existing model/ordinary worker policy, lease, cancellation and
cleanup behavior are preserved. A focused test now exercises the preparation
layer's observed policy digest separately from the worker's declared digest
consumer, including schema rejection and changed-digest binding. The new tests
use the package-qualified worker namespace shared by the preparation wrapper,
so safe exceptions are checked against the actual producing class.

Only request/configuration validation and unconditional pre-launch rejection
are implemented controls. Filesystem secrecy, independent action restrictions,
narrow credential delivery, qualified activation, exact invocation consumption
and cancellation/cleanup evidence for this intended runtime lack producers.
Resource/time/response budgets remain prepared configuration while activation
is rejected. Actual upstream request/retry/token/cost enforcement is unavailable.
No credentials or live clients were used. B10 PARTIAL;
STAGE31D_AUTHORIZED: NO. The next producer integration dependency described
above remains unchanged; this separation correction does not qualify it.


### Separation correction required verification — PASS, 2026-10-05

The two original separation regressions remain unchanged and passed. Focused
and affected checks passed: 36 tests in 13.874 seconds, covering those assertions,
text-inference schema/binding/rejection, actual copied-target pytest reporting,
controller progress, model profiles, package/identity, lease and worker cleanup
compatibility. An initial focused run exposed a test exception-class mismatch
between module aliases; the new test now imports the package-qualified worker
used by its preparation producer. No separation assertion was changed.

Exactly one subsequent required `/root/agent-stack/bin/freeagent-test` attempt
used the established `.venv-orchestrator/bin/python3 -m unittest discover`.
Authoritative outcome: **590 tests, 360.581 seconds, OK, RESULT=PASS,
EXIT_CODE=0**. Wrapper 362.540611148 seconds; output 8,884 bytes. No timeout or
truncation. Correcting the separation failures resolved output overflow in this
run without any reporting change. This does not guarantee that future failure
tracebacks fit; the unchanged 64 KiB bound and overflow rejection still apply.
Controller compact/target verbose reporting and named-test assertions remain
intact. Deadlines and resource controls are unchanged; disk fixture passed.

Private evidence: `/tmp/freeagent-text-separation-required-v9jkzyz3`.
Required-log SHA-256:
`33080fd3fd6f69ad143dc1c19518471940f76a385436c919a4f30acd21a0234d`.
Source-before/source-after SHA-256 (identical):
`b6bf3691cf06f7730b8542fc4dc0ae7324b76cb3a36869a60d40309b05ab8173`.
Progress SHA-256:
`915e925e367c2bfc1f070300b831606b1f2165f197ad46c0e9df201c32a66d9a`.
Invocation/configuration SHA-256:
`ae5d82cb507fbed019af69a4785472f17752aaeccf0d3b5e1ec66eafd3be07c1`.

Invocation activated only the existing development observer with
`PYTHONPATH=/root/agent-stack/devtools/controller_progress`,
`FREEAGENT_CONTROLLER_PROGRESS_DIR=/tmp/freeagent-text-separation-required-v9jkzyz3`,
`FREEAGENT_PYTEST_FIXTURE_PYTHON=/tmp/freeagent-rpt1-pytest-u56y3cq4/venv/bin/python3`
and
`FREEAGENT_PACKAGE_FIXTURE_PYTHON=/tmp/freeagent-package-runtime-s05jvirn/venv/bin/python3`.
Inherited normal umask was preserved. No dependencies were acquired or installed
into an established runtime. The 420-second required deadline, 64 KiB capture
rejection and six-second inner disk deadline were unchanged.

All 182 selected source files matched before/after and current bytes before
these result-only documentation additions. Coverage selection/omissions are
unchanged from the failed run and enumerated in coverage.json: tracked Python/
TOML/lock/C sources, bin/ and guidance, explicit proposal documents and the new
text-inference test. Installed dependencies, interpreter/base binaries, other
untracked/ignored material, credentials/runtime state and actual read sets are
not independently attested. Result documentation is subsequent to tested bytes.
Observer: 594 matched test intervals (four intentional nested cases), 985 matched
subcase intervals, 3,771 records / 545,492 bytes, diagnostic_error null and
PROCESS_END. Observer totals do not replace authoritative unittest counts.
Recorded runner/unittest PIDs were absent afterward, owned groups empty, and
no matching fixture mounts remained in bounded observations. No unowned cgroups
were inspected/mutated; historical cleanup/global descendant absence and disk
timeout causation remain unproven.

This verifies deterministic preparation and unconditional admission rejection,
not filesystem secrecy, action enforcement, credential delivery, activation or
upstream request/token/cost enforcement. Their trusted producers remain absent.
Implementation/tests are unchanged after the run; only this result record was
appended. Changes remain unstaged/uncommitted for review. B10 PARTIAL;
STAGE31D_AUTHORIZED: NO. No independent review or live qualification is claimed.


### Reviewed preparation hardening — reconciliation, 2026-10-05

The separation snapshot received a source-only PASS (manifest
`9a27044eb72ee29d59c7b54ab597fbe4cd4ff5474fc6a45b21dbf26c65550021`).
This does not independently reproduce execution or qualify live inference.

Confirmed by baseline regressions: ordinary multibyte fields could exceed
512/8192-byte intent while remaining below the aggregate 48 KiB cap; malformed
run/contract/snapshot/guidance identities could construct a plan; malformed
inner commands could reach resource setup. UTF-8 encoded byte checks now use
the existing limits and convert encoding errors to TEXT_INFERENCE_REQUEST_INVALID.
Source/guidance newlines and tabs remain valid data; no blanket control-character
filter was added. Producer Session.run is uuid4().hex (32 lowercase hex),
Session.contract and Snapshot.sha256 are SHA-256 hex, and GUIDANCE_SHA is pinned
64 lowercase hex. These exact formats are checked, without claiming provenance,
freshness, pinned-value agreement or authority from correctly shaped declarations.

The inner worker now explicitly rejects non-list/empty commands, a missing or
empty executable, non-string arguments and embedded NULs with WORKER_REQUEST_INVALID
before policy/resource/environment/launch setup. A text profile still rejects
unconditionally; a valid command naming the reserved executable still rejects
under any profile. The reserved /runtime/bin/claude-free path intentionally
collides with an otherwise configurable ordinary launcher: it is unavailable
for ordinary model/research use while this preparation is disabled. The default
claude-free launcher remains compatible. No configuration subsystem or bypass
was added; the reserved executable guard was preserved.

The preparation policy_sha256 binds source/policy identity supplied by the
preparation layer. Actual worker cleanup evidence's policy_sha256 instead hashes
the effective resource-policy dictionary. These domains have distinct producers
and consumers; comparing digest inequality would not prove their separation.
Comments at both sites now make this distinction explicit. The fixed text
environment builder is preparation data only and is not consumed by an admitted
launch. The ordinary worker still inherits its existing transport environment;
future activation requires actual environment selection/enforcement and trusted
credential provisioning. That integration remains deferred and disabled.

All three text admission gates remain unconditional rejection. Runtime identity,
visibility exclusion, independent action restrictions, narrow credential delivery,
qualified activation and cancellation/cleanup proof still lack trusted producers.
Upstream request/token/cost enforcement remains unproven. Resource/output/time
limits, leases, cleanup, policy-source identity, ordinary profiles and reporting
contracts remain unchanged. B10 PARTIAL; STAGE31D_AUTHORIZED: NO.


### Preparation hardening verification — BLOCKED, 2026-10-05

Before implementation, four new focused cases were run against the reviewed
worktree. Byte-bound, identity-format and inner-command families reproduced
acceptance/setup gaps. The first reserved-launcher case lacked the planner's
required schema argument (test setup error); correcting that fixture yielded a
PASS without changing application behavior. Reservation/default compatibility
is confirmed and intentionally preserved, not repaired by removing a guard.

After hardening, 61 focused/affected checks passed in 25.899 seconds. These
include the two unchanged production separation regressions, the full policy
identity case table, text-inference, model profiles, synthetic website proposals,
worker resources/timing, actual copied pytest reporting and controller progress.
Private focused-log SHA-256:
`92d7902e09d6d6fc966068e6dc389752740be9244bb952e73f9e75a10f7ef855`.

Exactly one required `/root/agent-stack/bin/freeagent-test` attempt used the
established `.venv-orchestrator/bin/python3 -m unittest discover`, with the
existing observer and development fixtures. RESULT=TIMEOUT, EXIT_CODE=124 at
the unchanged 420-second runner deadline. Wrapper 420.383063155 seconds; captured
log 709 bytes, no overflow. There was no final unittest count/duration/OK marker.
The last observed start was
`test_worker_resource.WorkerResourceTests.test_infinite_loop_times_out`
at 418.469 seconds relative to observer startup; the last recorded completion was
`test_worker_resource.WorkerResourceTests.test_fixer_timeout_with_proven_cleanup_cannot_verify`
(PASS). One unmatched TEST interval identifies unfinished execution when the
outer deadline fired; it does not establish a hang, per-test timeout defect,
host contention or sole causation. Existing disk fixture and new hardening cases
completed; no fixture/quota/deadline/reporting changes or retry were made.

Evidence directory: `/tmp/freeagent-text-hardening-required-9waa1gjd`.
Required-log SHA-256:
`deaa2e7ba4abf606f0c900710c1ee969cafdb9ad1da0ea8e851400330f4b74ab`.
Source-before/source-after SHA-256 (identical):
`5bb7369964215a4acfbe90aa4bb81a5481a0ada4614f7e0a76765e7bfd6738cb`.
Progress SHA-256:
`bf7555fc9d3877f4f88b7eec67a49730a4a8d6c8cbbebe8bf982fd365264b7d2`.
Invocation/configuration SHA-256:
`595837cbe2e1e945cda6336608dffc1656729ab2eca4fdc6e2274a09aa33900e`.

Activation was the existing controller_progress PYTHONPATH directory plus
FREEAGENT_CONTROLLER_PROGRESS_DIR naming that evidence directory. Existing
FREEAGENT_PYTEST_FIXTURE_PYTHON and FREEAGENT_PACKAGE_FIXTURE_PYTHON selected the
same isolated development fixtures as the earlier separation run. Invocation.json
records exact paths. No dependencies were downloaded/installed; normal inherited
umask, compact/verbose reporting, 64 KiB capture rejection, resource controls,
six-second inner disk deadline and 420-second required deadline were preserved.

All 182 selected sources matched before/after. Selection covers tracked
Python/TOML/lock/C, bin/, guidance and explicitly named proposal documents/new
test; coverage.json enumerates included/excluded paths. Installed dependencies,
interpreter/base binaries, other untracked/ignored files, credentials/runtime
state and actual read sets remain unattested. Only this result documentation was
appended after the attempt. Observer recorded 564 completed test intervals (with
intentional nested synthetic runs), 1,026 completed subcase intervals, 3,834 records
and 549,376 bytes. No PROCESS_END or shutdown result was available after termination;
this diagnostic incompleteness is distinct from the runner timeout verdict.

Recorded runner/unittest PIDs were absent afterward, their process groups empty
and no matching fixture mounts were visible in the current bounded observation.
No unowned cgroups were inspected or mutated. Historical cleanup, global descendant
absence and disk-timeout causation remain unproven. Required verification remains
BLOCKED; no commit/staging or additional attempt. The next verification decision
must use retained progress evidence before authorizing another run; no change to
limits or security checks is justified by this timeout alone. B10 PARTIAL;
STAGE31D_AUTHORIZED: NO. Live enforcement/evidence producers remain absent.


### Unchanged hardening verification reconciliation — PASS, 2026-10-05

The failed hardening log/manifests/progress and earlier separation PASS evidence
were freshly hash-checked against their recorded identities. Completed shared
interval comparison found foundation grew 103.386 -> 129.354 seconds (+25.969),
attribution 11.097 -> 15.880 (+4.783), and contract 4.410 -> 8.228 (+3.818).
The source_bound_exports subcase grew 52.460 -> 66.626 (+14.166) inside foundation;
these inclusive/nested times must not be added together. The four added hardening
tests consumed 0.133 seconds total in the failed run. Repeated generic subcase
labels do not identify unique phases; comparison.json records them as inclusive
aggregates, not exclusive costs. Failed-run completed tests omit later unfinished/
unstarted tests, so these comparisons are not a whole-suite cost decomposition.
Shared-test growth dominates added-test cost; its cause remains unproven. Host
contention, setup/I/O variability and other timing effects were not measured.

The interrupted test's source path is execute -> run_worker -> _run_worker_impl
-> namespace inner worker -> _run_inner -> ActivityLease/_read_worker_streams
-> _stop_scope -> _validate_evidence. It launches only the existing synthetic
Python infinite-loop fixture, with a two-second timeout, no activity grace,
ordinary model resource policy (CPU 100000/100000, memory 1536 MiB, swap zero,
64 processes, 256 descriptors, 128 MiB per-file, 256 KiB worker capture), and
one-second termination grace. Its assertions require confirmed cleanup, zero
remaining processes, enforced cgroup/resource controls, timeout evidence and
child result 124. Setup/collection/cleanup add time outside the two-second lease.
New inner shape validation is on this path, but the valid three-string command
passes it; neither text preparation nor the reserved path/profile is selected.
No lease, quota, timeout, cleanup or result-classification operation was changed.
The test completed in 2.201 seconds in the historical passing run but started at
418.469 seconds in the failed run (70.235 seconds later). The outer 420-second
runner deadline interrupted an interval whose normal duration exceeded the
approximately remaining time; this is not a demonstrated test defect or hang.

After bounded current preflight found recorded PIDs absent, groups empty, no
relevant current verification jobs or matching fixture mounts, exactly one
isolated invocation ran:
`.venv-orchestrator/bin/python3 -m unittest test_worker_resource.WorkerResourceTests.test_infinite_loop_times_out`.
It passed: one test in 2.225 seconds, exit zero; wrapper 3.419552 seconds;
98 captured bytes, no timeout/overflow, direct child reaped. Its private capture
SHA-256 is `acc46ff005a5e7dd714312c903836939325e3ace867bd322872861ff7a18ea87`.
The diagnostic wrapper bounded collection to 30 seconds/64 KiB without changing
the fixture's worker lease/assertions. No retry or instrumentation change.

That isolated PASS, distributed shared-test growth, absence of a reproduced
correctness failure and a second clear current preflight supported the separately
authorized one required attempt for unchanged implementation/test bytes.
Actual command `/root/agent-stack/bin/freeagent-test` retained established
`.venv-orchestrator/bin/python3 -m unittest discover`, 420-second runner deadline,
64 KiB overflow rejection, existing discovery/reporting, disk diagnostics and
six-second inner disk deadline. Explicit configuration:
`PYTHONPATH=/root/agent-stack/devtools/controller_progress`,
`FREEAGENT_CONTROLLER_PROGRESS_DIR=/tmp/freeagent-text-reconcile-jb0951e6/required`,
`FREEAGENT_PYTEST_FIXTURE_PYTHON=/tmp/freeagent-rpt1-pytest-u56y3cq4/venv/bin/python3`,
`FREEAGENT_PACKAGE_FIXTURE_PYTHON=/tmp/freeagent-package-runtime-s05jvirn/venv/bin/python3`.
Normal inherited umask unchanged; no dependencies installed or model calls made.

Authoritative result: **594 tests, 406.257 seconds, OK, RESULT=PASS, EXIT_CODE=0**.
Wrapper 408.770623943 seconds; captured output 8,883 bytes, no timeout/truncation.
Wrapper duration is not exact runner deadline headroom. Observer: 598 completed
test intervals (including four intentional nested tests), 1,026 completed subcase
intervals, no unmatched intervals, PROCESS_END, diagnostic_error null, 3,902
records / 562,015 bytes. Nested observer outcomes are not authoritative suite
failure counts. Required verification passes; this later PASS does not establish
the earlier slowdown/timeout cause or prove historical cleanup.

Evidence directory: `/tmp/freeagent-text-reconcile-jb0951e6/required`.
Required-log SHA-256:
`5a908e62ce8f8ce03a83470e36fdd3ed83e5950fcd41ef3b04bf1128f800fc81`.
Source-before/source-after SHA-256 (identical):
`693f9040cfa7cfc6e9735e0d1e2308e4eb98bfd5e744e34923485d0c5ebefabe`.
Progress SHA-256:
`a433e36d07a63769e7020b6fae52c907e03f9c98e95e8232f939504b542e9906`.
Invocation/configuration SHA-256:
`84b11323fe68f01927693e19dd3acc542cb05bfdac2fa427ff9bd5475a80d078`.
All 182 selected sources match before/after; all five pending-file hashes also
matched their milestone starting identities before this result-only append.
Coverage.json retains the selection: tracked Python/TOML/lock/C, bin/, guidance,
and explicitly named proposal documents/test files. Ignored/unselected untracked
material, installed/editable dependencies, interpreter/base binaries, credentials/
runtime state and the actual dependency/read set are not independently attested.

Current observations found recorded isolated/runner/unittest PIDs absent, their
process groups empty, and no matching fixture mounts visible. No unowned cgroups
were inspected/mutated; this is bounded current evidence, not global descendant
absence or historical cleanup proof. All implementation/test bytes remain
unchanged; only this documentation was appended. Nothing staged or committed.
B10 PARTIAL; STAGE31D_AUTHORIZED: NO. Live runtime visibility, action enforcement,
credential provisioning, qualified activation, protected identity/cleanup evidence
and upstream request/token/cost enforcement remain incomplete.


### Independent hardening review disposition — PASS, 2026-10-05

Independent hardening source review: **PASS, no blocking findings**. The reviewed
snapshot manifest is `64ef7e8ed05f79f642e3daea6503590ebc4d5eee257e81854c4084b5949aeb01`;
hardening-delta SHA-256 is
`70a3fefc80cf9d7b34182e0f792e93c978e4877098a7a593080c24d4eaf48777`.
The verdict covers preparation/separation only, not runtime enforcement or
live qualification. Recorded required verification remains 594 tests,
406.257 seconds, RESULT=PASS, EXIT_CODE=0; no tests were rerun for this disposition.

Non-blocking follow-up, deferred: outer ordinary-worker command validation
permits an empty executable or embedded NUL to reach inner rejection, causing
unnecessary unshare/interpreter setup and error-code inconsistency. A future
correction should share command validation before outer setup, with regressions
preserving valid empty non-first arguments and reserved-executable rejection.
This commit does not implement that correction. Admission remains closed;
live enforcement/evidence producers remain incomplete. Selected-source binding
is not independent dependency/read-set attestation. Prior failed attempts and
historical timeout/cleanup uncertainty remain recorded above. B10 PARTIAL;
STAGE31D_AUTHORIZED: NO.
