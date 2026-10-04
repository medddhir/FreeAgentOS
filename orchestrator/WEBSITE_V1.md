# FreeAgentOS website-v1 product preparation

FreeAgentOS is a coding agent for websites and applications. Local building,
preview and source export carry no FreeAgentOS fee. Third-party inference may
have costs, rate limits, availability constraints and its own terms. Managed
publishing, hosting and operations are future paid services. This is a product
model, not a promise of unlimited inference or a license grant for third-party
software. Claude Code remains user-supplied and is not redistributed here.

## Implemented preparation scope

### Recorded preparation CLI (current implementation)

The existing `freeagent-run` entrypoint now exposes an explicit rehearsal mode:

```sh
freeagent-run recorded-website --staging-parent /absolute/owned/private-parent \
  --title 'Local Studio' --heading 'Build locally' --button 'See more' \
  --revision-heading 'Revised page' --revision-button 'Explore details' \
  --design 'Warm neutral palette' --confirmed --json
```

The parent must already exist, belong to the current user and have mode 0700.
No privileged setup, model configuration, production credentials or provider
access is required by this command. Source-layout usage is
`.venv-orchestrator/bin/python3 orchestrator/cli.py recorded-website ...`;
the existing installed `orchestrator.entrypoint:main` bridge also handles it.
No separate export destination is accepted. Success reports the actual workspace
and `<owned-run>/export` path; plain output includes `EXPORT=...`.

This mode reuses `website.workflow_graph` (the same factory wrapped by
`graph.build_website_graph`), LangGraph, `RecordedAdapter`, FileTools, Session
snapshots/checks and `Session.export`. It avoids production graph initialization
and its model configuration when launched as this explicit CLI command. Ordinary
coding invocation and profiles retain their existing graph path and gates.

A fixed controller recording escapes brief text into HTML, supplies local
CSS/JS and README, then applies the confirmed heading/button revision and a
spacing change. Design is recorded text, not a claim of model-generated design.
No source JS/CSS is executed. Existing four-file, per-file/aggregate/context and
tool bounds apply unchanged. Invalid inputs, unavailable/unsafe staging paths,
unconfirmed/unchanged revisions and separate export options return nonzero.
No success result is emitted after a failure; owned partial artifacts remain
retained under the existing Session contract. A new invocation creates a fresh
run, and Session.export remains exclusive and snapshot/check-bound.

Results explicitly say RECORDED_PREPARATION, MODEL_CALLS=NONE,
PREPARATION_COMPLETE/PREPARATION_ONLY and live_qualified=false. Structural checks
are not functional/browser verification; preview remains DISABLED and live
launches still reject. Same-UID private staging is not hostile-user isolation.
Subprocess tests run under the available development UID/runtime and must not
be presented as non-root qualification or observed installed-package execution.
The historical result sections below remain historical; B10 PARTIAL and
Stage31D NOT AUTHORIZED are unchanged.

One static website: confirmed brief/design -> private scaffold -> recorded
coding -> meaningful user-requested revision -> protected structural checks ->
snapshot-bound preview contract -> complete source export. This is a LangGraph
vertical slice exposed through graph.build_website_graph(RecordedAdapter), not
another orchestration framework and not a production CLI cutover.

Session receives a ConfirmedBrief and a private, owned staging parent from
deterministic controller/test code. RecordedAdapter contains at most four fixed
path/text writes per phase, delivered through the existing FileTools broker as
coder/fixer roles. It accepts no callable, executable, shell command or live
adapter. Impeccable shape guidance is pinned data in its bounded context; it
cannot add tools or grant permission. Brief confirmation must already exist.

Schema-3 website policy permits exactly index.html, styles.css, app.js and
README.md. No new paths, deletions, test/config edits or guidance edits. Each
file is at most 8,192 UTF-8 bytes; project source is at most 32,768 bytes.
No existing profile's suffix list or schema-2 policy has been widened. Existing
broker read/tool/session bounds remain unchanged. The website-specific final
write bound also applies after Edit, not just to individual argument sizes.
The brief has six strings of at most 512 bytes; guidance is 3,547 bytes. Fixed
controller-owned scaffold and verification material are never model-writable.

Snapshots retain immutable bytes plus run/profile, contract, brief/guidance and
per-file hashes. Existing inspector descriptor-relative no-follow reads and
workspace hashing are reused. Root inode substitution, extra files, symlinks,
hardlinks, stale/cross-run snapshots and changed content reject acceptance.
This is same-UID local preparation, not a claim of a hostile-UID isolation
boundary. The private root and parent must remain controller-owned. Kernel
qualification and a protected live snapshot ingestion path remain prerequisites.

Protected structural checks validate title, heading, button labels, required
local CSS/JS links, supported HTML structure and nonempty source. The revision
must satisfy the separately confirmed revised heading/button and change the
snapshot. Configured checks/recordings do not prove JavaScript syntax, executed
interactions, rendering, accessibility, network isolation or browser success.
JS and CSS are never interpreted by this workflow.

Preview returns only a versioned contract: entry index.html, loopback-only bind,
run/contract/snapshot identity, execution DISABLED and qualification UNPROVEN.
No server, browser or URL is started. launch_live always rejects with
EXECUTION_QUALIFICATION_UNPROVEN, including caller booleans or recording PASS.
There is no qualification producer or override. A future server must serve the
exact snapshot bytes, reject traversal and follow neither project symlinks nor
project executable commands. Browser topology, dependencies, containment and
functional tests remain separately unqualified.

Export is a rehearsal artifact: all four complete source files plus export.json,
with PREPARATION_ONLY and live_qualified=false. Unlike a patch-only artifact it
contains the complete website. It uses an exclusive, fixed export subdirectory
inside the owned run, no caller-selected output path or automatic promotion.
It rechecks snapshot/check identities and uses no-follow exclusive writes and
file/directory fsync. Existing export contents are never overwritten. Failures
retain the private run/partial export for inspection; they do not publish a
success receipt or invoke broad cleanup. This extends the existing hashing,
owned-workspace and exclusive artifact conventions; it does not call
verified_patch with simulated production preflight evidence.

## Reuse and upstream identities

- LangGraph 1.2.12, already pinned; upstream tag commit
  49cce0ca852be4cfb567a1cbe0e511ff325a1682, MIT. Existing production graph unchanged.
- Existing Claude Code/FreeLLMAPI adapter remains the intended live coding seam;
  no model command or provider is invoked in this preparation graph.
  Installed client/gateway identities and compatibility are not freshly qualified.
  Historical gateway image revision e4a47f203dba3b610dc180f628d3e821abbaf564 is
  historical metadata, not a new installation pin.
- Impeccable e103efe779e2dd01274dabae83531fef00bf2563 (package metadata 4.1.0),
  Apache-2.0; exact selected source/license/notice hashes and scope are in
  website_guidance/SELECTION.md. The upstream CLI/engine is not integrated.
- Playwright 1.56.1, upstream commit
  54c711571a37de525377e6f3d3608c3e029b1829, is a deferred verification candidate,
  not a dependency added by this milestone. Browser artifacts/OS dependencies,
  sandboxing and owned cancellation/cleanup remain unqualified.

## Complete supplied reuse catalog

The supplied earlier catalog names 20 identifiable repositories, despite a later
reference to 21. Six additions are accounted for below; no unnamed entry invented.
Status is tracked evidence, not naming, installation or intent. Unselected
upstream capabilities/licenses are unverified; none is granted authority here.

| Repository | Intended role | Evidence-backed status at this milestone |
| --- | --- | --- |
| tashfeenahmed/freellmapi | Model gateway | Existing executable external adapter path; historical installation evidence, no newly qualified pin |
| tt-a1i/archify | Visualization | User-reported development use; .archify ignore rule, no product dependency |
| omnirush-ai/omnirush-gui | Sanitized reviewer | Historical external review use; no product integration or exact GUI build pin |
| NousResearch/hermes-agent | Skills/automation/operator ecosystem | Historical incidental credential-store reference; no agent integration |
| OpenHands/OpenHands | Engineering agent | Candidate; no tracked integration found |
| anomalyco/opencode | Coding agent | Candidate; no tracked integration found |
| aaif-goose/goose | Extensible agent | Candidate; no tracked integration found |
| browser-use/browser-use | Browser worker | Candidate; no tracked integration found |
| anthropics/skills | Skill format/capabilities | Reference/candidate; no direct integration established |
| usestrix/strix | Security capabilities | Candidate; no tracked integration found |
| trimstray/the-book-of-secret-knowledge | Knowledge reference | User reference; no tracked reuse established |
| BerriAI/litellm | Provider abstraction | Candidate; no tracked integration found |
| Aider-AI/aider | Repository coding | Candidate; no tracked integration found |
| agent0ai/agent-zero | Framework | Candidate; no tracked integration found |
| e2b-dev/E2B | Sandbox | Candidate; no integration or isolation equivalence established |
| FoundationAgents/OpenManus | Framework | Candidate; no tracked integration found |
| open-webui/open-webui | Product/UI reference | User reference; no tracked integration found |
| DietrichGebert/ponytail | Coding-discipline skill | Future plan; audit explicitly reports no integration |
| danveloper/flash-moe | Local-model reference | Future reference; no tracked integration found |
| pbakaus/impeccable | Product/project design guidance | Pinned shape text/license/notices added as data; no executable upstream tooling |
| msitarzewski/agency-agents | Agent-role guidance candidate | Supplied candidate; no tracked integration found |
| ruvnet/ruflo | Agent workflow candidate | Supplied candidate; no tracked integration found |
| garrytan/gstack | Coding/browser workflow candidate | Supplied candidate; no tracked integration found |
| Panniantong/Agent-Reach | Agent capability/research candidate | Supplied candidate; no tracked integration found |
| codecrafters-io/build-your-own-x | Engineering references | Derived data/buildx.json, source commit aa17439b62f384511a5561ce308e9598b94d8989; reference data, not an execution framework |
| public-apis/public-apis | API discovery references | Derived data/public_apis.json, source commit 7598f906a610c6d6ebf7adc2e72b6b5fccc7eba0; reference data, not an API integration |

Later Impeccable scope: Founder View/dashboard/setup/provider screens,
agent/run visualization, Skills/project screens and public website; optionally
design guidance for generated projects. This milestone addresses the building
workflow first, not those UI surfaces or an unrestricted skills runtime.

## Assurance boundaries and remaining work

N3 is source-traced, pending deterministic reproduction: unrequested Assign.value
or AnnAssign.value attribute lookup may preserve an invalid unrelated export.
No analyzer repair or hook execution occurs here. B10 remains PARTIAL; N2
independent review remains ongoing. candidate_prerequisite still requires
STATIC_METADATA_VERIFIED; static results never establish protected authority.
The changed read_policy/file_tools source changes policy identity through the
existing authoritative-source binding. Old mismatched journals remain rejected;
no real journal is read, rewritten, deleted or relabeled by this workflow.

Normal-user live coding remains blocked by the unqualified privilege boundary;
the production worker integration is unchanged. Preview/browser process profiles,
actual functional tests, qualified inference compatibility/credential delivery,
complete live source export and packaging/redistribution readiness remain product
work. No paid publishing, inference promise or sandbox equivalence is introduced.
Lease values remain 180 seconds, existing one-shot grace eligibility, 240 hard cap.
Doctor active isolation remains UNPROVEN. Stage31D NOT AUTHORIZED.

## Deterministic evidence

test_website.py runs the real LangGraph preparation nodes with recorded file-tool
writes: initial page and CSS/JS, then revised heading/button and spacing. It checks
complete source bytes and hashes, protected structural results, immutable preview
binding, wrong-owner snapshots, symlinks/hardlinks/root replacement, unauthorized
paths/commands/configuration, guidance-based escalation, bounds, stale/forged
evidence, exclusive export and unconditional live-launch rejection. These tests
do not establish browser/functional or kernel qualification. Required-suite
results will be recorded after execution, without altering its 420-second limit.

### Verification outcome: BLOCKED, uncommitted preparation

Focused website/file-read/read-write/model-profile/unit-graph regressions PASS:
96 tests in 30.176 seconds. PolicyIdentityCases PASS. After the final bounded
context/root/snapshot guards, all seven website cases PASS again in 0.438 seconds.

One unchanged required /root/agent-stack/bin/freeagent-test run returned
RESULT=FAIL, exit 1: 525 tests in 415.030 seconds, wrapper wall 417.962 seconds.
The sole failure was existing ResourceSandboxTests.test_workspace_disk_ceiling
(test_resource_sandbox.py:135): expected "No space left on device", but received
RESULT=TIMEOUT / EXIT_CODE=124. All new website cases passed within that run.
This was a target-test timeout outcome, not the required runner's 420-second
timeout. Its cause and causal relationship remain unresolved; the historical
disk-ceiling timing uncertainty is not reclassified as environment proof.

Private log: /tmp/freeagent-website-v1-required-4hdk7z9z.log, mode 0600; normal
test umask unchanged. No blind retry, assertion/workload/limit change or unrelated
sandbox repair. Final scope/whitespace inspection passed. Because required
verification failed, this milestone is BLOCKED and no commit is made. Scoped
preparation remains in the worktree. No live path is qualified or activated.

## Recorded CLI verification — 2026-10-04

Focused website/broker/model-profile checks passed (49 tests), followed by
CLI/runtime/ordinary-entrypoint checks (25 tests). The single required invocation
was `/root/agent-stack/bin/freeagent-test`, using its established
`.venv-orchestrator/bin/python3 -m unittest discover` selection. The existing
`FREEAGENT_PYTEST_FIXTURE_PYTHON` prerequisite pointed to
`/tmp/freeagent-rpt1-pytest-u56y3cq4/venv/bin/python3`; no dependencies were installed.
The committed development observer was activated by
`FREEAGENT_CONTROLLER_PROGRESS_DIR=/tmp/freeagent-recorded-cli-required-5a_0hfcq`
and the fixed `devtools/controller_progress` PYTHONPATH entry. Its existing
controller-only activation/removal rules were unchanged.

Required result: **566 tests, 416.678 seconds, OK, RESULT=PASS, EXIT_CODE=0**;
wrapper wall time 419.329 seconds. There was no timeout or output truncation
(the private wrapper log was 7,295 bytes). The 420-second deadline and 64 KiB
capture bound were unchanged. Wrapper time is not the runner's exact deadline
interval; headroom was narrow. The observer completed 570 intervals, including
intentional nested synthetic cases, with no unmatched intervals or diagnostic
failure. Its outcome totals are not authoritative suite failure counts.

The private pre-run selected-source manifest covered 205 tracked/relevant new
files (3,101,195 bytes), including CLI, website, tests, observer and documentation.
Every selected file's bytes/mode matched immediately after the run. Manifest
SHA-256: `5b395bd3bc68a445a23b1477cad017e45f1913c5cdddb6897985b0f7477a4ebc`.
Required-log SHA-256:
`456c87458df06f85f9f30b2c377f49ccd4064ce968e9e2507a3ce55b5519fab8`.
This paragraph and the qualification-plan result update were added after that
comparison; implementation/test bytes remain bound. This is selected-source
binding, not independent dependency or read-set attestation.

The runner and unittest launch identities were absent after completion; no
matching concurrent test invocation or known fixture mount was observed.
These bounded current observations do not prove historical cleanup or absence
of every resource; unowned cgroups were not inspected. Tests ran as UID 0 on
Python 3.12.3, so normal-user and installed-package qualification remain unproven.
Recorded structural preparation passed; live coding, preview/browser execution,
B10 completion and Stage31D authorization remain blocked/deferred as before.

## Recorded CLI failure reporting correction — 2026-10-04

The candidate's post-Session WebsiteError reporting used cleanup NONE despite
retaining the run. Baseline reproduction with a whitespace-padded heading left
one run and four project files (exit 2, PROTECTED_CHECK_FAILED). A title of
"Secret garden" triggered the existing broker filter after scaffolding: one run
and four scaffold files remained, including an empty index.html, without export.
The review claim that this code-phase failure leaves no run was contradicted.
It previously exited 4 as an unexpected controller failure.

Failure output now reports artifact_state NOT_CREATED only before constructor
entry, RETAINED after successful creation and a successful current root identity
check, or UNPROVEN when construction/identity cannot establish retention.
workspace_cleanup is respectively NONE, RETAINED or UNPROVEN; cleanup_attempted
is always false in this branch. Text output includes these same facts. No cleanup
or deletion is performed. Expected broker ReadDenied reports BLOCKED with the
fixed RECORDED_WEBSITE_POLICY_REJECTED code and exit 2; FILE_TOOL_INTERNAL remains
an unexpected controller failure (exit 4). No user text or uncontrolled exception
message is included. Failures never report preparation success.

Known non-blocking restrictions are unchanged: the content filter can reject
benign wording (including "Secret garden"); symlinked staging ancestors reject;
leading/trailing whitespace is accepted by brief validation but protected checks
compare stripped HTML text with exact confirmed text, so such headings/titles/
buttons can fail. Whitespace behavior is not normalized by this correction.
Programmatic imports can initialize the production graph before recorded dispatch;
explicit CLI subprocess invocation avoids it. Import redesign is out of scope.
Ownership, content policy, templates, bounds, fixed export and execution gates
are unchanged. Normal-user compatibility and live qualification remain UNPROVEN;
B10 PARTIAL, STAGE31D_AUTHORIZED NO. Verification results follow separately.

Verification of this correction: focused CLI/website/broker checks passed (50 tests
in 42.191s), followed by runtime/ordinary-entrypoint checks (19 tests in 9.385s).
The one required invocation was `/root/agent-stack/bin/freeagent-test`, selecting
`.venv-orchestrator/bin/python3 -m unittest discover`:
**568 tests in 414.529s, OK, RESULT=PASS, EXIT_CODE=0**. Wrapper time 416.697s
is distinct from the exact runner deadline interval. The 420s deadline and 64 KiB
capture limit were unchanged; no timeout, output truncation or diagnostic failure.
The existing pytest prerequisite was
`FREEAGENT_PYTEST_FIXTURE_PYTHON=/tmp/freeagent-rpt1-pytest-u56y3cq4/venv/bin/python3`.
The existing observer used
`FREEAGENT_CONTROLLER_PROGRESS_DIR=/tmp/freeagent-cli-retention-required-dr2zrji8`
and the fixed `/root/agent-stack/devtools/controller_progress` PYTHONPATH prefix.
It recorded 572 completed intervals (including four intentional nested synthetic
cases), no unmatched intervals and normal shutdown. Unittest's 568 count and
runner markers are authoritative; nested observer outcomes are not suite failures.

All 205 selected regular source files matched their pre-run bytes/modes afterward.
Pre-run manifest SHA-256:
`3215afe13d42ed653e99366526d1338218562caf4c3d55503456bf3ddc6da145`.
Required-log SHA-256:
`2d072ca03d98a791e4241983d02401bc71e0d0d2f999f7e3d23f3dddc5534784`.
Only this result documentation was appended after comparison. This is source
binding, not independent dependency/read-set attestation. Runner/unittest launch
identities were absent after completion; this does not prove historical cleanup.
Tests ran under development UID 0, not a normal-user qualification attempt.
No review of the new correction is claimed; no commit/tag/push/deployment.
