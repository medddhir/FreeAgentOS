# FreeAgentOS website-v1 product preparation

FreeAgentOS is a coding agent for websites and applications. Local building,
preview and source export carry no FreeAgentOS fee. Third-party inference may
have costs, rate limits, availability constraints and its own terms. Managed
publishing, hosting and operations are future paid services. This is a product
model, not a promise of unlimited inference or a license grant for third-party
software. Claude Code remains user-supplied and is not redistributed here.

## Implemented preparation scope

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
