# First normal-user coding execution qualification

2026-10-04. Source inspected at `08d88eb5b977a3091bb025d8d964a9782b04bac2`,
branch `main`; `n3s1-preparation-verified` peels to that commit. This is a plan,
not permission to execute it. No tests, builds, providers, projects, browsers,
servers or privileged operations were run for this document.

FreeAgentOS is a general coding agent for building, repairing and verifying
software. One static website is the first bounded qualification task, not the
overall scope. Local building/preview/export carry no FreeAgentOS fee;
third-party inference has its own costs and limits. Managed services come later.

## Actual paths and reality status

```text
Installed freeagent-run -> entrypoint.main -> cli._main -> graph.build_graph
  -> prepare_workspace -> preflight -> baseline/discovery -> inspector/planner
  -> coder/fixer -> model_command -> run_worker -> broker_session -> FileTools
  -> protected tester/run_isolated -> reviewer/finalizer -> verified_patch

Separate preparation API: build_website_graph(RecordedAdapter)
  -> Session/scaffold -> brokered code -> revision -> structural checks
  -> snapshot-bound DISABLED preview contract -> complete source export

Future normal-user execution: authenticated client -> qualified supervisor
  -> approved owned launcher [NOT integrated; prerequisites incomplete]
```

| Component / exact source evidence | Implemented | Qualified / remaining reality |
|---|---|---|
| `entrypoint.py:main`, `cli.py:_main`, `graph.py:build_graph` | Production CLI and LangGraph routing, permission inputs, cleanup/finalization | Existing path; no normal-user live qualification established here |
| `roles/workspace.py:prepare_workspace_node`, `verify_execution_contract`, `verified_patch` | Clean source snapshot, protected controller manifest, preflight/identity checks, drift-checked promotion patch | Production export is a patch, not website's complete-source export; no source auto-application |
| `roles/coder.py:coder_node`, `roles/model_profiles.py:model_command`, `roles/worker.py:run_worker` | Configured Claude Code/FreeLLMAPI command adapter and bounded process handling | CONFIGURED is not model or execution qualification; no website live adapter bridge |
| `roles/broker_session.py:BrokerSession`, `roles/file_tools.py`, `roles/read_policy.py` | Broker-owned tool policy and telemetry; bounded read/write/edit authority | Guidance/task text grants no tools; same-UID preparation is not hostile-process containment |
| `roles/preflight.py:check_host`, `roles/sandbox.py:run_isolated`, `roles/tester.py` | Active boundary preflight, networkless target tests, count/integrity checks and cleanup evidence | Direct privileged development implementation; normal-user support incomplete |
| `website.py:Session`, `RecordedAdapter`, `workflow_graph`, `launch_live` | Four-file recorded build/revision/check/export | Deterministically preparation-verified; preview is DISABLED; all live kinds reject `EXECUTION_QUALIFICATION_UNPROVEN` |
| `privilege/client.py:ControllerClient`, `execution.py:ApprovedExecution`, `service.py`, `build_closure.py:StagingClosureRegistration` | Prepared authenticated lifecycle, executable binding and staging prerequisite | Incomplete real publication/integration. Staging acceptance returns `qualified=False`, `execution_enabled=False` |
| `website_guidance/SELECTION.md` and catalog in `WEBSITE_V1.md` | Pinned design data and explicit reuse inventory | Reference/candidate entries do not imply executable integration |

Website `Session` uses a controller-owned 0700 parent, pinned root identities,
existing broker policy, immutable snapshot bytes/hashes and protected structural
checks. Only `index.html`, `styles.css`, `app.js`, `README.md` are writable,
8,192 bytes/file and 32,768 bytes total. Symlinks, hardlinks, changed roots,
foreign/stale snapshots and forged check evidence reject. `export` writes an
exclusive owned directory and complete sources with a PREPARATION_ONLY receipt.
HTML checks do not execute CSS/JS or establish rendering/functionality.
`workflow_graph` accepts exactly `RecordedAdapter`, and CLI `_main` invokes the
general graph, not that website preparation API.

The current status is documented in the latest dated section of
`STAGE31C_REAL_BACKEND_PREPARATION.md`: 560-test preparation PASS and independent
source reviews. Earlier BLOCKED/pending narratives in `WEBSITE_V1.md` are
historical and are not the current verification verdict. No completed review is
reopened by this plan.

## Normal-user execution boundary

`foundation.py:user_paths` provides HOME/XDG-based paths and resource lookup;
website staging checks the current EUID rather than requiring UID 0. Those
pieces can support a normal-user preparation CLI. That does not qualify live
code, inference or browser execution.

The production preflight/worker/test implementation creates mount/PID/network
namespaces, mounts cgroup v2 and tmpfs, writes controller limits, mounts runtime
trees, creates devices and uses chroot/setpriv. `doctor.py:privileges_available`
explicitly requires EUID 0 and capabilities 0,1,6,7,8,18,21,27. The test child
drops to UID/GID 65534; the controller still performs privileged setup.
`roles/worker.py:_run_worker_impl` has no `ControllerClient` handoff. Merely
enabling user namespaces or running this CLI as a normal user does not satisfy
the existing controls or make this code a reviewed rootless backend.

Host `/root/agent-stack` is this checkout, not an acceptable normal-user install
contract. `sandbox.py` also builds `/root/agent-stack` as a synthetic rootfs
compatibility path; it is not evidence of access to the host checkout. Installed
runtime layout, user-owned configuration and helper-owned state must have fixed
registered identities independent of a developer home. Python >=3.12 and pinned
LangGraph are declared in `pyproject.toml`; declaration alone does not qualify an
interpreter/dependency closure. B10's prepared supervisor-only bundle is not a
closure proof for the controller, Claude CLI or browser.

`foundation.py:adapter_environment` selects loopback gateway settings and a
named environment credential; do not inventory credential values. A normal-user
credential delivery/revocation boundary and user-supplied Claude executable
identity still require review. No host home/credential directory should be
projected into generated-project execution. Existing credential configuration is
not enrollment or owner approval.

Therefore **no currently qualified unprivileged live execution route is
established**. Preserve the prepared supervisor assurance gate:
`candidate_prerequisite` requires fresh `STATIC_METADATA_VERIFIED`, but that
staging result cannot authorize execution. B10 protected publication, installed
identities/dependencies and credentials remain incomplete; campaign, rollback,
target and real-kernel qualification inputs also remain prerequisites. The
prepared `ApprovedExecution` job-ID/class contract is not a finished production
coding/preview adapter. Stage31D synthetic validation, if later authorized, would
not itself authorize provider calls or production integration. Do not route
around these dependencies with the legacy privileged worker or another sandbox.

## Reuse choice

Keep the existing LangGraph 1.2.12 graph, configured adapter, FileTools broker,
snapshots, checks and export. `pyproject.toml` supplies the exact dependency;
`WEBSITE_V1.md` records historical LangGraph MIT/tag evidence, not a fresh upstream
audit. Claude Code is user-supplied; the historical gateway revision in the
handoff is installation metadata, not a newly verified redistribution/build pin.

At most two catalog selections:

| Selection | Decision and concrete seam | Provenance / footprint / boundary |
|---|---|---|
| `pbakaus/impeccable` | Keep/adapt the existing selected shape guidance for confirmed design; no executable upstream integration | Local `SELECTION.md`, LICENSE and NOTICE bind commit `e103efe779e2dd01274dabae83531fef00bf2563`, Apache-2.0 and selected blob hashes. Data-only footprint, no hooks/plugins/permissions |
| `browser-use/browser-use` | Defer. Browser interaction is a real missing verification capability, but no compatible bounded adapter is established | Catalog has no locally pinned source/license/dependency/cancellation evidence. All upstream capability/license claims remain unverified. A model-driven browser framework must not replace independent fixed assertions or gain network/tool authority |

No new external executable is selected now. Other coding/orchestration frameworks
are deferred: the actual gap is qualified execution and an accessible product
entrypoint, not another planner. A later browser implementation needs fixed
browser/executable identities, dependency closure, owned cancellation and
independent assertions; none is supplied by naming a catalog repository.

## First live qualification contract — proposed, disabled

Task: a normal-user-owned four-file static page with one heading and one button.
Confirmed brief requests a button that changes visible local text; one confirmed
revision changes the heading/button wording. No framework/package installation,
build script, arbitrary command, project plugin, external asset, deletion or
test/configuration edit. This task tests a coding slice, not general application
support. Preserve the current 8 KiB/file and 32 KiB aggregate website bounds.

Before execution, bind enrolled user/run/handle, policy, selected adapter,
executable/runtime identities, confirmed brief/revision, approved argv/profile,
snapshot and protected check identities. Caller flags, recorded PASS, guidance,
staging receipts and CONFIGURED profiles cannot produce qualification authority.
Control code/checks remain outside model write authority; generated code runs
only through the subsequently qualified existing backend integration.

Network: generated project/test workers have no external network. A fixed
snapshot server/browser pair may communicate only inside a reviewed loopback
topology; no public bind, remote browser, filesystem URL, arbitrary fetch or
downloads. Current networkless tester does not establish that preview topology.
The separately reviewed model worker may reach only its approved loopback gateway
through a contained credential/transport boundary; provider egress belongs to
that gateway. Such restriction is a proposed requirement, not a claim that the
legacy worker already implements it.

Retain model-worker base lease 180s, existing eligible one-shot grace and hard
cap 240s. Current worker ceilings: one CPU quota, 180 CPU seconds, 1,536 MiB
memory, zero swap, 64 processes, 256 FDs, 128 MiB/file, 256 KiB output
(`worker.py:WORKER_POLICY`). Existing tester request is 130s; policy caps are
150s wall, 120 CPU seconds, half CPU quota, 512 MiB/zero swap, 16 processes,
128 FDs, 128 MiB/file, 256 MiB workspace and 64 KiB output
(`tester.py:TEST_TIMEOUT`, `sandbox.py:RESOURCE_POLICY`). Do not change any of
these values to qualify the task. Proposed preview/browser budget: one owned
server/browser pair, 60s combined wall lifetime, sharing the tester's half-CPU,
512 MiB/zero-swap, 16-process, 128-FD and 64 KiB output ceilings. No project build
step or resource expansion is allowed. This is a proposed finite profile, not
an existing approved execution class. Browser fit, runtime identity and network
containment remain unproven; inadequate budgets must block the qualification,
not silently expand them. At most one initial code session and one revision
session, one protected test run and one browser verification; no automatic retry.

Independent success requires protected assertions on the exact snapshot:
complete four-file membership and hashes; revised heading/button; successful
local page load; a real click produces the required DOM change; no unexpected
requests, script errors or unauthorized files; fixed runner identity/count/result
evidence; complete source export bound to that checked snapshot. Model claims,
structural checks or exit 0 alone cannot satisfy functional/browser proof.
Use existing runtime/reporting integrity controls; test identities are not
independently attested merely by verbose output.

Release/disconnect/expiry/crash must terminate only owned descendants, close
broker/collector/server/browser descriptors, independently verify scope emptiness
and owned mount/socket/cgroup absence, and retain journal/recovery evidence when
ambiguous. Stop-on-failure, no automatic rerun or broad cleanup. Final success
requires cleanup proof; dirty state fences further admission.

Sequence: implementation -> deterministic integration checks -> separately
authorized target/live qualification -> separately reviewed production wiring.
Future authorizations must explicitly cover protected helper install/enrollment
and credential lifecycle; isolated synthetic privileged validation and rollback;
normal-user authenticated coding/provider requests; generated JS execution;
loopback server/browser launch; resource ownership/termination and cleanup.
They are separate from this plan and from the existing test-fixture authorization.

## One next implementation milestone

**Expose the existing recorded website preparation through a normal-user CLI.**
An explicitly labelled rehearsal entrypoint should invoke `build_website_graph`
and the fixed recorded adapter, accept a bounded confirmed brief/revision, create
an owned 0700 run under existing user paths, and return the complete export with
PREPARATION_ONLY/live_qualified=false. Keep live coding/preview/browser launch
unconditionally rejected. Do not accept arbitrary adapter commands or switch the
production graph to recording mode. This advances access to the existing vertical
slice while execution qualification remains a dependency, not a bypass.

Expected seams: `cli.py`/`entrypoint.py`, `graph.py:build_website_graph`, `website.py`,
`foundation.py:user_paths`; tests in `test_website.py` plus focused CLI coverage.
Reuse `test_file_read_policy.py`, `test_freeagent_test_runtime.py`,
`test_host_preflight.py`, `test_workspace_isolation.py`, `test_model_profiles.py`
and `test_lease.py` where affected. A subsequent coding milestone must run its
required verification; none was run for this plan.

Acceptance: packaged and source-layout invocation without `/root` assumptions;
fresh independent owned trees in temporary normal-user-layout fixtures; meaningful
revision and all four export bytes/hashes; protected checks stay controller-owned;
traversal/symlink/hardlink/root replacement/protected-edit rejection; no subprocess,
model call or server/browser launch; unchanged production graph and supervisor
gates. Mark actual execution as UNPROVEN even when deterministic CLI checks pass.

Unresolved decisions: supported normal-user OS/kernel and installed runtime
layout; protected B10 authority and complete controller/CLI/browser dependencies;
credential delivery/revocation and approved adapter provenance; real job-ID/broker
integration; browser/profile/loopback topology and cleanup proofs. Normal-user
configuration is portable groundwork, not evidence those questions are solved.

**B10: PARTIAL. STAGE31D_AUTHORIZED: NO.**

## Recorded CLI implementation update — 2026-10-04

The next preparation increment is implemented as `freeagent-run recorded-website`
with `--staging-parent`, `--title`, `--heading`, `--button`, `--revision-heading`,
`--revision-button`, `--design`, explicit `--confirmed`, and optional `--json`.
See WEBSITE_V1.md for the complete command. Only the existing caller-owned 0700
parent contract is accepted; no separate export location is offered. Output names
the actual `<owned-run>/export` produced exclusively by Session.export.

The CLI uses the existing website.workflow_graph factory with LangGraph directly
to avoid initializing the production graph/model configuration. Its existing
graph.build_website_graph wrapper uses that same factory. RecordedAdapter, broker,
four-file bounds, snapshots, structural checks, revision and exact source export
are reused; ordinary coding profiles and assurance gates are unchanged. The
fixed recording is controller-owned text substitution, not inference or a new
coding framework. Live launch remains unconditionally rejected.

The implementation is preparation only. Root-run subprocess tests cannot prove
normal-user compatibility; actual non-root installed execution and all live
qualification requirements above remain unproven. Required verification results
are recorded separately after the single authorized attempt; this text alone
does not certify a passing run. No B10 or Stage31D authority is granted.

### Recorded CLI verification result — 2026-10-04

The one authorized required run passed: 566 tests in 416.678 seconds,
RESULT=PASS, EXIT_CODE=0, with no timeout or capture truncation. Focused CLI,
website/broker, runtime-selection and ordinary-entrypoint regressions passed.
The 205 selected source files matched before/after the run; only result
documentation was subsequently appended. See WEBSITE_V1.md for invocation,
manifest/log hashes and observer configuration. Tests used UID 0, Python 3.12.3;
this establishes recorded preparation behavior, not non-root compatibility,
installed-package observation, functional/browser qualification or live authority.
The next live qualification requirements and B10 PARTIAL / Stage31D unauthorized
status in this plan remain unchanged.

## Non-root source-layout recorded preparation qualification — 2026-10-04

**Verified scope:** the explicit 30-file source selection from
`f90850b7d65bbf457993eda9f56d31c2b93c8294`, invoked through
`source/orchestrator/cli.py recorded-website` under account medhir, UID/GID
1000/1000. The fixture used its separate venv based on `/usr/bin/python3.12`
(Python 3.12.3, x86_64; recorded package version 3.12.3-1ubuntu0.17) and the
38 pinned official wheels, including LangGraph 1.2.12. Interpreter identity:
`e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f`.
The wheel runtime is not asserted equivalent to the established editable
LangGraph source commit `07b33185eab893be2ed031eedae52f09314bf77c`.

The first attempt failed with exit 4 in an incomplete source fixture. Static
inspection demonstrated that recorded broker content checking needed
`roles.coding_units`, whose imports required `roles.tester` and
`roles.repair_context`. Those three exact committed modules were added without
application implementation changes. The original captured exception bytes were
not retained: their hash cannot establish the precise original exception or
prove that this omission was the only cause. The original failed result and
staging artifacts remain historical evidence, unchanged.

A separately authorized second attempt passed after that fixture repair:
exit 0, elapsed 2.466301704 seconds, failure null, direct child reaped,
qualification `SOURCE_LAYOUT_RECORDED_PREPARATION_ONLY`. The bounded retained
capture was 1,751 bytes. Recorded status was PREPARATION_COMPLETE, model calls
NONE and live_qualified false. Integrity-only verifier output is not a
qualification verdict: the successful invocation and independent export
checks were required. Existing evidence was inspected for this documentation;
no qualification, tests, imports, installation or generated files were rerun.

Fresh evidence inspection confirmed the exact four revised project/export
files (`index.html`, `styles.css`, `app.js`, `README.md`), exclusive export plus
`export.json`, UID/GID 1000/1000 directories at 0700 and regular single-link
files at 0600. The heading/button revision and exact expected bytes matched;
receipt equality and per-file hashes matched. Before/final snapshots differed,
and independently recomputing the run/profile/contract/file-hash snapshot
matched checks, disabled preview and receipt. Structural PASS remains distinct
from functional/browser UNPROVEN. Artifacts are retained; direct-child reaping
is not descendant-absence proof.

Bounded evidence identities (SHA-256; private artifacts are not copied here):

| Evidence | SHA-256 |
|---|---|
| Historical failed result | `53bd1e8d7ceaf2e821bf1e207b35da090111197e89294d6265613fe11775a379` |
| V2 fixture manifest | `120bf851bc2c9bca6e442b16983681a7a9f98cfe12e6b86bce0648ae19041d1f` |
| V2 source manifest | `5585f50a2a7a8a6fff23cf1932178d54dd366fa5411b3ee624c3df6b617aa01d` |
| Offline wheel lock | `b4e4652a1b779179f01ee8b20e5c5029d72a86c5f41b0e679d6193df1439388a` |
| Wheel provenance manifest | `061f23be9def87440ed693d6ee00716ebc5bfd35eb76e1728a8618b77390a92e` |
| V2 qualification result (1,853 bytes) | `0de0035e36a512dbecf0cbdcf6198cccb5ff1fdd9a727884896e0e58ae9104ef` |
| V2 capture (1,751 bytes) | `953aeb15f9bcbe50fa139d629eff916b03ef8701d99c1ac4a974da21b95548d8` |
| Export receipt | `a8f25bfcaa4fcf1f2b85778ea54415628ff4bf7153e647aa12c85d9ddfebb7db` |
| Final snapshot | `b7da177dce4f1342c75043d72d3150e9e9af680d6cad6a2c116067a904728498` |

This verifies one normal-user **source-layout recorded preparation** with the
identified selection/runtime; it does not qualify all users, source layouts or
imports. Installed-package behavior, live building, provider access,
preview/browser/functional qualification, hostile isolation, complete dynamic
runtime closure and descendant absence remain UNPROVEN. Protected publication,
credential lifecycle and real backend/removal integration remain incomplete.
Historical root-run verification statements above retain their original scope.
**B10: PARTIAL. STAGE31D_AUTHORIZED: NO.**

## Installed-package preparation update — 2026-10-05

A fresh wheel from the existing package layout includes the recorded-path
modules, guidance/license/provenance and normal console entrypoint. No concrete
packaging membership defect justified changing application code or pyproject.toml.
The next bounded step is offline installed-console qualification, after separate
authorization, using a fresh normal-user fixture and identified project/runtime
wheels rather than editable source. See `../PACKAGING_VERIFICATION.md` for the
explicit development-only packaging checks and proposed single attempt.

The already qualified source fixture and both retained attempts are untouched.
Packaging regressions do not grant permission or installed/live qualification.
Installed-package behavior, live coding, browsers/functional checks, hostile
isolation and descendant absence remain UNPROVEN. B10 PARTIAL;
STAGE31D_AUTHORIZED: NO.

Packaging preparation's single required run passed: 572 tests in 357.648s,
RESULT=PASS, EXIT_CODE=0; 207 selected source files matched afterward, with no
timeout/truncation or progress diagnostic failure. Only result documentation
changed afterward. Fixed-condition duplicate wheel builds matched; installed
help/resource/content checks passed in a separate UID-0 development fixture.
This supports packaging preparation, not installed non-root or live execution
qualification. Artifact/evidence identities and the proposed later single
installed-console attempt are in PACKAGING_VERIFICATION.md. No implementation
or execution gate changed, and no new source-layout attempt was performed.
