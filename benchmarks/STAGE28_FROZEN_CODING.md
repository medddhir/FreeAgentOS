# Stage 2.8A frozen-plan Coder/Fixer benchmark

Stage 2.7 is inconclusive for coding-worker quality: the GPT-OSS arm timed out in
its common model-backed Planner and never exercised the selected Coder/Fixer.
Neither prior arm is retried or changed. The historical experiment is not input
to this benchmark; no AUTO-generated plan is reused.

The neutral fixture is version-controlled in shipment_frozen.py. One integration
coding unit asks for the README contract to be completed in the four existing
implementation modules (models, parser, reconcile, cli), preserving public APIs.
It supplies scope, not algorithms, solutions, hidden answers or model reasoning.
The existing explicit-unit validator enforces the four-target limit and checks
tracked paths. Its PLANNER_EXPLICIT schema label is reused for validation only;
provenance explicitly says CONTROLLER_FIXTURE, never a Planner model response.

Preparation runs deterministic Inspector and unit derivation in independent
controller-owned baseline snapshots. Their bounded structural facts, exact units,
public test IDs, task, controls and initial capability manifest are written once
as canonical frozen-plan.json. Both reconstructions must be byte-identical.
Every validation checks the exact file hash and full equality with independent
reconstruction. Source SHA256s and symbols are facts, not implementation content.
No raw source or model reasoning is embedded. Both future workers load the same
validated bytes, copied into separate state objects to prevent cross-arm mutation.

Only Coder and Fixer selection changes: claude-free-default versus
claude-free-gpt-oss-120b. There is no Planner, Researcher or Reviewer model call.
Inspector, preflight, integrity, Tester, rollback, Coder/Fixer adapters, routing
and model attribution use existing production functions. The external benchmark
pipeline reuses the production single-unit Coder/Tester/Fixer gates and global
Fixer budget of two. A Coder timeout stops coding exactly as production does;
it does not receive an automatic retry or extra repair opportunity. Tests that
fail after a completed Coder may receive up to two Fixers under the usual gates.
Test phases record after-Coder, after each completed repair and final post-run
scores; each previous score is the next repair's before score. A timed-out last
repair has a separately labelled POST_RUN observation if safely possible.

Reviewer is excluded from the comparison (option B); deterministic Tester and
post-run scoring determine public results. Production VERIFIED remains dependent
on its existing review/verification rules, which this driver does not alter.
The driver never fabricates review PASS, calls production finalizer/promoter, or
creates a verified promotion patch. Completed benchmark runs remain UNVERIFIED;
timed-out controllers remain BLOCKED even if their partial filesystem passes all
15 tests. production_verified is always false. Machine verification is recorded
separately from OBSERVATIONAL_NOT_PRODUCTION_VERIFICATION scoring.

Only after every observed model worker proves cleanup and zero remaining
processes can post-run scoring use the actual retained target workspace. It
checks the immutable execution manifest, test/verification inventory and baseline
before using the same networkless production test sandbox and 130s budget.
No arbitrary shell or worker test execution is added. An unparseable score is
null/UNAVAILABLE, never guessed from baseline; integrity/sandbox failures remain
driver failures. The score may factually be X/15 while controller completion is
BLOCKED. Cleanup is guaranteed on normal execution/errors/interrupts; an abrupt
process kill leaves the exclusive attempt marker and cannot silently allow retry.

Fresh independently cloned repositories live inside a new stage28-ab-UUID under
/tmp/freeagentos-evals, each named shipment-stage28-auto or shipment-stage28-gptoss.
No Stage 2.7 workspace or artifact is reused. Canonical source is read-only at
0df82b5f7f0b6f5c82ff62b12bf84f5add1e97ec. Preparation requires exactly 6 passed,
7 failed and 2 errors out of 15 in both clones, with matching public test IDs.
The lost hidden suite is unavailable and is not reconstructed.

Both arms have the same initial eight-file readable surface, four writable
existing targets and zero creation-approved paths. allow_new_files remains the
same existing controller setting as Stage 2.7; task language cannot approve
extra paths. Actual repair context/capabilities may narrow according to each
arm's changed files and failures, using the same unchanged production policy.
Root paths/inodes are necessarily workspace-specific and are not capability
expansion. Read/write caps, Planner target cap, base/grace/hard lease, all resource
controls and global Fixer budget remain unchanged. No routing or gateway changes.

Run order is recorded before generation and enforced serially. One exclusive
attempt marker per arm forbids reruns; complete safe evidence/confirmed cleanup
are required before the second arm. Before generation, validate exact controller
commit and clean tree, immutable canonical baseline, both fresh clone baselines,
frozen schema/hash/reconstruction, target manifest, compatible profiles, local
/api/ping health and real production host/resource preflight. No automatic retry.

Private bounded evidence lives in a separate stage28 directory under persistent
benchmark evidence. Records include pinned commit/hash/profiles, before/final and
phase public scores with exact test IDs, worker/result/timeout/lease/broker/tools,
resources, per-role timings, cleanup, changed paths and final diff hash. Coder and
Fixer route summaries are separate and retain per-worker attribution too. Only
SESSION_BOUND_DISPATCH + ROUTER_DISPATCH permits a concrete route; multiple routes
remain sets with unavailable singular identities. Served identity stays
UNAVAILABLE. No raw model output, prompts beyond this controlled fixture, tool
arguments, credentials, provider payloads or test tracebacks are retained.

prepare, validate and compare never invoke a model boundary. run requires explicit
--live and a separately authorized workload. Example commands:

```sh
bin/freeagent-shipment-frozen prepare --expected-controller-commit FULL_SHA --order auto,gptoss
bin/freeagent-shipment-frozen validate --plan NEW_PLAN --arm auto
bin/freeagent-shipment-frozen run --plan NEW_PLAN --arm auto --live
bin/freeagent-shipment-frozen run --plan NEW_PLAN --arm gptoss --live
bin/freeagent-shipment-frozen compare --plan NEW_PLAN
```

No arm is executed in Stage 2.8A. One later run per arm can establish factual
single-run differences only, not a general best-model or statistical claim.
