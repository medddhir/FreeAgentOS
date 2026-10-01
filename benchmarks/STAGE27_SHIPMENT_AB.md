# Stage 2.7A controlled shipment A/B harness

Question: on one controlled workload run per arm, how do Coder/Fixer profile
choices affect completion, public score, repairs, runtime and broker behavior?
This is not a statistical model ranking. Planner and Reviewer retain the same
claude-free-default profile; Researcher remains research-tools and Inspector is
deterministic. Only Coder + Fixer change between claude-free-default and
claude-free-gpt-oss-120b. Common requested profiles do not guarantee identical
upstream routes or planner output; per-session evidence records that variability.

Canonical source is read-only:
/root/freeagentos-benchmarks/shipment-reconciliation-baseline at
0df82b5f7f0b6f5c82ff62b12bf84f5add1e97ec. Only the public 15 tests are scored.
The lost hidden suite is not reconstructed, scored or used for comparison.

The driver is external to the production graph, under benchmarks/. It uses the
existing production API, role mapping, preflight, sandbox, resource and file
policies unchanged. Both arms share the fixed TASK string and its recorded hash.
The task follows README.md, permits controller-approved new implementation files,
and prohibits test edits/deletes/verification edits. Read/write caps, shell
restrictions, 180+60/240 worker lease and Fixer limit 2 are unchanged.

prepare is a no-model dry run: pin the clean controller commit, canonical commit
and clean tree, validate both profile mappings, check only gateway /api/ping and
run deterministic host/resource probes. Create independent clones with no local
hardlinks/alternates in separate arm directories inside a fresh experiment under
/tmp/freeagentos-evals. Test each clone through a controller-owned snapshot and
production networkless test sandbox. Require identical exact test IDs/results and
6/15 passes, with 9 failures/errors. Tests never run in the canonical source.

Persist a private exclusive plan under /root/freeagentos-benchmarks/evidence.
The plan pins controller/baseline commits, task hash, profiles, resource/control
configuration, test IDs/results and chosen run order. Any mismatch fails closed.
Every live arm revalidates both untouched baseline clones and all preconditions
before model invocation. Run requires explicit --live. An exclusive lock enforces
serial execution/order and an exclusive arm-started record prevents reruns even
when an arm fails. Never automatically retry or add repeats. The second arm is
blocked if workspace or worker cleanup is unproven, or the first driver failed.
A collected BLOCKED workload is still a valid observation when cleanup is proven.
Driver exit zero means evidence was collected, not that the workload passed.

Prepare and validate invoke no production task graph or model; active preflight
executes only deterministic Python probes. The production graph is invoked only
by run --live. Its existing retain_workspace option preserves the final working
state briefly for scoring. Streamed controller states preserve failure evidence
without changing graph nodes. Final tests use the same production sandbox and
pinned immutable test inventory, then the existing cleanup routine removes the
retained run directory. Source arm clones remain unchanged. Both arms use this
identical retention/scoring/cleanup policy. Interrupted runs record honest partial
evidence; a process crash leaves an arm-started marker and never permits retry.

Safe bounded JSON records contain times, controller outcome/block code, profiles,
public baseline/final scores and IDs, patch hash/changed paths, Fixer counts, role
timings, per-worker completion/result/timeout/lease/broker/tool/resource/cleanup
and requested/route identity metadata. If scoring cannot complete, public_after
is null rather than guessed from stale output. No raw model/test streams,
prompts, arguments, credentials, provider payloads or raw exceptions are stored.
Raw incidental output is discarded rather than buffered. Verified production
patches are copied only as private evidence artifacts; never applied anywhere.
The hash of the actual final Git diff (plus sorted new-file diffs) is separate
from a verified promotion patch hash.

Only controller-authenticated session observations qualify as ROUTER_DISPATCH.
Workload coding-route aggregation requires evidence for every observed Coder/Fixer
session. Otherwise the aggregate is UNAVAILABLE while each session retains its
own honest evidence. Distinct routes produce MULTIPLE_ROUTES and unavailable
singular provider/model fields. Requested identities are never used to infer a
route, and routed identity never becomes served identity (UNAVAILABLE).

Choose and record order before either live arm. Use one offline coin toss if an
unbiased order is preferred; then pass the resulting explicit order to prepare.
Avoid concurrent loads, use serial runs, and record timing. Do not add warmup
model calls. A single pair cannot remove temporal/cache/provider variability.

Commands (prepare prints the concrete private plan path):

```sh
bin/freeagent-shipment-ab prepare --expected-controller-commit FULL_REVIEWED_COMMIT --order auto,gptoss
bin/freeagent-shipment-ab validate --plan /root/freeagentos-benchmarks/evidence/EXPERIMENT/plan.json
bin/freeagent-shipment-ab compare --plan /root/freeagentos-benchmarks/evidence/EXPERIMENT/plan.json
```

Only after separate live authorization, in the plan's recorded order:

```sh
bin/freeagent-shipment-ab run --plan /root/freeagentos-benchmarks/evidence/EXPERIMENT/plan.json --arm auto --live
bin/freeagent-shipment-ab run --plan /root/freeagentos-benchmarks/evidence/EXPERIMENT/plan.json --arm gptoss --live
```

compare is deterministic and reports only factual results, with explicit
single-run/no-statistical-superiority flags. Attribute workload results to a
route only with SESSION_BOUND_DISPATCH and ROUTER_DISPATCH. A blocked workload
still has a public score if final scoring completes; failed scoring stays unknown.
Do not promote either result to the immutable canonical benchmark.
