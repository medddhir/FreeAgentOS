# Stage 2.6A: default client profile session characterization

At verified checkpoint 503b3d4, model_qualification.describe accepted only the
explicit GPT-OSS profile. qualify called describe before catalog_ready, workspace
creation, capability sealing, command construction, attribution setup or worker
spawn. claude-free-default therefore raised QUALIFICATION_PROFILE_INVALID; main's
privacy-preserving catch converted it to QUALIFICATION_FAILED/BLOCKED. The saved
Stage 2.6 output matches that branch. The failed default attempt could not invoke
a worker or provider through this code path. A deterministic mocked reproduction
confirmed catalog, workspace and worker functions were never called.

The default profile is registered and Coder/Fixer compatible at the client
adapter level. Its model_id is None and model_command omits --model. CLIENT_DEFAULT
with REQUESTED_CONFIG records that controller configuration, not a concrete
model, nor a promise that the gateway will choose a particular Auto route.

The same full semantic session smoke now accepts two explicit controller profiles:
the existing concrete candidate and claude-free-default. A separate weaker route
operation is unnecessary: the full smoke exercises the same tiny Read/Edit fixture,
result, EOF, exit, cleanup, resource and semantic gates for both. The new fixed
qualification_scope distinguishes EXPLICIT_MODEL_SESSION from CLIENT_DEFAULT_SESSION.
SESSION_SMOKE_PASS describes one profile session, never a permanently qualified
upstream model, served identity, coding quality or long-session reliability.

Only the concrete candidate depends on its existing pinned Groq catalog check;
applying that check to the default would incorrectly couple default readiness to
the candidate's availability. Default retains role compatibility validation and
all the same sandbox/security/preflight/worker checks. Unknown profiles and other
registered profiles outside this narrowly approved smoke scope remain rejected
before any worker invocation. No selection, retry, gateway routing or policy is
changed, and no concrete-profile gate is relaxed.

Requested, routed and served identities remain independent. Default requested
identity stays CLIENT_DEFAULT even if the gateway dispatches a concrete model.
Only existing session-bound controller gateway evidence can supply ROUTER_DISPATCH.
Multiple routes keep MULTIPLE_ROUTES and unavailable singular identifiers. Missing
evidence remains UNAVAILABLE; a semantic session pass alone does not establish a
route. Served identity remains UNAVAILABLE regardless of requested or routed data.

Non-live description (does not check the gateway or start a worker):

```sh
/root/agent-stack/bin/freeagent-qualify-model --profile claude-free-default
```

After separate explicit authorization, the one controlled default observation is:

```sh
/root/agent-stack/bin/freeagent-qualify-model --profile claude-free-default --live
```

For successful session-and-route characterization, require SESSION_SMOKE_PASS,
all independent qualification_checks PASS, requested CLIENT_DEFAULT, and gateway
SESSION_BOUND_DISPATCH / ROUTER_DISPATCH with honest SINGLE_ROUTE or MULTIPLE_ROUTES.
A pass with attribution UNAVAILABLE cannot establish default route distinctness.
Do not copy the dispatched model into requested or served identity. Do not rerun
the already successful GPT-OSS candidate. No live observation was performed while
implementing this correction.
