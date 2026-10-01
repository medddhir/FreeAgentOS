# Stage 2.5 session-bound route attribution: source prerequisite blocked

Status: PARTIAL. No gateway/controller attribution implementation is installed.
No source checkout, running service, credential, routing policy or checkpoint was
modified. No qualification, generation, network source fetch or restart was run.

## Verified installation

- FreeAgentOS starting HEAD: e00187c, Stage 2.4A verified checkpoint.
- Port 127.0.0.1:3001 is published by docker-proxy, PID 822 at inspection.
- Container: freellmapi-freellmapi-1; internal port 3001.
- Image: ghcr.io/tashfeenahmed/freellmapi:latest.
- Installed image ID:
  sha256:db20496c7345a148572c9884f39fa2b0889ce1cdce82067597239bcf8f1987e8.
- Image revision label: e4a47f203dba3b610dc180f628d3e821abbaf564.
  This is image metadata, not a verified local Git source commit.
- Compose metadata: /root/freellmapi/docker-compose.yml; working directory
  /root/freellmapi. Restart policy: unless-stopped.
- Entrypoint: /usr/local/bin/docker-entrypoint.sh; command:
  node server/dist/index.js.
- Data volume destination: /app/server/data. No development-source mount.
- Installed server package: @freellmapi/server, version 0.2.1.
- Deployment directory has no .git, package.json, server or src tree.
- Container has /app/server/dist/routes/anthropic.js, but no /app/.git or
  /app/server/src/routes/anthropic.ts.

There is no verified gateway source working tree whose cleanliness or exact
commit can be established locally. An initial Git probe traversed into parent
metadata; that parent is unrelated and was not used as gateway source. A repeat
with GIT_CEILING_DIRECTORIES=/root confirmed that the deployment directory is not
a Git repository. No parent worktree/reset/checkout operation was attempted.

The installed claude-free launcher fixes ANTHROPIC_BASE_URL to the loopback
service and forwards arguments to Claude Code. The installed client binary
contains ANTHROPIC_CUSTOM_HEADERS, but a marker is not proof of supported header
syntax, overriding behavior or propagation on every agent request. Those remain
unverified. No client invocation was performed to test them.

## Exact isolated-source prerequisite

Provide a local gateway source repository containing the full revision
 e4a47f203dba3b610dc180f628d3e821abbaf564 (or independently establish the correct
installed source revision). Verify its repository root without parent traversal,
then record its commit and bounded working-tree status. Create a separate detached
development worktree/copy from that exact commit, outside the original checkout.
Do not alter the original deployment, its data volume or running container.
Do not substitute current upstream HEAD or an unverified compiled-build copy.
No source retrieval or deployment is authorized by this handoff.

## Minimal patch contract for that isolated source

1. Add one gateway attribution module and test suite. Maintain a bounded active
   session registry: random controller-generated 128-bit-or-greater opaque
   attribution_session_id, fixed request/attempt counters and metadata only.
   The ID encodes no task, user, path, model or credential information and must
   never appear in prompts. Suggested limits: 64 active sessions, 64 requests per
   session, 16 recorded attempts per request, 32 distinct routes per session,
   maximum 16 KiB per evidence record and 600-second retention. These are proposed
   observation limits, not worker leases or router retry limits. Mark overflow,
   incomplete requests and expiry explicitly; never truncate into a success.

2. Establish a trusted transport binding before accepting the new header.
   Proposed ID header: X-FreeAgentOS-Attribution-Session. Prove installed-client
   propagation using a synthetic local HTTP fixture only; do not invoke an
   upstream provider. Overwrite/remove case-insensitive duplicate reserved headers
   in controller-owned transport configuration. A prompt, model result, arbitrary
   state field or caller-supplied body.model cannot create or replace this ID.
   Keep the normal model command/profile and capability policy independent.

   The ID is non-secret correlation metadata, NOT a bearer credential. Randomness
   alone does not authenticate another client's claimed ID. Registration/retrieval
   must use an independent controller-only channel with verified peer ownership.
   Bind inbound requests to that registered transport, not just possession of the
   public ID. If the TCP/client interface cannot attest this, use a separate
   authenticated transport tag, provisioned through the controller-only channel,
   excluded from all evidence and held outside model-visible data. The opaque ID
   remains non-secret. Do not expose a public evidence endpoint or treat a shared
   gateway API key/client-agent string as proof of worker-session membership.

3. In routes/anthropic.ts, after normal authentication and request validation,
   resolve the verified active attribution context. Assign each Anthropic request
   its own monotonically increasing request ordinal; concurrent requests in one
   session must not share an attempt list. Unknown/invalid/expired contexts yield
   no attributed evidence and must not alter ordinary routing decisions.

4. At the existing runFallbackLoop dispatch callback, immediately before calling
   streamCompletion or provider.chatCompletion, record route.platform and
   route.modelId, request ordinal and attempt ordinal as ROUTER_DISPATCH evidence.
   Copy only approved catalog/configuration identifiers. Never copy route.apiKey,
   key IDs/labels, proxy URLs, request messages, tool arguments or errors. Record
   fixed outcomes DISPATCHED/COMMITTED/COMPLETED/FAILED/CANCELED; close each request
   in finally, including disconnect/error paths, without adding retries.

   Record actual attempts, including pre-commit fallback, rather than just the
   last X-Routed-Via value. One worker session may use multiple routes. Report a
   bounded set/list, counts and completeness. Do not claim a singular routed
   model when routes differ or evidence is incomplete. Default Auto and explicit
   candidate requests must use the identical observation hooks.

5. Expose sealed metadata through the controller-only local channel. A private
   Unix socket with peer-credential checks, or a restrictive controller/gateway
   spool with verified writer ownership, is preferable to shared request logs.
   Fetch the exact registered session, seal after worker cleanup and all matching
   requests close, then expire/delete it. Validate source ownership, freshness,
   exact session binding, bounds and schema before the controller accepts it.
   Missing, mismatched, stale or overflow evidence remains UNAVAILABLE. Do not
   read global analytics by timestamp, requested model, IP or client-agent name.

6. In FreeAgentOS, extend model_attribution.py with that authenticated consumer;
   integrate controller-owned session lifecycle around run_worker, including
   exception/timeout cleanup. The production service remains unchanged until a
   later approved deployment. The isolated source and synthetic gateway/client
   tests must pass before enabling a consumer. An evidence label or syntactically
   valid header in worker stdout is never an authenticated ingestion boundary.

   Qualification output retains separate requested_model_id/REQUESTED_CONFIG,
   routed provider/model observations/ROUTER_DISPATCH and served_model_id.
   Stage 2.5 route-only work should leave served_model_id=UNAVAILABLE. Native
   upstream attribution requires a separate provenance boundary excluding
   synthesized tool-rescue responses and requested-model echo fields. Do not
   rename dispatched identity as served identity.

## Deterministic acceptance cases before deployment

- Two concurrent workers cannot merge or retrieve one another's sessions.
- Multiple/concurrent Anthropic requests and failed dispatch attempts retain
  correct session/request/attempt association and fixed bounded outcomes.
- A known public session ID without authenticated transport binding cannot
  contribute evidence; spoofed headers, prompt/model claims and raw payloads
  cannot register sessions, route evidence or served identity.
- TTL, overflow, malformed evidence, disconnect, late requests and controller
  interruption do not produce a complete-session identity claim.
- Header transport is exercised against a synthetic local fixture and the real
  supported client integration, without provider generation.
- Evidence never contains tokens, auth tags, headers, URLs, prompts, model text,
  arguments, file contents, paths, user/session semantic data or raw exceptions.
- Profile selection, sealed file policy, new-file approvals, sandbox, resources,
  180+60/240-second lease and Fixer budget remain byte/behavior equivalent.
- Default Auto weights/preferences and existing provider fallback are unchanged.
- Corrected fixture verification remains independent of route attribution.

No live qualification or shipment run is recommended in this blocked-source
state. Existing requested identity remains trustworthy; routed/served identity
remains UNAVAILABLE until the transport and isolated gateway patch are verified.
