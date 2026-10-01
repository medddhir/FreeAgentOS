# Stage 2.5: session-bound dispatch attribution

The isolated gateway checkout began clean at
`e4a47f203dba3b610dc180f628d3e821abbaf564`, matching the running Docker image's
revision label. The deployment directory and running container were not changed.
The historical prerequisite handoff remains separate and unchanged.

## Evidence and trust boundary

FreeAgentOS creates a fresh random 128-bit correlation ID for each Claude worker.
The ID is not authentication. A private gateway Unix socket registers the ID and
returns an independent random 256-bit transport token. The gateway stores its
SHA-256 digest, validates the token on each authenticated Anthropic request, and
records only actual dispatch callback `route.platform` and `route.modelId`.

The control directory must be an actual UID-1000-owned directory with mode 0700;
the socket must be UID-1000-owned with mode 0600. FreeAgentOS verifies filesystem
ownership/type/modes and Linux SO_PEERCRED. Only trusted local controller/root
and the gateway service account may access this channel. This trusts the gateway
and its service account, not arbitrary processes using that same account.
No public HTTP attribution endpoint exists. Transport tags are never evidence.

The installed Claude Code 2.1.284 parser accepts newline-separated custom headers
from ANTHROPIC_CUSTOM_HEADERS and supplies them to the SDK default headers;
claude-free preserves that variable and forwards CLI arguments. Deterministic
verification executes only the extracted header parser, alongside synthetic
HTTP gateway and Unix IPC tests. No Claude executable or provider was invoked.
The complete installed client-to-gateway exchange still needs the later live run.

Transport fields travel in controller-owned worker IPC/environment, never in
prompts, model profiles or tool arguments. Reserved inherited header aliases are
removed before insertion. The deprivileged worker cannot access the private
control directory; its existing controlled tools do not expose environments,
processes, arbitrary shell, or the transport token. Worker output cannot author
route evidence: the outer controller overwrites observations using the private
peer response after worker cleanup.

Limits: 64 sessions, 64 requests/session, 16 attempts/request, 32 distinct routes,
16 KiB/evidence response, 600-second TTL, 64 concurrent private IPC connections,
1024-byte control commands and 500 ms socket idle timeout. Controller IPC reads
have a 250 ms timeout. Overflow, open requests, expiry, malformed evidence and
missing transport produce UNAVAILABLE rather than a truncated attribution claim.
Finish consumes the session. Failed dispatch attempts remain represented; multiple
routes produce MULTIPLE_ROUTES and unavailable singular identifiers. Existing
provider fallback behavior is observed without changing it.

Requested identity remains REQUESTED_CONFIG. Route identity claims only
ROUTER_DISPATCH. Anthropic model echo fields are ignored; served identity remains
UNAVAILABLE. Attribution is independent of semantic qualification. No payloads,
headers, credentials, prompts, outputs, tool arguments, file paths or raw errors
are retained in attribution evidence. Registration briefly transfers its private
token; it is not emitted in evidence and is cleared after retrieval.

The socket feature is opt-in in the gateway. An absent/unreachable/invalid socket
or observation error cannot change routing, retries, worker results, permissions,
resources, leases or trusted-progress rules. No production deployment has occurred.

## Later approved deployment procedure (not executed)

Review and commit the isolated patch first, recording its reviewed commit as
PATCH_COMMIT. Verify the service remains UID 1000 (the current node server does).
Keep the existing compose configuration and persistent data volume unchanged.

Build only the isolated checkout, using its existing Dockerfile:

```sh
cd /root/freellmapi-stage25
PATCH_COMMIT=$(git rev-parse HEAD)
docker build --build-arg FREELLMAPI_COMMIT_SHA="$PATCH_COMMIT" \
  --label org.opencontainers.image.revision="$PATCH_COMMIT" \
  -t freellmapi:stage25 .
install -d -m 0700 -o 1000 -g 1000 /run/freeagentos-attribution
```

Create a reviewed isolated-source compose override (not in production source):

```yaml
services:
  freellmapi:
    image: freellmapi:stage25
    environment:
      FREEAGENT_ATTRIBUTION_SOCKET: /run/freeagentos-attribution/gateway.sock
    volumes:
      - /run/freeagentos-attribution:/run/freeagentos-attribution
```

After separate deployment authorization, recreate only the gateway:

```sh
docker compose -f /root/freellmapi/docker-compose.yml \
  -f /root/freellmapi-stage25/compose.stage25.yml \
  up -d --no-deps --pull never freellmapi
```

This requires a gateway replacement/restart. Do not perform it during development.
Verify the reviewed image revision, normal service health, private directory 0700,
socket 0600 and owner UID 1000. Registration/finish IPC readiness checks need no
model generation. On subsequent restarts, an existing stale socket is not blindly
unlinked by the patch: inspect it and establish the previous server has stopped
before an operator removes that exact stale socket. Socket startup failure safely
disables attribution and must be resolved before qualification.

Then, only with separate explicit live authorization, run exactly once:

```sh
/root/agent-stack/bin/freeagent-qualify-model --profile claude-free-gpt-oss-120b --live
```

Require existing execution/tool/result/EOF/exit/cleanup and fixture-semantic checks
to pass independently. Expect requested configuration plus SESSION_BOUND_DISPATCH,
ROUTER_DISPATCH, SINGLE_ROUTE or honest MULTIPLE_ROUTES, safe route pairs, and served
UNAVAILABLE. Missing/incomplete attribution is not a routed identity claim.
One candidate session cannot establish distinctness from default Auto without
separately session-bound default evidence. No shipment run is part of this milestone.
