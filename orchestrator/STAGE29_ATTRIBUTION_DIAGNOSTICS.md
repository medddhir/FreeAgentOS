# Stage 2.9A attribution lifecycle diagnostics

Attribution diagnostics are additive lifecycle observations from the common
production `run_worker()` wrapper. They are not provenance and never participate
in `route_observation()` acceptance. Existing route projection is unchanged.
Qualification and benchmark consumers use the same CLI evidence whitelist.

The `attribution_diagnostics` object contains only fixed categories, booleans,
and bounded counts. It has no session ID, token, header, payload, model text,
prompt, path, provider metadata or exception text.

- `registration_attempted`, `registration_status`: REGISTERED,
  GATEWAY_UNAVAILABLE, INVALID_EVIDENCE, IPC_FAILURE, PEER_INVALID, IPC_BOUNDS,
  or UNAVAILABLE. A rejected registration does not reveal capacity/auth/TTL cause.
- `custom_headers_configured`: whether the validated controller transport was
  used when spawning the inner model process. Missing spawn evidence remains
  UNAVAILABLE. This does not assert attachment to individual HTTP requests.
- `finish_attempted`, `finish_ipc_status`: SUCCESS, IPC_FAILURE, PEER_INVALID,
  IPC_BOUNDS, INVALID_EVIDENCE, or UNAVAILABLE. Finish remains after cleanup on
  normal completion, base timeout and hard-cap timeout, with no retries.
- `gateway_record_status`: COMPLETE, INCOMPLETE, SESSION_UNAVAILABLE,
  INVALID_EVIDENCE, or UNAVAILABLE. SESSION_UNAVAILABLE reflects the gateway's
  existing UNAVAILABLE response, not a claim about why its session was absent.
- `request_count` (0..65), `settled_count` and `unsettled_count` (0..64),
  `attempt_count` (0..1024), `route_count` (0..32): derived only from validated
  existing session-bound response structure. Settled means a closed request
  with nonempty, terminal attempts. Counts describe retained records, not
  every attempted upstream operation; counts never grant route identity.
- `overflow`: true only when the gateway's saturated counter proves request
  overflow. Otherwise UNAVAILABLE: the existing protocol does not expose its
  general incomplete/overflow flag. No gateway extension is required.
- `projection_status`: ACCEPTED, REJECTED, UNAVAILABLE.
- `projection_reason`: ACCEPTED, REGISTRATION_UNAVAILABLE, IPC_FAILURE,
  SESSION_UNAVAILABLE, NO_ROUTE_OBSERVED, INCOMPLETE, INVALID_EVIDENCE,
  BOUNDS_REJECTED, DIAGNOSTIC_FAILURE, UNAVAILABLE. Instrumentation failures
  do not discard accepted route proof. NO_ROUTE_OBSERVED means a validated session
  record with zero requests. Its raw gateway class remains INCOMPLETE, and
  route identity remains unavailable. Nonzero incomplete records remain
  INCOMPLETE even if some attempts appear settled.

Old gateway responses are supported without changes. Unknown fields and
out-of-range diagnostic values project to UNAVAILABLE. Served identity stays
independent and unavailable. No deployment is required for these controller
changes. Historical Stage 2.8 evidence cannot be retroactively diagnosed.

Pure tests simulate settled single route, incomplete open request, failed
registration with no configured headers, and hard-cap timeout with settled
multiple routes. One later separately authorized tiny diagnostic could check
these fields against the deployed gateway; it cannot establish the cause of
historical attribution loss or prove headers reached every internal request.
