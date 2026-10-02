# Stage 3.0C — Zero-generation FreeAgentOS doctor

## Purpose and invocation

Installed command: `freeagent doctor`, or `freeagent doctor --json`.
Source checkout: `bin/freeagent doctor`; it uses the existing controller venv
when present, otherwise the current Python so missing dependencies can be
reported. `freeagent --help` is supported. No setup/run/models/skills subcommands
are added. Existing production `freeagent-run` remains unchanged.

Optional arguments: `--config /absolute/config.toml` uses Stage 3.0B precedence;
`--repo /path/to/project` inspects existing root Python test markers only, without
running tests, Git, a build, dependency scripts or any project source.

## Zero-generation and observer contract

Doctor never calls `run_worker`, Claude, a model, qualification, research
services, or a provider generation endpoint. It starts no external command,
namespace, cgroup or attribution session, and performs no registration, finish,
configuration change, installation, ownership change, sudo request, deployment
or service restart. Its source launcher may re-exec the same script with the
existing Python venv; this is not a model/client invocation.

The only HTTP request is unauthenticated **GET /api/ping** on the validated
loopback gateway. That endpoint is present in the inspected FreeLLMAPI app.
Timeout is 0.75 seconds, redirects are not followed, response bodies are not
read, and credentials/headers/raw responses are not retained. This proves
HTTP health/reachability only, not provider authentication, quota or generation.

Path usability uses immediately closed/deleted temporary files in the nearest
existing directory. It creates no persistent directories. It never creates a
cgroup or invokes the active production preflight. Kernel observations are
bounded reads from known `/proc` and `/sys` files. Bundled data existence checks
do not load models or download assets.

## Checks and classification

There are 39 checks: 31 REQUIRED, 6 OPTIONAL, 2 INFORMATIONAL.
Statuses: PASS, WARN, FAIL, SKIP. All output reasons are fixed codes; raw
exception/config/client/provider output is never emitted.

- Installation/core: package files, Python >=3.12, installed runtime dependency
  metadata closure, OS/architecture, production binary paths, version-1 config,
  XDG paths, state writability, workspace root and bundled resources.
- Inference prerequisites: executable launcher, compatible registered role
  profiles, loopback endpoint policy, safe gateway health, credential source
  presence and client compatibility limitations.
- Isolation prerequisites: namespace APIs/interfaces, cgroup v2/controller
  visibility, cgroup.kill visibility, libc/Python prerequisites and current
  effective privileged capability requirements.
- Attribution: optional socket filesystem security and explicit lack of
  authenticated session proof.
- Research: optional curl/mcporter presence and unproven service configuration.
- Target: informational supported root Python test markers. This is not an
  authoritative test-suite/dependency or verification result.

Architecture qualification is limited to the x86_64 reference target. Linux
support checks are necessary prerequisites, not certification of every distro.
Binary observations reflect actual production paths (Git/system Python/setpriv/
chroot/env) or PATH lookup where production does so (unshare). Mounting uses
libc, so no invented mount/nsenter binary requirement is added.

## Readiness semantics and limits

`READY` requires **every REQUIRED check to be PASS**. A required WARN/SKIP is
unknown, not permission to proceed. Optional/informational warnings alone do
not prevent READY. `production_worker_ready` mirrors this conservative result.
Dimensions are `core`, `inference`, `isolation`, `attribution`, `research`;
required checks determine a dimension when present, otherwise all its checks.
These booleans describe observed prerequisites, never actual served models.

**Current read-only doctor cannot certify active worker isolation.** It always
reports required `ACTIVE_ISOLATION_UNPROVEN`; it does not mount namespaces,
create/write cgroups or execute chroot probes. Production's unchanged active
preflight remains mandatory before model execution. Therefore actual current
runs remain NOT_READY even when all static prerequisites pass. Tests cover
READY aggregation for fully proven synthetic records, but no command-line
flag accepts fabricated proof or bypasses this limitation.

Client flag/MCP/stream/result compatibility is likewise `CLIENT_COMPATIBILITY_UNPROVEN`:
no arbitrary launcher --help/--version is executed. Historical installed-client
header extraction tests do not constitute a portable full-client proof.
Credential references check only presence in environment; they do not validate
credentials. With no explicit reference, wrapper integration is UNPROVEN rather
than falsely claiming credentials are missing. Credential names/values, tokens,
private headers and hashes are not printed. Config source is CLI, ENVIRONMENT or
DEFAULT_FILE or BUILTIN_DEFAULTS, plus version; raw TOML and secret-bearing values are omitted.

`cgroup.kill` may be absent at the cgroup root even on a supporting kernel;
absence there is UNPROVEN, not evidence that production's disposable non-root
scope cannot expose it. Root/capability/API checks cannot establish LSM/seccomp
or actual cgroup enforcement, which requires active preflight.

Current development runtime requires privileged Linux operations. Doctor's
remediation explains this fact and future reviewed privilege separation; it
does not recommend chmod 777, disabled controls, or running every task under
sudo. Stage 3.0D must not replace missing security controls with weaker substitutes.

## Attribution optionality

Doctor uses the same filesystem validator as production GatewaySession:
parent directory 0700, socket 0600, existing trusted gateway UID 1000, no
symlink/type substitutions. Production additionally retains its unchanged
peer-credential/token/session validation. Doctor makes no socket connection or
protocol request; authenticated peer and dispatch remain UNPROVEN. A valid
socket does not become ROUTER_DISPATCH evidence, and a missing socket does not
fail inference checks. Requested/routed/served identity semantics are unchanged.

## JSON and exit contract

Schema version 1:

```json
{
  "schema_version": 1,
  "status": "NOT_READY",
  "production_worker_ready": false,
  "dimensions": {"core": true, "inference": false, "isolation": false,
                 "attribution": false, "research": false},
  "checks": [{"id": "active_isolation_proof", "status": "WARN",
              "requirement": "REQUIRED", "dimension": "isolation",
              "reason": "ACTIVE_ISOLATION_UNPROVEN", "remediation": "..."}]
}
```

Each check has the fields shown. Optional `detail` is a resolved binary path,
MISSING, config source/version or UNAVAILABLE; never raw environment/payloads.
Human output uses the same result and non-destructive guidance. Errors use a
fixed `DOCTOR_INTERNAL_ERROR`, schema version 1, status ERROR; usage errors use
fixed `DOCTOR_USAGE_ERROR` and never echo arbitrary arguments.

Exit codes: **0 READY**, **1 NOT_READY**, **2 usage/internal error**. Invalid
configuration is an actionable required failure and returns 1. Optional warnings
never independently change the exit code. No automatic repairs occur.

## Remaining product work

This is not a complete installer or proof of fresh-machine runtime support.
Bootstrap must provision reviewed dependencies/client/config and a qualified
privileged execution boundary; future evidence mechanisms must independently
prove required checks before allowing READY. No provider/model calls are needed
for ordinary doctor observations. FreeAgentOS licensing remains unresolved;
no license is selected by this milestone.

## Verification record

Parent: `e7a10985eb780e316028afb05366f3e06be65b8a`.
Doctor regressions are integrated into the existing bounded foundation table,
with synthetic ready/failure records, configuration/version/endpoint failures,
missing prerequisites, optional attribution, secret-free human/JSON/usage
errors, fixed health-only HTTP, no subprocess/worker/session calls and exit codes.
Focused foundation/doctor plus existing attribution: 2 grouped tests passed in
7.600 seconds. Trusted suite: 518 tests in 231.278 seconds, RESULT=PASS, exit 0.
No output cap, lease, resource or timeout was raised.

Current privileged development machine: NOT_READY, 39 checks (31 REQUIRED,
6 OPTIONAL, 2 INFORMATIONAL), no required FAIL. Required WARN blockers are
CLIENT_COMPATIBILITY_UNPROVEN, CREDENTIAL_SOURCE_UNPROVEN, CGROUP_KILL_UNPROVEN,
ACTIVE_ISOLATION_UNPROVEN. Optional session proof and research configuration,
and informational unselected target are also unproven. Static gateway health,
namespace/cgroup/controller/privilege prerequisites and socket filesystem
security pass. Built-in config defaults are in use. Human and JSON output were
captured under `/tmp`, with no configuration or service change.

Fresh Python venv under `/tmp/freeagentos-stage30c-venv`: pinned dependencies,
local wheel/console installation and pip check passed. Installed `freeagent doctor
--json` ran from `/tmp` using a disposable empty HOME, returned NOT_READY/exit 1
and 39 checks, and left that HOME empty. This validates command installation and
observer behavior, not a rootless installation or a model session. No generation,
worker or attribution session is performed by doctor. Existing trusted tests
independently exercise synthetic workers and isolated local IPC fixtures.
