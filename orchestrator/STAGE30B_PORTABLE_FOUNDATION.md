# Stage 3.0B — Portable configuration and dependency foundation

This milestone preserves the production graph, Linux isolation, file policy,
resource controls, leases, repair limits and attribution evidence meanings.
It is not a complete installer, setup wizard, rootless runtime or new provider.
Public source is not formally open-source until the owner selects a license;
no license is selected by the project metadata.

## Python and reproducibility

Python requirement: **>=3.12**. Development version is manually maintained as
`0.3.0.dev0` in PEP 621 `pyproject.toml`. Production imports were inspected:
LangGraph is the sole direct third-party Python runtime import. The repository's
deterministic tests use stdlib unittest; there is no pytest requirement for
this suite. Arbitrary target projects can independently require pytest/npm/etc.
Benchmarks use controller runtime plus stdlib and external fixtures, not an
additional Python dependency set.

`requirements.lock` pins the 38-distribution non-extra runtime closure from the
verified Python 3.12 environment; it is not an indiscriminate pip freeze.
`requirements-build.lock` pins setuptools/wheel separately. The optional `dev`
extra contains those build tools. No heavyweight package manager is introduced.
The lock is qualified on Linux/Python 3.12; other interpreter/platform combinations
need independent dependency and isolation qualification. Pins reproduce versions;
these files do not authenticate package artifacts with hashes. Use a trusted
package index and review dependency updates explicitly.

Example disposable development environment (not a full installation):

```bash
python3.12 -m venv /tmp/freeagentos-dev
/tmp/freeagentos-dev/bin/python -m pip install -r requirements.lock -r requirements-build.lock
/tmp/freeagentos-dev/bin/python -m pip install --no-build-isolation --no-deps .
/tmp/freeagentos-dev/bin/python -m pip check
/tmp/freeagentos-dev/bin/freeagent-run --help
```

For the existing source-tree launcher, provision the same pinned environment
at `.venv-orchestrator` instead. The installed console script bridges the
existing controller module layout; it does not replace the orchestration graph.
Neither installation nor `--help` calls a model. Full production operation still
needs a qualified privileged Linux environment, a compatible client/launcher,
provider access and target verification dependencies.

To update the lock: in a disposable environment install the intentionally
selected LangGraph version; traverse `importlib.metadata.distribution(...).requires`
using `packaging.requirements.Requirement`, evaluating markers with `extra=''`,
starting at LangGraph. Write sorted canonical names and installed versions for
that closure. Update metadata and build pins deliberately, then repeat fresh-venv,
`pip check`, focused tests and trusted suite. Never include environment URLs,
credentials, unrelated packages, editable paths or global pip configuration.

## Portable files and user locations

`orchestrator/foundation.py` owns resource lookup, user paths, configuration and
launcher discovery. Bundled JSON indexes and approved utility scripts resolve
from the checkout or installed package resources, independent of cwd. Research
scripts no longer require `/root/agent-stack`. No indexes are downloaded or
copied during import. `build_indexes.py` derives its source root from its file.

| Kind | Default | Standard override | FreeAgentOS override |
| --- | --- | --- | --- |
| Config directory | `~/.config/freeagentos` | `XDG_CONFIG_HOME` + `/freeagentos` | `FREEAGENTOS_CONFIG_HOME` |
| User data | `~/.local/share/freeagentos` | `XDG_DATA_HOME` + `/freeagentos` | `FREEAGENTOS_DATA_HOME` |
| Cache | `~/.cache/freeagentos` | `XDG_CACHE_HOME` + `/freeagentos` | `FREEAGENTOS_CACHE_HOME` |
| State/evidence | `~/.local/state/freeagentos` | `XDG_STATE_HOME` + `/freeagentos` | `FREEAGENTOS_STATE_HOME` |

FreeAgentOS directory overrides are exact directories, with no suffix added.
All overrides must be absolute. APIs resolve paths without creating directories.
User-generated indexes can later live under the returned data directory's
`indexes/`; they do not automatically replace controller-bundled catalogs.
Future doctor/setup can use these APIs for state/evidence. Existing disposable
workspace roots/recovery rules and historical benchmark evidence locations are
not migrated in this stage; generated user state is not newly written into
package source. Developer global policy synchronization and historical
benchmark/qualification host assumptions remain separate installation work.

## Versioned configuration and precedence

Format: TOML, read with stdlib tomllib. Version: `config_version = 1`.
Default file: the resolved config directory's `config.toml`.

Config-file selection is **CLI `--config` > `FREEAGENTOS_CONFIG` > resolved
config-directory default**. An explicit missing file is an error; absent default
file uses safe built-in defaults. There is no file merging. Directory resolution
is **FreeAgentOS directory override > XDG directory > HOME fallback**.
Role selection is **explicit controller/CLI role override > config `[models]`
role assignment > registry role default**. CLI tasks/model output never select
configuration or authorize capabilities. The CLI scopes one immutable
configuration through a graph invocation, avoiding per-worker file changes.
Direct controller APIs should use `config_scope(load_config(...))` around their
operation for the same snapshot behavior.

Only these fields are supported:

- `config_version`: integer 1.
- `[adapter]`: `launcher`, `endpoint`, optional `credential_env` (variable name).
- `[attribution]`: boolean `enabled`, absolute `socket`.
- `[models]`: existing role names mapped to registered compatible profile IDs.

Unknown fields, unsupported versions, malformed TOML, invalid types, invalid
profiles and relative security-critical paths fail with fixed diagnostic codes.
Security/resource/lease/permission fields are not part of this schema. XDG
paths are a filesystem foundation, not new permission or resource knobs.
`examples/config.toml` contains no credentials or personal home paths.

## Launcher and endpoint contract

Default launcher is the PATH name `claude-free`, preserving today's development
installation. An explicit executable path must be absolute. `discover_launcher`
returns a fixed `ADAPTER_LAUNCHER_UNAVAILABLE` diagnostic if unavailable.
Commands are structured argv, never shell command strings; there is no generic
configurable argument prefix. Existing adapter/profile logic continues to own
all model, stream/result, strict MCP and permission flags. A launcher must accept
those flags unchanged and implement the same Claude client contract. Selecting
a launcher does not add a provider adapter or change authorization.

Endpoint defaults to `http://127.0.0.1:3001`; only HTTP/HTTPS exact loopback hosts
(`localhost`, `127.0.0.1`, `::1`) are accepted. Credentials in URLs, query strings,
fragments and endpoint path prefixes are rejected. No network listener is created.
The worker configures `ANTHROPIC_BASE_URL` and its optional `/health` observation
from that endpoint. The existing external `claude-free` wrapper overwrites its
own endpoint; to use a different configured endpoint, choose a compatible
launcher that honors the environment (for example the installed `claude`
executable, once its required flags/credentials are validated). This stage does
not rewrite that external wrapper or read/copy its credential store.

`credential_env` references a validated environment VARIABLE NAME only. If set,
the child copies its inherited value to `ANTHROPIC_AUTH_TOKEN`; the value never
enters TOML, the worker request, examples or telemetry. Missing referenced
credentials fail. This is not a credentials vault. Keep secrets outside Git,
use private user configuration/keychain integration in a later setup stage,
and do not log raw environments or token/header values.

## Optional attribution

Default enhancement remains enabled at
`/run/freeagentos-attribution/gateway.sock`, retaining the existing deployment.
Config can select another absolute socket path or disable the enhancement.
Expected gateway UID remains the existing trust anchor 1000; it is deliberately
not a freely configurable ownership-bypass setting. Parent 0700, socket 0600,
ownership, peer credentials, session authentication, bounds and fail-closed
projection remain intact. Future normal-user installations must establish a
compatible ownership/trust contract; changing a path alone does not solve that.
Missing/untrusted IPC still degrades to unavailable attribution and diagnostics.

Configured alternative launchers receive the same ordinary production attribution
lifecycle as the legacy name. REQUESTED_CONFIG, ROUTER_DISPATCH, UPSTREAM_REPORTED
and UNAVAILABLE retain their meanings. Requested/echoed/routed identity never
becomes served proof. No gateway change or deployment is needed for this stage.

## Limits and next work

This foundation does not solve privileged execution, target dependency provisioning,
complete setup, broad platform qualification, extra providers, skill runtime or
licensing. Installed-package import/help/resource checks are not a complete
fresh-machine production certification. The current verified source installation
and existing wrapper remain compatible; root-specific developer/benchmark paths
are not relabeled as portable public interfaces.

Next: Stage 3.0C `freeagent doctor`, with no generation by default, should use
these APIs to report Python/dependency/client/config/endpoint/socket readiness,
then prove required Linux controls with bounded deterministic probes. It must
never report READY when required security controls are absent, never print
secrets, and distinguish optional attribution from inference readiness.

## Verification record

- Parent: `30cc66e6a79ed71fed075d5a5a0a3e3d080480f4`.
- Focused controller regressions: 76 tests passed in 15.351 seconds, including
  the compact 21-case foundation table and existing profile/attribution/worker/
  lease coverage.
- Final trusted `bin/freeagent-test`: 518 tests passed in 214.844 seconds,
  `RESULT=PASS`, exit 0. Existing timeout/output limits were not raised.
- Fresh Python 3.12 venv under `/tmp/freeagentos-stage30b-venv`: installed the
  pinned runtime/build requirements and the locally built wheel; `pip check`
  passed. Installed graph/CLI/Coder/Fixer/worker imports, default config, resource
  lookup and local research helpers passed from `/tmp`, outside the checkout.
  Installed CLI `--help` passed. New foundation table: 1 unittest containing
  21 regression cases passed in 0.197 seconds with the fresh interpreter.
- No live model, provider generation, benchmark or qualification execution;
  no gateway changes/restarts; no global/system Python package installation.
- This validates dependency/configuration/package plumbing, not a complete
  non-root fresh-machine runtime or additional platform/client compatibility.
