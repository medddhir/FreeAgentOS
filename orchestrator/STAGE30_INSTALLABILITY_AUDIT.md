# Stage 3.0A — Fresh-machine installability audit

Audit date: 2026-10-02. Audited FreeAgentOS commit:
`dbc72e8aaf9456c9bd056d68614dff60a4fdc1f5`, tagged
`stage-2.9b-verified`. This document is an audit and proposed design, not an
installer, a platform certification, or authorization to change security.

## CURRENT_INSTALLABILITY_STATUS

**Not ready for a supported fresh-user installation.** An expert can manually
reconstruct the present privileged Linux environment, but the public tracked
repository does not specify or bootstrap that environment. There is no
`install.sh`, dependency manifest/lock, setup wizard, or installation guide.
There is no tracked project license. Public visibility alone does not establish
an open-source redistribution license.

An executable, no-model check reproduced the first blocker: a temporary
`git archive HEAD` snapshot, containing only tracked files, returned exit 4 for
`bin/freeagent-run --help`, with `PRODUCTION_RUNTIME_UNAVAILABLE`. The launcher
requires `.venv-orchestrator/bin/python3`, which is ignored and not provisioned.
The temporary snapshot was removed. No worker or provider was invoked.

The current product requires an existing clean Git repository and supported
pre-existing tests. `freeagent-run --repo PATH --task TEXT` snapshots that
repository; a verified result yields a promotion-ready patch rather than
editing the original. The proposed “build a todo app” from an empty directory
is not currently a supported project-initialization workflow. Dependency
provisioning and trusted starter/test scaffolding need explicit design.

### Ordered blockers

1. No reproducible Python/bootstrap installation or dependency metadata.
2. Privileged Linux isolation is required; no non-root privilege broker exists.
3. Untracked `claude-free` wrapper depends on another root user's credentials
   file; no portable provider/client setup is shipped.
4. No public configuration, dependency doctor, or first-run workflow.
5. Target test dependencies are not generally provisioned inside verification.
6. Conditional research tools contain installation-root assumptions and require
   external MCP configuration.
7. Enhanced attribution requires a separately patched gateway, a private
   socket, and a fixed ownership contract not distributed by this repository.
8. Missing license, public documentation, security/reporting policy, and CI.

## DEPENDENCY_MATRIX

“Required” means required by the current execution path, not a recommendation
that every future provider must use the same implementation.

| Dependency | Classification | Evidence / detection / fresh-machine gap |
| --- | --- | --- |
| Linux kernel with mount/PID/network namespaces, procfs, cgroup v2 CPU/memory/pids and `cgroup.kill` | REQUIRED | `roles/preflight.py`, `sandbox.py`, `worker.py`; static checks plus active sandbox/worker probes. Missing controls fail closed. |
| Privileges for namespace/mount/cgroup/chroot/device/ownership operations | REQUIRED today | Current code is not a rootless implementation; see privilege section. |
| Python 3.12+ with matching system/venv ABI | REQUIRED | `inspector.py` uses `tomllib` (3.11+); worker uses `os.unshare` (3.12+). Current runtime is Python 3.12.3. Verify the complete supported version range before publishing one. |
| `.venv-orchestrator` and LangGraph | REQUIRED | Launcher pins repo-relative venv; `graph.py` imports `langgraph.graph`. No requirements/pyproject/lock. Current installed LangGraph is 1.2.12; this is environment evidence, not a supported dependency pin. |
| LangGraph transitive dependencies | REQUIRED via package resolution | Installed metadata lists langchain-core, langgraph-checkpoint, langgraph-prebuilt, langgraph-sdk, pydantic, xxhash. Future lock must capture a tested complete environment. |
| Git | REQUIRED | Repository inspection, snapshots, integrity, patch generation; controller strips Git configuration overrides. Preflight checks executable. |
| util-linux `unshare`, `setpriv`; coreutils `chroot`, `env`; system Python | REQUIRED | Executable checks and active probes. Several commands use absolute `/usr/bin` or `/usr/sbin` paths. libc mount/umount support is also assumed. |
| Claude Code compatible CLI | REQUIRED for current model adapter | Shared command builder assumes particular print/JSON/stream/MCP/permission flags. Worker checks executable resolution, not all protocol/version compatibility. Must pin or qualify client releases. |
| `claude-free` | REQUIRED for current model adapter | Always the model command executable; wrapper is not in the repository. |
| Compatible Anthropic endpoint, credentials and enabled tool-capable route | REQUIRED for current adapter | Current wrapper fixes local FreeLLMAPI endpoint. Actual upstream models are selected by the external gateway, not Python SDKs here. |
| Target project's test dependencies | REQUIRED for that target | unittest needs only stdlib; pytest/npm branches need their respective runtime/dependencies. An unrecognized or unavailable test runner cannot establish verification. |
| Docker / Compose | OPTIONAL deployment; BENCHMARK/DIAGNOSTIC in specific tools | Common local FreeLLMAPI deployment choice. Not required by core `run_worker()` itself. Qualification additionally queries a named Docker service/catalog. |
| Patched gateway private attribution IPC | OPTIONAL enhanced runtime | Missing registration/IPC preserves worker execution and reports unavailable attribution with diagnostics. Required to obtain current trusted ROUTER_DISPATCH evidence. |
| `curl` / Jina Reader | OPTIONAL, required when that research action is selected | `research_execution.py` owns bounded HTTPS commands; no arbitrary shell. |
| `mcporter` and configured Exa MCP service | OPTIONAL, required for Exa research | `bin/exa-intel` invokes `exa.web_search_exa`; configuration/bootstrap is not tracked. Provider/service access may have costs. |
| Checked-in research JSON indexes | OPTIONAL, required for local catalog research | `dev-intel`, `prompt-intel`; their data paths are currently root-specific. |
| Node / npm | OPTIONAL target/service tooling; DEVELOPMENT_ONLY for client header tests | Native Claude need not imply npm installation. Gateway has its own external Node dependencies. Repository header test invokes Node on extracted installed-client code. Node/npm target verification requires binaries available in the sandbox. |
| pip / Python venv support | Installation/development dependency | Needed for future reproducible bootstrap; no bootstrap exists now. |
| pytest | OPTIONAL target tests, not required for repository unittest discovery itself | Runner chooses based on target layout. Do not silently assume controller venv has every target package. |
| Codex, RTK, Hermes | Not production runtime requirements | Codex/RTK appear in global policy synchronization; Hermes is an accidental local wrapper credential-store dependency, not an orchestration requirement. |
| Upstream catalog checkouts under `sources/` | DEVELOPMENT_ONLY | `build_indexes.py`; ignored and absent from a public clone. Not required to consume tracked indexes. |
| Shipment fixtures, immutable commits, Docker catalog checks | BENCHMARK_ONLY / developer qualification | Must not become first-user installation dependencies. |

The repository's substantive Python runtime is stdlib plus LangGraph. It does
not directly import an OpenAI/Anthropic model SDK. Installing an SDK alone
would not replace the Claude tool-loop adapter.

### Verification dependency gap

The tester copies a bounded target snapshot, excludes dependency directories
such as `node_modules` and virtualenvs, disables test networking, and exposes
the controller venv read-only. System interpreter and site-packages must match.
This is intentionally restrictive, but a fresh arbitrary web-app target may
lack its test dependencies. A future installer/setup must support trusted,
explicit dependency preparation before the verification sandbox, with reviewed
artifacts and retained provenance. Do not enable network installation or
arbitrary dependency scripts inside verification as a convenience shortcut.

The trusted controller suite budget remains 420 seconds. Target runner limits
and the sandbox's separate 150-second ceiling remain unchanged. Existing
preflight is a security probe, not a complete installation doctor.

## HARD_CODED_PATHS

| Path / assumption | Classification | Action proposed, not performed |
| --- | --- | --- |
| `/root/agent-stack/data` in `bin/dev-intel`; prompt index path in `bin/prompt-intel` | Conditional production blocker for research | Derive bundled data from installed package location; allow only validated controller configuration for external data. |
| `/root/agent-stack` in `build_indexes.py` | Development-only | Portable repository discovery for index maintenance. |
| `/root/agent-stack/skills`, `/root/.claude`, `/root/.codex` in `sync-agent-policy` | Developer-only, unsuitable public setup | Never automatically run: it overwrites global agent files without merge/backup. Replace only with separately authorized integration later. |
| `/root/.hermes/.env` in installed `claude-free` | Production blocker | Replace incidental root-owned credential dependency with a documented private user configuration boundary. |
| `http://127.0.0.1:3001` in wrapper and worker health probe | Should become configurable | Separate adapter endpoint configuration from optional health observation; default local binding remains private. Worker probes `/health`; health alone does not prove provider compatibility. |
| `/run/freeagentos-attribution/gateway.sock`, expected gateway UID 1000 | Optional attribution portability blocker | Installation-owned path and authenticated expected peer configuration; preserve ownership/mode/peer checks. |
| `/usr/bin/git`, `/usr/bin/python3`, `/usr/bin/setpriv`, `/usr/sbin/chroot`, `/usr/bin/env`, `/usr/bin/curl` | Linux filesystem assumptions | Doctor must validate real binaries and controlled execution paths; do not accept arbitrary task-selected executables. |
| `/sys/fs/cgroup`, `/proc` | Required Linux kernel interfaces | Not ordinary home-directory settings; validate kernel/delegation model. |
| `/root/agent-stack` inside synthetic test rootfs | Acceptable isolation layout | This is an empty sandbox path, not a requirement to install on the host under `/root`. |
| `/workspace`, `/opt/freeagent/venv`, `/home/freeagent`, UID 65534 inside sandbox | Internal isolation layout | Preserve controlled namespace semantics; unrelated to user's home path. |
| `tempfile` roots `freeagentos-run-*`, `freeagentos-worker-*`, `freeagentos-sandbox-*`, promotion dirs | Acceptable private temporary paths with constraints | Future location changes must preserve owner/mode and recovery predicates, not just replace a string. |
| `/root/freeagentos-benchmarks`, `/tmp/freeagentos-evals` | Benchmark/developer diagnostic only | Exclude from public install requirements. Keep historical experiment documents unchanged. |
| `/root/.local/share/claude/versions/2.1.284`, `/usr/local/bin/claude-free` in `test_attribution.py` | Test-only fresh-machine blocker | Replace host-client fixture dependence with a reproducible test fixture or explicitly separate installed-client conformance checks. |
| Docker container `freellmapi-freellmapi-1`, `/app/server/data/freeapi.db` | Qualification-only installation assumptions | Separate optional deployment/candidate checks from ordinary execution setup. |
| Root paths in Stage 1/2 docs and benchmark examples | Documentation-only historical context | Add portable public guide; do not rewrite historical provenance as current installation instructions. |
| `.venv-orchestrator` in launchers | Configurable installation convention, currently repo-relative | Already portable across clone locations, but unprovisioned. Package/bootstrap must honor or safely replace this contract. |

The authoritative public launcher does **not** hard-code `/root/agent-stack`:
`Path(__file__).resolve().parents[1]` derives its root. Conditional research
helpers and the external wrapper do contain real machine-specific paths.

## CONFIGURATION_MATRIX

Only names and categories are listed; no secret values were read or recorded.

| Surface | Classification | Present contract / proposed ownership |
| --- | --- | --- |
| CLI `--repo`, `--task` | USER_CONFIG_REQUIRED | Existing clean Git root and bounded task data; tasks cannot authorize paths. |
| `--allow-new-files`, `--allow-deletes`, `--allow-test-changes` | USER_CONFIG_REQUIRED, trusted security choices | Explicit user/controller approvals, independently validated; never profile or model-selected. Keep secure defaults. |
| `--model-profile ROLE=PROFILE` | USER_CONFIG_REQUIRED with SAFE DEFAULT | Validated immutable registry; default resolves to existing common profiles. No arbitrary model/provider selector. |
| Profile IDs / adapter ID / requested selector | INTERNAL configuration identifiers | Public inspection can show validated identifiers, not credentials or inferred served identities. |
| `ANTHROPIC_BASE_URL` | USER_CONFIG_REQUIRED / local SAFE DEFAULT | External wrapper currently sets fixed loopback endpoint. Future validate endpoint without logging secret URLs. |
| `FREELLMAPI_API_KEY`, `ANTHROPIC_AUTH_TOKEN` | SECRET | Wrapper reads root Hermes env and maps credential to client. No public storage/setup contract. |
| `ANTHROPIC_CUSTOM_HEADERS` | INTERNAL private transport | Controller injects session correlation/authentication headers; never expose values or let tasks redefine them. |
| Attribution socket path / expected peer UID | AUTO-DETECTABLE installation contract + INTERNAL trust configuration | Present constants. Future configuration must bind to authenticated gateway ownership, not weaken checks. |
| Gateway provider credentials/catalog | SECRET / USER_CONFIG_REQUIRED, external gateway-owned | Keep separate from FreeAgentOS model profiles. No secret import or gateway mutation during audit. |
| `PATH` | AUTO-DETECTABLE with validation | Wrapper/client/helper resolution; controlled test path differs from host nvm/other user installations. |
| `FREEAGENT_SANDBOX_TIMEOUT` | INTERNAL | Controlled child environment and bounded ceiling; not a public lease/resource override. |
| `FREEAGENT_TEST_BOOTSTRAP_ATTEMPTED` | INTERNAL | Re-exec loop protection, not user setup configuration. |
| `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL`, Git environment filtering | INTERNAL | Controller avoids inherited Git configuration affecting trusted operations. |
| Sandbox HOME/TMPDIR/PYTHONPATH/environment | INTERNAL | Deliberate isolation; do not inherit arbitrary user config to improve installation. |
| Workspace/evidence/runtime locations | INTERNAL today; future installation-owned config | No general XDG public configuration currently. Benchmark-specific evidence is not general product storage. |
| Research Exa MCP configuration and credentials if applicable | USER_CONFIG_REQUIRED / SECRET | External service setup missing; explicitly optional research capability. |
| Resource limits, read/write caps, repair limit, leases | INTERNAL security policy | Not configurable through model profiles or task text; preserve exact current controls. |

There is no unified public config schema, migration/version policy, config
command, or first-run validator. Controller model profile selection is real
and safe; it is not a general provider setup system.

## PRIVILEGE_REQUIREMENTS

**The current complete runtime requires elevated Linux privileges.** Mount/PID
namespace creation, cgroup mounting/control, chroot, device creation, and
ownership changes are performed directly by controller code. Commands do not
create a rootless user namespace or connect to a narrow privileged helper.
Being in the Docker group does not solve this runtime privilege requirement
and is itself a powerful host privilege.

Tester processes use UID/GID 65534 inside their controlled sandbox. Worker
processes drop capabilities and protect controller/cgroup material, but that
is not evidence that the whole controller or every model worker runs as a
normal non-root user. Do not market rootless operation today.

Future design: run CLI, configuration, provider credentials and user evidence
as the normal user. Use an independently audited, narrow Linux execution
service/helper for the privileged isolation operations, or prove an equivalent
rootless delegation design. Bind requests to OS peer identity and explicit
controller contracts; expose no arbitrary shell, arbitrary mounts, user-chosen
resource overrides, or broad root-executed commands. Installer elevation must
be explicit and limited to reviewed installation steps. Do not simply grant
capabilities to a general Python interpreter or ask users to run all prompts
under `sudo`.

The private gateway socket requires parent mode 0700, socket mode 0600,
authentication token and verified peer credentials. Present gateway UID 1000
is machine-specific; a different normal user cannot be assumed to access it.
Future gateway/controller ownership or a protected mediation mechanism must
be designed, not fixed with world-readable sockets or permissive directories.

## FREELLMAPI_INTEGRATION_STATUS

Current validated inference route is Claude Code → `claude-free` → local
FreeLLMAPI Anthropic-compatible endpoint → provider. Upstream gateway aliases
may resolve to Auto; concrete enabled catalog selectors choose groups. Requested
identity, actual dispatch, and upstream served identity are different layers.

Ordinary execution can continue when the optional attribution channel is
absent or fails. It returns unavailable routed evidence plus lifecycle
diagnostics, without inventing a route or changing execution authorization.
A compatible upstream FreeLLMAPI endpoint can supply inference without our
patch in principle; a fresh stock deployment has not been validated here.
No alternative provider adapter is currently implemented/qualified.

Trusted session-bound ROUTER_DISPATCH requires the separate Stage 2.5 gateway
patch: registration and finish over private Unix IPC, controller-owned custom
headers, gateway dispatch records, bounds/TTL and peer/token authentication.
The FreeAgentOS repository does not include that complete external patch or a
reproducible gateway distribution. Historical handoff documentation is not an
installer. Current patched lineage is `912a47b896c743fc8fd792170af8eef59cad1a51`,
based on upstream `e4a47f203dba3b610dc180f628d3e821abbaf564`.

Recommend optional enhanced attribution with clear capability reporting;
pursue an upstream contribution and a versioned, audited patch/release recipe
if necessary. Do not require a maintained fork before evaluating upstream
integration. Do not copy third-party source into FreeAgentOS. The inspected
isolated FreeLLMAPI LICENSE is MIT, copyright 2026 Tashfeen Ahmed; retain its
license/copyright notices if distributing modified artifacts, and review
image/transitive dependency provenance separately.

Anthropic response `model` metadata may echo the requested selector. It must
not become served identity. Only authenticated session-bound dispatch evidence
may become ROUTER_DISPATCH. Served identity remains UNAVAILABLE until
trustworthy upstream-native evidence is implemented. Stage 2.9B's successful
Groq route demonstrates this integration on the existing machine, not a
fresh-user install certification.

## CLAUDE_FREE_STATUS

`/usr/local/bin/claude-free` is a local untracked Bash launcher. It requires
`/root/.hermes/.env`, extracts the named FreeLLMAPI credential using shell text
parsing, exports the local Anthropic endpoint/authentication configuration,
and executes `claude "$@"`. Explicit model flags pass through. The credential
file itself was not read during this audit.

This executable name is required by the current command builder and attribution
integration. Its Hermes/root dependency is not architecturally necessary.
A public installer needs a reviewed, portable adapter launcher or an equivalent
validated command contract; it should not scrape another application's env file.
Do not synchronize global Claude/Codex policy files as part of installation.

Claude print/stream JSON, structured results, strict MCP, restricted tool and
permission flags are adapter requirements. Compatibility flags in model
profiles are declared execution requirements, not proof of upstream model
quality. Installed-client conformance must be tested against supported releases;
public setup cannot assume an arbitrary latest CLI supports every required flag.

## SUPPORTED_PLATFORM_MATRIX

| Platform | Current status | Qualification needed |
| --- | --- | --- |
| Ubuntu 24.04 under WSL2, existing privileged development environment | CURRENTLY VALIDATED for that environment | Host audit confirms Ubuntu 24.04, Microsoft kernel, Python 3.12.3. Not proof for fresh WSL installs or non-root users. |
| Ubuntu 24.04 LTS native x86_64 | LIKELY PORTABLE; fresh-user support REQUIRES WORK | Reference target: normal non-root user, fresh home, internet, Docker available/installable. Validate dependencies, kernel controls and privilege separation on a disposable clean machine. |
| Fresh Ubuntu 24.04 WSL2 x86_64 | REQUIRES WORK | Same reference target; explicitly check WSL kernel/cgroup/namespace capabilities and service lifecycle. |
| Other Linux distributions | REQUIRES WORK | Validate Python, libc, filesystem/binary layout, security policies, namespaces, delegated cgroups and compatible CLI. |
| macOS native | UNSUPPORTED by present isolation implementation | Linux namespaces/cgroup/proc/peer-credential implementation cannot run natively. Future Linux VM integration needs its own qualification. |
| Windows native | UNSUPPORTED | Current code relies on POSIX/Linux APIs; WSL2 is a separate environment, not native Windows support. |

No fresh-machine installation was attempted and no additional platform was
certified during this audit.

## WORKSPACE_AND_FILESYSTEM_DESIGN

Current production uses owned temporary workspace copies, controller manifests,
private worker/sandbox state and promotion artifacts. Canonical repositories
are not agent scratch directories. Recovery accepts only proven owned run
directories with expected naming, parent and mode constraints; location changes
must update and test this lifecycle coherently. Benchmark paths are external
experiment infrastructure, not general product state.

Proposed user layout:

- `$XDG_CONFIG_HOME/freeagentos` (default `~/.config/freeagentos`): versioned
  non-secret config plus separately protected 0600 credentials if needed.
- `$XDG_DATA_HOME/freeagentos`: installation metadata, reviewed skill registry,
  retained user-owned evidence/patches with explicit retention rules.
- `$XDG_CACHE_HOME/freeagentos`: rebuildable indexes and vetted dependency cache.
- `$XDG_STATE_HOME/freeagentos`: safe run summaries/recovery bookkeeping.
- `$XDG_RUNTIME_DIR/freeagentos`: private transient IPC/session state; otherwise
  securely created owned temporary directories with validated cleanup rules.

Do not persist raw prompts, model/private output, IPC frames or tokens. Patches
contain user code and paths, so retention/export needs explicit user ownership
and privacy design rather than treating every artifact as anonymous telemetry.

## PUBLIC_CLI_DESIGN

| Existing command | Audience / disposition |
| --- | --- |
| `freeagent-run` | Present public task entry; retain compatibility. |
| `freeagent-code` | Retired entry; explanatory failure, not another production path. |
| `freeagent-test` | Trusted developer verification and target test infrastructure. |
| `dev-intel`, `prompt-intel`, `exa-intel` | Bounded research utilities; optional power-user interface. |
| `sync-agent-policy` | Developer-only global file overwrite; never implicit installation. |
| `freeagent-qualify-model`, `freeagent-attribution-diagnostic` | Explicit opt-in developer live diagnostics; not setup defaults. |
| `freeagent-shipment-ab`, `freeagent-shipment-frozen` | Benchmark-only; excluded from onboarding. |

Proposed `freeagent` is a thin public facade over the existing controller, not a
replacement graph: `version`, `doctor`, `config`, `models`, `setup`, `run`,
`status`, and later `skills`. `doctor` is no-generation by default; it reports
missing controls honestly and never makes unsupported machines READY.
`models` distinguishes requested profile, configured capabilities, live
qualification and unavailable served identity. `run` preserves clean-repository,
permission and deterministic verification contracts. New-project scaffolding
must be explicit and backed by trusted starter tests. Existing commands remain.

## FIRST_RUN_DESIGN

1. Detect supported OS/Python/kernel and show supported versus unsupported
   status; check dependencies without modifying services.
2. Explain and validate the privilege/isolation setup; request only the limited
   installation actions needed for a reviewed execution boundary.
3. Choose the one supported adapter initially; configure endpoint and credential
   privately. Offer enhanced attribution separately. Do not invent adapters.
4. Validate client/version/config/socket/health without generation; optional
   research tools are individually reported and activated.
5. Create versioned user config and give a no-model local test/preflight path.
6. Offer one tiny live smoke only with explicit consent, provider-cost/limit
   awareness, same isolation and no automatic retry/fallback.
7. Show READY only for proven required controls. Otherwise show a concrete
   actionable blocker; attribution unavailable is a separate capability state.
8. Run on a supported clean repository with tests; explain patch review/promotion
   and cleanup, rather than silently changing the user's canonical project.

### Free experience and provider extension

The intended software is free/open source once a license is adopted by the
owner. Model inference costs/limits remain provider-dependent. Existing lowest
friction zero-charge inference path is a user-configured compatible FreeLLMAPI
route using an actually available free-tier credential and tool-capable model;
availability, quotas and pricing are not guaranteed by FreeAgentOS. Do not
promise unlimited free inference or silently fall back to a paid route.

Current profiles cleanly separate model choice from security, but only implement
`claude-code-freellmapi` and bounded research tools. Generic OpenAI-compatible,
Ollama, LM Studio, llama.cpp and vLLM integration requires an actual adapter for
session/tool execution, stream parsing, result envelopes and compatibility
validation. Merely changing a base URL does not translate the Anthropic client
protocol. Future provider contract should cover those execution properties,
private credential access, cancellation/cleanup and safe identity provenance;
it must not contain file permissions, leases or resource overrides. No provider
self-selection, adaptive routing, retries or races are proposed here.

## SKILLS_STATUS

The only tracked skill is `skills/coding-intelligence.md`, a prose agent policy.
The bounded research tools and controller tool broker are real capabilities;
there is no community skill manifest, installation/activation/runtime system.
Do not describe a safe extensible skill marketplace as already implemented.

A future reviewed manifest should record skill ID/version/source, license,
content hash, binary/model prerequisites, requested filesystem/network
capabilities, risk class, activation rules and verification. Requested
capabilities never grant authority: controller/user approval and sealed policy
remain authoritative. Treat downloaded instructions as untrusted task material;
verify provenance, updates and tool dispatch independently. No Ponytail or
other external skill integration is included in this milestone.

## PUBLIC_REPO_GAPS

| Priority | Missing / incomplete items |
| --- | --- |
| REQUIRED_BEFORE_PUBLIC_MARKETING | Owner-approved LICENSE; README with supported scope and limitations; reproducible dependency metadata/bootstrap; install/setup/doctor guide; safe credential/provider instructions; SECURITY reporting policy; privilege/platform/verification explanation; dependency/provenance notices; CI running deterministic security tests in a qualified isolated environment; contribution/PR guidance. |
| USEFUL_SOON | CONTRIBUTING, issue/bug templates with safe diagnostic collection, PR template, CODE_OF_CONDUCT, versioned CHANGELOG, minimal example with deterministic tests, setup troubleshooting, public architecture overview and demo showing honest verification states. |
| LATER | Broad platform support, extra providers, community skill catalog/runtime, polished screenshots/video, Founder View and advanced dashboards. |

All listed conventional files (README, LICENSE, CONTRIBUTING, SECURITY,
CODE_OF_CONDUCT, CHANGELOG, `.github`) are absent from the tracked tree inspected.
Existing execution-isolation and milestone docs are valuable engineering
records, but not a beginner guide. GitHub organization settings and remote-only
configuration were not audited; no claim is made about them.

### Secrets and provenance

A bounded scan of current tracked files for common private-key/API-token
signatures found no matches. This is not a complete entropy or Git-history
secret audit. No external credential files were opened. `.gitignore` covers
`.env`, `.env.*`, virtualenvs, logs, caches, sources and development workspaces;
it does not broadly cover OAuth/credential JSON, private-key files or all future
user config. Ignore rules do not prevent deliberate commits or leakage.

Use private user configuration outside Git, restrictive ownership/modes,
optional OS keychain integration, ephemeral session authentication material,
redacted diagnostics and CI/pre-commit secret checks. Worker transport currently
starts from inherited host environment; public setup needs an explicit review
of credential exposure to trusted adapters, not a claim that every worker env
is already secret-free. Test sandbox environment is separately controlled.

No copied third-party source tree is tracked. Included derivative catalog data
requires license/provenance review and appropriate notices before redistribution:

- `data/public_apis.json`: public-apis/public-apis,
  `7598f906a610c6d6ebf7adc2e72b6b5fccc7eba0`.
- `data/buildx.json`: codecrafters-io/build-your-own-x,
  `aa17439b62f384511a5561ce308e9598b94d8989`.
- `data/prompt_patterns.json`: sanitized curated summaries referencing
  elder-plinius/CL4R1T4S, `a4d3da04e63324e794a65500c3e41994fc4ab02e`.

These source identifiers are metadata, not a bundled license grant. Source
licenses for those exact snapshots were not established in this audit. Record
license/source/hash/update policy and review derived content; keep raw prompt
repositories untrusted and external. Claude Code remains an external installed
component with its own terms; do not redistribute it or assume it shares the
future FreeAgentOS license. Owner must decide project license explicitly.

## SECURITY_INSTALLATION_RULES

- No blindly executed moving remote scripts; review/pin downloads and verify
  release integrity/provenance before execution.
- No chmod 777, disabled OS security, broadly privileged interpreter, or
  root-only onboarding workaround sold as non-root support.
- Bind local provider/admin services to loopback/private IPC by default. Never
  expose a gateway or its credentials publicly as part of installation.
- Keep provider credentials outside Git; never print them, raw headers,
  authentication tokens, model text or transport payloads in doctor/evidence.
- Installation must not silently install clients, grant host privileges,
  overwrite global agent policies, restart services or trigger paid inference.
- Preserve sealed read/write/new-file authority, path defenses, hidden-test and
  verification boundaries, namespace/cgroup/resource controls and repair limits.
- Preserve Coder/Fixer 180-second base lease, at most one 60-second grace,
  240-second cap and broker-success trusted progress. Generic text/liveness
  cannot earn grace. Model profile or attribution diagnostics cannot authorize.
- Preserve strict IPC ownership/mode/peer/token/session/bounds checks. Unsupported
  attribution remains unavailable; echoed model fields are never served proof.
- Preserve deterministic test/verification criteria and patch integrity; never
  label a timeout's partial workspace as a production-verified result.

## STAGE3_IMPLEMENTATION_SEQUENCE

1. **3.0B — Portable configuration and dependency foundation.** Add reviewed
   Python packaging/locked tested environment, portable bundled data lookup,
   versioned user config and adapter-launcher contract. Explicitly separate
   provider config from controller security policy and optional attribution.
2. **3.0C — No-generation `freeagent doctor`.** Validate dependencies, client
   compatibility, endpoint/private IPC, Linux controls and target test readiness;
   fixed safe categories, no secret values and no provider dispatch by default.
3. **3.0D — Non-root execution boundary design and qualification.** Prove a narrow
   privileged helper or equivalent rootless isolation without weakening controls.
   This is a release gate for the stated normal-user reference target.
4. **3.0E — Reviewed installer/bootstrap.** Install the tested environment and CLI
   with minimal explicit elevation, no service mutation/generation by default;
   validate on disposable native Ubuntu and WSL fresh homes. Decide license and
   prepare minimum public documentation before distributing as open source.
5. **3.1 — First-run setup.** Private provider configuration, optional attribution,
   user-consented tiny smoke, safe readiness/troubleshooting and cleanup.
6. **3.2 — Unified CLI and project experience.** Thin facade over current graph,
   status/evidence/patch review; explicit trusted project scaffolding and
   dependency preparation for new apps rather than bypassing verification.
7. **3.3 — Provider contract expansion.** Implement and qualify one additional
   real compatible adapter at a time, below identical authorization boundaries.
8. **3.4 — Skill Manifest / Runtime v1.** Provenance, capability approval,
   installation/activation isolation and verification before community execution.
9. **3.5 — Founder View.** User-facing progress, approvals, evidence and outcomes
   after underlying install/run contracts are stable.

## AUDIT_VERIFICATION

Initial repository and verified checkpoint were clean/matched. Source and
configuration inspection, installed package metadata, selected OS metadata,
current tracked-file signature scan, and a disposable tracked-snapshot launcher
check were performed without model/provider execution. Only this document is
changed. No service, gateway, canonical benchmark or Stage 2 evidence was
modified. Full suite is not rerun for this documentation-only audit, as allowed
by the milestone; installation and rootless support remain unverified until
future clean-machine executable qualification.
