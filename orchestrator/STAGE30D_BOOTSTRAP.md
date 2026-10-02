# Stage 3.0D: safe user bootstrap

Reference: Ubuntu 24.04 LTS x86_64, Python >=3.12, Git, normal non-root
user. Ubuntu 24.04 WSL2 is reported separately when the kernel identifies
Microsoft WSL2. Other distributions/architectures are rejected for now.
This installs software, not a production-ready autonomous worker system.
Project licensing remains unresolved; the repository is publicly available
but this document makes no open-source licensing claim.

From a cloned, reviewed checkout:

```
./install.sh --dry-run
./install.sh
freeagent doctor
```

The launcher detects Python and venv support. Missing prerequisites need
manual installation: on Ubuntu, Python 3.12 and `python3.12-venv`, plus Git.
There is no sudo, apt, remote script execution, service configuration,
credential copying, provider installation, or shell startup modification.
Root is rejected, including dry-run. Do not run this bootstrap with sudo.
If `~/.local/bin` is absent from PATH, add it yourself; the installer prints
that instruction and does not edit your shell files.

## Layout and reproducibility

`foundation.user_paths()` is the sole directory resolver. XDG and existing
FREEAGENTOS overrides apply unchanged. Defaults:

- program: `~/.local/share/freeagentos/installation/`
- venv: `~/.local/share/freeagentos/installation/venv/`
- command: `~/.local/bin/freeagent` (symlink to installed console script)
- config: `~/.config/freeagentos/`
- cache: `~/.cache/freeagentos/`
- state/evidence: `~/.local/state/freeagentos/`

New directories request 0700; existing directory permissions are never
relaxed. Symlinked destination ancestry is rejected. No config file is
created: built-in defaults suffice for doctor. Existing config is preserved.
No credentials or provider preferences are written.

The venv is installed at its final path because console-script shebangs
must not be broken by renaming a venv. The launcher is published only after
pinned `requirements-build.lock` and `requirements.lock` installation,
package installation with `--no-deps --no-build-isolation`, and `pip check`.
A disposable copy is used for setuptools builds, leaving checkout source
untouched. The installer executes structured argv, never shell=True.
Build/index output is suppressed to avoid leaking private index credentials.
A dependency failure reports a fixed category; inspect index connectivity
and pins manually rather than changing security controls.

`installation.json` (0600) records package version, checkout commit when
available, and a content digest of installation inputs. It contains no
credential material or pip environment dump. Matching second installs run
pip check and doctor and report ALREADY_INSTALLED. Different/unrecognized
installs or conflicting launchers are refused; this is not an update manager.
Concurrent first installs fail on exclusive install-directory creation,
without deleting the other process's installation. Handled install failures
remove only the newly created program directory and published launcher.
User directories/config/evidence remain. An uncatchable interruption may
leave an unrecognized partial installation; it is refused on the next run.

## Exit contract

- 0: SUCCESS, ALREADY_INSTALLED, or DRY_RUN.
- 2: invalid usage.
- 3: unsupported platform.
- 4: prerequisite failure (including root invocation/Python/venv/Git).
- 5: dependency or package install/pip check failure.
- 6: filesystem/path error or conflicting installation.
- 7: internal/installed environment error.

Doctor runs after SUCCESS or ALREADY_INSTALLED. READY, NOT_READY, and ERROR
are recorded separately: doctor NOT_READY never changes install success.
Doctor makes only its documented loopback health GET and filesystem
observations; bootstrap never invokes Claude, run_worker, model generation,
qualification, Planner or benchmark paths.

## Remaining boundary

Provider launcher/credentials, FreeLLMAPI, authenticated attribution, active
isolation proof, privilege separation, and target test environments remain
separate prerequisites. No gateway is cloned, installed, restarted or
configured. The local private claude-free wrapper is never copied.
Do not use `sudo freeagent` as an installation workaround. Production
namespaces, mounts, chroot, ownership, cgroups, leases and resources are
unchanged. The next milestone must design a secure privilege boundary.

For manual removal, first inspect the recorded install location and launcher
symlink. Remove only that program directory and its matching launcher.
Configuration, data outside `installation/`, and state/evidence are distinct
user-owned material and must not be automatically removed.

## Verification

Deterministic foundation/doctor/bootstrap and attribution tables passed
(2 grouped tests, 5.765 seconds). The trusted suite passed 518 tests in
253.934 seconds, RESULT=PASS, exit 0. Tests extend the existing compact
foundation table without increasing the trusted runner's output budget.

A real isolated Ubuntu 24.04 installation was executed with UID/GID 1000,
a temporary HOME and explicit temporary XDG paths, without sudo. Dry-run
left install destinations absent; first install returned 0; second install
returned 0; venv console symlink and pip check passed; existing config
bytes were preserved; no shell startup file was created. The disposable
source copy, environment, and installation were removed. No provider,
worker, benchmark, or production service was invoked by bootstrap.
