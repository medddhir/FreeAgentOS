# RPT-1 development verification fixture

This is an isolated development prerequisite, not production pytest support,
protected runtime qualification or permission to execute a campaign. The
established controller and target interpreters remain unchanged. Tests never
download dependencies and fail with PYTEST_DEVELOPMENT_FIXTURE_REQUIRED when
the explicit prerequisite is missing. Do not set this variable from project
content or model output; it selects only a trusted developer test fixture and
is not consumed by the production runner or sandbox.

Use Python 3.12 on Linux. No existing project pytest pin was found. PyPI's
official version metadata was checked for pytest 8.3.5 (requires Python >=3.8),
iniconfig 2.0.0 (>=3.7), packaging 24.2 (>=3.8), pluggy 1.5.0 (>=3.8):
https://pypi.org/pypi/pytest/8.3.5/json and the corresponding package/version
JSON endpoints. These four packages satisfy the non-extra Python 3.12/Linux
dependencies. requirements-rpt1-fixture.lock records each downloaded universal
wheel's SHA-256. No source distribution, upstream installer or setup script is
used. Bootstrap pip belongs to the temporary venv created by Python's bundled
venv/ensurepip; it does not modify established interpreters.

Reproduce outside the repository, with normal test umask:

```sh
fixture_root=$(mktemp -d /tmp/freeagent-rpt1-pytest-XXXXXX)
chmod 700 "$fixture_root"
/usr/bin/python3 -m venv "$fixture_root/venv"
"$fixture_root/venv/bin/python3" -m pip download --only-binary=:all: \
  --require-hashes --index-url https://pypi.org/simple \
  -r /root/agent-stack/requirements-rpt1-fixture.lock -d "$fixture_root/wheels"
"$fixture_root/venv/bin/python3" -m pip install --no-index --only-binary=:all: \
  --require-hashes --find-links "$fixture_root/wheels" \
  -r /root/agent-stack/requirements-rpt1-fixture.lock
export FREEAGENT_PYTEST_FIXTURE_PYTHON="$fixture_root/venv/bin/python3"
cd /root/agent-stack
.venv-orchestrator/bin/python3 -m unittest test_pytest_reporting -v
bin/freeagent-test
```

The installation example is a separate explicit developer action, never part
of test discovery. Tests check the external venv and exact dependency versions;
hash-checked preparation is still a trusted prerequisite, not independent
attestation of all interpreter or installed package bytes. Preserve private
wheel provenance and test logs locally; no credentials are needed.

Tests launch the actual copied runner using the fixture interpreter. They
cover pytest.ini, conftest.py and pyproject.toml selection, misleading target
controller-layout markers, addopts=-q alongside target -vv, result names/counts,
failures/setup errors/skips, output overflow and timeout. A timeout test uses
the existing run() globals injection seam in a fresh subprocess to shorten
only its synthetic test clock; production deadlines are unchanged. Overflow
uses a real passing pytest fixture with uncaptured output greater than 64KiB
and must still return FAIL. Synthetic trusted-controller layout creates its
own no-pip venv and supplies these isolated packages through test-only PYTHONPATH;
neither established .pth files nor production runtime selection are altered.
Target unittest retains verbose named evidence.

The test environment removes ambient pytest settings and disables third-party
plugin autoload. Project hooks/plugins can alter output or tests: -vv is not
independent named-test attestation and does not defeat arbitrary project code.
Existing protected-input/count checks remain unchanged. Redesigning a stronger
named-evidence acceptance contract is outside RPT-1.

CAP-1 remains OPEN; N3 pending; B10 PARTIAL; live website execution unqualified;
historical disk-timeout causation unresolved; Stage31D NOT AUTHORIZED.
