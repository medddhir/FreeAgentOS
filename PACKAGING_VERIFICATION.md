# Installed recorded CLI packaging preparation

The existing `setuptools.build_meta` backend, explicit packages and console
entrypoint already include the required recorded path. A wheel from source
`184c84f6421565b6ad2fe025ef5428cd95e943a1` contains `roles.coding_units`,
`roles.tester`, `roles.repair_context`, all other declared package modules and
`website_guidance/shape.md`, LICENSE, NOTICE.md and SELECTION.md. No packaging
membership or application defect was demonstrated, so pyproject.toml and
application code were not changed. The earlier source-fixture omission was not
an omission from the declared wheel packages.

This milestone adds executable offline packaging regressions and this procedure,
not another installer, execution backend or permission system. The qualified
feature remains the separately recorded source-layout preparation; packaging
checks do not qualify an installed non-root preparation invocation or live coding.

## Build inputs and repeatability

Build a private copy of the explicitly selected tracked `pyproject.toml`,
`orchestrator/`, `data/` and `bin/` regular files. Exclude editable venvs, Git,
ignored build outputs and runtime state; reject links. Bounds used by checks:
256 source files, 8 MiB/file, 32 MiB aggregate. Identify current source bytes
separately from the baseline commit when building an uncommitted candidate.
Use `/usr/bin/python3.12` with the already available system setuptools 68.1.2
and wheel 0.42.0, matching requirements-build.lock and pyproject.toml. No new
build dependency, download or modification of an established runtime is needed.

From that private source directory, with a fresh private wheel destination:

```sh
SOURCE_DATE_EPOCH=<recorded-source-commit-timestamp> \
  /usr/bin/python3.12 -c 'from setuptools.build_meta import build_wheel; import sys; print(build_wheel(sys.argv[1]))' \
  /absolute/private/wheel-destination
```

Two clean staged builds with the same source bytes, pinned backend and fixed
SOURCE_DATE_EPOCH must match wheel bytes. This is repeatability under those
conditions, not universal reproducibility, independent toolchain attestation or
B10 build-closure completion. Wheels/manifests/logs stay outside Git.

## Development-only executable prerequisite

`test_installed_package.py` requires FREEAGENT_PACKAGE_FIXTURE_PYTHON pointing
to a separately prepared Python 3.12 development venv with pip and the complete
runtime dependencies. It fails explicitly when missing; tests never download
or install dependencies. Prepare that fixture outside the repository using the
existing official wheelhouse and hash-locked requirements-offline.lock from the
reviewed non-root fixture. Do not change that fixture, its installed venv or
its historical attempts. The dependency lock SHA-256 is
`b4e4652a1b779179f01ee8b20e5c5029d72a86c5f41b0e679d6193df1439388a`;
wheel provenance SHA-256 is
`061f23be9def87440ed693d6ee00716ebc5bfd35eb76e1728a8618b77390a92e`.
These describe 38 official wheels, including LangGraph 1.2.12, distinct from
editable LangGraph commit 07b33185eab893be2ed031eedae52f09314bf77c.

The tests create private no-pip venvs and install only the freshly built project
wheel there using the external fixture's pip, --no-index and --no-deps. Their
sanitized subprocess environment uses test-only PYTHONPATH for the external
fixture's dependency site-packages (which has no installed FreeAgentOS). Project
modules must resolve inside the newly installed project venv, not cwd or /root.
This dependency seam is consumed only by tests; it grants no runtime authority.
Do not treat this layout as a complete production dependency installation.

Checks cover all project Python modules, guidance/provenance bytes, console
entrypoint/dependency metadata, wheel RECORD hashes, fixed-condition repeated
builds, installed guidance identity rejection after deliberate test-owned
mutation, and the function-local broker content import chain. Actual generated
console scripts run recorded-website --help and invalid-input rejection from
an unrelated cwd without production model initialization. They do not perform
another successful preparation invocation. Existing CLI/website tests retain
workflow/export and execution-gate coverage.

```sh
FREEAGENT_PACKAGE_FIXTURE_PYTHON=/absolute/development-venv/bin/python3 \
  .venv-orchestrator/bin/python3 -m unittest test_installed_package -v
```

The required suite needs this explicit development prerequisite in addition to
the existing documented FREEAGENT_PYTEST_FIXTURE_PYTHON. Keep normal umask,
420-second runner deadline, 64 KiB capture rejection and compact controller
reporting. A private controller progress observer may be activated only as
specified in devtools/controller_progress/README.md. Record selected source
bytes before/after; this is not dependency/read-set attestation.

## Proposed later installed-console qualification — NOT authorized here

After separate review/authorization, medhir UID/GID 1000/1000 would use a fresh
private fixture independent of the prior source fixture and create a fresh venv
from the identified /usr/bin/python3.12. Install the exact hash-reviewed runtime
wheels offline with --no-index --require-hashes --no-deps and then the reviewed
FreeAgentOS wheel using a separate hash-bound project lock, --no-index
--require-hashes --no-deps. No editable .pth, source checkout or PYTHONPATH is
needed in that fully installed candidate. Verify wheel/lock/installed metadata
and console shebang, and unset PYTHONPATH/PYTHONHOME before invocation.

Create a fresh caller-owned 0700 staging parent and authorize exactly ONE
30-second/64 KiB bounded `venv/bin/freeagent-run recorded-website` invocation
with the previously reviewed Local Studio brief, Revised page / Explore details
revision, Warm neutral palette design, --confirmed and --json. Use a separately
reviewed bounded capture helper adapted only to the installed console path;
the historical source helpers/results must not be overwritten or reused.
Independent success checks must inspect all four exact export bytes, revision,
receipt/file hashes, snapshot binding and PREPARATION_ONLY/live false status.
Retain artifacts and bound owned-child cleanup; do not execute generated files,
launch a browser/server, call providers or infer descendant absence.

Installed-package qualification remains UNPROVEN until that authorized attempt
and independent checks pass. Live building, functional/browser behavior,
hostile isolation, descendant absence and complete dynamic dependency closure
remain UNPROVEN. B10 PARTIAL; STAGE31D_AUTHORIZED: NO.

## Recorded preparation verification — 2026-10-05

Focused installed-wheel/website/runtime/pytest checks: 41 tests in 35.556s, OK;
affected read-policy/progress checks: 39 tests in 4.363s, OK. The development
runtime was a fresh offline venv from /usr/bin/python3.12 using the existing
38-wheel lock; neither established runtime nor the prior medhir fixture changed.
No successful installed-console preparation was invoked. Help, invalid-input
rejection, installed content imports and guidance reads were executed as UID 0;
these are development packaging checks, not non-root qualification.

Artifact: freeagentos-0.3.0.dev0-py3-none-any.whl, SHA-256
`5ebf0db2bf59b00e7ea1d9a17d113765ff1cb84a75f8cb2202bba3b7418b7a47`.
Two clean staged builds matched (105 wheel members), using SOURCE_DATE_EPOCH
1791141624 and the existing pinned backend. Build source manifest SHA-256:
`59a82aae1608d3fcc0764c8f7252833ccddccd3f8868fab2cd535f8160d4f8dd`.
Its 124 selected tracked worktree files had baseline HEAD
184c84f6421565b6ad2fe025ef5428cd95e943a1 and two updated qualification documents;
application/configuration bytes were unchanged. These documentation files are
not wheel package members. Subsequent result text does not change wheel bytes.

The exactly one required invocation was `/root/agent-stack/bin/freeagent-test`,
selecting `.venv-orchestrator/bin/python3 -m unittest discover`:
**572 tests in 357.648s, OK, RESULT=PASS, EXIT_CODE=0**. Wrapper wall time
359.416s is not the runner's exact deadline interval. The 420s deadline and
64 KiB capture bound remained unchanged. Capture was 7,279 bytes; no timeout or
output truncation. The established pytest fixture and the new separate offline
package fixture were explicitly supplied through their documented development
variables. The existing progress observer used its fixed source directory as
PYTHONPATH and a fresh private progress directory; its activation is removed
before descendant launches as documented in its README.

All 207 selected files matched pre-run bytes/modes immediately afterward.
Selected-source manifest SHA-256:
`758f0ea67e4f3f8ee1eee36583e8b39ef3f414dc78073f8c8177bee2b9628f39`.
Required-log SHA-256:
`599b22898a4bf41d1f11ebc98505d1954e7ba4cabb31dd56f5fb8ca528b7275f`.
Progress SHA-256:
`f227c0f25d6dbe9618f404d03a3878777aef8f8b5b6b75cf4efbcd115e25b398`.
Observer: 576 completed intervals, including four intentional nested synthetic
cases, no unmatched test/subcase intervals, no diagnostic error, 3,561 records
and 516,954 bytes. Unittest counts/runner markers are authoritative, not nested
observer outcome totals. The observed runner launch identity was absent after
reaping; current bounded inspection found no matching test jobs. This is not
historical or complete resource-absence proof. Only result documentation was
subsequently appended. Source binding is not independent dependency/read-set
attestation. No retry, suite-limit change, commit, tag, publication or deployment.

For the later reviewed project-wheel lock, use only this artifact identity:

```text
freeagentos==0.3.0.dev0 --hash=sha256:5ebf0db2bf59b00e7ea1d9a17d113765ff1cb84a75f8cb2202bba3b7418b7a47
```

After separate authorization and ordinary-user fixture provisioning, the offline
installation would use the fresh venv's pip with --no-index --only-binary=:all:
--require-hashes --no-deps --find-links <reviewed-private-wheelhouse>, first for
the complete runtime lock and then the above project lock. The single bounded
helper would launch this console command (not executed in this milestone):

```sh
<fresh-installed-venv>/bin/freeagent-run recorded-website \
  --staging-parent <fresh-owned-0700-parent> \
  --title 'Local Studio' --heading 'Build locally' --button 'See more' \
  --revision-heading 'Revised page' --revision-button 'Explore details' \
  --design 'Warm neutral palette' --confirmed --json
```

Both historical source-layout attempts remain preserved. Installed-package
qualification and live execution remain UNPROVEN. B10 PARTIAL;
STAGE31D_AUTHORIZED: NO.

## Non-root installed-console recorded preparation qualification — 2026-10-05

**Qualified scope:** one separately authorized installed-console recorded
preparation attempt under medhir UID/GID 1000/1000, using the identified
`/usr/bin/python3.12` (Python 3.12.3, x86_64; recorded package version
3.12.3-1ubuntu0.17), the reviewed FreeAgentOS 0.3.0.dev0 wheel and the 38-wheel
offline dependency runtime, including LangGraph 1.2.12. System interpreter binary
SHA-256: `e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f`.
This is distinct from the earlier qualified source-layout attempt: launch used
`venv/bin/freeagent-run`, not a checkout's cli.py or an editable install. The
pinned helper creates a fresh empty fixture workdir and launches there with an
explicit environment containing no source PYTHONPATH or PYTHONHOME. Current
inspection confirms that workdir is empty. These retained source/result facts
are not independent historical process-environment or full read-set attestation.
The wheel runtime is not asserted equivalent to the established editable runtime.

Recorded result: **exit 0; elapsed 1.6329543629835825 seconds; failure null;
direct child reaped; INSTALLED_CONSOLE_RECORDED_PREPARATION_ONLY**. Capture is
1,747 bytes; result is 2,017 bytes. Recorded status is PREPARATION_COMPLETE,
model_calls NONE, live_qualified false. Integrity-verifier output alone is not
a qualification verdict; invocation success and independent export checks are
required. This documentation milestone inspected existing regular-file evidence
only: no tests, imports of application/runtime modules, builds, installation,
qualification rerun or generated-file execution occurred.

Fresh bounded evidence inspection confirmed the exact revised four project and
export files (index.html, styles.css, app.js, README.md), with export.json as the
only additional export member; single-link regular files at 0600 and owned
run/project/export directories at 0700, UID/GID 1000/1000. Expected heading,
button, CSS, JS and README bytes matched, receipt equality and all four hashes
matched, before/final snapshots differed, and recomputing the run/profile/
contract/file-hash snapshot matched the receipt, checks and disabled preview.
Structural PASS remains separate from functional/browser UNPROVEN.

The result's `wheel_members_observed=1524` and
`wheel_bytes_observed=51737975` are enumeration totals, including excluded
installer-rewritten entries. The pinned installed-byte observer counts entries
before excluding 39 wheel RECORD files and the three explicit jsonpointer/
jsonpatch script shebang rewrites (42 entries, 142,953 declared bytes). Its
comparison path covers the remaining 1,482 entries, 51,595,022 declared bytes;
console bytes and the pinned pip console producer are checked separately. This
milestone reconciled that counter derivation from archive metadata, not by
rerunning the observer. Generated installation metadata/bytecode, bootstrap
runtime, undeclared site contents, dynamic loader behavior and every runtime
read are not independently attested. Counted membership is not blanket proof
that every member was compared or executed successfully.

Bounded evidence identities (SHA-256; no raw logs/artifacts are committed):

| Evidence | SHA-256 |
|---|---|
| Installed fixture manifest | `b945ff97512a4426308b71d991ad82c7cafa8053e5c4360c45d8ff2c18847694` |
| Qualification result | `7b93538f43efdf4e215dd9bad585c9b63c24e3b02031410484c94cfcb4a5c3c2` |
| Qualification capture | `f121b740d340f24f32b7942a09eddee0f4ab2405400ddc9f7e9f395620a529c4` |
| Project wheel | `5ebf0db2bf59b00e7ea1d9a17d113765ff1cb84a75f8cb2202bba3b7418b7a47` |
| Runtime lock | `b4e4652a1b779179f01ee8b20e5c5029d72a86c5f41b0e679d6193df1439388a` |
| Wheel provenance | `061f23be9def87440ed693d6ee00716ebc5bfd35eb76e1728a8618b77390a92e` |
| Export receipt | `a7a53ffe63de0cfece1bc80bdebf9b8d43e4025cb541bb17eaa6a0b135289d6d` |
| Final snapshot | `f9b886962ad5aa476c0a12378d4eb1d62a3d5f36b26c79817eae029b555aebc4` |

All qualification artifacts remain retained; the previous source fixture,
runtime and both source-layout attempts are preserved. Historical preparation
sections above retain their earlier UNPROVEN status for those milestones; this
new result qualifies only the explicit installed recorded-preparation path.
No live model calls or generated-code execution are qualified. Live building,
functional/browser verification, hostile isolation, descendant absence,
complete dynamic closure and protected production integration remain UNPROVEN.
Direct-child reaping is not descendant absence. **B10 PARTIAL;
STAGE31D_AUTHORIZED: NO.**
