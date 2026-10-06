# Disk-capacity diagnostic retention

This is a development-only retention seam for the existing
`test_resource_sandbox.ResourceSandboxTests.test_workspace_disk_ceiling` fixture.
It does not change the 256 MiB workspace, six 60 MiB demands, backing checks,
ENOSPC/full-space assertions, quotas, six-second inner deadline, classification,
or cleanup behavior.

When `disk_diagnostics=True`, `roles.sandbox.run_isolated` retains the already
constructed `evidence.disk_diagnostics` projection before returning to the test
fixture. This occurs before the fixture can print the object or execute its
assertions, so a later assertion failure or buffered controller shutdown cannot
discard the private copy. The controller uses the existing
`FREEAGENT_CONTROLLER_PROGRESS_DIR` when it is present and private; otherwise it
creates a fresh controller-owned 0700 directory under the system temporary
directory. The configured directory must be a non-symlink directory owned by
the controller with mode 0700.

Each invocation receives a fresh 32-hex identifier. The controller opens the
destination and every ancestor as directories with `O_NOFOLLOW`, keeps the
validated destination directory descriptor held, and creates a private
`disk-diagnostic-<id>.json.partial` relative to that descriptor with
`O_EXCL`, `O_NOFOLLOW`, and mode 0600. It writes the bounded projection to the
partial name, closes it, then publishes it with an exclusive hard-link
operation; only the complete published name is `disk-diagnostic-<id>.json`.
Existing evidence is never overwritten. Ancestors must be directories and
must not be links; they need not all be private, so normal `/tmp` ancestry is
allowed. The leaf destination remains controller-owned mode 0700.

The envelope is a fixed-field projection with a 32 KiB encoded bound and at
most the existing 40 child progress records. It contains the runner digest,
timeout, controller PID, result and exit code, but no environment, credentials,
exception objects or arbitrary input fields. Retention status and fixed error
codes are attached to the in-memory result without changing the original
result or assertion path. No `fsync` is used: these are auxiliary diagnostics,
not durable execution attestations. A successful write has ordinary closed
file semantics only; filesystem latency and durability are not hard timing
guarantees.

If writing or publication fails, the just-created partial inode is removed
only after a directory-relative identity/owner/regular-file/link-count check.
If that check or removal cannot safely complete, the fixed retention error
includes an `artifact` object reporting the partial-file and fallback-directory
state. Prior evidence and prior runs are never removed. A fresh fallback
directory is created only after a bounded payload has been validated. The
fallback directory is deliberately retained on failure rather than removed by
a re-resolved pathname; its retained scope is limited to that
controller-created directory and the reported partial artifact.

When the post-evidence result guard would raise
`ISOLATED_SANDBOX_SETUP_FAILED` because the child return code is outside the
accepted set or no `RESULT=` marker exists, diagnostics enabled for that
invocation first retain only fixed metadata: child return code/PID, marker
presence/count, bounded capture length/hash, truncation, runner/source
identity and the fixed guard branch. No output, environment, or exception is
retained. The original generic exception is then raised unchanged. This
record is evidence about the post-evidence guard condition, not proof of a
setup exception or of a result-parsing cause.

The retained envelope labels supervisor samples as `CONTROLLER_OBSERVED`, the
fixture progress channel as `CHILD_REPORTED`, and qualification authority as
`NONE`. `CHILD_REPORTED` progress is never promoted to an authoritative
allocation, backing, cleanup or timeout conclusion. Controller observations are
bounded samples from the existing owned sandbox scope; they are not independent
kernel/read-set attestation and do not establish historical causation.

Retention errors are explicit (`status=ERROR` with a fixed code), remain
auxiliary diagnostics, and cannot convert a failure into a pass. The change
adds no polling task, thread, sandbox process, retry, profiling framework,
provider call or production admission authority.
