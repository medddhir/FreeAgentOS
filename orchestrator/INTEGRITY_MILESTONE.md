# Integrity policy and selective rollback

The trusted caller supplies optional boolean fields in `AgentState`:

```python
initial_state = {
    "task": "Implement the requested change",
    "repo_dir": "/absolute/path/to/a/git/root",
    "allow_new_files": False,
    "allow_deletes": False,
    "allow_test_changes": False,
    "fix_attempts": 0,
    "trace": [],
}
```

Missing fields, strings such as `"true"`, and task wording grant no permission.
New test files require both `allow_new_files=True` and
`allow_test_changes=True`. Deleting tests requires both `allow_deletes=True`
and `allow_test_changes=True`. These are caller-wide exceptions, not path
allowlists. Model role outputs do not set these fields. Coder and Fixer receive
the effective policy in their prompts; the Tester enforces it independently.

## Execution and evidence

The production graph starts with a deterministic `baseline` node before the
Planner. It records the Git root, HEAD, dirty paths, and existing file names
(including ignored files). It does not read existing ignored file contents.
The Tester checks both the index and worktree. Staging a new file or putting a
protected worktree file back to HEAD cannot conceal an index violation.
Newly created ignored files also require permission. Standalone Tester calls
without a baseline retain ordinary Git untracked-file detection; use the
production graph for ignored-file provenance and rollback.

Machine tests must return exit 0 and the runner's final `RESULT=PASS` marker.
Git diff checks include staged, unstaged, and authorized untracked changes.
Reviewer evidence includes staged and authorized untracked file diffs.
Integrity failure overrides
a successful test command. The Tester returns `integrity_violations`, including
exact paths and fingerprints of the observed files and index entries.

On a violation, routing is:

```text
Tester FAIL → rollback → Fixer → Tester → Reviewer → Finalizer
```

Rollback preflights every target before mutation, rechecks recorded evidence,
and handles only verifier-identified paths. It restores previously clean tracked
files from the captured HEAD, or removes new files and their staged entries.
Git path arguments are literal. It never calls broad reset or clean commands.
Legitimate changes, including staged implementation changes, remain in place.

Pre-existing dirty targets, pre-existing new/ignored files, changed HEAD,
changed evidence, symlinks, unsupported file types, and failed Git operations
block safe rollback. No Fixer runs after a blocked rollback. A successful
rollback still requires fresh machine tests and review before verification.
The Fixer limit remains **two**. Cleanup still runs after the final failed
attempt, but cleanup alone never converts a failure to `VERIFIED`.

`rollback_evidence` records completed `restored` and `removed` paths, planned
actions and fingerprints, the postcheck result, and any error. All attempts are
retained in `rollback_history`.

## Verification

Run from `/root/agent-stack` using the existing orchestration environment:

```bash
PATH=/root/agent-stack/.venv-orchestrator/bin:/root/agent-stack/bin:$PATH freeagent-test
```

`test_integrity_core.py` builds the same production graph factory. It replaces
model behavior and external research transports with deterministic fixtures;
Planner normalization, Researcher provenance/grounding, Tester, Reviewer gates,
rollback, routing, and Finalizer execute normally. Real temporary Git
repositories and real `freeagent-test` subprocesses exercise the changes.
Calculator and weather regression cases copy the existing test files unchanged.
The research documentation fixture is synthetic, not a claim of live retrieval.

Coverage includes default deny and explicit permissions, repeated adversarial
changes, selective rollback, surviving implementation changes, bounded repair,
staged additions/deletions, index-only tampering, literal/newline filenames,
ignored files, stale rollback evidence, pre-existing work, missing tests, normal
calculator repair, Open-Meteo grounding, wrong-domain rejection, and the
`quantum_weather_mode` block before Coder/Tester.

The live Open-Meteo graph regression stopped at `planner:error`. Separate bounded
Planner probes timed out both inside and outside the sandbox. Live model and
research-provider integration was therefore not revalidated in this session.
No provider database or service configuration was changed.

The project source files were already untracked under the parent `/root` Git
repository. Review uses Git no-index diffs against the existing core archive and
the before-change copies in `backups/`, in addition to scoped Git status/diff
checks. No index staging or commit is required for that review.

## Architecture review and next milestone

The Planner currently receives only the task and has no repository tools. Its
prompt directs unspecified-dependency requests to `research_type=none`, but the
graph then proceeds to Coder with no later research-routing stage. Local facts
discovered by Coder cannot safely trigger the required documentation research.

The recommended next milestone is **a deterministic local Inspector before the
Planner, followed by a deterministic research router**. Extract bounded facts
from allowlisted tracked manifests, lockfiles and imports, with source paths
and hashes. Give those facts to the existing single Planner call. Require
research entities to be supported by the task or Inspector evidence; block
unresolved entities. This avoids adding another model call or a speculative
planning loop. Test unknown-provider rejection and dependency identification
with repository fixtures.

That milestone should also preserve task-required technical identifiers through
routing: `_research_api()` currently receives the Planner's query, and grounding
coverage checks that query. A requirement omitted from the query is not covered
by the current grounding check. The deterministic router should carry task
requirements separately from the model's search terms.

Other remaining execution gaps are a trusted manifest for verification commands,
configuration and expected test discovery (test protection is currently based
on file names), and stronger process/workspace isolation. Fingerprint checks
detect observed races but do not provide exclusive ownership against arbitrary
concurrent writes or hostile changes to Git configuration. These changes do not
claim to provide an operating-system sandbox for model edits or test code.
