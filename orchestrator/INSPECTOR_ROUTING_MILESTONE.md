# Deterministic Inspector and evidence-validated research routing

This extends the verified integrity milestone; `INTEGRITY_MILESTONE.md` remains
the historical record for its original 34 tests.

## Production flow

```text
START → baseline → Inspector → Planner → research validation
                                      ├─ Researcher → Coder
                                      ├─ Coder (local task)
                                      └─ Finalizer (BLOCKED)
Coder → Tester → Reviewer → Finalizer
          └─ rollback when needed → Fixer → Tester
```

The existing baseline, selective rollback, test protection, staged-change checks,
whitespace checks and two-attempt Fixer bound remain in place. Inspector and
research validation make no model calls. `build_graph()` is shared by production
and deterministic integration tests.

## Inspector contract

Only tracked, allowlisted files are considered. Git metadata lists candidate
paths without recursive filesystem traversal. Exclusions apply before opening
files: `.git`, dependency/virtualenv directories, generated/build/cache output,
credential/secret/token/OAuth/key/configuration paths and provider databases.
`.env` files and credential files are never read by Inspector.

Limits: 10,000 indexed paths, 20 opened candidate files, 64 KiB per file,
256 KiB total, 64 records per fact category and a 12,000-character JSON packet.
Overlarge individual files are skipped with `truncated=true`; unsafe opens,
malformed selected manifests and an excessive path inventory block inspection.
Missing evidence never licenses a guessed dependency.

Supported manifests are `package.json`, `pyproject.toml`, `requirements.txt`,
`Cargo.toml`, `go.mod` and `composer.json`. Python imports/declarations use AST
parsing; JavaScript/TypeScript imports use bounded static extraction. No source
code, package script, build hook or dependency installation is executed.
Other recognized source suffixes contribute language/location facts only.

The packet contains languages, dependencies and safely parsed declared versions,
imports, local symbols, relevant/test file locations and observed test frameworks.
Every read source has a path and SHA-256 digest. Raw source, descriptions, script
bodies and dependency authentication URLs are omitted. File access rejects
symlinks, hardlinks and special files and checks for changes during a read.

Fields: `repo_facts`, `repo_facts_text`, `inspector_error`.

## Planner and research validation

Planner receives the bounded packet as data. It may use only task or Inspector
identifiers to choose vendors, packages, versions, endpoints and other technical
entities. Its schema and normalization bound query length to 1,000 characters,
steps to five and each step to 300 characters. Task and facts inputs are bounded.

The deterministic validator accepts known task/Inspector identifiers and a closed
vocabulary of ordinary search phrasing. Unknown providers, frameworks, versions
and endpoints block before Researcher. This vocabulary deliberately favors
false rejection over guessing; it is not a vendor catalog.

For API research, omitted technical task identifiers are deterministically added.
The established semantic requirements (`current`, `timezone`, `auto`, HTTPS,
endpoint) are also preserved. Local target filenames and declared local symbols
are recorded separately so official API docs need not describe application-local
functions. Ordinary prose is not copied wholesale into the query.

An API request needs an evidenced identity. If the query omits it, a unique
evidenced dependency may be added; missing or ambiguous identity blocks. Ordinary
task nouns alone are not promoted into providers. Tasks requiring current external
documentation cannot silently bypass research through `research_type=none`.
Current API/SDK/integration requests also cannot bypass API grounding by selecting
the web or workflow research route; the validator blocks that mismatch.

Machine evidence includes validation status/error, required/query/added/rejected
identifiers, local identifiers, source origins and expected provider identities.
Researcher requires the catalog provider to match the validated identity before
fetching docs. Existing official-domain provenance and documentation coverage
continue to apply. A domain's suffix alone cannot establish provider identity.

## Verification infrastructure protection

`allow_verification_changes` is a new trusted caller boolean, default false. It
is distinct from `allow_test_changes` and is included in Coder/Fixer policy data.
The verifier protects agent policies, verifier entrypoints, orchestration paths,
CI workflows and test configuration, including `package.json` and
`pyproject.toml`. Changes join the existing selective rollback path.

Because manifests can choose verification commands, the entire manifest is
protected. A legitimate dependency update that edits such a manifest requires
explicit `allow_verification_changes=True`; permission is never inferred from
task wording. Other new-file/deletion/test permissions still apply independently.

## Deterministic verification

Run from the project root:

```bash
PATH=/root/agent-stack/.venv-orchestrator/bin:/root/agent-stack/bin:$PATH freeagent-test
```

The suite exercises the production graph with deterministic model/transport
fixtures and real temporary Git repositories, rollback and machine test runs.
Existing calculator and weather test files are copied unchanged. The only edits
to the prior integrity suite are its two exact-trace expectations for the new
Inspector and validation nodes. No behavioral assertions were removed.

Evidence is in `backups/inspector-routing-tests.log`,
`backups/inspector-routing-review.patch` and
`backups/inspector-routing-review.json`. Pre-change production files and the
previous suite are in `backups/inspector-routing-before.tar.gz`.

The source tree was already untracked in the parent `/root` repository. Scoped
Git status/diff checks are supplemented by Git no-index review against that
backup, with whitespace diagnostics checked explicitly.

## Separate live diagnostic

One 45-second-bounded Planner invocation was made after the deterministic suite
was green. The local gateway at `127.0.0.1:3001` was listening; a sandboxed TCP
probe failed, while the outside-sandbox diagnostic connected and received
HTTP 200 from `/health`.

The live call returned schema-valid output, exit 0, in 24.915 seconds. Its envelope
reported 18.615 seconds of CLI execution, 17.124 seconds of API time, two CLI
turns and no error. The task was 58 characters and the Inspector packet 987
characters. Structured output works for this small input. The earlier timeout
was not reproduced; the historical upstream cause cannot be determined from
this single successful probe. No repeated Planner attempt was made. Sanitized
gateway log categories contained no timeout, rate-limit or authentication error
events, but the absence of such logs is not proof about historical behavior.

Only sanitized metadata was saved in `backups/inspector-live-diagnostic.json`.
Provider configuration and databases were not changed. This verifies one live
Planner invocation, not a fresh live end-to-end coding workflow.

## Remaining limits and next milestone

Inspection is a bounded static sample, not runtime dependency resolution. Private
package aliases, unsupported manifests, non-English or unusual query phrasing,
and ambiguous dependencies may block conservatively. Declared dependencies do
not prove that the requested integration actually uses them at runtime.

Query validation preserves technical tokens; it does not prove their semantics.
The established documentation coverage gate remains literal/heuristic, and
evidence truncation can limit review of large changes. Stronger symbol/version
coverage and semantic requirement checking remain future work.

Control-path protection is a conservative inventory, not an operating-system
sandbox. Arbitrary test code and concurrent processes still need isolation.

Recommended next milestone: **isolated per-run execution workspaces with an
externally owned verification manifest and runner**, including test-discovery
attestation and enforcement that target-repository code cannot modify the
controller or verifier. Preserve the current graph and regression suite while
adding deterministic escape/configuration-tampering tests.
