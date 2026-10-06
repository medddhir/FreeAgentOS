"""Recorded/synthetic static-site preparation. No model, server, browser or target execution.

Uses the existing graph library, file broker and descriptor-bound snapshot reads.
Preparation checks are structural, never functional/browser qualification.
"""
from dataclasses import dataclass
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import TypedDict
import uuid

from roles.file_tools import FileTools
from roles.inspector import _read
from roles.read_policy import (WEBSITE_FILES, WEBSITE_PROFILE, website_policy,
                               content_allowed)
from roles.workspace import _sha

PIN = "e103efe779e2dd01274dabae83531fef00bf2563"
GUIDANCE_SHA = "a55f016c046cb6a27c55bd7f346375aeb506a755c4fbca19a5f92dbd42309c23"
LICENSE_SHA = "02bb8c3b4e70190e3986c0404ad2fd8d639b4f534252d82379cc1b502b6d1812"
NOTICE_SHA = "c60a093c2845fd9fb82f9c6f742ece31f379f8190b535309d32d66c45ccffdcb"
MAX_FILE_BYTES = 8192
MAX_PROJECT_BYTES = 4 * MAX_FILE_BYTES
MAX_ACTIONS = 4


class WebsiteError(ValueError):
    pass


def digest(value):
    return _sha(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())


def guidance():
    """Pinned upstream data, not a skill loader or permission source."""
    root = Path(__file__).with_name("website_guidance")
    selected = None
    for name, expected in (("shape.md", GUIDANCE_SHA), ("LICENSE", LICENSE_SHA),
                           ("NOTICE.md", NOTICE_SHA)):
        raw = _read(root, name)
        if raw is None or len(raw) > 16384 or _sha(raw) != expected:
            raise WebsiteError("GUIDANCE_IDENTITY_MISMATCH")
        if name == "shape.md":
            selected = raw.decode()
    return selected


@dataclass(frozen=True)
class ConfirmedBrief:
    title: str
    heading: str
    button: str
    revision_heading: str
    revision_button: str
    design: str
    confirmed: bool

    def __post_init__(self):
        if self.confirmed is not True:
            raise WebsiteError("BRIEF_NOT_CONFIRMED")
        for value in (self.title, self.heading, self.button, self.revision_heading,
                      self.revision_button, self.design):
            if (type(value) is not str or not 0 < len(value.encode()) <= 512
                    or any(ord(c) < 32 for c in value)):
                raise WebsiteError("BRIEF_INVALID")
        if (self.heading, self.button) == (self.revision_heading, self.revision_button):
            raise WebsiteError("REVISION_REQUIRED")


@dataclass(frozen=True)
class RecordedAdapter:
    """Finite file-tool recordings; no callable/command/live-adapter escape hatch."""
    code: tuple
    revision: tuple

    def __post_init__(self):
        for actions in (self.code, self.revision):
            if (type(actions) is not tuple or not 1 <= len(actions) <= MAX_ACTIONS
                    or any(type(a) is not tuple or len(a) != 2
                           or any(type(v) is not str for v in a) for a in actions)
                    or len({a[0] for a in actions}) != len(actions)
                    or any(len(a[1].encode()) > MAX_FILE_BYTES for a in actions)):
                raise WebsiteError("RECORDING_INVALID")

    def apply(self, session, phase):
        if phase not in ("code", "revision"):
            raise WebsiteError("RECORDING_PHASE_INVALID")
        session.assert_root()
        context = {"brief": session.brief.__dict__, "design_guidance": guidance(),
                   "guidance_pin": PIN, "guidance_sha256": GUIDANCE_SHA,
                   "role": "coder" if phase == "code" else "fixer",
                   "adapter_id": "RECORDED_FILE_TOOLS", "execution_authority": "NONE"}
        if len(json.dumps(context, ensure_ascii=False).encode()) > MAX_FILE_BYTES:
            raise WebsiteError("CONTEXT_BOUNDS_EXCEEDED")
        broker = FileTools(website_policy(session.workspace, context["role"]))
        actions = self.code if phase == "code" else self.revision
        for path, text in actions:
            broker.call("write_file", {"path": path, "text": text})
        return {"phase": phase, "recorded": True, "tool_calls": broker.calls,
                "context_sha256": digest(context), "live_qualified": False}


@dataclass(frozen=True)
class Snapshot:
    run: str
    profile: str
    contract: str
    files: tuple  # immutable (exact relative path, bytes) pairs
    sha256: str


def recorded_site_adapter(brief):
    """Fixed rehearsal recording, parameterized by confirmed text, never code."""
    from html import escape
    if type(brief) is not ConfirmedBrief:
        raise WebsiteError("BRIEF_INVALID")
    def page(heading, button):
        return ('<!doctype html><html><head><meta charset="utf-8"><title>' +
                escape(brief.title) + '</title><link rel="stylesheet" href="styles.css">'
                '</head><body><main><h1>' + escape(heading) +
                '</h1><button id="more">' + escape(button) +
                '</button><p id="detail" hidden>Made locally.</p></main>'
                '<script src="app.js"></script></body></html>')
    css = 'body { background: #faf8f2; color: #232323; margin: 2rem; }'
    js = ('document.querySelector("#more").addEventListener("click", () => { '
          'document.querySelector("#detail").hidden = false; });')
    return RecordedAdapter((("index.html", page(brief.heading, brief.button)),
                            ("styles.css", css), ("app.js", js),
                            ("README.md", "Recorded static website preparation.\nDesign brief: " +
                             brief.design + "\nFunctional/browser qualification: UNPROVEN.\n")),
                           (("index.html", page(brief.revision_heading, brief.revision_button)),
                            ("styles.css", css + ' button { padding: 1rem; }')))


class _HTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.text = {"title": "", "h1": "", "button": ""}
        self.count = {k: 0 for k in self.text}
        self.css = self.js = 0
        self.unsafe = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if len(values) != len(attrs):
            self.unsafe = True
        if tag in ("iframe", "object", "embed", "base", "form", "meta"):
            # charset/viewport metadata are the only supported meta forms.
            if tag != "meta" or not (set(values) == {"charset"} or
                                     values.get("name") == "viewport" and set(values) == {"name", "content"}):
                self.unsafe = True
        for key, value in attrs:
            if key.startswith("on") or key in ("srcdoc", "style"):
                self.unsafe = True
            if key in ("src", "href", "action") and value not in ("styles.css", "app.js", "#"):
                self.unsafe = True
        if tag == "script":
            if values != {"src": "app.js"}:
                self.unsafe = True
            self.js += 1
        if tag == "link":
            if values != {"rel": "stylesheet", "href": "styles.css"}:
                self.unsafe = True
            self.css += 1
        if tag in self.count:
            self.count[tag] += 1
        if tag not in ("meta", "link", "img", "br", "hr", "input"):
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            self.unsafe = True

    def handle_data(self, data):
        if "script" in self.stack and data.strip():
            self.unsafe = True
        for tag in self.text:
            if tag in self.stack:
                self.text[tag] += data


def structural_checks(files, brief, revised):
    """Same protected structural subset for proposed bytes and actual snapshots."""
    page = _HTML()
    page.feed(dict(files)["index.html"].decode("utf-8"))
    page.close()
    expected = {"title": brief.title,
                "h1": brief.revision_heading if revised else brief.heading,
                "button": brief.revision_button if revised else brief.button}
    if (page.unsafe or page.stack or page.css != 1 or page.js != 1
            or any(page.count[k] != 1 or page.text[k].strip() != v for k, v in expected.items())
            or not all(dict(files)[n].strip() for n in WEBSITE_FILES)):
        raise WebsiteError("PROTECTED_CHECK_FAILED")


class Session:
    """One private, controller-owned rehearsal; retains artifacts on failure."""
    def __init__(self, brief, parent, *, preparation="recorded"):
        if type(preparation) is not str or preparation not in ("recorded", "synthetic"):
            raise WebsiteError("PREPARATION_KIND_INVALID")
        self.preparation = preparation
        self._proposal_phase = "code"
        if type(brief) is not ConfirmedBrief:
            raise WebsiteError("BRIEF_INVALID")
        # Caller is deterministic controller/test code, never model/tool input.
        parent = Path(parent).absolute()
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise WebsiteError("STAGING_PARENT_UNSAFE")
        self.root = Path(tempfile.mkdtemp(prefix="freeagentos-website-", dir=parent))
        self.root_identity = self.identity(self.root)
        self.workspace = self.root / "project"
        self.workspace.mkdir(mode=0o700)
        self.workspace_identity = self.identity(self.workspace)
        self.brief = brief
        self.run = uuid.uuid4().hex
        contract = {"profile": WEBSITE_PROFILE, "files": WEBSITE_FILES,
                    "max_file_bytes": MAX_FILE_BYTES, "guidance": GUIDANCE_SHA,
                    "brief": brief.__dict__, "checks": "STRUCTURAL_V1"}
        if preparation == "synthetic":
            contract["preparation"] = "SYNTHETIC_PROPOSAL_V1"
        self.contract = digest(contract)

    @staticmethod
    def identity(path):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise WebsiteError("ROOT_CHANGED")
        return [info.st_dev, info.st_ino]

    def assert_root(self):
        if (self.identity(self.root) != self.root_identity or
                self.identity(self.workspace) != self.workspace_identity):
            raise WebsiteError("ROOT_CHANGED")

    def scaffold(self):
        self.assert_root()
        fd = os.open(self.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for name in WEBSITE_FILES:
                self.write(fd, name, b"" if name != "README.md" else b"Static website source. Local preview is not qualified yet.\n")
        finally:
            os.close(fd)

    @staticmethod
    def write(directory, name, raw):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    def snapshot(self):
        self.assert_root()
        if set(os.listdir(self.workspace)) != set(WEBSITE_FILES):
            raise WebsiteError("PROJECT_MEMBERSHIP_INVALID")
        files = []
        for name in WEBSITE_FILES:
            raw = _read(self.workspace, name, self.workspace_identity)
            if raw is None or len(raw) > MAX_FILE_BYTES:
                raise WebsiteError("PROJECT_BOUNDS_EXCEEDED")
            files.append((name, raw))
        if sum(len(raw) for _, raw in files) > MAX_PROJECT_BYTES:
            raise WebsiteError("PROJECT_BOUNDS_EXCEEDED")
        payload = {"run": self.run, "profile": WEBSITE_PROFILE, "contract": self.contract,
                   "files": [(n, _sha(b)) for n, b in files]}
        return Snapshot(self.run, WEBSITE_PROFILE, self.contract, tuple(files), digest(payload))

    def validate_snapshot(self, snapshot):
        if type(snapshot) is not Snapshot or self.snapshot() != snapshot:
            raise WebsiteError("SNAPSHOT_CHANGED")

    def checks(self, snapshot, revised):
        self.validate_snapshot(snapshot)
        structural_checks(snapshot.files, self.brief, revised)
        return {"snapshot_sha256": snapshot.sha256, "contract": self.contract,
                "structural": "PASS", "recorded": self.preparation == "recorded", "functional": "UNPROVEN",
                "browser": "UNPROVEN", "active_isolation": "UNPROVEN"}

    def preview(self, snapshot):
        self.validate_snapshot(snapshot)
        return {"version": 1, "run": self.run, "snapshot_sha256": snapshot.sha256,
                "contract": self.contract, "entry": "index.html", "bind": "127.0.0.1",
                "execution": "DISABLED", "qualification": "UNPROVEN"}

    def export(self, snapshot, checks):
        if self.preparation == "synthetic" and self._proposal_phase != "complete":
            raise WebsiteError("PROPOSAL_NOT_COMPLETE")
        self.validate_snapshot(snapshot)
        if checks != self.checks(snapshot, True):
            raise WebsiteError("CHECK_EVIDENCE_MISMATCH")
        root = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        directory = None
        try:
            if [os.fstat(root).st_dev, os.fstat(root).st_ino] != self.root_identity:
                raise WebsiteError("ROOT_CHANGED")
            os.mkdir("export", mode=0o700, dir_fd=root)  # no caller-selected destination
            directory = os.open("export", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            for name, raw in snapshot.files:
                self.write(directory, name, raw)
            self.validate_snapshot(snapshot)
            manifest = {"version": 1, "run": self.run, "profile": WEBSITE_PROFILE,
                        "snapshot_sha256": snapshot.sha256, "contract": self.contract,
                        "files": {n: _sha(b) for n, b in snapshot.files},
                        "status": "PREPARATION_ONLY", "live_qualified": False}
            if self.preparation == "synthetic":
                manifest.update(synthetic=True, model_calls="NONE", recorded=False)
            self.write(directory, "export.json", json.dumps(manifest, sort_keys=True).encode())
            os.fsync(directory)
            os.fsync(root)
            return {"directory": str(self.root / "export"), "manifest": manifest}
        finally:
            if directory is not None:
                os.close(directory)
            os.close(root)


MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 48 * 1024


class ProposalError(WebsiteError):
    """Safe fixed rejection category; retained files are never cleaned up here."""
    def __init__(self, stage, session):
        super().__init__("PROPOSAL_" + stage + "_FAILED")
        try:
            session.assert_root()
            retained = "RETAINED"
        except Exception:
            retained = "UNPROVEN"
        self.evidence = {"stage": stage, "artifact_state": retained,
                         "cleanup_attempted": False, "model_calls": "NONE",
                         "live_qualified": False}


def proposal_request(session, phase):
    """Controller-only request data. No callable transport or execution authority."""
    if session.preparation != "synthetic" or phase not in ("code", "revision"):
        raise WebsiteError("PROPOSAL_PHASE_INVALID")
    base = session.snapshot()
    request = {"version": 1, "run": session.run, "profile": WEBSITE_PROFILE,
               "phase": phase, "contract": session.contract, "base_snapshot": base.sha256,
               "brief": session.brief.__dict__, "guidance": guidance(),
               "guidance_sha256": GUIDANCE_SHA,
               "files": [{"path": n, "text": b.decode("utf-8")} for n, b in base.files]}
    if len(json.dumps(request, ensure_ascii=False).encode("utf-8")) > MAX_REQUEST_BYTES:
        raise WebsiteError("PROPOSAL_REQUEST_BOUNDS")
    return request, base


def _proposal_json(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RESPONSE_BYTES:
        raise WebsiteError("PROPOSAL_INVALID")
    text = raw.decode("utf-8", "strict")
    # Check structural work before json.loads: only top object, files array and
    # four entry objects fit this schema. Braces inside strings are not structure.
    depth = containers = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            containers += 1
            if depth > 3 or containers > 6:
                raise WebsiteError("PROPOSAL_INVALID")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise WebsiteError("PROPOSAL_INVALID")
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise WebsiteError("PROPOSAL_INVALID")
            result[key] = value
        return result
    def invalid_number(value):
        raise WebsiteError("PROPOSAL_INVALID")
    def integer(value):
        if len(value) > 20:
            raise WebsiteError("PROPOSAL_INVALID")
        return int(value)
    return json.loads(text, object_pairs_hook=object_pairs, parse_int=integer,
                      parse_float=invalid_number, parse_constant=invalid_number)


def validate_proposal(raw, session, phase, base):
    """Validate every replacement and retained byte before any proposal write."""
    if session.preparation != "synthetic" or phase not in ("code", "revision"):
        raise WebsiteError("PROPOSAL_PHASE_INVALID")
    session.validate_snapshot(base)
    value = _proposal_json(raw)
    binding = {"version": 1, "run": session.run, "profile": WEBSITE_PROFILE,
               "phase": phase, "contract": session.contract, "base_snapshot": base.sha256}
    if (type(value) is not dict or set(value) != set(binding) | {"files"}
            or any(type(value[key]) is not type(want) or value[key] != want
                   for key, want in binding.items())):
        raise WebsiteError("PROPOSAL_INVALID")
    entries = value["files"]
    if type(entries) is not list or not 1 <= len(entries) <= MAX_ACTIONS:
        raise WebsiteError("PROPOSAL_INVALID")
    actions = []
    seen = set()
    merged = dict(base.files)
    for entry in entries:
        if (type(entry) is not dict or set(entry) != {"path", "text"}
                or type(entry["path"]) is not str or entry["path"] not in WEBSITE_FILES
                or entry["path"] in seen or type(entry["text"]) is not str):
            raise WebsiteError("PROPOSAL_INVALID")
        raw_text = entry["text"].encode("utf-8", "strict")
        if len(raw_text) > MAX_FILE_BYTES or not content_allowed(raw_text):
            raise WebsiteError("PROPOSAL_INVALID")
        seen.add(entry["path"])
        actions.append((entry["path"], entry["text"]))
        merged[entry["path"]] = raw_text
    if phase == "code" and seen != set(WEBSITE_FILES):
        raise WebsiteError("PROPOSAL_INVALID")
    files = tuple((n, merged[n]) for n in WEBSITE_FILES)
    if (sum(len(b) for _, b in files) > MAX_PROJECT_BYTES
            or any(not content_allowed(b) for _, b in files)
            or phase == "revision" and files == base.files):
        raise WebsiteError("PROPOSAL_INVALID")
    structural_checks(files, session.brief, phase == "revision")
    session.validate_snapshot(base)
    return tuple(actions), files


@dataclass(frozen=True)
class SyntheticProposalAdapter:
    """Two finite, externally bound byte responses; no callbacks or live transport."""
    code: bytes
    revision: bytes
    _adapter_id = "SYNTHETIC_PROPOSAL_V1"

    def __post_init__(self):
        for response in (self.code, self.revision):
            if type(response) is not bytes or not 0 < len(response) <= MAX_RESPONSE_BYTES:
                raise WebsiteError("PROPOSAL_RESPONSE_BOUNDS")

    def _response(self, phase):
        return self.code if phase == "code" else self.revision

    def apply(self, session, phase):
        try:
            if session._proposal_phase != phase:
                raise WebsiteError("PROPOSAL_PHASE_INVALID")
            request, base = proposal_request(session, phase)
            response = self._response(phase)
            actions, files = validate_proposal(response, session, phase, base)
        except Exception:
            session._proposal_phase = "blocked"
            raise ProposalError("VALIDATION", session) from None
        try:
            broker = FileTools(website_policy(session.workspace, "coder" if phase == "code" else "fixer"))
            session.validate_snapshot(base)
            for path, text in actions:
                session.assert_root()
                broker.call("write_file", {"path": path, "text": text})
            observed = session.snapshot()
            if observed.files != files:
                raise WebsiteError("PROPOSAL_APPLICATION_CHANGED")
            session.checks(observed, phase == "revision")
        except Exception:
            session._proposal_phase = "blocked"
            raise ProposalError("APPLICATION", session) from None
        session._proposal_phase = "revision" if phase == "code" else "complete"
        return {"phase": phase, "recorded": False, "synthetic": True,
                "adapter_id": self._adapter_id, "model_calls": "NONE",
                "context_sha256": digest(request), "base_snapshot": base.sha256,
                "response_sha256": _sha(response), "snapshot_sha256": observed.sha256,
                "tool_calls": broker.calls, "live_qualified": False}


@dataclass(frozen=True)
class SyntheticModelResponseAdapter(SyntheticProposalAdapter):
    """Two finite synthetic transport envelopes; extraction grants no authority.

    Extraction runs inside the existing whole-proposal validation/failure fence,
    before any broker exists. Direct-proposal callers retain their original path.
    No provider, callback, launcher or admission producer is involved.
    """
    _adapter_id = "SYNTHETIC_MODEL_RESPONSE_V1"

    def _response(self, phase):
        from model_response import extract_model_response
        return extract_model_response(super()._response(phase))

    def apply(self, session, phase):
        evidence = super().apply(session, phase)
        return {**evidence, "transport_sha256": _sha(super()._response(phase))}


def launch_live(kind, *args, **kwargs):
    """No qualification producer is wired; booleans/recordings cannot grant it."""
    raise WebsiteError("EXECUTION_QUALIFICATION_UNPROVEN")


class WorkflowState(TypedDict, total=False):
    session: Session
    code_evidence: dict
    revision_evidence: dict
    before: Snapshot
    after: Snapshot
    checks: dict
    preview: dict
    export: dict
    status: str
    synthetic: bool
    model_calls: str
    live_qualified: bool


def workflow_graph(adapter, graph_type, start, end):
    if type(adapter) not in (RecordedAdapter, SyntheticProposalAdapter, SyntheticModelResponseAdapter):
        raise WebsiteError("RECORDED_ADAPTER_REQUIRED")
    builder = graph_type(WorkflowState)
    def scaffold(state):
        session = state["session"]
        expected = "recorded" if type(adapter) is RecordedAdapter else "synthetic"
        if session.preparation != expected:
            raise WebsiteError("PREPARATION_KIND_MISMATCH")
        session.scaffold()
        return {}
    def code(state):
        session = state["session"]
        result = adapter.apply(session, "code")
        snapshot = session.snapshot()
        session.checks(snapshot, False)
        return {"code_evidence": result, "before": snapshot}
    def revise(state):
        session = state["session"]
        session.validate_snapshot(state["before"])
        result = adapter.apply(session, "revision")
        snapshot = session.snapshot()
        if snapshot == state["before"]:
            raise WebsiteError("REVISION_REQUIRED")
        return {"revision_evidence": result, "after": snapshot}
    def checks(state):
        return {"checks": state["session"].checks(state["after"], True)}
    def export(state):
        session = state["session"]
        return {"preview": session.preview(state["after"]),
                "export": session.export(state["after"], state["checks"]),
                "status": ("SYNTHETIC_PREPARATION_COMPLETE" if session.preparation == "synthetic"
                           else "PREPARATION_COMPLETE"),
                **({"synthetic": True, "model_calls": "NONE", "live_qualified": False}
                   if session.preparation == "synthetic" else {})}
    for name, node in (("scaffold", scaffold), ("code", code), ("revision", revise),
                       ("checks", checks), ("export", export)):
        builder.add_node(name, node)
    for left, right in ((start, "scaffold"), ("scaffold", "code"), ("code", "revision"),
                        ("revision", "checks"), ("checks", "export"), ("export", end)):
        builder.add_edge(left, right)
    return builder.compile()
