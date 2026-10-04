"""Recorded static-site preparation. No model, server, browser or target execution.

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
from roles.read_policy import WEBSITE_FILES, WEBSITE_PROFILE, website_policy
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


class Session:
    """One private, controller-owned rehearsal; retains artifacts on failure."""
    def __init__(self, brief, parent):
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
        self.contract = digest({"profile": WEBSITE_PROFILE, "files": WEBSITE_FILES,
                                "max_file_bytes": MAX_FILE_BYTES, "guidance": GUIDANCE_SHA,
                                "brief": brief.__dict__, "checks": "STRUCTURAL_V1"})

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
        page = _HTML()
        page.feed(dict(snapshot.files)["index.html"].decode("utf-8"))
        page.close()
        expected = {"title": self.brief.title,
                    "h1": self.brief.revision_heading if revised else self.brief.heading,
                    "button": self.brief.revision_button if revised else self.brief.button}
        if (page.unsafe or page.stack or page.css != 1 or page.js != 1
                or any(page.count[k] != 1 or page.text[k].strip() != v for k, v in expected.items())
                or not all(dict(snapshot.files)[n].strip() for n in WEBSITE_FILES)):
            raise WebsiteError("PROTECTED_CHECK_FAILED")
        return {"snapshot_sha256": snapshot.sha256, "contract": self.contract,
                "structural": "PASS", "recorded": True, "functional": "UNPROVEN",
                "browser": "UNPROVEN", "active_isolation": "UNPROVEN"}

    def preview(self, snapshot):
        self.validate_snapshot(snapshot)
        return {"version": 1, "run": self.run, "snapshot_sha256": snapshot.sha256,
                "contract": self.contract, "entry": "index.html", "bind": "127.0.0.1",
                "execution": "DISABLED", "qualification": "UNPROVEN"}

    def export(self, snapshot, checks):
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
            self.write(directory, "export.json", json.dumps(manifest, sort_keys=True).encode())
            os.fsync(directory)
            os.fsync(root)
            return {"directory": str(self.root / "export"), "manifest": manifest}
        finally:
            if directory is not None:
                os.close(directory)
            os.close(root)


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


def workflow_graph(adapter, graph_type, start, end):
    if type(adapter) is not RecordedAdapter:
        raise WebsiteError("RECORDED_ADAPTER_REQUIRED")
    builder = graph_type(WorkflowState)
    def scaffold(state):
        state["session"].scaffold()
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
                "status": "PREPARATION_COMPLETE"}
    for name, node in (("scaffold", scaffold), ("code", code), ("revision", revise),
                       ("checks", checks), ("export", export)):
        builder.add_node(name, node)
    for left, right in ((start, "scaffold"), ("scaffold", "code"), ("code", "revision"),
                        ("revision", "checks"), ("checks", "export"), ("export", end)):
        builder.add_edge(left, right)
    return builder.compile()
