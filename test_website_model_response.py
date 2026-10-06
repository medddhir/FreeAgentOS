"""Finite synthetic envelopes through the real graph/broker; no code execution."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "orchestrator"))
import graph
import model_response as m
import website as w
from roles.file_tools import FileTools
from test_website import brief
from test_website_proposals import adapter, encode, proposed_files


def transport(proposal, form):
    if form == "structured_output":
        return encode({"type": "result", "is_error": False, "structured_output": proposal})
    if form == "result":
        return encode({"type": "result", "result": encode(proposal).decode()})
    return encode(proposal)


def responses(session, form="structured_output"):
    direct = adapter(session)
    return w.SyntheticModelResponseAdapter(
        transport(json.loads(direct.code), form), transport(json.loads(direct.revision), form))


class WebsiteModelResponseTests(unittest.TestCase):
    def test_all_three_transport_forms_complete_graph_revision_and_exact_export(self):
        for form in ("structured_output", "result", "direct"):
            with self.subTest(form=form), tempfile.TemporaryDirectory() as parent:
                session = w.Session(brief(), parent, preparation="synthetic")
                source = responses(session, form)
                with patch.object(m, "extract_model_response", wraps=m.extract_model_response) as extract:
                    result = graph.build_website_graph(source).invoke({"session": session})
                self.assertEqual(extract.call_count, 2)
                self.assertEqual([call.args[0] for call in extract.call_args_list],
                                 [source.code, source.revision])
                self.assertEqual(result["status"], "SYNTHETIC_PREPARATION_COMPLETE")
                self.assertEqual(result["model_calls"], "NONE")
                self.assertTrue(result["synthetic"])
                self.assertFalse(result["live_qualified"])
                self.assertNotEqual(result["before"].sha256, result["after"].sha256)
                self.assertEqual(dict(result["before"].files),
                                 {n: t.encode() for n, t in proposed_files().items()})
                self.assertEqual(dict(result["after"].files),
                                 {n: t.encode() for n, t in proposed_files(True).items()})
                for phase, raw, count in (("code", source.code, 4), ("revision", source.revision, 2)):
                    evidence = result[phase + "_evidence"]
                    self.assertEqual(evidence["adapter_id"], "SYNTHETIC_MODEL_RESPONSE_V1")
                    self.assertEqual(evidence["tool_calls"], count)
                    self.assertEqual(evidence["transport_sha256"], hashlib.sha256(raw).hexdigest())
                    self.assertEqual(evidence["response_sha256"],
                                     hashlib.sha256(m.extract_model_response(raw)).hexdigest())
                    self.assertFalse(evidence["recorded"])
                self.assertEqual(result["revision_evidence"]["base_snapshot"], result["before"].sha256)
                self.assertEqual(result["revision_evidence"]["snapshot_sha256"], result["after"].sha256)
                self.assertEqual(result["checks"]["structural"], "PASS")
                for name in ("functional", "browser", "active_isolation"):
                    self.assertEqual(result["checks"][name], "UNPROVEN")
                self.assertEqual(result["preview"]["execution"], "DISABLED")
                exported = Path(result["export"]["directory"])
                self.assertEqual(exported, session.root / "export")
                self.assertEqual(set(p.name for p in exported.iterdir()), set(w.WEBSITE_FILES) | {"export.json"})
                for name, raw in result["after"].files:
                    self.assertEqual((exported / name).read_bytes(), raw)
                receipt = json.loads((exported / "export.json").read_bytes())
                self.assertEqual(receipt, result["export"]["manifest"])
                self.assertEqual(set(receipt["files"]), set(w.WEBSITE_FILES))
                self.assertEqual(receipt["status"], "PREPARATION_ONLY")
                self.assertFalse(receipt["live_qualified"])
                with self.assertRaises(FileExistsError):
                    session.export(result["after"], result["checks"])
                with self.assertRaisesRegex(w.WebsiteError, "CHECK_EVIDENCE_MISMATCH"):
                    session.export(result["after"], dict(result["checks"], browser="PASS"))

    def rejected(self, transform):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation="synthetic")
            session.scaffold()
            valid = responses(session)
            before = session.snapshot()
            raw = transform(json.loads(adapter(session).code))
            bad = w.SyntheticModelResponseAdapter(raw, valid.revision)
            with patch.object(w, "FileTools") as broker, self.assertRaises(w.ProposalError) as caught:
                bad.apply(session, "code")
            broker.assert_not_called()
            self.assertEqual(str(caught.exception), "PROPOSAL_VALIDATION_FAILED")
            self.assertEqual(caught.exception.evidence["artifact_state"], "RETAINED")
            self.assertFalse(caught.exception.evidence["cleanup_attempted"])
            self.assertEqual(session.snapshot(), before)
            self.assertFalse((session.root / "export").exists())
            with self.assertRaises(w.ProposalError):
                valid.apply(session, "code")
            with self.assertRaisesRegex(w.WebsiteError, "PROPOSAL_NOT_COMPLETE"):
                session.export(before, {})

    def test_transport_errors_reject_before_broker_and_fence_session(self):
        for raw in (b'{', b'{} {}', b'\xff', b'{"result":"{]"}',
                    b'{"structured_output":{"version":1,"version":1}}'):
            with self.subTest(raw=raw):
                self.rejected(lambda value, raw=raw: raw)
        for extra in ({"is_error": True}, {"type": "assistant"}, {"result": "malformed"},
                      {"structured_output": None}):
            with self.subTest(extra=extra):
                self.rejected(lambda value, extra=extra:
                              encode({"structured_output": value, **extra}))
        for raw in (b'', b'x' * (w.MAX_RESPONSE_BYTES + 1), '{}'):
            with self.subTest(bound=type(raw).__name__), self.assertRaisesRegex(
                    w.WebsiteError, "PROPOSAL_RESPONSE_BOUNDS"):
                w.SyntheticModelResponseAdapter(raw, b'{}')

    def test_extraction_cannot_repair_bindings_paths_content_or_structural_rules(self):
        for key, value in (("version", True), ("run", "foreign"), ("profile", "ordinary"),
                           ("phase", "revision"), ("contract", "f" * 64),
                           ("base_snapshot", "0" * 64), ("tools", ["shell"]),
                           ("live_qualified", True)):
            with self.subTest(field=key):
                self.rejected(lambda proposal, key=key, value=value:
                              transport({**proposal, key: value}, "structured_output"))
        for change in (lambda v: v["files"][-1].update(path="../outside"),
                       lambda v: v["files"][-1].update(text="Secret garden"),
                       lambda v: v["files"][-1].update(text="x" * (w.MAX_FILE_BYTES + 1)),
                       lambda v: v["files"].append(copy.deepcopy(v["files"][0])),
                       lambda v: v["files"][0].update(text="<html></html>")):
            def invalid(value, change=change):
                change(value)
                return transport(value, "result")
            self.rejected(invalid)

    def test_stale_revision_rejects_without_writes_and_keeps_initial_snapshot(self):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation="synthetic")
            session.scaffold()
            source = responses(session)
            source.apply(session, "code")
            before = session.snapshot()
            direct = adapter(session)
            value = json.loads(direct.revision)
            value["base_snapshot"] = json.loads(direct.code)["base_snapshot"]
            bad = w.SyntheticModelResponseAdapter(source.code, transport(value, "structured_output"))
            with patch.object(w, "FileTools") as broker, self.assertRaises(w.ProposalError):
                bad.apply(session, "revision")
            broker.assert_not_called()
            self.assertEqual(session.snapshot(), before)
            with self.assertRaises(w.ProposalError):
                source.apply(session, "revision")
            self.assertFalse((session.root / "export").exists())

    def test_partial_revision_retains_artifacts_and_cannot_export_structural_pass(self):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation="synthetic")
            session.scaffold()
            source = responses(session)
            source.apply(session, "code")
            before = session.snapshot()
            original = FileTools.call
            def fail_styles(broker, name, arguments):
                if arguments["path"] == "styles.css":
                    raise OSError("private fixture detail")
                return original(broker, name, arguments)
            with patch.object(FileTools, "call", fail_styles), self.assertRaises(w.ProposalError) as caught:
                source.apply(session, "revision")
            self.assertEqual(str(caught.exception), "PROPOSAL_APPLICATION_FAILED")
            self.assertNotIn("private", repr(caught.exception.evidence))
            self.assertEqual(caught.exception.evidence["artifact_state"], "RETAINED")
            self.assertFalse(caught.exception.evidence["cleanup_attempted"])
            after = session.snapshot()
            self.assertNotEqual(before, after)
            self.assertEqual(dict(after.files)["index.html"], proposed_files(True)["index.html"].encode())
            self.assertEqual(dict(after.files)["styles.css"], dict(before.files)["styles.css"])
            checks = session.checks(after, True)
            self.assertEqual(checks["structural"], "PASS")
            with self.assertRaisesRegex(w.WebsiteError, "PROPOSAL_NOT_COMPLETE"):
                session.export(after, checks)
            with self.assertRaises(w.ProposalError):
                source.apply(session, "revision")
            self.assertFalse((session.root / "export").exists())

    def test_adapter_is_explicit_synthetic_only_and_live_launch_stays_closed(self):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent)
            with self.assertRaisesRegex(w.WebsiteError, "PREPARATION_KIND_MISMATCH"):
                graph.build_website_graph(responses(session)).invoke({"session": session})
            class Unlisted(w.SyntheticModelResponseAdapter):
                pass
            with self.assertRaisesRegex(w.WebsiteError, "RECORDED_ADAPTER_REQUIRED"):
                graph.build_website_graph(Unlisted(b'{}', b'{}'))
            with self.assertRaisesRegex(w.WebsiteError, "EXECUTION_QUALIFICATION_UNPROVEN"):
                w.launch_live("coding", synthetic=True)


if __name__ == "__main__":
    unittest.main()
