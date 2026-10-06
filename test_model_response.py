"""Synthetic extraction and existing broker-boundary fixtures; no live execution."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / "orchestrator"))
import model_response as m
import website as w
from roles.file_tools import FileTools
from test_website import brief
from test_website_proposals import proposed_files, envelope, encode, snapshot_hash

FIXED_CODES = frozenset((
    "RESPONSE_BOUNDS", "RESPONSE_ENCODING", "RESPONSE_STRUCTURE", "RESPONSE_JSON",
    "RESPONSE_ENVELOPE", "RESPONSE_FIELD_TYPE", "RESPONSE_MODEL_ERROR",
    "RESPONSE_AMBIGUOUS", "RESPONSE_CANDIDATE_MISSING",
    "RESPONSE_STRUCTURED_OUTPUT_INVALID", "RESPONSE_RESULT_INVALID",
    "RESPONSE_CANDIDATE", "RESPONSE_SERIALIZATION", "RESPONSE_OUTPUT_BOUNDS",
    "RESPONSE_UNSUPPORTED_TYPE"))


def scaffold():
    files = {name: "" for name in w.WEBSITE_FILES}
    files["README.md"] = "Static website source. Local preview is not qualified yet.\n"
    return files


def proposal(session, phase="code"):
    return envelope(session, phase, proposed_files(), snapshot_hash(session, scaffold()))


def wrapped(value):
    return encode({"type": "result", "is_error": False, "structured_output": value})


class ModelResponseTests(unittest.TestCase):
    def session(self, parent):
        session = w.Session(brief(), parent, preparation="synthetic")
        session.scaffold()
        return session

    def test_structured_output_result_and_direct_forms_converge(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            value = proposal(session)
            expected = json.loads(m.extract_model_response(encode(value)))
            for raw in (wrapped(value), encode({"result": encode(value).decode()}), encode(value)):
                with self.subTest(form=raw[:28]):
                    self.assertEqual(json.loads(m.extract_model_response(raw)), expected)
            self.assertEqual(set(expected), {"version", "run", "profile", "phase",
                                             "contract", "base_snapshot", "files"})
            self.assertEqual([entry["path"] for entry in expected["files"]],
                             list(w.WEBSITE_FILES))

    def test_unicode_and_source_text_round_trip(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            value = proposal(session)
            text = "caf\u00e9 \u2192 \U0001F600\n\t\"quoted\" \\ slash \u2028 end"
            value["files"][2]["text"] = text
            out = m.extract_model_response(wrapped(value))
            self.assertEqual(json.loads(out)["files"][2]["text"], text)
            self.assertIn("caf\u00e9".encode("utf-8"), out)
            self.assertIn("\U0001F600".encode("utf-8"), out)
            self.assertNotIn(b"\\u00e9", out)
            self.assertNotIn(b"\\ud83d", out)
            self.assertIn(b"\\n", out)
            self.assertIn(b"\\t", out)

    def test_binding_fields_and_four_file_array_are_preserved(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            value = proposal(session)
            restored = json.loads(m.extract_model_response(wrapped(value)))
            for key in ("version", "run", "profile", "phase", "contract", "base_snapshot"):
                self.assertEqual(restored[key], value[key])
            self.assertEqual(len(restored["files"]), 4)
            self.assertEqual(restored["files"], value["files"])
            self.assertEqual(restored["base_snapshot"], snapshot_hash(session, scaffold()))
            self.assertEqual(restored["profile"], w.WEBSITE_PROFILE)
            self.assertEqual(set(restored), set(value))

    def test_duplicate_keys_reject_everywhere(self):
        cases = ((b'{"structured_output":{"a":1,"a":2}}', "RESPONSE_JSON"),
                 (b'{"a":1,"a":2,"structured_output":{}}', "RESPONSE_JSON"),
                 (b'{"result":"{\\"a\\":1,\\"a\\":2}"}', "RESPONSE_JSON"))
        for raw, code in cases:
            with self.subTest(raw=raw), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(raw)
            self.assertEqual(caught.exception.code, code)

    def test_malformed_utf8_and_bom_reject(self):
        for raw in (b"\xff", b'{"structured_output":{"a":"\xff"}}', b"\xef\xbb\xbf{}"):
            with self.subTest(raw=raw), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(raw)
            self.assertEqual(caught.exception.code, "RESPONSE_ENCODING")

    def test_trailing_and_multiple_values_reject(self):
        for raw in (b"{} {}", b"{}{}", b"{} trailing", b'{"structured_output":{}} []'):
            with self.subTest(raw=raw), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(raw)
            self.assertEqual(caught.exception.code, "RESPONSE_JSON")

    def test_ambiguous_candidates_reject_including_malformed_secondary(self):
        cases = ({"structured_output": {"a": 1}, "result": "{\"b\":2}"},
                 {"structured_output": {"a": 1}, "result": "not json"},
                 {"structured_output": {"a": 1}, "result": 5},
                 {"structured_output": {"a": 1}, "result": []},
                 {"structured_output": [], "result": "{\"b\":2}"})
        for value in cases:
            with self.subTest(value=value), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(encode(value))
            self.assertEqual(caught.exception.code, "RESPONSE_AMBIGUOUS")

    def test_null_candidates_are_absent_and_missing_candidates_reject(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            value = proposal(session)
            raw = encode({"structured_output": None, "result": encode(value).decode()})
            self.assertEqual(json.loads(m.extract_model_response(raw)), value)
        for raw in (encode({"structured_output": None}),
                    encode({"structured_output": None, "result": None}),
                    encode({"result": None, "is_error": False})):
            with self.subTest(raw=raw), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(raw)
            self.assertEqual(caught.exception.code, "RESPONSE_CANDIDATE_MISSING")

    def test_error_and_type_field_semantics_and_wrong_types(self):
        accepted = ({"structured_output": {"a": 1}, "is_error": False},
                    {"structured_output": {"a": 1}, "error": ""},
                    {"structured_output": {"a": 1}, "error": None},
                    {"structured_output": {"a": 1}, "type": "result"})
        for case in accepted:
            with self.subTest(case=case):
                self.assertEqual(json.loads(m.extract_model_response(encode(case))), {"a": 1})
        model_error = ({"structured_output": {"a": 1}, "is_error": True},
                       {"structured_output": {"a": 1}, "error": "boom"},
                       {"structured_output": {"a": 1}, "error": True},
                       {"structured_output": {"a": 1}, "type": "error"})
        for case in model_error:
            with self.subTest(case=case), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(encode(case))
            self.assertEqual(caught.exception.code, "RESPONSE_MODEL_ERROR")
        field_type = ({"structured_output": {"a": 1}, "is_error": "no"},
                      {"structured_output": {"a": 1}, "error": {"code": 1}},
                      {"structured_output": {"a": 1}, "type": 7})
        for case in field_type:
            with self.subTest(case=case), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(encode(case))
            self.assertEqual(caught.exception.code, "RESPONSE_FIELD_TYPE")

    def test_type_field_requires_exact_result_string(self):
        for kind in ("assistant", "result ", " result", "RESULT", "Error", ""):
            case = {"structured_output": {"a": 1}, "type": kind}
            with self.subTest(kind=kind), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(encode(case))
            self.assertEqual(caught.exception.code, "RESPONSE_UNSUPPORTED_TYPE")
        for kind in (7, None, True, [], {"result": 1}):
            case = {"structured_output": {"a": 1}, "type": kind}
            with self.subTest(kind=repr(kind)), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(encode(case))
            self.assertEqual(caught.exception.code, "RESPONSE_FIELD_TYPE")
        self.assertEqual(json.loads(m.extract_model_response(
            encode({"structured_output": {"a": 1}, "type": "result"}))), {"a": 1})

    def test_mismatched_brackets_reject_before_json_loads(self):
        for raw in (b"{]", b"[}", b'{"a":[}', b'{"a":1]', b'[{"a":1]}',
                    b'{"structured_output":[}]'):
            with self.subTest(raw=raw), patch.object(m.json, "loads") as loads:
                with self.assertRaises(m.ResponseExtractionError) as caught:
                    m.extract_model_response(raw)
                loads.assert_not_called()
            self.assertEqual(caught.exception.code, "RESPONSE_STRUCTURE")
        with self.assertRaises(m.ResponseExtractionError) as caught:
            m.extract_model_response(b"{,}")
        self.assertEqual(caught.exception.code, "RESPONSE_JSON")

    def test_result_scan_precedes_inner_parser_and_handles_escapes(self):
        original = m.json.loads
        for inner in ('{]', '[' * 4 + ']' * 4,
                      '{"files":[{},{},{},{},{}]}'):
            raw = encode({"result": inner})
            with self.subTest(inner=inner), patch.object(m.json, "loads", wraps=original) as loads:
                with self.assertRaises(m.ResponseExtractionError) as caught:
                    m.extract_model_response(raw)
                self.assertEqual(caught.exception.code, "RESPONSE_STRUCTURE")
                self.assertEqual(loads.call_count, 1)  # outer envelope only
        value = {"text": 'brackets } ] [ {, quote " and backslash \\'}
        self.assertEqual(json.loads(m.extract_model_response(
            encode({"result": encode(value).decode()}))), value)

    def test_outer_bounds_precede_parser(self):
        for raw in (b'[' * 5 + b']' * 5, b'{"a":[{},{},{},{},{},{}]}'):
            with self.subTest(raw=raw), patch.object(m.json, "loads") as loads:
                with self.assertRaises(m.ResponseExtractionError) as caught:
                    m.extract_model_response(raw)
                self.assertEqual(caught.exception.code, "RESPONSE_STRUCTURE")
                loads.assert_not_called()

    def test_numeric_token_boundaries(self):
        for token in (b'9' * 20, b'-' + b'9' * 19, b'0.' + b'1' * 30):
            self.assertIsInstance(json.loads(m.extract_model_response(
                b'{"n":' + token + b'}'))['n'], (int, float))
        for token in (b'9' * 21, b'-' + b'9' * 20, b'0.' + b'1' * 31):
            with self.subTest(token=token), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(b'{"n":' + token + b'}')
            self.assertEqual(caught.exception.code, "RESPONSE_JSON")

    def test_canonical_output_bound_is_independent_of_raw_bound(self):
        prefix = b'{"n":1e-4,"padding":"'
        suffix = b'"}'
        raw = prefix + b'x' * (m.MAX_RESPONSE_BYTES - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(raw), m.MAX_RESPONSE_BYTES)
        with self.assertRaises(m.ResponseExtractionError) as caught:
            m.extract_model_response(raw)  # 1e-4 canonicalizes to the longer 0.0001
        self.assertEqual(caught.exception.code, "RESPONSE_OUTPUT_BOUNDS")

    def test_candidate_type_errors(self):
        cases = ((encode({"structured_output": []}), "RESPONSE_STRUCTURED_OUTPUT_INVALID"),
                 (encode({"structured_output": "x"}), "RESPONSE_STRUCTURED_OUTPUT_INVALID"),
                 (encode({"result": 5}), "RESPONSE_RESULT_INVALID"),
                 (encode({"result": "[]"}), "RESPONSE_RESULT_INVALID"),
                 (encode({"result": "null"}), "RESPONSE_RESULT_INVALID"))
        for raw, code in cases:
            with self.subTest(raw=raw), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(raw)
            self.assertEqual(caught.exception.code, code)

    def test_nonfinite_and_overlong_numbers_reject(self):
        cases = (b'{"structured_output":{"a":NaN}}',
                 b'{"structured_output":{"a":Infinity}}',
                 b'{"structured_output":{"a":-Infinity}}',
                 b'{"structured_output":{"a":1e999}}',
                 b'{"structured_output":{"a":' + b'9' * 40 + b'}}')
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(raw)
            self.assertEqual(caught.exception.code, "RESPONSE_JSON")

    def test_outer_structural_limits(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            self.assertTrue(m.extract_model_response(wrapped(proposal(session))))
        admitted = b'{"structured_output":{"a":{"b":{}}}}'
        self.assertEqual(json.loads(m.extract_model_response(admitted)), {"a": {"b": {}}})
        cases = (b'{"structured_output":{"a":{"b":{"c":{}}}}}',
                 b'{"structured_output":{"files":[{},{},{},{}],"x":{}}}',
                 b'{"structured_output":{"a":1}',
                 b'{"structured_output":"open}',
                 b'[' * 20 + b']' * 20)
        for raw in cases:
            with self.subTest(raw=raw[:32]), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(raw)
            self.assertEqual(caught.exception.code, "RESPONSE_STRUCTURE")

    def test_result_string_structural_limits(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            value = proposal(session)
            raw = encode({"result": encode(value).decode()})
            self.assertEqual(json.loads(m.extract_model_response(raw)), value)
        inner = (json.dumps({"a": {"b": {"c": {"d": 1}}}}),
                 json.dumps({"files": [{}, {}, {}, {}, {}]}),
                 "[" * 8 + "]" * 8)
        for text in inner:
            with self.subTest(inner=text[:24]), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(encode({"result": text}))
            self.assertEqual(caught.exception.code, "RESPONSE_STRUCTURE")

    def test_exact_raw_and_output_bounds(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            value = proposal(session)
            value["files"][0]["text"] = ""
            pad = m.MAX_RESPONSE_BYTES - len(encode(value))
            value["files"][0]["text"] = "x" * pad
            raw = encode(value)
            self.assertEqual(len(raw), m.MAX_RESPONSE_BYTES)
            out = m.extract_model_response(raw)
            self.assertTrue(0 < len(out) <= m.MAX_RESPONSE_BYTES)
            self.assertLess(len(out), len(raw))
            self.assertEqual(json.loads(out)["files"][0]["text"], "x" * pad)
            for bad in (b"", b"x" * (m.MAX_RESPONSE_BYTES + 1), "{}"):
                with self.subTest(kind=type(bad).__name__), self.assertRaises(m.ResponseExtractionError) as caught:
                    m.extract_model_response(bad)
                self.assertEqual(caught.exception.code, "RESPONSE_BOUNDS")

    def test_fixed_messages_and_suppressed_displayed_chains(self):
        samples = (b"", b"\xff", b"[1,2]", b'{"a":1,"a":2}', b'{"is_error":"no"}',
                   b'{"structured_output":[]}', b'{"structured_output":{}} {}')
        for raw in samples:
            with self.subTest(raw=raw), self.assertRaises(m.ResponseExtractionError) as caught:
                m.extract_model_response(raw)
            error = caught.exception
            self.assertIsInstance(error, ValueError)
            self.assertIn(error.code, FIXED_CODES)
            self.assertEqual(str(error), error.code)
            self.assertNotIn(repr(raw), str(error))
            self.assertIsNone(error.__cause__)
            self.assertTrue(error.__suppress_context__)

    def test_escaped_unicode_errors_are_fixed(self):
        lone = b'{"structured_output":{"a":"\\ud800"}}'
        with self.assertRaises(m.ResponseExtractionError) as caught:
            m.extract_model_response(lone)
        self.assertEqual(caught.exception.code, "RESPONSE_SERIALIZATION")
        self.assertIsNone(caught.exception.__cause__)
        pair = b'{"structured_output":{"a":"\\ud83d\\ude00"}}'
        self.assertEqual(json.loads(m.extract_model_response(pair)), {"a": "\U0001F600"})

    def test_module_depends_only_on_standard_library(self):
        for forbidden in ("os", "subprocess", "socket", "website", "worker", "privilege"):
            self.assertNotIn(forbidden, vars(m))
        self.assertIn("json", vars(m))
        self.assertIn("math", vars(m))

    def test_unchanged_website_validator_accepts_extracted_proposal(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            request, base = w.proposal_request(session, "code")
            value = envelope(session, "code", proposed_files(), base.sha256)
            extracted = m.extract_model_response(wrapped(value))
            actions, files = w.validate_proposal(extracted, session, "code", base)
            self.assertEqual([path for path, _ in actions], list(w.WEBSITE_FILES))
            self.assertEqual(dict(files), {n: t.encode() for n, t in proposed_files().items()})
            self.assertEqual(json.loads(extracted)["base_snapshot"], base.sha256)

    def test_binding_invalid_extracted_proposal_rejects_without_writes(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            request, base = w.proposal_request(session, "code")
            value = envelope(session, "code", proposed_files(), base.sha256)
            value["contract"] = "f" * 64
            extracted = m.extract_model_response(wrapped(value))
            self.assertEqual(json.loads(extracted)["contract"], "f" * 64)
            with patch.object(FileTools, "call") as calls:
                with self.assertRaises(w.ProposalError) as caught:
                    w.SyntheticProposalAdapter(extracted, extracted).apply(session, "code")
                calls.assert_not_called()
            self.assertEqual(caught.exception.evidence["stage"], "VALIDATION")
            self.assertFalse((session.root / "export").exists())

    def test_finite_float_passes_extraction_but_not_proposal_validation(self):
        with tempfile.TemporaryDirectory() as parent:
            session = self.session(parent)
            request, base = w.proposal_request(session, "code")
            value = envelope(session, "code", proposed_files(), base.sha256)
            value["version"] = 1.5
            extracted = m.extract_model_response(wrapped(value))
            self.assertEqual(json.loads(extracted)["version"], 1.5)
            with self.assertRaises(w.WebsiteError):
                w.validate_proposal(extracted, session, "code", base)


if __name__ == "__main__":
    unittest.main()
