"""Synthetic response bytes only; no model, target execution or live qualification."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
import graph
import website as w
from roles.file_tools import FileTools
from test_website import brief


def proposed_files(revised=False):
    b = brief()
    heading = b.revision_heading if revised else b.heading
    button = b.revision_button if revised else b.button
    return {
        'index.html': ('<!doctype html><html><head><title>Local Studio</title>'
                       '<link rel="stylesheet" href="styles.css"></head><body><article>'
                       '<h1>' + heading + '</h1><p>A compact studio for local work.</p>'
                       '<button>' + button + '</button></article>'
                       '<script src="app.js"></script></body></html>'),
        'styles.css': 'article { max-width: 52rem; margin: auto; }' +
                      (' button { border-radius: 1rem; }' if revised else ''),
        'app.js': 'document.querySelector("button").dataset.ready = "yes";',
        'README.md': 'Synthetic website proposal. Structural checks only.\n',
    }


def snapshot_hash(session, files):
    return w.digest({'run': session.run, 'profile': w.WEBSITE_PROFILE,
                     'contract': session.contract,
                     'files': [(n, w._sha(files[n].encode())) for n in w.WEBSITE_FILES]})


def envelope(session, phase, files, base):
    return {'version': 1, 'run': session.run, 'profile': w.WEBSITE_PROFILE,
            'phase': phase, 'contract': session.contract, 'base_snapshot': base,
            'files': [{'path': n, 'text': t} for n, t in files.items()]}


def encode(value):
    return json.dumps(value, ensure_ascii=False).encode()


def adapter(session):
    scaffold = {n: '' for n in w.WEBSITE_FILES}
    scaffold['README.md'] = 'Static website source. Local preview is not qualified yet.\n'
    code = proposed_files()
    revision = {n: t for n, t in proposed_files(True).items() if code[n] != t}
    return w.SyntheticProposalAdapter(
        encode(envelope(session, 'code', code, snapshot_hash(session, scaffold))),
        encode(envelope(session, 'revision', revision, snapshot_hash(session, code))))


class WebsiteProposalTests(unittest.TestCase):
    def test_variable_graph_revision_checks_and_complete_export(self):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation='synthetic')
            responses = adapter(session)
            result = graph.build_website_graph(responses).invoke({'session': session})
            self.assertEqual(result['status'], 'SYNTHETIC_PREPARATION_COMPLETE')
            self.assertTrue(result['synthetic'])
            self.assertEqual(result['model_calls'], 'NONE')
            self.assertFalse(result['live_qualified'])
            self.assertFalse(result['checks']['recorded'])
            self.assertEqual(result['checks']['structural'], 'PASS')
            self.assertEqual(result['checks']['functional'], 'UNPROVEN')
            self.assertEqual(result['checks']['browser'], 'UNPROVEN')
            self.assertEqual(result['preview']['execution'], 'DISABLED')
            self.assertNotEqual(result['before'], result['after'])
            self.assertEqual(result['revision_evidence']['base_snapshot'], result['before'].sha256)
            self.assertEqual(result['code_evidence']['tool_calls'], 4)
            self.assertEqual(result['revision_evidence']['tool_calls'], 2)
            self.assertEqual(result['revision_evidence']['snapshot_sha256'], result['after'].sha256)
            output = Path(result['export']['directory'])
            self.assertEqual(output, session.root / 'export')
            self.assertEqual(set(p.name for p in output.iterdir()), set(w.WEBSITE_FILES) | {'export.json'})
            for name, text in proposed_files(True).items():
                self.assertEqual((output / name).read_bytes(), text.encode())
                self.assertEqual(dict(result['after'].files)[name], text.encode())
            receipt = json.loads((output / 'export.json').read_bytes())
            self.assertEqual(receipt, result['export']['manifest'])
            self.assertTrue(receipt['synthetic'])
            self.assertFalse(receipt['recorded'])
            self.assertEqual(receipt['snapshot_sha256'], result['after'].sha256)
            forged = dict(result['checks'], structural='PASS', browser='PASS')
            with self.assertRaisesRegex(w.WebsiteError, 'CHECK_EVIDENCE_MISMATCH'):
                session.export(result['after'], forged)
            with self.assertRaises(FileExistsError):
                session.export(result['after'], result['checks'])
            with self.assertRaisesRegex(w.WebsiteError, 'EXECUTION_QUALIFICATION_UNPROVEN'):
                w.launch_live('coding', synthetic=True)

    def rejected(self, transform):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation='synthetic')
            session.scaffold()
            responses = adapter(session)
            before = session.snapshot()
            value = json.loads(responses.code)
            raw = transform(value)
            bad = w.SyntheticProposalAdapter(raw, responses.revision)
            with patch.object(FileTools, 'call', wraps=FileTools.call) as calls:
                with self.assertRaises(w.ProposalError) as caught:
                    bad.apply(session, 'code')
                self.assertEqual(calls.call_count, 0)
            self.assertEqual(caught.exception.evidence['stage'], 'VALIDATION')
            self.assertEqual(caught.exception.evidence['artifact_state'], 'RETAINED')
            self.assertFalse(caught.exception.evidence['cleanup_attempted'])
            self.assertEqual(session.snapshot(), before)
            self.assertFalse((session.root / 'export').exists())
            with self.assertRaises(w.ProposalError):
                responses.apply(session, 'code')  # failed run cannot be retried

    def test_malformed_schema_types_encodings_and_bounds_reject_before_writes(self):
        invalid = [b'{', b'[]', b'null', b'{} {}', b'\xff', b'\xef\xbb\xbf{}',
                   b'[' * 50 + b']' * 50, b'{"version":NaN}',
                   b'{"version":1.0}', b'{"version":' + b'9'*100 + b'}']
        for raw in invalid:
            with self.subTest(kind='syntax', raw_length=len(raw)):
                self.rejected(lambda v, raw=raw: raw)
        for key, value in [('version', True), ('files', {}), ('run', 1), ('phase', 'shell'),
                           ('profile', 'ordinary'), ('contract', 'foreign'),
                           ('base_snapshot', '0'*64), ('success', True), ('run', 'foreign'),
                           ('tools', ['shell']), ('live_qualified', True),
                           ('commands', ['echo no']), ('export', '/tmp/out'),
                           ('credentials', 'not-an-authority'), ('limits', {})]:
            def change(v, key=key, value=value):
                v[key] = value
                return encode(v)
            with self.subTest(field=key):
                self.rejected(change)
        self.rejected(lambda v: encode(v).replace(b'"version": 1', b'"version": 1, "version": 1'))
        self.rejected(lambda v: encode(v).replace(b'"path": "index.html"',
                                                 b'"path": "index.html", "path": "index.html"'))
        self.rejected(lambda v: encode(v).replace(b'Local Studio', b'\\ud800', 1))
        with self.assertRaisesRegex(w.WebsiteError, 'PROPOSAL_RESPONSE_BOUNDS'):
            w.SyntheticProposalAdapter(b' ' * (w.MAX_RESPONSE_BYTES + 1), b'{}')
        with self.assertRaisesRegex(w.WebsiteError, 'PROPOSAL_RESPONSE_BOUNDS'):
            w.SyntheticProposalAdapter('{}', b'{}')

    def test_paths_operations_content_and_structural_rejection_are_whole_batch(self):
        for path in ('../outside', '/tmp/out', './index.html', 'checks.json', 'test_hidden.py',
                     'shape.md', 'assets/a.css', 'other.js'):
            def change(v, path=path):
                v['files'][-1]['path'] = path  # valid earlier files cannot be written
                return encode(v)
            with self.subTest(path=path):
                self.rejected(change)
        for change in (
            lambda v: v['files'].append(copy.deepcopy(v['files'][0])),
            lambda v: v['files'].pop(),
            lambda v: v['files'][-1].update(path='index.html'),
            lambda v: v['files'][0].update(operation='delete'),
            lambda v: v['files'][0].update(text=42),
            lambda v: v['files'][-1].update(text='x' * (w.MAX_FILE_BYTES + 1)),
            lambda v: v['files'][-1].update(text='Secret garden'),
            lambda v: v['files'][0].update(text='<html></html>'),
        ):
            def transformed(v, change=change):
                change(v)
                return encode(v)
            self.rejected(transformed)

    def test_stale_revision_binding_and_no_change_reject(self):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation='synthetic')
            session.scaffold()
            responses = adapter(session)
            responses.apply(session, 'code')
            before = session.snapshot()
            value = json.loads(responses.revision)
            value['base_snapshot'] = json.loads(responses.code)['base_snapshot']
            bad = w.SyntheticProposalAdapter(responses.code, encode(value))
            with patch.object(FileTools, 'call') as calls, self.assertRaises(w.ProposalError):
                bad.apply(session, 'revision')
            calls.assert_not_called()
            self.assertEqual(before, session.snapshot())
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation='synthetic'); session.scaffold()
            responses = adapter(session); responses.apply(session, 'code')
            request, base = w.proposal_request(session, 'revision')
            same = envelope(session, 'revision', {'styles.css': proposed_files()['styles.css']}, base.sha256)
            with self.assertRaises(w.WebsiteError):
                w.validate_proposal(encode(same), session, 'revision', base)

    def test_application_failure_retains_partial_writes_and_blocks_run(self):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation='synthetic')
            responses = adapter(session)
            original = FileTools.call
            def fail_second(broker, name, arguments):
                if arguments['path'] == 'styles.css':
                    raise OSError('uncontrolled private diagnostic')
                return original(broker, name, arguments)
            with patch.object(FileTools, 'call', fail_second), self.assertRaises(w.ProposalError) as caught:
                graph.build_website_graph(responses).invoke({'session': session})
            self.assertEqual(str(caught.exception), 'PROPOSAL_APPLICATION_FAILED')
            self.assertNotIn('private', repr(caught.exception.evidence))
            self.assertEqual(caught.exception.evidence['artifact_state'], 'RETAINED')
            self.assertFalse(caught.exception.evidence['cleanup_attempted'])
            self.assertEqual((session.workspace / 'index.html').read_text(), proposed_files()['index.html'])
            self.assertEqual((session.workspace / 'styles.css').read_bytes(), b'')
            self.assertFalse((session.root / 'export').exists())
            with self.assertRaises(w.ProposalError):
                responses.apply(session, 'revision')

    def test_partial_revision_cannot_export_even_when_structural_checks_pass(self):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation='synthetic'); session.scaffold()
            responses = adapter(session); responses.apply(session, 'code')
            original = FileTools.call
            def fail_styles(broker, name, arguments):
                if arguments['path'] == 'styles.css':
                    raise OSError('failed write')
                return original(broker, name, arguments)
            with patch.object(FileTools, 'call', fail_styles), self.assertRaises(w.ProposalError):
                responses.apply(session, 'revision')
            snapshot = session.snapshot()
            checks = session.checks(snapshot, True)  # old CSS still meets structural subset
            self.assertEqual(checks['structural'], 'PASS')
            with self.assertRaisesRegex(w.WebsiteError, 'PROPOSAL_NOT_COMPLETE'):
                session.export(snapshot, checks)
            self.assertFalse((session.root / 'export').exists())

    def test_failed_identity_observation_is_unproven_not_absent(self):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation='synthetic'); session.scaffold()
            responses = adapter(session)
            with patch.object(session, 'assert_root', side_effect=w.WebsiteError('ROOT_CHANGED')):
                with self.assertRaises(w.ProposalError) as caught:
                    responses.apply(session, 'code')
            self.assertEqual(caught.exception.evidence['artifact_state'], 'UNPROVEN')
            self.assertTrue(session.root.exists())

    def test_actual_snapshot_and_policy_remain_required_and_request_bounded(self):
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent, preparation='synthetic'); session.scaffold()
            request, base = w.proposal_request(session, 'code')
            value = envelope(session, 'code', proposed_files(), base.sha256)
            FileTools(w.website_policy(session.workspace)).call('write_file', {'path': 'README.md', 'text': 'Changed.'})
            with self.assertRaisesRegex(w.WebsiteError, 'SNAPSHOT_CHANGED'):
                w.validate_proposal(encode(value), session, 'code', base)
            with patch.object(w, 'guidance', return_value='x' * w.MAX_REQUEST_BYTES):
                with self.assertRaisesRegex(w.WebsiteError, 'PROPOSAL_REQUEST_BOUNDS'):
                    w.proposal_request(session, 'code')
        with tempfile.TemporaryDirectory() as parent:
            session = w.Session(brief(), parent)  # recorded is still the default
            with self.assertRaisesRegex(w.WebsiteError, 'PREPARATION_KIND_MISMATCH'):
                graph.build_website_graph(adapter(session)).invoke({'session': session})
            self.assertEqual(list(session.workspace.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
