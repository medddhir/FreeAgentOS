"""Non-privileged development-profiler checks; never run the export group here."""
import contextlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch, Mock
from devtools import export_timing as d


class ExportTimingTests(unittest.TestCase):
    def recorder(self):
        file = tempfile.TemporaryFile()
        self.addCleanup(file.close)
        return d.Recorder(file.fileno()), file

    def test_results_exceptions_and_cleanup_are_preserved(self):
        recorder, file = self.recorder()
        marker = object()
        self.assertIs(recorder.wrap(lambda: marker, 'return_value')(), marker)
        error = RuntimeError('not logged')
        def fail():
            raise error
        with self.assertRaises(RuntimeError) as caught:
            recorder.wrap(fail, 'exception')()
        self.assertIs(caught.exception, error)
        actions = []
        @contextlib.contextmanager
        def fixture():
            actions.append('enter')
            try:
                yield marker
            finally:
                actions.append('exit')
        with self.assertRaises(RuntimeError):
            with recorder.fixture(fixture, 'fixture')() as value:
                self.assertIs(value, marker)
                raise error
        self.assertEqual(actions, ['enter', 'exit'])
        file.seek(0)
        records = [json.loads(line) for line in file]
        self.assertEqual(sum(r['event']=='START' for r in records), sum(r['event']=='END' for r in records))
        self.assertNotIn(b'not logged', b''.join(json.dumps(r).encode() for r in records))

    def test_bounded_failure_does_not_skip_original_calls_or_finalizers(self):
        for bound in ('MAX_RECORDS','MAX_BYTES','MAX_RECORD_BYTES'):
            recorder, file = self.recorder()
            calls = []
            with patch.object(d, bound, 0):
                value = recorder.wrap(lambda: calls.append('called') or 17, 'bounded')()
                recorder.flush()
            self.assertEqual(value, 17)
            self.assertEqual(calls, ['called'])
            self.assertEqual(recorder.error, 'SIDECAR_BOUND')
        recorder, file = self.recorder()
        with patch.object(d.os, 'write', side_effect=OSError('not logged')):
            self.assertEqual(recorder.wrap(lambda: 9, 'write_failure')(), 9)
            recorder.flush()
        self.assertEqual(recorder.error, 'SIDECAR_WRITE_FAILED')

    def test_fixture_suppression_teardown_failure_and_hash_freshness(self):
        recorder, file = self.recorder()
        @contextlib.contextmanager
        def suppress():
            try:
                yield 1
            except RuntimeError:
                pass
        with recorder.fixture(suppress, 'suppression')():
            raise RuntimeError()
        error = ValueError('teardown')
        @contextlib.contextmanager
        def teardown():
            yield
            raise error
        with self.assertRaises(ValueError) as caught:
            with recorder.fixture(teardown, 'teardown_failure')():
                pass
        self.assertIs(caught.exception, error)
        reads = []
        values = iter((b'first', b'changed'))
        def read():
            reads.append(1)
            return next(values)
        wrapped = recorder.aggregate(read, 'source_read')
        self.assertEqual(wrapped(), b'first')
        self.assertEqual(wrapped(), b'changed')
        self.assertEqual(len(reads), 2)  # timing never introduces a result cache
        with patch.object(d, 'MAX_AGG_KEYS', 0):
            limited, _ = self.recorder()
            self.assertEqual(limited.aggregate(lambda: 23, 'bound')(), 23)
            def fail():
                raise error
            with self.assertRaises(ValueError) as caught:
                limited.aggregate(fail, 'bound')()
            self.assertIs(caught.exception, error)
            self.assertEqual(limited.error, 'AGGREGATE_BOUND')

    def test_schema_short_write_and_process_identity(self):
        recorder, file = self.recorder()
        recorder.emit({'event':'START','unexpected':'field'})
        self.assertEqual(recorder.error, 'SIDECAR_SCHEMA')
        recorder, file = self.recorder()
        original = os.write
        def short(fd, raw):
            return original(fd, raw[:max(1,len(raw)//2)])
        with patch.object(d.os, 'write', side_effect=short):
            recorder.wrap(lambda: None, 'short_writes')()
            recorder.flush()
        self.assertIsNone(recorder.error)
        own = d.identity(os.getpid())
        self.assertEqual(own['pgid'], os.getpgrp())
        self.assertEqual(own['session'], os.getsid(0))
        self.assertGreater(own['start_ticks'], 0)

    def test_reserve_preserves_case_group_and_exception_terminals(self):
        recorder, file = self.recorder()
        error = RuntimeError('private')
        with patch.object(d, 'MAX_RECORDS', 12), patch.object(d, 'RESERVED_RECORDS', 8):
            with self.assertRaises(RuntimeError):
                with recorder.span('GROUP', 'group'):
                    with recorder.span('CASE', 'case'):
                        for _ in range(8):
                            with recorder.span('FIXTURE', 'rhs_example'):
                                pass
                        recorder.aggregate(lambda: 7, 'source_read')()
                        recorder.flush()
                        raise error
        file.seek(0)
        rows = [json.loads(line) for line in file]
        self.assertEqual(recorder.error, 'SIDECAR_BOUND')
        self.assertLessEqual(len(rows), 12)
        self.assertEqual([(x['kind'], x['outcome']) for x in rows
                          if x['event']=='END' and x['kind'] in ('CASE','GROUP')],
                         [('CASE','RAISE'),('GROUP','RAISE')])
        self.assertTrue(any(x['event']=='AGGREGATE' for x in rows))

    def test_repeated_phases_are_bounded_aggregates_and_fresh(self):
        recorder, file = self.recorder()
        for case in ('first','second'):
            recorder.case = case
            for _ in range(100):
                self.assertEqual(recorder.wrap(lambda: 5, 'analysis_explicit')(), 5)
            recorder.flush()
            self.assertEqual(recorder.totals, {})
        file.seek(0)
        rows = [json.loads(line) for line in file]
        self.assertEqual(len(rows), 2)
        self.assertEqual([x['calls'] for x in rows], [100,100])
        self.assertEqual([x['case'] for x in rows], ['first','second'])
        self.assertTrue(all(x['duration_ns']>=x['max_ns'] and x['cpu_ns']>=0 for x in rows))
        self.assertIsNone(recorder.error)

    def test_owned_cleanup_closes_pipe_after_wait_failure(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        process.wait.side_effect = OSError('wait failure')
        with patch.object(d.os, 'killpg') as kill:
            with self.assertRaises(OSError):
                with d.owned_process(process):
                    pass
        kill.assert_called_once_with(123, d.signal.SIGTERM)
        process.stdout.close.assert_called_once()
