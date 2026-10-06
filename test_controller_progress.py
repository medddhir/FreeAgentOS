"""Development observer tests; production runner policy is untouched."""
import io
import contextlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from devtools.controller_progress import progress as p

class ControllerProgressTests(unittest.TestCase):
    @contextlib.contextmanager
    def observing(self, recorder):
        names=('startTest','stopTest','addSuccess','addFailure','addError','addSkip',
               'addExpectedFailure','addUnexpectedSuccess','addSubTest')
        methods={name:getattr(unittest.TextTestResult,name) for name in names}
        subtest=unittest.TestCase.subTest
        try:
            p.instrument(recorder)
            yield
        finally:
            for name,value in methods.items():setattr(unittest.TextTestResult,name,value)
            unittest.TestCase.subTest=subtest

    def test_actual_unittest_results_and_subcases(self):
        methods={name:getattr(unittest.TextTestResult,name) for name in ('startTest','stopTest','addSuccess','addFailure','addError','addSkip','addExpectedFailure','addUnexpectedSuccess','addSubTest')}
        subtest=unittest.TestCase.subTest
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);recorder=p.Progress(root)
            class Cases(unittest.TestCase):
                def test_good(self):
                    with self.subTest(case='fixed_case'):self.assertTrue(True)
                def test_bad(self):self.fail('must remain failure')
                def test_error(self):raise ValueError('must remain error')
                @unittest.skip('fixed skip')
                def test_skip(self):pass
            try:
                p.instrument(recorder)
                result=unittest.TextTestRunner(stream=io.StringIO()).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
            finally:
                for name,value in methods.items():setattr(unittest.TextTestResult,name,value)
                unittest.TestCase.subTest=subtest
                recorder.finish()
            self.assertEqual((result.testsRun,len(result.failures),len(result.errors),len(result.skipped)),(4,1,1,1))
            rows=[json.loads(line) for line in (root/'progress.jsonl').read_text().splitlines()]
            self.assertEqual({x['outcome'] for x in rows if x['event']=='TEST_END'},{'PASS','FAIL','ERROR','SKIP'})
            self.assertTrue(any(x['event']=='SUBCASE_START' and x['label']=='fixed_case' for x in rows))
            details=[x for x in rows if x['event']=='FAILURE_DETAIL']
            self.assertEqual({x['detail']['message'] for x in details},
                             {'must remain failure','must remain error'})
            self.assertEqual({x['detail']['exception_type'] for x in details},
                             {'AssertionError','ValueError'})
            self.assertTrue(all(x['detail']['test_id'].endswith(('test_bad','test_error')) for x in details))
    def test_record_exhaustion_keeps_terminal_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            with patch.object(p,'MAX_RECORDS',8),patch.object(p,'RESERVE_RECORDS',4):
                for _ in range(12):r.event('TEST_START','fixed')
                detail=p.failure_detail('fixed',(AssertionError,AssertionError('bounded'),None))
                self.assertFalse(r.event('FAILURE_DETAIL','fixed','FAIL',detail=detail))
                r.event('TEST_END','fixed','ERROR',terminal=True)
                r.finish()
            rows=[json.loads(line) for line in (root/'progress.jsonl').read_text().splitlines()]
            self.assertEqual(len(rows),6)
            self.assertEqual(rows[-2]['outcome'],'ERROR')
            self.assertEqual(json.loads((root/'progress-result.json').read_text())['diagnostic_error'],'PROGRESS_BOUND')
    def test_interruption_remains_unmatched_not_a_test_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            r.event('TEST_START','unfinished');p.os.close(r.fd)
            rows=[json.loads(line) for line in (root/'progress.jsonl').read_text().splitlines()]
            self.assertEqual([x['event'] for x in rows],['TEST_START'])
            self.assertIsNone(rows[0]['outcome'])
    def test_byte_bound_write_failure_and_private_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            with patch.object(p,'RESERVE_BYTES',0),patch.object(p,'MAX_BYTES',256):
                for _ in range(10):r.event('TEST_START','fixed')
            self.assertLessEqual(r.bytes,256)
            self.assertEqual(r.error,'PROGRESS_BOUND')
            r.finish()
            self.assertEqual((root/'progress.jsonl').stat().st_mode&0o777,0o600)

    def test_failure_details_precede_original_result_callbacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root);seen=[]
            original_failure=unittest.TextTestResult.addFailure
            original_error=unittest.TextTestResult.addError
            def check(fn, outcome):
                def callback(result,test,error):
                    rows=[json.loads(n) for n in (root/'progress.jsonl').read_text().splitlines()]
                    row=[x for x in rows if x['event']=='FAILURE_DETAIL'][-1]
                    self.assertEqual(row['outcome'],outcome)
                    self.assertEqual(row['detail']['test_id'],test.id())
                    self.assertIn('test_',row['detail']['traceback'])
                    self.assertNotIn('/root/',row['detail']['traceback'])
                    seen.append(outcome)
                    return fn(result,test,error)
                return callback
            class Cases(unittest.TestCase):
                def test_bad(self):
                    private_local='LOCAL_MUST_NOT_BE_RECORDED'
                    self.fail('fixed assertion')
                def test_error(self):raise ValueError('fixed error')
            with patch.object(unittest.TextTestResult,'addFailure',check(original_failure,'FAIL')), \
                    patch.object(unittest.TextTestResult,'addError',check(original_error,'ERROR')):
                with self.observing(r):
                    result=unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
            r.finish()
            self.assertEqual(seen,['FAIL','ERROR'])
            self.assertEqual((result.testsRun,len(result.failures),len(result.errors)),(2,1,1))
            self.assertIn('fixed assertion',result.failures[0][1])
            self.assertIn('fixed error',result.errors[0][1])
            self.assertNotIn('LOCAL_MUST_NOT_BE_RECORDED',(root/'progress.jsonl').read_text())

    def test_oversized_unicode_details_fit_records_and_keep_terminal_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            class Cases(unittest.TestCase):
                def test_bad(self):self.fail('\u96ea'*10000+'\ud800')
            with self.observing(r):
                result=unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
            r.finish()
            lines=(root/'progress.jsonl').read_bytes().splitlines(keepends=True)
            self.assertTrue(all(len(line)<=p.MAX_RECORD_BYTES for line in lines))
            rows=[json.loads(line) for line in lines]
            detail=next(x['detail'] for x in rows if x['event']=='FAILURE_DETAIL')
            self.assertTrue(detail['truncated']);self.assertFalse(detail['message_omitted'])
            self.assertTrue(detail['message'])
            self.assertEqual(rows[-2]['event'],'TEST_END');self.assertEqual(rows[-1]['event'],'PROCESS_END')
            self.assertIsNone(r.error)
            self.assertEqual(len(result.failures),1)
            self.assertIn('\u96ea'*10000,result.failures[0][1])

    def test_non_string_arguments_are_not_formatted_or_dumped(self):
        class Opaque:
            def __str__(self):raise AssertionError('must not call str')
            def __repr__(self):raise AssertionError('must not call repr')
        detail=p.failure_detail('fixed',(ValueError,ValueError(Opaque()),None))
        self.assertEqual(detail['exception_type'],'ValueError')
        self.assertEqual(detail['message'],'');self.assertTrue(detail['message_omitted'])

    def test_subcase_failure_is_captured_with_parent_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            class Cases(unittest.TestCase):
                def test_bad(self):
                    with self.subTest(case='fixed_subcase'):self.assertEqual(1,2)
            with self.observing(r):
                result=unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
            r.finish()
            rows=[json.loads(n) for n in (root/'progress.jsonl').read_text().splitlines()]
            row=next(x for x in rows if x['event']=='FAILURE_DETAIL')
            self.assertEqual(row['outcome'],'FAIL');self.assertEqual(row['detail']['message'],'1 != 2')
            self.assertTrue(row['detail']['test_id'].endswith('Cases.test_bad'))
            self.assertEqual(len(result.failures),1);self.assertEqual(result.testsRun,1)

    def test_diagnostic_write_failure_preserves_unittest_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            class Cases(unittest.TestCase):
                def test_bad(self):self.fail('original failure')
                def test_error(self):raise ValueError('original error')
            original_write=p.os.write
            fixture_fd=r.fd
            def fail_fixture_write(fd, data):
                if fd==fixture_fd:
                    raise OSError('synthetic write failure')
                return original_write(fd,data)
            with patch.object(p.os,'write',side_effect=fail_fixture_write):
                with self.observing(r):
                    result=unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
            r.finish()
            self.assertEqual((result.testsRun,len(result.failures),len(result.errors)),(2,1,1))
            self.assertIn('original failure',result.failures[0][1]);self.assertIn('original error',result.errors[0][1])
            self.assertEqual(r.error,'PROGRESS_WRITE_FAILED')
            self.assertEqual(json.loads((root/'progress-result.json').read_text())['diagnostic_error'],r.error)

    def test_fixture_write_failure_keeps_active_outer_observer_healthy(self):
        original_write=p.os.write
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);outer=p.Progress(root)
            class LaterCases(unittest.TestCase):
                def test_bad(self):self.fail('later failure')
                def test_error(self):raise ValueError('later error')
                def test_good(self):pass
            try:
                with self.observing(outer):
                    fixture_result=unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.TestSuite([ControllerProgressTests(
                            'test_diagnostic_write_failure_preserves_unittest_results')]))
                    self.assertIs(p.os.write,original_write)
                    later_result=unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.defaultTestLoader.loadTestsFromTestCase(LaterCases))
            finally:
                outer.finish()
            self.assertEqual(fixture_result.testsRun,1)
            self.assertTrue(fixture_result.wasSuccessful())
            self.assertEqual((later_result.testsRun,len(later_result.failures),
                              len(later_result.errors)),(3,1,1))
            self.assertIsNone(outer.error)
            rows=[json.loads(line) for line in (root/'progress.jsonl').read_text().splitlines()]
            details=[row for row in rows if row['event']=='FAILURE_DETAIL']
            self.assertEqual({row['detail']['message'] for row in details},
                             {'original failure','original error','later failure','later error'})
            self.assertEqual({row['outcome'] for row in details},{'FAIL','ERROR'})
            starts=[row['label'] for row in rows if row['event']=='TEST_START']
            ends=[row['label'] for row in rows if row['event']=='TEST_END']
            self.assertCountEqual(starts,ends)
            self.assertEqual(len(ends),6)
            self.assertEqual(rows[-1]['event'],'PROCESS_END')
            self.assertIsNone(json.loads((root/'progress-result.json').read_text())['diagnostic_error'])

    def test_unexpected_diagnostic_exception_does_not_replace_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            class Cases(unittest.TestCase):
                def test_bad(self):self.fail('original assertion')
            for target in ('event','detail'):
                with self.subTest(case=target):
                    mocked=patch.object(r,'event',side_effect=RuntimeError('diagnostic')) if target=='event' else \
                        patch.object(p,'failure_detail',side_effect=RuntimeError('diagnostic'))
                    with mocked,self.observing(r):
                        result=unittest.TextTestRunner(stream=io.StringIO()).run(
                            unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
                    self.assertEqual(result.testsRun,1);self.assertEqual(len(result.failures),1)
                    self.assertIn('original assertion',result.failures[0][1])
            r.finish();self.assertEqual(r.error,'PROGRESS_DIAGNOSTIC_FAILED')

class ObserverShutdownTimingTests(unittest.TestCase):
    def test_completion_follows_result_publication_and_fd_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            r.finish()
            import os
            with self.assertRaises(OSError):os.fstat(r.fd)
            self.assertTrue((root/'progress-result.json').is_file())
            end=json.loads((root/'progress.jsonl').read_text().splitlines()[-1])
            completion=json.loads((root/'observer-shutdown.json').read_text())
            self.assertEqual(completion['event'],'OBSERVER_SHUTDOWN_COMPLETE')
            self.assertGreaterEqual(completion['monotonic_ns'],end['monotonic_ns'])
            self.assertEqual((root/'observer-shutdown.json').stat().st_mode&0o777,0o600)

    def test_optional_completion_publication_failure_is_contained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            (root/'observer-shutdown.json').write_text('exclusive occupied')
            r.finish()
            self.assertEqual((root/'observer-shutdown.json').read_text(),'exclusive occupied')
            self.assertIsNone(json.loads((root/'progress-result.json').read_text())['diagnostic_error'])
