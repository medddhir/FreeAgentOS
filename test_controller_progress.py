"""Development observer tests; production runner policy is untouched."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from devtools.controller_progress import progress as p

class ControllerProgressTests(unittest.TestCase):
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
            self.assertNotIn('must remain', (root/'progress.jsonl').read_text())
    def test_record_exhaustion_keeps_terminal_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);r=p.Progress(root)
            with patch.object(p,'MAX_RECORDS',8),patch.object(p,'RESERVE_RECORDS',4):
                for _ in range(12):r.event('TEST_START','fixed')
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
