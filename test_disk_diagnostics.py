"""Unprivileged diagnostic parsing and bounded runner-reporting regressions."""
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / 'orchestrator'))
from roles import sandbox


class DiskDiagnosticTests(unittest.TestCase):
    def test_progress_is_bounded_untrusted_and_no_follow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tmp').mkdir()
            path = root / 'tmp' / sandbox.DISK_DIAGNOSTIC_FILE
            record = {'phase': 'write', 'monotonic': 1.0, 'written_bytes': 10 * sandbox.MIB}
            path.write_text(json.dumps(record) + '\n')
            self.assertEqual(sandbox._disk_progress(root)['status'], 'CHILD_REPORTED')
            invalid = [json.dumps(record), 'invalid\n', json.dumps(record) + '\n' * 41,
                       'x' * (sandbox.DIAGNOSTIC_BYTES + 1),
                       json.dumps({**record, 'written_bytes': 361 * sandbox.MIB}) + '\n',
                       json.dumps({**record, 'monotonic': float('nan')}) + '\n',
                       json.dumps(record) + '\n' + json.dumps({**record, 'monotonic': 0}) + '\n']
            for text in invalid:
                with self.subTest(size=len(text)):
                    path.write_text(text)
                    self.assertEqual(sandbox._disk_progress(root)['status'], 'MISSING_OR_INVALID')
            path.unlink()
            path.symlink_to(root / 'outside')
            self.assertEqual(sandbox._disk_progress(root)['status'], 'MISSING_OR_INVALID')
            path.unlink()
            os.mkfifo(path)
            self.assertEqual(sandbox._disk_progress(root)['status'], 'MISSING_OR_INVALID')

    def test_owned_sample_deltas_and_unavailable_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'cpu.stat'
            def counters(value):
                path.write_text(''.join(f'{key} {value}\n' for key in sandbox.CPU_DIAGNOSTIC_KEYS))
            counters(1)
            before = sandbox._disk_sample(root, root)
            counters(4)
            after = sandbox._disk_sample(root, root)
            self.assertEqual(sandbox._cpu_delta(before, after),
                             dict.fromkeys(sandbox.CPU_DIAGNOSTIC_KEYS, 3))
            self.assertIsNone(sandbox._cpu_delta(after, before))
            path.write_text('usage_usec unknown\n')
            missing = sandbox._disk_sample(root, root)
            self.assertEqual(missing, {'status': 'UNAVAILABLE'})
            self.assertIsNone(sandbox._cpu_delta(before, missing))

    def test_memory_semantics_deltas_missing_reset_and_report_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            scope = Path(directory)
            def populate(value):
                for name, kind, keys in sandbox.MEMORY_DIAGNOSTIC_FILES:
                    if keys is None:
                        text = "max" if name == "memory.high" else str(value)
                    elif name == "memory.pressure":
                        text = "".join(f"{key} avg10=0.00 avg60=0.00 avg300=0.00 total={value}\n"
                                       for key in keys)
                    else:
                        text = "".join(f"{key} {value}\n" for key in keys)
                    (scope / name).write_text(text)
            populate(1)
            first = sandbox._memory_sample(scope)
            populate(4)
            last = sandbox._memory_sample(scope)
            delta = sandbox._memory_deltas(first, last)
            self.assertEqual(delta['memory.stat'], dict.fromkeys(sandbox.MEMORY_COUNTERS, 3))
            self.assertEqual(delta['memory.pressure'], {'some': 3, 'full': 3})
            self.assertNotIn('memory.current', delta)
            self.assertNotIn('memory.peak', delta)
            self.assertNotIn('memory.max', delta)
            self.assertNotIn('anon', delta['memory.stat'])
            self.assertEqual([r['file'] for r in last],
                             [row[0] for row in sandbox.MEMORY_DIAGNOSTIC_FILES])
            self.assertTrue(all(r['start'] <= r['end'] for r in last))
            self.assertEqual(next(r for r in last if r['file'] == 'memory.high')['values']['value'], 'max')
            self.assertTrue(all(value is None for values in sandbox._memory_deltas(last, first).values()
                                for value in values.values()))
            populate(2 ** 63 - 1)
            largest = sandbox._memory_sample(scope)
            self.assertLess(len(json.dumps({'before': largest, 'after': largest,
                                           'deltas': sandbox._memory_deltas(first, largest)})), 12 * 1024)
            (scope / 'memory.stat').write_text('anon 1\n')
            incomplete = sandbox._memory_sample(scope)
            stat = next(r for r in incomplete if r['file'] == 'memory.stat')
            self.assertIsNone(stat['values']['pgscan'])
            self.assertIsNone(sandbox._memory_deltas(first, incomplete)['memory.stat']['pgscan'])

    def test_memory_unavailable_and_no_follow_does_not_fabricate_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            scope = Path(directory)
            for malformed in ('-1', str(2 ** 63), 'not-a-counter', 'x' * 8193):
                (scope / 'memory.current').write_text(malformed)
                reading = sandbox._memory_sample(scope)[0]
                self.assertEqual(reading['status'], 'UNAVAILABLE')
                self.assertIsNone(reading['values'])
            (scope / 'memory.current').unlink()
            (scope / 'memory.current').symlink_to(scope / 'foreign')
            (scope / 'foreign').write_text('0')
            self.assertEqual(sandbox._memory_sample(scope)[0]['status'], 'UNAVAILABLE')
            (scope / 'memory.events').write_text('oom 1\noom 2\n')
            (scope / 'memory.pressure').write_text('some avg10=0.00 total=1 total=2\n')
            readings = {r['file']: r for r in sandbox._memory_sample(scope)}
            self.assertEqual(readings['memory.events']['status'], 'UNAVAILABLE')
            self.assertEqual(readings['memory.pressure']['status'], 'UNAVAILABLE')


    def test_descriptor_closes_on_parse_read_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data'
            path.write_text('data')
            original = os.close
            with patch.object(os, 'read', side_effect=OSError('synthetic')), \
                    patch.object(os, 'close', wraps=original) as close:
                with self.assertRaises(OSError):
                    sandbox._diagnostic_read(path)
                close.assert_called_once()

    def test_fixture_generation_preserves_work_and_assertions_without_launch(self):
        from test_resource_sandbox import ResourceSandboxTests
        case = ResourceSandboxTests('test_workspace_disk_ceiling')
        case.setUp()
        try:
            with patch('test_resource_sandbox.run_isolated', side_effect=RuntimeError('recorded')) as launch:
                with self.assertRaisesRegex(RuntimeError, 'recorded'):
                    case.test_workspace_disk_ceiling()
            source = (case.workspace / 'test_attack.py').read_text()
            compile(source, 'recorded-fixture', 'exec')  # Syntax only; never execute fixture.
            self.assertIn("+ '\\n'", source)
            self.assertIn('range(6)', source)
            self.assertIn('range(60)', source)
            self.assertEqual(launch.call_args.kwargs, {'timeout': 6, 'disk_diagnostics': True})
        finally:
            case.doCleanups()


class BoundedReportingTests(unittest.TestCase):
    def test_same_discovery_and_success_failure_error_skip_overflow(self):
        import contextlib
        import io
        runner = runpy.run_path(str(ROOT / 'bin/freeagent-test'))
        run = runner['run']
        globals_ = run.__globals__
        cases = [
            ('self.assertTrue(True)', 0, 'RESULT=PASS'),
            ("self.fail('ACTIONABLE_FAILURE')", 1, 'ACTIONABLE_FAILURE'),
            ("raise RuntimeError('ACTIONABLE_ERROR')", 1, 'ACTIONABLE_ERROR'),
            ("self.skipTest('EXPLICIT_SKIP')", 0, 'skipped=1'),
            ("print('x' * (70 * 1024))", 1, 'OUTPUT_TRUNCATED=true'),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for body, expected, marker in cases:
                with self.subTest(body=body):
                    (root / 'test_case.py').write_text(
                        'import unittest\nclass Case(unittest.TestCase):\n def test_case(self):\n  ' + body + '\n')
                    output = io.StringIO()
                    with patch.dict(globals_, {'ROOT': root}), contextlib.redirect_stdout(output):
                        command, name = runner['detect']()
                        self.assertEqual(command, [sys.executable, '-m', 'unittest', 'discover', '-v'])
                        code = run(command, name)
                    self.assertEqual(code, expected)
                    self.assertIn(marker, output.getvalue())
                    self.assertIn('Ran 1 test', output.getvalue())
                    if expected:
                        self.assertIn('RESULT=FAIL', output.getvalue())
                    if marker == 'skipped=1':
                        self.assertIn('EXPLICIT_SKIP', output.getvalue())
                    if expected == 0:
                        self.assertIn('test_case', output.getvalue())
                    if 'ACTIONABLE' in marker:
                        self.assertIn('Traceback', output.getvalue())
            self.assertEqual(globals_['MAX_CAPTURE'], 65536)
            self.assertEqual(globals_['TIMEOUT'], 420)
