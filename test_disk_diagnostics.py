"""Unprivileged diagnostic parsing and bounded runner-reporting regressions."""
import hashlib
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


def _retention_memory():
    readings = []
    for name, kind, keys in sandbox.MEMORY_DIAGNOSTIC_FILES:
        if keys is None:
            value = "max" if name in ("memory.high", "memory.max") else 1
            values = {"value": value}
        elif name == "memory.pressure":
            values = {key: 1 for key in keys}
        else:
            values = {key: 1 for key in keys}
        readings.append({"file": name, "kind": kind, "start": 1.0,
                         "end": 2.0, "status": "OBSERVED", "values": values})
    return readings


def _retention_diagnostic():
    cpu = {key: 1 for key in sandbox.CPU_DIAGNOSTIC_KEYS}
    sample = {"status": "OBSERVED", "monotonic": 1.0, "cpu_stat": cpu,
              "available_bytes": 256 * sandbox.MIB,
              "available_inodes": 20000}
    record = {"phase": "reservation_before", "monotonic": 1.0,
              "written_bytes": 0, "demand": 1, "category": "NONE"}
    return {
        "schema_version": 1,
        "authority": "NONE",
        "phases": {name: 1.0 for name in ("setup_start", "setup_complete",
                                            "launch_start", "launch_return",
                                            "wait_return", "result_collection")},
        "before": sample,
        "after": {**sample, "monotonic": 2.0},
        "cpu_delta": {key: 1 for key in sandbox.CPU_DIAGNOSTIC_KEYS},
        "progress": {"status": "CHILD_REPORTED", "records": [record]},
        "memory": {"before": _retention_memory(), "after": _retention_memory(),
                    "deltas": {name: {key: 1 for key in keys} for name, keys in (
                        ("memory.stat", sandbox.MEMORY_COUNTERS),
                        ("memory.events", sandbox.MEMORY_EVENTS),
                        ("memory.events.local", sandbox.MEMORY_EVENTS),
                        ("memory.pressure", ("some", "full")))}}
    }


def _retention_result(*, output="RESULT=TIMEOUT\nEXIT_CODE=124\n", result="TIMEOUT",
                      exit_code=124):
    return {"output": output, "result": result, "exit_code": exit_code, "isolated": True,
            "evidence": {"cleanup_status": "CONFIRMED", "remaining_processes": 0,
                         "cgroup_status": "ENFORCED", "controls": {
                             key: "ENFORCED" for key in sandbox.REQUIRED_CONTROLS},
                         "timeout_triggered": True, "output_truncated": False,
                         "resource_hits": {"disk": True},
                         "disk_diagnostics": _retention_diagnostic()}}


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

    def test_private_retention_success_is_bounded_and_source_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            result = _retention_result(result="FAIL", exit_code=1,
                                       output="RESULT=RESOURCE_LIMIT\nEXIT_CODE=1\n")
            result["evidence"]["disk_diagnostics"]["secret"] = "must not be retained"
            report = sandbox._retain_disk_diagnostics(result, "a" * 64, 6, root, "b" * 32)
            path = Path(report["path"])
            raw = path.read_bytes()
            payload = json.loads(raw)
            self.assertEqual(report["status"], "RETAINED")
            self.assertEqual(report["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertLessEqual(len(raw), sandbox.RETENTION_BYTES)
            self.assertLessEqual(report["records"], sandbox.RETENTION_RECORDS)
            self.assertEqual(payload["invocation"]["id"], "b" * 32)
            self.assertEqual(payload["authority"], {
                "controller_observations": "CONTROLLER_OBSERVED",
                "child_progress": "CHILD_REPORTED", "qualification": "NONE"})
            self.assertEqual(payload["diagnostic"]["progress"]["status"], "CHILD_REPORTED")
            self.assertNotIn("secret", raw.decode())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_post_evidence_guard_branches_retain_metadata_before_original_error(self):
        cases = ((125, "RESULT=FAIL\n", "RETURN_CODE_INVALID", 1),
                 (0, "child output without a result marker\n", "RESULT_MARKER_ABSENT", 0))
        for returncode, output, branch, marker_count in cases:
            with self.subTest(branch=branch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                root.chmod(0o700)
                capture = sandbox.BoundedCapture(64)
                capture.add(b"PRIVATE_CAPTURE_TEXT\n" + output.encode())

                class Child:
                    pid = 321
                    pass

                Child.returncode = returncode
                with patch.dict(os.environ, {"FREEAGENT_CONTROLLER_PROGRESS_DIR": str(root)}):
                    with self.assertRaisesRegex(RuntimeError, "ISOLATED_SANDBOX_SETUP_FAILED"):
                        sandbox._post_evidence_guard(Child(), capture, output,
                                                     "a" * 64, 6, True)
                retained = list(root.glob("disk-diagnostic-*.json"))
                self.assertEqual(len(retained), 1)
                raw = retained[0].read_bytes()
                payload = json.loads(raw)
                guard = payload["guard"]
                self.assertEqual(payload["kind"], "POST_EVIDENCE_RESULT_GUARD")
                self.assertEqual(guard["child_returncode"], returncode)
                self.assertEqual(guard["marker_count"], marker_count)
                self.assertEqual(guard["marker_present"], bool(marker_count))
                self.assertEqual(guard["branch"], branch)
                self.assertEqual(guard["capture_total_bytes"], len(capture.render()))
                self.assertEqual(guard["capture_retained_bytes"], len(capture.render()))
                self.assertEqual(guard["capture_sha256"], hashlib.sha256(capture.render()).hexdigest())
                self.assertNotIn("PRIVATE_CAPTURE_TEXT", raw.decode())
                self.assertIsInstance(guard["source_sha256"], str)
                self.assertEqual(len(guard["source_sha256"]), 64)

        capture = sandbox.BoundedCapture(64)
        capture.add(b"fixed")

        class Child:
            pid = 654
            returncode = 125

        with patch.object(sandbox, "_retain_post_evidence_guard",
                          side_effect=OSError("diagnostic-only")):
            with self.assertRaisesRegex(RuntimeError, "ISOLATED_SANDBOX_SETUP_FAILED"):
                sandbox._post_evidence_guard(Child(), capture, "", "b" * 64, 6, True)

    def test_descriptor_is_held_and_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            held = sandbox._open_private_retention_directory(root)
            descriptor = held.descriptor
            held.close()
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_unsafe_ancestor_and_replacement_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            target = root / "target"
            target.mkdir()
            target.chmod(0o700)
            (target / "retention").mkdir()
            link = root / "ancestor-link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(sandbox._DiagnosticRetentionError) as caught:
                sandbox._open_private_retention_directory(link / "retention")
            self.assertIn(caught.exception.code, {
                "DIAGNOSTIC_DESTINATION_INVALID", "DIAGNOSTIC_DESTINATION_UNSAFE"})

            leaf = root / "leaf"
            leaf.mkdir()
            leaf.chmod(0o700)
            replacement = root / "leaf-replacement"
            held = sandbox._open_private_retention_directory(leaf)
            leaf.rename(replacement)
            leaf.mkdir()
            leaf.chmod(0o700)
            try:
                with self.assertRaises(sandbox._DiagnosticRetentionError) as caught:
                    sandbox._check_retention_directory(held)
            finally:
                held.close()
                leaf.rmdir()
                replacement.rmdir()
            self.assertEqual(caught.exception.code, "DIAGNOSTIC_DESTINATION_REPLACED")

    def test_partial_write_and_publication_failure_remove_only_new_partial(self):
        result = _retention_result()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            original_write = os.write
            calls = [0]

            def partial_write(fd, data):
                calls[0] += 1
                if calls[0] == 1:
                    return original_write(fd, data[:1])
                raise OSError("synthetic write failure")

            original_open = os.open
            original_close = os.close
            opened = []
            closed = []

            def track_open(path, flags, mode=0o777, *, dir_fd=None):
                descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
                if str(path).endswith(".partial"):
                    opened.append(descriptor)
                return descriptor

            def track_close(descriptor):
                closed.append(descriptor)
                return original_close(descriptor)

            with patch.object(sandbox.os, "open", side_effect=track_open), \
                    patch.object(sandbox.os, "close", side_effect=track_close), \
                    patch.object(sandbox.os, "write", side_effect=partial_write), \
                    patch.object(sandbox.os, "fsync", side_effect=AssertionError("durability write")):
                with self.assertRaises(sandbox._DiagnosticRetentionError) as caught:
                    sandbox._retain_disk_diagnostics(result, "a" * 64, 6,
                                                     root, "3" * 32)
            self.assertEqual(len(opened), 1)
            self.assertIn(opened[0], closed)
            self.assertEqual(caught.exception.code, "DIAGNOSTIC_RETENTION_WRITE_FAILED")
            self.assertEqual(caught.exception.artifact, {
                "partial_file": "REMOVED", "fallback_directory": "NOT_CREATED"})
            self.assertEqual(list(root.glob("disk-diagnostic-*.json*")), [])

            with patch.object(sandbox.os, "link", side_effect=OSError("synthetic publish failure")), \
                    patch.object(sandbox.os, "fsync", side_effect=AssertionError("durability write")):
                with self.assertRaises(sandbox._DiagnosticRetentionError) as caught:
                    sandbox._retain_disk_diagnostics(result, "a" * 64, 6,
                                                     root, "4" * 32)
            self.assertEqual(caught.exception.code, "DIAGNOSTIC_RETENTION_PUBLISH_FAILED")
            self.assertEqual(caught.exception.artifact, {
                "partial_file": "REMOVED", "fallback_directory": "NOT_CREATED"})
            self.assertEqual(list(root.glob("disk-diagnostic-*.json*")), [])

    def test_private_retention_bounds_unsafe_destination_and_no_overwrite(self):
        result = _retention_result()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            file_path = root / "file"
            file_path.write_text("existing")
            unsafe = [file_path]
            link = root / "link"
            link.symlink_to(root)
            unsafe.append(link)
            public = root / "public"
            public.mkdir()
            public.chmod(0o755)
            unsafe.append(public)
            for destination in unsafe:
                with self.subTest(destination=destination):
                    with self.assertRaises(sandbox._DiagnosticRetentionError) as caught:
                        sandbox._retain_disk_diagnostics(result, "a" * 64, 6,
                                                         destination, "c" * 32)
                    self.assertIn(caught.exception.code, {
                        "DIAGNOSTIC_DESTINATION_UNSAFE", "DIAGNOSTIC_DESTINATION_INVALID"})
            report = sandbox._retain_disk_diagnostics(result, "a" * 64, 6, root, "d" * 32)
            before = Path(report["path"]).read_bytes()
            with self.assertRaises(sandbox._DiagnosticRetentionError) as caught:
                sandbox._retain_disk_diagnostics(result, "a" * 64, 6, root, "d" * 32)
            self.assertEqual(caught.exception.code, "DIAGNOSTIC_DESTINATION_EXISTS")
            self.assertEqual(Path(report["path"]).read_bytes(), before)
            self.assertEqual(list(root.glob("disk-diagnostic-d*.json.partial")), [])

            too_many = _retention_result()
            too_many["evidence"]["disk_diagnostics"]["progress"]["records"] = [
                too_many["evidence"]["disk_diagnostics"]["progress"]["records"][0]
            ] * (sandbox.RETENTION_RECORDS + 1)
            with self.assertRaises(sandbox._DiagnosticRetentionError) as caught:
                sandbox._retain_disk_diagnostics(too_many, "a" * 64, 6, root, "e" * 32)
            self.assertEqual(caught.exception.code, "DIAGNOSTIC_PROGRESS_INVALID")
            with patch.object(sandbox, "RETENTION_BYTES", 1):
                with self.assertRaises(sandbox._DiagnosticRetentionError) as caught:
                    sandbox._retain_disk_diagnostics(result, "a" * 64, 6, root, "f" * 32)
            self.assertEqual(caught.exception.code, "DIAGNOSTIC_RETENTION_BOUNDS")

    def test_retention_failure_preserves_fixture_result_and_reports_error(self):
        from test_resource_sandbox import ResourceSandboxTests
        case = ResourceSandboxTests("test_workspace_disk_ceiling")
        case.setUp()
        try:
            destination = case.run_dir / "unsafe-destination"
            destination.write_text("not a directory")
            with patch.object(sandbox, "_run_isolated_in_area", return_value=_retention_result()), \
                    patch.dict(os.environ, {"FREEAGENT_CONTROLLER_PROGRESS_DIR": str(destination)}):
                result = sandbox.run_isolated(case.workspace, case.run_dir, case.runner_hash,
                                              timeout=6, disk_diagnostics=True)
            self.assertEqual((result["result"], result["exit_code"]), ("TIMEOUT", 124))
            self.assertEqual(result["evidence"]["disk_diagnostics_retention"], {
                "status": "ERROR", "code": "DIAGNOSTIC_DESTINATION_UNSAFE"})
        finally:
            case.doCleanups()

    def test_default_off_ignores_configured_retention_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "controller"
            control.mkdir()
            destination = root / "diagnostics"
            destination.mkdir(mode=0o700)
            original = _retention_result()
            before = json.dumps(original, sort_keys=True)
            with patch.object(sandbox, "_run_isolated_in_area", return_value=original) as launch, \
                    patch.object(sandbox, "_retain_disk_diagnostics") as retain, \
                    patch.object(sandbox, "_retention_destination") as choose_destination, \
                    patch.object(sandbox.os, "write", wraps=os.write) as write, \
                    patch.dict(os.environ, {"FREEAGENT_CONTROLLER_PROGRESS_DIR": str(destination)}):
                # Deliberately omit the opt-in keyword: exercise its real default.
                result = sandbox.run_isolated(root / "workspace", root, "a" * 64, timeout=6)
            self.assertIs(result, original)
            self.assertEqual(json.dumps(result, sort_keys=True), before)
            self.assertIs(launch.call_args.args[-1], False)
            self.assertNotIn("disk_diagnostics_retention", result["evidence"])
            retain.assert_not_called()
            choose_destination.assert_not_called()
            write.assert_not_called()
            self.assertEqual(list(destination.iterdir()), [])
            self.assertEqual(list(control.iterdir()), [])

    def test_fallback_creation_failure_has_consistent_artifact_and_retained_state(self):
        for after_mkdir in (False, True):
            with self.subTest(after_mkdir=after_mkdir), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                original_open = os.open
                original_mkdir = os.mkdir
                opened = []

                def fail_after_mkdir(path, flags, mode=0o777, *, dir_fd=None):
                    if str(path).startswith("freeagent-disk-diagnostics-"):
                        raise OSError("synthetic post-mkdir open failure")
                    descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
                    opened.append(descriptor)
                    return descriptor

                def mkdir(path, mode=0o777, *, dir_fd=None):
                    if not after_mkdir:
                        raise OSError("synthetic mkdir failure")
                    return original_mkdir(path, mode, dir_fd=dir_fd)

                with patch.dict(os.environ):
                    os.environ.pop("FREEAGENT_CONTROLLER_PROGRESS_DIR", None)
                    with patch.object(sandbox.tempfile, "gettempdir", return_value=str(root)), \
                            patch.object(sandbox.os, "mkdir", side_effect=mkdir), \
                            patch.object(sandbox.os, "open", side_effect=fail_after_mkdir):
                        with self.assertRaises(sandbox._DiagnosticRetentionError) as caught:
                            sandbox._retention_destination()
                self.assertEqual(caught.exception.code, "DIAGNOSTIC_DESTINATION_CREATE_FAILED")
                artifact = {"partial_file": "NOT_CREATED",
                            "fallback_directory": "RETAINED" if after_mkdir else "NOT_CREATED"}
                self.assertEqual(caught.exception.artifact, artifact)
                self.assertEqual(sandbox._retention_failure(caught.exception), {
                    "status": "ERROR", "code": "DIAGNOSTIC_DESTINATION_CREATE_FAILED",
                    "artifact": artifact})
                retained = list(root.iterdir())
                self.assertEqual(len(retained), int(after_mkdir))
                if after_mkdir:
                    self.assertTrue(retained[0].is_dir())
                    self.assertFalse(retained[0].is_symlink())
                    self.assertEqual(retained[0].stat().st_uid, os.getuid())
                    self.assertEqual(retained[0].stat().st_mode & 0o777, 0o700)
                    self.assertEqual(list(retained[0].iterdir()), [])
                for descriptor in opened:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_retention_exists_before_fixture_assertion_failure(self):
        from test_resource_sandbox import ResourceSandboxTests
        case = ResourceSandboxTests("test_workspace_disk_ceiling")
        case.setUp()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                root.chmod(0o700)
                with patch.object(sandbox, "_run_isolated_in_area", return_value=_retention_result()), \
                        patch.dict(os.environ, {"FREEAGENT_CONTROLLER_PROGRESS_DIR": str(root)}):
                    with self.assertRaisesRegex(AssertionError, "No space left on device"):
                        case.test_workspace_disk_ceiling()
                retained = list(root.glob("disk-diagnostic-*.json"))
                self.assertEqual(len(retained), 1)
                self.assertEqual(json.loads(retained[0].read_text())["outcome"]["result"],
                                 "TIMEOUT")
        finally:
            case.doCleanups()


class BoundedReportingTests(unittest.TestCase):
    def test_same_discovery_and_success_failure_error_skip_overflow(self):
        import contextlib
        import io
        import shutil
        with patch.object(Path, 'cwd', return_value=ROOT):
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
            self.assertEqual(globals_['TIMEOUT'], 600)
            # Deadline selection happens at initialization, before fixture ROOT
            # overrides. Exercise foreign and copied entrypoints independently.
            with patch.object(Path, 'cwd', return_value=root):
                foreign = runpy.run_path(str(ROOT / 'bin/freeagent-test'))
                self.assertEqual(foreign['TIMEOUT'], 180)
                copied_path = root / 'protected' / 'freeagent-test'
                copied_path.parent.mkdir()
                shutil.copyfile(ROOT / 'bin/freeagent-test', copied_path)
                copied = runpy.run_path(str(copied_path))
                self.assertEqual(copied['TIMEOUT'], 180)
