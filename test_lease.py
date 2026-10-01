"""Stage 1.10: controller clocks and synthetic workers, never model calls."""
import copy
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
from roles import worker, activity, broker_telemetry, fixer, read_policy
from roles.lease import ActivityLease, hard_cap_seconds, safe_lease, NS
import cli


class Lease(unittest.TestCase):
    def lease(self, role='coder', streaming=True, ceiling=240):
        return ActivityLease(180, role, 'model', streaming, ceiling, 10 * NS)

    def broker(self, seconds=None, tool='read_file'):
        telemetry = broker_telemetry.BrokerTelemetry()
        if seconds is not None:
            with patch.object(broker_telemetry.time, 'monotonic_ns', return_value=int((10 + seconds) * NS)):
                telemetry.request(tool)
                telemetry.success(tool)
        return SimpleNamespace(telemetry=telemetry)

    def qualify(self, seconds, **kwargs):
        lease = self.lease(**kwargs)
        granted = lease.extend(190 * NS, broker=self.broker(seconds))
        return lease, granted

    def test_fast(self):
        e = self.lease().evidence(50 * NS, success=True)
        self.assertFalse(e['grace_granted'])
        self.assertFalse(e['base_lease_exceeded'])

    def test_zero(self):
        self.assertFalse(self.qualify(None)[1])

    def test_early(self):
        self.assertFalse(self.qualify(20)[1])

    def test_stale(self):
        self.assertFalse(self.qualify(120)[1])

    def test_outside(self):
        self.assertFalse(self.qualify(149.999)[1])

    def test_boundary(self):
        self.assertTrue(self.qualify(150)[1])

    def test_read(self):
        self.assertTrue(self.qualify(165)[1])

    def test_glob(self):
        lease = self.lease()
        self.assertTrue(lease.extend(190 * NS, broker=self.broker(165, 'glob_files')))

    def test_grep(self):
        lease = self.lease()
        self.assertTrue(lease.extend(190 * NS, broker=self.broker(165, 'grep_files')))

    def test_edit(self):
        lease = self.lease()
        self.assertTrue(lease.extend(190 * NS, broker=self.broker(165, 'edit_file')))

    def test_write(self):
        lease = self.lease()
        self.assertTrue(lease.extend(190 * NS, broker=self.broker(165, 'write_file')))

    def test_denials(self):
        broker = self.broker()
        broker.telemetry.failure('READ_DENIED')
        self.assertIsNone(broker.telemetry.last_success_ns)
        self.assertFalse(self.lease().extend(190 * NS, broker=broker))

    def stream(self, blocks, malformed=False):
        capture = activity.ActivityCapture()
        capture.now_ms = 165000
        capture.add((json.dumps({'type': 'assistant', 'message': {'content': blocks}}) + '\n').encode())
        if malformed:
            capture.add(b'{malformed}\n')
        return capture

    def tool(self, name='read_file'):
        return {'type': 'tool_use', 'id': 't', 'name': 'mcp__freeagent_files__' + name, 'input': {}}

    def completed(self):
        c = self.stream([self.tool()])
        c.add(b'{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t","is_error":false}]}}\n')
        return c

    def test_fallback(self):
        lease = self.lease()
        self.assertTrue(lease.extend(190 * NS, capture=self.completed()))
        self.assertEqual(lease.source, 'STREAM_TOOL_SUCCESS')

    def test_broker_first(self):
        self.assertFalse(self.lease().extend(190 * NS, broker=self.broker(), capture=self.completed()))

    def test_malformed(self):
        c = self.completed()
        c.add(b'{malformed}\n')
        self.assertFalse(self.lease().extend(190 * NS, capture=c))

    def test_text(self):
        c = self.stream([{'type': 'text', 'text': 'fake secret /host/file'}])
        self.assertFalse(self.lease().extend(190 * NS, capture=c))

    def test_reasoning(self):
        c = self.stream([{'type': 'thinking', 'thinking': 'fake secret'}])
        self.assertFalse(self.lease().extend(190 * NS, capture=c))

    def test_unknown(self):
        c = self.stream([self.tool('unknown')])
        self.assertFalse(self.lease().extend(190 * NS, capture=c))

    def test_pending(self):
        self.assertFalse(self.lease().extend(190 * NS, capture=self.stream([self.tool()])))

    def test_grace_end(self):
        lease, _ = self.qualify(165)
        e = lease.evidence(215 * NS, success=True)
        self.assertTrue(e['completed_during_grace'])
        self.assertTrue(e['base_lease_exceeded'])
        self.assertEqual(e['last_trusted_progress_ms'], 165000)

    def test_one_shot(self):
        lease, _ = self.qualify(165)
        self.assertFalse(lease.extend(210 * NS, broker=self.broker(195)))
        self.assertFalse(lease.extend(250 * NS, broker=self.broker(239)))
        self.assertEqual(lease.deadline_ns, 250 * NS)

    def test_roles(self):
        for role in ('planner', 'reviewer', 'researcher', 'worker'):
            self.assertFalse(self.qualify(165, role=role)[1])
        self.assertTrue(self.qualify(165, role='fixer')[1])

    def test_short(self):
        self.assertEqual(hard_cap_seconds(2, 'coder', 'model', True, 240), 2)
        self.assertFalse(self.qualify(165, streaming=False)[1])
        self.assertEqual(hard_cap_seconds(180, 'coder', 'research', True, 240), 180)

    def test_ceiling(self):
        lease, granted = self.qualify(165, ceiling=200)
        self.assertTrue(granted)
        self.assertEqual(lease.hard_ns, 210 * NS)

    def test_late_clock(self):
        self.assertFalse(self.lease().extend(250 * NS, broker=self.broker(165)))
        self.assertFalse(self.qualify(180)[1])
        self.assertFalse(self.qualify(-1)[1])

    def test_no_early(self):
        lease = self.lease()
        self.assertFalse(lease.extend(189 * NS, broker=self.broker(165)))
        self.assertFalse(lease.decided)
        self.assertTrue(lease.extend(190 * NS, broker=self.broker(165)))

    def test_cli(self):
        secret = 'Bearer FAKE_LEASE_SECRET /host/private'
        e = cli._evidence({'lease': {**self.qualify(165)[0].evidence(215 * NS, success=True),
                                    'raw': secret, 'progress_source': secret}})
        self.assertNotIn(secret, json.dumps(e))
        self.assertNotIn('private', json.dumps(e))
        self.assertTrue(e['lease']['grace_granted'])
        self.assertNotIn('progress_source', e['lease'])
        self.assertNotIn('base_ms', safe_lease({'base_ms': 10**100}))

    def test_attempts(self):
        result = fixer.fixer_node({'fix_attempts': 2})
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['fixer_error'], 'FIX_ATTEMPT_LIMIT_OR_STATE_INVALID')


class Inner(unittest.TestCase):
    def run_inner(self, *, final=205, progress=165, role='coder', interrupt=None, truncate=False, hits=None, cleanup_failure=False):
        now = [0]
        delivered = [False]
        telemetry = broker_telemetry.BrokerTelemetry()
        broker = SimpleNamespace(telemetry=telemetry, start=MagicMock(), stop=MagicMock(side_effect=telemetry.snapshot))
        stdout = SimpleNamespace(fileno=lambda: 11, close=MagicMock())
        stderr = SimpleNamespace(fileno=lambda: 12, close=MagicMock())
        proc = SimpleNamespace(stdout=stdout, stderr=stderr, returncode=None, pid=99)
        def poll():
            if final is not None and now[0] >= final * NS:
                proc.returncode = 0
            return proc.returncode
        proc.poll = poll
        proc.wait = MagicMock(side_effect=lambda **kw: setattr(proc, 'returncode', -9))
        scope, mount = MagicMock(), MagicMock()
        cleanup_calls = []
        def stop(*args):
            cleanup_calls.append(now[0])
            if proc.poll() is None:
                proc.returncode = -9
            return {'remaining_processes': 1 if cleanup_failure else 0, 'forced_kill_used': proc.returncode == -9}
        class Selector:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def register(self, *args): pass
            def unregister(self, *args): pass
            def select(self, seconds):
                now[0] += max(1, int(seconds * NS))
                if progress is not None and now[0] >= progress * NS:
                    with patch.object(broker_telemetry.time, 'monotonic_ns', return_value=now[0]):
                        telemetry.success('read_file')
                if interrupt is not None and now[0] >= interrupt * NS:
                    raise KeyboardInterrupt
                if final is not None and now[0] >= final * NS and not delivered[0]:
                    delivered[0] = True
                    return [(SimpleNamespace(fileobj=stdout, data='stdout'), 1)]
                return []
        final_bytes = b'{"type":"result","subtype":"success","is_error":false,"result":"fake private data"}\n'
        reads = iter([final_bytes, b'', b''])
        def read(*args):
            return next(reads, b'')
        original = copy.deepcopy(worker.WORKER_POLICY)
        request = {'policy': dict(original), 'limits': {}, 'profile': 'model', 'timeout': 180,
                   'role': role, 'stream_activity': True, 'scope_name': 'synthetic', 'cmd': ['synthetic'], 'cwd': '.'}
        capture_type = activity.ActivityCapture
        class Capture(capture_type):
            def add(self, chunk):
                super().add(chunk)
                if truncate:
                    self.truncated = True
        try:
            with patch.object(worker.time, 'monotonic_ns', side_effect=lambda: now[0]), \
                 patch.object(worker, '_start_cgroup', return_value=(mount, scope)), \
                 patch.object(worker.subprocess, 'Popen', return_value=proc), \
                 patch('roles.broker_session.prepare_session', return_value=(request['cmd'], broker)), \
                 patch.object(worker.selectors, 'DefaultSelector', Selector), \
                 patch.object(worker.os, 'set_blocking'), patch.object(worker.os, 'read', side_effect=read), \
                 patch.object(worker, '_stop_scope', side_effect=stop), \
                 patch.object(worker, '_scope_pids', return_value=[]), patch.object(worker, '_umount'), \
                 patch.object(worker, '_event_values', return_value=hits or {}), \
                 patch.object(worker, 'ActivityCapture', Capture):
                result = worker._run_inner('/tmp/synthetic-lease', request)
                self.assertEqual(worker.WORKER_POLICY, original)
                self.assertNotIn('fake private data', json.dumps(result))
                self.assertTrue(scope.rmdir.called)
                self.assertTrue(mount.rmdir.called)
                self.assertTrue(broker.stop.called)
                return result, cleanup_calls
        except KeyboardInterrupt:
            self.assertTrue(scope.__truediv__.return_value.write_text.called)
            self.assertTrue(scope.rmdir.called)
            self.assertTrue(broker.stop.called)
            raise

    def test_grace(self):
        result, calls = self.run_inner()
        self.assertEqual(result['returncode'], 0)
        self.assertTrue(result['evidence']['lease']['completed_during_grace'])
        self.assertEqual(result['evidence']['cleanup_status'], 'CONFIRMED')
        self.assertEqual(len(calls), 1)

    def test_coder_cap(self):
        result, calls = self.run_inner(final=None)
        self.assertEqual(result['returncode'], 124)
        self.assertEqual(calls, [240 * NS])
        self.assertTrue(result['evidence']['lease']['grace_granted'])

    def test_fixer_cap(self):
        result, calls = self.run_inner(final=None, role='fixer')
        self.assertEqual(result['returncode'], 124)
        self.assertEqual(calls, [240 * NS])

    def test_base(self):
        result, calls = self.run_inner(final=None, progress=None)
        self.assertEqual(result['returncode'], 124)
        self.assertEqual(calls, [180 * NS])
        self.assertFalse(result['evidence']['lease']['grace_granted'])

    def test_output(self):
        result, _ = self.run_inner(truncate=True)
        self.assertEqual(result['returncode'], 1)
        self.assertTrue(result['evidence']['output_truncated'])

    def test_memory(self):
        result, _ = self.run_inner(hits={'oom': 1})
        self.assertEqual(result['returncode'], 1)
        self.assertTrue(result['evidence']['resource_hits']['memory'])

    def test_pids(self):
        result, _ = self.run_inner(hits={'max': 1})
        self.assertEqual(result['returncode'], 1)
        self.assertTrue(result['evidence']['resource_hits']['process_count'])

    def test_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_inner(final=None, interrupt=195)

    def test_clean_gate(self):
        result, _ = self.run_inner(cleanup_failure=True)
        with self.assertRaises(worker.WorkerBoundaryError):
            worker._validate_evidence(result['evidence'], worker.WORKER_POLICY, result['returncode'])

    def test_fast(self):
        result, calls = self.run_inner(final=25, progress=None)
        self.assertEqual(result['returncode'], 0)
        self.assertFalse(result['evidence']['lease']['grace_granted'])
        self.assertLess(calls[0], 180 * NS)

    def test_outer(self):
        proc = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(), pid=99,
                               returncode=0, poll=lambda: 0, wait=lambda **kw: None)
        budgets = []
        def read(proc, seconds, capture):
            budgets.append(seconds)
            capture.add((worker.MARKER + '{}\n').encode())
            return False
        with patch.object(worker.subprocess, 'Popen', return_value=proc), \
             patch.object(worker, '_read_bounded', side_effect=read), \
             patch.object(worker, '_drain_ready'), patch.object(worker, '_validate_evidence'), \
             patch.object(worker, '_cleanup_outer_scope'):
            worker.run_worker(['synthetic'], role='coder', timeout=180, stream_activity=True)
        self.assertEqual(budgets, [250])

    def test_auth(self):
        import test_file_read_policy as fixtures
        fixtures.FileReadPolicyTests.setUp(self)
        operations = [('read_file', {'path': 'app.py'}), ('glob_files', {'pattern': '*.py'}),
                      ('grep_files', {'query': 'return'}),
                      ('edit_file', {'path': 'app.py', 'old_text': '1', 'new_text': '2'}),
                      ('write_file', {'path': 'app.py', 'text': 'value = 3\n'})]
        lease = ActivityLease(180, 'coder', 'model', True, 240, 0)
        broker = SimpleNamespace(telemetry=self.tools.telemetry)
        for tool, args in operations:
            with patch.object(broker_telemetry.time, 'monotonic_ns', return_value=165 * NS):
                self.tools.call(tool, args)
            self.assertEqual(broker.telemetry.last_success_ns, 165 * NS)
        with self.assertRaises(read_policy.ReadDenied):
            self.tools.call('read_file', {'path': 'unrelated.py'})
        self.assertEqual(broker.telemetry.last_success_ns, 165 * NS)
        self.assertTrue(lease.extend(180 * NS, broker=broker))
        self.assertNotIn('last_success_ns', broker.telemetry.snapshot())
