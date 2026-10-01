"""Synthetic Claude Code transport fixtures; no model/provider requests."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / 'orchestrator'))
from roles.activity import ActivityCapture, MAX_EVENTS, MAX_RECORD_BYTES, MAX_STREAM_BYTES, safe_activity
from roles.worker import run_worker, WorkerBoundaryError
from roles import coder, fixer
import cli

SECRET = 'Bearer FAKE_ACTIVITY_SECRET_847239'
def use(tool='read_file', identifier='u1', **arguments):
    return {'type':'assistant','message':{'content':[{'type':'tool_use','id':identifier,
        'name':'mcp__freeagent_files__'+tool,'input':arguments}]}}
def reply(identifier='u1', error=False):
    return {'type':'user','message':{'content':[{'type':'tool_result','tool_use_id':identifier,
        'content':SECRET,'is_error':error}]}}
def final(error=False):
    return {'type':'result','subtype':'error_during_execution' if error else 'success',
            'is_error':error,'result':SECRET}
def record(event):
    return (json.dumps(event,ensure_ascii=False)+'\n').encode()

class WorkerActivityTests(unittest.TestCase):
    def parse(self, events):
        parser=ActivityCapture()
        for i,event in enumerate(events):
            parser.now_ms=i*100
            parser.add(record(event))
        evidence=parser.finish()
        self.assertNotIn(SECRET,json.dumps(evidence))
        self.assertNotIn(SECRET,parser.render().decode())
        return parser,evidence

    def test_read_edit_completion(self):
        p,e=self.parse([use(),reply(),use('edit_file','u2'),reply('u2'),final()])
        self.assertEqual(e['activity_status'],'COMPLETE')
        self.assertEqual((e['read_events'],e['edit_events'],e['tool_success_events']),(1,1,2))
        self.assertEqual(p.render(),b'MODEL_WORKER_COMPLETED')
        self.assertEqual(e['first_tool_event_ms'],0)
        self.assertEqual(e['last_tool_event_ms'],300)
        self.assertEqual(e['final_result_ms'],400)

    def test_multiple_reads_and_grep(self):
        _,e=self.parse([use(),reply(),use(identifier='u2'),reply('u2'),use('grep_files','u3'),reply('u3'),final()])
        self.assertEqual(e['read_events'],2)
        self.assertEqual(e['grep_events'],1)

    def test_glob_and_write(self):
        _,e=self.parse([use('glob_files'),reply(),use('write_file','u2'),reply('u2'),final()])
        self.assertEqual((e['glob_events'],e['write_events']),(1,1))

    def test_unknown_tool_not_echoed_or_progress(self):
        _,e=self.parse([use(SECRET),reply(),final()])
        self.assertEqual(e['unknown_tool_events'],1)
        self.assertIsNone(e['first_tool_event_ms'])

    def test_malformed_json(self):
        p=ActivityCapture();p.add(b'not json '+SECRET.encode()+b'\n')
        self.assertEqual(p.finish()['activity_status'],'INVALID')
        self.assertEqual(p.render(),b'')

    def test_oversized_line(self):
        p=ActivityCapture();p.add(b'x'*(MAX_RECORD_BYTES+1))
        self.assertEqual(p.finish()['activity_status'],'INVALID')
        self.assertEqual(len(p.buffer),0)
        self.assertTrue(p.truncated)

    def test_event_flood(self):
        p=ActivityCapture()
        for _ in range(MAX_EVENTS+200):p.add(record({'type':'system','subtype':'init'}))
        self.assertEqual(p.finish()['activity_status'],'INVALID')
        self.assertEqual(p.data['stream_events_total'],MAX_EVENTS)
        self.assertEqual(len(p.buffer),0)
        self.assertLessEqual(len(p.pending),128)

    def test_total_bytes_bound(self):
        p=ActivityCapture()
        for _ in range(20):p.add(record({'type':'system','subtype':'init','text':'x'*20000}))
        self.assertTrue(p.truncated)
        self.assertEqual(p.finish()['activity_status'],'INVALID')

    def test_missing_final(self):
        _,e=self.parse([use(),reply()]);self.assertEqual(e['activity_status'],'NO_FINAL_RESULT')

    def test_event_after_final(self):
        p,e=self.parse([final(),{'type':'system','subtype':'init'}])
        self.assertEqual(e['activity_status'],'INVALID');self.assertEqual(p.render(),b'')

    def test_secret_arguments(self):
        _,e=self.parse([use(path=SECRET),reply(),final()]);self.assertNotIn(SECRET,json.dumps(e))

    def test_secret_tool_result(self):
        _,e=self.parse([use(),reply(),final()]);self.assertEqual(e['tool_success_events'],1)

    def test_text_and_reasoning_ignored(self):
        _,e=self.parse([{'type':'assistant','message':{'content':[
            {'type':'text','text':SECRET},{'type':'thinking','thinking':SECRET}]}},final()])
        self.assertEqual(e['tool_events_total'],0)
        self.assertEqual(e['last_progress_event_ms'],100)

    def test_traversal_has_no_path_authority(self):
        _,e=self.parse([use(path='../../.ssh/id_rsa'),reply(error=True),final()])
        self.assertNotIn('path',json.dumps(e))

    def test_host_path_not_retained(self):
        _,e=self.parse([use(path='/proc/self/environ'),reply(),final()])
        self.assertNotIn('/proc',json.dumps(e))

    def test_control_and_unicode_discarded(self):
        _,e=self.parse([use(path='\x00\n秘密'),reply(),final()])
        self.assertEqual(e['activity_status'],'COMPLETE')

    def test_tool_error_count(self):
        _,e=self.parse([use(),reply(error=True),final()])
        self.assertEqual(e['tool_error_events'],1)

    def test_unknown_failure_does_not_echo(self):
        p,e=self.parse([{'type':SECRET}]);self.assertEqual(e['activity_status'],'INVALID')

    def test_partial_result_rejected(self):
        p=ActivityCapture();p.add(record(final()).rstrip(b'\n'))
        self.assertEqual(p.finish()['activity_status'],'INVALID')

    def test_invalid_envelopes(self):
        for event in ([],{}, {'type':'assistant'}, {'type':'system'},
                      {'type':'result','is_error':False,'subtype':'success'},
                      {'type':'result','is_error':False,'subtype':'unknown'},
                      reply(),use(identifier='x'*129)):
            with self.subTest(event_type=type(event).__name__):
                _,e=self.parse([event]);self.assertEqual(e['activity_status'],'INVALID')

    def test_duplicate_invocation_rejected(self):
        _,e=self.parse([use(),use()]);self.assertEqual(e['activity_status'],'INVALID')

    def test_pending_tool_prevents_success(self):
        _,e=self.parse([use(),final()]);self.assertEqual(e['activity_status'],'INVALID')

    def test_model_error_result(self):
        p,e=self.parse([final(error=True)]);self.assertEqual(e['activity_status'],'MODEL_ERROR');self.assertEqual(p.render(),b'')

    def test_incremental_utf8(self):
        p=ActivityCapture();raw=record(use(path='é'))+record(reply())+record(final())
        for byte in raw:p.add(bytes([byte]))
        self.assertEqual(p.finish()['activity_status'],'COMPLETE')

    def test_cli_whitelists_fields_and_types(self):
        data={'activity_status':'COMPLETE','read_events':2,'raw':SECRET,'final_result_seen':True,
              'last_tool_event_ms':10,'edit_events':SECRET,'first_stream_event_ms':-1}
        rendered=json.dumps(cli._evidence({'activity':data}))
        self.assertNotIn(SECRET,rendered);self.assertNotIn('raw',rendered)
        self.assertEqual(safe_activity(data)['read_events'],2)

    def test_long_session_timing_is_controller_owned(self):
        p=ActivityCapture();p.now_ms=179000;p.add(record(final()))
        self.assertEqual(p.finish()['final_result_ms'],179000)

    def execute(self, events, *, role='coder', hang=False):
        code='import sys,time\n'
        for event in events:code+='sys.stdout.buffer.write('+repr(record(event))+');sys.stdout.flush()\n'
        if hang:code+='time.sleep(10)\n'
        return run_worker([sys.executable,'-c',code],cwd=ROOT,timeout=1 if hang else 3,
                          role=role,stream_activity=True)

    def test_contained_coder_stream_success(self):
        r=self.execute([use(),reply(),final()]);self.assertEqual(r.returncode,0)
        self.assertEqual(r.stdout,'MODEL_WORKER_COMPLETED')
        self.assertEqual(r.evidence['activity']['read_events'],1)
        self.assertEqual(r.evidence['remaining_processes'],0)
        self.assertNotIn(SECRET,json.dumps(r.__dict__))

    def test_contained_fixer_stream_success(self):
        r=self.execute([final()],role='fixer');self.assertEqual(r.returncode,0)
        self.assertEqual(r.evidence['activity']['activity_status'],'COMPLETE')

    def test_active_timeout(self):
        r=self.execute([use(),reply()],hang=True)
        self.assertEqual(r.returncode,124);self.assertEqual(r.evidence['activity']['read_events'],1)
        self.assertEqual(r.evidence['remaining_processes'],0)

    def test_idle_timeout(self):
        r=self.execute([],hang=True)
        self.assertEqual(r.returncode,124);self.assertEqual(r.evidence['activity']['tool_events_total'],0)

    def test_missing_final_blocks_exit_zero(self):
        r=self.execute([use(),reply()]);self.assertEqual(r.returncode,65)
        self.assertEqual(r.stdout,'')

    def test_cleanup_failure_still_blocks(self):
        from roles import worker
        with patch.object(worker,'_cleanup_outer_scope',side_effect=WorkerBoundaryError('WORKER_SCOPE_CLEANUP_UNPROVEN')):
            with self.assertRaises(WorkerBoundaryError):self.execute([final()])

    def test_modes_are_role_restricted(self):
        with self.assertRaisesRegex(WorkerBoundaryError,'WORKER_ACTIVITY_MODE_INVALID'):
            run_worker([sys.executable,'-c','print(1)'],role='planner',stream_activity=True)

if __name__=='__main__':unittest.main()
