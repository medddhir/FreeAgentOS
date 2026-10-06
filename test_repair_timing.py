"""Non-privileged development wrapper tests; no application fixture execution."""
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from devtools import repair_timing as t
from devtools.export_timing import Recorder

class RepairTimingTests(unittest.TestCase):
    def test_delegate_return_exception_and_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'sidecar';fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:
                recorder=Recorder(fd);m=t.Measurements(recorder)
                token=object();calls=[]
                def fn(*args,**kwargs):calls.append((args,kwargs));return token
                owner=types.SimpleNamespace(fn=fn)
                with m.patches([(owner,'fn','workspace_prepare')]):
                    self.assertIs(owner.fn(1,n=2),token)
                self.assertIs(owner.fn,fn);self.assertEqual(calls,[((1,),{'n':2})])
                error=ValueError('fixed')
                def fail():raise error
                with self.assertRaises(ValueError) as caught:m.wrap(fail,'rollback')()
                self.assertIs(caught.exception,error)
                self.assertEqual(m.totals['rollback']['exceptions'],1)
                self.assertFalse(m.stack)
            finally:os.close(fd)

    def test_nested_accounting_is_explicit_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd=os.open(Path(tmp)/'sidecar',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:
                r=Recorder(fd);m=t.Measurements(r)
                inner=m.wrap(lambda:None,'sandbox_wait')
                with patch.object(t.time,'monotonic_ns',side_effect=[0,10,30,50]):
                    m.wrap(inner,'validation_testing')()
                self.assertEqual(m.totals['validation_testing']['elapsed_ns'],50)
                self.assertEqual(m.totals['validation_testing']['exclusive_instrumented_ns'],30)
                self.assertEqual(m.totals['sandbox_wait']['elapsed_ns'],20)
                self.assertLessEqual(len(m.totals),len(t.LABELS))
                with self.assertRaises(ValueError):m.wrap(lambda:None,'untrusted_label')
            finally:os.close(fd)

    def test_diagnostics_do_not_replace_results_and_terminal_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd=os.open(Path(tmp)/'sidecar',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:
                r=Recorder(fd);m=t.Measurements(r);token=object()
                with patch.object(r,'accumulate',side_effect=OSError()):
                    self.assertIs(m.wrap(lambda:token,'cleanup')(),token)
                self.assertEqual(m.error,'PROFILE_DIAGNOSTIC_FAILED')
                with patch.object(t,'cpu',side_effect=OSError()):
                    self.assertIs(m.wrap(lambda:token,'cleanup')(),token)
                from devtools import export_timing as e
                with patch.object(e,'MAX_RECORDS',4),patch.object(e,'RESERVED_RECORDS',3):
                    with r.span('GROUP','fixed'):
                        with r.span('CASE','fixed_case'):
                            r.emit(dict(v=1,event='START',kind='HASH_OR_READ',label='normal',
                                        id=99,parent=None,monotonic_ns=0))
                rows=[json.loads(line) for line in (Path(tmp)/'sidecar').read_text().splitlines()]
                self.assertEqual(r.error,'SIDECAR_BOUND')
                self.assertEqual(rows[-1]['event'],'END');self.assertEqual(rows[-1]['kind'],'GROUP')
                self.assertLessEqual(len(rows),4)
            finally:os.close(fd)

    def test_fixed_fixture_and_budget(self):
        self.assertEqual(t.TEST,'test_intermediate_repair.IntermediateRepairTests.test_unauthorized_repair_paths_block')
        self.assertEqual(t.OUTER_SECONDS,1780)
        self.assertEqual(t.MAX_CAPTURE,65536)
