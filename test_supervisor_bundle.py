"""Concrete Ubuntu staging, without interpreter/fixture execution or activation."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from orchestrator.supervisor_bundle import Candidate, _read
from orchestrator.privilege import build_closure as c, closure_verify as v
from orchestrator.privilege import installed_identity as n, protocol as p
from test_privilege_closure_verify import IndependentClosureCases


class ConcreteBundleCases(unittest.TestCase):
    def cases(self):
        for name in sorted(v for v in dir(self) if v.startswith('case_')):
            with self.subTest(case=name):getattr(self,name)()
    def reject(self,fn):
        with self.assertRaises((p.BoundaryError,OSError)):fn()
    def case_concrete_candidate(self):
        # Commit is an input identity, not approval. Fixture builds are reviewed
        # fixed compiler commands; neither their output nor target Python runs.
        with Candidate('4c15868b6224555d5448bc8d5c4ccecee55253ef') as candidate:
            root=candidate.path
            self.assertLessEqual(len(candidate.manifest['nodes']),n.MAX_NODES)
            self.assertLessEqual(sum(map(len,candidate.files.values())),n.MAX_TOTAL)
            for path in ('python_base/lib/python3.12/encodings/__init__.py',
                         'python_base/lib/python3.12/importlib/__init__.py',
                         'python_base/lib/python3.12/site.py','runtime/lib/libexpat.so.1',
                         'runtime/lib/libm.so.6','runtime/lib/libz.so.1'):
                self.assertIn(path,candidate.files)
            self.assertEqual(candidate.builds['status'],'MATCHED')
            self.assertFalse(candidate.builds['fixtures_executed'])
            self.assertEqual(candidate.builds['reproducibility'],'UNPROVEN')
            self.assertEqual(candidate.analysis['status'],'UNRESOLVED')
            self.assertFalse(candidate.analysis['qualified'])
            self.assertTrue(any('DYNAMIC_IMPORT_UNRESOLVED' in x for x in candidate.analysis['issues']))
            self.assertFalse(any(x.startswith('DECLARED_EDGE_MISSING:') for x in candidate.analysis['issues']))
            self.reject(candidate.prerequisite)
            # Existing staging/registration gate refuses these actual findings.
            self.reject(lambda:c.StagingClosureRegistration.candidate_prerequisite(
                candidate.tree,candidate.snapshot,candidate.closure,candidate.binding,candidate.provenance))
            for path in ('venv/bin/python','package/orchestrator/privilege/service.py',
                         'python_base/lib/python3.12/encodings/__init__.py','runtime/lib/libc.so.6'):
                dest=root/path;raw=dest.read_bytes();mode=dest.stat().st_mode&0o777
                old=candidate.tree.capture()
                dest.unlink();self.reject(candidate.tree.capture)
                dest.write_bytes(raw);dest.chmod(mode)
                self.reject(lambda:candidate.tree.recheck(old))
                old=candidate.tree.capture()
                dest.write_bytes(b'changed');self.reject(candidate.tree.capture)
                dest.write_bytes(raw);dest.chmod(mode)
                self.reject(lambda:candidate.tree.recheck(old))
            # Planned/staging metadata never becomes protected authority even
            # in the hypothetical complete-analysis branch.
            fresh=candidate.tree.capture()
            with patch.object(v,'analyze',return_value={'status':'STATIC_METADATA_VERIFIED','qualified':False}):
                result=c.StagingClosureRegistration.candidate_prerequisite(candidate.tree,fresh,
                    candidate.closure,candidate.binding,candidate.provenance)
                self.assertFalse(result['qualified']);self.assertFalse(result['installed_observed'])
                self.assertFalse(result['execution_enabled'])
        self.assertFalse(root.exists())
    def case_no_follow_and_fresh_reads(self):
        # This reader requires non-writable ancestry, unlike the separate
        # private staging-tree observer. /tmp's shared ancestor is not allowed.
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory);file=root/'input';file.write_bytes(b'first');file.chmod(0o600)
            self.assertEqual(_read(root,'input'),b'first')
            file.write_bytes(b'changed');self.assertEqual(_read(root,'input'),b'changed')
            (root/'alias').symlink_to(file);self.reject(lambda:_read(root,'alias'))
            self.reject(lambda:_read(root,'../input'))
    def case_self_import_and_source_bound(self):
        fixture=IndependentClosureCases()
        with fixture.fixture(service=b'import orchestrator.privilege.service\n') as (_,args,closure,tree):
            result=fixture.analyze(args,closure)
            self.assertEqual(result['status'],'STATIC_METADATA_VERIFIED')
            self.assertNotIn('package/orchestrator/privilege/service.py',result['derived']['package/orchestrator/privilege/service.py'])
        with fixture.fixture(child=b'#'+b'x'*v.MAX_PY_BYTES) as (_,args,closure,tree):
            result=fixture.analyze(args,closure)
            self.assertEqual(result['status'],'UNRESOLVED')
            self.assertIn('SOURCE_ANALYSIS_BOUND:package/orchestrator/privilege/child.py',result['issues'])
            self.assertFalse(result['qualified'])
    def case_export_analysis_is_local_and_bounded(self):
        fixture=IndependentClosureCases()
        raw=b'one=1\ntwo=2\nthree=3\n'
        with fixture.fixture(service=raw,child=b'from .service import one, two, three\n') as (_,args,closure,tree):
            next(x for x in closure['artifacts'] if x['path'].endswith('/child.py'))['requires'].append('package/orchestrator/privilege/service.py')
            with patch.object(v,'syntax',wraps=v.syntax) as parse:
                self.assertEqual(fixture.analyze(args,closure)['status'],'STATIC_METADATA_VERIFIED')
                self.assertLessEqual(sum(call.args[0]==raw for call in parse.call_args_list),2)
            # A second observation reads again; no stale cross-call export cache.
            with patch.object(v,'syntax',wraps=v.syntax) as parse:
                self.assertEqual(fixture.analyze(args,closure)['status'],'STATIC_METADATA_VERIFIED')
                self.assertGreater(sum(call.args[0]==raw for call in parse.call_args_list),0)


if __name__=='__main__':
    suite=unittest.TestSuite([ConcreteBundleCases('cases')])
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
