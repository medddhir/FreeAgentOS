"""Source-only policy binding, temporary fixtures; no privileged backend or model."""
import contextlib
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from orchestrator.privilege import policy, policy_sources as sources, protocol as p
from orchestrator.privilege.client import ControllerClient
from orchestrator.privilege.supervisor import Supervisor, LocalServer
from orchestrator.privilege.journal import Journal
from orchestrator.privilege.real_journal import ResourceJournal
from test_privilege import PrivilegeCases
from test_privilege_complete import LinuxCompleteCases

class PolicyIdentityCases(unittest.TestCase):
    def cases(self):
        for name in ('stable','mutations','invalid','no_execution','agreement','mismatch','journals','packaging'):
            with self.subTest(case=name):getattr(self,'case_'+name)()

    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in (*sources.AUTHORITATIVE,*sources.PRIVILEGE_SOURCES):
                dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(sources._source_root()/name,dest)
            with patch.object(sources,'_source_root',return_value=root):yield root

    def case_stable(self):
        with self.fixture() as root:
            first=policy.policy_hash();self.assertEqual(first,policy.policy_hash())
            (root/'private-local-state.json').write_text('not a policy input')
            (root/'privilege/unregistered.py').write_text('not policy')
            # Excluded application/UI orchestration must not affect this contract.
            path=root/'graph.py';path.write_text(path.read_text().replace('def finalizer_node(', 'def renamed_finalizer_node('))
            self.assertEqual(first,policy.policy_hash())
            self.assertEqual(set(sources.source_identity()['sources']),set(sources.AUTHORITATIVE)|set(sources.PRIVILEGE_SOURCES))

    def case_mutations(self):
        changes=(
            ('roles/lease.py','BASE_SECONDS = 180','BASE_SECONDS = 181'),
            ('roles/lease.py','GRACE_SECONDS = 60','GRACE_SECONDS = 59'),
            ('roles/lease.py','RECENT_SECONDS = 30','RECENT_SECONDS = 29'),
            ('roles/lease.py','HARD_SECONDS = 240','HARD_SECONDS = 239'),
            ('roles/lease.py',"role in ('coder', 'fixer')", "role in ('coder',)"),
            ('roles/lease.py','or self.decided:', 'or self.granted:'),
            ('roles/lease.py','last < self.base_ns', 'last <= self.base_ns'),
            ('roles/worker.py','not lease.extend(now_ns, broker=broker, capture=capture)', 'True'),
            ('roles/planner.py','PLANNER_TIMEOUT = 90','PLANNER_TIMEOUT = 89'),
            ('roles/planner.py','PLANNER_TIMEOUT = 90','PLANNER_TIMEOUT = 90\nPLANNER_TIMEOUT *= 2'),
            ('roles/coder.py','CODER_TIMEOUT = 180','CODER_TIMEOUT = 179'),
            ('roles/fixer.py','FIXER_TIMEOUT = 180','FIXER_TIMEOUT = 179'),
            ('roles/reviewer.py','REVIEWER_TIMEOUT = 90','REVIEWER_TIMEOUT = 89'),
            ('roles/tester.py','TEST_TIMEOUT = 130','TEST_TIMEOUT = 129'),
            ('roles/read_policy.py','MAX_READ_FILES = 8','MAX_READ_FILES = 7'),
            ('roles/read_policy.py','len(write) == MAX_READ_FILES','len(write) > MAX_READ_FILES'),
            ('roles/read_policy.py','MAX_TOOL_CALLS = 128','MAX_TOOL_CALLS = 127'),
            ('roles/coding_units.py','MAX_TARGET_FILES = 4','MAX_TARGET_FILES = 3'),
            ('roles/worker.py','1536 * MIB','1535 * MIB'),
            ('roles/sandbox.py','"max_processes": 16','"max_processes": 15'),
            ('roles/research_execution.py','timeout = 50','timeout = 49'),
            ('graph.py','MAX_FIX_ATTEMPTS = 2','MAX_FIX_ATTEMPTS = 1'),
            ('graph.py','attempts < MAX_FIX_ATTEMPTS','attempts <= MAX_FIX_ATTEMPTS'),
            ('roles/fixer.py','attempts >= 2','attempts >= 1'),
            ('roles/intermediate_repair.py','not 0 <= value["fix_attempts_before"] < 2','not 0 <= value["fix_attempts_before"] < 1'),
        )
        with self.fixture() as root:
            baseline=policy.policy_hash()
            for name,old,new in changes:
                with self.subTest(source=name,rule=old):
                    path=root/name;original=path.read_text();self.assertIn(old,original)
                    try:path.write_text(original.replace(old,new));self.assertNotEqual(baseline,policy.policy_hash())
                    finally:path.write_text(original)
            self.assertEqual(baseline,policy.policy_hash())

    def case_invalid(self):
        with self.fixture() as root:
            path=root/'roles/lease.py';original=path.read_bytes()
            for bad in (b'',b'def invalid(:',b'BASE_SECONDS = 180\n',original.replace(b'BASE_SECONDS = 180',b'BASE_SECONDS = True'),
                        original+b'BASE_SECONDS = 180\n',b'x'*(sources.MAX_SOURCE_BYTES+1)):
                path.write_bytes(bad)
                with self.assertRaisesRegex(p.BoundaryError,'POLICY_REJECTED'):policy.policy_hash()
            path.unlink()
            with self.assertRaisesRegex(p.BoundaryError,'POLICY_REJECTED'):policy.policy_hash()
            path.symlink_to(root/'roles/activity.py')
            with self.assertRaisesRegex(p.BoundaryError,'POLICY_REJECTED'):policy.policy_hash()
            path.unlink();path.write_bytes(original)
            with patch.object(sources.os,'read',side_effect=PermissionError('private detail')):
                with self.assertRaisesRegex(p.BoundaryError,'POLICY_REJECTED'):policy.policy_hash()
            cap=root/'roles/read_policy.py';cap.write_text(cap.read_text().replace('MAX_READ_FILES = 8','MAX_READ_FILES = "bad"'))
            with self.assertRaisesRegex(p.BoundaryError,'POLICY_REJECTED'):policy.policy_hash()

    def case_no_execution(self):
        with self.fixture() as root:
            path=root/'roles/lease.py';path.write_text(path.read_text()+'\nraise AssertionError("must never execute")\n')
            self.assertEqual(len(policy.policy_hash()),64)
        code="import sys; sys.path.insert(0,sys.argv[1]); from orchestrator.privilege.policy import policy_hash; policy_hash(); assert not any(n.startswith(('orchestrator.roles.', 'roles.')) for n in sys.modules)"
        result=subprocess.run([sys.executable,'-I','-c',code,str(Path.cwd())],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode()[:500])

    def case_agreement(self):
        cases=PrivilegeCases()
        with cases.fixture() as (base,e,roots,journal,backend,engine):
            server=LocalServer(base/'gateway.sock',engine).start()
            try:
                client=ControllerClient(base/'gateway.sock',e,os.getuid(),os.getgid())
                try:self.assertEqual(journal.policy,policy.policy_hash());self.assertEqual(client.probe()['mode'],'SIMULATED')
                finally:client.close()
            finally:server.close()

    def case_mismatch(self):
        cases=PrivilegeCases()
        with cases.fixture() as (base,e,roots,journal,backend,engine):
            with patch.object(journal,'policy','f'*64):
                with self.assertRaisesRegex(p.BoundaryError,'POLICY_REJECTED'):Supervisor(e,roots,backend,journal)
            server=LocalServer(base/'gateway.sock',engine).start()
            try:
                with patch('orchestrator.privilege.client.policy_hash',return_value='f'*64):
                    with self.assertRaisesRegex(p.BoundaryError,'POLICY_REJECTED'):ControllerClient(base/'gateway.sock',e,os.getuid(),os.getgid())
                self.assertFalse(engine.records)
            finally:server.close()

    def case_journals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            old=Journal(root,'0'*64);old.save([]);old.close()
            before=(root/'state.json').read_bytes();new=Journal(root,policy.policy_hash())
            try:
                with self.assertRaisesRegex(p.BoundaryError,'JOURNAL_INVALID'):new.load()
                self.assertEqual(before,(root/'state.json').read_bytes())
            finally:new.close()
        cases=LinuxCompleteCases()
        with cases.fixture() as (b,d,j,*_):
            cases.create(b);record=j.load()[0]
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);root.chmod(0o700)
                old=ResourceJournal(root,'0'*64,j.owner,uid=os.getuid())
                try:old.save([{**record,'policy':'0'*64}])
                finally:old.close()
                before=(root/'resources.json').read_bytes()
                new=ResourceJournal(root,policy.policy_hash(),j.owner,uid=os.getuid())
                try:
                    with self.assertRaisesRegex(p.BoundaryError,'JOURNAL_INVALID'):new.load()
                    self.assertEqual(before,(root/'resources.json').read_bytes())
                finally:new.close()

    def case_packaging(self):
        import tomllib
        metadata=tomllib.loads(Path('pyproject.toml').read_text())
        self.assertTrue({'orchestrator','orchestrator.roles','orchestrator.privilege'}<=set(metadata['tool']['setuptools']['packages']))
        self.assertTrue(all((sources._source_root()/name).is_file() for name in (*sources.AUTHORITATIVE,*sources.PRIVILEGE_SOURCES)))
