"""Non-privileged Linux preparation regression table."""
import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock, mock_open
from orchestrator.privilege import linux as l
from orchestrator.privilege.protocol import BoundaryError
from orchestrator.privilege.policy import policy_hash, CLASSES
from orchestrator.privilege.supervisor import Supervisor

class LinuxPreparationCases(unittest.TestCase):
    def cases(self):
        for case in ('import','paths','plan','deadlines','cgroups','recovery','executable','platform','gating','child'):
            with self.subTest(case=case):getattr(self,'case_'+case)()

    def case_import(self):
        with patch('os.mkdir',side_effect=AssertionError),patch('os.chroot',side_effect=AssertionError),patch('os.setuid',side_effect=AssertionError),patch('ctypes.CDLL',side_effect=AssertionError):
            importlib.reload(l)

    def case_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'file').write_text('safe');(root/'link').symlink_to(root/'file')
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            try:
                child=l.secure_open(fd,'file')
                self.assertFalse(os.get_inheritable(child));os.close(child)
                for value in ('../file','/etc/passwd','link','./file','a//b','x\0y'):
                    with self.assertRaises(BoundaryError):l.secure_open(fd,value)
                with patch.object(l.ctypes,'CDLL') as lib:
                    lib.return_value.syscall.return_value=-1
                    self.assertFalse(l.path_primitive_available(fd,'file'))
                self.assertEqual(l.RESOLVE,15)
            finally:os.close(fd)

    def case_plan(self):
        a=l.execution_plan('MODEL_WORKER','coder',65534,65534)
        self.assertEqual(a['limits']['wall_timeout_seconds'],240)
        self.assertLess(a['order'].index('SET_UID'),a['order'].index('EXEC_PINNED_CLASS'))
        self.assertLess(a['order'].index('CLEAR_CAPSET'),a['order'].index('EXEC_PINNED_CLASS'))
        self.assertLess(a['order'].index('NO_NEW_PRIVS'),a['order'].index('EXEC_PINNED_CLASS'))
        self.assertEqual(a['devices'],('null','zero','random','urandom'))
        self.assertNotIn('LD_PRELOAD',a['environment'])
        self.assertNotIn('PYTHONPATH',a['environment'])
        for uid in (0,-1,True):
            with self.assertRaises(BoundaryError):l.execution_plan('MODEL_WORKER','coder',uid,1)
        for field in ('memory_limit_bytes','cpu_quota_us','max_processes'):
            with self.assertRaises(BoundaryError):l.execution_plan('MODEL_WORKER','coder',1,1,{field:CLASSES['MODEL_WORKER'].limits[field]+1})
        with self.assertRaises(TypeError):l.execution_plan('MODEL_WORKER','coder',1,1,mounts=[])
        with self.assertRaises(TypeError):l.execution_plan('MODEL_WORKER','coder',1,1,executable='/bin/sh')
        with self.assertRaises(TypeError):l.MOUNT_RECIPES['new']=()

    def case_deadlines(self):
        now=[0];d=l.Deadline(lambda:now[0]);now[0]=179
        self.assertFalse(d.expired());d.grant_grace(True)
        now[0]=239;self.assertFalse(d.expired());now[0]=240;self.assertTrue(d.expired())
        self.assertTrue(l.Deadline(lambda:0).expired(False))
        d=l.Deadline(lambda:0)
        with self.assertRaises(BoundaryError):d.grant_grace('model says active')
        now=[0];d=l.Deadline(lambda:now[0]);now[0]=180;self.assertTrue(d.expired())

    def case_cgroups(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY)
            cg=l.OwnedCgroup(fd)
            try:
                with patch('os.mkdir',side_effect=AssertionError),patch('os.write',side_effect=AssertionError):
                    with self.assertRaisesRegex(BoundaryError,'RECOVERY_REQUIRED'):cg.create('a'*32,'MODEL_WORKER','coder')
                    with self.assertRaisesRegex(BoundaryError,'RECOVERY_REQUIRED'):cg.terminate('a'*32)
                self.assertEqual(list(Path(tmp).iterdir()),[])
            finally:cg.close();os.close(fd)

    def case_recovery(self):
        r={'version':1,'handle':'a'*32,'policy':policy_hash(),'boot_id':'fixture','state':'RUNNING','recipe':'MODEL_WORKER'}
        plan=l.recovery_plan(r,policy_hash(),'fixture')
        self.assertEqual(plan[0],'VERIFY_OWNED_SCOPE')
        for key,value in [('version',2),('boot_id','foreign'),('handle','../../host'),('recipe','host')]:
            with self.assertRaises(BoundaryError):l.recovery_plan({**r,key:value},policy_hash(),'fixture')
        with self.assertRaises(BoundaryError):l.recovery_plan({**r,'pid':123},policy_hash(),'fixture')

    def case_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'worker';p.write_bytes(b'harmless fixture');p.chmod(0o700)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                # Privileged executable enrollment requires real root ownership;
                # unprivileged tests explicitly assert rejection instead.
                if os.getuid()!=0:
                    with self.assertRaises(BoundaryError):l.PinnedFile.executable(fd,'worker')
                else:
                    pinned=l.PinnedFile.executable(fd,'worker')
                    try:
                        pinned.verify();p.write_bytes(b'replacement')
                        with self.assertRaises(BoundaryError):pinned.verify()
                        self.assertFalse(os.get_inheritable(pinned.fd))
                    finally:os.close(pinned.fd)
            finally:os.close(fd)

    def case_platform(self):
        with patch.object(l.platform,'system',return_value='Windows'):
            self.assertFalse(l.platform_report()['reference_platform'])
            with self.assertRaises(BoundaryError):l.secure_open(0,'file')
        self.assertEqual(l.platform_report()['enforcement'],'UNPROVEN')

    def case_gating(self):
        backend=l.LinuxIsolationBackend()
        with self.assertRaisesRegex(BoundaryError,'RECOVERY_REQUIRED'):backend.prepare()
        with self.assertRaisesRegex(BoundaryError,'POLICY_REJECTED'):Supervisor(None,None,backend,None)
        self.assertFalse(backend.simulation_only)

    def case_child(self):
        child=l.ChildSetup()
        with patch('os.setuid',side_effect=AssertionError),patch('os.setgid',side_effect=AssertionError),patch('ctypes.CDLL',side_effect=AssertionError):
            with self.assertRaises(BoundaryError):child.namespaces()
            with self.assertRaises(BoundaryError):child.drop_identity(1,1)
        with patch('os.getpid',return_value=child.parent_pid+1),patch.object(child,'_libc') as lib:
            lib.return_value.unshare.return_value=0
            child.namespaces()
            self.assertEqual(child.stage,'PID_FORK_REQUIRED')
            with self.assertRaisesRegex(BoundaryError,'RECOVERY_REQUIRED'):child.pid_namespace_child()
            with self.assertRaises(BoundaryError):child.drop_identity(1,1)

        child=l.ChildSetup();child.stage='ROOTFS_READY'
        events=[];lib=Mock();lib.prctl.return_value=0;lib.capset.side_effect=lambda *a:events.append('capset') or 0
        with patch('os.getpid',return_value=child.parent_pid+1),patch.object(child,'_libc',return_value=lib),patch('builtins.open',mock_open(read_data='40')),patch('os.setgroups',side_effect=lambda a:events.append('groups')),patch('os.setgid',side_effect=lambda a:events.append('gid')),patch('os.setuid',side_effect=lambda a:events.append('uid')),patch('os.getuid',return_value=123),patch('os.geteuid',return_value=123),patch('os.getgid',return_value=456),patch('os.getegid',return_value=456):
            child.drop_identity(123,456)
        self.assertEqual(events,['groups','gid','uid','capset'])
        self.assertEqual(child.stage,'DROPPED')
        self.assertIn(((38,1,0,0,0),{}),[(c.args,c.kwargs) for c in lib.prctl.call_args_list])
