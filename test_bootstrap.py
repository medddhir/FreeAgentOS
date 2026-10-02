"""Bounded bootstrap contract cases; all installs here are mocked, no inference."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parent/'orchestrator'))
import bootstrap as b


class BootstrapCases(unittest.TestCase):
    def cases(self):
        source = Path(__file__).parent.resolve()
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp)/'home';home.mkdir()
            env={'HOME':str(home),'PATH':'/usr/bin:/bin'}
            with patch.dict(os.environ,env,clear=True), patch.object(b.os,'geteuid',return_value=os.getuid()), patch.object(b,'platform_id',return_value='linux-ubuntu-24.04'):
                # Root rejection is independent of all other prerequisites.
                with patch.object(b.os,'geteuid',return_value=0):
                    with self.assertRaisesRegex(b.BootstrapError,''):b.install(source)
                with patch.object(b.os,'geteuid',return_value=1000):
                    dry=b.install(source,True)
                self.assertEqual(dry['installation'],'DRY_RUN');self.assertEqual(list(home.iterdir()),[])
                self.assertNotIn('/root',dry['install_root'])
                with patch.object(b.os,'geteuid',return_value=1000), patch.object(b.sys,'version_info',(3,11)):
                    with self.assertRaises(b.BootstrapError) as error:b.install(source)
                    self.assertEqual(error.exception.reason,'PYTHON_UNSUPPORTED')
                with patch.object(b.os,'geteuid',return_value=1000), patch.object(b.shutil,'which',return_value=None):
                    with self.assertRaises(b.BootstrapError) as error:b.install(source)
                    self.assertEqual(error.exception.reason,'GIT_MISSING')
                with patch.object(b.os,'geteuid',return_value=1000), patch('importlib.util.find_spec',return_value=None):
                    with self.assertRaises(b.BootstrapError) as error:b.install(source)
                    self.assertEqual(error.exception.reason,'VENV_SUPPORT_MISSING')
                with patch.dict(os.environ, {'XDG_DATA_HOME':str(home/'xdg-data'), 'XDG_STATE_HOME':str(home/'xdg-state')}):
                    self.assertEqual(b.layout()[1],home/'xdg-data/freeagentos/installation')
                    self.assertEqual(b.layout()[0].state,home/'xdg-state/freeagentos')
                paths,root,venv,command=b.layout()
                paths.config.mkdir(parents=True);config=paths.config/'config.toml';config.write_text('config_version=1\n')
                # Pretend to be a normal user owning the test directories.
                uid=os.getuid() or 1000
                def create(_self,dest):
                    (dest/'bin').mkdir(parents=True);(dest/'bin/freeagent').write_text('fixture');(dest/'bin/python').write_text('fixture')
                with patch.object(b.os,'geteuid',return_value=uid),patch.object(b.Path,'stat',autospec=True) as stat,patch.object(b.venv.EnvBuilder,'create',create),patch.object(b,'execute') as execute,patch.object(b,'doctor',return_value='NOT_READY'):
                    # Delegate stat, replacing ownership only (never production).
                    original=os.stat
                    stat.side_effect=lambda p,**kw: type('Stat',(),{'st_uid':uid,'st_mode':original(p,**kw).st_mode})()
                    result=b.install(source)
                    self.assertEqual(result['installation'],'SUCCESS');self.assertEqual(result['doctor'],'NOT_READY')
                    self.assertTrue(command.is_symlink());self.assertTrue(venv.exists())
                    calls=[c.args[0] for c in execute.call_args_list]
                    self.assertTrue(any('requirements.lock' in ' '.join(c) and 'requirements-build.lock' in ' '.join(c) for c in calls))
                    self.assertTrue(any(c[-2:]==['pip','check'] for c in calls))
                    self.assertFalse(any('sudo' in c for c in calls))
                    self.assertEqual(b.install(source)['installation'],'ALREADY_INSTALLED')
                    self.assertEqual(config.read_bytes(),b'config_version=1\n')
                    self.assertFalse((home/'.bashrc').exists())
                # Failed fresh install must not publish a launcher, or erase config.
                command.unlink();import shutil;shutil.rmtree(root)
                with patch.object(b.os,'geteuid',return_value=uid),patch.object(b.Path,'stat',autospec=True) as stat,patch.object(b.venv.EnvBuilder,'create',create),patch.object(b,'execute',side_effect=b.BootstrapError(5,'DEPENDENCY_INSTALL_FAILED')):
                    stat.side_effect=lambda p,**kw: type('Stat',(),{'st_uid':uid,'st_mode':os.stat(p,**kw).st_mode})()
                    with self.assertRaises(b.BootstrapError):b.install(source)
                    self.assertFalse(command.exists());self.assertFalse(root.exists());self.assertTrue(config.exists())
                with patch.object(b.os,'geteuid',return_value=1000),patch.object(b.Path,'mkdir',side_effect=PermissionError):
                    with self.assertRaises(PermissionError):b.install(source)
                    self.assertFalse(command.exists())
                command.write_text('existing user launcher')
                with patch.object(b.os,'geteuid',return_value=1000):
                    with self.assertRaises(b.BootstrapError) as error:b.install(source)
                    self.assertEqual(error.exception.reason,'LAUNCHER_CONFLICT')
                self.assertEqual(command.read_text(),'existing user launcher')
        with patch.object(b.platform,'system',return_value='Darwin'):
            with self.assertRaises(b.BootstrapError):b.platform_id()
        with patch.object(b.platform,'system',return_value='Linux'),patch.object(b.platform,'machine',return_value='x86_64'),patch.object(b.platform,'freedesktop_os_release',return_value={'ID':'ubuntu','VERSION_ID':'24.04'}):
            with patch.object(b.platform,'release',return_value='6.6-microsoft-standard-WSL2'):self.assertEqual(b.platform_id(),'linux-wsl2')
            with patch.object(b.platform,'release',return_value='6.8-generic'):self.assertEqual(b.platform_id(),'linux-ubuntu-24.04')

        code=(source/'orchestrator/bootstrap.py').read_text()
        for forbidden in ('shell=True','run_worker(', 'sudo ', '/usr/local/bin', 'claude-free'):
            self.assertNotIn(forbidden,code)
        self.assertNotIn('requirements', (source/'install.sh').read_text())
