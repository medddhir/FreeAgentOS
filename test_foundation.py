"""No-generation portable foundation contracts."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
import foundation as f
from roles import model_profiles as mp, model_attribution as ma, worker


class FoundationTests(unittest.TestCase):
    def test(self):
        # Compact table, matching existing tests and retaining the 64 KiB runner cap.
        for name in ['case_paths', 'case_xdg', 'case_overrides', 'case_resources', 'case_absent', 'case_version', 'case_malformed', 'case_precedence', 'case_launchers', 'case_structured_command', 'case_endpoints', 'case_socket_trust', 'case_model_configuration', 'case_credentials', 'case_gitignore', 'case_no_policy_changes', 'case_configured_health', 'case_alternate_launcher_attribution', 'case_disabled_attribution', 'case_portable_helpers', 'case_worker_environment']:
            with self.subTest(case=name):
                getattr(self, name)()
        # Extend the same bounded foundation table with observer regressions.
        from test_doctor import DoctorCases
        with self.subTest(case="doctor"):
            DoctorCases().cases()
        from test_bootstrap import BootstrapCases
        with self.subTest(case="bootstrap"):
            BootstrapCases().cases()

    def config(self, text, env=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.toml'; path.write_text(text)
            return f.load_config(path, env=env or {'HOME': '/home/example'})

    def case_paths(self):
        p = f.user_paths({'HOME': '/home/example'})
        self.assertEqual(p.config, Path('/home/example/.config/freeagentos'))
        self.assertEqual(p.data, Path('/home/example/.local/share/freeagentos'))
        self.assertEqual(p.cache, Path('/home/example/.cache/freeagentos'))
        self.assertEqual(p.state, Path('/home/example/.local/state/freeagentos'))
        self.assertNotIn('/root', str(p))

    def case_xdg(self):
        for name in ('CONFIG', 'DATA', 'CACHE', 'STATE'):
            p=f.user_paths({'HOME':'/home/example', 'XDG_'+name+'_HOME':'/tmp/xdg'})
            self.assertEqual(getattr(p,name.lower()),Path('/tmp/xdg/freeagentos'))

    def case_overrides(self):
        for name in ('CONFIG','DATA','CACHE','STATE'):
            p=f.user_paths({'HOME':'/home/example','XDG_'+name+'_HOME':'/tmp/xdg','FREEAGENTOS_'+name+'_HOME':'/tmp/chosen'})
            self.assertEqual(getattr(p,name.lower()),Path('/tmp/chosen'))
        with self.assertRaises(f.ConfigError):f.user_paths({'HOME':'relative'})

    def case_resources(self):
        self.assertTrue(f.bundled_data('public_apis.json').is_file())
        self.assertTrue(f.bundled_tool('dev-intel').is_file())
        with self.assertRaises(f.ConfigError):f.bundled_data('../private')
        # Namespace resources may be MultiplexedPath: resolve a concrete child.
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/'packaged';directory.mkdir()
            resource=Mock();resource.joinpath.return_value=directory/'freeagent-test'
            with patch.object(f,'__file__',str(Path(tmp)/'missing/foundation.py')),patch.object(f,'files',return_value=resource):
                self.assertEqual(f.bundled_tools_root(),directory)
                self.assertEqual(f.bundled_tool('dev-intel'),directory/'dev-intel')

    def case_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=f.load_config(env={'HOME':tmp})
        self.assertEqual(c,f.Configuration())

    def case_version(self):
        self.assertEqual(self.config('config_version = 1').version,1)
        for s in ['config_version = 2','config_version = true','config_version = "1"','']:
            with self.assertRaises(f.ConfigError):self.config(s)

    def case_malformed(self):
        with self.assertRaisesRegex(f.ConfigError,'CONFIG_MALFORMED'):self.config('[')
        for s in ['[security]\nread_files = ["all"]','[adapter]\nargs=["--dangerous"]','[attribution]\nenabled="yes"']:
            with self.assertRaises(f.ConfigError):self.config('config_version=1\n'+s)

    def case_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/'a';b=Path(tmp)/'b'
            a.write_text('config_version=1\n[adapter]\nlauncher="selected"')
            b.write_text('config_version=1')
            self.assertEqual(f.load_config(a,env={'HOME':tmp,'FREEAGENTOS_CONFIG':str(b)}).launcher,'selected')
            self.assertEqual(f.load_config(env={'HOME':tmp,'FREEAGENTOS_CONFIG':str(b)}).launcher,'claude-free')
        with self.assertRaisesRegex(f.ConfigError,'CONFIG_NOT_FOUND'):f.load_config('/tmp/no-such-freeagentos-config')

    def case_launchers(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable=Path(tmp)/'test-launcher';executable.write_text('#!/bin/sh\nexit 0\n');executable.chmod(0o700)
            with patch.dict(os.environ, {'PATH':tmp}):
                self.assertEqual(f.discover_launcher(f.Configuration(launcher='test-launcher')),str(executable))
                self.assertEqual(f.discover_launcher(f.Configuration(launcher=str(executable))),str(executable))
                with self.assertRaisesRegex(f.ConfigError,'ADAPTER_LAUNCHER_UNAVAILABLE'):f.discover_launcher(f.Configuration(launcher='absent'))
        for v in ['relative/file','shell;command','']:
            with self.assertRaises(f.ConfigError):self.config('config_version=1\n[adapter]\nlauncher='+repr(v).replace("'",'"'))

    def case_structured_command(self):
        c=self.config('config_version=1\n[adapter]\nlauncher="/opt/adapter executable"')
        with f.config_scope(c),mp.profile_scope():
            cmd=mp.model_command('coder',['--tools',''], 'text; $(command)')
            self.assertEqual(cmd[0],'/opt/adapter executable');self.assertEqual(cmd[-1],'text; $(command)')
            self.assertEqual(mp.command_identity(cmd,'coder')['requested_model_id'],'CLIENT_DEFAULT')

    def case_endpoints(self):
        for v in ['http://127.0.0.1:3001','https://localhost:443','http://[::1]:3001']:
            self.assertEqual(f.local_endpoint(v),v)
        for v in ['http://0.0.0.0:3001','http://example.com','file:///tmp/gateway','http://user:password@localhost','http://localhost?token=value','http://localhost:0','http://localhost/v1']:
            with self.assertRaises(f.ConfigError):f.local_endpoint(v)

    def case_socket_trust(self):
        c=self.config('config_version=1\n[attribution]\nsocket="/tmp/private/gateway.sock"')
        with f.config_scope(c):
            session=ma.GatewaySession();self.assertEqual(session.path,c.attribution_socket);self.assertEqual(session.uid,1000)
        with self.assertRaises(f.ConfigError):self.config('config_version=1\n[attribution]\nsocket="relative"')
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'not-a-socket';path.write_text('')
            session=ma.GatewaySession(path,os.getuid())
            with self.assertRaisesRegex(ValueError,'ATTRIBUTION_PEER_INVALID'):session._exchange('register')

    def case_model_configuration(self):
        c=self.config('config_version=1\n[models]\ncoder="claude-free-gpt-oss-120b"')
        with f.config_scope(c),mp.profile_scope():self.assertEqual(mp.selected_profile('coder').model_id,'openai/gpt-oss-120b')
        with f.config_scope(c),mp.profile_scope({'coder':'claude-free-default'}):self.assertIsNone(mp.selected_profile('coder').model_id)
        for v in ['unknown','research-tools']:
            with self.assertRaisesRegex(f.ConfigError,'CONFIG_MODEL_PROFILE_INVALID'):self.config(f'config_version=1\n[models]\ncoder="{v}"')

    def case_credentials(self):
        c=self.config('config_version=1\n[adapter]\ncredential_env="PROVIDER_KEY"')
        self.assertEqual(c.credential_env,'PROVIDER_KEY')
        env=f.adapter_environment({'PROVIDER_KEY':'synthetic'}, {'endpoint':c.endpoint,'credential_env':c.credential_env})
        self.assertEqual(env['ANTHROPIC_AUTH_TOKEN'],'synthetic')
        with self.assertRaisesRegex(f.ConfigError,'ADAPTER_CREDENTIAL_UNAVAILABLE'):f.adapter_environment({}, {'endpoint':c.endpoint,'credential_env':c.credential_env})
        example=Path('examples/config.toml').read_text()
        self.assertNotIn('AUTH_TOKEN =', example)
        for forbidden in ['api_key','token','password']:
            with self.assertRaises(f.ConfigError):self.config(f'config_version=1\n[adapter]\n{forbidden}="synthetic"')

    def case_gitignore(self):
        for name in ['.freeagentos/auth-token','freeagentos-credentials.json','freeagentos.local.toml']:
            self.assertEqual(subprocess.run(['git','check-ignore','-q',name]).returncode,0)
        self.assertNotEqual(subprocess.run(['git','check-ignore','-q','examples/config.toml']).returncode,0)

    def case_no_policy_changes(self):
        from roles.lease import ActivityLease
        from roles.sandbox import RESOURCE_POLICY
        before=(dict(worker.WORKER_POLICY),dict(RESOURCE_POLICY))
        c=self.config('config_version=1\n[adapter]\nlauncher="claude"\n[attribution]\nenabled=false')
        with f.config_scope(c):
            self.assertTrue(worker._model_command(['claude','-p','x']))
            self.assertFalse(worker._model_command(['curl']))
        self.assertEqual(before,(worker.WORKER_POLICY,RESOURCE_POLICY))

    def case_configured_health(self):
        c=f.Configuration(endpoint='http://localhost:4321')
        with f.config_scope(c),patch.object(worker.http.client,'HTTPConnection') as client:
            client.return_value.getresponse.return_value.status=200
            self.assertEqual(worker._gateway_health()['gateway_health_status'],'HEALTHY')
            client.assert_called_once_with('localhost',4321,timeout=.75)
            client.return_value.request.assert_called_once_with('GET','/health')

    def case_alternate_launcher_attribution(self):
        from types import SimpleNamespace
        c=f.Configuration(launcher='claude')
        with f.config_scope(c),patch.object(ma,'GatewaySession') as session,patch.object(worker,'_run_worker_impl') as impl:
            session.return_value.diagnostics=ma.diagnostic_defaults()
            session.return_value.finish.return_value=ma.route_observation(None,'')
            impl.return_value=SimpleNamespace(evidence={})
            r=worker.run_worker(['claude','-p','synthetic'],role='coder')
            session.return_value.begin.assert_called_once()
            session.return_value.finish.assert_called_once()
            self.assertEqual(r.evidence['gateway_attribution']['routed_evidence'],'UNAVAILABLE')
            self.assertIn('attribution_diagnostics',r.evidence)

    def case_disabled_attribution(self):
        from types import SimpleNamespace
        with f.config_scope(f.Configuration(attribution_enabled=False)),patch.object(ma,'GatewaySession') as session,patch.object(worker,'_run_worker_impl') as impl:
            impl.return_value=SimpleNamespace(evidence={})
            r=worker.run_worker(['claude-free','-p','synthetic'],role='coder')
            session.assert_not_called()
            self.assertFalse(r.evidence['attribution_diagnostics']['registration_attempted'])

    def case_portable_helpers(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'bin').mkdir();(root/'orchestrator').mkdir();(root/'data').mkdir()
            shutil.copyfile('orchestrator/foundation.py',root/'orchestrator/foundation.py')
            for name in ['dev-intel','prompt-intel']:
                shutil.copyfile('bin/'+name,root/'bin'/name)
            for name in ['public_apis.json','buildx.json','prompt_patterns.json']:
                shutil.copyfile('data/'+name,root/'data'/name)
            for args in [('dev-intel','api','weather'),('prompt-intel','testing')]:
                r=subprocess.run([sys.executable,str(root/'bin'/args[0]),*args[1:],'--limit','1','--json'],cwd=tmp,capture_output=True)
                self.assertEqual(r.returncode,0,r.stderr.decode())

    def case_worker_environment(self):
        request={'adapter_settings':{'endpoint':'http://localhost:4321','credential_env':None}}
        with patch.dict(os.environ,{},clear=True):
            env=worker._worker_environment(request)
        self.assertEqual(env['ANTHROPIC_BASE_URL'],'http://localhost:4321')
        self.assertNotIn('ANTHROPIC_AUTH_TOKEN',env)
