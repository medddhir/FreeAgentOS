"""Doctor observers are mocked: no worker, client, IPC session or generation."""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
import doctor as d
import foundation as f
from roles import model_attribution as ma


class DoctorCases(unittest.TestCase):
    def cases(self):
        # One table keeps the existing trusted runner's output cap unchanged.
        for name in ('ready', 'failures', 'configuration', 'optional', 'outputs', 'health',
                     'read_only', 'exits', 'target', 'socket_validation'):
            with self.subTest(case=name):getattr(self, name)()

    def observed(self, **overrides):
        values={'config':f.Configuration(credential_env='PROVIDER_KEY'), 'dependencies':True,
                'linux':'Linux','arch':'x86_64','usable':True,'launcher':'/usr/bin/claude',
                'health':True,'privilege':True,'socket':True,'which':'/usr/bin/tool',
                'read':'cpu memory pids\n - cgroup2 ','exists':True,'file':True}
        values.update(overrides)
        with contextlib.ExitStack() as stack:
            for name,value in [('load_config',values['config']),('dependencies_available',values['dependencies']),
                               ('usable',values['usable']),('discover_launcher',values['launcher']),
                               ('health',values['health']),('privileges_available',values['privilege']),
                               ('attribution_security',values['socket']),('read',values['read'])]:
                stack.enter_context(patch.object(d,name,return_value=value))
            stack.enter_context(patch.object(d.platform,'system',return_value=values['linux']))
            stack.enter_context(patch.object(d.platform,'machine',return_value=values['arch']))
            stack.enter_context(patch.object(d.shutil,'which',return_value=values['which']))
            stack.enter_context(patch.object(d.os.path,'isfile',return_value=values['file']))
            stack.enter_context(patch.object(d.os,'access',return_value=True))
            stack.enter_context(patch.object(d.Path,'is_file',return_value=values['file']))
            stack.enter_context(patch.object(d.Path,'exists',return_value=values['exists']))
            stack.enter_context(patch.dict(d.os.environ,{'PROVIDER_KEY':'SYNTHETIC_PRIVATE_VALUE'},clear=False))
            return d.collect()

    def ready(self):
        result=self.observed()
        # A read-only observation correctly leaves required active proofs unknown.
        self.assertEqual(result['status'],'NOT_READY')
        self.assertFalse(result['production_worker_ready'])
        checks=[dict(c,status='PASS') for c in result['checks']]
        fully_proven=d.summarize(checks)
        self.assertEqual(fully_proven['status'],'READY')
        self.assertTrue(fully_proven['production_worker_ready'])
        self.assertEqual(len(result['checks']),39)

    def failures(self):
        for kwargs,identifier in [({'dependencies':False},'runtime_dependencies'),({'file':False},'git'),
                                  ({'launcher':None},'launcher'),({'health':False},'gateway_health'),
                                  ({'privilege':False},'effective_privileges'),({'read':''},'cgroup_v2'),
                                  ({'read':'cpu\n - cgroup2 '},'cgroup_controllers'),
                                  ({'exists':False},'namespace_prerequisites'),({'usable':False},'state_directory'),
                                  ({'file':False},'bundled_resources'),({'linux':'Darwin'},'operating_system')]:
            with self.subTest(identifier=identifier):
                r=self.observed(**kwargs)
                check=next(c for c in r['checks'] if c['id']==identifier)
                self.assertEqual(check['status'],'FAIL');self.assertEqual(r['status'],'NOT_READY')
        with patch.object(d.sys,'version_info',(3,11)):
            self.assertEqual(next(c for c in self.observed()['checks'] if c['id']=='python')['status'],'FAIL')

    def configuration(self):
        for reason in ('CONFIG_MALFORMED','CONFIG_VERSION_UNSUPPORTED','CONFIG_ENDPOINT_INVALID'):
            with patch.object(d,'load_config',side_effect=f.ConfigError(reason)),patch.object(d,'health') as health:
                result=d.collect()
            self.assertEqual(next(c for c in result['checks'] if c['id']=='configuration')['reason'],reason)
            health.assert_not_called()
            self.assertEqual(result['status'],'NOT_READY')

    def optional(self):
        r=self.observed(socket=False,which=None)
        self.assertEqual(next(c for c in r['checks'] if c['id']=='attribution_socket_security')['requirement'],'OPTIONAL')
        checks=[dict(c,status='PASS') if c['requirement']=='REQUIRED' else c for c in r['checks']]
        self.assertEqual(d.summarize(checks)['status'],'READY')
        self.assertTrue(d.summarize(checks)['dimensions']['inference'])
        checks[0]['status']='FAIL'
        self.assertEqual(d.summarize(checks)['status'],'NOT_READY')

    def outputs(self):
        r=self.observed()
        for text in (d.render(r),json.dumps(r)):
            self.assertNotIn('SYNTHETIC_PRIVATE_VALUE',text)
            self.assertNotIn('PROVIDER_KEY',text)
            self.assertNotIn('ANTHROPIC_CUSTOM_HEADERS',text)
        for c in r['checks']:
            self.assertIn(c['status'],d.STATUSES);self.assertIn(c['requirement'],d.REQUIREMENTS)

    def health(self):
        with patch.object(d.http.client,'HTTPConnection') as connection:
            connection.return_value.getresponse.return_value.status=200
            self.assertTrue(d.health('http://127.0.0.1:3001'))
            connection.return_value.request.assert_called_once_with('GET','/api/ping')
            connection.return_value.close.assert_called_once()
            connection.return_value.getresponse.return_value.read.assert_not_called()
        with patch.object(d.http.client,'HTTPConnection') as connection:
            connection.return_value.request.side_effect=OSError('PRIVATE_EXCEPTION')
            self.assertFalse(d.health('http://localhost'))
        with self.assertRaises(f.ConfigError):d.health('http://remote.example')

    def read_only(self):
        import subprocess
        from roles import worker
        with patch.object(worker,'run_worker',side_effect=AssertionError('NO_WORKER')) as run,patch.object(subprocess,'Popen',side_effect=AssertionError('NO_PROCESS')) as spawn,patch.object(ma,'GatewaySession',side_effect=AssertionError('NO_SESSION')) as session:
            self.observed()
            run.assert_not_called();spawn.assert_not_called();session.assert_not_called()
        source=Path('orchestrator/doctor.py').read_text()
        for forbidden in ('shell=True','unshare(','.chown(','.chmod(',"'POST'",'run_worker('):self.assertNotIn(forbidden,source)

    def exits(self):
        for status,code in [('READY',0),('NOT_READY',1)]:
            r=d.summarize([{'id':'fixture','status':'PASS' if status=='READY' else 'FAIL','requirement':'REQUIRED','dimension':'core','reason':'FIXTURE','remediation':''}])
            with patch.object(d,'collect',return_value=r),contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(d.main(['doctor','--json']),code)
                self.assertEqual(json.loads(output.getvalue())['schema_version'],1)
        with patch.object(d,'collect',side_effect=RuntimeError('PRIVATE_EXCEPTION')),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(d.main(['doctor','--json']),2)
            self.assertNotIn('PRIVATE_EXCEPTION',output.getvalue())
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as exit:
            d.main(['unknown'])
        self.assertEqual(exit.exception.code,2)
        with contextlib.redirect_stderr(io.StringIO()) as errors,self.assertRaises(SystemExit):
            d.main(['doctor','--unrecognized','SYNTHETIC_PRIVATE_VALUE'])
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE',errors.getvalue())

    def target(self):
        with patch.object(d.Path,'is_dir',return_value=True),patch.object(d.Path,'glob',return_value=iter([Path('test_fixture.py')])),patch.object(d,'health',return_value=False):
            result=d.collect(target='/tmp/fixture')
        self.assertEqual(next(c for c in result['checks'] if c['id']=='target_tests')['status'],'PASS')

    def socket_validation(self):
        with patch.object(ma,'validate_socket_path') as validate:
            self.assertTrue(d.attribution_security(f.Configuration()))
            validate.assert_called_once_with(f.Configuration().attribution_socket)
        with patch.object(ma,'validate_socket_path',side_effect=ValueError('PRIVATE_EXCEPTION')):
            self.assertFalse(d.attribution_security(f.Configuration()))
