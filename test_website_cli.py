"""Real CLI subprocesses: recorded preparation only, no generated execution."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).parent.resolve()
PYTHON = ROOT/'.venv-orchestrator/bin/python3'

class WebsiteCLITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='freeagent-website-cli-')
        self.addCleanup(self.temp.cleanup)
        self.parent=Path(self.temp.name);self.parent.chmod(0o700)
        self.args=['recorded-website','--staging-parent',str(self.parent),'--title','Local Studio',
                   '--heading','Build locally','--button','See more','--revision-heading','Revised page',
                   '--revision-button','Explore details','--design','Warm neutral palette','--confirmed','--json']
    def run_cli(self,args=None,bridge=False):
        env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1'
        env['FREEAGENTOS_CONFIG_HOME']=str(self.parent/'absent-config')
        if bridge:
            env['PYTHONPATH']=str(ROOT)
            command=[str(PYTHON),'-c','from orchestrator.entrypoint import main; raise SystemExit(main())']
        else:command=[str(PYTHON),str(ROOT/'orchestrator/cli.py')]
        return subprocess.run(command+(self.args if args is None else args),cwd=self.parent,env=env,
                              capture_output=True,text=True,timeout=15)
    def test_success_complete_exact_export_revision_and_receipt(self):
        result=self.run_cli();self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        value=json.loads(result.stdout);self.assertEqual(value['operation'],'RECORDED_PREPARATION')
        self.assertEqual(value['status'],'PREPARATION_COMPLETE');self.assertEqual(value['model_calls'],'NONE')
        self.assertFalse(value['live_qualified']);self.assertNotEqual(value['before_snapshot'],value['after_snapshot'])
        self.assertEqual(value['checks']['functional'],'UNPROVEN');self.assertEqual(value['checks']['browser'],'UNPROVEN')
        self.assertEqual(value['preview']['execution'],'DISABLED')
        self.assertEqual(value['checks']['snapshot_sha256'],value['after_snapshot'])
        self.assertEqual(value['export_manifest']['snapshot_sha256'],value['after_snapshot'])
        project=Path(value['workspace']);export=Path(value['export'])
        self.assertEqual(project.parent.parent,self.parent);self.assertEqual(export,project.parent/'export')
        expected={'index.html':('<!doctype html><html><head><meta charset="utf-8"><title>Local Studio</title>'
                 '<link rel="stylesheet" href="styles.css"></head><body><main><h1>Revised page</h1>'
                 '<button id="more">Explore details</button><p id="detail" hidden>Made locally.</p>'
                 '</main><script src="app.js"></script></body></html>').encode(),
                 'styles.css':b'body { background: #faf8f2; color: #232323; margin: 2rem; } button { padding: 1rem; }',
                 'app.js':b'document.querySelector("#more").addEventListener("click", () => { document.querySelector("#detail").hidden = false; });',
                 'README.md':b'Recorded static website preparation.\nDesign brief: Warm neutral palette\nFunctional/browser qualification: UNPROVEN.\n'}
        self.assertEqual({p.name for p in export.iterdir()},set(expected)|{'export.json'})
        for name,raw in expected.items():
            self.assertEqual((project/name).read_bytes(),raw);self.assertEqual((export/name).read_bytes(),raw)
            self.assertEqual(value['export_manifest']['files'][name],hashlib.sha256(raw).hexdigest())
        self.assertEqual(json.loads((export/'export.json').read_text()),value['export_manifest'])
        # New invocation has a new owned run; it never overwrites prior export.
        second=self.run_cli();self.assertEqual(second.returncode,0,second.stderr)
        self.assertNotEqual(json.loads(second.stdout)['export'],str(export))
        self.assertEqual((export/'index.html').read_bytes(),expected['index.html'])
    def test_help_text_and_entrypoint_bridge(self):
        help_result=self.run_cli(['recorded-website','--help'])
        self.assertEqual(help_result.returncode,0);self.assertIn('Recorded preparation only',help_result.stdout)
        self.assertIn('<owned-run>/export',help_result.stdout)
        args=self.args[:-1];result=self.run_cli(args,bridge=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('OPERATION=RECORDED_PREPARATION',result.stdout)
        self.assertIn('EXPORT=',result.stdout);self.assertIn('FUNCTIONAL=UNPROVEN',result.stdout)
    def test_invalid_inputs_and_separate_export_rejected_without_run(self):
        for change in ('unconfirmed','unchanged','oversized','extra_export'):
            with self.subTest(case=change):
                args=self.args.copy()
                if change=='unconfirmed':args.remove('--confirmed')
                elif change=='unchanged':
                    args[args.index('--revision-heading')+1]='Build locally';args[args.index('--revision-button')+1]='See more'
                elif change=='oversized':args[args.index('--title')+1]='x'*513
                else:args+=['--export-destination',str(self.parent/'elsewhere')]
                result=self.run_cli(args);self.assertNotEqual(result.returncode,0)
                self.assertNotIn('PREPARATION_COMPLETE',result.stdout)
                self.assertEqual(list(self.parent.iterdir()),[])
    def test_path_rejections(self):
        link=self.parent/'link';link.symlink_to(self.parent,target_is_directory=True)
        file=self.parent/'file';file.write_text('untouched')
        unsafe=self.parent/'unsafe';unsafe.mkdir(mode=0o755)
        for value in ('relative',str(self.parent/'..'/self.parent.name),str(link),str(file),str(unsafe),str(self.parent/'absent')):
            with self.subTest(case='path'):
                args=self.args.copy();args[args.index('--staging-parent')+1]=value
                result=self.run_cli(args);self.assertNotEqual(result.returncode,0)
                self.assertNotIn('PREPARATION_COMPLETE',result.stdout)
        self.assertEqual(file.read_text(),'untouched');self.assertFalse(any(p.name.startswith('freeagentos-website-') for p in self.parent.iterdir()))
    def test_preparation_cannot_call_live_boundaries(self):
        # Actual CLI main, guarded in a fresh subprocess after trusted imports.
        code='''import sys
sys.path.insert(0,sys.argv.pop(1))
import cli,foundation
from roles import worker,preflight
from unittest.mock import patch
with patch.object(foundation,'load_config',side_effect=AssertionError('config read')), patch.object(worker,'run_worker',side_effect=AssertionError('worker')), patch.object(preflight,'check_host',side_effect=AssertionError('preflight')), patch('subprocess.Popen',side_effect=AssertionError('process')):
 raise SystemExit(cli.main())
'''
        result=subprocess.run([str(PYTHON),'-c',code,str(ROOT/'orchestrator'),*self.args],cwd=self.parent,
                              capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)

    def test_ignores_production_configuration_and_escapes_input_text(self):
        config=self.parent/'absent-config';config.mkdir(mode=0o700)
        (config/'config.toml').write_text('invalid = [')
        args=self.args.copy();args[args.index('--title')+1]='Local <script> Studio'
        result=self.run_cli(args)
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        exported=Path(json.loads(result.stdout)['export'])
        self.assertIn('Local &lt;script&gt; Studio',(exported/'index.html').read_text())

    def test_failure_artifact_lifecycle_and_safe_reporting(self):
        for case,expected_exit,state,reason in (
                ('before',3,'NOT_CREATED','RECORDED_WEBSITE_USAGE_INVALID'),
                ('check',2,'RETAINED','PROTECTED_CHECK_FAILED'),
                ('policy',2,'RETAINED','RECORDED_WEBSITE_POLICY_REJECTED')):
            for json_mode in (True,False):
                with self.subTest(case=case,json=json_mode):
                    parent=self.parent/(case+str(json_mode));parent.mkdir(mode=0o700)
                    args=self.args.copy();args[args.index('--staging-parent')+1]=str(parent)
                    if not json_mode:args.remove('--json')
                    if case=='before':args.remove('--confirmed')
                    if case=='check':args[args.index('--heading')+1]=' Build locally '
                    if case=='policy':args[args.index('--title')+1]='Secret garden'
                    result=self.run_cli(args)
                    self.assertEqual(result.returncode,expected_exit,result.stderr+result.stdout)
                    self.assertNotIn('PREPARATION_COMPLETE',result.stdout)
                    self.assertNotIn('Secret garden',result.stdout+result.stderr)
                    self.assertNotIn('Traceback',result.stderr)
                    cleanup='NONE' if state=='NOT_CREATED' else 'RETAINED'
                    if json_mode:
                        value=json.loads(result.stdout)
                        self.assertEqual(value['artifact_state'],state)
                        self.assertEqual(value['workspace_cleanup'],cleanup)
                        self.assertFalse(value['cleanup_attempted']);self.assertFalse(value['live_qualified'])
                        self.assertEqual(value['block_reason'],reason)
                        self.assertEqual(value['status'],'INVALID_INPUT' if case=='before' else 'BLOCKED')
                    else:
                        self.assertIn('ARTIFACT_STATE='+state,result.stdout)
                        self.assertIn('WORKSPACE_CLEANUP='+cleanup,result.stdout)
                        self.assertIn('CLEANUP_ATTEMPTED=false',result.stdout)
                        self.assertIn('BLOCK_REASON='+reason,result.stdout)
                    runs=list(parent.iterdir())
                    if case=='before':self.assertEqual(runs,[])
                    else:
                        self.assertEqual(len(runs),1);self.assertFalse((runs[0]/'export').exists())
                        self.assertEqual({p.name for p in (runs[0]/'project').iterdir()},
                                         {'index.html','styles.css','app.js','README.md'})
                        if case=='policy':
                            self.assertEqual((runs[0]/'project/index.html').read_bytes(),b'')
                        else:self.assertIn(b' Build locally ',(runs[0]/'project/index.html').read_bytes())

    def test_partial_constructor_or_uncertain_identity_remains_unproven(self):
        for case in ('partial_constructor','identity_failure','unexpected_before'):
            with self.subTest(case=case):
                parent=self.parent/case;parent.mkdir(mode=0o700)
                args=self.args.copy();args[args.index('--staging-parent')+1]=str(parent)
                code="import sys\nsys.path.insert(0,sys.argv.pop(1))\ncase=sys.argv.pop(1)\nimport cli,website\nfrom unittest.mock import patch\nif case=='partial_constructor':\n def fail(self,brief,parent):\n  from pathlib import Path\n  (Path(parent)/'partial-owned-run').mkdir(mode=0o700)\n  raise OSError('uncontrolled diagnostic must not escape')\n target=patch.object(website.Session,'__init__',fail)\nelif case=='identity_failure':\n target=patch.object(website.Session,'assert_root',side_effect=OSError('uncontrolled diagnostic must not escape'))\nelse:\n target=patch.object(website,'recorded_site_adapter',side_effect=RuntimeError('uncontrolled diagnostic must not escape'))\nwith target:\n raise SystemExit(cli.main())\n"
                result=subprocess.run([str(PYTHON),'-c',code,str(ROOT/'orchestrator'),case,*args],
                                      cwd=parent,capture_output=True,text=True,timeout=15)
                value=json.loads(result.stdout)
                self.assertEqual(result.returncode,4 if case=='unexpected_before' else 2)
                expected='NOT_CREATED' if case=='unexpected_before' else 'UNPROVEN'
                self.assertEqual(value['artifact_state'],expected)
                self.assertEqual(value['workspace_cleanup'],'NONE' if expected=='NOT_CREATED' else 'UNPROVEN')
                self.assertFalse(value['cleanup_attempted'])
                self.assertNotIn('uncontrolled diagnostic',result.stdout+result.stderr)
                self.assertNotIn('PREPARATION_COMPLETE',result.stdout)
                self.assertEqual(len(list(parent.iterdir())),0 if case=='unexpected_before' else 1)
