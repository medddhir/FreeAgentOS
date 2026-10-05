"""Offline wheel/installed-console preparation checks; no live qualification."""
import base64
import configparser
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent
BUILD_PYTHON = '/usr/bin/python3.12'


def run(args, cwd, env, timeout=60):
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if len(result.stdout) > 65536:
        raise AssertionError('PACKAGING_OUTPUT_BOUND')
    return result


class InstalledPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = os.environ.get('FREEAGENT_PACKAGE_FIXTURE_PYTHON', '')
        cls.fixture = Path(fixture)
        if not fixture or not cls.fixture.is_file():
            raise AssertionError('OFFLINE_PACKAGE_DEVELOPMENT_FIXTURE_REQUIRED')
        cls.tmp = tempfile.TemporaryDirectory(prefix='freeagent-package-test-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.private = Path(cls.tmp.name)
        cls.env = {'PATH': '/usr/bin:/bin', 'HOME': str(cls.private),
                   'PYTHONDONTWRITEBYTECODE': '1', 'PIP_NO_INDEX': '1'}
        # Explicit existing build backend/pins, not an editable runtime.
        check = run([BUILD_PYTHON, '-c',
                     'from importlib.metadata import version; '
                     'assert version("setuptools")=="68.1.2"; '
                     'assert version("wheel")=="0.42.0"'], cls.private, cls.env)
        if check.returncode:
            raise AssertionError('PINNED_BUILD_TOOLS_REQUIRED')
        sources = subprocess.check_output(['git', 'ls-files', '-z',
                                          'pyproject.toml', 'orchestrator', 'data', 'bin'],
                                         cwd=ROOT).decode().split('\0')
        cls.sources = [p for p in sources if p]
        if len(cls.sources) > 256:
            raise AssertionError('BUILD_SOURCE_BOUND')
        epoch = subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'],
                                        cwd=ROOT).decode().strip()
        cls.env['SOURCE_DATE_EPOCH'] = epoch
        cls.wheels = []
        for attempt in range(2):
            stage = cls.private / ('build-' + str(attempt)); stage.mkdir()
            size = 0
            for name in cls.sources:
                source = ROOT / name
                info = source.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise AssertionError('BUILD_SOURCE_TYPE')
                raw = source.read_bytes(); size += len(raw)
                if len(raw) > 8*1024*1024 or size > 32*1024*1024:
                    raise AssertionError('BUILD_SOURCE_BOUND')
                target = stage / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            dist = stage / 'dist'; dist.mkdir()
            build = run([BUILD_PYTHON, '-c',
                         'from setuptools.build_meta import build_wheel; import sys; '
                         'build_wheel(sys.argv[1])', str(dist)], stage, cls.env)
            if build.returncode:
                raise AssertionError('WHEEL_BUILD_FAILED')
            cls.wheels.append(next(dist.glob('*.whl')))
        cls.venv = cls.private / 'installed'
        subprocess.run([BUILD_PYTHON, '-m', 'venv', '--without-pip', str(cls.venv)],
                       check=True, env=cls.env, timeout=30)
        install = run([str(cls.fixture), '-m', 'pip', '--python',
                       str(cls.venv / 'bin/python3'), 'install', '--no-index',
                       '--no-deps', str(cls.wheels[0])], cls.private, cls.env)
        if install.returncode:
            raise AssertionError('OFFLINE_PROJECT_INSTALL_FAILED')
        dep = run([str(cls.fixture), '-c',
                   'import sysconfig; print(sysconfig.get_path("purelib"))'],
                  cls.private, cls.env)
        if dep.returncode:
            raise AssertionError('DEPENDENCY_FIXTURE_INVALID')
        cls.env['PYTHONPATH'] = dep.stdout.decode().strip()
        cls.command = cls.venv / 'bin/freeagent-run'

    def test_complete_wheel_membership_metadata_and_record(self):
        with zipfile.ZipFile(self.wheels[0]) as z:
            names = z.namelist()
            self.assertEqual(len(names), len(set(names)))
            required = [p for p in self.sources if p.startswith('orchestrator/') and
                        (p.endswith('.py') or p.startswith('orchestrator/website_guidance/'))]
            for name in required:
                self.assertEqual(z.read(name), (ROOT / name).read_bytes(), name)
            for name in ('coding_units', 'tester', 'repair_context'):
                self.assertIn('orchestrator/roles/' + name + '.py', names)
            entry = configparser.ConfigParser()
            entry.read_string(z.read('freeagentos-0.3.0.dev0.dist-info/entry_points.txt').decode())
            self.assertEqual(dict(entry['console_scripts']), {
                'freeagent': 'orchestrator.entrypoint:doctor_main',
                'freeagent-run': 'orchestrator.entrypoint:main'})
            metadata = z.read('freeagentos-0.3.0.dev0.dist-info/METADATA').decode()
            self.assertIn('Requires-Python: >=3.12', metadata)
            self.assertIn('Requires-Dist: langgraph ==1.2.12', metadata)
            import csv, io
            for name, digest, count in csv.reader(io.StringIO(z.read(
                    'freeagentos-0.3.0.dev0.dist-info/RECORD').decode())):
                if digest:
                    raw = z.read(name)
                    expected = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()
                    self.assertEqual(digest, 'sha256=' + expected)
                    self.assertEqual(int(count), len(raw))
            self.assertFalse(any(n.endswith(('.pth', '.whl')) for n in names))

    def test_repeat_build_bytes_under_fixed_conditions(self):
        self.assertEqual(self.wheels[0].read_bytes(), self.wheels[1].read_bytes())

    def test_installed_resources_and_function_local_imports(self):
        code = '''import json, sys
from orchestrator import entrypoint
sys.path.insert(0, str(__import__('pathlib').Path(entrypoint.__file__).parent))
import website
from roles.read_policy import content_allowed
assert content_allowed(b'Hello locally')
assert website.guidance()
from roles import coding_units, tester, repair_context
print(json.dumps([m.__file__ for m in (entrypoint, website, coding_units, tester, repair_context)]))
'''
        result = run([str(self.venv / 'bin/python3'), '-c', code], self.private, self.env)
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        for path in json.loads(result.stdout):
            self.assertTrue(Path(path).is_relative_to(self.venv))
            self.assertNotIn('/root', path)
        # A damaged installed guidance resource must still fail identity checking.
        resource = self.venv / 'lib/python3.12/site-packages/orchestrator/website_guidance/shape.md'
        original = resource.read_bytes()
        try:
            resource.write_bytes(original + b'\nchanged')
            reject = run([str(self.venv / 'bin/python3'), '-c',
                          'import sys; from orchestrator import entrypoint; '
                          'from pathlib import Path; sys.path.insert(0,str(Path(entrypoint.__file__).parent)); '
                          'import website; website.guidance()'], self.private, self.env)
            self.assertNotEqual(reject.returncode, 0)
            self.assertIn(b'GUIDANCE_IDENTITY_MISMATCH', reject.stdout)
        finally:
            resource.write_bytes(original)

    def test_installed_console_help_and_invalid_input_without_execution(self):
        result = run([str(self.command), 'recorded-website', '--help'], self.private, self.env)
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        self.assertIn(b'recorded', result.stdout.lower())
        self.assertIn(b'--staging-parent', result.stdout)
        self.assertNotIn(b'PREPARATION_COMPLETE', result.stdout)
        result = run([str(self.command), 'recorded-website', '--json'], self.private, self.env)
        self.assertNotEqual(result.returncode, 0)
        value = json.loads(result.stdout)
        self.assertNotEqual(value.get('status'), 'PREPARATION_COMPLETE')
        self.assertFalse(list(self.private.glob('freeagentos-website-*')))
