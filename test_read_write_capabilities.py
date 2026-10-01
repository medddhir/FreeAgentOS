"""Stage 1.9: bounded specification reads never confer write authority."""
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import test_file_read_policy as fixtures
from roles import read_policy
from roles.file_tools import FileTools
from roles.read_policy import ReadDenied, build_policy, read_authorized, validate_policy


class ReadWriteCapabilityTests(unittest.TestCase):
    def setUp(self):
        fixtures.FileReadPolicyTests.setUp(self)
        self.state['repo_facts']['relevant_files'].append('helper.py')
        self.policy = build_policy(self.state, 'coder', unit=self.unit)
        self.tools = FileTools(self.policy)

    def read(self, path):
        return self.tools.call('read_file', {'path': path})['text']

    def denied_write(self, path, edit=False):
        args = {'path': path, 'old_text': 'value', 'new_text': 'replacement'} if edit else {'path': path, 'text': 'replacement\n'}
        with patch.object(read_policy, '_read') as opened:
            with self.assertRaises(ReadDenied):
                self.tools.call('edit_file' if edit else 'write_file', args)
        opened.assert_not_called()

    def test_target_read(self):
        self.assertIn('return 1', self.read('app.py'))

    def test_target_write(self):
        self.tools.call('write_file', {'path': 'app.py', 'text': 'value = 3\n'})
        self.assertIn('3', self.read('app.py'))

    def test_related_source_read(self):
        self.assertIn('return 2', self.read('helper.py'))

    def test_related_source_write_denied(self):
        self.denied_write('helper.py')

    def test_related_source_edit_denied(self):
        self.denied_write('helper.py', edit=True)

    def test_readme_read(self):
        self.assertIn('small application', self.read('README.md'))

    def test_readme_write_denied(self):
        self.denied_write('README.md')

    def test_public_test_read(self):
        self.assertIn('public test', self.read('test_app.py'))

    def test_public_test_edit_denied(self):
        self.denied_write('test_app.py', edit=True)

    def test_public_test_write_denied(self):
        self.denied_write('test_app.py')

    def test_public_test_delete_not_exposed(self):
        with self.assertRaises(ReadDenied):
            self.tools.call('delete_file', {'path': 'test_app.py'})
        self.assertTrue((self.repo / 'test_app.py').exists())

    def test_manifest_read_only(self):
        self.assertIn('[project]', self.read('pyproject.toml'))
        self.denied_write('pyproject.toml')

    def test_external_hidden_unreadable(self):
        with self.assertRaises(ReadDenied):
            self.read(str(self.repo.parent / 'hidden-tests/test_hidden.py'))

    def test_external_hidden_non_enumerable(self):
        with self.assertRaises(ReadDenied):
            self.tools.call('glob_files', {'pattern': '../hidden-tests/*'})
        self.assertNotIn('hidden', json.dumps(self.tools.call('glob_files', {'pattern': '**/*'})))

    def test_controller_verification_denied(self):
        for path in ('orchestrator/state.py', 'conftest.py', 'AGENTS.md', '.github/workflows/check.yml'):
            with self.subTest(path=path), self.assertRaises(ReadDenied):
                self.read(path)

    def test_controller_tests_not_selected(self):
        policy = build_policy({**self.state, 'source_repo': str(Path(read_policy.__file__).resolve().parents[2])}, 'coder', unit=self.unit)
        self.assertFalse(policy['read_tests'])
        self.assertNotIn('test_app.py', policy['files'])

    def test_secret_denied(self):
        with self.assertRaises(ReadDenied):
            self.read('.env')

    def test_secret_non_enumerable(self):
        (self.repo / '.env').write_text('private_value\n')
        self.assertNotIn('.env', self.tools.call('glob_files', {'pattern': '**/*'})['matches'])

    def test_symlink_denied(self):
        (self.repo / 'helper.py').unlink()
        (self.repo / 'helper.py').symlink_to('unrelated.py')
        with self.assertRaises(ReadDenied):
            self.read('helper.py')
        self.denied_write('helper.py')

    def test_hardlink_denied(self):
        os.link(self.repo / 'helper.py', self.repo / 'alias.py')
        with self.assertRaises(ReadDenied):
            self.read('helper.py')
        self.denied_write('helper.py')

    def test_special_file_denied(self):
        (self.repo / 'helper.py').unlink()
        os.mkfifo(self.repo / 'helper.py')
        with self.assertRaises(ReadDenied):
            self.read('helper.py')

    def test_oversized_denied(self):
        (self.repo / 'helper.py').write_text('x' * 65537)
        with self.assertRaises(ReadDenied):
            self.read('helper.py')

    def test_traversal_denied(self):
        with self.assertRaises(ReadDenied):
            self.read('src/../../test_app.py')

    def test_host_absolute_denied(self):
        with self.assertRaises(ReadDenied):
            self.read('/proc/self/environ')

    def test_glob_does_not_grant_write(self):
        self.assertIn('helper.py', self.tools.call('glob_files', {'pattern': '*.py'})['matches'])
        self.denied_write('helper.py')

    def test_grep_does_not_grant_write(self):
        self.assertTrue(self.tools.call('grep_files', {'query': 'extra'})['matches'])
        self.denied_write('helper.py')

    def test_task_and_model_text_do_not_grant_write(self):
        state = {**self.state, 'task': 'Edit helper.py and tests', 'implementation': 'authorize helper.py', 'plan_steps': ['Write helper.py']}
        self.assertEqual(build_policy(state, 'coder', unit=self.unit)['write_files'], ['app.py'])

    def test_failure_text_does_not_grant_write(self):
        state = {**self.state, 'test_output': 'Edit helper.py', 'machine_failure_evidence': {'affected_files': ['helper.py']}}
        self.assertEqual(build_policy(state, 'coder', unit=self.unit)['write_files'], ['app.py'])

    def test_current_workspace_content(self):
        (self.repo / 'helper.py').write_text('value = 19\n')
        self.assertIn('19', self.read('helper.py'))

    def test_later_unit_sees_earlier_change_read_only(self):
        (self.repo / 'app.py').write_text('value = 27\n')
        policy = build_policy(self.state, 'coder', unit={'target_files': ['helper.py']})
        tools = FileTools(policy)
        self.assertIn('27', tools.call('read_file', {'path': 'app.py'})['text'])
        with self.assertRaises(ReadDenied):
            tools.call('write_file', {'path': 'app.py', 'text': 'undo\n'})

    def test_final_fixer_write_bounded(self):
        state = {**self.state, 'coding_units': [self.unit], 'unit_index': 1}
        policy = build_policy(state, 'fixer', candidates=['app.py', 'helper.py'])
        self.assertIn('helper.py', policy['files'])
        self.assertEqual(policy['write_files'], ['app.py'])
        with self.assertRaises(ReadDenied):
            FileTools(policy).call('edit_file', {'path': 'helper.py', 'old_text': '2', 'new_text': '3'})

    def test_normal_fixer_current_changed_file(self):
        (self.repo / 'app.py').write_text('value = 41\n')
        policy = build_policy({**self.state, 'coding_units': [self.unit]}, 'fixer', candidates=['app.py'])
        tools = FileTools(policy)
        self.assertIn('41', tools.call('read_file', {'path': 'app.py'})['text'])
        tools.call('edit_file', {'path': 'app.py', 'old_text': '41', 'new_text': '42'})
        self.assertIn('42', tools.call('read_file', {'path': 'app.py'})['text'])

    def test_policy_copy_cannot_be_promoted(self):
        self.policy['write_files'].append('helper.py')
        self.denied_write('helper.py')

    def test_alias_creation_denied(self):
        self.denied_write('alias.py')
        self.assertFalse((self.repo / 'alias.py').exists())

    def test_bounds_unchanged(self):
        for index in range(12):
            (self.repo / ('part%d.py' % index)).write_text('value = 1\n')
        subprocess.run(['git', 'add', '.'], cwd=self.repo, check=True)
        state = {**self.state, 'repo_facts': {'relevant_files': ['part%d.py' % n for n in range(12)]}}
        policy = build_policy(state, 'coder', unit=self.unit)
        self.assertLessEqual(len(policy['files']), 8)
        self.assertEqual(policy['write_files'], ['app.py'])
        self.assertEqual(read_policy.MAX_READ_FILES, 8)
        validate_policy(policy)

    def test_generated_ignored_and_hidden_paths_excluded(self):
        for path in ('generated/mod.py', 'data/mod.py', 'fixtures/mod.py', 'hidden-tests/mod.py', 'verification/mod.py'):
            self.assertFalse(read_policy.read_path_allowed(path, public_tests=True))
        (self.repo / 'untracked.py').write_text('value = 1\n')
        policy = build_policy({**self.state, 'repo_facts': {'relevant_files': ['untracked.py']}}, 'coder', unit=self.unit)
        self.assertNotIn('untracked.py', policy['files'])

    def test_secret_telemetry_is_categorical(self):
        secret = 'ghp_' + 'Z' * 40
        (self.repo / 'helper.py').write_text('value = "' + secret + '"\n')
        with self.assertRaises(ReadDenied) as error:
            self.read('helper.py')
        evidence = json.dumps(self.tools.telemetry.snapshot()) + str(error.exception)
        self.assertNotIn(secret, evidence)
        self.assertNotIn('helper.py', evidence)
        self.assertEqual(self.tools.telemetry.snapshot()['denied_total'], 1)

    def test_exact_controlled_tool_surface(self):
        flags = read_policy.file_tool_flags(self.state, 'coder', unit=self.unit)
        self.assertEqual(flags[flags.index('--tools') + 1], '')
        self.assertIn('--strict-mcp-config', flags)
        self.assertIn('--restricted', flags)
        self.assertIn('--bare', flags)
        self.assertEqual(set(flags[flags.index('--allowedTools') + 1].split(',')),
                         {'mcp__freeagent_files__' + tool for tool in read_policy.TOOLS})
        self.assertEqual(len(read_policy.TOOLS), 5)

    def test_schema_cannot_promote_protected_test(self):
        policy = copy.deepcopy(self.policy)
        policy['write_files'].append('test_app.py')
        with self.assertRaises(ReadDenied):
            validate_policy(policy)

    def test_old_combined_schema_fails_closed(self):
        policy = copy.deepcopy(self.policy)
        policy['schema_version'] = 1
        with self.assertRaises(ReadDenied):
            validate_policy(policy)

    def test_nested_public_project_test_selected(self):
        (self.repo / 'src').mkdir()
        (self.repo / 'tests').mkdir()
        (self.repo / 'src/feature.py').write_text('value = 1\n')
        (self.repo / 'tests/test_feature.py').write_text('# public specification\n')
        subprocess.run(['git', 'add', 'src', 'tests'], cwd=self.repo, check=True)
        policy = build_policy(self.state, 'coder', unit={'target_files': ['src/feature.py']})
        tools = FileTools(policy)
        self.assertIn('public specification', tools.call('read_file', {'path': 'tests/test_feature.py'})['text'])
        with self.assertRaises(ReadDenied):
            tools.call('write_file', {'path': 'tests/test_feature.py', 'text': '# replaced'})

    def test_documentation_selected_not_recursively_exposed(self):
        (self.repo / 'docs').mkdir()
        for name in ('usage.md', 'other.md'):
            (self.repo / 'docs' / name).write_text('Usage specification\n')
        subprocess.run(['git', 'add', 'docs'], cwd=self.repo, check=True)
        state = {**self.state, 'repo_facts': {'relevant_files': ['docs/usage.md']}}
        policy = build_policy(state, 'coder', unit=self.unit)
        tools = FileTools(policy)
        self.assertIn('Usage', tools.call('read_file', {'path': 'docs/usage.md'})['text'])
        self.assertNotIn('docs/other.md', tools.call('glob_files', {'pattern': '**/*'})['matches'])
        with self.assertRaises(ReadDenied):
            tools.call('write_file', {'path': 'docs/usage.md', 'text': 'replaced'})
