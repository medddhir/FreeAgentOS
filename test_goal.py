"""Stage 1.10a goal contract: synthetic responses, no model requests."""
import ast
import copy
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
from roles import planner, coding_units as units
from roles.worker import WorkerResult
import cli


class Goal(unittest.TestCase):
    def unit(self, goal):
        return {'goal': goal, 'target_files': []}

    def validate(self, goal):
        return units.validate_planner_units(['Implement behavior'], [self.unit(goal)])[0]['goal']

    def state(self, proposed):
        payload = {'needs_research': False, 'research_type': 'none', 'research_query': '',
                   'steps': ['Inspect inputs', 'Implement coupled behavior', 'Verify existing tests'],
                   'coding_units': proposed}
        result = WorkerResult(0, json.dumps({'structured_output': payload}),
                              {'cleanup_status': 'CONFIRMED', 'remaining_processes': 0,
                               'timeout_triggered': False, 'output_truncated': False})
        with patch.object(planner, 'verify_execution_contract'), \
             patch.object(planner, 'run_worker', return_value=result) as worker:
            state = planner.planner_node({'task': 'Implement generic behavior'})
        worker.assert_called_once()
        return state

    def test_valid(self):
        cases = ['Implement domain models and parsing for valid records', 'Fix',
                 'Implement ' + 'x' * 290, ' \tImplement behavior\n',
                 'Implement\nvalidation', 'Implement checks\x00',
                 'Implement validación Ξ', 'Implement ' + 'λ' * 290,
                 'İmplement behavior', 'Inspect inputs then fix consumers']
        for goal in cases:
            with self.subTest(goal_type='valid', length=len(goal)):
                self.assertEqual(self.validate(goal), goal.strip())
        self.assertEqual(len(self.validate(cases[2])), 300)
        repeated = units.validate_planner_units(['Implement behavior'], [self.unit('Fix')] * 3)
        self.assertEqual(len(repeated), 3)
        self.assertIn('\x00', self.validate('Implement checks\x00'))

    def test_reasons(self):
        cases = [(None, 'GOAL_NOT_STRING'), (17, 'GOAL_NOT_STRING'),
                 ({}, 'GOAL_NOT_STRING'), ([], 'GOAL_NOT_STRING'),
                 ('', 'GOAL_EMPTY'), (' \t\n', 'GOAL_EMPTY'),
                 ('\u001c\u2003', 'GOAL_EMPTY'), (' ' * 301, 'GOAL_EMPTY'),
                 ('Implement ' + 'x' * 291, 'GOAL_TOO_LONG'),
                 (' ' * 300 + 'Fix', 'GOAL_TOO_LONG'),
                 ('Implement domain behavior ' + 'with validation ' * 30, 'GOAL_TOO_LONG'),
                 ('Run tests', 'GOAL_NO_IMPLEMENTATION_ACTION'),
                 ('F', 'GOAL_NO_IMPLEMENTATION_ACTION'),
                 ('\x00Implement behavior', 'GOAL_NO_IMPLEMENTATION_ACTION'),
                 ('Implementé behavior', 'GOAL_NO_IMPLEMENTATION_ACTION')]
        for goal, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(units.UnitGoalFailure) as caught:
                    self.validate(goal)
                self.assertEqual(str(caught.exception), 'UNIT_GOAL_INVALID')
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(caught.exception.args, ('UNIT_GOAL_INVALID',))
                state = self.state([self.unit(goal)])
                self.assertEqual(state['status'], 'BLOCKED')
                self.assertEqual(state['planner_error_code'], 'PLANNER_CODING_UNITS_INVALID')
                self.assertEqual(state['planner_diagnostic']['unit_validation_code'], 'UNIT_GOAL_INVALID')
                self.assertEqual(state['planner_diagnostic']['unit_goal_validation_reason'], reason)
                self.assertNotIn('plan_steps', state)
                forged = units.derive_units_node({'unit_derivation_source': 'PLANNER_EXPLICIT',
                    'plan_steps': ['Implement behavior'], 'planner_coding_units': [self.unit(goal)]})
                self.assertEqual(forged['status'], 'BLOCKED')
                self.assertEqual(forged['unit_error'], 'UNIT_GOAL_INVALID')

    def test_schema(self):
        schema = planner.PLANNER_SCHEMA['properties']['coding_units']['items']
        goal = schema['properties']['goal']
        self.assertEqual(goal['minLength'], 1)
        self.assertEqual(goal['maxLength'], units.MAX_EXPLICIT_GOAL)
        self.assertEqual(goal['pattern'], units.GOAL_GENERATION_PATTERN)
        self.assertFalse(schema['additionalProperties'])
        self.assertEqual(set(schema['required']), {'goal', 'target_files'})
        self.assertNotIn('(?i)', goal['pattern'])
        for verb in units.IMPLEMENTATION_VERBS:
            for prefix in ('', '\t\u2003'):
                for value in (verb, verb.upper() + ' behavior', prefix + verb.title() + ' validación'):
                    with self.subTest(verb=verb):
                        self.assertIsNotNone(re.search(goal['pattern'], value))
                        self.assertEqual(self.validate(value), value.strip())
        for invalid in ('Run tests', 'Domain model implementation', ' ', '\ufeffImplement behavior', 'Implementé behavior'):
            self.assertIsNone(re.search(goal['pattern'], invalid))
        # Existing broader controller placement remains accepted, while generation
        # deliberately asks for a portable verb-first format.
        self.assertEqual(self.validate('Read inputs then implement behavior'), 'Read inputs then implement behavior')
        self.assertIsNone(re.search(goal['pattern'], 'Read inputs then implement behavior'))

    def test_plans(self):
        proposed = [self.unit('Implement domain models and parsing for valid records'),
                    self.unit('Implement core behavior and consumers'),
                    self.unit('Implement interface output')]
        for count in (1, 2, 3):
            state = self.state(proposed[:count])
            self.assertNotEqual(state.get('status'), 'BLOCKED')
            self.assertEqual(len(state['planner_coding_units']), count)
        coupled = copy.deepcopy(proposed[:1])
        coupled[0]['target_files'] = ['src/domain.py', 'src/parser.py']
        self.assertEqual(len(self.state(coupled)['planner_coding_units'][0]['target_files']), 2)
        rejected = [[], proposed + proposed[:1], [{'target_files': []}],
                    [{'goal': 'Implement behavior', 'target_files': [], 'extra': 'private'}],
                    [{'goal': 'Implement behavior', 'target_files': 'src/domain.py'}]]
        for value in rejected:
            state = self.state(value)
            self.assertEqual(state['status'], 'BLOCKED')
            self.assertNotIn('plan_steps', state)
        missing = {'needs_research': False, 'research_type': 'none', 'research_query': '',
                   'steps': ['Implement behavior'], '_worker_evidence': {}}
        with self.assertRaises(planner.PlannerFailure) as caught:
            planner._normalize(missing)
        self.assertEqual(caught.exception.code, 'PLANNER_CODING_UNITS_MISSING')
        self.assertEqual(units.MAX_UNITS, 3)
        self.assertEqual(units.MAX_TARGET_FILES, 4)

    def test_prompt(self):
        payload = {'needs_research': False, 'research_type': 'none', 'research_query': '',
                   'steps': ['Implement behavior'], 'coding_units': [self.unit('Implement behavior')]}
        result = WorkerResult(0, json.dumps({'structured_output': payload}),
                              {'cleanup_status': 'CONFIRMED', 'remaining_processes': 0})
        with patch.object(planner, 'run_worker', return_value=result) as worker:
            planner._run_planner('Implement a generic coupled feature')
        worker.assert_called_once()
        command = worker.call_args.args[0]
        prompt = command[-1]
        for guidance in ('at most 300 characters INCLUDING whitespace', 'start each goal',
                         'test-coherent behavioral slices', 'not one-file-per-unit edits',
                         'independently implementable', 'tightly coupled', 'order prerequisites',
                         '1 to 3', 'up to 4 target_files'):
            self.assertIn(guidance, prompt)
        self.assertEqual(json.loads(command[command.index('--json-schema') + 1]), planner.PLANNER_SCHEMA)

    def test_private(self):
        secret = 'Bearer FAKE_GOAL_SECRET_918273'
        path = '/host/private/hidden-tests/example.py'
        goal = 'Implement ' + secret + path + 'x' * 300
        state = self.state([self.unit(goal)])
        diagnostic = cli._planner_diagnostic(state['planner_diagnostic'])
        self.assertEqual(diagnostic['unit_goal_validation_reason'], 'GOAL_TOO_LONG')
        for value in (json.dumps(state), json.dumps(diagnostic)):
            self.assertNotIn(secret, value)
            self.assertNotIn(path, value)
            self.assertNotIn(goal, value)
        self.assertNotIn('unit_goal_validation_reason', cli._planner_diagnostic({'unit_goal_validation_reason': secret}))
        missing = self.state([{'target_files': []}])
        self.assertEqual(missing['planner_diagnostic']['unit_validation_code'], 'UNIT_SCHEMA_INVALID')
        self.assertNotIn('unit_goal_validation_reason', missing['planner_diagnostic'])
