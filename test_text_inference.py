"""Fixed preparation binding; no credentials, real clients or positive authority."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
from orchestrator.roles import worker
from orchestrator.privilege import validation
from roles.lease import ActivityLease, NS
from website import Session, proposal_request
from test_website import brief


class TextInferenceTests(unittest.TestCase):
    def request(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        s = Session(brief(), tmp.name, preparation='synthetic')
        s.scaffold()
        return proposal_request(s, 'code')[0]

    def plan(self, request=None, **kwargs):
        return validation.prepare_text_inference_plan(self.request() if request is None else request,
            **dict(runtime_sha256='a'*64, executable_sha256='b'*64,
                   invocation='c'*32, credential_reference='SYNTHETIC_TOKEN', **kwargs))

    def test_canonical_binding_fixed_command_and_no_inherited_environment(self):
        r = self.request()
        with patch.dict(os.environ, {'PRIVATE_SENTINEL': 'synthetic-private',
                                    'ANTHROPIC_AUTH_TOKEN': 'synthetic-secret'}):
            p = self.plan(r)
            q = self.plan(dict(reversed(list(r.items()))))
            env = worker.text_inference_environment()
        self.assertEqual(p, q)
        self.assertEqual(p.request_sha256, hashlib.sha256(p.request).hexdigest())
        self.assertEqual(json.loads(p.request), r)
        self.assertEqual(p.argv[0], '/runtime/bin/claude-free')
        self.assertEqual(p.argv[-2:], ('-p', p.request.decode()))
        self.assertNotIn('synthetic-secret', json.dumps(env))
        self.assertNotIn('PRIVATE_SENTINEL', env)
        self.assertNotIn('ANTHROPIC_AUTH_TOKEN', env)
        self.assertLessEqual(set(env), set(worker.TEXT_INFERENCE_ENV_KEYS))
        self.assertEqual(worker.text_inference_environment(), env)
        env['PATH'] = 'foreign'
        self.assertEqual(worker.text_inference_environment()['PATH'], '/runtime/bin')
        changed = dict(r, guidance=r['guidance'] + ' data')
        self.assertNotEqual(self.plan(changed).binding_sha256, p.binding_sha256)

    def test_invalid_requests_bounds_and_safe_errors(self):
        r = self.request()
        variants = [dict(r, credentials='synthetic-secret'), dict(r, version=True),
                    dict(r, files=[]), dict(r, guidance='x'*8193),
                    dict(r, brief={'confirmed': True}), dict(r, phase='exec')]
        huge = dict(r, files=[dict(e, text='\\'*8192) for e in r['files']])
        variants.append(huge)  # JSON escaping exceeds the byte cap.
        for v in variants:
            with self.subTest(kind=len(v)), self.assertRaises(worker.WorkerBoundaryError) as e:
                self.plan(v)
            self.assertEqual(str(e.exception), 'TEXT_INFERENCE_REQUEST_INVALID')
            self.assertNotIn('synthetic-secret', repr(e.exception.evidence))
        with self.assertRaises(worker.WorkerBoundaryError):
            validation.prepare_text_inference_plan(r, runtime_sha256='foreign',
                executable_sha256='b'*64, invocation='c'*32, credential_reference='bad-ref')

    def test_utf8_field_boundaries_and_encoding(self):
        r = self.request()
        # Byte boundaries, not character counts; newlines/tabs remain source data.
        for field, size in [('brief', 512), ('guidance', 8192), ('file', 8192)]:
            for extra in (0, 1):
                text = 'é' * (size // 2) + ('x' if extra else '')
                v = json.loads(json.dumps(r))
                if field == 'brief':
                    v['brief']['title'] = text
                elif field == 'guidance':
                    v['guidance'] = text
                else:
                    v['files'][0]['text'] = text
                with self.subTest(field=field, extra=extra):
                    if extra:
                        with self.assertRaisesRegex(worker.WorkerBoundaryError,
                                                    '^TEXT_INFERENCE_REQUEST_INVALID$'):
                            self.plan(v)
                    else:
                        self.assertEqual(json.loads(self.plan(v).request), v)
        for field in ('guidance', 'file', 'brief'):
            v = json.loads(json.dumps(r))
            if field == 'guidance': v['guidance'] = '\ud800'
            elif field == 'file': v['files'][0]['text'] = '\ud800'
            else: v['brief']['title'] = '\ud800'
            with self.subTest(encoding=field), self.assertRaisesRegex(
                    worker.WorkerBoundaryError, '^TEXT_INFERENCE_REQUEST_INVALID$'):
                self.plan(v)
        v = dict(r, guidance='source\n\tdata')
        v['files'] = [dict(e, text='source\n\tdata') for e in r['files']]
        self.assertEqual(json.loads(self.plan(v).request), v)

    def test_producer_identity_formats_are_not_provenance(self):
        r = self.request()
        self.assertRegex(r['run'], '^[0-9a-f]{32}$')
        for key in ('contract', 'base_snapshot', 'guidance_sha256'):
            self.assertRegex(r[key], '^[0-9a-f]{64}$')
        self.assertEqual(json.loads(self.plan(r).request), r)
        for key in ('run', 'contract', 'base_snapshot', 'guidance_sha256'):
            width = 32 if key == 'run' else 64
            for value in ('', 'z' * width, 'A' * width, 'a' * (width - 1),
                          'a' * (width + 1), True):
                with self.subTest(key=key, kind=type(value).__name__), self.assertRaisesRegex(
                        worker.WorkerBoundaryError, '^TEXT_INFERENCE_REQUEST_INVALID$'):
                    self.plan(dict(r, **{key: value}))
        # Another correctly shaped declaration still grants no authority.
        p = self.plan(dict(r, run='d'*32, contract='e'*64))
        with self.assertRaisesRegex(worker.WorkerBoundaryError,
                                    '^TEXT_INFERENCE_QUALIFICATION_UNPROVEN$'):
            worker.run_worker(list(p.argv), policy_profile='model')

    def test_inner_command_shape_rejects_before_side_effects(self):
        with patch.object(worker, '_start_cgroup', side_effect=worker.WorkerBoundaryError(
                'UNEXPECTED_SETUP')) as scope, patch.object(worker, '_worker_environment') as env, \
                patch.object(worker.subprocess, 'Popen') as launch, \
                patch.object(worker, '_gateway_health') as health:
            for cmd in (worker.TEXT_INFERENCE_EXECUTABLE, '', [], [1],
                        ['tool', None], ['tool', True], [''], ['tool', 'a\x00b']):
                request = {'profile': 'model', 'cmd': cmd, 'limits': {},
                           'policy': worker.WORKER_POLICY, 'timeout': 1, 'scope_name': 'unused'}
                with self.subTest(kind=type(cmd).__name__), self.assertRaisesRegex(
                        worker.WorkerBoundaryError, '^WORKER_REQUEST_INVALID$'):
                    worker._run_inner('unused', request)
            scope.assert_not_called(); env.assert_not_called()
            launch.assert_not_called(); health.assert_not_called()

    def test_reserved_launcher_is_rejected_and_default_remains_compatible(self):
        from foundation import Configuration, config_scope
        from roles.model_profiles import model_command
        with config_scope(Configuration(launcher=worker.TEXT_INFERENCE_EXECUTABLE)):
            cmd = model_command('planner', [], 'synthetic prompt', schema='{"type":"object"}')
        self.assertEqual(cmd[0], worker.TEXT_INFERENCE_EXECUTABLE)
        with patch.object(worker, '_start_cgroup') as scope, \
                patch.object(worker.subprocess, 'Popen') as launch:
            for call in (lambda: worker.run_worker(cmd, policy_profile='model'),
                         lambda: worker._run_worker_impl(cmd, policy_profile='model'),
                         lambda: worker._run_inner('unused', {'profile': 'model', 'cmd': cmd})):
                with self.assertRaisesRegex(worker.WorkerBoundaryError,
                                            '^TEXT_INFERENCE_QUALIFICATION_UNPROVEN$'):
                    call()
            scope.assert_not_called(); launch.assert_not_called()
        with config_scope(Configuration()):
            ordinary_cmd = model_command('planner', [], 'synthetic prompt', schema='{"type":"object"}')
        self.assertEqual(ordinary_cmd[0], 'claude-free')
        result = worker.WorkerResult(0, 'synthetic', {})
        with patch.object(worker, '_run_worker_impl', return_value=result) as ordinary:
            self.assertIs(worker.run_worker(ordinary_cmd), result)
            ordinary.assert_called_once()

    def test_worker_accepts_only_declared_policy_digest_and_still_cannot_activate(self):
        r = self.request()
        options = dict(runtime_sha256='a'*64, executable_sha256='b'*64,
                       invocation='c'*32, credential_reference='SYNTHETIC_TOKEN')
        for value in (True, None, {'qualified': True}, 'foreign'):
            with self.subTest(kind=type(value).__name__), self.assertRaises(worker.WorkerBoundaryError):
                worker.prepare_text_inference(r, **options, policy_sha256=value)
        p = worker.prepare_text_inference(r, **options, policy_sha256='d'*64)
        q = worker.prepare_text_inference(r, **options, policy_sha256='e'*64)
        self.assertNotEqual(p.binding_sha256, q.binding_sha256)
        self.assertEqual(p.profile_sha256, q.profile_sha256)
        with self.assertRaisesRegex(worker.WorkerBoundaryError, '^TEXT_INFERENCE_QUALIFICATION_UNPROVEN$'):
            worker.run_worker(list(p.argv), policy_profile=worker.TEXT_INFERENCE_PROFILE)

    def test_binding_covers_declared_runtime_invocation_policy_and_reference(self):
        r = self.request(); p = self.plan(r)
        for key, value in [('runtime_sha256', 'd'*64), ('executable_sha256', 'd'*64),
                           ('invocation', 'd'*32), ('credential_reference', 'OTHER_SYNTHETIC')]:
            kwargs = dict(runtime_sha256='a'*64, executable_sha256='b'*64,
                          invocation='c'*32, credential_reference='SYNTHETIC_TOKEN')
            kwargs[key] = value
            q = validation.prepare_text_inference_plan(r, **kwargs)
            self.assertNotEqual(p.binding_sha256, q.binding_sha256)
        self.assertEqual(p.policy_sha256, validation.policy_hash())
        self.assertEqual(len(p.policy_sha256), 64)
        self.assertEqual(len(p.profile_sha256), 64)

    def test_all_activation_entries_reject_before_environment_or_launch(self):
        p = self.plan()
        # Neither declared plans nor forged/replayed/staging claims are authority.
        claims = [None, True, {'qualified': True}, {'execution_enabled': False},
                  {'expires': 0}, replace(p, runtime_sha256='d'*64), p]
        with patch.object(worker.subprocess, 'Popen') as launch, \
                patch.object(worker, '_worker_environment') as environment, \
                patch.object(worker, '_start_cgroup') as scope, \
                patch.object(worker, '_gateway_health') as health:
            for claim in claims:
                with self.subTest(claim=type(claim).__name__):
                    for call in (lambda: worker.run_worker(list(p.argv)),
                                 lambda: worker._run_worker_impl(list(p.argv)),
                                 lambda: worker.run_worker(list(p.argv), limits=claim,
                                        policy_profile=worker.TEXT_INFERENCE_PROFILE),
                                 lambda: worker._run_worker_impl(list(p.argv), limits=claim,
                                        policy_profile=worker.TEXT_INFERENCE_PROFILE),
                                 lambda: worker._run_inner('unused', {'profile': worker.TEXT_INFERENCE_PROFILE,
                                                                   'admission': claim})):
                        with self.assertRaises(worker.WorkerBoundaryError) as e:
                            call()
                        self.assertEqual(str(e.exception), 'TEXT_INFERENCE_QUALIFICATION_UNPROVEN')
                        self.assertEqual(e.exception.evidence['cleanup_status'], 'UNPROVEN')
            launch.assert_not_called(); environment.assert_not_called()
            scope.assert_not_called(); health.assert_not_called()

    def test_fixed_limits_no_grace_and_existing_cleanup_evidence_requirement(self):
        policy = worker._effective_policy(None, worker.TEXT_INFERENCE_PROFILE)
        self.assertEqual(policy, worker.TEXT_INFERENCE_LIMITS)
        self.assertEqual(policy['wall_timeout_seconds'], 60)
        self.assertEqual(policy['max_output_bytes'], 65536)
        self.assertEqual(worker.TEXT_INFERENCE_BOUNDS['cli_invocations'], 1)
        with self.assertRaises(worker.WorkerBoundaryError):
            worker._effective_policy({'wall_timeout_seconds': 61}, worker.TEXT_INFERENCE_PROFILE)
        lease = ActivityLease(60, 'planner', worker.TEXT_INFERENCE_PROFILE, False, 60, 0)
        self.assertFalse(lease.extend(60*NS))
        self.assertEqual(lease.hard_ns, 60*NS)
        for evidence in ({}, {'cleanup_status': 'CONFIRMED', 'remaining_processes': 1},
                         {'cleanup_status': 'UNPROVEN', 'remaining_processes': 0}):
            with self.assertRaises(worker.WorkerBoundaryError):
                worker._validate_evidence(evidence, policy, 0)
        self.assertEqual(worker._effective_policy(None), worker.WORKER_POLICY)
        result = worker.WorkerResult(0, 'synthetic', {})
        with patch.object(worker, '_run_worker_impl', return_value=result) as ordinary:
            self.assertIs(worker.run_worker(['synthetic-tool']), result)
            ordinary.assert_called_once()
