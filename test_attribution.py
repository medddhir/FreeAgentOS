"""Requested/dispatch/upstream boundaries, no provider traffic or payload logs."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).parent / 'orchestrator'))
from roles import model_profiles as profiles, model_attribution as attribution, worker
from roles.read_policy import file_tool_flags, sealed_policy
from roles.lease import ActivityLease, NS
import model_qualification as qualification
import test_contract as contract


class I(unittest.TestCase):
    def test(self):
        # Grouped to preserve the existing trusted runner's bounded verbose output.
        self.assertEqual(attribution.EVIDENCE_LEVELS,
                         ('REQUESTED_CONFIG','ROUTER_DISPATCH','UPSTREAM_REPORTED','UNAVAILABLE'))
        for role in profiles.MODEL_ROLES:
            for profile in ('claude-free-default','claude-free-auto'):
                with profiles.profile_scope({role:profile}):
                    identity=attribution.attribution_for(role)
                    before=profiles.model_command(role,[],'fixture',schema='{}' if role in ('planner','reviewer') else None)
                    for _ in range(2): attribution.attribution_for(role)
                    self.assertEqual(before,profiles.model_command(role,[],'fixture',schema='{}' if role in ('planner','reviewer') else None))
                self.assertEqual(identity['requested_evidence'],'REQUESTED_CONFIG')
                self.assertEqual(identity['routed_provider_id'],'UNAVAILABLE')
                self.assertEqual(identity['routed_model_id'],'UNAVAILABLE')
                self.assertEqual(identity['served_model_id'],'UNAVAILABLE')
                self.assertEqual(attribution.safe_attribution(identity),identity)
                for field in ('routed_evidence','served_evidence'):
                    self.assertEqual(identity[field],'UNAVAILABLE')
                # A claimed label, echoed model, route header or provider payload
                # never establishes a trusted controller-bound channel.
                for field,value in (('served_model_id',identity['requested_model_id']),
                                    ('routed_model_id','openai/gpt-oss-120b'),
                                    ('routed_provider_id','groq'),('routed_evidence','ROUTER_DISPATCH'),
                                    ('served_evidence','UPSTREAM_REPORTED'),('served_evidence','FAKE_SECRET')):
                    self.assertEqual(attribution.safe_attribution({**identity,field:value}),{})
                raw={'model':identity['requested_model_id'],
                     'headers':{'X-Routed-Via':'groq/openai/gpt-oss-120b','Authorization':'FAKE_SECRET'},
                     'prompt':'FAKE_PROMPT','choices':[{'text':'FAKE_COT','arguments':'FAKE_ARGS'}],
                     'path':'/FAKE_PRIVATE_PATH'}
                self.assertEqual(attribution.safe_attribution(raw),{})
                self.assertEqual(attribution.safe_attribution({**identity,**raw}),identity)
                self.assertNotIn('FAKE_',json.dumps(attribution.safe_attribution({**identity,**raw})))
        for value in (None,[],{'requested_profile_id':'FAKE_SECRET'}):
            self.assertEqual(attribution.safe_attribution(value),{})
        fixture=contract.C();fixture.reset();self.addCleanup(fixture.doCleanups)
        resource=worker._effective_policy(None)
        for role in ('coder','fixer'):
            flags=file_tool_flags(fixture.state,role,unit=fixture.unit)
            baseline=sealed_policy(flags)
            with profiles.profile_scope({role:qualification.PROFILE}):
                self.assertEqual(attribution.attribution_for(role)['requested_model_id'],qualification.MODEL)
                self.assertEqual(sealed_policy(file_tool_flags(fixture.state,role,unit=fixture.unit)),baseline)
                self.assertEqual(worker._effective_policy(None),resource)
                lease=ActivityLease(180,role,'model',True,240,0)
                attribution.attribution_for(role)
                self.assertFalse(lease.extend(180*NS))
                self.assertEqual(lease.evidence(180*NS,success=False)['hard_cap_ms'],240000)
        with patch.object(qualification,'qualify') as live, patch.object(qualification,'catalog_ready') as catalog, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(qualification.main(['--profile',qualification.PROFILE]),0)
        live.assert_not_called();catalog.assert_not_called()
        described=json.loads(output.getvalue())
        self.assertEqual(described['identity_attribution']['requested_model_id'],qualification.MODEL)
        self.assertEqual(described['identity_attribution']['served_evidence'],'UNAVAILABLE')
        self.assertEqual(described['live_result'],'NOT_RUN')
        with patch.object(qualification,'qualify',return_value=described) as live, redirect_stdout(io.StringIO()):
            self.assertEqual(qualification.main(['--profile',qualification.PROFILE,'--live']),0)
        live.assert_called_once_with(qualification.PROFILE)  # mocked; no generation
        with patch.object(qualification,'qualify',side_effect=RuntimeError('FAKE_SECRET')) as live, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(qualification.main(['--profile',qualification.PROFILE,'--live']),2)
        self.assertNotIn('FAKE_SECRET',output.getvalue())
        self.assertEqual(profiles.selected_profile('coder').profile_id,'claude-free-default')
