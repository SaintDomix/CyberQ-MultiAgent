"""P1–P12 and integration contracts; constructed scenarios are not live findings."""
import asyncio
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import math
from unittest.mock import patch
import httpx
import pytest
from cqi_v2 import evaluate,compare,Policy,registry
from cqi_v2.policy import aggregate
from cqi_v2.validation import scenarios,sensitivity_policies,finding,CONTROLS,TIME,incident
from cqi_v2.model import finding_value
from fusion.schema import utc
from behavioral_runtime.package import verify
from demo.backend.app import create_app
from demo.backend.services import Application
from demo.backend.config import Config

ROOT=Path(__file__).resolve().parents[1]

def run(name,policy=None):return evaluate(**scenarios()[name],policy=policy)

@pytest.mark.parametrize('name',list(scenarios()))
def test_P1_boundedness_and_P2_determinism(name):
    a=run(name);assert a==run(name)
    assert a['overall'] is None or 0<=a['overall']<=100
    assert 0<=a['quality_bounds']['lower']<=a['quality_bounds']['upper']<=100.000000001
    for d in a['dimensions']:
        assert d['score'] is None or 0<=d['score']<=100

@pytest.mark.parametrize('name',list(sensitivity_policies()))
def test_P3_P4_security_improvement_deterioration_across_predeclared_parameters(name):
    p=sensitivity_policies()[name];clean=run('normal_complete',p);bad=run('confirmed_critical',p)
    fixed=run('verified_remediation',p);extra=run('independent_additional_weakness',p)
    assert fixed['overall']>=bad['overall'] and clean['overall']>=bad['overall']>=extra['overall']

def test_P5_severity_order_and_reliability_semantics():
    values=[]
    for severity in ['LOW','MEDIUM','HIGH','CRITICAL']:
        s=scenarios()['confirmed_critical'];s['posture_rows'][0]['severity']=severity
        values.append(evaluate(**s)['overall'])
    assert values==sorted(values,reverse=True)
    assert run('only_low_confidence_indication')['overall']>run('confirmed_critical')['overall']
    low=run('only_low_confidence_indication');assert low['overall']<100
    assert low['overall_status']=='PARTIAL_EVIDENCE'

def test_P6_duplicate_source_and_observation_episode_invariance():
    a=run('confirmed_critical');b=run('duplicate_native_zap')
    assert a['overall']==b['overall'] and a['coverage']==b['coverage']
    assert run('known_incident')['overall']==run('duplicate_episode')['overall']
    assert len(run('duplicate_episode')['behavioral']['active_incidents'])==1

def test_P7_missing_failed_control_cannot_inflate_conservative_score():
    a=scenarios()['confirmed_critical'];before=evaluate(**a)
    a['posture_rows']=a['posture_rows'][1:];after=evaluate(**a)
    assert after['quality_bounds']['lower']<=before['quality_bounds']['lower']
    assert compare(before,after)['delta'] is None and not compare(before,after)['comparable']
    assert after['overall_status']=='PARTIAL_EVIDENCE'

def test_P7_missing_member_of_already_incomplete_shared_root_cannot_raise_bound():
    s=scenarios()['confirmed_critical'];s['controls']=deepcopy(CONTROLS)+[dict(CONTROLS[0],control_id='ALIAS-D1')]
    a=evaluate(**s);s['posture_rows']=s['posture_rows'][1:];b=evaluate(**s)
    assert b['overall']<=a['overall']

def test_P7_empty_all_unavailable_never_returns_perfect_score():
    r=evaluate([],as_of=TIME,controls=CONTROLS)
    assert r['overall'] is None and r['overall_status']=='INSUFFICIENT_EVIDENCE'
    assert r['coverage']['observability']==0 and r['conditional_overall'] is None

def test_P8_moodle_inapplicability_neutrality_and_no_excluding_known_failed_dimension():
    assert run('generic_moodle_inapplicable')['overall']==run('normal_complete')['overall']
    s=scenarios()['confirmed_critical'];s['dimension_applicability']={'D1':{'state':'NOT_APPLICABLE','evidence_reference':'fictional'}}
    with pytest.raises(ValueError,match='known failed'):evaluate(**s)

def test_P9_P10_behavioral_sensitivity_closure_and_temporal_recovery():
    clean=run('normal_complete');known=run('known_incident');two=run('two_independent_incidents')
    unknown=run('unknown_incident');isolated=run('isolated_unknown_observation')
    assert clean['overall']>unknown['overall']>=known['overall']>=two['overall']
    assert isolated['overall']==clean['overall']  # Scoring redesign; incident decisions unchanged.
    assert run('verified_incident_closure')['overall']==clean['overall']
    recovery=run('temporal_activity_recovery');assert recovery['overall']==clean['overall']
    assert 'NOT_VERIFIED_RESOLVED' in recovery['behavioral']['historical_incidents'][0]['state']
    missing=run('old_incident_no_recent_telemetry')
    assert missing['overall']<recovery['overall'] and not missing['behavioral']['available']

def test_unverified_closure_does_not_change_active_hazard():
    s=scenarios()['verified_incident_closure'];s['closures'][0]['verified']=False
    assert evaluate(**s)['overall']==run('known_incident')['overall']

def test_verified_remediation_preserves_history_and_does_not_mutate_input():
    s=scenarios()['verified_remediation'];before=deepcopy(s);r=evaluate(**s)
    assert s==before and r['overall']==100
    assert any(m['reason']=='VERIFIED_REMEDIATION_OR_OBSOLESCENCE' for c in r['contributors'] for m in c.get('members',[]))
    s['posture_rows'][0]['lifecycle']['verified']=False
    assert evaluate(**s)['overall']==run('confirmed_critical')['overall']

def test_explicit_false_positive_vs_dismissed_without_support():
    s=scenarios()['confirmed_critical'];s['posture_rows'][0].update(check_result='DISMISSED',confirmation_status='FALSE_POSITIVE')
    assert evaluate(**s)['overall']==100
    s['posture_rows'][0]['confirmation_status']='NOT_CONFIRMED'
    assert evaluate(**s)['overall']<100

def test_stale_posture_never_recovers_as_pass():
    s=scenarios()['confirmed_critical'];s['as_of']='2026-11-03T00:00:00+00:00'
    r=evaluate(**s);assert r['overall'] is None
    assert all(d['status']=='INSUFFICIENT_EVIDENCE' for d in r['dimensions'])

def test_fixed_denominator_and_no_reward_for_trivial_pass_inventory():
    a=run('confirmed_critical');s=scenarios()['confirmed_critical']
    for i in range(30):s['posture_rows'].append(dict(finding('D3','PASS'),finding_id='unregistered-pass-'+str(i),evidence_id='pass-'+str(i)))
    b=evaluate(**s);assert b['overall']==a['overall'] and b['coverage']==a['coverage']

def test_independent_supplementary_mapped_weakness_changes_hazard_not_denominator():
    s=scenarios()['normal_complete'];s['posture_rows'].append(dict(finding('D3'),finding_id='new-mapped',evidence_id='new'))
    b=evaluate(**s);a=run('normal_complete')
    assert b['overall']<a['overall'] and b['coverage']==a['coverage']

def test_known_supplementary_weakness_cannot_disappear_to_inflate_score():
    s=scenarios()['normal_complete'];extra=dict(finding('D3'),finding_id='mapped-addition',evidence_id='new')
    s['known_controls']=[{'control_id':'mapped-addition','root_id':'mapped-addition','dimension':'D3','platform_scope':'GENERIC_HTTP'}]
    s['posture_rows'].append(extra);a=evaluate(**s)
    s['posture_rows'].pop();b=evaluate(**s)
    assert b['overall']<=a['overall'] and compare(a,b)['comparable'] is False
    assert b['coverage']['missing_controls']

def test_unmapped_alert_visible_without_invented_penalty():
    s=scenarios()['normal_complete'];s['posture_rows'].append(dict(finding(),finding_id='ZAP-new',evidence_id='unmapped',category='UNMAPPED'))
    r=evaluate(**s);assert r['overall']==100 and r['warnings'][0]['reason'].startswith('UNMAPPED')

def test_aggregate_comparison_guard_limits_compensation():
    p=Policy();q={d:100 for d in p.weights};q['D1']=20
    assert aggregate(q,p.weights,'arithmetic')>aggregate(q,p.weights,'geometric')>aggregate(q,p.weights,guard=20)
    assert aggregate(q,p.weights,guard=20)<=40

def test_known_model_disagreement_uses_policy_not_uncalibrated_score_multiplier():
    s=scenarios()['known_incident'];s['observations'][0]['novelty_anomalous']=False
    s['observations'][0]['xgb_confidence']=.81;a=evaluate(**s)
    s['observations'][0]['xgb_confidence']=.999;b=evaluate(**s)
    assert a['overall']==b['overall'];assert a['behavioral']['active_incidents'][0]['reliability']==.8

def test_P12_traceable_every_dimension_and_policy_registry_hashes():
    r=run('confirmed_critical');assert r['policy']['sha256'] and registry()['sha256']
    for d in r['dimensions']:
        assert d['explanation'] and d['policy_weight']>0
        assert math.isclose(d['supported_hazard'],math.fsum(c['hazard'] for c in d['contributors']))
    assert r['contributors'][0]['members'][0]['source_id']

def test_evidence_reordering_does_not_change_result():
    s=scenarios()['duplicate_native_zap'];a=evaluate(**s);s['posture_rows'].reverse()
    assert evaluate(**s)==a

def test_active_validation_trace_retained_without_multiplying_contribution():
    s=scenarios()['confirmed_critical'];a=evaluate(**s)
    s['posture_rows'][0]['active_validation']={'status':'CONFIRMED','validator_id':'fixture-reviewed','executed':True}
    b=evaluate(**s);assert b['overall']==a['overall']
    assert b['contributors'][0]['members'][0]['active_validation']['validator_id']=='fixture-reviewed'

def test_registry_control_identities_unique_and_fixed():
    r=registry();assert len(r['controls'])==83
    assert len({c['control_id'] for c in r['controls']})==83
    assert len({(c['dimension'],c['root_id']) for c in r['controls']})==69

def test_conflicting_identity_fails_closed():
    s=scenarios()['normal_complete'];s['posture_rows'].append(dict(s['posture_rows'][0],check_result='FAIL'))
    with pytest.raises(ValueError,match='Conflicting'):evaluate(**s)

def test_different_assessments_cannot_be_mixed_as_current():
    s=scenarios()['normal_complete'];s['posture_rows'][0]['assessment_id']='first';s['posture_rows'][1]['assessment_id']='second'
    with pytest.raises(ValueError,match='one current'):evaluate(**s)

@pytest.mark.parametrize('values',[{'compensation_points':float('nan')},{'hazard_scale':float('inf')},{'weights':{'D1':1}},{'missing_control_hazard':.5}])
def test_invalid_policy_fails(values):
    with pytest.raises(ValueError):Policy(**values)

def test_P11_actual_backend_legacy_compatibility_and_new_versioned_contract():
    service=Application(Config());app=create_app(application=service)
    async def call():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://testserver') as c:
            old=await c.get('/api/cqi?mode=ACCEPTED_REPLAY&replay=BENIGN_TEST')
            new=await c.get('/api/cqi/v2?mode=ACCEPTED_REPLAY&replay=BENIGN_TEST')
            policy=await c.get('/api/cqi/v2/policy')
            bad=await c.get('/api/cqi/v2?as_of=not-a-time')
            return old,new,policy,bad
    old,new,p,bad=asyncio.run(call())
    assert old.status_code==new.status_code==p.status_code==200 and bad.status_code==503
    assert old.json()['policy']['formula_version']=='fusion-cqi-1.1'
    assert old.json()['overall']==pytest.approx(52.7587890625)
    assert new.json()['policy']['version']=='cqi-evidence-2.0' and not new.json()['is_probability']
    assert new.json()['comparison_context']['policy_change_is_security_change'] is False
    assert len(new.json()['dimensions'])==6

def test_live_api_uses_current_clock_and_retains_stale_evidence_as_unavailable(tmp_path,monkeypatch):
    from test_live_human_explainability import journal,record
    # The timestamp is deliberately old; neither re-scoring nor a recent UI
    # request is fresh collection. Reuse the existing saved-journal fixture.
    journal(tmp_path,record('BENIGN'))
    service=Application(Config(mode='LIVE_LAB'));service.control.session=tmp_path
    # Missing-posture fixture must not depend on the workstation's retained scans.
    monkeypatch.setattr(service.posture_service,'current',lambda:None)
    app=create_app(application=service)
    async def call():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://testserver') as c:
            return await c.get('/api/cqi/v2?mode=LIVE_LAB')
    response=asyncio.run(call());assert response.status_code==200
    data=response.json();assert data['overall_status']=='INSUFFICIENT_EVIDENCE'
    assert data['overall'] is None and not data['behavioral']['available']
    assert data['comparison_context']['as_of_semantics']=='CURRENT_UTC_OR_EXPLICIT_AS_OF'

def test_frozen_behavioral_hash_unchanged():
    assert verify(ROOT/'outputs/branch2/accepted_behavioral_v2')['root_sha256']=='59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436'
