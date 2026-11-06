"""Operational profile selection, preservation, freshness and bounded execution."""
import copy
import json
import inspect
import hashlib
from pathlib import Path
from unittest.mock import Mock,patch
import pytest
from test_zap_full_authorized import SyntheticAPI,alert,offline
from test_operational_posture import NativeFixture,CATALOG,AT,application,request,native_row
from test_posture_demo_patch import synthetic_http
from test_current_active import stage,current
from posture.zap_standard import StandardBudget,scanner_policy,MANIFEST,POLICY_ID
from posture.zap_full import FullZapProvider,FullBudget,EXCLUDED
from posture.target import AuthorizedTarget
from posture.orchestration import PostureAssessmentOrchestrator
from posture.native import Branch1CurrentProvider,NativeClient
from posture.model import deduplicate
from posture.active import CurrentExecutor,CurrentSafetyPolicy
from branch1.active.models import RequestSpec
from branch1.active.safety import SafetyError
from fusion.pipeline import assemble
from demo.backend.schemas import PostureAction
from demo.backend.app import create_app

ROOT=Path(__file__).resolve().parents[1]
SELECTED={'0','20019','40003','40012','40018','40032','40034'}


def standard(tmp_path,change=None):
    target=AuthorizedTarget('https://school.example/',True,scan_profile='STANDARD')
    api=SyntheticAPI(None,target)
    if change:change(api)
    return FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),tmp_path,api_factory=lambda *a:api).run('fixture',target),api


def test_standard_is_default_and_requires_authorization():
    assert inspect.signature(PostureAssessmentOrchestrator.start).parameters['mode'].default=='STANDARD'
    assert PostureAction(authorized=True).mode=='STANDARD'
    with pytest.raises(ValueError):PostureAction()
    assert PostureAction(mode='PASSIVE_BASELINE').mode=='PASSIVE_BASELINE'
    assert PostureAction(mode='FULL_AUTHORIZED',authorized=True).mode=='FULL_AUTHORIZED'


def test_standard_policy_uses_measured_prospective_manifest_and_nonzero_selection():
    m=json.loads(MANIFEST.read_text());assert m['selection_before_standard_acceptance']
    assert len(m['scanners'])==53
    installed=[{'id':r['scanner_id'],'name':r['name']} for r in m['scanners']]
    p=scanner_policy(installed)
    assert p['id']==POLICY_ID and set(p['enabled_ids'])==SELECTED
    assert p['manifest_sha256']==hashlib.sha256(MANIFEST.read_bytes()).hexdigest()


@pytest.mark.parametrize('sid,state',[('6','DEEP_ONLY_RUNTIME'),('40026','DEEP_ONLY_BROWSER'),('40024','DEEP_ONLY_TECHNOLOGY_SPECIFIC'),('40019','DEEP_ONLY_TECHNOLOGY_SPECIFIC')])
def test_expensive_rules_are_deep_only_with_actual_measurements(sid,state):
    row=next(r for r in json.loads(MANIFEST.read_text())['scanners'] if r['scanner_id']==sid)
    assert row['standard_state']==state and row['full_authorized_state']=='ENABLED'
    assert row['previous_observed_runtime_ms']>0 and row['previous_request_count']>0


def test_missing_and_new_rules_do_not_get_silently_enabled():
    p=scanner_policy([{'id':'999999','name':'New unreviewed rule'}])
    assert p['enabled_ids']==[]
    assert next(r for r in p['scanner_review'] if r['scanner_id']=='999999')['standard_state']=='DEEP_ONLY_UNREVIEWED'
    assert next(r for r in p['scanner_review'] if r['scanner_id']=='40018')['standard_state']=='NOT_INSTALLED'


def test_full_policy_and_budget_are_preserved_against_frozen_real_snapshot():
    old=json.loads((ROOT/'runtime/posture/posture-20261027T184230Z-2760023ac85e/zap.json').read_text())
    selected={str(s['id']) for s in old['inventory']['active_scanners'] if str(s['id']) not in EXCLUDED}
    assert len(selected)==43 and selected==set(old['policy']['enabled_ids'])
    assert old['policy']['bounds']==FullBudget().__dict__
    assert SELECTED<selected


def test_standard_reuses_full_executor_and_performs_fresh_passive_and_actual_active(tmp_path):
    r,api=standard(tmp_path)
    assert r['status']=='COMPLETE' and r['assessment_profile']=='STANDARD'
    assert r['policy']['id']==POLICY_ID and len(r['policy']['enabled_ids'])>0
    assert '40018' in r['policy']['enabled_ids'] and '40012' in r['policy']['enabled_ids']
    assert r['stages']['passive']['queue_complete'] and r['stages']['active']['status']=='COMPLETE'
    assert r['active_alerts']==2 and r['passive_alerts']==1
    assert len([n for c,k,n,p in api.calls if n=='newSession'])==1
    assert any(c=='ascan' and n=='scan' for c,k,n,p in api.calls)
    assert r['session_lifecycle']=='FRESH_VERIFIED_EMPTY' and r['final_zap_mode']=='safe'


def test_standard_discovery_is_explicitly_not_browser_failure(tmp_path):
    r,api=standard(tmp_path)
    assert r['stages']['spider']['status']=='COMPLETE'
    assert r['target_profile']['discovery_profile']=='SPIDER'
    assert r['stages']['clientSpider']['status']==r['stages']['ajaxSpider']['status']=='NOT_RUN_STANDARD'
    assert not any(c in ('clientSpider','ajaxSpider') and n=='scan' for c,k,n,p in api.calls)
    assert any(c=='spider' and n=='setOptionMaxDepth' and p['Integer']=='3' for c,k,n,p in api.calls)


def test_standard_strength_does_not_weaken_full_policy(tmp_path):
    r,api=standard(tmp_path)
    assert r['policy']['attack_strength']=='LOW'
    from test_zap_full_authorized import run
    full,_=run(tmp_path)
    assert full['policy']['attack_strength']=='MEDIUM' and full['profile']=='FULL_AUTHORIZED'
    assert full['stages']['clientSpider']['status']=='COMPLETE'


@pytest.mark.parametrize('kwargs',[{'overall_seconds':301},{'active_seconds':181},{'spider_seconds':26},{'cleanup_seconds':60}])
def test_standard_cannot_expand_its_limits(kwargs):
    with pytest.raises(ValueError):StandardBudget(**kwargs)


class Factory:
    instances=[]
    def __init__(self,passive,project):self.project=project
    def run(self,aid,target,**kw):
        api=SyntheticAPI(None,target);self.instances.append(api)
        return FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),self.project,api_factory=lambda *a:api).run(aid,target,**kw)


def test_two_standard_runs_refresh_native_zap_passive_active_validation_and_active(tmp_path):
    native=NativeFixture();active,_=stage(tmp_path);active.run=Mock(wraps=active.run)
    engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=native,active_stage=active,full_provider_factory=Factory)
    before=len(Factory.instances)
    a=engine.start(authorized=True,background=False)
    saved={p.name:p.read_bytes() for p in engine.location(a['assessment_id']).iterdir()}
    b=engine.start(authorized=True,background=False)
    assert a['assessment_id']!=b['assessment_id'] and native.calls==2 and active.run.call_count==2
    assert a['assessment_profile']==b['assessment_profile']=='STANDARD'
    assert b['active_validation_status']=='COMPLETE'
    assert all(f['assessment_id']==b['assessment_id'] for f in b['findings'])
    assert saved=={p.name:p.read_bytes() for p in engine.location(a['assessment_id']).iterdir()}
    for api in Factory.instances[before:]:
        assert any(n=='newSession' for c,k,n,p in api.calls)
        assert any(c=='ascan' and n=='scan' for c,k,n,p in api.calls)
    assert b['assessment_budget']['hard_seconds']==480


def test_real_native_response_change_reaches_canonical_cqi_in_standard(tmp_path):
    sessions=[]
    def client(policy):
        s=synthetic_http();original=s.request.side_effect
        if sessions:
            def fixed(*a,**kw):
                r=original(*a,**kw);r.headers['Content-Security-Policy']="default-src 'self'";return r
            s.request.side_effect=fixed
        sessions.append(s);return NativeClient(policy,session=s)
    native=Branch1CurrentProvider(ROOT,client,collector=Mock(return_value=({'core':{},'settings':{},'filesystem':{},'runtime':{}},{'collector_status':'NOT_AVAILABLE','reason_code':'FIXTURE_NO_INTERNAL_COLLECTOR'})))
    class FixedFactory(Factory):
        count=0
        def run(self,aid,target,**kw):
            api=SyntheticAPI(None,target);original=api.call
            self.__class__.count+=1
            if self.count==2:
                def call(c,k,n,**p):
                    if n=='alerts':return {'alerts':[]}  # Fresh scanner no longer reports CSP.
                    if n=='alertsIds':return {'alertsIds':[]}
                    return original(c,k,n,**p)
                api.call=call
            return FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),self.project,api_factory=lambda *a:api).run(aid,target,**kw)
    active,_=stage(tmp_path)
    e=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=native,active_stage=active,full_provider_factory=FixedFactory)
    a=e.start(authorized=True,background=False);saved={p.name:p.read_bytes() for p in e.location(a['assessment_id']).iterdir()}
    b=e.start(authorized=True,background=False)
    csp=lambda j:next(f for f in j['findings'] if f['finding_id']=='HDR-002')
    assert csp(a)['check_result']=='FAIL' and csp(b)['check_result']=='PASS'
    qa=assemble(a['findings'],[],'current','none',as_of=AT);qb=assemble(b['findings'],[],'current','none',as_of=AT)
    assert qb['cqi']['cqi']>qa['cqi']['cqi']
    assert all(s.request.call_count>0 for s in sessions) and len(sessions)==2
    assert saved=={p.name:p.read_bytes() for p in e.location(a['assessment_id']).iterdir()}


def test_api_default_standard_and_first_class_zap_only_finding(application):
    engine=application.posture_service;engine.full_provider_factory=Factory;start=engine.start
    engine.start=lambda *a,**kw:start(*a,**kw,background=False)
    app=create_app(application=application,config=application.config)
    r=request(app,'/api/posture/assessments','POST',{'authorized':True},{'X-Product-Control':'1'})
    assert r.status_code==202,r.text
    assert r.json()['assessment_profile']=='STANDARD'
    rows=request(app,'/api/posture/findings?view=current&limit=200').json()['items']
    assert any(f['source']=='ZAP_ACTIVE' and f['status']=='FAIL' and f['cqi_mapping']=='UNMAPPED' for f in rows)
    profiles=request(app,'/api/scanners').json()
    assert profiles['default_profile']=='STANDARD' and 'FULL_AUTHORIZED' in profiles['profiles']
    assert 'SECRET' not in json.dumps(rows)


def test_explicit_passive_legacy_route_never_inherits_the_active_default(application):
    e=application.posture_service;start=e.start
    e.start=lambda *a,**kw:start(*a,**kw,background=False)
    e.full_provider_factory=Mock(side_effect=AssertionError('Passive alias must not start DAST'))
    app=create_app(application=application,config=application.config)
    r=request(app,'/api/scanners/zap/passive-assessment','POST',{}, {'X-Product-Control':'1'})
    assert r.status_code==202 and r.json()['assessment_profile']=='PASSIVE_BASELINE'
    e.full_provider_factory.assert_not_called()
    assert request(app,'/api/scanners/zap/passive-assessment','POST',{'mode':'STANDARD','authorized':True},{'X-Product-Control':'1'}).status_code==422


def test_standard_uses_same_configurable_target_without_moodle_results(tmp_path):
    e=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativeFixture(),full_provider_factory=Factory)
    generic={'provider_id':'native','status':'COMPLETE','findings':[],
        'provenance':{'platform':'generic_web','moodle_collector_run':False}}
    with patch('platform_normalization.posture.collect_generic',return_value=generic) as collect:
        r=e.start(target_url='https://another.example/lms/',authorized=True,background=False)
    assert r['assessment_profile']=='STANDARD' and r['provider_statuses']['native']=='COMPLETE'
    assert r['target']=='https://another.example/lms/'
    assert collect.call_count==1 and collect.call_args.args[2].target_url==r['target']
    assert not any('NATIVE_POSTURE' in f['evidence_sources'] for f in r['findings'])  # Empty generic fixture never reuses lab findings; ZAP may independently map HDR-002.


def test_validation_cannot_admit_protocol_past_remaining_global_deadline(tmp_path):
    a,s=stage(tmp_path);rows=[current()]
    a.clock=lambda:100
    r=a.run(rows,'fixture',absolute_deadline=101)
    assert r['budget']['actual_requests']==0 and rows[0]['active_validation']['status']=='NOT_RUN'
    assert 'STANDARD assessment deadline' in rows[0]['active_validation']['reason']


def test_standard_active_deadline_preserves_passive_and_cancels_owned_job(tmp_path):
    t=AuthorizedTarget('https://school.example/',True,scan_profile='STANDARD');api=SyntheticAPI(None,t);original=api.call;clock=[0]
    def call(c,k,n,**kw):
        if c=='ascan' and n=='status':return {'status':'10'}
        if c=='ascan' and n=='scans' and api.active:return {'scans':[{'id':'1','state':'RUNNING','progress':'10'}]}
        return original(c,k,n,**kw)
    api.call=call
    r=FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),tmp_path,api_factory=lambda *a:api,clock=lambda:clock[0],pause=lambda s:clock.__setitem__(0,clock[0]+s)).run('fixture',t,budget=StandardBudget(active_seconds=1))
    assert r['status']=='PARTIAL' and r['stages']['active']['status']=='PARTIAL'
    assert r['stages']['passive']['queue_complete'] and r['passive_alerts']==1
    assert any(c=='ascan' and n=='stop' for c,k,n,p in api.calls)


def test_standard_stage_reserves_bounded_cleanup_inside_absolute_deadline(tmp_path):
    t=AuthorizedTarget('https://school.example/',True,scan_profile='STANDARD');api=SyntheticAPI(None,t);clock=[0];original=api.call
    def call(c,k,n,**p):
        assert p['control_deadline']<=50
        return original(c,k,n,**p)
    api.call=call
    r=FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),tmp_path,api_factory=lambda *a:api,clock=lambda:clock[0]).run('fixture',t,absolute_deadline=50)
    assert r['status']=='COMPLETE' and r['final_zap_mode']=='safe'


def test_validation_request_does_not_start_when_timeout_would_cross_global_deadline():
    from posture.policy import TARGET
    spec=RequestSpec(url=TARGET,purpose='bounded fixture')
    policy=CurrentSafetyPolicy(TARGET,True,True,1,5,.25)
    session=Mock();session.headers={}
    executor=CurrentExecutor(policy,specs=[spec],session=session,clock=lambda:100,absolute_deadline=101)
    with pytest.raises(SafetyError):executor.get(spec)
    session.get.assert_not_called()


def test_standard_does_not_use_historical_full_findings(tmp_path):
    class Broken(Factory):
        def run(self,aid,target,**kw):return {'status':'FAILED','findings':[],'profile':'STANDARD'}
    e=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativeFixture(),full_provider_factory=Factory)
    old=e.start(mode='FULL_AUTHORIZED',authorized=True,background=False)
    e.full_provider_factory=Broken
    new=e.start(authorized=True,background=False)
    assert any('ZAP_ACTIVE' in f['evidence_sources'] for f in old['findings'])
    assert not any('ZAP_ACTIVE' in f['evidence_sources'] for f in new['findings'])
    assert new['provider_statuses']['native']=='COMPLETE' and new['active_validation_status']=='COMPLETE'
    assert e.get(old['assessment_id'])['assessment_profile']=='FULL_AUTHORIZED'


def test_cqi_comparison_does_not_treat_profile_coverage_change_as_remediation(application):
    e=application.posture_service;e.full_provider_factory=Factory
    old=e.start(mode='FULL_AUTHORIZED',authorized=True,background=False)
    new=e.start(authorized=True,background=False)
    app=create_app(application=application,config=application.config)
    r=request(app,'/api/posture/assessments/'+new['assessment_id']).json()
    assert r['before_after']['before'] is None
    assert r['before_after']['comparison_scope']=='SAME_TARGET_AND_ASSESSMENT_PROFILE'
    assert e.get(old['assessment_id'])['assessment_profile']=='FULL_AUTHORIZED'


def test_historical_api_profile_is_derived_from_original_mode_without_mutation(application,monkeypatch):
    old={'assessment_id':'historical-full','mode':'FULL_AUTHORIZED','status':'PARTIAL','started_at':AT}
    monkeypatch.setattr(application.posture_service,'history',lambda:[old])
    app=create_app(application=application,config=application.config)
    r=request(app,'/api/posture/assessments').json()['items'][0]
    assert r['assessment_profile']=='FULL_AUTHORIZED' and 'assessment_profile' not in old


def test_standard_duplicate_native_passive_active_evidence_does_not_add_penalties(tmp_path):
    r,_=standard(tmp_path);n=native_row()
    before=assemble(deduplicate([n]),[],'current','none',as_of=AT)
    rows=deduplicate([n,*r['findings']]);csp=[f for f in rows if f['finding_id']=='HDR-002']
    assert len(csp)==1 and csp[0]['member_count']==2
    assert any('ZAP_ACTIVE' in f['evidence_sources'] and f['category']=='UNMAPPED' for f in rows)
    after=assemble(rows,[],'current','none',as_of=AT)
    assert before['cqi']['cqi']==after['cqi']['cqi']
