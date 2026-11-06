"""Offline gate tests. No executing scan/cancellation is claimed by this suite."""
import copy
import json
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'src')]
from posture.zap_active import ZapActiveStage, candidates, review_scanners, ENABLED_SCANNERS
from posture.providers import ZapAPI, zap_findings
from posture.policy import TARGET
from posture.orchestration import PostureAssessmentOrchestrator
from posture.model import deduplicate
from fusion.pipeline import assemble
from test_operational_posture import NativeFixture, CATALOG, native_row, alert, AT, application, request
from test_posture_demo_patch import SyntheticZap


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*a, **kw): raise AssertionError('No network or fitting')
    for name in ('socket.create_connection','socket.socket.connect', 'sklearn.svm.OneClassSVM.fit', 'xgboost.XGBClassifier.fit'):
        monkeypatch.setattr(name, deny)


def passive(aid='current'):
    return {'status':'COMPLETE','scope_integrity':{'result':'PASS'},'provenance':{
        'session_lifecycle':{'assessment_session_id':aid,'state':'COLLECTED'},
        'requests':[{'method':'GET','url':TARGET,'status':200},
            {'method':'GET','url':TARGET+'my/','status':303}]}}


class API:
    def __init__(self): self.calls=[]
    def call(self,c,k,n,**kw):
        self.calls.append((c,k,n,kw))
        assert k=='view', 'Never mutate runtime or dispatch scan'
        if n=='mode':return {'mode':'safe'}
        if n=='numberOfMessages':return {'numberOfMessages':'11'}
        if n=='scanners':return {'scanners':[{'id':'0','name':'Directory Browsing'}, {'id':'40019','name':'SQL Injection - MySQL (Time Based)'}, {'id':'999999','name':'New rule'}]}
        raise AssertionError('Unexpected control')


def stage():
    api=API();provider=Mock(api=api,owned_ephemeral=True)
    return ZapActiveStage(provider),api


@pytest.mark.parametrize('sid',['0','10106','40019','90020','90034','50000','999999'])
def test_no_installed_default_or_unknown_rule_is_implicitly_enabled(sid):
    assert ENABLED_SCANNERS==()
    review=review_scanners([{'id':sid,'name':'Rule','enabled':'true'}])[0]
    assert review['decision'].startswith('DISABLED_') and not review['enabled_by_application']


def test_installed_review_complete_and_every_rule_disabled():
    review=json.loads((ROOT/'docs/posture/ZAP_ACTIVE_SCANNER_REVIEW.json').read_text())
    assert review['review_count']==len(review['scanners'])==53
    assert review['decisions']=={'DISABLED_UNSAFE':42,'DISABLED_NOT_RELEVANT':4,'DISABLED_UNREVIEWED':7}
    assert not review['enabled_ids']


def test_forbidden_injection_callback_dos_and_execution_scanners_denied():
    for sid in ['40019','90020','90034','40044','40014','30001']:
        assert review_scanners([{'id':sid}])[0]['decision']=='DISABLED_UNSAFE'


@pytest.mark.parametrize('url',['http://evil.test/moodle/','http://127.0.0.1/moodle/',
    'http://169.254.169.254/latest/meta-data/','https://192.168.226.132/moodle/',
    'http://192.168.226.132/private','http://192.168.226.132/moodle/%252e%252e/admin/',
    TARGET+'?token=SECRET',TARGET+'#SECRET',TARGET+'login/logout.php'])
def test_candidate_scope_and_secret_url_rejected(url):
    p=passive();p['provenance']['requests']=[{'method':'GET','url':url,'status':200}]
    assert candidates(p,'current')==[]


def test_only_current_no_follow_normalized_deduplicated_gets_used():
    p=passive();p['provenance']['requests'] += [
        {'method':'GET','url':'http://192.168.226.132:80/moodle/','status':200},
        {'method':'POST','url':TARGET,'status':200},
        {'method':'GET','url':TARGET+'admin/','status':303,'location':'http://evil.test/'},
        {'method':'GET','url':TARGET+'course/','status':200}]
    assert candidates(p,'current')==[TARGET,TARGET+'course/']
    assert candidates(p,'old-session')==[]
    p['scope_integrity']['result']='FAIL'
    assert candidates(p,'current')==[]


def test_historical_urls_and_alerts_do_not_seed_current_stage():
    p=passive();p['historical_urls']=[TARGET+'admin/'];p['old_alerts']=[alert()]
    s,api=stage();r=s.run('current',p)
    assert r['selected_urls']==[TARGET] and not r['findings']
    assert not r['scan_started'] and r['scan_id'] is None
    assert r['historical_alerts_reused'] is False
    assert all(c[1]=='view' for c in api.calls)


def test_zero_rule_hard_ceiling_is_enforced_by_absence_of_dispatch():
    s,api=stage();r=s.run('current',passive())
    assert r['status']=='NOT_AVAILABLE' and r['reason_code']=='NO_REVIEWED_SAFE_SCANNERS'
    p=r['plan']
    assert p['hard_request_ceiling']==p['per_target_ceiling']==p['estimated_target_requests']==0
    assert p['maximum_scan_duration_seconds']==p['concurrency']==0
    assert r['target_message_delta']==0 and r['history_message_delta']==0
    assert r['budget_enforcement']=='NO_SCAN_DISPATCH_CAPABILITY'
    assert r['cancellation_reason'] is None  # No scan, not a claimed cancellation test.


@pytest.mark.parametrize('endpoint,params',[
    (('ascan','action','scan'),{'url':TARGET}),
    (('ascan','action','enableAllScanners'),{}),
    (('spider','action','scan'),{}),
    (('core','action','setMode'),{'mode':'protected'}),
    (('ascan','view','scanners'),{'scanPolicyName':'unreviewed'})])
def test_no_scan_dispatch_or_global_mode_weakening_in_closed_client(endpoint,params):
    session=Mock();api=ZapAPI('http://127.0.0.1:8081','secret',session=session)
    with pytest.raises(ValueError):api.call(*endpoint,**params)
    session.get.assert_not_called()


def test_inventory_deadline_and_errors_do_not_export_secrets():
    s,api=stage();api.call=Mock(side_effect=RuntimeError('cookie=SECRET token=SECRET'))
    r=s.run('current',passive())
    assert r['reason_code']=='ZAP_ACTIVE_INVENTORY_UNAVAILABLE' and not r['findings']
    assert 'SECRET' not in json.dumps(r)
    times=iter([0,0,9,9,9,9]);s,api=stage();s.clock=lambda:next(times)
    r=s.run('current',passive())
    assert r['reason_code']=='ZAP_ACTIVE_INVENTORY_UNAVAILABLE'


def test_safe_mode_not_silently_changed():
    s,api=stage();api.call=Mock(return_value={'mode':'standard'})
    assert s.run('current',passive())['reason_code']=='PASSIVE_SAFE_MODE_REQUIRED'
    assert api.call.call_count==1


@pytest.mark.parametrize('scanners',[[{'id':'../secret'}],[{'id':'0'},{'id':'0'}],[{'id':str(i)} for i in range(129)]])
def test_inventory_bounds_and_identity(scanners):
    with pytest.raises(ValueError):review_scanners(scanners)


def test_sanitizer_does_not_export_scanner_payloads_secrets_or_bodies():
    r=review_scanners([{'id':'999','name':'cookie=SECRET','description':'SECRET','attack':'SECRET','requestBody':'SECRET','policyId':'SECRET'}])
    assert 'SECRET' not in json.dumps(r)
    assert r[0]['name']=='[name withheld]' and r[0]['category_id'] is None


def test_native_passive_repository_active_survive_fourth_stage_failure(tmp_path):
    z=Mock();z.run.side_effect=RuntimeError('SECRET')
    engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativeFixture(),zap=SyntheticZap(),zap_active_stage=z)
    r=engine.start(mode='PASSIVE_BASELINE',background=False)
    assert r['provider_statuses']=={'native':'COMPLETE','zap':'COMPLETE'}
    assert r['active_validation_status']=='COMPLETE'
    assert r['zap_active_status']=='NOT_AVAILABLE' and r['status']=='PARTIAL'
    assert 'SECRET' not in json.dumps(r)
    assert r['findings'] and r['findings'][0]['active_validation']
    assert (engine.location(r['assessment_id'])/'zap_active.json').exists()


def test_rerun_uses_new_identity_preserves_first_and_never_admits_stale_rows(tmp_path):
    z=Mock()
    z.run.side_effect=lambda aid,p:{'status':'NOT_AVAILABLE','reason_code':'NO_REVIEWED_SAFE_SCANNERS','findings':[],'assessment_id':aid}
    native=NativeFixture();engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=native,zap=SyntheticZap(),zap_active_stage=z)
    a=engine.start(mode='PASSIVE_BASELINE',background=False);path=engine.location(a['assessment_id'])
    before={p.name:p.read_bytes() for p in path.iterdir()}
    b=engine.start(mode='PASSIVE_BASELINE',background=False)
    assert a['assessment_id']!=b['assessment_id'] and native.calls>=2 and z.run.call_count==2
    assert z.run.call_args_list[0].args[0]==a['assessment_id']
    assert z.run.call_args_list[1].args[0]==b['assessment_id']
    assert before=={p.name:p.read_bytes() for p in path.iterdir()}
    assert engine.get(a['assessment_id'])==a
    z.run.side_effect=lambda aid,p:{'status':'COMPLETE','findings':[native_row('old-session')],'scan_started':True}
    c=engine.start(mode='PASSIVE_BASELINE',background=False)
    assert c['zap_active_status']=='NOT_AVAILABLE'
    assert all(r['assessment_id']==c['assessment_id'] for r in c['findings'])


def test_four_sources_one_reviewed_weakness_not_four_penalties():
    n=native_row();p=copy.deepcopy(n);p.update(evidence_source='OWASP_ZAP',evidence_id='passive')
    a=copy.deepcopy(n);a.update(evidence_source='ZAP_ACTIVE',evidence_id='active')
    rows=deduplicate([n,p,a]);assert len(rows)==1
    rows[0]['active_validation']={'status':'CONFIRMED','score_effect':'NONE'}
    rows[0]['validation_sources']=['NATIVE_POSTURE','OWASP_ZAP','ACTIVE_VALIDATION','ZAP_ACTIVE']
    before=assemble(deduplicate([n]),[],'fixture','none',as_of=AT)
    after=assemble(rows,[],'fixture','none',as_of=AT)
    assert before['cqi']==after['cqi']
    assert before['dimensions']==after['dimensions']
    assert set(rows[0]['evidence_sources'])=={'NATIVE_POSTURE','OWASP_ZAP','ZAP_ACTIVE'}


def test_unmapped_existing_adapter_is_not_an_invented_penalty():
    # Regression of existing mapping, not acceptance of arbitrary active alerts.
    unknown=zap_findings([alert('999999')],'fixture',AT)[0]
    assert unknown[0]['category']=='UNMAPPED'
    base=assemble(deduplicate([native_row()]),[],'fixture','none',as_of=AT)
    combined=assemble(deduplicate([native_row(),*unknown]),[],'fixture','none',as_of=AT)
    assert base['cqi']['cqi']==combined['cqi']['cqi']
    assert base['dimensions']==combined['dimensions']
    assert combined['coverage']['branch1']['unmapped_categories']==['UNMAPPED']


def test_active_status_api_reports_current_result_without_running_scanner(application):
    from demo.backend.app import create_app
    service=application
    app=create_app(application=service,config=service.config)
    before=request(app,'/api/scanners/zap/active-status')
    assert before.status_code==200 and before.json()['status']=='NOT_RUN'
    job=service.posture_service.start(mode='PASSIVE_BASELINE',background=False,zap_enabled=False)
    r=request(app,'/api/scanners/zap/active-status')
    assert r.status_code==200 and r.json()['assessment_id']==job['assessment_id']
    assert r.json()['status']=='NOT_AVAILABLE'
    assert r.json()['summary']['scan_started'] is False


def test_accepted_behavioral_package_is_still_verified():
    from behavioral_runtime.package import verify
    package=verify(ROOT/'outputs/branch2/accepted_behavioral_v2')
    assert package['package_id']=='behavioral-v2-59a8c7c5d3d51632d0af'
