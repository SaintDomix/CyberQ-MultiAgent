"""Bounded current active evidence; all HTTP is mocked, no lab requests or fitting."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest
import requests

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from posture.active import (ActiveValidationStage,CurrentExecutor,CurrentSafetyPolicy,HARD_CEILING,MAXIMUM)
from posture.model import row,deduplicate
from posture.policy import TARGET
from posture.orchestration import PostureAssessmentOrchestrator
from branch1.active.runtime import RuntimeContext
from branch1.active.models import RequestSpec
from branch1.active.safety import SafetyError
from fusion.pipeline import assemble
from demo.backend.adapters import finding
from test_operational_posture import NativeFixture,CATALOG,AT,application,request


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*a,**kw):raise AssertionError('No network or fitting')
    for name in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect',
                 'sklearn.svm.OneClassSVM.fit','xgboost.XGBClassifier.fit'):
        monkeypatch.setattr(name,deny)
    monkeypatch.delenv('B1_ACTIVE_CONTEXT',raising=False)


def current(fid='EXPOSURE-001',title='Exposed Apache server-status',category='Exposure',aid='fixture',status='FAIL',confirmation='CONFIRMED'):
    return row(fid,category,title,status,'MEDIUM',confirmation,'NATIVE_POSTURE',aid,AT,
               weakness_key=fid,evidence={'current':True})


def session_for(reply):
    s=Mock();s.headers={}
    def get(url,**kw):
        status,body=reply(url)
        r=Mock();r.__enter__=Mock(return_value=r);r.__exit__=Mock(return_value=False)
        r.status_code=status;r.headers={'Content-Type':'text/html','Set-Cookie':'MoodleSession=SECRET_COOKIE'}
        r.iter_content.return_value=[body.encode()]
        return r
    s.get.side_effect=get
    return s


def stage(tmp_path,reply=None):
    s=session_for(reply or (lambda u:(404,'missing') if '__branch1_control_' in u else (200,'Apache Server Status; Server Uptime: 10')))
    def factory(policy,**kw):
        return CurrentExecutor(policy,session=s,sleep=lambda n:None,**kw)
    return ActiveValidationStage(tmp_path,executor_factory=factory),s


def test_confirmed_exposure_has_sanitized_evidence_and_preserves_parent(tmp_path):
    rows=deduplicate([current()]);before=copy.deepcopy(rows);a,s=stage(tmp_path)
    summary=a.run(rows,'fixture');v=rows[0]['active_validation']
    assert v['status']=='CONFIRMED' and v['validator_id']=='sensitive_path'
    assert v['request_count']==2 and v['baseline_observation']['status']==200
    assert v['probe_observations'][0]['status']==404
    assert v['evidence_summary']['outcome']=='EXPOSED_CONTENT'
    assert summary['counts']['eligible']==summary['counts']['executed']==1
    assert summary['budget']['actual_requests']==summary['budget']['planned_requests']==2
    assert rows[0]['check_result']==before[0]['check_result']=='FAIL'
    assert rows[0]['confirmation_status']==before[0]['confirmation_status']
    assert 'SECRET_COOKIE' not in json.dumps(summary)+json.dumps(rows)
    assert 'body' not in v['baseline_observation']
    assert all(c.kwargs['allow_redirects'] is False for c in s.get.call_args_list)


def test_negative_active_result_does_not_turn_finding_into_pass(tmp_path):
    rows=deduplicate([current()]);a,_=stage(tmp_path,lambda u:(200,'same generic page'))
    a.run(rows,'fixture');v=rows[0]['active_validation']
    assert v['status']=='NOT_CONFIRMED' and rows[0]['check_result']=='FAIL'
    assert 'false positive' in v['not_confirmed_semantics'] and v['score_effect']=='NONE'


@pytest.mark.parametrize('fid',['HDR-001','HDR-002','COOKIE-MoodleSession-SECURE','ADV-MSA-26-0031','FS-001','PATCH-001'])
def test_direct_controls_are_na_and_send_no_active_requests(tmp_path,fid):
    rows=deduplicate([current(fid,'Directly observed control')]);a,s=stage(tmp_path)
    result=a.run(rows,'fixture')
    assert rows[0]['active_validation']['status']=='NOT_APPLICABLE'
    assert result['budget']['planned_requests']==result['budget']['actual_requests']==0
    s.get.assert_not_called()


@pytest.mark.parametrize('title,validator',[('SQL injection indication','sql_injection'),('Unsafe reflection / XSS indication','unsafe_reflection_xss'),('Open redirect indication','open_redirect'),('Account enumeration','account_enumeration'),('Access control indication','access_control'),('Session behavior indication','session_control'),('SSRF context indication','ssrf_context')])
def test_missing_real_runtime_prerequisites_are_visible(tmp_path,title,validator):
    rows=deduplicate([current('F-CONTEXT',title,'Application Security')]);a,s=stage(tmp_path)
    a.run(rows,'fixture');v=rows[0]['active_validation']
    assert v['status']=='NOT_AVAILABLE' and v['validator_id']==validator
    assert v['reason'] and v['prerequisite_state']=='MISSING_CONTEXT'
    s.get.assert_not_called()


def test_native_zap_active_have_one_unchanged_fusion_penalty(tmp_path):
    n=current();z={**current(),'evidence_source':'OWASP_ZAP','evidence_id':'zap-fixture','confirmation_status':'NOT_CONFIRMED'}
    rows=deduplicate([n,z]);assert len(rows)==1 and rows[0]['multi_source']
    before=assemble(copy.deepcopy(rows),[],'fixture','none',as_of=AT)
    a,_=stage(tmp_path);a.run(rows,'fixture')
    after=assemble(rows,[],'fixture','none',as_of=AT)
    assert after==before
    assert rows[0]['validation_sources']==['ACTIVE_VALIDATION','NATIVE_POSTURE','OWASP_ZAP']
    assert len(rows)==1 and rows[0]['member_count']==2


def test_second_assessment_reruns_and_keeps_first_snapshot(tmp_path):
    class Native(NativeFixture):
        def start_assessment(self,aid,policy,target_id='moodle-local'):
            return {'status':'COMPLETE','findings':[current(aid=aid)],'provenance':{}}
    a,s=stage(tmp_path);engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=Native(),active_stage=a)
    first=engine.start(mode='PASSIVE_BASELINE',background=False,zap_enabled=False)
    path=engine.location(first['assessment_id']);preserved={p.name:p.read_bytes() for p in path.iterdir()}
    second=engine.start(mode='PASSIVE_BASELINE',background=False,zap_enabled=False)
    assert s.get.call_count==4 and first['assessment_id']!=second['assessment_id']
    assert preserved=={p.name:p.read_bytes() for p in path.iterdir()}
    assert first['findings'][0]['active_validation']['candidate_id']!=second['findings'][0]['active_validation']['candidate_id']
    assert all(f['active_validation']['assessment_id']==second['assessment_id'] for f in second['findings'])
    assert (engine.location(second['assessment_id'])/'active_validation.json').is_file()
    assert engine.get(first['assessment_id'])==first


def test_transport_failure_is_isolated_without_exporting_exception_secrets(tmp_path):
    a,s=stage(tmp_path);s.get.side_effect=requests.ReadTimeout('SECRET_PASSWORD cookie=SECRET_COOKIE')
    rows=deduplicate([current()]);r=a.run(rows,'fixture')
    assert rows[0]['active_validation']['status']=='NOT_AVAILABLE'
    assert rows[0]['active_validation']['request_count']==1
    assert rows[0]['check_result']=='FAIL'
    assert 'SECRET' not in json.dumps(rows)+json.dumps(r)


def test_stage_failure_does_not_prevent_native_or_zap_completion(tmp_path):
    from test_posture_demo_patch import SyntheticZap
    a=Mock();a.run.side_effect=RuntimeError('SECRET')
    engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativeFixture(),zap=SyntheticZap(),active_stage=a)
    job=engine.start(mode='PASSIVE_BASELINE',background=False)
    assert job['provider_statuses']=={'native':'COMPLETE','zap':'COMPLETE'}
    assert job['active_validation_status']=='FAILED' and job['status']=='PARTIAL'
    assert 'SECRET' not in json.dumps(job)
    assert any(f['check_result']=='FAIL' for f in job['findings'])


@pytest.mark.parametrize('url',['http://evil.test/moodle/x','http://127.0.0.1/moodle/x','http://169.254.169.254/latest/meta-data/','http://192.168.226.132/private','http://192.168.226.132/moodle/%252e%252e/x'])
def test_off_lab_and_unreviewed_paths_are_blocked(url):
    p=CurrentSafetyPolicy(TARGET,True,True,2)
    with pytest.raises(SafetyError):p.check(RequestSpec(url,'forbidden'))


def test_exact_protocol_plan_rejects_unplanned_requests(tmp_path):
    s=session_for(lambda u:(200,'generic'));p=CurrentSafetyPolicy(TARGET,True,True,2)
    e=CurrentExecutor(p,specs=[],session=s)
    with pytest.raises(SafetyError):e.get(RequestSpec(TARGET,'not planned'))
    s.get.assert_not_called()


def test_derived_budget_admits_only_whole_protocols(tmp_path,monkeypatch):
    rows=deduplicate([current('SQL-'+str(i),'SQL injection indication','Application Security') for i in range(8)])
    mappings={r['finding_id']:{'sql_injection':{'url':TARGET+'course/search.php','parameter':'q','baseline_value':'sample','read_only':True}} for r in rows}
    monkeypatch.setenv('B1_ACTIVE_CONTEXT',json.dumps({'mappings':mappings}))
    a,s=stage(tmp_path,lambda u:(200,'generic'));r=a.run(rows,'fixture')
    assert HARD_CEILING==sum(MAXIMUM.values())==23
    assert r['budget']['planned_requests']==r['budget']['actual_requests']==20
    assert r['counts']['executed']==5 and r['counts']['NOT_RUN']==3
    assert s.get.call_count==20
    assert all(x['check_result']=='FAIL' for x in rows)


def test_ssrf_context_is_request_free(tmp_path,monkeypatch):
    rows=deduplicate([current('F-SSRF','SSRF context indication','Application Security')])
    monkeypatch.setenv('B1_ACTIVE_CONTEXT',json.dumps({'mappings':{'F-SSRF':{'ssrf_context':{'feature_enabled':True,'url_fetch_available':True,'feature_evidence':'current authorized configuration'}}}}))
    a,s=stage(tmp_path);r=a.run(rows,'fixture')
    assert r['budget']['actual_requests']==0 and r['counts']['executed']==1
    assert rows[0]['active_validation']['support_level']=='CONTEXTUAL'
    assert rows[0]['active_validation']['status']=='NOT_CONFIRMED'
    s.get.assert_not_called()


def test_sqli_signal_keeps_likely_support_without_promoting_exploitation(tmp_path,monkeypatch):
    from urllib.parse import parse_qs,urlsplit
    rows=deduplicate([current('F-SQL','SQL injection indication','Application Security')])
    monkeypatch.setenv('B1_ACTIVE_CONTEXT',json.dumps({'mappings':{'F-SQL':{'sql_injection':{
        'url':TARGET+'course/search.php','parameter':'q','baseline_value':'sample','read_only':True}}}}))
    def reply(url):return 200,('SQLSTATE[42000] parser error' if parse_qs(urlsplit(url).query).get('q')==["sample'"] else 'ordinary response')
    a,_=stage(tmp_path,reply);a.run(rows,'fixture');v=rows[0]['active_validation']
    assert v['status']=='NOT_CONFIRMED' and v['support_level']=='LIKELY'
    assert v['evidence_summary']['outcome']=='REPRODUCIBLE_DB_ERROR'
    assert v['successful_exploitation_confirmed'] is False and rows[0]['check_result']=='FAIL'


def test_authorized_role_cookies_and_identity_markers_never_export(tmp_path,monkeypatch):
    rows=deduplicate([current('F-ACCESS','Access control indication','Access Control')])
    ctx={'url':TARGET+'admin/','restricted_session':'LAB_LOW','privileged_session':'LAB_HIGH',
         'restricted_role':'student','privileged_role':'administrator','roles_verified':True,
         'identity_markers':{'restricted':'PRIVATE_LOW_MARKER','privileged':'PRIVATE_HIGH_MARKER'},
         'privileged_markers':['PRIVATE_CAPABILITY_MARKER'],'expected_denied':True,'read_only':True}
    monkeypatch.setenv('ROLE_LOW_COOKIE','MoodleSession=LOW_SECRET')
    monkeypatch.setenv('ROLE_HIGH_COOKIE','MoodleSession=HIGH_SECRET')
    monkeypatch.setenv('B1_ACTIVE_CONTEXT',json.dumps({'mappings':{'F-ACCESS':{'access_control':ctx}},
        'sessions':{'LAB_LOW':{'role':'student','cookie_env':'ROLE_LOW_COOKIE'},
                    'LAB_HIGH':{'role':'administrator','cookie_env':'ROLE_HIGH_COOKIE'}}}))
    a,s=stage(tmp_path);original=s.get.side_effect
    def get(url,**kw):
        r=original(url,**kw)
        high='HIGH_SECRET' in kw['headers']['Cookie']
        r.status_code=200 if high else 403
        r.iter_content.return_value=[b'PRIVATE_HIGH_MARKER PRIVATE_CAPABILITY_MARKER' if high else b'access denied']
        return r
    s.get.side_effect=get
    result=a.run(rows,'fixture');v=rows[0]['active_validation']
    assert v['executed'] and v['request_count']==4 and v['status']=='NOT_CONFIRMED'
    assert rows[0]['check_result']=='FAIL'
    output=json.dumps(result)+json.dumps(rows)+json.dumps(finding(rows[0]).model_dump())
    for secret in ('LOW_SECRET','HIGH_SECRET','PRIVATE_HIGH_MARKER','PRIVATE_LOW_MARKER','PRIVATE_CAPABILITY_MARKER','LAB_LOW','LAB_HIGH'):
        assert secret not in output


def test_api_returns_active_evidence_without_session_secrets(application):
    from demo.backend.app import create_app
    a,s=stage(application.config.repository)
    class Native(NativeFixture):
        def start_assessment(self,aid,policy,target_id='moodle-local'):
            return {'status':'COMPLETE','findings':[current(aid=aid)],'provenance':{}}
    application.posture_service.providers['native']=Native();application.posture_service.active_stage=a
    job=application.posture_service.start(mode='PASSIVE_BASELINE',background=False,zap_enabled=False)
    api=request(create_app(application=application,config=application.config),'/api/posture/findings?view=current').json()
    first=next(f for f in api['items'] if f['finding_id']=='EXPOSURE-001')
    assert first['active_validation']['status']=='CONFIRMED'
    assert first['active_validation']['assessment_id']==job['assessment_id']
    assert 'SECRET_COOKIE' not in json.dumps(api)
