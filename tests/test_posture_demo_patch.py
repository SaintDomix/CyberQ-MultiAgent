"""Synthetic current-Branch1/readiness/history tests; no laboratory requests."""
import json
from pathlib import Path
import shutil
import sys
from unittest.mock import Mock

import pytest
import requests

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from posture.providers import ZapPassiveProvider
from posture.policy import PassivePolicy, TARGET
from posture.native import Branch1CurrentProvider, NativeClient, fresh_internal
from posture.model import row
from posture.orchestration import PostureAssessmentOrchestrator
from demo.backend.app import create_app
from test_operational_posture import application, request, NativeFixture, CATALOG, AT, native_row
from test_zap_history import API


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def no(*a,**kw):raise AssertionError('No live requests or fitting')
    for name in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect',
                 'sklearn.svm.OneClassSVM.fit','xgboost.XGBClassifier.fit'):
        monkeypatch.setattr(name,no)


@pytest.mark.parametrize('used,expected',[(False,'READY'),(True,'READY')])
def test_reachable_zap_separates_readiness_from_runtime(used,expected):
    state=ZapPassiveProvider(API(shared=used)).readiness()
    assert state['status']==state['runtime_status']=='AVAILABLE'
    assert state['version']=='2.17.0' and state['assessment_readiness']==expected


@pytest.mark.parametrize('flag',['scanner','spider'])
def test_unsafe_zap_policy_is_blocked_while_runtime_is_available(flag):
    state=ZapPassiveProvider(API(**{flag:True})).readiness()
    assert state['runtime_status']=='AVAILABLE' and state['assessment_readiness']=='POLICY_BLOCKED'


def test_unowned_zap_skips_collection_but_native_still_executes(tmp_path):
    zap=ZapPassiveProvider(API(shared=True), owned_ephemeral=False)
    zap.start_assessment=Mock(side_effect=AssertionError('Unowned collection must not start'))
    native=NativeFixture();engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=native,zap=zap)
    job=engine.start(mode='PASSIVE_BASELINE',background=False)
    assert native.calls==1 and job['provider_statuses']=={'native':'COMPLETE','zap':'SKIPPED'}
    assert job['provider_reasons']['zap']=='POLICY_BLOCKED'
    assert job['raw_finding_counts']['zap']==0
    zap.start_assessment.assert_not_called()


class SyntheticZap:
    provider_name='Synthetic passive'; state='READY'; fail=False
    def readiness(self):return {'status':'AVAILABLE','runtime_status':'AVAILABLE','assessment_readiness':self.state,'version':'fixture'}
    def availability(self):return self.readiness()
    def supported_modes(self):return ['PASSIVE_BASELINE']
    def start_assessment(self,aid,policy):
        if self.fail:return {'provider_id':'zap','status':'FAILED','findings':[],'provenance':{}}
        return {'provider_id':'zap','status':'COMPLETE','completed_at':AT,'findings':[
            row('HDR-002','Security Headers','CSP','FAIL','HIGH','NOT_CONFIRMED','OWASP_ZAP',aid,AT,weakness_key='HDR-002'),
            row('ZAP-fixture','UNMAPPED','Unknown rule','NOT_REEVALUATED','INFO','NOT_TESTED','OWASP_ZAP',aid,AT)],'provenance':{}}


@pytest.mark.parametrize('later_failure',[False,True])
def test_last_success_survives_skipped_and_failed_attempts_and_stays_out_of_cqi(application,later_failure):
    engine=application.posture_service;zap=SyntheticZap();engine.providers['zap']=zap
    first=engine.start(mode='PASSIVE_BASELINE',background=False)
    preserved={p.name:p.read_bytes() for p in engine.location(first['assessment_id']).iterdir()}
    zap.state='READY' if later_failure else 'FRESH_SESSION_REQUIRED';zap.fail=later_failure
    class Passed(NativeFixture):
        def start_assessment(self,aid,policy,target_id='moodle-local'):
            out=super().start_assessment(aid,policy,target_id)
            out['findings'][0].update(check_result='PASS',operational_status='PASS',severity='INFO')
            return out
    engine.providers['native']=Passed()
    second=engine.start(mode='PASSIVE_BASELINE',background=False)
    assert second['provider_statuses']['zap']==('FAILED' if later_failure else 'SKIPPED')
    assert all('OWASP_ZAP' not in f['evidence_sources'] for f in second['findings'])
    assert application.current_posture_quality(second).overall==100
    assert engine.retained_zap()['assessment_id']==first['assessment_id']
    assert engine.retained_zap()['alert_count']==2 and engine.retained_zap()['counted_as_fresh_in_current_cqi'] is False
    assert preserved=={p.name:p.read_bytes() for p in engine.location(first['assessment_id']).iterdir()}
    app=create_app(application=application,config=application.config)
    status=request(app,'/api/scanners/zap/status').json()
    assert status['runtime_status']=='AVAILABLE' and status['fresh_alerts_in_current_run']==0
    assert status['last_successful_assessment']['assessment_id']==first['assessment_id']
    retained=request(app,'/api/scanners/zap/findings?view=retained').json()
    assert len(retained['items'])==2 and retained['counted_as_fresh_in_current_cqi'] is False
    assert all(f['assessment_scope']=='RETAINED_ZAP_EVIDENCE' for f in retained['items'])
    assert request(app,'/api/scanners/zap/findings?view=current').json()['items']==[]


def test_fresh_success_still_enters_current_canonical_findings(application):
    application.posture_service.providers['zap']=SyntheticZap()
    job=application.posture_service.start(mode='PASSIVE_BASELINE',background=False)
    assert job['provider_statuses']['zap']=='COMPLETE' and job['multi_source_count']==1
    assert any('OWASP_ZAP' in f['evidence_sources'] for f in job['findings'])
    assert job['coverage']['unmapped_zap_rules']==1
    assert job['coverage']['not_checked_in_run']==len(application.posture_service.catalog)-1
    assert job['coverage']['not_reevaluated']==job['coverage']['not_checked_in_run']+1


def test_retention_refuses_hash_corruption(application):
    engine=application.posture_service;engine.providers['zap']=SyntheticZap()
    job=engine.start(mode='PASSIVE_BASELINE',background=False)
    (engine.location(job['assessment_id'])/'zap.json').write_text('corrupt')
    with pytest.raises(ValueError):engine.retained_zap()


def synthetic_http():
    s=Mock();s.headers={};s.proxies={}
    def send(method,url,**kw):
        r=requests.Response();r.url=url;r.status_code=200
        if '/my/' in url or '/admin/' in url or '/report/security/' in url:
            r.status_code=303;r.headers['Location']=TARGET+'login/index.php'
        if url.endswith('install.php'):
            r.status_code=303;r.headers['Location']=TARGET+'admin/index.php?lang=en'
        if any(url.endswith(p) for p in ('README.txt','upgrade.txt','composer.json','package.json','phpunit.xml.dist','Gruntfile.js')):r.status_code=404
        r.headers['Set-Cookie']='MoodleSession=DO_NOT_PERSIST; HttpOnly; Path=/moodle/'
        r._content=b'<html>Moodle<form method="post"><input name="logintoken" value="DO_NOT_PERSIST"></form>log in password</html>'
        r._content_consumed=True
        return r
    s.request.side_effect=send
    return s


def test_full_provider_reuses_accepted_modules_with_fresh_evidence_and_shared_budget(tmp_path,monkeypatch):
    (tmp_path/'src/branch1').mkdir(parents=True)
    shutil.copyfile(ROOT/'src/branch1/advisories.json',tmp_path/'src/branch1/advisories.json')
    moodle=tmp_path/'moodle';moodle.mkdir();(moodle/'config.php').write_text('fixture only')
    s=synthetic_http()
    collector=Mock(return_value=({'core':{'version':'2024100700','branch':'405','release':'fixture'},'settings':{},'filesystem':{},'runtime':{}},
                                {'collector_status':'NOT_AVAILABLE','reason_code':'MOODLE_CONFIG_NOT_READABLE_BY_DEMO_UID'}))
    from posture import native
    monkeypatch.delenv('B1_ACTIVE_CONTEXT',raising=False);monkeypatch.delenv('POSTURE_ENABLE_EXISTING_ACTIVE',raising=False)
    for name in ('external','internal','intelligence'):
        module=getattr(native,name);monkeypatch.setattr(module,'assess',Mock(wraps=module.assess))
    p=Branch1CurrentProvider(tmp_path,lambda policy:NativeClient(policy,session=s),collector=collector,moodle_root=moodle)
    result=p.start_assessment('fixture',PassivePolicy())
    assert result['status']=='COMPLETE'
    for name in ('external','internal','intelligence'):getattr(native,name).assess.assert_called_once()
    ids={f['finding_id'] for f in result['findings']}
    assert {'MOODLE-001','AUTH-001','AUTH-002','ACCESS-001','HTTP-002','CORE-001','FS-001'}<=ids
    assert any(fid.startswith('ADV-') for fid in ids)
    from posture.native_plan import MAX_REQUESTS
    assert result['provenance']['total_request_count']<=MAX_REQUESTS and result['provenance']['cache_hits']>0
    assert 'DO_NOT_PERSIST' not in json.dumps(result)
    assert all(f['assessment_id']=='fixture' for f in result['findings'])
    assert next(f for f in result['findings'] if f['finding_id']=='FS-001')['operational_status']=='NOT_REEVALUATED'


def test_fresh_version_is_reassessed_even_when_config_cannot_be_read(tmp_path,monkeypatch):
    (tmp_path/'version.php').write_text("<?php $version = 2024100700.00; $branch = '405'; $release = '4.5';")
    (tmp_path/'config.php').write_text('DO_NOT_READ_OR_EXPORT')
    monkeypatch.setattr('posture.native.os.access',lambda p,mode:Path(p).name!='config.php')
    run=Mock(side_effect=AssertionError('Unreadable config must not bootstrap PHP'))
    monkeypatch.setattr('posture.native.subprocess.run',run)
    payload,meta=fresh_internal(ROOT,tmp_path,99999999999)
    assert payload['core']['branch']=='405' and payload['core']['version']=='2024100700.00'
    assert meta['reason_code']=='MOODLE_CONFIG_NOT_READABLE_BY_DEMO_UID'
    assert not payload['settings'] and 'DO_NOT_READ_OR_EXPORT' not in json.dumps(payload)
    run.assert_not_called()


def test_native_scope_is_explicit_and_does_not_expand_zap_scope():
    from posture.providers import StrictClient
    s=synthetic_http();n=NativeClient(PassivePolicy(),session=s)
    assert n.allowed_url(TARGET+'README.txt') and n.allowed_url('http://192.168.226.132/server-status')
    assert not n.allowed_url('http://evil.test/server-status') and not n.allowed_url(TARGET+'admin/delete.php')
    assert not n.allowed_url(TARGET+'install.php')
    z=StrictClient(PassivePolicy(),session=synthetic_http())
    assert not z.allowed_url(TARGET+'README.txt')
    with pytest.raises(requests.RequestException):z.trace(TARGET)
