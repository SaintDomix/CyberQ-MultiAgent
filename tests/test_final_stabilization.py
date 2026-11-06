"""Integrated candidate contracts: read-only artifacts and in-memory control fakes."""
from copy import deepcopy
from unittest.mock import patch
import pytest
from demo.backend.app import create_app
from demo.backend.config import Config,ROOT
from demo.backend.preview import preview_application,JournalReader
from demo.backend.runtime import SourceUnavailable
from test_ux_clarity import request
from test_ux_c2 import FakeStore

@pytest.fixture(scope='module')
def saved():
    service=preview_application(Config())
    app=create_app(Config(),service,read_only=True)
    return service,app

@pytest.mark.parametrize('path',[
 '/api/health','/api/application/snapshot','/api/product/assessment','/api/posture/findings?limit=2',
 '/api/behavior/observations?limit=2','/api/behavior/incidents?limit=2','/api/fusion/events?limit=2',
 '/api/cqi','/api/cqi/dimensions','/api/cqi/v2','/api/cqi/v2/policy',
 '/api/runtime/status','/api/model','/api/model/evaluation','/api/research/benchmark',
 '/api/research/normalization-example','/api/ingestion/schema','/api/report/final',
 '/reports/behavioral-v2.md','/reports/behavioral-v2.json','/report.html'])
def test_actual_saved_contracts(saved,path):
    service,app=saved
    response=request(app,'GET',path)
    assert response.status_code==200,path
    assert response.headers['cache-control']=='no-store'


def test_bound_findings_episodes_explanations_and_shap(saved):
    service,app=saved
    p=request(app,'GET','/api/product/assessment?mode=ACCEPTED_REPLAY&replay=ATTACK_HOLDOUT').json()
    obs=p['snapshot']['observations'][0];episode=p['snapshot']['incidents'][0];finding=p['snapshot']['posture'][0]
    for identity,expected in ((obs['observation_id'],'OBSERVATION'),(finding['finding_id'],'POSTURE'),(episode['episode_id'],'INCIDENT')):
        result=request(app,'GET','/api/product/evidence/'+identity+'?mode=ACCEPTED_REPLAY&replay=ATTACK_HOLDOUT').json()
        assert result['type']==expected
    explained=request(app,'GET','/api/explainability/'+obs['observation_id']+'?mode=ACCEPTED_REPLAY&replay=ATTACK_HOLDOUT').json()
    for field in ('summary','anomaly','classification','technical','provenance'):
        assert explained[field]==obs['explanation'][field]
    assert explained['shap']==obs['explanation']['shap']
    assert explained['uncalibrated_score']==obs['xgb_score']
    assert request(app,'GET','/api/behavior/incidents/'+episode['episode_id']).json()['observation_ids']==episode['observation_ids']
    assert len(p['scientific_cqi']['dimensions'])==6
    assert p['snapshot']['cqi']['policy']['formula_version']=='fusion-cqi-1.1'
    assert p['scientific_cqi']['policy']['version']=='cqi-evidence-2.0'


def test_selected_native_zap_evidence_and_no_historical_d6(saved):
    service,app=saved;job=service.posture_service.current();aid=job['assessment_id']
    p=request(app,'GET','/api/product/assessment?mode=LIVE_LAB&assessment_id='+aid).json()
    rows=p['snapshot']['posture'];sources={s for f in rows for s in f['evidence_sources']}
    assert 'NATIVE_POSTURE' in sources and any('ZAP' in s for s in sources)
    assert not p['scientific_cqi']['behavioral']['available']
    for source in ('NATIVE_POSTURE','ZAP_ACTIVE','ZAP_PASSIVE'):
        selected=next((f for f in rows if source in f['evidence_sources']),None)
        if selected:
            evidence=request(app,'GET','/api/product/evidence/'+selected['finding_id']+'?mode=LIVE_LAB&assessment_id='+aid).json()['data']
            assert evidence['assessment_id']==aid and evidence['member_evidence_ids']==selected['member_evidence_ids']
    assert request(app,'GET','/api/product/history?limit=5&offset=0').json()['total']>=len(p['history'])


def test_unexpected_contracts_fail_explicitly(saved):
    service,app=saved
    assert request(app,'GET','/api/product/history?limit=10000').status_code==422
    assert request(app,'GET','/api/unexpected-endpoint').status_code==404
    assert request(app,'GET','/api/explainability/missing-record').status_code==404
    with patch.object(service,'scientific_quality',side_effect=SourceUnavailable('Fixture: unavailable current evidence')):
        response=request(app,'GET','/api/product/assessment')
        assert response.status_code==503 and response.json()['error']=='SOURCE_UNAVAILABLE'
    for name in ('start','stop'):
        result=request(app,'POST','/api/runtime/'+name,headers={'X-Product-Control':'1'},json={})
        assert result.status_code==403 and result.json()['error']=='READ_ONLY_UX_PREVIEW'


class FakeMonitor(JournalReader):
    def __init__(self,config):super().__init__(config);self.calls=[];self.running=False
    def status(self):return {'process_running':self.running,'process_state':'RUNNING' if self.running else 'STOPPED','exit_code':None,'last_error':None,'session':None}
    def start(self):
        if self.running:raise SourceUnavailable('Fake monitor already running')
        self.calls.append('start');self.running=True;return self.status()
    def stop(self):self.calls.append('stop');self.running=False;return self.status()


def test_monitoring_controls_normal_app_with_fake_only():
    service=preview_application(Config(mode='LIVE_LAB'));service.control=FakeMonitor(service.config)
    app=create_app(service.config,service)
    assert request(app,'POST','/api/runtime/start',json={}).status_code==403
    assert not service.control.calls
    with patch('subprocess.Popen',side_effect=AssertionError('No process allowed')):
        headers={'X-Product-Control':'1'}
        assert request(app,'POST','/api/runtime/start',headers=headers,json={}).json()['process_running']
        assert request(app,'POST','/api/runtime/start',headers=headers,json={}).status_code==503
        assert not request(app,'POST','/api/runtime/stop',headers=headers,json={}).json()['process_running']
    assert service.control.calls==['start','stop']


@pytest.mark.parametrize('profile',['STANDARD','FULL_AUTHORIZED','PASSIVE_BASELINE'])
def test_profile_route_dispatch_is_preserved_with_fake_executor(saved,profile):
    service=preview_application(Config(mode='LIVE_LAB'));job=service.posture_service.current()
    service.posture_service=FakeStore(job,'COMPLETE');app=create_app(service.config,service)
    with patch('subprocess.Popen',side_effect=AssertionError('No scanner process allowed')):
        response=request(app,'POST','/api/posture/assessments',headers={'X-Product-Control':'1'},
            json={'mode':profile,'target_url':'http://192.168.226.132/moodle/','authorized':True})
    assert response.status_code==202
    call=service.posture_service.calls[0]
    assert call[0]=='start' and call[1][2]==profile
    assert service.posture_service.saved==job
