"""C2 operational parity uses fake executors and saved evidence, never lab actions."""
from copy import deepcopy
import hashlib
from pathlib import Path
from threading import Event
from unittest.mock import patch
import pytest
from demo.backend.config import Config,ROOT
from demo.backend.preview import preview_application,EvidenceStore
from demo.backend.posture_projection import assessment_metadata,execution_metadata
from demo.backend.product_quality import product_assessment
from posture.orchestration import PostureAssessmentOrchestrator
from test_ux_clarity import request


@pytest.fixture(scope='module')
def selected():
    store=EvidenceStore(ROOT)
    return next(j for j in store.history() if j['status'] in ('COMPLETE','PARTIAL'))


class FakeStore(EvidenceStore):
    """Only existing in-memory cancellation semantics; no provider construction."""
    pending_id='posture-20990101T000000Z-aaaaaaaaaaaa'
    def __init__(self,selected,state='RUNNING'):
        super().__init__(ROOT);self.saved=deepcopy(selected);self.calls=[];self.cancellations={}
        self.attempt=deepcopy(selected) if state in ('COMPLETE','PARTIAL') else {
            'assessment_id':self.pending_id,'status':state,'target':selected['target'],
            'mode':'STANDARD','assessment_profile':'STANDARD','started_at':'2099-01-01T00:00:00+00:00',
            'completed_at':None,'provider_statuses':{'native':'COMPLETE','zap':state},
            'zap_progress':{'active':{'status':state,'request_count':7,'progress':12}},
            'error':'Fixture interrupted; no completed evidence' if state in ('FAILED','INTERRUPTED') else None}
        self.attempt['status']=state
        if state=='RUNNING':
            self.jobs[self.pending_id]=self.attempt;self.cancellations[self.pending_id]=Event()
    def history(self):
        return [deepcopy(self.attempt)]+([] if self.attempt['assessment_id']==self.saved['assessment_id'] else [deepcopy(self.saved)])
    def get(self,aid):
        self.location(aid)
        if aid==self.attempt['assessment_id']:return deepcopy(self.attempt)
        if aid==self.saved['assessment_id']:return deepcopy(self.saved)
        raise ValueError('Unknown fixture assessment')
    def latest(self,successful=False):
        return next((j for j in self.history() if not successful or j['status'] in ('COMPLETE','PARTIAL')),None)
    def cancel(self,aid):
        self.calls.append(('cancel',aid))
        return PostureAssessmentOrchestrator.cancel(self,aid)
    def start(self,*args,**kwargs):
        self.calls.append(('start',args,kwargs))
        if self.attempt['status'] in ('QUEUED','RUNNING'):raise ValueError('Owned fixture job already running')
        return self.get(self.attempt['assessment_id'])


def service_for(selected,state='RUNNING',read_only=True):
    service=preview_application(Config(mode='LIVE_LAB'))
    service.posture_service=FakeStore(selected,state);service.preview_read_only=read_only
    return service


@pytest.mark.parametrize('state',['QUEUED','RUNNING','COMPLETE','PARTIAL','FAILED','INTERRUPTED'])
def test_selected_snapshot_and_latest_execution_are_independent(selected,state):
    service=service_for(selected,state)
    before=deepcopy(selected)
    p=product_assessment(service,'LIVE_LAB',assessment_id=selected['assessment_id'])
    assert p['assessment']['assessment_id']==selected['assessment_id']
    assert p['latest_execution']['status']==state
    assert p['latest_execution']['start_blocked']==(state in ('QUEUED','RUNNING'))
    assert p['scientific_cqi']['comparison_context']['assessment_id']==selected['assessment_id']
    assert not p['scientific_cqi']['behavioral']['available']
    assert service.posture_service.saved==selected==before
    assert service.posture_service.calls==[]


@pytest.mark.parametrize('state',['QUEUED','RUNNING','FAILED','INTERRUPTED'])
def test_missing_live_completion_never_becomes_accepted_baseline(selected,state):
    p=product_assessment(service_for(selected,state),'LIVE_LAB')
    assert p['assessment'] is None and p['selection']['assessment_id'] is None
    assert p['selection']['profile'] is None
    assert p['selection']['evidence_state']=='NO_COMPLETED_CURRENT_POSTURE'
    assert p['latest_execution']['status']==state
    assert all(f.status not in ('PASS','FAIL') for f in p['snapshot']['posture'])


def test_cancel_only_explicit_owned_running_job_and_no_get_side_effect(selected):
    from demo.backend.app import create_app
    service=service_for(selected,read_only=False);store=service.posture_service
    app=create_app(Config(mode='LIVE_LAB'),service)
    response=request(app,'GET','/api/product/assessment?mode=LIVE_LAB&assessment_id='+selected['assessment_id'])
    assert response.status_code==200 and response.json()['latest_execution']['cancellation']['eligible']
    assert not store.calls and not store.cancellations[store.pending_id].is_set()
    response=request(app,'POST','/api/posture/assessments/'+store.pending_id+'/cancel',headers={'X-Product-Control':'1'})
    assert response.status_code==200 and response.json()['status']=='CANCELLATION_REQUESTED'
    assert store.calls==[('cancel',store.pending_id)] and store.cancellations[store.pending_id].is_set()
    assert not execution_metadata(service,store.attempt)['cancellation']['eligible']
    assert store.saved==selected


def test_preview_and_unowned_jobs_cannot_offer_cancellation(selected):
    service=service_for(selected)
    assert not execution_metadata(service,service.posture_service.attempt)['cancellation']['eligible']
    service.preview_read_only=False;service.posture_service.jobs={}
    assert not execution_metadata(service,service.posture_service.attempt)['cancellation']['eligible']


def test_duplicate_start_rejected_by_existing_route_with_fake_executor(selected):
    from demo.backend.app import create_app
    service=service_for(selected,read_only=False);app=create_app(Config(),service)
    response=request(app,'POST','/api/posture/assessments',json={'mode':'STANDARD','authorized':True,
        'target_url':selected['target']},headers={'X-Product-Control':'1'})
    assert response.status_code==409 and service.posture_service.calls[0][0]=='start'
    assert service.posture_service.saved==selected


def test_hash_verified_historical_counts_recovered_without_mutation():
    store=EvidenceStore(ROOT);aid='posture-20261027T172357Z-b6df0bf04712'
    job=store.get(aid);path=store.location(aid)/'snapshot.json';before=hashlib.sha256(path.read_bytes()).hexdigest()
    p=assessment_metadata(store,job)
    assert p['zap_execution']['passive_alerts']==1182
    assert p['zap_execution']['active_alerts']==0
    assert p['zap_execution']['alert_count_derivation'].startswith('HASH_VERIFIED')
    assert job['zap_execution'].get('passive_alerts') is None
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before


def test_missing_count_source_is_explicitly_unavailable(tmp_path,selected):
    store=FakeStore(selected,'COMPLETE')
    job=deepcopy(selected);job['zap_execution']={}
    with patch.object(store,'location',return_value=tmp_path):p=assessment_metadata(store,job)
    assert p['zap_execution']['alert_count_availability']=='SOURCE_UNAVAILABLE'
    assert p['zap_execution'].get('active_alerts') is None


def test_complete_attempt_history_paginates_all_statuses(selected):
    from demo.backend.app import create_app
    service=service_for(selected);store=service.posture_service
    jobs=[{**store.attempt,'assessment_id':'posture-20990101T000000Z-'+format(i,'012x'),
           'status':['COMPLETE','PARTIAL','RUNNING','FAILED','INTERRUPTED','QUEUED'][i%6]} for i in range(61)]
    with patch.object(store,'history',return_value=jobs):
        app=create_app(Config(),service,read_only=True)
        pages=[request(app,'GET','/api/product/history?limit=25&offset='+str(offset)).json() for offset in (0,25,50)]
    assert all(p['total']==61 for p in pages)
    assert [len(p['items']) for p in pages]==[25,25,11]
    assert len({j['assessment_id'] for p in pages for j in p['items']})==61
    assert {j['status'] for p in pages for j in p['items']}=={'COMPLETE','PARTIAL','RUNNING','FAILED','INTERRUPTED','QUEUED'}


def test_current_execution_does_not_change_selected_cqi(selected):
    first=product_assessment(service_for(selected,'RUNNING'),'LIVE_LAB',assessment_id=selected['assessment_id'])
    second=product_assessment(service_for(selected,'FAILED'),'LIVE_LAB',assessment_id=selected['assessment_id'])
    assert first['scientific_cqi']==second['scientific_cqi']
