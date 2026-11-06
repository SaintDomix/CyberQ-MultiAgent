"""UX contracts use saved evidence and read-only adapters; no operational execution."""
import asyncio
from unittest.mock import patch
from pathlib import Path
import httpx
import pytest
from demo.backend.config import Config,ROOT
from demo.backend.preview import preview_application,create_preview,EvidenceStore,JournalReader
from demo.backend.product_quality import product_assessment,verified_root_resolution
from demo.backend.research_api import benchmark
from demo.backend.runtime import SourceUnavailable
from behavioral_runtime.package import verify

@pytest.fixture(scope='module')
def service():return preview_application(Config())

def request(app,method,path,**kw):
    async def call():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://testserver') as c:
            return await c.request(method,path,**kw)
    return asyncio.run(call())

def test_preview_has_no_monitor_or_scanner_controller(service):
    assert isinstance(service.control,JournalReader)
    assert isinstance(service.posture_service,EvidenceStore)
    assert not hasattr(service.posture_service,'providers')
    with pytest.raises(ValueError):service.control.start()
    with pytest.raises(ValueError):service.posture_service.start()
    assert service.control.process is None

@pytest.mark.parametrize('source,n,lower',[('BENIGN_TEST',33,.18541838299814833),('ATTACK_HOLDOUT',68,.09270919149907415)])
def test_bound_projection_reuses_saved_outputs_once(service,source,n,lower):
    with patch.object(service,'replay',wraps=service.replay) as reader:
        p=product_assessment(service,'ACCEPTED_REPLAY',source)
    assert reader.call_count==1
    assert len(p['snapshot']['observations'])==n
    assert p['scientific_cqi']['overall']==pytest.approx(lower)
    assert p['scientific_cqi']['policy']['version']=='cqi-evidence-2.0'
    assert p['snapshot']['cqi'].policy['formula_version']=='fusion-cqi-1.1'
    assert all(o.explanation.get('anomaly') for o in p['snapshot']['observations'])
    assert p['preview_read_only']

def test_historical_posture_never_reads_current_journal(service):
    job=next(j for j in service.posture_service.history() if j['status'] in ('COMPLETE','PARTIAL'))
    original=service.control.session;service.control.session=ROOT/'runtime/unused-fixture'
    try:
        with patch('demo.backend.services.read_journal',side_effect=AssertionError('Historical D6 must not read current journal')):
            p=product_assessment(service,'LIVE_LAB',assessment_id=job['assessment_id'])
    finally:service.control.session=original
    assert p['snapshot']['observations']==[] and p['snapshot']['incidents']==[]
    assert not p['scientific_cqi']['behavioral']['available']
    assert p['selection']['behavior_scope']=='UNPAIRED_HISTORICAL_POSTURE'
    assert p['scientific_cqi']['as_of'].replace('Z','+00:00')==job['completed_at'].replace('Z','+00:00')
    assert all(f.assessment_id==job['assessment_id'] for f in p['snapshot']['posture'])

def test_benchmark_is_verified_and_metric_roles_separate():
    p=benchmark();a,b,c=[p['pipelines'][x] for x in 'ABC']
    assert [v['attack']['novelty_window_recall']['count'] for v in (a,b,c)]==[65,41,3]
    assert [v['attack']['strict_end_to_end_recall']['count'] for v in (a,b,c)]==[63,40,3]
    assert all(v['attack']['production_run_recall']['count']==14 for v in (a,b,c))
    assert all(v['benign']['window_fpr']['count']==1 and v['benign']['window_fpr']['total']==33 for v in (a,b,c))
    assert all(v['benign']['false_incident_sessions']['count']==0 for v in (a,b,c))
    assert p['classification']['all_evaluation']['correct']==99
    assert p['classification']['attack_only']['correct']==66
    assert p['decision']['decision']=='KEEP_OCSVM' and not p['experiments_executed']
    assert len({v['classifier_sha256'] for v in (a,b,c)})==1

def test_benchmark_identity_fails_closed_without_fallback(monkeypatch):
    monkeypatch.setattr('demo.backend.research_api.BENCHMARK_ROOT','0'*64)
    with pytest.raises(SourceUnavailable):benchmark()

def test_preview_denies_every_write_and_scanner_probe(tmp_path):
    app=create_preview(ROOT/'demo/frontend/preview-ux-20261104')
    for path in ['/api/runtime/start','/api/runtime/stop','/api/demo/mode','/api/posture/assessments','/api/scanners/zap/passive-assessment','/api/ingestion/inspect']:
        response=request(app,'POST',path,json={},headers={'X-Product-Control':'1'})
        assert response.status_code==403 and response.json()['error']=='READ_ONLY_UX_PREVIEW'
    status=request(app,'GET','/api/scanners/zap/status').json()
    assert status['runtime_status']=='NOT_PROBED'
    assert request(app,'GET','/api/health').json()['preview_read_only'] is True

def test_product_api_values_and_bound_evidence(service):
    from demo.backend.app import create_app
    app=create_app(Config(),service,read_only=True)
    response=request(app,'GET','/api/product/assessment?mode=ACCEPTED_REPLAY&replay=BENIGN_TEST');assert response.status_code==200
    p=response.json();o=p['snapshot']['observations'][0]
    r=request(app,'GET','/api/product/evidence/'+o['observation_id']+'?mode=ACCEPTED_REPLAY&replay=BENIGN_TEST')
    assert r.status_code==200 and r.json()['data']['explanation']==o['explanation']
    bad=request(app,'GET','/api/product/assessment?mode=LIVE_LAB&assessment_id=../../secret')
    assert bad.status_code==503 and '../../secret' not in bad.text

def test_preview_rejects_stable_served_asset_path():
    with pytest.raises(ValueError):create_preview(ROOT/'demo/frontend/dist')


def test_current_evidence_guard_does_not_request_unpaired_historical_view(service):
    from demo.backend.app import create_app
    snap=service.snapshot('ACCEPTED_REPLAY','BENIGN_TEST')
    obs=snap['observations'][0]
    def bound(*args,**kwargs):
        assert kwargs['assessment_id'] is None
        kwargs['evidence']['assessment']={'assessment_id':'current-fixture'}
        return snap
    app=create_app(Config(),service,read_only=True)
    with patch.object(service,'snapshot',side_effect=bound):
        base='/api/product/evidence/'+obs.observation_id+'?mode=LIVE_LAB&expected_assessment_id='
        result=request(app,'GET',base+'current-fixture')
        assert result.status_code==200 and result.json()['type']=='OBSERVATION'
        assert request(app,'GET',base+'different-assessment').status_code==503

def test_partial_root_never_becomes_verified_remediation():
    old={'members':[{'finding_id':'A','hazard':1},{'finding_id':'B','hazard':1}]}
    after={'hazard':0,'coverage':.5,'members':[{'finding_id':'A','reason':'VERIFIED_REMEDIATION_OR_OBSOLESCENCE'}]}
    assert not verified_root_resolution(old,after)
    after['coverage']=1;assert not verified_root_resolution(old,after)

def test_accepted_model_hash_unchanged():
    assert verify(ROOT/'outputs/branch2/accepted_behavioral_v2')['root_sha256']=='59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436'


def test_observation_pagination_has_no_silent_200_limit(service):
    from demo.backend.app import create_app
    app=create_app(Config(),service,read_only=True)
    base='/api/product/observations?mode=ACCEPTED_REPLAY&replay=BENIGN_TEST&limit=25&offset='
    a=request(app,'GET',base+'0').json();b=request(app,'GET',base+'25').json()
    assert a['total']==b['total']==33 and len(a['items'])==25 and len(b['items'])==8
    assert not {x['observation_id'] for x in a['items']} & {x['observation_id'] for x in b['items']}
    job=service.posture_service.current()
    if job:
        r=request(app,'GET','/api/product/observations?mode=LIVE_LAB&assessment_id='+job['assessment_id']).json()
        assert r['items']==[] and r['total']==0


def test_preview_reads_never_contact_runtime_or_spawn_workers():
    app=create_preview(ROOT/'demo/frontend/preview-ux-20261104')
    with patch('subprocess.Popen',side_effect=AssertionError('No subprocess')),patch('requests.sessions.Session.request',side_effect=AssertionError('No scanner/network probe')):
        for path in ['/api/scanners/zap/status','/api/product/assessment?mode=ACCEPTED_REPLAY&replay=BENIGN_TEST','/api/research/benchmark','/api/research/normalization-example','/api/research/cqi-method','/api/research/cqi-sensitivity']:
            assert request(app,'GET',path).status_code==200


def test_normalization_example_keeps_generic_capability_limitations():
    from demo.backend.research_api import normalization_example
    v=normalization_example();assert v['value']['capabilities']['adapter']['platform_id']=='generic_web'
    assert 'no new ingestion' in v['evidence_type']
    assert v['value']['capabilities']['behavioral']['state']=='BEHAVIORAL_COMPATIBLE_WITH_OPTIONAL_CONTEXT_MISSING'
