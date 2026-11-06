"""Live reader -> real API contract tests with isolated numeric journal fixtures."""
import asyncio
import copy
import hashlib
import json
from unittest.mock import Mock,patch
import httpx
import pytest
from branch2.reconciliation import reconcile
from branch2.live_storage import Journal,atomic_json
from behavioral_runtime.incidents import Incidents
from behavioral_runtime.package import verify
from demo.backend.config import Config,ROOT
from demo.backend.explainability import baseline,digest
from demo.backend.explanation_sources import live_window_evidence
from demo.backend.runtime import read_journal
from demo.backend.adapters import observation
from demo.backend.services import Application
from demo.backend.app import create_app
from demo import operations


PACKAGE='behavioral-v2-59a8c7c5d3d51632d0af'
SCHEMA='b85df9aac8b1d8d9553db6e3e8bee4e7496ad9ea9b9d6db96bec3715d5d54caa'


def record(kind='BENIGN',shap=True):
    anomalous=kind!='BENIGN';label='BENIGN' if not anomalous else 'SQLI_ATTEMPT'
    score=.7 if kind=='UNKNOWN_ANOMALY' else .99
    values={k:v['median'] for k,v in baseline()['features'].items()}
    if anomalous:values.update(request_count=40.,request_rate=4.,sql_token_count=5.,client_error_ratio=.6)
    p={'record_id':'fixture-observation','observation_id':'fixture-observation','sequence':1,
        'session_id':'fixture','run_id':'fixture','window_start':'2020-01-01T00:00:00+00:00',
        'window_end':'2020-01-01T00:00:10+00:00','client_id':'pseudo-client','user_agent_id':'pseudo-agent',
        'source_sha256':'a'*64,'schema_sha256':SCHEMA,'model_id':PACKAGE,'training_performed':False,
        'confidence_calibrated':False,'successful_exploitation_confirmed':False,
        'emitted_at_utc':'2020-01-01T00:00:10+00:00','feature_schema_version':'dataset-v3.1-features-2.1',
        'novelty_anomalous':anomalous,'if_anomalous':anomalous,
        'novelty_score':.4 if anomalous else 2.,'novelty_threshold':1.2667822314625847,
        'xgb_label':label,'xgb_confidence':score,'reconciliation':reconcile(anomalous,label,score,.8),
        'robust_deviations':[], 'shap_explanation':{'status':'AVAILABLE' if shap else 'NOT_REQUESTED',
            'top_features':[{'feature':'sql_token_count','contribution':3.}] if shap and anomalous else []}}
    row={k:p[k] for k in ('window_start','window_end','client_id','user_agent_id','source_sha256')}
    row.update(features=values,schema_sha256=SCHEMA)
    return {'prediction':p,'window':{'record_id':p['record_id'],'observation_id':p['record_id'],'session_id':'fixture','row':row}}


def adapted(stored):
    values,evidence=live_window_evidence(stored,PACKAGE,SCHEMA,'payload-hash')
    return observation(stored['prediction'],{},PACKAGE,features=values,feature_evidence=evidence)


def journal(path,stored):
    atomic_json(path/'session_manifest.json',{'model_id':PACKAGE,'schema_sha256':SCHEMA,
        'session_id':'fixture','source_path':'/fixture/access.log'})
    atomic_json(path/'checkpoint.json',{'source':{'read_offset':100,'safe_offset':100},
        'updated_at_utc':stored['prediction']['window_end'],'integrity_status':'OK'})
    j=Journal(path);es=Incidents(j,2,PACKAGE);j.persist(stored['window'],stored['prediction']);es.sync();j.close()


def test_live_resolver_reuses_actual_vector_and_binds_identity():
    stored=record();values,e=live_window_evidence(stored,PACKAGE,SCHEMA,'verified-payload-hash')
    assert values is stored['window']['row']['features']
    assert len(values)==83 and e['vector_sha256']==digest(values)
    assert e['observation_id']==stored['prediction']['record_id'] and e['identity_verified']
    assert e['journal_payload_sha256']=='verified-payload-hash' and e['recomputed'] is False


@pytest.mark.parametrize('kind',['BENIGN','UNKNOWN_ANOMALY','SQLI_ATTEMPT'])
def test_live_states_get_same_engine_structured_explanation(kind):
    s=record(kind);o=adapted(s);e=o.explanation
    assert e['anomaly']['verdict']==o.novelty_state
    assert e['classification']['class']==o.xgb_label
    assert e['evidence_quality']['available_features']==83
    assert e['provenance']['feature_evidence']['used_evidence']=='RETAINED_INFERENCE_VECTOR'


def test_unknown_does_not_require_confident_known_class():
    o=adapted(record('UNKNOWN_ANOMALY'));e=o.explanation
    assert o.reconciled_label=='UNKNOWN_ANOMALY' and not o.actionable
    assert e['anomaly']['factors'] and e['classification']['class']=='SQLI_ATTEMPT'
    assert e['classification']['score']==.7 and e['classification']['accepted_confidence_threshold']==.8
    assert 'no known class is asserted' in e['summary']


def test_missing_shap_still_explains_actual_anomaly():
    e=adapted(record('UNKNOWN_ANOMALY',False)).explanation
    assert e['anomaly']['factors'] and e['evidence_quality']['shap_status']=='NOT_REQUESTED'
    assert any(f['feature']=='sql_token_count' for f in e['classification']['factors'])


def test_structured_factors_match_real_values_and_reference():
    s=record('UNKNOWN_ANOMALY');e=adapted(s).explanation
    for f in e['anomaly']['factors']+e['classification']['factors']:
        assert f['observation']==s['window']['row']['features'][f['feature']]
        assert f['reference']==baseline()['features'][f['feature']]['median']
        assert f['direction'] and f['comparison']
    assert 'UNCALIBRATED' in e['classification']['score_semantics']


@pytest.mark.parametrize('mutation,reason',[
    ('missing','FEATURE_VECTOR_NOT_RETAINED'),('schema','FEATURE_VECTOR_SCHEMA_MISMATCH'),
    ('identity','FEATURE_VECTOR_IDENTITY_MISMATCH'),('incomplete','FEATURE_VECTOR_INCOMPLETE'),
    ('nonfinite','FEATURE_VECTOR_NONFINITE_OR_INVALID'),('prediction','FEATURE_VECTOR_PREDICTION_MISMATCH')])
def test_missing_or_wrong_evidence_has_specific_reason(mutation,reason):
    s=record()
    if mutation=='missing':s['window']['row'].pop('features')
    elif mutation=='schema':s['window']['row']['schema_sha256']='other'
    elif mutation=='identity':s['window']['row']['window_start']='different'
    elif mutation=='incomplete':s['window']['row']['features'].pop('request_rate')
    elif mutation=='nonfinite':s['window']['row']['features']['request_rate']=float('inf')
    else:s['prediction']['robust_deviations']=[{'feature':'request_rate','value':999.,'signed_deviation':1.}]
    o=adapted(s)
    assert o.explanation['evidence_quality']['reason_code']==reason
    assert 'anomaly' not in o.explanation
    assert o.reconciled_label=='BENIGN'


def test_live_privacy_allowlists_vector_and_provenance():
    s=record('UNKNOWN_ANOMALY');s['window']['row']['raw_query']='password=DO_NOT_EXPORT'
    s['window']['cookie']='DO_NOT_EXPORT';s['prediction']['body']='DO_NOT_EXPORT'
    o=adapted(s);assert 'DO_NOT_EXPORT' not in json.dumps(o.explanation)


def test_journal_projection_does_not_mutate_predictions_or_incidents(tmp_path):
    journal(tmp_path,record('UNKNOWN_ANOMALY'))
    before=hashlib.sha256((tmp_path/'journal.sqlite3').read_bytes()).hexdigest()
    a,ae,_=read_journal(tmp_path,PACKAGE,SCHEMA)
    b,be,_=read_journal(tmp_path,PACKAGE,SCHEMA,include_features=True)
    assert b[0].pop('_explanation_evidence')['status']=='RESOLVED'
    assert len(b[0].pop('_explanation_features'))==83
    assert a==b and ae==be
    assert hashlib.sha256((tmp_path/'journal.sqlite3').read_bytes()).hexdigest()==before


@pytest.mark.parametrize('kind',['BENIGN','UNKNOWN_ANOMALY'])
def test_production_api_exposes_live_structured_explanation(tmp_path,kind):
    journal(tmp_path,record(kind));service=Application(Config(mode='LIVE_LAB'));service.control.session=tmp_path
    app=create_app(application=service)
    async def call():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://testserver') as c:
            rows=(await c.get('/api/behavior/observations?mode=LIVE_LAB')).json()['items']
            e=await c.get('/api/explainability/'+rows[0]['observation_id']+'?mode=LIVE_LAB')
            return rows[0],e
    o,response=asyncio.run(call());assert response.status_code==200
    assert response.json()['anomaly']==o['explanation']['anomaly']
    assert response.json()['provenance']['feature_evidence']['package_root_sha256']==Config().expected_root
    assert o['explanation']['evidence_quality']['available_features']==83


def test_retained_restart_validates_path_before_child_start():
    with patch('demo.operations.owned',return_value=False),patch('demo.operations.subprocess.Popen') as child:
        with pytest.raises(ValueError):operations.start('LIVE_LAB',8000,'../escape')
        with pytest.raises(ValueError):operations.start('ACCEPTED_REPLAY',8000,'runtime/behavioral_v2/fixture')
    child.assert_not_called()


def test_retained_restart_does_not_start_or_adopt_monitor(tmp_path):
    state=tmp_path/'state.json';log=tmp_path/'backend.log'
    # Only lifecycle orchestration is mocked; no real process or lab request.
    model={'integrity':'VERIFIED','package_id':PACKAGE,'schema_sha256':SCHEMA}
    with patch('demo.operations.STATE',state),patch('demo.operations.owned',return_value=False), \
        patch('demo.backend.services.Application') as app,patch('demo.backend.runtime.read_journal'), \
        patch('demo.operations.preflight',return_value={'result':'PASS','model_package_id':PACKAGE}), \
        patch('demo.operations.identity',return_value={'start_ticks':'1'}), \
        patch('demo.operations.subprocess.Popen') as factory,patch('demo.operations.status',return_value={'backend':'OK'}), \
        patch('demo.operations.api',return_value={'model_integrity':'VERIFIED'}) as api:
        app.return_value.model.return_value=model;factory.return_value.pid=123;factory.return_value.poll.return_value=None
        result=operations.start('LIVE_LAB',8000,'runtime/behavioral_v2/fixture')
    assert result['backend']=='OK'
    assert factory.call_args.kwargs['env']['PRODUCT_RUNTIME_SESSION']=='runtime/behavioral_v2/fixture'
    assert all('/api/runtime/start' not in c.args for c in api.call_args_list)


def test_accepted_hash_is_unchanged():
    assert verify(ROOT/'outputs/branch2/accepted_behavioral_v2')['root_sha256']==Config().expected_root
