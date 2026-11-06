"""Pure presentation QA and read-only accepted-evidence acceptance. No training."""
import asyncio
import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
import httpx
import pytest
from demo.backend.explainability import (baseline, canonical, digest, explain, incident_explanation,
    MAX_FACTORS, safe_shap)
from demo.backend.feature_catalog import CATALOG, catalog_entry
from demo.backend.config import Config, ROOT
from demo.backend.services import Application
from demo.backend.app import create_app
from scripts.build_explanation_reference import build
from behavioral_runtime.package import verify


def prediction(label='SQLI_ATTEMPT', anomalous=True, shap=True):
    return {'xgb_label': label, 'xgb_confidence': .94, 'novelty_anomalous': anomalous,
        'novelty_score': 1.0, 'reconciliation': {'decision': label,
            'model_disagreement': False}, 'robust_deviations': [],
        'shap_explanation': {'status': 'AVAILABLE' if shap else 'NOT_REQUESTED',
            'top_features': [{'feature': 'sql_token_count', 'contribution': 2.5}] if shap else []}}


def vector(**overrides):
    return {**{k: r['median'] for k, r in baseline()['features'].items()}, **overrides}


def test_frozen_package_and_schema_identity():
    m = verify(ROOT / Config().accepted)
    assert m['root_sha256'] == Config().expected_root
    schema = json.loads((ROOT / Config().accepted / 'model/feature_schema.json').read_text())
    assert schema['sha256'] == 'b85df9aac8b1d8d9553db6e3e8bee4e7496ad9ea9b9d6db96bec3715d5d54caa'
    assert len(schema['feature_order']) == len(CATALOG) == 83
    assert set(CATALOG) == set(schema['feature_order'])


def test_catalog_verified_sources_and_unknown_stays_technical():
    for entry in CATALOG.values():
        assert entry['verified'] and entry['definition'] and entry['formatter']
        for source in entry['source'].split('; '):
            assert (ROOT / source.split(':')[0]).is_file()
    assert catalog_entry('feature_999')['human_readable'] is False
    e = explain(prediction(), features={'feature_999': 100})
    assert 'feature_999' not in canonical(e)


def test_baseline_deterministic_and_hash_bound():
    a = build(); b = build()
    assert canonical(a) == canonical(b) == canonical(baseline())
    assert digest({k: v for k, v in a.items() if k != 'sha256'}) == a['sha256']
    assert a['benign_train_windows'] == 101
    assert a['source_sha256'] == hashlib.sha256((ROOT / a['source']).read_bytes()).hexdigest()
    assert not any('019' in rid for rid in a['benign_train_run_ids'])


@pytest.mark.parametrize('median', [0, 1e-12, -1])
def test_zero_tiny_negative_median_never_makes_ratio(median):
    ref = copy.deepcopy(baseline()); ref['features']['sql_token_count']['median'] = median
    e = explain(prediction(), features={'sql_token_count': 10}, reference=ref)
    f = e['classification']['factors'][0]
    assert f['ratio'] is None and '×' not in f['human_text']
    canonical(e)


def test_valid_rate_ratio_and_percentage_point_format():
    e = explain(prediction(), features=vector(request_rate=11, client_error_ratio=.62))
    f = next(x for x in e['technical']['top_features'] if x['feature'] == 'request_rate')
    assert f['ratio'] == 10 and '10.00×' in f['human_text']
    f = next(x for x in e['technical']['top_features'] if x['feature'] == 'client_error_ratio')
    assert f['ratio'] is None and '62.0%' in f['human_text'] and 'percentage points' in f['comparison']


def test_missing_nonfinite_unknown_secret_values_never_exported():
    p = prediction(); p['shap_explanation']['top_features'] += [
        {'feature':'sql_token_count','contribution':float('nan')},
        {'feature':'password=LEAK','contribution':8}]
    e = explain(p, features={'sql_token_count': 5, 'request_rate': float('inf'),
        'password': 'LEAK', 'query': 'token=LEAK', 'post_count': None})
    output = canonical(e)
    assert 'LEAK' not in output and 'Infinity' not in output and 'NaN' not in output
    assert e['evidence_quality']['feature_coverage'] == 'PARTIAL'
    p['shap_explanation']['top_features'] = [{'feature':'sql_token_count','contribution':1.79e308}]
    canonical(explain(p, features=vector(sql_token_count=7)))


def test_optional_metadata_is_not_inferred_from_missing_fields():
    e = explain(prediction(), features=vector(unique_users=0, identity_observed_ratio=0))
    assert 'unique_users' in e['evidence_quality']['uninterpreted_features']
    assert all(x['feature'] != 'unique_users' for x in e['technical']['top_features'])


def test_observed_deviation_is_actual_and_no_ocsvm_attribution():
    e = explain(prediction(), features=vector(sql_token_count=21))
    f = next(x for x in e['anomaly']['factors'] if x['feature'] == 'sql_token_count')
    assert f['observation'] == 21 and f['reference'] == 0
    assert f['basis'] == 'OBSERVED_REFERENCE_COMPARISON_NOT_OCSVM_ATTRIBUTION'
    assert 'does not identify an attack class' in e['anomaly']['interpretation']


def test_classifier_uses_actual_positive_class_margin_shap():
    p = prediction(); e = explain(p, features=vector(sql_token_count=7))
    f = e['classification']['factors'][0]
    assert f['model_contribution'] == 2.5 and f['observation'] == 7
    assert f['basis'] == 'POSITIVE_MODEL_MARGIN_CONTRIBUTION'
    assert e['technical']['shap']['top_features'] == p['shap_explanation']['top_features']
    assert 'predict_proba' in e['classification']['score_semantics']
    assert 'UNCALIBRATED' in e['classification']['score_semantics']


def test_negative_shap_is_not_presented_as_positive_support():
    p = prediction(); p['shap_explanation']['top_features'][0]['contribution'] = -5
    assert explain(p, features=vector(sql_token_count=7))['classification']['factors'] == []


def test_missing_shap_uses_only_class_related_observations():
    e = explain(prediction(shap=False), features=vector(sql_token_count=7, request_count=100))
    assert e['classification']['factors'][0]['feature'] == 'sql_token_count'
    assert e['classification']['factors'][0]['basis'] == 'CLASS_RELATED_OBSERVATION_NOT_MODEL_ATTRIBUTION'
    assert e['technical']['shap']['status'] == 'NOT_REQUESTED'


def test_deterministic_ranking_limits_and_nonredundancy():
    p = prediction(shap=False); v = vector(request_count=600, request_rate=60, unique_paths=550,
        query_length_max=800, sql_token_count=50, client_error_ratio=.9)
    a = explain(p, features=v); b = explain(copy.deepcopy(p), features=dict(reversed(list(v.items()))))
    assert canonical(a) == canonical(b)
    for section in ['anomaly', 'classification']:
        fs = a[section]['factors']
        assert len(fs) <= MAX_FACTORS and len({f['group'] for f in fs}) == len(fs)


def test_benign_evidence_is_non_alarmist_and_no_forced_class_reason():
    p = prediction('BENIGN', False, False); e = explain(p, features=vector())
    assert 'BENIGN' in e['summary'] and e['anomaly']['verdict'] == 'NORMAL'
    assert e['classification']['factors'] == []
    assert e['anomaly']['factors']
    assert all(abs(f['robust_deviation']) <= 1 for f in e['anomaly']['factors'])


@pytest.mark.parametrize('label,feature', [('SQLI_ATTEMPT','sql_token_count'),
    ('XSS_ATTEMPT','xss_marker_count'),('PATH_TRAVERSAL_ATTEMPT','traversal_count')])
def test_attempt_semantics_and_class_specific_evidence(label, feature):
    e = explain(prediction(label, shap=False), features=vector(**{feature: 20}))
    assert e['classification']['class'] == label
    assert e['classification']['factors'][0]['feature'] == feature
    assert 'not prove successful exploitation' in e['evidence_quality']['limitation']


def test_unknown_and_disagreement_remain_visible_without_forced_class():
    p = prediction('BENIGN', True, False); p['reconciliation'].update(decision='UNKNOWN_ANOMALY', model_disagreement=True)
    e = explain(p, features=vector(request_rate=100))
    assert e['classification']['class'] == 'BENIGN'
    assert e['classification']['factors'] == [] and e['technical']['model_disagreement']
    assert 'no known class is asserted' in e['summary']


def test_uncertain_is_not_narrated_as_a_known_attempt():
    p = prediction('SQLI_ATTEMPT', False); p['xgb_confidence'] = .45
    p['reconciliation']['decision'] = 'UNCERTAIN'
    e = explain(p, features=vector(sql_token_count=3))
    assert 'insufficient' in e['summary'] and 'known attempt-pattern observation' not in e['summary']
    assert e['classification']['class'] == 'SQLI_ATTEMPT'


@pytest.fixture(scope='module')
def application():
    return Application(Config())


def test_real_replay_vectors_full_coverage_and_all_eight_classes(application):
    seen = set()
    for source in ('ATTACK_HOLDOUT','BENIGN_TEST'):
        s = application.snapshot(replay=source)
        for o in s['observations']:
            e = o.explanation
            assert e['evidence_quality']['available_features'] == 83
            assert e['classification']['class'] == o.xgb_label
            for f in e['anomaly']['factors'] + e['classification']['factors']:
                assert f['feature'] in CATALOG and f['observation'] == e['technical']['feature_values'][f['feature']]
            canonical(e); seen.add(o.xgb_label)
    assert len(seen) == 8


def test_no_prediction_or_episode_mutation_and_no_fit(application):
    model = application.model(); rows, raw, _ = application.replay('ATTACK_HOLDOUT',None,model)
    before = copy.deepcopy(rows); before_episodes = copy.deepcopy(raw)
    with patch('xgboost.XGBClassifier.fit', side_effect=AssertionError('No fitting')), patch('sklearn.svm.OneClassSVM.fit', side_effect=AssertionError('No fitting')):
        for p in rows: explain(p)
        a = application.snapshot(); b = application.snapshot()
    assert rows == before and raw == before_episodes
    assert [e.model_dump() for e in a['incidents']] == [e.model_dump() for e in b['incidents']]
    from behavioral_v2.episodes import episodes
    expected = [e for e in episodes(rows, model['persistence']) if e['alert']]
    assert [sorted(e.observation_ids) for e in a['incidents']] == [sorted(e['member_record_ids']) for e in expected]


def test_incident_aggregates_windows_without_regrouping(application):
    s = application.snapshot(); e = next(e for e in s['incidents'] if e.observation_count > 1)
    explanation = incident_explanation(e,s['observations'])
    assert explanation == e.explanation
    assert explanation['linked_window_count'] == e.observation_count
    assert 'one existing episode' in explanation['summary']
    assert explanation['observation_is_incident'] is False
    assert len(explanation['representative_factors']) <= MAX_FACTORS


def test_api_structured_explanation_backwards_compatible(application):
    app = create_app(application=application)
    o = application.snapshot()['observations'][0]
    async def call():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://testserver') as client:
            return await client.get('/api/explainability/'+o.observation_id)
    response = asyncio.run(call()); assert response.status_code == 200
    e = response.json()
    for key in ('shap','robust_deviations','robust_semantics','reconciliation_reason','causal',
                'summary','anomaly','classification','technical','provenance'):
        assert key in e
    assert e['classification']['class'] == e['xgb_class'] == o.xgb_label


def test_reference_failure_does_not_change_model_or_cqi(application):
    from demo.backend.adapters import observation
    rows, _, _ = application.replay('ATTACK_HOLDOUT',None,application.model()); p = rows[0]
    with patch('demo.backend.explainability.baseline', side_effect=ValueError('Broken reference')):
        o = observation(p, {}, application.model()['package_id'])
    assert o.reconciled_label == p['reconciliation']['decision']
    assert o.explanation['evidence_quality']['feature_coverage'] == 'UNAVAILABLE'


def test_cqi_and_existing_incident_fields_identical_with_presentation_disabled():
    enabled = Application(Config()).snapshot()
    with patch('demo.backend.explainability.explain', return_value={}):
        disabled = Application(Config()).snapshot()
    assert enabled['cqi'].model_dump() == disabled['cqi'].model_dump()
    for a, b in zip(enabled['incidents'], disabled['incidents']):
        assert a.model_dump(exclude={'explanation'}) == b.model_dump(exclude={'explanation'})


def test_live_readonly_journal_supplies_raw_vector_and_no_prediction_mutation(tmp_path, application):
    from branch2.live_storage import Journal, atomic_json
    from behavioral_runtime.incidents import Incidents
    from demo.backend.runtime import read_journal
    model = application.model(); rows, _, _ = application.replay('ATTACK_HOLDOUT',None,model)
    p = copy.deepcopy(rows[0]); p['model_id'] = model['package_id']; p['sequence'] = 1
    p['observation_id'] = p['record_id']
    atomic_json(tmp_path/'session_manifest.json', {'model_id':model['package_id'],
        'schema_sha256':model['schema_sha256'], 'session_id':'fixture','source_path':'fixture.log'})
    atomic_json(tmp_path/'checkpoint.json',{'source':{'read_offset':1,'safe_offset':1},
        'updated_at_utc':p['window_end'],'integrity_status':'OK'})
    j = Journal(tmp_path); incidents = Incidents(j,2,model['package_id'])
    values=vector()
    # This reader fixture tests retention, not inference. Keep its existing saved
    # feature deviations numerically consistent with its retained input vector.
    for d in p.get('robust_deviations',[]):values[d['feature']]=d['value']
    j.persist({'record_id':p['record_id'],'row':{**{k:p[k] for k in
        ('window_start','window_end','client_id','user_agent_id','source_sha256')},'features':values,
        'schema_sha256':model['schema_sha256']}}, p); incidents.sync(); j.close()
    before = hashlib.sha256((tmp_path/'journal.sqlite3').read_bytes()).hexdigest()
    legacy, _, _ = read_journal(tmp_path, model['package_id'], model['schema_sha256'])
    enriched, _, _ = read_journal(tmp_path, model['package_id'], model['schema_sha256'], include_features=True)
    assert enriched[0].pop('_explanation_features') == values
    assert enriched[0].pop('_explanation_evidence')['status']=='RESOLVED'
    assert legacy == enriched
    assert hashlib.sha256((tmp_path/'journal.sqlite3').read_bytes()).hexdigest() == before


def test_shap_privacy_and_finite_legacy_technical_fields():
    from demo.backend.explainability import safe_deviations
    assert safe_shap({'status':'token=SECRET', 'backend':'SECRET',
        'top_features':[{'feature':'cookie=SECRET','contribution':1}]})['top_features'] == []
    assert safe_deviations([{'feature':'sql_token_count','value':float('nan'),'signed_deviation':0}]) == []
    assert safe_shap({'status':'AVAILABLE', 'top_features':None})['top_features'] == []
    assert safe_shap({'status':'UNAVAILABLE', 'top_features':[{'feature':'sql_token_count','contribution':5}]})['top_features'] == []
