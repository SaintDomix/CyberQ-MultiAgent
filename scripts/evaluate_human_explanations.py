#!/usr/bin/env python3
"""Read-only accepted replay interpretation QA. No inference/training/traffic."""
import hashlib
import json
from pathlib import Path
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
from demo.backend.config import Config
from demo.backend.services import Application
from demo.backend.explainability import baseline, canonical, digest, explain, MAX_FACTORS
from demo.backend.feature_catalog import CATALOG
from behavioral_runtime.package import verify


def evaluate():
    service = Application(Config()); model = service.model()
    if model['integrity'] != 'VERIFIED': raise ValueError('Accepted package failed integrity')
    examples = {}; timings = []; checked = 0
    for source in ('BENIGN_TEST', 'ATTACK_HOLDOUT'):
        snapshot = service.snapshot(replay=source)
        predictions, _, _ = service.replay(source, None, model)
        for o in snapshot['observations']:
            p = next(p for p in predictions if p['record_id'] == o.observation_id)
            e = o.explanation; values = e['technical']['feature_values']
            assert e['evidence_quality']['available_features'] == 83
            assert e['classification']['class'] == p['xgb_label']
            texts = [e['summary']] + [f['human_text'] for part in ('anomaly','classification') for f in e[part]['factors']]
            for text in texts:
                assert not any(claim in text.lower() for claim in (
                    'successful sql injection', 'sql injection succeeded', 'xss executed',
                    'compromise confirmed', 'ocsvm detected sql', 'calibrated confidence'))
            for part in ('anomaly', 'classification'):
                factors = e[part]['factors']
                assert len(factors) <= MAX_FACTORS and len({f['group'] for f in factors}) == len(factors)
                for f in factors:
                    assert f['feature'] in CATALOG and f['observation'] == values[f['feature']]
                    if f['ratio'] is not None: assert f['reference'] > 0
                    if f.get('basis') == 'POSITIVE_MODEL_MARGIN_CONTRIBUTION': assert f['model_contribution'] > 0
            expected = {k: e[k] for k in ('version','summary','anomaly','classification','evidence_quality','technical','provenance')}
            before = canonical(p)
            start = time.perf_counter()
            repeated = explain(p, features=values, package_id=model['package_id'])
            timings.append((time.perf_counter() - start)*1000)
            assert canonical(repeated) == canonical(expected) and canonical(p) == before
            checked += 1
            label = p['label']
            if label not in examples and p['xgb_label'] == label:
                examples[label] = {'source': source, 'run_id': p['run_id'], 'observation_id': o.observation_id,
                    'true_experimental_label': label, 'reconciled_label': o.reconciled_label,
                    'novelty_verdict': o.novelty_state, 'novelty_score': o.novelty_score,
                    'classifier_output': o.xgb_label, 'uncalibrated_score': o.xgb_score,
                    'anomaly_factors': e['anomaly']['factors'], 'classification_factors': e['classification']['factors'],
                    'shap_status': e['evidence_quality']['shap_status'], 'feature_coverage': 83,
                    'supported_factor_values_verified': True, 'unsupported_claims_detected_by_template_checks': False,
                    'explanation_sha256': digest(expected), 'feature_values_sha256': digest(values),
                    'provenance': e['provenance']}
        if source == 'ATTACK_HOLDOUT':
            incident = next(e for e in snapshot['incidents'] if e.observation_count > 1)
    assert len(examples) == 8
    # Distinct actual classifier evidence, not the same generic alarm narrative.
    assert examples['SQLI_ATTEMPT']['classification_factors'] != examples['REQUEST_BURST_DOS_LIKE']['classification_factors']
    result = {'version': 'human-explanation-acceptance-1.0', 'accepted_package_id': model['package_id'],
        'accepted_root_sha256': model['root_sha256'], 'feature_count':83, 'catalog_count':len(CATALOG),
        'verified_semantics':sum(v['verified'] for v in CATALOG.values()), 'unverified_technical_only':0,
        'reference_sha256':baseline()['sha256'], 'schema_sha256':model['schema_sha256'],
        'windows_checked':checked, 'examples':examples, 'incident':{'episode_id':incident.episode_id, **incident.explanation},
        'checks':{'determinism':'PASS','finite_json':'PASS','feature_membership':'PASS','zero_ratio_guard':'PASS',
            'primary_factor_limits':'PASS','distinct_class_evidence':'PASS','prediction_unchanged':'PASS'},
        'projection_time_ms': {'count':len(timings), 'mean':sum(timings)/len(timings),
            'max':max(timings), 'scope':'Pure explanation only, warm baseline; not detection latency or an ML benchmark'},
        'training_calls':0, 'model_inference_calls':0, 'network_calls':0,
        'limitations':['Template checks do not establish causal attribution or successful exploitation.',
            'Saved exact TreeSHAP contains only top eight margin contributions, not a complete human causal explanation.',
            'Missing full evidence falls back to saved deviations and explicitly partial coverage.',
            'Scores and pipeline decisions are unchanged; no attack-success or statistical-significance claim.']}
    assert verify(ROOT/Config().accepted)['root_sha256'] == model['root_sha256']
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default='outputs/explainability/task2a_01')
    out = (ROOT/parser.parse_args().out).resolve()
    if not out.is_relative_to(ROOT/'outputs/explainability'):
        raise SystemExit('Derived acceptance outputs must remain under outputs/explainability')
    if out.exists(): raise SystemExit('Refuse to overwrite prior interpretation acceptance')
    result = evaluate(); out.mkdir(parents=True)
    (out/'examples.json').write_text(json.dumps(result, sort_keys=True, indent=2, allow_nan=False)+'\n')
    (out/'feature_catalog.json').write_text(json.dumps(CATALOG, sort_keys=True, indent=2)+'\n')
    lines = ['# Behavioral v2 human-readable explanation acceptance', '',
        f"Checked {result['windows_checked']} saved windows; eight true-label examples. No inference, training or traffic.", '',
        'OCSVM deviations are associated evidence, not per-feature attribution. XGBoost selected-class scores are uncalibrated.',
        'The burst-class example may be driven by response-size contributions rather than high request rate; no rate claim is manufactured.', '']
    for label, e in sorted(result['examples'].items()):
        lines += [f'## {label}', '', f"Run: {e['run_id']}; observation: {e['observation_id']}",
            f"Truth {label}; novelty {e['novelty_verdict']}; classifier {e['classifier_output']}; SHAP {e['shap_status']}.", '',
            'Anomaly/reference factors:', ''] + ['- '+f['human_text'] for f in e['anomaly_factors']]
        lines += ['', 'Selected-class factors:', ''] + ['- '+f['human_text'] for f in e['classification_factors']] + ['']
    lines += ['## Incident', '', result['incident']['summary'], result['incident']['persistence_semantics'], '',
        '## Limitations', ''] + ['- '+x for x in result['limitations']]
    (out/'report.md').write_text('\n'.join(lines)+'\n')
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir())}
    (out/'hashes.json').write_text(json.dumps(hashes,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'path':str(out.relative_to(ROOT)), 'windows_checked':result['windows_checked'],
        'examples':len(result['examples']), 'projection_time_ms':result['projection_time_ms'], 'hashes':hashes}))
