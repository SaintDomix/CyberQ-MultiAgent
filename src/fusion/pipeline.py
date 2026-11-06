"""Offline orchestration with deterministic artifacts and no-overwrite output."""
from pathlib import Path
import hashlib
import json
from collections import Counter
from .schema import VERSION, KNOWN, dumps, stable_id, SEVERITY, RESULT, CONFIRMATION, BEHAVIOR, SUPPORT
from .adapters import posture, behavior, recent
from .dedup import clusters
from .correlation import correlate
from .cqi import dimensions, score, sensitivity

LIMITATIONS = [
    'Validated on local Moodle testbed; platform universality is not claimed.',
    'Behavior classes are attempts/patterns, not successful exploits; no causal claim.',
    'Apache combined logs do not expose POST bodies.',
    'XGBoost confidence is uncalibrated; no probability or compromise inference.',
    'VERSION_BASED advisory matches do not confirm exploitation.',
    'Weights and ordinal coefficients are transparent policy, not empirically calibrated.',
    'Correlations are contextual and never change CQI.',
    'Posture snapshot must describe one assessed platform; known root rules operate within that snapshot.',
    'Recent horizon uses emission time, not event time; available dimensions are renormalized and missing coverage is reported.',
    'Behavior windows are correlated; complementary-product index is not a probabilistic independence model.',
]


def coverage(posture_items, all_behavior, selected, horizon):
    counts = Counter(x.check_result for x in posture_items)
    return {'branch1': {'total_findings': len(posture_items), 'score_eligible': sum(x.score_eligible for x in posture_items),
        'excluded_from_scoring': sum(not x.score_eligible for x in posture_items),
        'pass': counts['PASS'], 'fail': counts['FAIL'], 'partial': counts['PARTIAL'], 'dismissed': counts['DISMISSED'],
        'not_applicable': sum(x.check_result == 'NOT_APPLICABLE' or x.evidence_strength == 'NOT_APPLICABLE' for x in posture_items),
        'not_tested': sum('NOT_TESTED' in x.exclusions for x in posture_items),
        'false_positive': sum(x.evidence_strength == 'FALSE_POSITIVE' for x in posture_items),
        'unmapped_categories': sorted(set(x.category for x in posture_items if x.dimension is None)),
        'unknown_severities': sorted(set(str(x.severity) for x in posture_items if 'UNKNOWN_SEVERITY' in x.source_details.get('data_quality_observations', []))),
        'unknown_statuses': sorted(set(x.check_result for x in posture_items if 'UNKNOWN_RESULT' in x.source_details.get('data_quality_observations', []))),
        'unknown_confirmations': sorted(set(x.evidence_strength for x in posture_items if 'UNKNOWN_CONFIRMATION' in x.source_details.get('data_quality_observations', [])))},
        'branch2': {'total_predictions': len(all_behavior), 'recent_selected_predictions': len(selected),
            'excluded_old_predictions': horizon['excluded_older_count'], 'excluded_future_predictions': horizon['excluded_future_count'],
            'benign': sum(x.behavior_class == 'BENIGN' for x in selected),
            'uncertain': sum(x.behavior_class == 'UNCERTAIN' for x in selected),
            'unknown_anomaly': sum(x.behavior_class == 'UNKNOWN_ANOMALY' for x in selected),
            'known_attack_attempts': sum(x.behavior_class in KNOWN for x in selected)},
        'data_quality_observations': [{'evidence_id': x.evidence_id, 'observations': x.source_details['data_quality_observations']}
                                      for x in posture_items if x.source_details.get('data_quality_observations')],
        'exclusions': [{'evidence_id': x.evidence_id, 'reasons': x.exclusions} for x in posture_items if x.exclusions]}


def assemble(posture_rows, behavior_rows, branch1_path, branch2_path, as_of=None, lookback=300):
    p = posture(posture_rows, branch1_path)
    b = behavior(behavior_rows, branch2_path)
    selected, horizon = recent(b, as_of, lookback)
    items = sorted(p + selected, key=lambda x: x.evidence_id)
    grouped = clusters(items)
    dims = dimensions(items, grouped)
    cqi = score(dims)
    cov = coverage(p, b, selected, horizon)
    cqi.update({'limitations': LIMITATIONS, 'coverage': cov, 'behavior_horizon': horizon,
        'coefficients': {'posture_severity': SEVERITY, 'posture_result': RESULT, 'posture_confirmation': CONFIRMATION,
                         'behavior_severity': BEHAVIOR, 'behavior_support': SUPPORT}})
    recommendations = []
    for c in grouped:
        if c['contribution'] is not None and c['contribution'] > 0 and c['recommendations']:
            recommendations.append({'cluster_id': c['cluster_id'], 'evidence_ids': c['member_evidence_ids'], 'actions': c['recommendations']})
    for x in selected:
        if x.behavior_class != 'BENIGN':
            recommendations.append({'evidence_id': x.evidence_id, 'behavior_class': x.behavior_class,
                'actions': ['Preserve evidence', 'Investigate related request evidence', 'Inspect application/server logs',
                            'Review relevant controls; validate affected components where supported'],
                'successful_exploitation_claim': False})
    canonical = [x.export() for x in items]
    artifacts = {'canonical_evidence': canonical, 'fusion_clusters': grouped, 'correlations': correlate(p, selected, [c for c in grouped if c['dimension'] == 'D6']),
        'dimensions': dims, 'cqi': cqi, 'coverage': cov, 'sensitivity': sensitivity(dims), 'recommendations': recommendations,
        'unified_findings': {'schema_version': VERSION, 'evidence': canonical, 'clusters': grouped,
                             'semantics': 'All parent observations retained unchanged in source; no upgrades by correlation'},
        'summary': {'version': VERSION, 'posture_findings': len(p), 'selected_behavior': len(selected),
                    'cqi': cqi['cqi'], 'behavior_horizon': horizon, 'limitations': LIMITATIONS}}
    return artifacts


def read_json(path):
    return json.loads(path.read_bytes(), parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def validate_provenance(rows, manifest, model_hash, acceptance):
    if manifest.get('version') != 'branch2-model-package-1.0' or manifest.get('complete_parallel_package') is not True:
        raise ValueError('Incomplete/unsupported model package manifest')
    files = manifest.get('files_sha256', {})
    for name in ('feature_schema.json', 'isolation_forest.joblib', 'xgboost.json', 'reconciliation.json'):
        value = files.get(name)
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('Invalid package provenance hash')
    if acceptance.get('acceptance') != 'PASS' or acceptance.get('training_performed') is not False or acceptance.get('model_id') != model_hash:
        raise ValueError('Live acceptance/model mismatch')
    schema_hash = acceptance.get('schema_sha256')
    if not isinstance(schema_hash, str) or len(schema_hash) != 64: raise ValueError('Missing accepted schema identity')
    integrity = acceptance.get('live_integrity', {})
    if integrity.get('predictions') != len(rows) or integrity.get('unique_record_ids') != len(rows) or integrity.get('duplicates') != 0 or integrity.get('sequence_holes') != []:
        raise ValueError('Live acceptance count/integrity mismatch')
    if sorted(r.get('sequence', -1) for r in rows) != list(range(1, len(rows)+1)):
        raise ValueError('Noncontiguous live sequences')
    for row in rows:
        if row.get('model_id') != model_hash or row.get('schema_sha256') != schema_hash or row.get('feature_schema_version') != 'dataset-v2-features-1.0':
            raise ValueError('Prediction model/schema mismatch')
        if row.get('reconciliation', {}).get('confidence_threshold') != .8:
            raise ValueError('Frozen reconciliation threshold mismatch')
        ranges = row.get('source_byte_ranges')
        if not isinstance(ranges, list) or not ranges or not row.get('source_sha256'):
            raise ValueError('Missing authoritative byte provenance')
        for span in ranges:
            if type(span.get('start')) is not int or type(span.get('end')) is not int or not 0 <= span['start'] < span['end'] or not isinstance(span.get('sha256'), str) or len(span['sha256']) != 64:
                raise ValueError('Malformed byte provenance')


def evaluate(branch1, branch2, model_manifest, live_acceptance, out, as_of=None, lookback=300):
    paths = {k: Path(v).resolve() for k, v in {'branch1': branch1, 'branch2': branch2,
             'model_manifest': model_manifest, 'live_acceptance': live_acceptance}.items()}
    expected_suffixes = {'branch1': '.json', 'branch2': '.jsonl', 'model_manifest': '.json', 'live_acceptance': '.json'}
    if any(path.suffix != expected_suffixes[key] or '/var/log/' in str(path) for key, path in paths.items()):
        raise ValueError('Only offline JSON artifacts are allowed; host logs are forbidden')
    target = Path(out).resolve()
    if target.exists(): raise FileExistsError('Refusing existing output directory')
    # These four JSON artifacts are the only input files opened. Never dereference source log paths.
    if any(target == p or target in p.parents for p in paths.values()): raise ValueError('Output contains input artifact')
    hashes = {k: hashlib.sha256(p.read_bytes()).hexdigest() for k, p in paths.items()}
    p = read_json(paths['branch1'])
    rows = [json.loads(line, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
            for line in paths['branch2'].read_text().splitlines() if line.strip()]
    validate_provenance(rows, read_json(paths['model_manifest']), hashes['model_manifest'], read_json(paths['live_acceptance']))
    artifacts = assemble(p, rows, str(paths['branch1']), str(paths['branch2']), as_of, lookback)
    provenance = {'version': VERSION, 'inputs': {k: {'path': str(paths[k]), 'sha256': hashes[k]} for k in paths},
                  'behavior_horizon': artifacts['summary']['behavior_horizon'], 'training_performed': False,
                  'result_hash': stable_id('result', artifacts), 'input_paths_are_not_dereferenced': True}
    if any(hashlib.sha256(p.read_bytes()).hexdigest() != hashes[k] for k, p in paths.items()):
        raise ValueError('Input changed during evaluation')
    artifacts['provenance'] = provenance
    target.mkdir(parents=True, exist_ok=False)
    for name, value in sorted(artifacts.items()):
        with (target / (name + '.json')).open('x', encoding='utf-8') as handle:
            handle.write(dumps(value) + '\n')
    return artifacts
