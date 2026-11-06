"""Offline deterministic interpretation only. No inference, fitting or grouping.

All inputs are raw extractor-space numeric scalars. The display reference does
not change the scaler or threshold. OCSVM has no per-feature attribution here.
"""
from collections import Counter
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
from .feature_catalog import CATALOG

VERSION = 'behavioral-explanation-1.0'
REFERENCE = Path(__file__).with_name('explanation_reference.json')
MAX_FACTORS = 4
NORMAL_GROUP_PRIORITY = {'TRAFFIC_RATE': 10, 'STATUS_CODES': 9, 'PATH_BEHAVIOR': 8,
    'REPETITION': 7, 'RESOURCE_BEHAVIOR': 6, 'NAVIGATION': 5, 'QUERY_BEHAVIOR': 4,
    'TIMING': 3, 'METHOD_BEHAVIOR': 2, 'RESPONSE_SIZE': 1}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


@lru_cache(maxsize=1)
def catalog_hash():
    return digest(CATALOG)


def finite(value):
    return isinstance(value, (float, int)) and not isinstance(value, bool) and math.isfinite(value)


@lru_cache(maxsize=1)
def baseline():
    value = json.loads(REFERENCE.read_text())
    if digest({k: v for k, v in value.items() if k != 'sha256'}) != value['sha256']:
        raise ValueError('Explanation reference integrity failed')
    return value


def safe_shap(raw):
    """Allowlist numeric attribution; never echo arbitrary predictor strings."""
    raw = raw if isinstance(raw, dict) else {}
    available = raw.get('status') == 'AVAILABLE'
    items = raw.get('top_features')
    items = items if available and isinstance(items, list) else []
    output = {'status': raw.get('status') if raw.get('status') in ('AVAILABLE', 'UNAVAILABLE', 'NOT_REQUESTED', 'UNAVAILABLE_OR_INCOMPATIBLE') else 'UNAVAILABLE', 'causal': False,
        'backend': 'XGBOOST_NATIVE_EXACT_TREE_SHAP' if available else None,
        'output_space': 'raw model margin' if available else None,
        'top_features': [{'feature': x['feature'], 'contribution': x['contribution']}
            for x in items if isinstance(x, dict)
            and x.get('feature') in CATALOG and finite(x.get('contribution'))][:83]}
    if finite(raw.get('additivity_max_absolute_error')):
        output['additivity_max_absolute_error'] = raw['additivity_max_absolute_error']
    return output


def safe_deviations(raw):
    return [{k: x[k] for k in ('feature', 'value', 'signed_deviation')} for x in (raw or [])
        if isinstance(x, dict) and x.get('feature') in CATALOG
        and finite(x.get('value')) and finite(x.get('signed_deviation'))]


def usable(name, values):
    if name.startswith('response_bytes_') and name != 'response_bytes_observed_ratio':
        return values.get('response_bytes_observed_ratio', 0) > 0
    if name in ('unique_users', 'requests_per_user_mean'):
        return values.get('identity_observed_ratio', 0) > 0
    if name in ('unique_sessions', 'requests_per_session_mean'):
        return values.get('session_observed_ratio', 0) > 0
    if name in ('unique_roles', 'privileged_role_request_ratio'):
        return values.get('role_observed_ratio', 0) > 0
    if name.endswith('inter_request'):
        return values.get('request_count', 0) > 1
    return True


def fact(name, value, reference):
    entry = CATALOG[name]; median = reference['median']; delta = value - median
    direction = 'HIGH' if delta > 0 else 'LOW' if delta < 0 else 'AT_REFERENCE'
    ratio = None
    # Counts/rates/sizes only; fractions use percentage-point comparisons.
    if entry['ratio_to_baseline'] and median >= 1e-6 and value > median:
        candidate = value / median
        if finite(candidate) and candidate <= 1e6:
            ratio = candidate
    if entry['unit'] == 'fraction':
        observation = f'{value * 100:.1f}%'; ref = f'{median * 100:.1f}%'
        comparison = f'{delta * 100:+.1f} percentage points'
    else:
        observation = f'{value:.4g}'; ref = f'{median:.4g}'
        comparison = f'{ratio:.2f}×' if ratio is not None else f'{delta:+.4g}'
    text = (f"{entry['label']} was {ratio:.2f}× the benign TRAIN median ({observation} versus {ref} {entry['unit']})."
        if ratio is not None else f"{entry['label']}: {observation} versus a benign TRAIN median of {ref}"
        + ('.' if entry['unit'] == 'fraction' else f" {entry['unit']}.") )
    return {'factor_id': name + '_' + direction.lower(), 'feature': name,
        'group': entry['group'], 'label': entry['label'], 'unit': entry['unit'],
        'observation': value, 'reference': median, 'reference_scale': reference['scale'],
        'comparison': comparison, 'ratio': ratio, 'direction': direction,
        'human_text': text}


def select(candidates):
    chosen = []; groups = set()
    for factor in sorted(candidates, key=lambda f: (-f['importance'], f['feature'])):
        if factor['group'] in groups:
            continue
        groups.add(factor['group']); chosen.append(factor)
        if len(chosen) == MAX_FACTORS:
            break
    return chosen


def explain(prediction, *, features=None, package_id=None, reference=None):
    """Pure projection: input prediction and incident verdicts are never changed."""
    ref = reference if reference is not None else baseline()
    supplied = features or {}
    values = {k: float(v) for k, v in supplied.items() if k in CATALOG and finite(v)}
    # Legacy saved records remain interpretable even if full vector is unavailable.
    for item in safe_deviations(prediction.get('robust_deviations')):
        if item.get('feature') in CATALOG and finite(item.get('value')):
            values.setdefault(item['feature'], float(item['value']))
    shap = safe_shap(prediction.get('shap_explanation'))
    contributions = {x['feature']: x['contribution'] for x in shap['top_features']}
    label = prediction['xgb_label']; anomalous = bool(prediction['novelty_anomalous'])
    normal = prediction['reconciliation']['decision'] == 'BENIGN'
    anomaly = []; classification = []; technical = []
    for name in sorted(values):
        r = ref['features'].get(name)
        if r is None or not finite(r.get('scale')) or r['scale'] <= 0 or not usable(name, values):
            continue
        value = values[name]; z = (value - r['median']) / r['scale']
        if not finite(z):
            continue
        f = fact(name, value, r)
        f.update(robust_deviation=z, model_contribution=contributions.get(name))
        technical.append(dict(f))
        # Display thresholds only; not detector thresholds or empirical quantiles.
        if (normal and abs(z) <= 1 and f['group'] in NORMAL_GROUP_PRIORITY) or (not normal and abs(z) >= 1):
            a = dict(f, importance=(NORMAL_GROUP_PRIORITY[f['group']] + 1 / (1 + abs(z)) if normal else min(abs(z), 100)),
                basis='OBSERVED_REFERENCE_COMPARISON_NOT_OCSVM_ATTRIBUTION')
            anomaly.append(a)
        positive = contributions.get(name, 0) > 0
        relevant = label in CATALOG[name]['relevant_classes']
        if positive or (shap['status'] != 'AVAILABLE' and label != 'BENIGN' and relevant and abs(z) >= 1):
            # Preserve contribution magnitude as primary, modestly favor a
            # supported deviation and reviewed class-specific semantics.
            c = dict(f, importance=(min(abs(contributions[name]), 1e100) *
                (1 + min(abs(z), 10) / 100 + (.1 if relevant else 0)) if positive else min(abs(z), 100)),
                basis='POSITIVE_MODEL_MARGIN_CONTRIBUTION' if positive else 'CLASS_RELATED_OBSERVATION_NOT_MODEL_ATTRIBUTION')
            if not positive and value <= 0:
                continue
            c['human_text'] += (' Positive contribution to the selected class margin.' if positive
                else ' Associated class-related evidence; classifier attribution is unavailable.')
            classification.append(c)
    # Numeric-only, schema-bound technical vectors. No URLs, query values or bodies.
    score = prediction.get('xgb_confidence'); novelty_score = prediction.get('novelty_score')
    return {'version': VERSION,
        'summary': ('The reconciled window is BENIGN.' if normal else
            'The novelty verdict is NORMAL, but classifier evidence is insufficient for a confident reconciled class.'
            if prediction['reconciliation']['decision'] == 'UNCERTAIN' else
            'The window differs from the benign reference; no known class is asserted by reconciliation.'
            if prediction['reconciliation']['decision'] == 'UNKNOWN_ANOMALY' else
            'The reconciled window contains a known attempt-pattern observation.') +
            ' Observation ≠ incident. This interpretation does not change escalation.',
        'anomaly': {'verdict': 'ANOMALOUS' if anomalous else 'NORMAL',
            'score': novelty_score if finite(novelty_score) else None,
            'score_semantics': 'OCSVM score_samples compared with frozen cutoff; not a probability',
            'interpretation': 'Associated deviations — not causal attribution. OCSVM does not identify an attack class.',
            'factors': select(anomaly)},
        'classification': {'class': label, 'display_label': label.replace('_', ' '),
            'score': score if finite(score) else None,
            'score_semantics': 'Maximum XGBoost predict_proba class score; UNCALIBRATED. SHAP is in raw-margin space.',
            'interpretation': 'Positive selected-class margin contributions when available; otherwise class-related observed deviations. Neither proves causality or exploitation.',
            'factors': select(classification)},
        'evidence_quality': {'available_features': len(values), 'expected_features': 83,
            'feature_coverage': 'FULL' if len(values) == 83 else 'PARTIAL',
            'missing_features': sorted(set(ref['features']) - set(values)),
            'uninterpreted_features': sorted(k for k in values if not usable(k, values)),
            'shap_status': shap['status'], 'causal': False,
            'limitation': 'Benign TRAIN laboratory reference, not a population normal range. Apache logs omit POST bodies. Attempt patterns do not prove successful exploitation.'},
        'technical': {'top_features': technical, 'shap': shap, 'feature_values': values,
            'baseline': {k: ref['features'][k] for k in sorted(values) if k in ref['features']},
            'value_space': 'RAW_EXTRACTOR_SPACE; not OCSVM scaled model space',
            'model_disagreement': bool(prediction['reconciliation'].get('model_disagreement'))},
        'provenance': {'package_id': package_id, 'schema_sha256': ref['schema_sha256'],
            'baseline_sha256': ref['sha256'], 'baseline_source': ref['source'],
            'catalog_sha256': catalog_hash(), 'algorithm': VERSION, 'network_calls': 0}}


def incident_explanation(incident, observations):
    members = [o for o in observations if o.observation_id in incident.observation_ids]
    classes = Counter(o.xgb_label for o in members)
    counts = Counter(); factors = {}
    for o in members:
        for f in o.explanation.get('anomaly', {}).get('factors', []):
            counts[f['feature']] += 1
            if f['feature'] not in factors or f['importance'] > factors[f['feature']]['importance']:
                factors[f['feature']] = dict(f, representative_observation_id=o.observation_id)
    ranked = [dict(factors[k], windows_observed=counts[k]) for k in sorted(counts, key=lambda k: (-counts[k], k))]
    # Recurrence is primary; one factor per semantic group.
    primary = []; groups = set()
    for f in ranked:
        if f['group'] not in groups:
            primary.append(f); groups.add(f['group'])
        if len(primary) == MAX_FACTORS: break
    return {'version': VERSION, 'summary': f'{len(members)} linked windows form one existing episode; not separate successful attacks.',
        'linked_window_count': len(members), 'declared_observation_count': incident.observation_count,
        'anomalous_windows': sum(o.novelty_state == 'ANOMALOUS' for o in members),
        'dominant_classifier_class': sorted(classes, key=lambda k: (-classes[k], k))[0] if classes else None,
        'class_counts': dict(sorted(classes.items())), 'duration_seconds': incident.duration,
        'start_time': incident.start_time, 'last_seen': incident.last_seen,
        'persistence_semantics': 'Frozen UNKNOWN persistence=2; confident known patterns may alert after one window. Existing membership is not recalculated.',
        'representative_factors': primary, 'observation_is_incident': False,
        'successful_exploitation_confirmed': False}
