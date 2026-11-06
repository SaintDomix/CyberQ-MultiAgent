"""Transparent ordinal index, not a probability model."""
import math
from fractions import Fraction
from .schema import DIMENSIONS, VERSION

WEIGHTS = {d: Fraction(1, 6) for d in DIMENSIONS}


def dimensions(items, clusters):
    out = []
    for dim, name in DIMENSIONS.items():
        evidence = [x for x in items if x.dimension == dim]
        scored = [c for c in clusters if c['dimension'] == dim and c['score_eligible']]
        risk = 1 - math.prod(1 - c['contribution'] for c in scored) if scored else None
        out.append({'dimension': dim, 'name': name, 'score_status': 'SCORED' if scored else 'INSUFFICIENT_EVIDENCE',
            'evidence_count': len(evidence), 'score_eligible_evidence_count': sum(x.score_eligible for x in evidence),
            'scored_cluster_count': len(scored), 'cluster_ids': [c['cluster_id'] for c in scored],
            'risk': risk, 'quality': 100 * (1 - risk) if risk is not None else None,
            'baseline_weight': float(WEIGHTS[dim]), 'baseline_weight_exact': '1/6'})
    return out


def score(dims, weights=None):
    weights = weights or WEIGHTS
    available = [d for d in dims if d['quality'] is not None]
    total = sum(weights[d['dimension']] for d in available)
    normalized = {d['dimension']: float(weights[d['dimension']] / total) for d in available} if total else {}
    value = math.fsum(d['quality'] * normalized[d['dimension']] for d in available) if total else None
    return {'cqi': value, 'cqi_display': round(value, 2) if value is not None else None,
        'score_status': 'SCORED' if len(available) == 6 else ('PARTIAL_EVIDENCE' if available else 'INSUFFICIENT_EVIDENCE'),
        'normalized_available_dimension_weights': normalized, 'weighting': 'BASELINE_EQUAL_DIMENSION_WEIGHTING',
        'weights_are_empirically_calibrated': False, 'is_probability': False, 'formula_version': VERSION,
        'formula': 'risk_d=1-product(1-c_cluster); quality_d=100*(1-risk_d); CQI=sum(quality_d*w_d)/sum(available w_d)',
        'coefficient_semantics': 'Transparent ordinal policy coefficients; not empirical probabilities',
        'display_rounding': '2 decimal places; internal calculations retain full float precision'}


def sensitivity(dims):
    baseline = score(dims)['cqi']
    variants = []
    for dim in DIMENSIONS:
        for change in (Fraction(4, 5), Fraction(6, 5)):
            # Change focal normalized baseline weight by +/-20%; others proportional.
            focal = WEIGHTS[dim] * change
            weights = {k: focal if k == dim else WEIGHTS[k] * (1-focal)/(1-WEIGHTS[dim]) for k in WEIGHTS}
            variants.append({'dimension': dim, 'change': '-20%' if change < 1 else '+20%',
                'weights': {k: float(v) for k, v in weights.items()},
                'weights_exact': {k: str(v) for k, v in weights.items()}, 'cqi': score(dims, weights)['cqi']})
    values = [v['cqi'] for v in variants if v['cqi'] is not None]
    return {'baseline_cqi': baseline, 'variants': variants, 'min_cqi': min(values) if values else None,
        'max_cqi': max(values) if values else None, 'absolute_range': max(values)-min(values) if values else None,
        'maximum_deviation': max(abs(x-baseline) for x in values) if values else None,
        'scope': 'Dimension-weight sensitivity only; no outcome-based tuning'}
