"""Explicit checks: no hidden failures, scoring or model execution."""
import math


def bounded(value, low, high):
    return type(value) in (int, float) and math.isfinite(value) and low <= value <= high


def check_acceptance(assessment, comparison, integrity, reports_generated):
    checks = {}
    def add(name, passed, observed, expected, explanation, required=True):
        checks[name] = {'status': 'PASS' if passed else 'FAIL', 'required': required,
                        'observed': observed, 'expected': expected, 'explanation': explanation}
    cqi = assessment['cqi']
    add('protected_artifacts_unchanged', integrity['unchanged'], {'unchanged':integrity['unchanged'], 'changed_or_missing':integrity.get('changed_or_missing',[])}, 'All pre-existing files byte-identical',
        'Runtime before/after hash comparison; new assessment files are not pre-existing artifacts.')
    add('no_training_performed', assessment['training_performed'] is False, assessment['training_performed'], False,
        'Only frozen JSON outputs are consumed; neither model loading nor training is performed.')
    identity = assessment['model_package_identity']
    add('model_identity_preserved', identity['validated'] and identity['model_id'] == identity['accepted_model_id'] == assessment['provenance']['inputs']['model_manifest']['sha256']
        and all(x == identity['model_id'] for x in identity['prediction_model_ids']), identity, 'Prediction model ID equals input package-manifest SHA256',
        'Fusion validates saved-inference provenance and M2D acceptance identity.')
    add('feature_schema_identity_preserved', identity['schema_validated'] and all(x == identity['feature_schema_sha256'] for x in identity['prediction_schema_ids']), identity['feature_schema_sha256'],
        'All supplied prediction schemas equal accepted M2D schema identity', 'Upstream schema metadata is retained; feature extraction is not rerun.')
    add('cqi_not_probability', assessment['cqi_is_probability'] is False and cqi['is_probability'] is False,
        assessment['cqi_is_probability'], False, 'CQI is a transparent ordinal quality index.')
    add('weights_not_empirically_calibrated', assessment['weights_are_empirically_calibrated'] is False and cqi['weights_are_empirically_calibrated'] is False,
        assessment['weights_are_empirically_calibrated'], False, 'Equal baseline weights are methodological policy.')
    ds = assessment['dimensions']
    add('all_dimensions_bounded', len(ds) == 6 and all(bounded(d['quality'],0,100) and bounded(d['risk'],0,1) for d in ds),
        [{'dimension':d['dimension'],'quality':d['quality'],'risk':d['risk']} for d in ds], 'Six assessed dimensions: quality 0..100; risk 0..1',
        'Insufficient/null dimensions fail full end-to-end acceptance; they are not silently made perfect.')
    add('overall_cqi_bounded', bounded(cqi['cqi'],0,100), cqi['cqi'], '0..100', 'Full-precision Fusion result.')
    cs = assessment['correlations'] + ([] if comparison.get('status') != 'COMPARED' else comparison['sqli_correlations'] + comparison['baseline_correlations'])
    add('correlations_have_no_score_effect', all(c['score_effect']=='NONE' for c in cs), [c['score_effect'] for c in cs], 'NONE', 'Correlation is contextual only.')
    add('no_causal_correlations', all(c['causal'] is False for c in cs), [c['causal'] for c in cs], False, 'Association is not causation.')
    exploit_flags = [assessment['successful_exploitation_confirmed']] + [c['exploit_confirmed'] for c in cs]
    exploit_flags += [x['successful_exploitation_confirmed'] for x in assessment['behavioral_episodes']]
    add('no_exploit_confirmation', all(x is False for x in exploit_flags), exploit_flags, False, 'Attempt/pattern evidence never claims exploit success.')
    requested = comparison.get('status') == 'COMPARED'
    comp_checks = {
        'baseline_posture_equals_sqli_posture': (comparison.get('posture_identical') is True, comparison.get('posture_identical'), True),
        'only_D6_changed_between_acceptance_states': (comparison.get('changed_dimensions') == ['D6'], comparison.get('changed_dimensions'), ['D6']),
        'sqli_episode_count_expected': (comparison.get('sqli_episode_count') == 1, comparison.get('sqli_episode_count'), 1),
        'sqli_episode_member_count_expected': (comparison.get('sqli_episode_member_counts') == [comparison.get('expected_sqli_members')], comparison.get('sqli_episode_member_counts'), [comparison.get('expected_sqli_members')]),
        'comparison_cqi_decreased': (requested and comparison['delta'] is not None and comparison['delta'] < 0, comparison.get('delta'), 'Negative delta'),
        'sqli_contextual_correlation_present': (bool(comparison.get('sqli_contextual_correlations')), comparison.get('sqli_contextual_correlations',[]), 'SQLI episode association with score_effect NONE'),
    }
    for name, (passed, observed, expected) in comp_checks.items():
        add(name, requested and passed, observed, expected,
            'Acceptance scenario invariant.' if requested else 'Comparison not requested; check not assessed and not required.', required=requested)
    add('reports_generated', reports_generated, reports_generated, True, 'Markdown and standalone HTML files exist and are nonempty.')
    inputs = assessment['provenance']['inputs']
    add('provenance_complete', set(inputs) == {'branch1','branch2','model_manifest','live_acceptance'} and all(len(x['sha256'])==64 for x in inputs.values()),
        inputs, 'Four hashed frozen inputs', 'Model IDs and input identities are recorded without dereferencing raw logs.')
    return {'version':'m3c-acceptance-1.0', 'profile':'M3C_SCENARIO' if requested else 'CORE_ASSESSMENT',
            'overall':'PASS' if all(c['status']=='PASS' for c in checks.values() if c['required']) else 'FAIL',
            'checks':checks, 'comparison_requested':requested}
