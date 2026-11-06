"""Pure adapters: retain source observations, never run branch implementations."""
from datetime import timedelta
import math
from .schema import (Evidence, CATEGORIES, SEVERITY, RESULT, CONFIRMATION, BEHAVIOR,
                     SUPPORT, KNOWN, stable_id, utc, dumps)


def unique(items):
    by_id = {}
    for item in items:
        key = item.evidence_id
        if key in by_id and dumps(by_id[key].export()) != dumps(item.export()):
            raise ValueError('Conflicting duplicate evidence identity')
        by_id[key] = item
    return sorted(by_id.values(), key=lambda x: x.evidence_id)


def posture(rows, source_path):
    if not isinstance(rows, list):
        raise ValueError('Branch1 findings must be a list')
    out = []
    for row in rows:
        for key in ('finding_id', 'evidence_id', 'category', 'finding_type', 'check_result', 'confirmation_status'):
            if not isinstance(row.get(key), str) or not row[key]:
                raise ValueError('Missing Branch1 field: ' + key)
        result, confirmation, severity = row['check_result'], row['confirmation_status'], row.get('severity')
        dimension = CATEGORIES.get(row['category'])
        reasons = []
        if dimension is None: reasons.append('UNMAPPED_CATEGORY')
        if result == 'NOT_TESTED' or confirmation == 'NOT_TESTED': reasons.append('NOT_TESTED')
        if result not in RESULT and result != 'NOT_TESTED': reasons.append('UNKNOWN_RESULT')
        if confirmation not in CONFIRMATION and confirmation != 'NOT_TESTED': reasons.append('UNKNOWN_CONFIRMATION')
        if severity not in SEVERITY: reasons.append('UNKNOWN_SEVERITY')
        # Definitive zero-risk disposition takes precedence over unknown severity.
        zero = result in ('PASS', 'DISMISSED', 'NOT_APPLICABLE') or confirmation in ('FALSE_POSITIVE', 'NOT_APPLICABLE') or severity == 'INFO'
        eligible = dimension is not None and 'NOT_TESTED' not in reasons and (not reasons or zero)
        contribution = (0. if zero else SEVERITY[severity] * RESULT[result] * CONFIRMATION[confirmation]) if eligible else None
        out.append(Evidence(
            stable_id('posture', row['evidence_id']), 'BRANCH1_POSTURE', row['finding_id'], source_path,
            {'source_evidence_id': row['evidence_id'], 'source_provenance': row.get('provenance', {})},
            row['category'], row['finding_type'], None, row.get('affected_asset'), row.get('affected_component'),
            result, severity, confirmation, {'start_utc': row.get('start_utc'), 'end_utc': row.get('end_utc')},
            row.get('recommendation'), eligible, 'Posture observation; confirmation does not assert exploitation',
            dimension, contribution, {'severity': SEVERITY.get(severity), 'result': RESULT.get(result),
                                      'confirmation': CONFIRMATION.get(confirmation), 'confidence_multiplier': None},
            reasons if not eligible else [],
            {**{k: row.get(k) for k in ('evidence', 'explanation', 'expected_value', 'observed_value', 'confidence', 'root_cause')},
             'data_quality_observations': [r for r in reasons if r.startswith('UNKNOWN_')]},
        ))
    return unique(out)


def behavior(rows, source_path):
    out = []
    records, sequences = set(), set()
    for row in rows:
        rid, seq = row.get('record_id'), row.get('sequence')
        if not isinstance(rid, str) or not rid or type(seq) is not int or seq < 1:
            raise ValueError('Invalid behavioral identity/sequence')
        if rid in records or seq in sequences: raise ValueError('Duplicate behavioral record/sequence')
        records.add(rid); sequences.add(seq)
        r = row.get('reconciliation', {})
        decision, reason = r.get('decision'), r.get('reason')
        if decision not in BEHAVIOR or reason not in SUPPORT: raise ValueError('Unknown behavioral semantics')
        expected = {'BENIGN': 'BOTH_BENIGN_NORMAL', 'UNKNOWN_ANOMALY': 'ANOMALY_WITHOUT_CONFIDENT_KNOWN_ATTACK',
                    'UNCERTAIN': 'NORMAL_IF_WITH_UNCERTAIN_OR_UNAVAILABLE_CLASSIFIER'}
        if (decision in expected and reason != expected[decision]) or (decision in KNOWN and not reason.startswith('KNOWN_ATTACK_')):
            raise ValueError('Inconsistent behavioral decision/reason')
        expected_anomaly = reason in ('ANOMALY_WITHOUT_CONFIDENT_KNOWN_ATTACK', 'KNOWN_ATTACK_WITH_ANOMALY_SUPPORT')
        if type(row.get('if_anomalous')) is not bool or row['if_anomalous'] != expected_anomaly or r.get('if_anomalous') != expected_anomaly:
            raise ValueError('Inconsistent IF/reconciliation evidence')
        confidence = row.get('xgb_confidence')
        if confidence is not None and (type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1):
            raise ValueError('Invalid uncalibrated classifier score')
        if r.get('xgb_confidence') != confidence or r.get('xgb_label') != row.get('xgb_label'):
            raise ValueError('Inconsistent classifier evidence')
        if decision in KNOWN and row.get('xgb_label') != decision:
            raise ValueError('Known pattern/classifier mismatch')
        if row.get('confidence_calibrated') is not False or r.get('confidence_calibrated') is not False or row.get('training_performed') is not False:
            raise ValueError('Expected uncalibrated saved-model inference')
        emitted = utc(row.get('emitted_at_utc')).isoformat()
        out.append(Evidence(stable_id('behavior', rid), 'BRANCH2_BEHAVIOR', rid, source_path,
            {k: row.get(k) for k in ('sequence', 'session_id', 'run_id', 'client_id', 'user_agent_id', 'source_file', 'source_path', 'source_device',
                                     'source_inode', 'source_byte_ranges', 'source_sha256', 'model_id', 'schema_sha256', 'feature_schema_version')},
            'Behavioral Threat Activity', decision, decision, row.get('affected_asset'), None,
            'OBSERVED_MODEL_PATTERN', decision, reason,
            {'emitted_at_utc': emitted, 'window_start': row.get('window_start'), 'window_end': row.get('window_end')},
            None, True, 'Behavioral attempt/pattern evidence; no successful exploitation claim', 'D6',
            BEHAVIOR[decision] * SUPPORT[reason], {'behavior_severity': BEHAVIOR[decision], 'support': SUPPORT[reason],
                                               'confidence_multiplier': None}, [],
            {k: row.get(k) for k in ('reconciliation', 'xgb_confidence', 'xgb_label', 'if_anomalous',
                                      'robust_explanation', 'shap_explanation', 'semantic_scope')},
        ))
    return unique(out)


def recent(items, as_of=None, lookback=300):
    if type(lookback) is not int or lookback <= 0: raise ValueError('Positive integer lookback required')
    if as_of is None and not items: raise ValueError('Empty behavior requires explicit as-of')
    end = utc(as_of) if as_of is not None else max(utc(x.timestamps['emitted_at_utc']) for x in items)
    start = end - timedelta(seconds=lookback)
    selected = [x for x in items if start <= utc(x.timestamps['emitted_at_utc']) <= end]
    return selected, {'as_of': end.isoformat(), 'behavior_lookback_seconds': lookback,
        'interval': 'inclusive [as_of-lookback, as_of], based on emitted evidence time',
        'selected_record_ids': sorted(x.source_record_id for x in selected),
        'selected_sequences': sorted(x.provenance['sequence'] for x in selected),
        'excluded_older_count': sum(utc(x.timestamps['emitted_at_utc']) < start for x in items),
        'excluded_future_count': sum(utc(x.timestamps['emitted_at_utc']) > end for x in items)}
