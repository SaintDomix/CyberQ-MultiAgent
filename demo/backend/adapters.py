"""Presentation adapters preserve evidence; no inference, fitting or CQI policy."""
from branch2.events import utc
from branch2.live_storage import digest
from fusion.schema import CATEGORIES, BEHAVIOR
from .privacy import sanitize
from .schemas import PostureFinding, BehaviorObservation, Incident, FusionEvent


def finding(row):
    # Early operational snapshots used the parent evidence IDs in the source-ID
    # slot. Preserve those immutable bytes and normalize the application view
    # from the retained source members; no evidence/result is re-created.
    if row.get('canonical_finding_id') and 'member_evidence_ids' not in row:
        row = dict(row)
        row['member_evidence_ids'] = row.get('source_finding_ids', [])
        row['source_finding_ids'] = sorted({m.get('source_finding_id', m.get('source_rule_id', m['finding_id']))
            for m in row.get('evidence', {}).get('members', [])})
    return PostureFinding(finding_id=row['finding_id'], source=row.get('evidence_source', 'BRANCH1'),
        category=row['category'], dimension=CATEGORIES.get(row['category']), status=row.get('operational_status', row['check_result']),
        severity=row.get('severity'), confirmation=row['confirmation_status'], title=row['finding_type'],
        description=sanitize(row.get('explanation')), evidence_summary=sanitize(row.get('evidence')),
        affected_component=row.get('affected_component'), remediation=sanitize(row.get('recommendation')),
        provenance=sanitize({'evidence_id': row['evidence_id'], **row.get('provenance', {})}),
        created_at=row.get('end_utc') or row.get('start_utc'),
        active_validation=sanitize(row.get('active_validation')),
        validation_sources=row.get('validation_sources',[]),
        cqi_mapping=row.get('cqi_mapping'),parameter=row.get('parameter'),method=row.get('method'),
        zap_details=sanitize(row.get('zap_details')),
        assessment_scope='CURRENT_OPERATIONAL_POSTURE' if row.get('assessment_id') else 'RESEARCH_BASELINE',
        **{k: row[k] for k in ('canonical_finding_id', 'assessment_id', 'source_rule_id', 'source_finding_id',
            'source_finding_ids', 'evidence_sources', 'multi_source', 'dedup_rule', 'source_severity',
            'normalized_severity', 'source_confidence', 'confidence', 'member_evidence_ids', 'url', 'cwe', 'rule_reference', 'source_status_conflict', 'prerequisite_reason', 'current_state') if k in row})


def episode(raw, package_id, replay=False):
    decision = raw['behavior_class']
    ids = raw.get('observation_ids', raw.get('member_record_ids', []))
    eid = raw.get('episode_id') or 'episode-' + digest([package_id, raw['run_id'], raw.get('client_id'),
        raw.get('user_agent_id'), decision, raw['start']])
    factor = BEHAVIOR.get(decision, 0)
    severity = 'HIGH' if factor >= .75 else 'MEDIUM' if factor >= .4 else 'LOW'
    return Incident(episode_id=eid, type=raw['state'], behavior_class=decision,
        status='REPLAY_EVIDENCE' if replay else 'OBSERVED_EPISODE', severity=severity,
        start_time=raw['start'], last_seen=raw['end'], duration=(utc(raw['end']) - utc(raw['start'])).total_seconds(),
        observation_ids=ids, observation_count=raw['member_count'], known_attack=decision != 'UNKNOWN_ANOMALY',
        model_package_id=package_id, evidence_summary={'model_disagreement': raw['model_disagreement_visible'],
            'semantics': 'Attempt pattern or unclassified anomaly episode; not successful exploitation'})


def observation(p, incident_by_observation, package_id, features=None, feature_evidence=None):
    from .explainability import explain, safe_shap, safe_deviations, finite
    identity = p['record_id']
    assigned = incident_by_observation.get(identity)
    label = p['reconciliation']['decision']
    isolated = label == 'UNKNOWN_ANOMALY' and assigned is None
    state = ('SUPPRESSED_ISOLATED_ANOMALY' if isolated else 'UNKNOWN_ANOMALY' if label == 'UNKNOWN_ANOMALY'
             else 'KNOWN_ATTEMPT' if label not in ('BENIGN', 'UNCERTAIN') else label)
    shap = safe_shap(p.get('shap_explanation'))
    reason = None
    try:
        if feature_evidence and feature_evidence.get('status') != 'RESOLVED':
            reason = feature_evidence.get('reason_code', 'FEATURE_VECTOR_UNAVAILABLE')
            # Partial retained deviations remain useful when the vector is genuinely
            # absent. A mismatched vector must never be interpreted as this window.
            if reason != 'FEATURE_VECTOR_NOT_RETAINED' or not safe_deviations(p.get('robust_deviations')):
                raise ValueError('Live evidence not resolvable')
        human_explanation = explain(p, features=features, package_id=package_id)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Presentation failures cannot remove an observation or change CQI.
        reason = reason or ('EXPLANATION_REFERENCE_UNAVAILABLE' if isinstance(exc, OSError) else
            'MODEL_OUTPUT_INCOMPLETE' if isinstance(exc, KeyError) else 'EXPLANATION_REFERENCE_OR_INPUT_INVALID')
        human_explanation = {'summary': 'Human-readable reference unavailable; model decision is unchanged.',
            'evidence_quality': {'feature_coverage': 'UNAVAILABLE', 'reason_code': reason, 'causal': False}}
    if feature_evidence:
        human_explanation.setdefault('provenance', {})['feature_evidence'] = dict(feature_evidence,
            used_evidence='RETAINED_INFERENCE_VECTOR' if feature_evidence.get('status') == 'RESOLVED' else
                'SAVED_ROBUST_DEVIATIONS' if 'anomaly' in human_explanation else 'UNAVAILABLE')
        human_explanation['evidence_quality']['reason_code'] = reason
        if 'anomaly' in human_explanation:
            cut = p.get('novelty_threshold')
            human_explanation['anomaly']['threshold'] = cut if finite(cut) else None
            cut = p['reconciliation'].get('confidence_threshold')
            human_explanation['classification']['accepted_confidence_threshold'] = cut if finite(cut) else None
    return BehaviorObservation(observation_id=identity, sequence=p['sequence'], window_start=p['window_start'],
        window_end=p['window_end'], reconciled_label=label,
        novelty_state='ANOMALOUS' if p['novelty_anomalous'] else 'NORMAL', novelty_score=p['novelty_score'],
        xgb_label=p['xgb_label'], xgb_score=p['xgb_confidence'], model_disagreement=p['reconciliation']['model_disagreement'],
        actionable=assigned is not None, suppression_reason='Frozen UNKNOWN persistence has not been met' if isolated else None,
        presentation_state=state, episode_id=assigned, model_package_id=package_id,
        evidence=sanitize({k: p.get(k) for k in ('source_sha256', 'source_byte_ranges', 'client_id', 'user_agent_id',
            'schema_sha256', 'run_id', 'observation_count', 'emitted_at_utc', 'time_semantics')}),
        explanation=sanitize({'shap': shap, 'robust_deviations': safe_deviations(p.get('robust_deviations')),
            'robust_semantics': 'Associated deviations — not causal attribution.',
            'reconciliation_reason': p['reconciliation']['reason'], 'causal': False, **human_explanation}))


def fusion_event(correlation, incident, posture_ids):
    matched = sorted(posture_ids[e] for e in correlation['posture_evidence_ids'] if e in posture_ids)
    direct = incident.behavior_class in ('SQLI_ATTEMPT', 'XSS_ATTEMPT', 'REQUEST_BURST_DOS_LIKE')
    return FusionEvent(fusion_event_id='fusion-' + digest([correlation['correlation_id'], incident.episode_id]),
        behavior_episode_id=incident.episode_id, related_posture_finding_ids=matched,
        relationship_type='DIRECT_CONTEXT' if direct else 'SUPPORTING_CONTEXT', context_strength='CONTEXTUAL',
        contextual_severity=incident.severity, created_at=incident.last_seen, rule_id=correlation['rule_id'],
        explanation=correlation['explanation'] + ' Rule ' + correlation['rule_id'] +
            ' links this episode to ' + ', '.join(matched) +
            '. Presentation severity is unchanged; contextual evidence adds no CQI penalty and does not upgrade posture confirmation.')
