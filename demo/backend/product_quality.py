"""Read-only product migration. One selected evidence set, two explicit policy views."""
from cqi_v2 import evaluate, compare, registry
from cqi_v2.model import leaves, root_for
from fusion.schema import CATEGORIES
from .privacy import sanitize
from .posture_projection import assessment_metadata, execution_metadata, history_page
from collections import Counter


def verified_root_resolution(before, after):
    """Do not call a partly missing root remediated after one member is fixed."""
    if not after or after['hazard'] > 0 or after['coverage'] != 1:
        return False
    previously_failed = {m['finding_id'] for m in before.get('members', []) if m['hazard'] > 0}
    verified = {m['finding_id'] for m in after.get('members', [])
                if m['reason'] == 'VERIFIED_REMEDIATION_OR_OBSOLESCENCE'}
    return bool(previously_failed) and previously_failed <= verified


def posture_comparison(engine, selected):
    """Compare immutable posture at acquisition time; no unrelated live D6 is imported."""
    if not selected:
        return {'comparable': False, 'reason': 'NO_COMPLETED_POSTURE_ASSESSMENT', 'delta': None}
    previous = next((j for j in engine.history() if j['status'] in ('COMPLETE', 'PARTIAL')
        and j['target'] == selected['target'] and j['started_at'] < selected['started_at']
        and j.get('assessment_profile', j.get('mode')) == selected.get('assessment_profile', selected.get('mode'))), None)
    if not previous:
        return {'comparable': False, 'reason': 'NO_PREVIOUS_SAME_TARGET_PROFILE', 'delta': None}
    previous = engine.get(previous['assessment_id'])
    base_ids = {c['control_id'] for c in registry()['controls']}
    known = {}
    for job in (previous, selected):
        for row in (leaf for parent in job['findings'] for leaf in leaves(parent)):
            fid = row['finding_id']; root, dimension = root_for(fid)
            dimension = dimension or CATEGORIES.get(row['category'])
            if fid not in base_ids and dimension:
                known[fid] = {'control_id':fid, 'root_id':row.get('weakness_key') or row.get('canonical_finding_id') or root,
                    'dimension':dimension, 'platform_scope':'GENERIC_HTTP'}
    def score(job):
        return evaluate(job['findings'], as_of=job['completed_at'], posture_time=job['completed_at'],
            known_controls=list(known.values()),
            platform='moodle' if job['target'] == 'http://192.168.226.132/moodle/' else 'generic_web')
    before, after = score(previous), score(selected)
    result = compare(before, after)
    def compact(q):
        return {k: q[k] for k in ('overall', 'conditional_overall', 'coverage', 'dimensions', 'policy', 'as_of')}
    def weaknesses(q):
        return {r['root_id']: r for r in q['contributors'] if r['hazard'] > 0}
    old, new = weaknesses(before), weaknesses(after)
    after_roots = {r['root_id']: r for r in after['contributors']}
    resolved = [rid for rid in old if rid not in new and verified_root_resolution(old[rid], after_roots.get(rid))]
    return sanitize({**result, 'scope': 'POSTURE_ONLY_AT_ACQUISITION; D6 UNAVAILABLE IN BOTH',
        'previous_assessment_id': previous['assessment_id'], 'assessment_id': selected['assessment_id'],
        'before': compact(before), 'after': compact(after), 'verified_resolved_roots': resolved,
        'newly_observed_roots': sorted(set(new)-set(old)),
        'no_longer_supported_roots': sorted(set(old)-set(new)-set(resolved)),
        'disappearance_is_remediation': False,
        'plateau_caution': 'A guarded aggregate may remain unchanged when a dimension improves. Inspect dimensions; no strict scalar responsiveness is claimed.',
        'behavior_comparison': 'NOT_PAIRED; current journal is not a historical incident snapshot'})


def product_assessment(service, mode=None, replay='ATTACK_HOLDOUT', run_id=None, assessment_id=None):
    mode = mode or service.current_mode
    if assessment_id and mode != 'LIVE_LAB':
        raise ValueError('Historical posture selection requires LIVE_LAB evidence view')
    evidence = {}
    snap = service.snapshot(mode, replay, run_id, assessment_id=assessment_id, evidence=evidence)
    scientific = service.scientific_quality(mode, replay, run_id, bound_snapshot=(snap, evidence))
    assessment = evidence.get('assessment')
    latest = service.posture_service.latest()
    execution = execution_metadata(service, latest)
    history = history_page(service.posture_service, limit=50)
    # Source identity is explicit, including when the latest attempt is incomplete.
    selection = {'mode': mode, 'replay': replay if mode == 'ACCEPTED_REPLAY' else None,
        'run_id': run_id, 'assessment_id': assessment['assessment_id'] if assessment else None,
        'target': assessment['target'] if assessment else snap['status'].target['base_url'],
        'profile': assessment.get('assessment_profile', assessment.get('mode')) if assessment else
                   'ACCEPTED_RESEARCH_BASELINE' if mode == 'ACCEPTED_REPLAY' else None,
        'evidence_state': assessment['status'] if assessment else
                          'ACCEPTED_RESEARCH_BASELINE' if mode == 'ACCEPTED_REPLAY' else 'NO_COMPLETED_CURRENT_POSTURE',
        'latest_attempt_status': execution['status'],
        'posture_completed_at': assessment.get('completed_at') if assessment else None,
        'as_of_semantics': scientific['comparison_context']['as_of_semantics'],
        'historical_selection': bool(assessment_id), 'current_ml_predictions_rewritten': False,
        'behavior_scope':'UNPAIRED_HISTORICAL_POSTURE' if assessment_id else 'ACCEPTED_EVIDENCE_TIME' if mode=='ACCEPTED_REPLAY' else 'CURRENT_VERIFIED_JOURNAL',
        'posture_scope':snap['status'].posture_scope}
    if selection['assessment_id'] != scientific['comparison_context']['assessment_id']:
        raise ValueError('Posture and quality source identity mismatch')
    # Match the existing application API's bounded newest-first stream. D6 and
    # episode explanations above used the complete same-read inference evidence.
    view = {**snap, 'observations':list(reversed(snap['observations']))[:200]}
    return {'schema_version': 'product-assessment-3.0', 'snapshot': view, 'scientific_cqi': scientific,
        'assessment':assessment_metadata(service.posture_service, assessment) if assessment else None,
        'latest_execution': execution,
        'behavior_summary': {'scope':'ALL_SELECTED_RETAINED_OBSERVATIONS',
            'observations':len(snap['observations']),
            'novelty_counts':dict(Counter(o.novelty_state for o in snap['observations'])),
            'reconciled_counts':dict(Counter(o.reconciled_label for o in snap['observations']))},
        'preview_read_only':getattr(service,'preview_read_only',False),
        'selection': selection, 'comparison': posture_comparison(service.posture_service, assessment),
        'history': history['items'], 'history_total': history['total'],
        'closure_review': {'available': False, 'reason': 'DURABLE_AUTHENTICATED_VERIFICATION_WORKFLOW_NOT_IMPLEMENTED',
            'semantics': 'Expiry is temporal inactivity, not verified remediation. Predictions and episode evidence are immutable.'}}
