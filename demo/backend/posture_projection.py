"""Read-only metadata projection shared by legacy and product posture views.

Callers supply jobs obtained from the orchestrator's verified get/history reads.
No execution, scanner, scoring or canonicalization policy lives here.
"""
from collections import Counter
from copy import deepcopy
import json
from .privacy import sanitize


COMPLETED = frozenset(('COMPLETE', 'PARTIAL'))
BUSY = frozenset(('QUEUED', 'RUNNING', 'CANCELLATION_REQUESTED'))


def assessment_metadata(engine, job):
    if not job:
        return {'status': 'NOT_ASSESSED', 'assessment_id': None,
                'scope': 'CURRENT_OPERATIONAL_POSTURE'}
    result = deepcopy({k: v for k, v in job.items() if k != 'findings'})
    result['assessment_profile'] = job.get('assessment_profile', job.get('mode'))
    if job.get('mode') in ('STANDARD', 'FULL_AUTHORIZED') and job['status'] in COMPLETED:
        execution = dict(result.get('zap_execution') or {})
        if execution.get('active_alerts') is None or execution.get('passive_alerts') is None:
            try:
                # get/history already verified this immutable source's manifest.
                source = json.loads((engine.location(job['assessment_id']) / 'zap.json').read_text())['findings']
                execution.update(
                    active_alerts=sum(f['evidence_source'] == 'ZAP_ACTIVE' for f in source),
                    passive_alerts=sum(f['evidence_source'] == 'ZAP_PASSIVE' for f in source),
                    risk_distribution=dict(Counter(f['severity'] for f in source)),
                    confidence_distribution=dict(Counter(f['source_confidence'] for f in source)),
                    alert_count_derivation='HASH_VERIFIED_IMMUTABLE_NORMALIZED_FINDINGS; original failure retained')
            except (OSError, ValueError, KeyError, TypeError):
                execution['alert_count_availability'] = 'SOURCE_UNAVAILABLE'
                execution['alert_count_reason'] = 'Verified retained ZAP counts could not be resolved; no counts invented.'
        result['zap_execution'] = execution
    return sanitize(result)


def execution_metadata(service, job):
    """Execution identity is independent of the selected scoring snapshot."""
    value = assessment_metadata(service.posture_service, job)
    aid = value['assessment_id']
    engine = service.posture_service
    owned = (getattr(engine, 'jobs', {}).get(aid) or {}).get('status') == 'RUNNING'
    event = getattr(engine, 'cancellations', {}).get(aid)
    requested = bool(event and event.is_set())
    read_only = getattr(service, 'preview_read_only', False)
    value['cancellation'] = {
        'eligible': bool(owned and event and value['status'] == 'RUNNING' and not requested and not read_only),
        'requested': requested,
        'reason': 'READ_ONLY_PREVIEW' if read_only else 'CANCELLATION_ALREADY_REQUESTED' if requested
                  else 'OWNED_RUNNING_ASSESSMENT' if owned and event and value['status'] == 'RUNNING'
                  else 'NO_OWNED_RUNNING_ASSESSMENT',
    }
    value['start_blocked'] = value['status'] in BUSY
    value['scope_label'] = 'LATEST_OPERATIONAL_EXECUTION; independent of selected immutable evidence'
    return value


def history_page(engine, offset=0, limit=25):
    jobs = engine.history()
    fields = ('assessment_id', 'target', 'assessment_profile', 'mode', 'status',
              'started_at', 'completed_at', 'error')
    return {'items': [sanitize({k: job.get(k) for k in fields}) for job in jobs[offset:offset + limit]],
            'total': len(jobs), 'offset': offset, 'limit': limit}
