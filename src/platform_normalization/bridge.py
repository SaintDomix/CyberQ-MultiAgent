"""Gated compatibility boundary into saved features/models. No fitting entry point."""
from branch2.events import CanonicalBehavioralEvent
from branch2.windowing import windows
from behavioral_v2.features31 import extract
from behavioral_v2.schema import FEATURES
from .dependencies import behavioral_contract
from .adapters import adapter


def legacy_event(event):
    for name in ('timestamp', 'client_id', 'method', 'path', 'query', 'status'):
        if name in event.missing_fields: raise ValueError('BEHAVIORAL_INSUFFICIENT_TELEMETRY: '+name)
    return CanonicalBehavioralEvent(event.timestamp, event.client_id, event.method, event.path,
        event.query, event.status, event.response_bytes, event.user_agent, event.referrer,
        event.source_file, event.source_sha256, event.line_number, event.record_sha256,
        authenticated_user_id=event.authenticated_user_id, session_id=event.session_id,
        role=event.role, infrastructure_dummy=event.infrastructure_dummy)


def feature_rows(batch, *, platform=None, run_id='normalized-input', feature_schema_hash=None):
    contract = behavioral_contract(batch)
    if not contract['execution_allowed']: raise ValueError('BEHAVIORAL_INSUFFICIENT_TELEMETRY')
    platform = platform or adapter(batch.source.get('platform', 'generic_web'))
    es = [legacy_event(e) for e in batch.events if not e.infrastructure_dummy]
    result = []
    for group in windows(es):
        f = extract(group['events'], platform.semantic_adapter())
        assert list(f) == list(FEATURES)
        result.append({k: v for k, v in group.items() if k != 'events'} | {
            'run_id': run_id, 'features': f, 'schema_sha256': feature_schema_hash,
            'source_file': es[0].source_file, 'source_sha256': es[0].source_sha256,
            'line_numbers': [e.line_number for e in group['events']]})
    return result


def predict(batch, package, *, platform=None, run_id='normalized-input', explain=True):
    # A frozen numerical contract is necessary but does not establish domain accuracy.
    # The separate adapter identity is never substituted into the frozen schema.
    if not behavioral_contract(batch)['execution_allowed']:
        raise ValueError('BEHAVIORAL_INSUFFICIENT_TELEMETRY')
    platform = platform or adapter(batch.source.get('platform', 'generic_web'))
    rows = feature_rows(batch, platform=platform, run_id=run_id,
                        feature_schema_hash=package.feature_schema['sha256'])
    return {'predictions': package.predict(rows, explain=explain),
            'rows': rows, 'adapter': platform.identity(),
            'model_schema_sha256': package.feature_schema['sha256'],
            'empirical_accuracy_validation': 'Accepted local Moodle laboratory only; ingestion does not validate accuracy in a new deployment.',
            'compatibility_semantics': 'Numerical and canonical vocabulary compatibility; not equal cross-platform accuracy.'}
