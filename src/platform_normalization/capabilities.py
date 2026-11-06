"""Capability denominator fixed prospectively; availability is not a security PASS."""
from .dependencies import behavioral_contract

# These 20 user-facing functions define the denominator before fixture evaluation.
# PARTIAL is reported separately and never counted as AVAILABLE.
CAPABILITIES = (
    'http_transport_headers', 'cors_methods', 'server_disclosure', 'cookie_session_attributes',
    'zap_passive', 'zap_standard_active', 'native_active_validation',
    'web_telemetry_ingestion', 'behavioral_83_features', 'behavioral_explanations',
    'traffic_timing', 'status_distribution', 'path_method_behavior', 'query_pattern_behavior',
    'response_size_behavior', 'session_context', 'role_context', 'authentication_context',
    'platform_configuration', 'platform_patch_advisories')


def assess(batch, platform=None, context=None):
    from .adapters import adapter
    platform = platform or adapter(batch.source.get('platform', 'generic_web'))
    context = dict(context or {})
    if set(context) - {'authorized_target', 'http_collection_available', 'zap_runtime_ready',
                       'native_validator_prerequisites', 'internal_collector_verified', 'patch_baseline_verified'}:
        raise ValueError('Unknown capability prerequisite')
    contract = behavioral_contract(batch); rows = {}
    mapped=[platform.semantic_adapter().map_request(e.path,e.method or 'GET')
            for e in batch.events if e.path is not None]
    contract['semantic_mapping']={'records':len(mapped),'unknown_records':sum(s.category=='UNKNOWN' for s in mapped),
        'reason':'Unreviewed generic paths remain UNKNOWN; declarative routes add explicit semantics. No authentication/navigation intent is inferred.'}
    def put(key, available, why, absent=None):
        rows[key] = {'state': 'AVAILABLE' if available else 'NOT_AVAILABLE',
                     'reason': why if available else absent or why, 'security_verdict': None}
    target = context.get('authorized_target', False) is True
    http = target and context.get('http_collection_available', False) is True
    for key in ('http_transport_headers', 'cors_methods', 'server_disclosure'):
        put(key, http, 'Existing generic Branch1 rules, subject to per-target reviewed scope.',
            'Authorized target and fresh HTTP transport are required; logs alone do not establish posture findings.')
    put('cookie_session_attributes', False, 'Existing cookie rule expects MoodleSession; generic cookie semantics are not implemented.')
    zap = target and context.get('zap_runtime_ready', False) is True
    for key in ('zap_passive', 'zap_standard_active'):
        put(key, zap, 'Existing unchanged ZAP profile is configured and ready; availability is not an executed scan.',
            'Explicit authorization and reachable dedicated fresh-session ZAP runtime required.')
    native = platform.platform_id == 'moodle' and target and context.get('native_validator_prerequisites', False) is True
    put('native_active_validation', native, 'Existing current Moodle validator safety gate and prerequisites satisfied.',
        'Current repository validation executor is Moodle-lab restricted; generic planning does not establish executable probes.')
    if platform.platform_id != 'moodle':
        rows['native_active_validation']['state'] = 'PARTIAL'
        rows['native_active_validation']['reason'] = 'Generic validator families exist, but the current executor requires a separately reviewed target context. No probes implied.'
    put('web_telemetry_ingestion', bool(batch.events), 'Canonical events parsed; quality report must still be reviewed.')
    put('behavioral_83_features', contract['execution_allowed'], contract['reason'])
    put('behavioral_explanations', contract['execution_allowed'], 'Task 2A engine supports the same numerical feature vocabulary; generic predictions are not externally validated.', contract['reason'])
    def fields(key, needed):
        ok = bool(batch.events) and all(all(f not in e.missing_fields for f in needed) for e in batch.events)
        put(key, ok, 'All required fields observed: '+', '.join(needed), 'Missing field coverage: '+', '.join(needed))
        if not ok and any(all(f not in e.missing_fields for f in needed) for e in batch.events): rows[key]['state'] = 'PARTIAL'
    fields('traffic_timing', ('timestamp', 'client_id'))
    fields('status_distribution', ('status',))
    fields('path_method_behavior', ('path', 'method'))
    fields('query_pattern_behavior', ('query',))
    fields('response_size_behavior', ('response_bytes',))
    fields('session_context', ('session_id',))
    fields('role_context', ('role',))
    fields('authentication_context', ('authentication_state',))
    for key, prerequisite in [('platform_configuration', 'internal_collector_verified'), ('platform_patch_advisories', 'patch_baseline_verified')]:
        put(key, platform.platform_id == 'moodle' and context.get(prerequisite, False) is True,
            'Existing Moodle implementation with verified fresh prerequisite.',
            'Moodle-specific enrichment and fresh collector/baseline are required.')
        if platform.platform_id != 'moodle': rows[key]['state'] = 'NOT_APPLICABLE'
    available = sum(r['state'] == 'AVAILABLE' for r in rows.values())
    assert set(rows) == set(CAPABILITIES)
    return {'version': 'platform-capability-matrix-1.0', 'adapter': platform.identity(),
            'behavioral': contract, 'capabilities': rows,
            'coverage': {'policy': '20 fixed user-facing capabilities; only AVAILABLE counts; PARTIAL has zero weight',
                         'available': available, 'denominator': len(CAPABILITIES),
                         'percentage': 100 * available / len(CAPABILITIES),
                         'meaning': 'This source and its explicit operational prerequisites only; not universal accuracy or platform validation.'}}
