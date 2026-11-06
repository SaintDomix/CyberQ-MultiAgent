"""Explicit dependencies traced to the frozen extractors, not inferred by prefix."""
from behavioral_v2.schema import FEATURES

REQUIRED = ('timestamp', 'client_id', 'method', 'path', 'query', 'status')
OPTIONAL = ('user_agent', 'response_bytes', 'authenticated_user_id', 'session_id', 'role')
BASE_SOURCE = 'src/branch2/features.py:extract'
SEMANTIC_SOURCE = 'src/behavioral_v2/features31.py:extract'


def dependency_matrix():
    groups = [
        ('timestamp', 'request_count request_rate active_span mean_inter_request min_inter_request max_inter_request std_inter_request', BASE_SOURCE, 'required'),
        ('path', 'unique_paths unique_path_ratio repeated_path_ratio max_requests_same_path path_repetition_ratio resource_breadth', BASE_SOURCE, 'required'),
        ('path method', 'login_request_count login_request_ratio admin_request_count admin_request_ratio ajax_request_count ajax_request_ratio api_request_count api_request_ratio', SEMANTIC_SOURCE, 'required'),
        ('method', 'get_count get_ratio post_count post_ratio other_method_count other_method_ratio', BASE_SOURCE, 'required'),
        ('status', 'status_1xx_count status_2xx_count status_3xx_count status_4xx_count status_5xx_count redirect_ratio client_error_ratio server_error_ratio error_ratio', BASE_SOURCE, 'required'),
        ('response_bytes', 'response_bytes_total response_bytes_mean response_bytes_max response_bytes_std response_bytes_observed_ratio', BASE_SOURCE, 'optional_flagged'),
        ('query', 'query_present_count query_present_ratio query_length_mean query_length_max parameter_count_total parameter_count_mean url_encoded_count url_encoded_ratio quote_count comment_sequence_count special_character_ratio sql_token_count xss_marker_count', BASE_SOURCE, 'required'),
        ('path query', 'traversal_count suspicious_query_ratio', BASE_SOURCE, 'required'),
        ('authenticated_user_id', 'identity_observed_ratio unique_users requests_per_user_mean', BASE_SOURCE, 'optional_flagged'),
        ('session_id', 'session_observed_ratio unique_sessions requests_per_session_mean', BASE_SOURCE, 'optional_flagged'),
        ('role', 'role_observed_ratio unique_roles privileged_role_request_ratio', BASE_SOURCE, 'optional_flagged'),
        ('path method', 'semantic_request_count semantic_request_rate asset_request_count asset_request_rate asset_ratio navigation_count semantic_navigation_ratio auth_request_count logout_request_count dashboard_request_count course_view_request_count quiz_request_count profile_request_count theme_request_count unknown_semantic_ratio semantic_unique_path_count semantic_unique_path_ratio', SEMANTIC_SOURCE, 'required'),
        ('status', 'successful_response_ratio', SEMANTIC_SOURCE, 'required')]
    entries = {}
    for fields, names, source, policy in groups:
        for name in names.split():
            entries[name] = {'feature': name, 'value_fields': fields.split(),
                'window_grouping_fields': ['timestamp', 'client_id', 'user_agent'],
                'optional_inputs': fields.split() if policy == 'optional_flagged' else [],
                'implementation': source, 'unavailable_policy':
                    'Accepted neutral values plus explicit observed-ratio flags; context not inferred.' if policy == 'optional_flagged' else
                    'BLOCK_ACCEPTED_MODEL; never substitute zero.',
                'safe_to_compute_without_value_fields': policy == 'optional_flagged',
                'model_compatibility': 'accepted_optional_missing_semantics' if policy == 'optional_flagged' else 'required'}
    assert set(entries) == set(FEATURES) and len(entries) == 83
    return {'version': 'behavioral83-field-dependencies-1.0', 'feature_schema_version': 'dataset-v3.1-features-2.1', 'feature_order': list(FEATURES),
        'required_fields': list(REQUIRED), 'optional_fields': list(OPTIONAL),
        'grouping_semantics': '10-second UTC windows; client and hashed user-agent; absent UA uses accepted missing group.',
        'scope': 'Path semantic features use the selected existing canonical category adapter; generic compatibility is not empirical accuracy validation.',
        'features': [entries[k] for k in FEATURES]}


def behavioral_contract(batch):
    missing = {k: sum(k in e.missing_fields for e in batch.events) for k in REQUIRED + OPTIONAL}
    required = {k: v for k, v in missing.items() if k in REQUIRED and v}
    optional = {k: v for k, v in missing.items() if k in OPTIONAL and v}
    blocked = batch.state != 'COMPLETE' or not any(not e.infrastructure_dummy for e in batch.events) or bool(required)
    state = ('BEHAVIORAL_INSUFFICIENT_TELEMETRY' if blocked else
             'BEHAVIORAL_COMPATIBLE_WITH_OPTIONAL_CONTEXT_MISSING' if optional else 'BEHAVIORAL_FULLY_COMPATIBLE')
    return {'state': state, 'execution_allowed': not blocked, 'required_missing': required,
            'optional_missing': optional, 'feature_count': 83,
            'reason': 'Incomplete/rejected batch or required field missing; no model verdict generated.' if blocked else
                'Accepted missing-value flags used for absent optional inputs; domain accuracy remains Moodle-validated only.'}
