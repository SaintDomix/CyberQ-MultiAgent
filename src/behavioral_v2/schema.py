"""Strict additive schema. The 65 accepted features retain their original meaning."""
import hashlib
import json
from pathlib import Path
import numpy as np
from branch2.features import FEATURES as BASE, extract as base_extract, schema as base_schema
from . import semantics

VERSION = 'dataset-v3-features-2.0'
ADDED = ('semantic_request_count', 'semantic_request_rate', 'asset_request_count',
         'asset_request_rate', 'asset_ratio', 'navigation_count', 'semantic_navigation_ratio',
         'auth_request_count', 'logout_request_count', 'dashboard_request_count',
         'course_view_request_count', 'quiz_request_count', 'profile_request_count',
         'theme_request_count', 'unknown_semantic_ratio', 'semantic_unique_path_count',
         'semantic_unique_path_ratio', 'successful_response_ratio')
FEATURES = BASE + ADDED


def schema():
    value = {'version': VERSION, 'feature_order': list(FEATURES), 'window_seconds': 10,
             'base_schema': base_schema(), 'semantic_adapter': 'moodle-explicit-paths-1.0',
             'semantic_adapter_sha256': hashlib.sha256(Path(semantics.__file__).read_bytes()).hexdigest(),
             'total_request_count': 'existing request_count; exact alias, not duplicated in matrix',
             'ajax_ratio': 'existing ajax_request_ratio; AJAX is not discarded',
             'missing_optional': 'unchanged neutral values plus observed-ratio flags',
             'POST_bodies': 'unavailable; lexical features observe URL/query only'}
    value['sha256'] = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return value


def extract(events):
    return {**base_extract(events), **semantics.semantic_features(events)}


def matrix(rows, expected=None):
    expected = expected or schema()
    if expected != schema(): raise ValueError('Unsupported v2 feature schema/order/hash')
    for row in rows:
        if row['schema_sha256'] != expected['sha256'] or set(row['features']) != set(FEATURES):
            raise ValueError('Feature schema mismatch')
    values = np.asarray([[r['features'][k] for k in FEATURES] for r in rows], dtype=float).reshape(len(rows), len(FEATURES))
    if not np.isfinite(values).all(): raise ValueError('Nonfinite features')
    return values
