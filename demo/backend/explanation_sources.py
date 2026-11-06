"""Read-only raw-feature resolution for locked replay, never reclassifies events.

Only server-controlled evidence roots are opened; full queries are never returned.
Missing evidence degrades to the numeric deviations already in saved predictions.
"""
import hashlib
import json
import math
from pathlib import Path
from behavioral_v2.schema import FEATURES
from branch2.adapters.apache import read_log
from branch2.windowing import windows
from behavioral_v2.features31 import extract
from behavioral_v2.platforms import MoodleBehaviorAdapter

BENIGN_LOCK = '807a14cbb6b2d26897709a71de2316f4b01c53fde85e836e9b25c344d84711a4'


def live_window_evidence(stored, package_id, schema_hash, payload_hash):
    """Bind the retained inference vector to its verified journal prediction.

    This does not extract features or run inference. Never echo unknown fields or
    diagnostic exception text; only reviewed structural/numeric evidence leaves
    the journal reader.
    """
    prediction = stored['prediction']; window = stored.get('window')
    window = window if isinstance(window, dict) else {}
    row = window.get('row'); row = row if isinstance(row, dict) else {}
    evidence = {'mode': 'LIVE_LAB', 'kind': 'LIVE_JOURNAL_WINDOW_ROW',
        'resolver': 'live-inference-vector-1.0', 'status': 'UNAVAILABLE',
        'reason_code': None, 'observation_id': prediction['record_id'],
        'window_start': prediction['window_start'], 'window_end': prediction['window_end'],
        'schema_sha256': schema_hash, 'package_id': package_id,
        'journal_payload_sha256': payload_hash, 'recomputed': False}
    def unavailable(reason):
        return {}, dict(evidence, reason_code=reason)
    if not row.get('features'):
        return unavailable('FEATURE_VECTOR_NOT_RETAINED')
    if row.get('schema_sha256') != schema_hash:
        return unavailable('FEATURE_VECTOR_SCHEMA_MISMATCH')
    if (window.get('record_id') != prediction['record_id']
            or window.get('observation_id', prediction['record_id']) != prediction['record_id']
            or any(row.get(k) != prediction.get(k) for k in
                   ('window_start', 'window_end', 'client_id', 'user_agent_id', 'source_sha256'))
            or window.get('session_id', prediction.get('session_id')) != prediction.get('session_id')):
        return unavailable('FEATURE_VECTOR_IDENTITY_MISMATCH')
    values = row['features']
    if not isinstance(values, dict) or set(values) != set(FEATURES):
        return unavailable('FEATURE_VECTOR_INCOMPLETE')
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in values.values()):
        return unavailable('FEATURE_VECTOR_NONFINITE_OR_INVALID')
    for d in prediction.get('robust_deviations') or []:
        if isinstance(d, dict) and d.get('feature') in values and isinstance(d.get('value'), (int, float)):
            if values[d['feature']] != d['value']:
                return unavailable('FEATURE_VECTOR_PREDICTION_MISMATCH')
    vector_hash = hashlib.sha256(json.dumps(values, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    return values, dict(evidence, status='RESOLVED', feature_count=len(values),
        vector_sha256=vector_hash, identity_verified=True, source_sha256=row.get('source_sha256'))


def key(row):
    return tuple(row.get(k) for k in ('run_id', 'window_start', 'window_end', 'client_id', 'user_agent_id'))


def replay_features(root, predictions, source, schema_hash):
    root = Path(root).resolve(); result = {}
    if source == 'BENIGN_TEST':
        path = root / 'outputs/branch2/m5_final_day/blind_benign_test_01/test_evidence_manifest.json'
        if not path.exists(): return result
        if hashlib.sha256(path.read_bytes()).hexdigest() != BENIGN_LOCK:
            return result
        lock = json.loads(path.read_text())
        allowed = {s['session_id']: s for s in lock['sessions'] if s['verified'] and s['state'] == 'COMPLETE'}
        for rid in sorted({p['run_id'] for p in predictions} & set(allowed)):
            path = root / 'outputs/branch2/m5_final_day/browser_sessions' / rid / 'features.json'
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != allowed[rid]['artifact_hashes']['features.json']:
                continue
            for row in json.loads(path.read_text()):
                if row['schema_sha256'] == schema_hash and row['run_id'] == rid:
                    result[key(row)] = row['features']
    else:
        approved = root / 'evidence/branch2_captures/m5_fresh_attack_holdout_01'
        cache = {}
        for p in predictions:
            # Run ID cannot supply a path, even when a damaged prediction is read.
            rid = p['run_id']
            if not isinstance(rid, str) or Path(rid).name != rid or rid in ('.', '..'):
                continue
            path = (approved / rid / 'access.log').resolve()
            if not path.is_relative_to(approved) or not path.is_file(): continue
            if rid not in cache:
                events, errors, source_hash = read_log(path, str(path))
                cache[rid] = None if errors else (events, source_hash)
            cached = cache[rid]
            if not cached or cached[1] != p['source_sha256']: continue
            selected = set(p.get('line_numbers') or [])
            events = [e for e in cached[0] if e.line_number in selected]
            groups = list(windows(events))
            if len(groups) != 1 or len(events) != len(selected): continue
            row = dict(groups[0], run_id=rid)
            if key(row) == key(p):
                result[key(p)] = extract(events, MoodleBehaviorAdapter())
    # Saved numeric deviations are an independent check on the reconstructed join.
    for p in predictions:
        values = result.get(key(p))
        if values is not None and any(abs(values.get(d['feature'], float('inf')) - d['value']) > 1e-8
                                      for d in p.get('robust_deviations', [])):
            result.pop(key(p), None)
    return result
