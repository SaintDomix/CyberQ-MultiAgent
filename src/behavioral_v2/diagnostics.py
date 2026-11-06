"""Descriptive evidence, never causal explanations or automatic relabeling."""
from collections import Counter
import json
from pathlib import Path
from urllib.parse import parse_qsl
import numpy as np
from branch2.features import FEATURES as BASE, extract as base_extract
from branch2.events import utc
from .semantics import classify


def distribution(values):
    x = np.asarray(values, dtype=float)
    med = float(np.median(x)); mad = float(np.median(abs(x-med)))
    q1, q3 = np.percentile(x, [25, 75]); iqr = float(q3-q1)
    scale = 1.4826*mad if mad else iqr/1.349 if iqr else max(abs(med)*.1, 1.)
    return {'n': len(x), 'min': float(x.min()), 'max': float(x.max()), 'mean': float(x.mean()),
            'median': med, 'MAD': mad, 'IQR': iqr, 'scale': scale}


def diagnostic(v1, split, external_rows, predictions, events):
    profiles = {name: {k: distribution([r['features'][k] for r in v1['rows']
        if r['run_id'] in split[name+'_runs'] and r['label']=='BENIGN']) for k in BASE}
        for name in ('train', 'validation', 'test')}
    records = []
    for row, pred in zip(external_rows, predictions):
        ranked = []
        for k in BASE:
            ref = profiles['train'][k]; value = row['features'][k]
            values = [r['features'][k] for r in v1['rows'] if r['run_id'] in split['train_runs'] and r['label']=='BENIGN']
            ranked.append({'feature': k, 'value': value,
                'signed_robust_deviation': (value-ref['median'])/ref['scale'],
                'absolute_robust_deviation': abs(value-ref['median'])/ref['scale'],
                'train_empirical_percentile_midrank': float((np.sum(np.asarray(values)<value)+.5*np.sum(np.asarray(values)==value))/len(values)),
                'benign_distributions': {n: profiles[n][k] for n in profiles}})
        ranked.sort(key=lambda f: (-f['absolute_robust_deviation'], f['feature']))
        es = events[row['record_id']]
        query_categories = {}
        for category in sorted({classify(e.path) for e in es}):
            selected = [e for e in es if classify(e.path)==category]
            obs = base_extract(selected)
            json_arguments = 0
            for e in selected:
                for name, value in parse_qsl(e.query):
                    if name == 'args':
                        try:
                            json_arguments += isinstance(json.loads(value),(dict,list))
                        except (ValueError,TypeError): pass
            query_categories[category] = {k:obs[k] for k in ('request_count','query_length_max','quote_count',
                'url_encoded_count','parameter_count_total','sql_token_count','xss_marker_count','traversal_count')}
            query_categories[category]['JSON_args_observations'] = json_arguments
        records.append({'sequence': row['sequence'], 'record_id': row['record_id'],
            'window_start': row['window_start'], 'window_end': row['window_end'],
            'decision': pred['reconciliation'], 'if_decision_function': pred['if_decision_function'],
            'if_raw_anomaly_score': pred['if_raw_anomaly_score'], 'xgb_label': pred['xgb_label'],
            'xgb_uncalibrated_score': pred['xgb_confidence'], 'observation_count': len(es),
            'semantic_counts': dict(Counter(classify(e.path) for e in es)),
            'method_counts': dict(Counter(e.method for e in es)),
            'status_counts': dict(Counter(str(e.status) for e in es)),
            'query_indicators_by_semantic_category': query_categories,
            'all_features_ranked': ranked, 'upstream_shap': pred['shap_explanation'],
            'upstream_robust_deviations': pred['robust_explanation'], 'causal': False})
    groups = {}
    for name, selected in {
        'BENIGN': [r for r in records if r['decision']['decision']=='BENIGN'],
        'UNKNOWN_WITH_XGB_BENIGN': [r for r in records if r['decision']['decision']=='UNKNOWN_ANOMALY' and r['xgb_label']=='BENIGN'],
    }.items():
        groups[name] = {'windows': len(selected), 'feature_medians': {
            k: float(np.median([next(f['value'] for f in r['all_features_ranked'] if f['feature']==k) for r in selected]))
            for k in BASE} if selected else {}}
    return {'status': 'EXTERNAL_DIAGNOSTIC_NOT_GROUND_TRUTH', 'training_use': False,
        'records': records, 'groups': groups, 'causal': False,
        'limitations': ['Operator reports legitimate browsing; HTTP paths/status cannot prove all intent, identity or authentication success.',
            'Feature deviations associate with model output; they do not identify causal IF feature attribution.',
            'Diagnostic evidence informed semantic feature design: this external session is not a completely blind generalization test.',
            'POST bodies unavailable. No passwords, queries, cookies, tokens, raw user agents or referrers exported.']}


def coverage(v1, cache, root=None):
    predicates = {
        'login_endpoint': lambda e: classify(e.path)=='AUTH_LOGIN',
        'login_POST': lambda e: classify(e.path)=='AUTH_LOGIN' and e.method=='POST',
        'logout': lambda e: classify(e.path)=='AUTH_LOGOUT',
        'dashboard': lambda e: classify(e.path)=='DASHBOARD',
        'course_navigation': lambda e: classify(e.path)=='COURSE_VIEW',
        'profile': lambda e: classify(e.path)=='PROFILE',
        'quiz_navigation': lambda e: classify(e.path)=='QUIZ_ACTIVITY',
        'AJAX': lambda e: classify(e.path)=='AJAX_SERVICE',
        'theme_static': lambda e: classify(e.path) in ('THEME_RESOURCE','STATIC_ASSET'),
        'POST': lambda e: e.method=='POST', 'redirect': lambda e: 300<=e.status<400,
    }
    matrix = []
    benign = [r for r in v1['rows'] if r['label']=='BENIGN']
    for scenario, predicate in predicates.items():
        rows = [r for r in benign if any(predicate(cache[r['run_id']][n]) for n in r['line_numbers'])]
        matrix.append({'scenario': scenario, 'run_ids': sorted({r['run_id'] for r in rows}),
                       'window_count': len(rows), 'status': 'PRESENT' if rows else 'ABSENT',
                       'note': 'Observed path/method/status; does not prove completed user action'})
    for scenario in ('successful_login','incorrect_then_successful_login','course_switching','multiple_roles'):
        matrix.append({'scenario': scenario, 'run_ids': [], 'window_count': None, 'status': 'NOT_PROVEN',
            'note': 'Requires session-linked action/audit or independent protocol evidence; Apache HTTP status is insufficient'})
    for name, test in (('rapid_browsing',lambda r:r['features']['request_rate']>=2),
                       ('slow_browsing',lambda r:0<r['features']['request_rate']<=.2)):
        rows=[r for r in benign if test(r)]
        matrix.append({'scenario':name,'run_ids':sorted({r['run_id'] for r in rows}), 'window_count':len(rows),
            'status':'PROXY_PRESENT' if rows else 'ABSENT',
            'note':'Predeclared rate proxy only: >=2 or <=0.2 requests/s; human browsing not established'})
    if root is not None:
        # Independent experiment protocol supplements HTTP observability. No
        # credentials or worker request URLs are copied into this matrix.
        path=Path(root)/'evidence/branch2_captures/session03_clean/schedule.json'
        schedule=json.loads(path.read_text())
        supported=[]
        for run in schedule['runs']:
            if run.get('auth_role')!='administrator' or run['label']!='BENIGN':continue
            manifest=path.parent/run['run_id']/'manifest.json'
            result=json.loads(manifest.read_text()).get('worker_result',{})
            if result.get('status')=='COMPLETE' and run['run_id'] in cache:supported.append(run['run_id'])
        for entry in matrix:
            if entry['scenario']=='successful_login' and supported:
                entry.update(run_ids=sorted(supported),status='PROTOCOL_SUPPORTED',
                    window_count=sum(r['run_id'] in supported for r in benign),
                    note='B04 administrator bootstrap includes identity verification; COMPLETE worker protocol supports login, not a browser asset load')
            if entry['scenario']=='multiple_roles' and supported:
                entry.update(run_ids=sorted(supported),status='PARTIAL_ADMIN_ONLY',
                    note='Administrator protocol supported; no separately verified student/teacher browser protocols established here')
    return matrix


def redundancy(train_rows, feature_order):
    values=np.asarray([[r['features'][k] for k in feature_order] for r in train_rows])
    variance=values.var(axis=0); active=np.flatnonzero(variance>1e-12)
    with np.errstate(invalid='ignore', divide='ignore'):
        corr=np.corrcoef(values[:,active],rowvar=False)
    pairs=[{'a':feature_order[int(active[i])], 'b':feature_order[int(active[j])], 'pearson':float(corr[i,j])}
        for i in range(len(active)) for j in range(i) if abs(corr[i,j])>=.98]
    return {'fit_partition':'TRAIN only','variance':dict(zip(feature_order,map(float,variance))),
        'constant_features':[k for k,v in zip(feature_order,variance) if v<=1e-12],
        'high_correlation_abs_ge_098':pairs,
        'decision':'Retain all baseline features for paired comparability; retain transparent count/ratio redundancy; no TEST/external feature selection.'}
