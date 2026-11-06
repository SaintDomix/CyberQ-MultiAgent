"""83-feature numerical contract built from canonical platform semantics."""
from collections import Counter
import hashlib
import json
import numpy as np
from branch2.features import extract as raw_extract
from .schema import FEATURES
from .platforms import MoodleBehaviorAdapter
from urllib.parse import parse_qsl


def schema(adapter):
    value={'version':'dataset-v3.1-features-2.1','feature_order':list(FEATURES),
        'window_seconds':10,'adapter':adapter.identity(),
        'semantics':'83 retained columns; login/admin/AJAX/API counters use canonical categories; theme is canonical rendering-resource subtype',
        'POST_bodies':'unavailable; raw lexical query indicators retained, no body inference',
        'feature_selection':'no TEST-driven feature deletion; raw lexical features retained for ablation'}
    value['sha256']=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return value


def extract(events,adapter):
    if not events:raise ValueError('Empty window')
    f=raw_extract(events);mapped=[adapter.map_request(e.path,e.method) for e in events]
    counts=Counter(s.category for s in mapped);n=len(events)
    for prefix,categories in {'login':{'AUTH_LOGIN','AUTH_LOGOUT'},'admin':{'ADMIN_ACTION'},
        'ajax':{'AJAX_SERVICE'},'api':{'APPLICATION_API'}}.items():
        count=sum(counts[c] for c in categories);f[prefix+'_request_count']=float(count);f[prefix+'_request_ratio']=count/n
    semantic=[e for e,s in zip(events,mapped) if s.category!='STATIC_ASSET']
    navigation=sum(s.category not in ('STATIC_ASSET','AJAX_SERVICE','APPLICATION_API','UNKNOWN') for s in mapped)
    assets=counts['STATIC_ASSET'];unique=len({e.path for e in semantic})
    f.update(semantic_request_count=len(semantic),semantic_request_rate=len(semantic)/10,
        asset_request_count=assets,asset_request_rate=assets/10,asset_ratio=assets/n,
        navigation_count=navigation,semantic_navigation_ratio=navigation/n,
        auth_request_count=counts['AUTH_LOGIN']+counts['AUTH_LOGOUT'],logout_request_count=counts['AUTH_LOGOUT'],
        dashboard_request_count=counts['DASHBOARD'],course_view_request_count=counts['COURSE_VIEW'],
        quiz_request_count=counts['QUIZ_ACTIVITY'],profile_request_count=counts['PROFILE'],
        theme_request_count=sum(s.resource_kind=='THEME' for s in mapped),
        unknown_semantic_ratio=counts['UNKNOWN']/n,semantic_unique_path_count=unique,
        semantic_unique_path_ratio=unique/max(len(semantic),1),
        successful_response_ratio=sum(200<=e.status<300 for e in events)/n)
    return {k:float(f[k]) for k in FEATURES}


def matrix(rows,expected):
    # Validate a generic numerical contract rather than requiring Moodle URLs.
    original={k:v for k,v in expected.items() if k!='sha256'}
    digest=hashlib.sha256(json.dumps(original,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if expected.get('version')!='dataset-v3.1-features-2.1' or expected.get('feature_order')!=list(FEATURES) or expected.get('sha256')!=digest:
        raise ValueError('Feature schema/order/hash mismatch')
    for r in rows:
        if r['schema_sha256']!=digest or set(r['features'])!=set(FEATURES):raise ValueError('Row schema mismatch')
    values=np.asarray([[r['features'][k] for k in FEATURES] for r in rows],float).reshape(len(rows),len(FEATURES))
    if not np.isfinite(values).all():raise ValueError('Nonfinite feature input')
    return values


def query_context(events,adapter):
    """Descriptive scalar sidecar, not extra fitted columns or benign relabeling."""
    result={}
    for category in sorted({adapter.map_request(e.path,e.method).category for e in events}):
        es=[e for e in events if adapter.map_request(e.path,e.method).category==category]
        f=raw_extract(es);valid_json=0
        for e in es:
            for name,value in parse_qsl(e.query):
                if name=='args':
                    try:valid_json+=isinstance(json.loads(value),(dict,list))
                    except (ValueError,TypeError):pass
        result[category]={k:f[k] for k in ('request_count','quote_count','url_encoded_count','query_length_max','parameter_count_total','sql_token_count','xss_marker_count','traversal_count')}
        result[category]['valid_JSON_args_requests']=valid_json
    return result


def review_historical(dataset,split,project):
    """Pre-capture descriptive TRAIN evidence only, not a new experiment."""
    from pathlib import Path
    from branch2.adapters.apache import read_log
    from .diagnostics import redundancy,distribution
    adapter=MoodleBehaviorAdapter();s=schema(adapter);cache={};rows=[]
    train=set(split['train_runs'])
    for r in dataset['rows']:
        if r['run_id'] not in train:continue
        name=r['source_file']
        if name not in cache:
            es,errors,filehash=read_log(Path(project)/name,name)
            if errors or filehash!=r['source_sha256']:raise ValueError('Historical source changed')
            cache[name]={e.line_number:e for e in es}
        es=[cache[name][n] for n in r['line_numbers']]
        rows.append({**r,'features':extract(es,adapter),'schema_sha256':s['sha256'],
            'query_context':query_context(es,adapter)})
    benign=[r for r in rows if r['label']=='BENIGN']
    return {'stage':'PREPARATORY_HISTORICAL_TRAIN_ONLY_NOT_V3_1_EVALUATION','runs':len(train),
        'windows':len(rows),'benign_windows':len(benign),'schema':s,
        'benign_distributions':{k:distribution([r['features'][k] for r in benign]) for k in FEATURES},
        'feature_analysis':redundancy(rows,FEATURES),
        'benign_query_context':[{'run_id':r['run_id'],'window_start':r['window_start'],'categories':r['query_context']} for r in benign],
        'fit_calls':0,'validation_or_test_inspected':False,
        'decision':'Retain 83 columns; defer empirical feature/policy selection to new TRAIN/VALIDATION data. Never tune against prior TEST.'}
