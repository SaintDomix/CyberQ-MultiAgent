"""Versioned observational features, never exploit or intent confirmation."""
from collections import Counter
import hashlib
import json
import re
from urllib.parse import unquote, parse_qsl
import numpy as np

VERSION='dataset-v2-features-1.0'
# Path categories are explicitly supplied by the adapter/context, not Moodle model code.
DEFAULT_PATH_RULES={'login':r'/login(?:/|\.|$)', 'admin':r'/admin(?:/|\.|$)',
                    'ajax':r'/ajax(?:/|\.|$)|_ajax\.php$', 'api':r'/api(?:/|\.|$)|/webservice(?:/|\.|$)'}
FEATURES=tuple('''request_count request_rate active_span mean_inter_request min_inter_request max_inter_request std_inter_request
unique_paths unique_path_ratio repeated_path_ratio max_requests_same_path path_repetition_ratio resource_breadth
login_request_count login_request_ratio admin_request_count admin_request_ratio ajax_request_count ajax_request_ratio api_request_count api_request_ratio
get_count get_ratio post_count post_ratio other_method_count other_method_ratio
status_1xx_count status_2xx_count status_3xx_count status_4xx_count status_5xx_count redirect_ratio client_error_ratio server_error_ratio error_ratio
response_bytes_total response_bytes_mean response_bytes_max response_bytes_std response_bytes_observed_ratio
query_present_count query_present_ratio query_length_mean query_length_max parameter_count_total parameter_count_mean
url_encoded_count url_encoded_ratio quote_count comment_sequence_count special_character_ratio sql_token_count xss_marker_count traversal_count suspicious_query_ratio
identity_observed_ratio unique_users requests_per_user_mean session_observed_ratio unique_sessions requests_per_session_mean role_observed_ratio unique_roles privileged_role_request_ratio'''.split())


def schema(seconds=10, path_rules=None):
    if isinstance(seconds,bool) or not isinstance(seconds,int) or seconds<1: raise ValueError('Positive integer window required')
    rules=dict(DEFAULT_PATH_RULES if path_rules is None else path_rules)
    if set(rules)!=set(DEFAULT_PATH_RULES): raise ValueError('Explicit login/admin/ajax/api path rules required')
    for pattern in rules.values(): re.compile(pattern)
    row={'version':VERSION,'feature_order':list(FEATURES),'window_seconds':seconds,
         'alignment':'UTC epoch; nonempty windows; run/client/user-agent digest',
         'path_rules':rules,
         'optional_missing':'neutral zero plus observed-ratio flags; bytes dash remains unknown',
         'query_decode':'raw plus at most two URL decode passes; lexical indicators, not exploit confirmation'}
    row['sha256']=hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return row


def matrix(rows, expected):
    if expected['feature_order'] != list(FEATURES) or expected != schema(expected['window_seconds'],expected['path_rules']):
        raise ValueError('Unsupported feature order/schema')
    for row in rows:
        if row['schema_sha256'] != expected['sha256'] or set(row['features']) != set(FEATURES):
            raise ValueError('Feature schema mismatch')
    array=np.asarray([[r['features'][k] for k in FEATURES] for r in rows],dtype=float).reshape(len(rows),len(FEATURES))
    if not np.isfinite(array).all(): raise ValueError('Non-finite features')
    return array


def extract(events, seconds=10, path_rules=None):
    if not events: raise ValueError('Empty feature window')
    rules=schema(seconds,path_rules)['path_rules']
    n=len(events); f=dict.fromkeys(FEATURES,0.0)
    ordered=sorted(events,key=lambda e:e.timestamp)
    ts=[e.timestamp.timestamp() for e in ordered]; gaps=np.diff(ts)
    f.update(request_count=n,request_rate=n/seconds,active_span=max(ts)-min(ts),
        mean_inter_request=float(np.mean(gaps)) if len(gaps) else 0,
        min_inter_request=float(min(gaps)) if len(gaps) else 0,
        max_inter_request=float(max(gaps)) if len(gaps) else 0,
        std_inter_request=float(np.std(gaps)) if len(gaps) else 0)
    paths=Counter(e.path for e in events)
    f.update(unique_paths=len(paths),unique_path_ratio=len(paths)/n,repeated_path_ratio=(n-len(paths))/n,
             max_requests_same_path=max(paths.values()),path_repetition_ratio=max(paths.values())/n,
             resource_breadth=len({e.path.rsplit('/',1)[0] for e in events}))
    for name,pattern in rules.items():
        count=sum(bool(re.search(pattern,e.path,re.I)) for e in events)
        f[name+'_request_count']=count;f[name+'_request_ratio']=count/n
    for method in ('get','post'):
        f[method+'_count']=sum(e.method==method.upper() for e in events);f[method+'_ratio']=f[method+'_count']/n
    f['other_method_count']=n-f['get_count']-f['post_count']; f['other_method_ratio']=f['other_method_count']/n
    for family in range(1,6): f[f'status_{family}xx_count']=sum(e.status//100==family for e in events)
    f['redirect_ratio']=f['status_3xx_count']/n; f['client_error_ratio']=f['status_4xx_count']/n
    f['server_error_ratio']=f['status_5xx_count']/n;f['error_ratio']=f['client_error_ratio']+f['server_error_ratio']
    sizes=[e.response_bytes for e in events if e.response_bytes is not None]
    f.update(response_bytes_total=sum(sizes),response_bytes_mean=float(np.mean(sizes)) if sizes else 0,
             response_bytes_max=max(sizes,default=0),response_bytes_std=float(np.std(sizes)) if sizes else 0,
             response_bytes_observed_ratio=len(sizes)/n)
    lengths=[len(e.query) for e in events];special=chars=suspicious=0
    for e in events:
        raw=e.query; decoded=unquote(unquote(raw))
        f['query_present_count']+=bool(raw)
        f['parameter_count_total']+=len(parse_qsl(raw,keep_blank_values=True))
        f['url_encoded_count']+=len(re.findall(r'%[0-9a-f]{2}',raw,re.I))
        quotes=len(re.findall(r'''['"]''',decoded));comments=len(re.findall(r'--|/\*|\*/|#',decoded))
        sql=len(re.findall(r'\b(?:select|union|sleep|benchmark|information_schema|drop|insert|update|delete|or\s+\d+\s*=\s*\d+)\b',decoded,re.I))
        xss=len(re.findall(r'<\s*(?:script|svg|img)\b|javascript\s*:|\bon(?:error|load|click)\s*=',decoded,re.I))
        traversal=len(re.findall(r'\.\.[/\\]',unquote(unquote(e.path+'?'+raw))))
        f['quote_count']+=quotes;f['comment_sequence_count']+=comments;f['sql_token_count']+=sql
        f['xss_marker_count']+=xss; f['traversal_count']+=traversal
        special+=sum(not (c.isalnum() or c.isspace()) for c in decoded);chars+=len(decoded)
        suspicious+=bool(quotes or comments or sql or xss or traversal)
    f.update(query_present_ratio=f['query_present_count']/n,query_length_mean=float(np.mean(lengths)),query_length_max=max(lengths),
             parameter_count_mean=f['parameter_count_total']/n,url_encoded_ratio=f['url_encoded_count']*3/max(sum(lengths),1),
             special_character_ratio=special/max(chars,1),suspicious_query_ratio=suspicious/n)
    for field,prefix in [('authenticated_user_id','identity'),('session_id','session'),('role','role')]:
        values=[getattr(e,field) for e in events if getattr(e,field) is not None]
        f[prefix+'_observed_ratio']=len(values)/n
        if field=='authenticated_user_id': f.update(unique_users=len(set(values)),requests_per_user_mean=len(values)/max(len(set(values)),1))
        elif field=='session_id': f.update(unique_sessions=len(set(values)),requests_per_session_mean=len(values)/max(len(set(values)),1))
        else: f.update(unique_roles=len(set(values)),privileged_role_request_ratio=sum(v in {'administrator','manager'} for v in values)/n)
    return {name:float(f[name]) for name in FEATURES}
