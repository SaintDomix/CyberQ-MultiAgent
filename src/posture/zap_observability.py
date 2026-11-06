"""Typed current-session ZAP telemetry; no request bodies or inferred verdicts."""
import json
import re
import math
from collections import deque
from urllib.parse import urlsplit
from .target import endpoint,sanitized_url,parameter
from .privacy import text,sha


def unpack(value,depth=0):
    if depth>16:return None
    if isinstance(value,str) and len(value)<2_000_000 and value.lstrip().startswith(('{','[')):
        try:return unpack(json.loads(value),depth+1)
        except ValueError:return value
    if isinstance(value,list):return [unpack(x,depth+1) for x in value]
    if isinstance(value,dict):return {k:unpack(v,depth+1) for k,v in value.items()}
    return value


def progress_rules(payload):
    """2.17 Plugin order: name,id,quality,status,timeInMs,reqCount,alertCount.

    ApiResponseList serializes response elements as positional values, and nested
    lists can themselves be JSON strings. Also accept named-field versions.
    """
    out={}
    def consume(fields):
        sid=str(fields.get('id',''));count=str(fields.get('reqCount',''))
        if not sid.isdigit() or not count.isdigit():return
        ms=str(fields.get('timeInMs','0'));alerts=str(fields.get('alertCount','0'))
        out[sid]={'id':sid,'name':text(fields.get('name',''))[:160],
            'request_count':int(count),'time_ms':int(ms) if ms.isdigit() else None,
            'alert_count':int(alerts) if alerts.isdigit() else None,
            'status':text(fields.get('status','Unknown'))[:200],
            'quality':text(fields.get('quality',''))[:40],'source':'ascan/view/scanProgress'}
    def visit(v,label=None):
        if isinstance(v,list):
            if len(v)==7 and str(v[1]).isdigit() and str(v[5]).isdigit() and all(isinstance(x,(str,int)) for x in v):
                consume(dict(zip(('name','id','quality','status','timeInMs','reqCount','alertCount'),v)))
            flat={k:x for i in v if isinstance(i,dict) for k,x in i.items() if isinstance(x,(str,int))}
            consume(flat)
            for i in v:visit(i)
        elif isinstance(v,dict):
            consume(v)
            for k,x in v.items():visit(x,k)
    visit(unpack(payload))
    return sorted(out.values(),key=lambda r:int(r['id']))


def stats_values(value):
    value=unpack(value)
    if isinstance(value,dict) and isinstance(value.get('stats'),dict):value=value['stats']
    return {k:int(v) for k,v in value.items() if re.fullmatch(r'stats\.ascan\.(?:\d+\.)?[A-Za-z.]+',k)
        and str(v).isdigit()} if isinstance(value,dict) else {}


def execution_report(installed,enabled,progress,before,after):
    by_id={r['id']:r for r in progress};enabled=set(enabled);rows=[]
    for scanner in installed:
        sid=str(scanner['id']);p=by_id.get(sid);prefix='stats.ascan.'+sid+'.'
        def delta(name):
            key=prefix+name
            return after.get(key,0)-before.get(key,0) if after.get(key,0)>=before.get(key,0) else None
        started=delta('started');skipped=delta('skipped');requests=p['request_count'] if p else None
        observed=bool((started or 0)>0 or (requests or 0)>0 or (p and (p['time_ms'] or 0)>0))
        status=p.get('status') if p else None
        state=('NOT_ENABLED' if sid not in enabled else 'NOT_APPLICABLE' if status and 'not applicable' in status.lower()
            else 'SKIPPED' if (skipped or 0)>0 or (status and status.lower().startswith('skipped'))
            else 'EXECUTED' if observed else 'NOT_OBSERVED')
        rows.append({'id':sid,'name':text(scanner.get('name',''))[:160],'enabled':sid in enabled,
            'strength':scanner.get('attackStrength'),'threshold':scanner.get('alertThreshold'),
            'execution_observed':observed,'execution_state':state,'request_count':requests,
            'alerts':p.get('alert_count') if p else None,'status':status,'started_counter_delta':started,
            'elapsed_ms':p.get('time_ms') if p else delta('time'),
            'url_work_counter_delta':delta('urls'),'counter_semantics':'urls/work units are not substituted for HTTP request count',
            'evidence':'CURRENT_SCAN_PROGRESS_AND_DAEMON_COUNTER_DELTAS' if p else 'DAEMON_COUNTER_DELTAS_ONLY'})
    return sorted(rows,key=lambda r:int(r['id']))


def completion_seconds(previous_seconds=600,previous_progress=.19,margin=1.15):
    # Planning estimate only: rule progress is not a calibrated linear ETA.
    return math.ceil(previous_seconds/previous_progress*margin/60)*60


def candidate_index(urls,target):
    raw=[u for u in urls if target.contains(u)]
    unique={endpoint(u) for u in raw}
    return {'raw_in_scope_urls':len(raw),'unique_endpoints':len(unique),
        'value_variants_collapsed':len(raw)-len(unique),
        'parameter_occurrences':sum(len(p) for u,p in unique),
        'endpoints':[{'url':u,'parameters':list(p)} for u,p in sorted(unique)],
        'execution_semantics':'One context scan; ZAP Sites Tree already groups query values by parameter names. No endpoint family is removed.'}


def session_index(call,target,guard,seed=None,spider=None,ajax=None):
    """Use body-free tree metadata instead of retrieving every history body.

    Forms come from the already received seed response. Spider/AJAX metadata
    retains any method/status fields they expose; absence is explicit.
    """
    total=int(call('core','view','numberOfMessages')['numberOfMessages'])
    queue=deque([target.target_url.rstrip('/') or target.target_origin]);visited=set();nodes=[];errors=[]
    while queue and len(visited)<10000:
        url=queue.popleft()
        if url in visited:continue
        visited.add(url)
        try:guard()
        except Exception:
            errors.append({'reason':'METADATA_GUARD_INTERRUPTED'});break
        try:
            children=unpack(call('core','view','childNodes',url=url)).get('childNodes',[])
        except Exception:
            errors.append({'operation':'childNodes','url':sanitized_url(url),'reason':'METADATA_UNAVAILABLE'});break
        for child in children:
            if not isinstance(child,dict):continue
            uri=child.get('uri','')
            if not target.contains(uri):continue
            method=child.get('method');method=method if method in ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS') else None
            ep,params=endpoint(uri)
            nodes.append({'url':sanitized_url(uri),'normalized_endpoint':ep,'method':method,
                'parameter_names':list(params),'message_id':str(child.get('hrefId')),
                'source':'CURRENT_ZAP_SITES_TREE','is_leaf':str(child.get('isLeaf')).lower()=='true'})
            if str(child.get('isLeaf')).lower()=='false':queue.append(uri)
    identities={(n['normalized_endpoint'],n['method'],tuple(n['parameter_names'])) for n in nodes}
    # No body/header fields from stage responses are persisted.
    stage_rows=[]
    def walk(v,source):
        v=unpack(v)
        if isinstance(v,list):
            for x in v:walk(x,source)
        elif isinstance(v,dict):
            url=v.get('url',v.get('uri'))
            if isinstance(url,str) and target.contains(url):
                method=v.get('method');status=v.get('statusCode',v.get('statuscode',v.get('responseCode')))
                stage_rows.append({'url':sanitized_url(url),'method':method if method in ('GET','POST','HEAD','OPTIONS') else None,
                    'status_code':int(status) if str(status).isdigit() else None,'source':source})
            for x in v.values():
                if isinstance(x,(list,dict)):walk(x,source)
    walk(spider,'SPIDER');walk(ajax,'AJAX_SPIDER')
    return {'total_history_messages':total,'metadata_source':'CURRENT_SITES_TREE_AND_DISCOVERY_STAGE_APIS',
        'tree_node_count':len(nodes),'normalized_identity_count':len(identities),'nodes':nodes,
        'stage_messages':stage_rows,'methods_observed':sorted({n['method'] for n in nodes if n['method']}),
        'status_codes_observed':sorted({n['status_code'] for n in stage_rows if n['status_code'] is not None}),
        'status_coverage':'Only fields exposed by discovery APIs; not a fabricated all-history status distribution',
        'forms':(seed or {}).get('forms',[]),'forms_coverage':'CURRENT_SEED_RESPONSE_ONLY; further form structure is not exposed by childNodes',
        'metadata_truncated':bool(queue) or bool(errors),'metadata_errors':errors,
        'response_bodies_retained':False,'history_bodies_downloaded_for_export':0}
