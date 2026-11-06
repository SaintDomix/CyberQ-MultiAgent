"""Evidence-based ZAP 2.17 completion telemetry; entirely synthetic/offline."""
import json
from unittest.mock import Mock
import pytest
from test_zap_full_authorized import SyntheticAPI,run,alert,offline
from posture.target import AuthorizedTarget
from posture.zap_full import FullZapProvider,FullBudget
from posture.zap_observability import progress_rules,execution_report,completion_seconds,candidate_index,session_index,stats_values


def test_real_217_positional_and_json_string_progress():
    payload={'scanProgress':['school:80',json.dumps([json.dumps(['SQL Injection','40018','release','Complete','1050','17','2']),json.dumps(['XSS','40012','release','Pending','0','0','0'])])]}
    rows=progress_rules(payload)
    assert [r['id'] for r in rows]==['40012','40018']
    assert rows[1]['request_count']==17 and rows[1]['time_ms']==1050 and rows[1]['alert_count']==2


def test_enabled_is_not_executed_and_counters_are_not_requests():
    installed=[{'id':'1'},{'id':'2'},{'id':'3'}]
    rows=execution_report(installed,['1','2'],[],{}, {'stats.ascan.1.started':1,'stats.ascan.1.urls':50})
    assert rows[0]['execution_observed'] and rows[0]['request_count'] is None
    assert rows[0]['url_work_counter_delta']==50
    assert rows[1]['execution_state']=='NOT_OBSERVED' and not rows[1]['execution_observed']
    assert rows[2]['execution_state']=='NOT_ENABLED'


def test_counter_baseline_excludes_previous_scan():
    counters={'stats.ascan.1.started':1,'stats.ascan.1.time':500}
    assert not execution_report([{'id':'1'}],['1'],[],counters,counters)[0]['execution_observed']
    assert stats_values({'stats':{**counters,'secret':'TOKEN'}})==counters


def test_skipped_and_not_applicable_require_explicit_evidence():
    p=progress_rules({'Plugin':['Rule','1','release','Not Applicable','0','0','0']})
    assert execution_report([{'id':'1'}],['1'],p,{}, {})[0]['execution_state']=='NOT_APPLICABLE'
    assert execution_report([{'id':'1'}],['1'],[],{}, {'stats.ascan.1.skipped':1})[0]['execution_state']=='SKIPPED'


def test_deadline_is_derived_and_absolutely_bounded():
    assert completion_seconds()==3660
    assert FullBudget().overall_seconds==4380
    for kwargs in ({'active_seconds':5401},{'overall_seconds':7201},{'concurrency':5},{'requests_per_second':9}):
        with pytest.raises(ValueError):FullBudget(**kwargs)


def test_equivalent_url_values_collapse_but_parameters_remain_distinct():
    t=AuthorizedTarget('https://school.example/',True)
    r=candidate_index([t.target_url+'course?id=SECRET',t.target_url+'course?id=2',t.target_url+'course?course=3','https://other.example/'],t)
    assert r['raw_in_scope_urls']==3 and r['unique_endpoints']==2
    assert r['value_variants_collapsed']==1 and 'SECRET' not in json.dumps(r)


def test_body_free_metadata_with_structural_root_methods_and_stages():
    t=AuthorizedTarget('https://school.example/moodle/',True);calls=[]
    def call(c,k,n,**p):
        calls.append((c,k,n,p))
        if n=='numberOfMessages':return {'numberOfMessages':'2345'}
        assert n=='childNodes' and p['url']=='https://school.example/moodle'
        return {'childNodes':[{'uri':t.target_url+'course?id=SECRET','method':'POST','isLeaf':True,'hrefId':'4','responseBody':'SECRET'}]}
    r=session_index(call,t,lambda:None,spider={'fullResults':[{'url':t.target_url,'method':'GET','statusCode':'200','responseBody':'SECRET'}]})
    assert r['total_history_messages']==2345 and not r['metadata_truncated']
    assert r['methods_observed']==['POST'] and r['status_codes_observed']==[200]
    assert r['history_bodies_downloaded_for_export']==0 and 'SECRET' not in json.dumps(r)


def test_metadata_api_failure_is_honest_and_finite():
    t=AuthorizedTarget('https://school.example/',True)
    def call(c,k,n,**p):
        if n=='numberOfMessages':return {'numberOfMessages':'99'}
        raise RuntimeError('secret')
    r=session_index(call,t,lambda:None)
    assert r['metadata_truncated'] and r['total_history_messages']==99 and len(r['metadata_errors'])==1
    assert 'secret' not in json.dumps(r)


def controlled_run(tmp_path,change):
    t=AuthorizedTarget('https://school.example/',True);api=SyntheticAPI(None,t);original=api.call;clock=[0]
    def call(c,k,n,**kw):
        override=change(api,c,k,n,kw,original)
        return original(c,k,n,**kw) if override is None else override
    api.call=call
    def pause(seconds):clock[0]+=seconds
    result=FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),tmp_path,api_factory=lambda *a:api,clock=lambda:clock[0],pause=pause).run('fixture',t,FullBudget(active_seconds=2,client_seconds=2,ajax_seconds=2))
    return result,api


def test_stopped_status_100_but_actual_progress_19_is_not_complete(tmp_path):
    def change(api,c,k,n,kw,original):
        if c=='ascan' and n=='scans' and api.active:return {'scans':[{'id':'1','state':'FINISHED','progress':'19'}]}
    r,_=controlled_run(tmp_path,change)
    assert r['stages']['active']['status']=='PARTIAL'
    assert str(r['stages']['active']['progress'])=='19'
    assert r['stages']['active']['cancellation_reason']=='ACTIVE_STAGE_DEADLINE'
    assert r['stages']['passive']['queue_complete']


def test_natural_100_has_progress_counters_and_passive_drain(tmp_path):
    r,api=run(tmp_path)
    assert r['stages']['active']['status']=='COMPLETE'
    assert r['active_progress_samples'][-1]['state']=='FINISHED'
    assert r['actual_executed_rule_ids']==['40018']
    assert r['stages']['passive']['queue_complete'] and r['traffic']['total_history_messages']==2
    assert not any(n=='messages' for c,k,n,p in api.calls)


def test_owned_client_timeout_is_partial_not_unavailable_and_late_state_not_reused(tmp_path):
    def change(api,c,k,n,kw,original):
        if c=='clientSpider' and n=='status':return {'status':'20'}
    r,api=controlled_run(tmp_path,change);before=json.dumps(r,sort_keys=True)
    assert r['stages']['clientSpider']['status']=='PARTIAL'
    stops=[p for c,k,n,p in api.calls if c=='clientSpider' and n=='stop']
    assert stops and stops[0]['control_deadline']>2
    assert r['stages']['active']['status']=='COMPLETE'
    # A later daemon result has no mutable path into the returned snapshot.
    api.call=lambda *a,**kw:{'status':'100'}
    assert before==json.dumps(r,sort_keys=True)


def test_metadata_failure_preserves_active_passive_and_current_alert_provenance(tmp_path):
    r,_=run(tmp_path,('core','view','childNodes'))
    assert r['status']=='PARTIAL' and r['stages']['active']['status']=='COMPLETE'
    assert r['active_alerts']==2 and r['passive_alerts']==1
    assert r['stages']['passive']['queue_complete']
    assert all(f['assessment_id']=='fixture' for f in r['findings'])


def test_failed_fresh_session_rejects_old_history_before_collecting_alerts(tmp_path):
    t=AuthorizedTarget('https://school.example/',True);api=SyntheticAPI(None,t);original=api.call
    def call(c,k,n,**p):
        if n=='numberOfMessages':return {'numberOfMessages':'1'}  # Session reset failed/no-op.
        return original(c,k,n,**p)
    api.call=call
    r=FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),tmp_path,api_factory=lambda *a:api).run('new-assessment',t)
    assert r['status']=='FAILED' and r['findings']==[]
    assert any(n=='newSession' for c,k,n,p in api.calls)
    assert not any(n in ('alerts','scan') for c,k,n,p in api.calls)
