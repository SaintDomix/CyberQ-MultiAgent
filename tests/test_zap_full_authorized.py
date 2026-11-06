"""Executable synthetic ZAP state machine. No real target traffic/model fitting."""
import copy
import json
import sys
from pathlib import Path
from unittest.mock import Mock
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from posture.target import AuthorizedTarget,sanitized_url,endpoint
from posture.zap_full import FullZapProvider,FullBudget,Forms,rule_progress
from posture.zap_full_api import FullZapAPI
from posture.zap_normalize import normalize_alerts
from posture.providers import ZapAPI
from posture.model import deduplicate
from posture.orchestration import PostureAssessmentOrchestrator
from fusion.pipeline import assemble
from demo.backend.app import create_app
from test_operational_posture import NativeFixture,CATALOG,native_row,AT,application,request


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*a,**kw):raise AssertionError('No external network or fitting')
    for name in ('socket.socket.connect','socket.create_connection','sklearn.svm.OneClassSVM.fit','xgboost.XGBClassifier.fit'):
        monkeypatch.setattr(name,deny)
    monkeypatch.delenv('B1_ACTIVE_CONTEXT',raising=False)


def alert(plugin='40018',**extra):
    return {'id':'20','pluginId':plugin,'alert':'SQL Injection' if plugin=='40018' else 'Cross Site Scripting',
        'riskcode':'3','confidence':'2','cweid':'89' if plugin=='40018' else '79',
        'url':'https://school.example/course/view.php?id=SECRET','param':'id','method':'GET',
        'attack':'password=SECRET','evidence':'Cookie: SECRET','solution':'Review application input handling.',**extra}


class SyntheticAPI:
    def __init__(self,*a):
        self.calls=[];self.mode='safe';self.active=False;self.enabled=[];self.owned_scans={}
        self.context_name=None;self.policy_name=None;self.target=a[-1] if a else AuthorizedTarget('https://school.example/',True)
    def call(self,c,k,n,**p):
        self.calls.append((c,k,n,p));base=self.target.target_url
        if n=='version':return {'version':'fixture-2.17.0'}
        if n=='installedAddons':return {'installedAddons':[{'id':x,'version':'1'} for x in ('ascanrules','pscan','spider','client','spiderAjax','openapi','graphql','soap','postman','fuzz','bruteforce','automation','sequence','authhelper')]}
        if n=='scanners':
            if c=='pscan':return {'scanners':[{'id':'10038','name':'CSP','enabled':'true'}]}
            return {'scanners':[{'id':i,'name':'Fixture rule '+i,'status':'release','enabled':str(i in self.enabled).lower()} for i in ('0','40018','40012','30001')]}
        if n=='enableScanners':self.enabled=p['ids'].split(',')
        if n=='scans':return {'scans':[{'id':'1','state':'FINISHED','progress':'100','reqCount':'2','alertCount':'2'}] if c=='ascan' and self.active else []}
        if n=='mode':return {'mode':self.mode}
        if n=='setMode':self.mode=p['mode']
        if n=='numberOfMessages':return {'numberOfMessages':'2' if self.active else '0'}
        if n=='newSession':self.active=False
        if n=='newContext':return {'contextId':'1'}
        if n=='includedTechnologyList':return {'technologyList':['PHP','Apache']}
        if n.startswith('option'):return {n:'false' if any(s in n for s in ('PostForm','RandomInputs','Persist','Logout','Process','Handle','ParseRobots','ParseSitemap')) else '1'}
        if n=='status':return {'status':'stopped' if c=='ajaxSpider' else '100'}
        if n=='scan':
            assert self.mode=='protect'
            if c=='ascan':
                assert self.enabled and p['contextId']=='1' and 'url' not in p;self.active=True
            else:assert p.get('url')==base
            return {'scan':'1','scanId':'1'}
        if n=='recordsToScan':return {'recordsToScan':'0'}
        if n=='domainsAlwaysInScope':return {'domainsAlwaysInScope':[]}
        if n in ('urls','results'):return {n:[base,base+'course/view.php?id=1',base+'course/view.php?id=2','https://other.example/']}
        if n=='fullResults':return {'fullResults':[]}
        if n=='alerts':
            return {'alerts':[alert('10038',id='1',cweid='693',alert='Missing CSP',riskcode='2',url=base,param='')]+([alert(url=base+'course/view.php?id=1'),alert('40012',id='21',url=base+'course/view.php?id=2')] if self.active else [])}
        if n=='messagesIds':return {'messagesIds':['10','11']}
        if n=='alertsIds':return {'alertsIds':['20','21']}
        if n=='scanProgress':return {'scanProgress':[{'HostProcess':[{'Plugin':['SQL Injection','40018','release','Complete','50','2','1']}]}]}
        if n=='stats':return {'stats':{'stats.ascan.40018.started':'1' if self.active else '0'}}
        if n=='childNodes':return {'childNodes':[{'method':'GET','uri':base,'hrefId':'10','isLeaf':True}]}
        if n=='messages':return {'messages':[{'id':str(i),'requestHeader':'GET '+base+'course/view.php?id=SECRET HTTP/1.1\r\nCookie: SECRET',
            'responseHeader':'HTTP/1.1 200 OK\r\nSet-Cookie: SECRET','responseBody':'<form action="login" method="post"><input name="password" value="SECRET"></form>'} for i in (10,11)][int(p['start']):int(p['start'])+int(p['count'])]}
        return {'Result':'OK'}
    def close(self):pass


def run(tmp_path,fail=None,target=None):
    target=target or AuthorizedTarget('https://school.example/',True)
    api=SyntheticAPI(None,target)
    if fail:
        original=api.call
        def call(c,k,n,**p):
            if (c,k,n)==fail:raise RuntimeError('password=SECRET')
            return original(c,k,n,**p)
        api.call=call
    provider=FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),tmp_path,api_factory=lambda *a:api,pause=lambda x:None)
    return provider.run('fixture',target),api


def test_realistic_synthetic_full_execution_has_enabled_rules_and_traffic(tmp_path):
    r,api=run(tmp_path)
    assert r['status']=='COMPLETE',r
    assert r['policy']['enabled_ids']==['0','40012','40018']
    assert r['stages']['active']['request_message_count']==2
    assert r['active_alerts']==2 and r['passive_alerts']==1
    assert r['stages']['spider']['status']=='COMPLETE'
    assert r['inventory']['capabilities']['active_scan']['executed']
    assert r['final_zap_mode']=='safe' and not r['cleanup_errors']
    assert r['unique_endpoints']==2 and r['parameter_count']==1
    assert all(f['assessment_id']=='fixture' for f in r['findings'])
    assert 'SECRET' not in json.dumps(r)


@pytest.mark.parametrize('url',['http://192.168.226.132/moodle/','https://moodle.example-university.kz/','https://school.example/lms/'])
def test_another_authorized_platform_needs_configuration_not_source_change(url):
    t=AuthorizedTarget(url,True)
    assert t.target_url==url and t.contains(url+'index.php?id=2')
    assert not t.contains('https://google.com/')
    assert not t.contains(url+'../escape')


@pytest.mark.parametrize('url',['http://127.0.0.1:8081/','http://localhost./','http://169.254.169.254/','http://user:pass@host/','http://host/?token=SECRET','http://host/app/../','ftp://school.example/'])
def test_unauthorized_or_control_targets_rejected(url):
    with pytest.raises(ValueError):AuthorizedTarget(url,True)
    with pytest.raises(ValueError):AuthorizedTarget('https://school.example/',False)


def test_endpoint_identity_discards_values_but_retains_parameter_identity():
    assert endpoint('https://school.example/path?id=1')==endpoint('https://school.example/path?id=2')
    assert endpoint('https://school.example/path?course=1')!=endpoint('https://school.example/path?id=1')
    assert 'SECRET' not in sanitized_url('https://school.example/path?token=SECRET&id=SECRET')


def test_zap_only_active_finding_is_fail_even_without_cqi_mapping():
    t=AuthorizedTarget('https://school.example/',True)
    rows,_=normalize_alerts([alert()],t,'fixture',AT,['20'],'1')
    assert rows[0]['check_result']=='FAIL' and rows[0]['severity']=='HIGH'
    assert rows[0]['evidence_source']=='ZAP_ACTIVE' and rows[0]['cqi_mapping']=='UNMAPPED'
    assert rows[0]['source_confidence']=='2' and rows[0]['confirmation_status']=='NOT_CONFIRMED'
    assert rows[0]['zap_details']['zap_confidence']=='Medium'
    assert 'SECRET' not in json.dumps(rows)
    art=assemble(rows,[],'fixture','none',as_of=AT)
    assert art['cqi']['cqi'] is None  # Visible finding, no invented score.


def test_sql_xss_same_parameter_distinct_and_same_sql_values_deduplicated():
    t=AuthorizedTarget('https://school.example/',True)
    rows,_=normalize_alerts([alert(),alert(id='22',url='https://school.example/course/view.php?id=2'),alert('40012',id='21')],t,'fixture',AT,['20','21','22'],'1')
    canonical=deduplicate(rows,t.target_url)
    assert len(canonical)==2 and sorted(r['member_count'] for r in canonical)==[1,2]


def test_native_passive_active_corroboration_has_one_maximum_penalty():
    t=AuthorizedTarget('http://192.168.226.132/moodle/',True)
    alerts=[alert('10038',id='1',cweid='693',url=t.target_url,param='',riskcode='2'),
            alert('10038',id='2',cweid='693',url=t.target_url,param='',riskcode='2')]
    z,_=normalize_alerts(alerts,t,'fixture',AT,['2'],'1')
    n=native_row();rows=deduplicate([n,*z])
    rows[0]['active_validation']={'status':'CONFIRMED','score_effect':'NONE'}
    before=assemble(deduplicate([n]),[],'fixture','none',as_of=AT)
    after=assemble(rows,[],'fixture','none',as_of=AT)
    assert len(rows)==1 and before['cqi']['cqi']==after['cqi']['cqi']
    assert set(rows[0]['evidence_sources'])=={'NATIVE_POSTURE','ZAP_PASSIVE','ZAP_ACTIVE'}


def test_offtarget_alert_is_never_a_target_finding():
    t=AuthorizedTarget('https://school.example/',True)
    rows,excluded=normalize_alerts([alert(url='https://other.example/')],t,'fixture',AT)
    assert not rows and excluded==1


def test_scan_failure_keeps_completed_passive_findings(tmp_path):
    r,api=run(tmp_path,('ascan','action','scan'))
    assert r['status']=='PARTIAL' and r['findings']
    assert all(f['evidence_source']=='ZAP_PASSIVE' for f in r['findings'])
    assert r['final_zap_mode']=='safe' and 'SECRET' not in json.dumps(r)


def test_optional_client_failure_does_not_block_active(tmp_path):
    r,api=run(tmp_path,('clientSpider','action','scan'))
    assert r['stages']['clientSpider']['status']=='NOT_AVAILABLE'
    assert r['stages']['active']['status']=='COMPLETE'


def test_capabilities_do_not_equate_installed_with_executed(tmp_path):
    r,_=run(tmp_path);caps=r['inventory']['capabilities']
    assert caps['fuzzer']['installed'] and not caps['fuzzer']['executed']
    assert caps['openapi']['installed'] and caps['openapi']['integrated'] and not caps['openapi']['executed']
    assert caps['forced_browse']['installed'] and not caps['forced_browse']['integrated']
    assert not caps['authentication']['executed'] and r['authentication_status']=='NOT_CONFIGURED'


def test_full_api_denies_scope_expansion_attack_mode_and_unowned_stop(monkeypatch):
    t=AuthorizedTarget('https://school.example/',True)
    api=FullZapAPI(ZapAPI('http://127.0.0.1:8081','secret'),t)
    transport=Mock(return_value={'scan':'1'})
    monkeypatch.setattr(api.transport,'_fetch',transport)
    api.context_name='owned';api.context_id='1';api.policy_name='owned-policy'
    for c,n,p in [('core','setMode',{'mode':'attack'}),('core','accessUrl',{'url':'https://other.example/','followRedirects':'false'}),
        ('context','includeInContext',{'contextName':'owned','regex':'.*'}),('ascan','stop',{'scanId':'22'}),
        ('ascan','scan',{'url':t.target_url,'inScopeOnly':'true','scanPolicyName':'owned-policy','contextId':'2'})]:
        with pytest.raises(ValueError):api.call(c,'action',n,**p)
    transport.assert_not_called()
    api.call('core','action','setMode',mode='protect')
    api.call('ascan','action','scan',contextId='1',inScopeOnly='true',scanPolicyName='owned-policy',recurse='true')


def test_api_error_enum_is_retained_without_secret_message():
    from posture.providers import ProviderFailure
    s=Mock();r=Mock();r.__enter__=Mock(return_value=r);r.__exit__=Mock(return_value=False)
    r.status_code=400;r.iter_content.return_value=[b'{"code":"mode_violation","message":"password=SECRET"}']
    s.get.return_value=r
    api=ZapAPI('http://127.0.0.1:8081','SECRET_KEY',session=s)
    with pytest.raises(ProviderFailure) as caught:api.call('core','view','mode')
    assert caught.value.cause_code=='ZAP_MODE_VIOLATION'
    assert 'SECRET' not in str(caught.value)


def test_protected_mode_is_verified_again_at_active_dispatch(tmp_path):
    t=AuthorizedTarget('https://school.example/',True);api=SyntheticAPI(None,t);original=api.call
    def call(c,k,n,**p):
        if c=='ajaxSpider' and n=='status' and api.mode=='protect':api.mode='safe'
        return original(c,k,n,**p)
    api.call=call
    r=FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),tmp_path,api_factory=lambda *a:api).run('fixture',t)
    assert r['stages']['active']['status']=='COMPLETE'
    assert r['mode_before_active']=='safe'


def test_explicit_bounds_and_finite_settings(tmp_path):
    with pytest.raises(ValueError):FullBudget(active_seconds=999999)
    r,api=run(tmp_path)
    calls=api.calls
    assert any(c[:3]==('ascan','action','setOptionMaxScanDurationInMins') and c[3]['Integer']=='62' for c in calls)
    assert any(c[:3]==('network','action','addRateLimitRule') and c[3]['requestsPerSecond']=='8' for c in calls)
    assert r['policy']['request_ceiling'] is None


def test_form_metadata_never_retains_credentials_or_values():
    t=AuthorizedTarget('https://school.example/',True);p=Forms(t,t.target_url)
    p.feed('<form action="login" method="POST"><input name="password" value="SECRET"><input name="id" value="SECRET"></form>')
    assert 'SECRET' not in repr(p.forms) and '[withheld]' in repr(p.forms)


def test_history_uses_single_record_pages_and_discloses_oversized_omission(tmp_path):
    from posture.providers import ProviderFailure
    t=AuthorizedTarget('https://school.example/',True);api=SyntheticAPI(None,t);api.active=True
    original=api.call
    def call(c,k,n,**p):
        if n=='messages':
            assert p['count']=='1'
            if p['start']=='0':raise ProviderFailure('ZAP_API_UNAVAILABLE','RESPONSE_SIZE_LIMIT')
        return original(c,k,n,**p)
    provider=FullZapProvider(Mock(),tmp_path)
    r=provider._history(call,t,['10','11'],lambda:None)
    assert r['exported_target_messages']==1
    assert r['omitted_metadata_records']==[{'history_index':0,'reason':'SINGLE_RECORD_EXCEEDS_CONTROL_RESPONSE_CAP'}]


def test_interrupted_metadata_retains_prior_records_and_marks_partial(tmp_path):
    from posture.providers import ProviderFailure
    t=AuthorizedTarget('https://school.example/',True);api=SyntheticAPI(None,t);api.active=True;original=api.call
    def call(c,k,n,**p):
        if n=='messages' and p['start']=='1':raise ProviderFailure('ZAP_API_UNAVAILABLE')
        return original(c,k,n,**p)
    r=FullZapProvider(Mock(),tmp_path)._history(call,t,['10','11'],lambda:None)
    assert r['exported_target_messages']==1 and r['metadata_truncated'] is True
    assert r['omitted_metadata_records'][0]['history_index']==1


def test_actual_rule_execution_requires_request_counts_not_enabled_flag():
    r=rule_progress({'scanProgress':[{'id':'school.example:443'}, {'HostProcess':[{'Plugin':[{'id':'40018'},{'reqCount':'12'},{'status':'Complete'}]},{'Plugin':[{'id':'40012'},{'reqCount':'0'},{'status':'Pending'}]}]}]})
    assert r==[{'id':'40012','request_count':0,'status':'Pending'},{'id':'40018','request_count':12,'status':'Complete'}]


def test_timeout_cancels_only_owned_scan_and_keeps_passive(tmp_path):
    t=AuthorizedTarget('https://school.example/',True);api=SyntheticAPI(None,t)
    original=api.call;clock=[0]
    def call(c,k,n,**kw):
        if c=='ascan' and n=='status':return {'status':'10'}
        return original(c,k,n,**kw)
    api.call=call
    def pause(seconds):clock[0]+=seconds
    p=FullZapProvider(Mock(owned_ephemeral=True,api=Mock()),tmp_path,api_factory=lambda *a:api,clock=lambda:clock[0],pause=pause)
    r=p.run('fixture',t,budget=FullBudget(active_seconds=1))
    assert r['stages']['active']['status']=='PARTIAL'
    assert r['stages']['active']['cancellation_reason']=='ACTIVE_STAGE_DEADLINE'
    assert any(c[:3]==('ascan','action','stop') and c[3]['scanId']=='1' for c in api.calls)


class FullFixture:
    def __init__(self,provider,root):self.root=root
    def run(self,aid,target,**kw):
        r,_=run(self.root,target=target)
        r['assessment_id']=aid
        r['findings']=normalize_alerts([alert(url=target.target_url+'course/view.php?id=2')],target,aid,AT,['20'],'1')[0]
        return r


def test_two_full_assessments_are_fresh_and_first_snapshot_preserved(tmp_path):
    native=NativeFixture();engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=native,full_provider_factory=FullFixture)
    a=engine.start(mode='FULL_AUTHORIZED',authorized=True,target_url='https://school.example/',background=False)
    assert a['status']=='PARTIAL' and any(r['evidence_source']=='ZAP_ACTIVE' for r in a['findings'])
    path=engine.location(a['assessment_id']);before={p.name:p.read_bytes() for p in path.iterdir()}
    b=engine.start(mode='FULL_AUTHORIZED',authorized=True,target_url='https://school.example/',background=False)
    assert a['assessment_id']!=b['assessment_id']
    assert before=={p.name:p.read_bytes() for p in path.iterdir()}
    assert all(r['assessment_id']==b['assessment_id'] for r in b['findings'])
    assert native.calls==0  # No Moodle-lab collector accidentally run against another target.


def test_full_api_primary_findings_include_zap_only_security_findings(application):
    engine=application.posture_service;engine.full_provider_factory=FullFixture
    app=create_app(application=application,config=application.config)
    start=engine.start
    engine.start=lambda *a,**kw:start(*a,**kw,background=False)
    response=request(app,'/api/posture/assessments','POST',{'mode':'FULL_AUTHORIZED','target_url':'https://school.example/','authorized':True},{'X-Product-Control':'1'})
    assert response.status_code==202,response.text
    response=request(app,'/api/posture/findings?view=current&limit=200')
    item=next(r for r in response.json()['items'] if r['source']=='ZAP_ACTIVE')
    assert item['status']=='FAIL' and item['cqi_mapping']=='UNMAPPED'
    assert item['zap_details']['zap_risk']=='HIGH'
    assert 'SECRET' not in response.text


def test_full_failure_preserves_native_and_repository_active(tmp_path):
    class Failed:
        def __init__(self,*a):pass
        def run(self,*a,**kw):raise RuntimeError('SECRET')
    engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativeFixture(),full_provider_factory=Failed)
    r=engine.start(mode='FULL_AUTHORIZED',authorized=True,background=False)
    assert r['provider_statuses']['native']=='COMPLETE'
    assert r['active_validation_status']=='COMPLETE'
    assert r['status']=='PARTIAL' and 'SECRET' not in json.dumps(r)


def test_read_view_recovers_missing_counts_without_modifying_snapshot(application):
    class MissingCounts(FullFixture):
        def run(self,*a,**kw):
            r=super().run(*a,**kw)
            r.pop('active_alerts',None);r.pop('passive_alerts',None)
            r['status']='PARTIAL';r['error_code']='METADATA_EXPORT_FAILED'
            return r
    engine=application.posture_service;engine.full_provider_factory=MissingCounts
    job=engine.start(mode='FULL_AUTHORIZED',target_url='https://school.example/',authorized=True,background=False)
    path=engine.location(job['assessment_id']);before={p.name:p.read_bytes() for p in path.iterdir()}
    app=create_app(application=application,config=application.config)
    data=request(app,'/api/posture/assessments/'+job['assessment_id']).json()
    assert data['zap_execution']['active_alerts']==1
    assert data['zap_execution']['error_code']=='METADATA_EXPORT_FAILED'
    assert before=={p.name:p.read_bytes() for p in path.iterdir()}
