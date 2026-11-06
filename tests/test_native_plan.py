"""Source-backed native plan, finite budgets and valid response sharing; no traffic."""
from pathlib import Path
import sys
from unittest.mock import Mock
import pytest
import requests

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from posture.policy import PassivePolicy,TARGET
from posture.native_plan import (NativeAssessmentPolicy,request_plan,budget,DIRECT_GET_URLS,
    MAX_REQUESTS,MAX_DURATION_SECONDS,REDIRECT_ALLOWANCE,REDIRECT_ONLY_URLS)
from posture.native import NativeClient,Branch1CurrentProvider,NATIVE_PATHS
from posture.providers import ProviderFailure
from branch1 import external
from test_posture_demo_patch import synthetic_http


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*a,**kw):raise AssertionError('No network or model fitting')
    for name in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect',
                 'sklearn.svm.OneClassSVM.fit','xgboost.XGBClassifier.fit'):
        monkeypatch.setattr(name,deny)
    monkeypatch.delenv('POSTURE_ENABLE_EXISTING_ACTIVE',raising=False)
    monkeypatch.delenv('B1_ACTIVE_CONTEXT',raising=False)


def fingerprint(method,url,headers):return method,url,tuple(sorted(headers.items()))


def test_plan_is_exact_existing_check_dispatch_with_no_duplicates():
    s=synthetic_http();c=NativeClient(NativeAssessmentPolicy(),session=s);c.installer_allowed=True
    rows,_=external.assess(TARGET,'fixture',client=c)
    assert not any(r.finding_id=='EXTERNAL-ERROR' for r in rows)
    actual=[fingerprint(*call.args,call.kwargs.get('headers',{})) for call in s.request.call_args_list]
    planned={fingerprint(p['method'],p['url'],p['headers']) for p in request_plan()}
    # This fixture adds the existing installer language redirect; all source
    # check calls themselves account for exactly 28 unique request variants.
    assert planned <= set(actual)
    assert set(actual)-planned=={fingerprint('GET',TARGET+'admin/index.php?lang=en',{})}
    assert len(actual)==len(set(actual))==29
    assert len(planned)==28 and len(DIRECT_GET_URLS)==24
    assert all(r.to_dict()['check_result'] not in ('ERROR','NOT_TESTED') for r in rows)
    assert len(c.transcript)==s.request.call_count and c.cache_hits>0


def test_budget_is_derived_and_zap_bounds_are_unchanged():
    b=budget()
    assert b['planned_unique_requests']==28
    assert REDIRECT_ALLOWANCE==len(REDIRECT_ONLY_URLS)+4*3==15
    assert MAX_REQUESTS==28+15==43
    assert MAX_DURATION_SECONDS==MAX_REQUESTS*8+15+5==364
    assert PassivePolicy().max_requests==20 and PassivePolicy().max_duration_seconds==60
    for kw in ({'max_requests':44},{'max_duration_seconds':365},{'active_scan':True},{'off_origin':'ALLOW'}):
        with pytest.raises(ValueError):NativeAssessmentPolicy(**kw)
    assert {__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(u).path for u in DIRECT_GET_URLS} | {'/moodle/admin/index.php'}==NATIVE_PATHS


def test_full_current_provider_has_no_external_budget_exclusions(tmp_path):
    import shutil
    (tmp_path/'src/branch1').mkdir(parents=True)
    shutil.copyfile(ROOT/'src/branch1/advisories.json',tmp_path/'src/branch1/advisories.json')
    moodle=tmp_path/'moodle';moodle.mkdir();(moodle/'config.php').write_text('fixture')
    s=synthetic_http()
    collector=Mock(return_value=({'core':{},'settings':{},'filesystem':{},'runtime':{}},
                    {'collector_status':'NOT_AVAILABLE','reason_code':'FIXTURE_INTERNAL_UNAVAILABLE'}))
    p=Branch1CurrentProvider(tmp_path,lambda policy:NativeClient(policy,session=s),collector=collector,moodle_root=moodle)
    r=p.start_assessment('fixture',PassivePolicy())
    assert r['status']=='COMPLETE' and r['provenance']['moodle_module']['status']=='COMPLETE'
    assert r['provenance']['request_count']==29
    assert r['provenance']['assessment_budget']['max_requests']==43
    assert not r['provenance']['external_collection_errors_present']
    assert not {'REQUEST_BUDGET_EXCEEDED','ASSESSMENT_DEADLINE_EXCEEDED'} & set(r['provenance']['failure_codes'])
    assert {'CORS-001','CORS-002','HDR-009','EXPOSURE-006','EXPOSURE-008','AUTH-002'} <= {f['finding_id'] for f in r['findings']}


def test_redirect_hops_share_completed_responses_but_not_header_variants():
    s=synthetic_http();original=s.request.side_effect
    def send(method,url,**kw):
        if url==TARGET:
            r=requests.Response();r.url=url;r.status_code=303;r.headers['Location']=TARGET+'my/'
            r._content=b'';r._content_consumed=True;return r
        return original(method,url,**kw)
    s.request.side_effect=send
    c=NativeClient(NativeAssessmentPolicy(),session=s)
    assert c.get(TARGET).status_code==200
    c.get(TARGET+'login/index.php');c.get(TARGET+'my/');c.get(TARGET)
    assert s.request.call_count==3
    c.get(TARGET+'login/index.php',headers={'Origin':'https://scanner-test.invalid'})
    assert s.request.call_count==4
    s2=synthetic_http();c2=NativeClient(NativeAssessmentPolicy(),session=s2);c2.get(TARGET+'login/index.php')
    assert s2.request.call_count==1  # A new client has no previous response cache.


def test_real_moodle_admin_cache_transition_completes_without_broad_query_permission():
    s=synthetic_http();original=s.request.side_effect
    def send(method,url,**kw):
        if url in (TARGET+'admin/',TARGET+'admin/index.php?lang=en',TARGET+'admin/index.php?cache=1'):
            r=requests.Response();r.url=url;r.status_code=303
            r.headers['Location']=TARGET+('login/index.php' if url.endswith('cache=1') else 'admin/index.php?cache=1')
            r._content=b'';r._content_consumed=True;return r
        return original(method,url,**kw)
    s.request.side_effect=send
    c=NativeClient(NativeAssessmentPolicy(),session=s);c.installer_allowed=True
    rows,_=external.assess(TARGET,'fixture',client=c)
    assert not any(r.to_dict()['check_result'] in ('ERROR','NOT_TESTED') for r in rows)
    assert next(r for r in rows if r.finding_id=='ACCESS-002').to_dict()['check_result']=='PASS'
    assert s.request.call_count==30 and c.allowed_url(TARGET+'admin/index.php?cache=1')
    for query in ('cache=0','cache=1&sesskey=secret','cache=1&upgradekeyhash=secret','cache=2','lang=xx'):
        assert not c.allowed_url(TARGET+'admin/index.php?'+query)


def test_failures_deadlines_and_off_origin_redirects_still_fail_closed():
    s=synthetic_http();s.request.side_effect=requests.ReadTimeout('secret')
    c=NativeClient(NativeAssessmentPolicy(max_requests=1),session=s)
    with pytest.raises(ProviderFailure,match='READ_TIMEOUT'):c.get(TARGET)
    with pytest.raises(ProviderFailure,match='REQUEST_BUDGET_EXCEEDED'):c.get(TARGET)
    assert s.request.call_count==1
    c=NativeClient(NativeAssessmentPolicy(),session=synthetic_http(),clock=lambda:0)
    c.get(TARGET);c.clock=lambda:365
    with pytest.raises(ProviderFailure,match='ASSESSMENT_DEADLINE_EXCEEDED'):c.get(TARGET)
    s=synthetic_http();r=requests.Response();r.url=TARGET;r.status_code=303;r.headers['Location']='https://evil.test/'
    r._content=b'';r._content_consumed=True;s.request.side_effect=lambda *a,**k:r
    c=NativeClient(NativeAssessmentPolicy(),session=s)
    with pytest.raises(ProviderFailure,match='SCOPE_INTEGRITY_FAILURE'):c.get(TARGET)
    assert s.request.call_count==1
