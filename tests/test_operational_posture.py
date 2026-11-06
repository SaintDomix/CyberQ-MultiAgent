"""Synthetic HTTP/ZAP fixtures only; immutable research sources are read-only."""
import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sys
from unittest.mock import Mock
import httpx
import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
from posture.policy import PassivePolicy, validate_target, scoped, TARGET, PAGES
from posture.providers import ExternalScannerProvider, StrictClient, NativePostureProvider, ZapPassiveProvider, ZapAPI, zap_findings
from posture.model import row, deduplicate, not_reevaluated
from posture.orchestration import PostureAssessmentOrchestrator
from fusion.pipeline import assemble
from demo.backend.services import Application
from demo.backend.config import Config
from demo.backend.app import create_app
from behavioral_runtime.package import verify

AT = '2026-01-01T00:00:00+00:00'
CATALOG = [{'finding_id': 'HDR-002', 'category': 'Security Headers', 'finding_type': 'CSP', 'check_result': 'FAIL'},
           {'finding_id': 'PATCH-001', 'category': 'Patch & Vulnerability Intelligence', 'finding_type': 'Patch state', 'check_result': 'FAIL'}]


def response(status=200, headers=None):
    r = requests.Response(); r.status_code = status; r.url = TARGET
    r.headers.update(headers or {}); r._content = b'fixture login token=DO_NOT_PERSIST'; r._content_consumed = True
    return r


def session(responses=None):
    s = Mock(); s.headers = {}; s.proxies = {}
    s.request.side_effect = responses if responses is not None else lambda *a, **kw: response(headers={
        'Set-Cookie': 'MoodleSession=DO_NOT_PERSIST; Path=/moodle/; HttpOnly; SameSite=Lax',
        'Server': 'Apache/2.4.0'})
    return s


def native_row(aid='fixture'):
    return row('HDR-002', 'Security Headers', 'CSP', 'FAIL', 'MEDIUM', 'CONFIRMED', 'NATIVE_POSTURE', aid, AT,
               weakness_key='HDR-002', evidence={'header': 'absent'}, recommendation='Review CSP')


class NativeFixture(ExternalScannerProvider):
    provider_id = 'native'; provider_name = 'Fixture native'; calls = 0
    def availability(self): return {'status': 'AVAILABLE', 'provider_id': 'native'}
    def start_assessment(self, aid, policy, target_id='moodle-local'):
        self.calls += 1
        return {'provider_id': 'native', 'version': 'fixture', 'status': 'COMPLETE',
                'findings': [native_row(aid)], 'provenance': {'fresh_execution': True}}


class ZapFixtureAPI:
    origin = 'http://127.0.0.1:8081'
    def __init__(self, alerts=None): self.calls = []; self.urls_reads = 0; self.alerts = alerts or []
    def call(self, component, kind, name, **kw):
        self.calls.append((component, kind, name, kw))
        if name == 'version': return {'version': 'fixture-2.17'}
        if name == 'newSession':
            self.urls_reads = 0
            return {'Result': 'OK'}
        if name == 'urls':
            self.urls_reads += 1
            return {'urls': [] if self.urls_reads == 1 else [TARGET + p for p in PAGES]}
        if name == 'scans': return {'scans': []}
        if name == 'mode': return {'mode': 'safe'}
        if name == 'recordsToScan': return {'recordsToScan': '0'}
        if name == 'numberOfMessages': return {'numberOfMessages': '0' if self.urls_reads < 2 else '5'}
        if name == 'messages':
            return {'messages': [] if self.urls_reads < 2 else [
                {'id': str(i+1), 'type': '1', 'requestHeader': f'GET {TARGET+p} HTTP/1.1\r\nHost: 192.168.226.132\r\nUser-Agent: Moodle-Operational-Posture/2.0\r\n\r\n',
                 'responseHeader': 'HTTP/1.1 200 OK\r\n\r\n', 'requestBody': '', 'responseBody': 'fixture'}
                for i,p in enumerate(PAGES)]}
        if name == 'alerts': return {'alerts': [] if kw.get('count') == '1' else self.alerts}
        return {'Result': 'OK'}


def alert(plugin='10038', **kw):
    return {'pluginId': plugin, 'riskcode': '2', 'confidence': '2', 'url': TARGET,
            'id': '1', 'param': '', 'evidence': 'MoodleSession=DO_NOT_PERSIST',
            'attack': 'DO_NOT_PERSIST', 'otherInfo': 'password=DO_NOT_PERSIST', **kw}


@pytest.fixture(autouse=True)
def no_network_or_fit(monkeypatch):
    def forbidden(*a, **kw): raise AssertionError('No network or fitting in operational posture tests')
    for n in ('socket.create_connection', 'socket.socket.connect', 'socket.getaddrinfo',
              'sklearn.svm.OneClassSVM.fit', 'sklearn.ensemble.IsolationForest.fit', 'xgboost.XGBClassifier.fit'):
        monkeypatch.setattr(n, forbidden)


@pytest.mark.parametrize('kwargs', [{'mode': 'ACTIVE'}, {'active_scan': True}, {'max_requests': 21},
    {'max_depth': 1}, {'max_duration_seconds': 61}, {'off_origin': 'ALLOW'}, {'state_changing_actions': 'ALLOW'}])
def test_unsafe_policy_rejected(kwargs):
    with pytest.raises(ValueError): PassivePolicy(**kwargs)


@pytest.mark.parametrize('url', ['http://evil.test/moodle/', 'http://192.168.226.133/moodle/',
    'https://192.168.226.132/moodle/', 'http://192.168.226.132/moodle/../config.php',
    TARGET + '%252e%252e/config.php', TARGET + '?token=DO_NOT_PERSIST', 'http://u:p@192.168.226.132/moodle/'])
def test_scope_denies_off_origin_encoded_traversal_and_secrets(url):
    assert not scoped(url)
    s = session(); c = StrictClient(PassivePolicy(), session=s)
    with pytest.raises(requests.RequestException): c.get(url)
    s.request.assert_not_called()


def test_unauthorized_profile_denied():
    for args in [('internet', TARGET, True), ('moodle-local', TARGET, False)]:
        with pytest.raises(ValueError): validate_target(*args)


def test_safe_native_rule_execution_is_fresh_and_secret_free():
    s = session(); provider = NativePostureProvider(lambda p: StrictClient(p, session=s))
    result = provider.start_assessment('fixture', PassivePolicy())
    assert result['status'] == 'COMPLETE'; assert s.request.call_count > 1
    assert {'TLS-001', 'HDR-002', 'COOKIE-MoodleSession-SECURE', 'CORS-001', 'CORS-002'} <= {r['finding_id'] for r in result['findings']}
    assert all(call.args[0] in ('GET', 'OPTIONS') and call.kwargs['allow_redirects'] is False for call in s.request.call_args_list)
    assert all(scoped(call.args[1]) for call in s.request.call_args_list)
    assert 'DO_NOT_PERSIST' not in json.dumps(result)
    assert all(f['assessment_id'] == 'fixture' and f['created_at'] for f in result['findings'])
    assert any(f['operational_status'] == 'NOT_REEVALUATED' for f in result['findings'])


def test_redirect_outside_target_is_not_sent():
    s = session([response(303, {'Location': 'https://evil.test/'})]); c = StrictClient(PassivePolicy(), session=s)
    with pytest.raises(requests.RequestException): c.get(TARGET)
    assert s.request.call_count == 1


def test_same_origin_state_changing_redirect_is_not_sent():
    s = session([response(303, {'Location': TARGET+'login/logout.php'})]); c = StrictClient(PassivePolicy(), session=s)
    with pytest.raises(requests.RequestException): c.get(TARGET)
    assert s.request.call_count == 1


def test_request_budget_includes_failed_sends_and_deadline():
    s = session([requests.ConnectionError('secret in exception')]); c = StrictClient(PassivePolicy(max_requests=1), session=s)
    with pytest.raises(requests.RequestException): c.get(TARGET)
    with pytest.raises(requests.RequestException): c.get(TARGET)
    assert s.request.call_count == 1 and 'secret' not in json.dumps(c.transcript)
    clock = Mock(side_effect=[0, 61]); c = StrictClient(PassivePolicy(), session=session(), clock=clock)
    with pytest.raises(requests.RequestException): c.get(TARGET)


def test_response_size_bound():
    c = StrictClient(PassivePolicy(max_response_bytes=5), session=session())
    with pytest.raises(requests.RequestException): c.get(TARGET)


def test_passive_only_api_has_no_active_or_spider_action():
    api = ZapAPI('http://127.0.0.1:8081', 'synthetic-secret', session=Mock())
    for endpoint, kw in [(('ascan', 'action', 'scan'), {}), (('spider', 'action', 'scan'), {}),
                         (('core', 'action', 'setMode'), {'mode': 'attack'}), (('core', 'action', 'sendRequest'), {})]:
        with pytest.raises(ValueError): api.call(*endpoint, **kw)
    for origin in ('http://evil.test:8081', 'http://127.0.0.1:8081/?token=x', 'http://u:p@127.0.0.1:8081'):
        with pytest.raises(ValueError): ZapAPI(origin, 'fixture')


def test_zap_unavailable_is_explicit(monkeypatch):
    monkeypatch.delenv('POSTURE_ZAP_OWNED_EPHEMERAL', raising=False)
    zap = ZapPassiveProvider()
    assert zap.availability()['runtime'] == 'UNAVAILABLE_PENDING_INSTALL'
    assert zap.start_assessment('fixture', PassivePolicy())['findings'] == []
    assert zap.assessment_status('fixture') == 'UNAVAILABLE'


def test_invalid_zap_configuration_does_not_break_native(monkeypatch, tmp_path):
    monkeypatch.setenv('POSTURE_ZAP_OWNED_EPHEMERAL', '1')
    monkeypatch.setenv('POSTURE_ZAP_API_KEY', 'synthetic-secret')
    monkeypatch.setenv('POSTURE_ZAP_API_ORIGIN', 'http://evil.test:8081')
    zap = ZapPassiveProvider()
    assert zap.availability()['runtime'] == 'INVALID_LOOPBACK_CONFIGURATION'
    engine = PostureAssessmentOrchestrator(tmp_path, CATALOG, native=NativeFixture(), zap=zap)
    job = engine.start(mode='PASSIVE_BASELINE',background=False)
    assert job['provider_statuses'] == {'native':'COMPLETE','zap':'UNAVAILABLE'}


def test_zap_passive_fixture_uses_safe_mode_fixed_gets_queue_and_sanitized_results():
    api = ZapFixtureAPI([alert()]); s = session()
    zap = ZapPassiveProvider(api, lambda p, proxy: StrictClient(p, proxy=proxy, session=s))
    result = zap.start_assessment('fixture', PassivePolicy())
    assert result['status'] == 'COMPLETE' and result['passive_queue_complete']
    assert result['raw_alert_count'] == 1 and s.request.call_count == 5
    assert all(c.kwargs['allow_redirects'] is False for c in s.request.call_args_list)
    assert all(c.args[0] == 'GET' for c in s.request.call_args_list)
    assert ('core', 'action', 'setMode', {'mode': 'safe'}) in api.calls
    assert not any(c[0] in ('ascan', 'spider') and c[1] == 'action' for c in api.calls)
    assert 'DO_NOT_PERSIST' not in json.dumps(result)
    f = result['findings'][0]; assert f['source_severity'] == '2' and f['source_confidence'] == '2'
    assert f['normalized_severity'] == 'MEDIUM' and f['confirmation_status'] == 'NOT_CONFIRMED'


def test_shared_zap_session_and_queue_timeout_fail_closed():
    api = ZapFixtureAPI(); original = api.call
    api.call = lambda c,k,n,**kw: {'urls': [TARGET]} if n == 'urls' else original(c,k,n,**kw)
    z = ZapPassiveProvider(api); assert z.start_assessment('fixture', PassivePolicy())['status'] == 'FAILED'
    api = ZapFixtureAPI(); original = api.call
    api.call = lambda c,k,n,**kw: {'recordsToScan': '1'} if n == 'recordsToScan' else original(c,k,n,**kw)
    clock = Mock(side_effect=[0, 0, 0, 0, 0, 0, 61])
    z = ZapPassiveProvider(api, lambda p,proxy: StrictClient(p,session=session()), clock=clock)
    assert z.start_assessment('fixture', PassivePolicy())['status'] == 'FAILED'


def test_false_positive_info_unmapped_and_off_scope_alerts():
    rows, safe, excluded = zap_findings([alert(confidence='0'), alert('999999'),
        alert('10015', riskcode='0'), alert(url='https://evil.test/')], 'fixture', AT)
    assert rows[0]['check_result'] == 'DISMISSED' and rows[0]['confirmation_status'] == 'FALSE_POSITIVE'
    assert rows[1]['category'] == 'UNMAPPED' and rows[1]['check_result'] == 'NOT_TESTED'
    assert rows[2]['severity'] == 'INFO' and excluded == 1
    assert 'DO_NOT_PERSIST' not in json.dumps(safe)


def test_cookie_equivalence_requires_exact_cookie_name():
    rows, _, _ = zap_findings([alert('10011', param='OtherCookie')], 'fixture', AT)
    assert rows[0]['category'] == 'UNMAPPED'


def test_dedup_multi_source_max_no_double_penalty():
    native = native_row(); zap = zap_findings([alert()], 'fixture', AT)[0][0]
    groups = deduplicate([native,zap,zap]); assert len(groups) == 1
    assert groups[0]['multi_source'] and groups[0]['member_count'] == 2
    def quality(rs): return assemble(rs, [], 'current', 'none', as_of=AT)['cqi']['cqi']
    assert quality([native]) == quality(groups)
    assert len(groups[0]['evidence']['members']) == 2
    assert 'HDR-002' in groups[0]['source_finding_ids']
    assert all(i.startswith('operational-evidence-') for i in groups[0]['member_evidence_ids'])


def test_early_snapshot_parent_ids_normalize_without_mutating_source():
    from demo.backend.adapters import finding
    r=deduplicate([native_row()])[0]
    original_ids=r.pop('member_evidence_ids');r['source_finding_ids']=original_ids
    before=deepcopy(r);projected=finding(r)
    assert projected.source_finding_ids==['HDR-002'] and projected.member_evidence_ids==original_ids
    assert r==before


def test_not_reevaluated_is_coverage_not_corroboration_or_historical_score():
    coverage = not_reevaluated(CATALOG, set(), 'fixture', AT)
    assert all(r['check_result'] == 'NOT_TESTED' and r['severity'] is None for r in coverage)
    zap = zap_findings([alert()], 'fixture', AT)[0][0]
    group = next(g for g in deduplicate(coverage+[zap]) if g['finding_id']=='HDR-002')
    assert group['evidence_sources'] == ['OWASP_ZAP'] and not group['multi_source']


def test_distinct_controls_and_new_posture_rule_do_not_map_to_D6():
    z = zap_findings([alert('10021'),alert('10015')], 'fixture', AT)[0]
    q = assemble(deduplicate([native_row()]+z), [], 'current', 'none', as_of=AT)
    assert len(q['fusion_clusters']) == 3
    assert next(d for d in q['dimensions'] if d['dimension']=='D6')['quality'] is None
    assert q['cqi']['normalized_available_dimension_weights']['D1'] == .5


def test_snapshot_immutability_history_and_corruption(tmp_path, monkeypatch):
    monkeypatch.delenv('POSTURE_ZAP_OWNED_EPHEMERAL', raising=False)
    provider = NativeFixture(); e = PostureAssessmentOrchestrator(tmp_path,CATALOG,native=provider)
    first = e.start(mode='PASSIVE_BASELINE',background=False); assert first['status']=='PARTIAL' and provider.calls==1
    old = {p.name:p.read_bytes() for p in e.location(first['assessment_id']).iterdir()}
    second = e.start(mode='PASSIVE_BASELINE',background=False); assert provider.calls==2 and second['assessment_id']!=first['assessment_id']
    assert len(e.history())==2 and first['coverage']['historical_results_recycled'] is False
    assert old == {p.name:p.read_bytes() for p in e.location(first['assessment_id']).iterdir()}
    assert first['provider_statuses']['zap']=='UNAVAILABLE'
    (e.location(first['assessment_id'])/'native.json').write_text('tampered')
    with pytest.raises(ValueError):e.get(first['assessment_id'])
    with pytest.raises(ValueError):e.get('../../outputs')


def test_provider_exception_does_not_break_native_or_leak_secrets(tmp_path):
    broken = Mock(); broken.start_assessment.side_effect=RuntimeError('password=DO_NOT_PERSIST')
    e=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativeFixture(),zap=broken)
    j=e.start(mode='PASSIVE_BASELINE',background=False)
    assert j['provider_statuses']=={'native':'COMPLETE','zap':'FAILED'} and j['status']=='PARTIAL'
    assert all('DO_NOT_PERSIST' not in p.read_text() for p in e.location(j['assessment_id']).iterdir())


@pytest.fixture
def application(tmp_path,monkeypatch):
    for name in ('accepted','benign','attack'):
        source=ROOT/getattr(Config(),name);target=tmp_path/name
        if name=='accepted':shutil.copytree(source,target)
        else:
            target.mkdir()
            files=['candidate_predictions.json','artifact_manifest.json'] if name=='benign' else ['predictions.json','artifact_hashes.json','candidate_metrics.json','v1_metrics.json']
            for f in files:shutil.copyfile(source/f,target/f)
    shutil.copyfile(ROOT/Config().posture,tmp_path/'posture.json')
    app=Application(Config(repository=tmp_path,accepted='accepted',benign='benign',attack='attack',posture='posture.json'))
    app.posture_service.providers['native']=NativeFixture()
    monkeypatch.delenv('POSTURE_ZAP_OWNED_EPHEMERAL',raising=False)
    app.posture_service.providers['zap']=ZapPassiveProvider()
    return app


def request(app,path,method='GET',body=None,headers=None):
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://testserver') as client:
            return await client.request(method,path,json=body,headers=headers)
    return asyncio.run(run())


def test_api_workflow_filters_and_no_historical_substitution(application,monkeypatch):
    app=create_app(application=application,config=application.config)
    start=application.posture_service.start
    monkeypatch.setattr(application.posture_service,'start',lambda *a,**kw:start(*a,**kw,background=False))
    assert request(app,'/api/posture/assessments/latest').json()['status']=='NOT_REEVALUATED'
    assert request(app,'/api/posture/findings?view=current').json()['items']==[]
    before=application.snapshot()['cqi'].overall
    j=request(app,'/api/posture/assessments','POST',{'mode':'PASSIVE_BASELINE'}, {'X-Product-Control':'1'}).json()
    assert j['status']=='PARTIAL' and j['native_checks_rerun']==['HDR-002']
    current=request(app,'/api/posture/findings?view=current&source=NATIVE_POSTURE&status=FAIL').json()['items']
    assert len(current)==1 and current[0]['assessment_id']==j['assessment_id']
    assert request(app,'/api/posture/findings?view=historical').json()['total']==40
    detail=request(app,'/api/posture/findings/HDR-002?view=current').json();assert detail['assessment_scope']=='CURRENT_OPERATIONAL_POSTURE'
    assert application.snapshot()['cqi'].overall==before
    live=application.snapshot(mode='LIVE_LAB');assert live['cqi'].overall_status=='PARTIAL_EVIDENCE'
    assert live['cqi'].dimensions[5].score is None and live['cqi'].policy['assessment_scope']=='CURRENT_CQI'
    assert live['cqi'].dimensions[3].score is None and 'D4' in live['cqi'].policy['unavailable_dimensions']
    assert 'missing checks are not PASS' in live['cqi'].policy['comparison_caution']
    assert all(f.status=='NOT_REEVALUATED' for f in live['posture'] if f.finding_id!='HDR-002')
    assert request(app,'/api/scanners/zap/status').json()['active_scanner']=='DISABLED'
    assert request(app,'/api/scanners/zap/findings').json()['items']==[]
    assert len(request(app,'/api/posture/assessments').json()['items'])==1
    assert request(app,'/api/posture/assessments/'+j['assessment_id']).json()['current_posture_cqi']['policy']['coverage']=='PARTIAL'


@pytest.mark.parametrize('body', [{'mode':'ACTIVE_SCAN'}, {'target_id':'internet'}, {'url':'https://evil.test'}, {'active_scan':True}])
def test_api_rejects_active_or_arbitrary_target_fields(application,body):
    app=create_app(application=application,config=application.config)
    assert request(app,'/api/posture/assessments','POST',body,{'X-Product-Control':'1'}).status_code==422
    assert application.posture_service.history()==[]


def test_api_local_control_required_and_no_active_endpoint(application):
    app=create_app(application=application,config=application.config)
    assert request(app,'/api/posture/assessments','POST',{}).status_code==403
    assert request(app,'/api/scanners/zap/active-scan','POST',{}, {'X-Product-Control':'1'}).status_code in (404,405)
    assert not any('active-scan' in path for path in app.openapi()['paths'])


def test_accepted_behavior_and_research_core_stay_hash_identical():
    m=verify(ROOT/'outputs/branch2/accepted_behavioral_v2')
    assert m['root_sha256']=='59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436'
    sources=json.loads((ROOT/'demo/artifact_sources.json').read_text())['sources']
    assert all(hashlib.sha256((ROOT/v['path']).read_bytes()).hexdigest()==v['sha256'] for v in sources.values())


def test_current_fusion_sees_new_passive_context_without_coverage_matches(application):
    from posture.fusion_bridge import current_correlations
    raw,_,_=application.replay('ATTACK_HOLDOUT',None,application.model())
    enum=next(p for p in raw if p['reconciliation']['decision']=='ENUMERATION_RECONNAISSANCE')
    zap=zap_findings([alert('10023')],'fixture',AT)[0]
    a=assemble(deduplicate(zap),[enum],'current','saved',as_of=enum['emitted_at_utc'])
    q=a['cqi']['cqi'];cs=current_correlations(a)
    assert cs and all(c['score_effect']=='NONE' and not c['causal'] and not c['exploit_confirmed'] for c in cs)
    a['correlations']=[];assert a['cqi']['cqi']==q
    sql=next(p for p in raw if p['reconciliation']['decision']=='SQLI_ATTEMPT')
    catalog=[{'finding_id':'ADV-MSA-26-0031','category':'Patch & Vulnerability Intelligence','finding_type':'SQL injection advisory'}]
    a=assemble(not_reevaluated(catalog,set(),'fixture',AT),[sql],'current','saved',as_of=sql['emitted_at_utc'])
    assert a['correlations'] and current_correlations(a)==[]


def test_conflicting_statuses_remain_visible_and_max_is_conservative():
    native=native_row();native.update(check_result='PASS',operational_status='PASS',severity='INFO')
    zap=zap_findings([alert()],'fixture',AT)[0][0]
    result=deduplicate([native,zap])[0]
    assert result['source_status_conflict'] and result['check_result']=='FAIL'
    assert {m['check_result'] for m in result['evidence']['members']}=={'PASS','FAIL'}


def test_running_job_duplicate_and_interrupted_snapshot_fail_closed(tmp_path):
    engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativeFixture())
    aid='posture-20260101T000000Z-123456789abc'
    engine.jobs[aid]={'status':'RUNNING'}
    with pytest.raises(ValueError):engine.start(mode='PASSIVE_BASELINE',background=False)
    engine.jobs.clear();p=engine.location(aid);p.mkdir(parents=True)
    (p/'request.json').write_text(json.dumps({'assessment_id':aid,'started_at':AT,'status':'RUNNING'}))
    assert engine.get(aid)['status']=='INTERRUPTED' and engine.latest(successful=True) is None


def test_native_transport_failure_does_not_reuse_baseline(tmp_path):
    s=session([requests.ConnectionError('password=DO_NOT_PERSIST')])
    engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativePostureProvider(lambda p:StrictClient(p,session=s)))
    j=engine.start(mode='PASSIVE_BASELINE',zap_enabled=False,background=False)
    assert j['status']=='FAILED' and all(r['operational_status']=='NOT_REEVALUATED' for r in j['findings'])
    assert 'DO_NOT_PERSIST' not in json.dumps(j)
