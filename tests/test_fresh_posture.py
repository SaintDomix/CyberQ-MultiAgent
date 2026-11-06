"""Fresh reassessment regressions: synthetic HTTP/ZAP only, no lab traffic."""
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'src')]
from posture.inventory import controls
from posture.native import Branch1CurrentProvider, NativeClient
from posture.orchestration import PostureAssessmentOrchestrator
from posture.policy import PassivePolicy, TARGET
from posture.providers import ZapAPI, ZapPassiveProvider
from test_operational_posture import CATALOG, NativeFixture, ZapFixtureAPI, alert, application, request
from test_zap_history import API, client_factory, message
from test_posture_demo_patch import synthetic_http


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*a, **kw): raise AssertionError('No network, fit or Apache access')
    for name in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect',
                 'sklearn.svm.OneClassSVM.fit','xgboost.XGBClassifier.fit'):
        monkeypatch.setattr(name, deny)
    monkeypatch.delenv('POSTURE_ENABLE_EXISTING_ACTIVE', raising=False)
    monkeypatch.delenv('B1_ACTIVE_CONTEXT', raising=False)


def file_hashes(directory):
    return {str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob('*') if p.is_file()}


def test_two_assessments_rerun_actual_native_modules_and_http_changes(tmp_path):
    sessions = []
    def factory(policy):
        s = synthetic_http()
        original = s.request.side_effect
        if sessions:
            def secured(*a, **kw):
                r = original(*a, **kw); r.headers['Content-Security-Policy'] = "default-src 'self'"; return r
            s.request.side_effect = secured
        sessions.append(s)
        return NativeClient(policy, session=s)
    provider = Branch1CurrentProvider(ROOT, factory,
        collector=Mock(return_value=({'core':{},'settings':{},'filesystem':{},'runtime':{}},
                      {'collector_status':'NOT_AVAILABLE','reason_code':'FIXTURE_NO_INTERNAL_COLLECTOR'})))
    engine = PostureAssessmentOrchestrator(tmp_path, CATALOG, native=provider)
    first = engine.start(mode='PASSIVE_BASELINE',background=False, zap_enabled=False)
    saved = file_hashes(engine.location(first['assessment_id']))
    second = engine.start(mode='PASSIVE_BASELINE',background=False, zap_enabled=False)
    assert first['assessment_id'] != second['assessment_id']
    assert len(sessions) == 2 and all(s.request.call_count > 0 for s in sessions)
    def csp(job): return next(f for f in job['findings'] if f['finding_id']=='HDR-002')
    assert csp(first)['check_result'] == 'FAIL' and csp(second)['check_result'] == 'PASS'
    assert file_hashes(engine.location(first['assessment_id'])) == saved
    assert engine.get(first['assessment_id']) == first
    assert all(f['assessment_id']==second['assessment_id'] for f in second['findings'])


def test_each_run_creates_new_zap_session_and_never_reuses_old_alerts(tmp_path):
    class FreshAPI(ZapFixtureAPI):
        generation = 0
        def call(self, c, k, n, **kw):
            if n=='newSession':
                self.generation += 1
                self.alerts = [alert('10038' if self.generation==1 else '10021')]
            return super().call(c,k,n,**kw)
    api = FreshAPI([alert('999999')])
    engine = PostureAssessmentOrchestrator(tmp_path, CATALOG, native=NativeFixture(),
        zap=ZapPassiveProvider(api,client_factory))
    # Use the 200-only response fixture to match this API's fixed response history.
    from test_operational_posture import session
    from posture.providers import StrictClient
    engine.providers['zap'].client_factory = lambda p,proxy:StrictClient(p,proxy=proxy,session=session())
    a = engine.start(mode='PASSIVE_BASELINE',background=False); saved = file_hashes(engine.location(a['assessment_id']))
    b = engine.start(mode='PASSIVE_BASELINE',background=False)
    assert a['provider_statuses']['zap']==b['provider_statuses']['zap']=='COMPLETE'
    assert [n for _,_,n,_ in api.calls].count('newSession') == 2
    fresh = [f for f in b['findings'] if 'OWASP_ZAP' in f['evidence_sources']]
    assert {f['finding_id'] for f in fresh} == {'HDR-005'}
    assert not any(f['source_rule_id']=='999999' for f in fresh)
    assert saved == file_hashes(engine.location(a['assessment_id']))
    z = json.loads((engine.location(b['assessment_id'])/'zap.json').read_text())
    assert z['provenance']['session_lifecycle']['state']=='COLLECTED'
    assert z['provenance']['session_lifecycle']['target_messages_before_collection']==0


@pytest.mark.parametrize('failure',['api_failure','not_ok','noop'])
def test_failed_fresh_session_keeps_native_but_never_exports_old_zap(tmp_path,failure):
    class Broken(API):
        def call(self,c,k,n,**kw):
            if n=='newSession':
                if failure=='api_failure': raise requests.ReadTimeout('SECRET_NOT_EXPORTED')
                if failure=='not_ok': return {'Result':'FAIL'}
                return {'Result':'OK'}  # Lies: leaves previous target history in place.
            return super().call(c,k,n,**kw)
    api=Broken(shared=True); native=NativeFixture()
    engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=native,zap=ZapPassiveProvider(api,client_factory))
    job=engine.start(mode='PASSIVE_BASELINE',background=False)
    assert native.calls==1 and job['status']=='PARTIAL'
    assert job['provider_statuses']=={'native':'COMPLETE','zap':'FAILED'}
    assert job['raw_finding_counts']['zap']==0
    assert all('OWASP_ZAP' not in f['evidence_sources'] for f in job['findings'])
    z=json.loads((engine.location(job['assessment_id'])/'zap.json').read_text())
    assert z['error_code']==('SCOPE_INTEGRITY_FAILURE' if failure=='noop' else 'ZAP_SESSION_CREATION_FAILED')
    assert 'SECRET_NOT_EXPORTED' not in json.dumps(z)


def test_source_inventory_covers_all_native_ids_and_conditionals():
    inventory=controls(ROOT)
    lookup={r['finding_id']:r for r in inventory}
    assert {'AUTH-007','TRANSPORT-004','PLUGIN-001','PLUGIN-002','COOKIE-000','TLS-002','PATCH-001',
            'FS-003','SSRF-DEF-002','PHP-001','ROLE-<verified-role>-manage_users',
            'VALIDATOR-session_control','VALIDATOR-sql_injection','ADV-MSA-26-0031'} <= set(lookup)
    assert all(r['required_prerequisite'] and r['implementation_path'] for r in inventory)
    assert all('check_result' not in r and 'severity' not in r for r in inventory)


def test_every_known_check_has_state_and_unavailable_reason(tmp_path):
    # Enumerate production IDs, but execute only fixture providers in a temp project.
    engine=PostureAssessmentOrchestrator(tmp_path,controls(ROOT),native=NativeFixture())
    job=engine.start(mode='PASSIVE_BASELINE',background=False,zap_enabled=False)
    assert len(job['check_coverage'])==len(engine.inventory)
    assert all(c['current_state'] in ('PASS','FAIL','PARTIAL','DISMISSED','NOT_AVAILABLE','NOT_APPLICABLE') for c in job['check_coverage'])
    assert all(c['reason'] for c in job['check_coverage'] if c['current_state']=='NOT_AVAILABLE')
    assert all(f.get('prerequisite_reason') for f in job['findings'] if f['check_result']=='NOT_TESTED')


def test_named_or_overwriting_zap_sessions_cannot_be_requested():
    api=ZapAPI('http://127.0.0.1:8081','SECRET',session=Mock())
    for params in ({'name':'saved-session'}, {'overwrite':'true'}, {'name':'','overwrite':'false'}):
        with pytest.raises((ValueError,TypeError)): api.call('core','action','newSession',**params)
    api.session.get.assert_not_called()


def test_shared_unowned_daemon_is_never_reset():
    api=API(shared=True); p=ZapPassiveProvider(api,client_factory,owned_ephemeral=False)
    assert p.readiness()['assessment_readiness']=='POLICY_BLOCKED'
    assert p.start_assessment('fixture',PassivePolicy())['status']=='FAILED'
    assert not any(n=='newSession' for _,_,n,_ in api.calls)


def test_nonempty_owned_history_is_replaced_and_fresh_history_still_checked():
    result=ZapPassiveProvider(API(shared=True),client_factory).start_assessment('fresh',PassivePolicy())
    assert result['status']=='COMPLETE' and result['scope_integrity']['target_messages']==5
    api=API(extra=[message('http://evil.test/',99)])
    result=ZapPassiveProvider(api,client_factory).start_assessment('foreign',PassivePolicy())
    assert result['status']=='FAILED' and result['error_code']=='SCOPE_INTEGRITY_FAILURE'


def test_old_alerts_after_apparently_successful_reset_are_rejected():
    class Stale(API):
        def call(self,c,k,n,**kw):
            if n=='alerts' and kw.get('count')=='1': return {'alerts':[alert('999999')]}
            return super().call(c,k,n,**kw)
    result=ZapPassiveProvider(Stale(),client_factory).start_assessment('stale',PassivePolicy())
    assert result['status']=='FAILED' and result['findings']==[]
    assert 'PREEXISTING_ALERTS_AFTER_NEW_SESSION' in result['scope_integrity']['failure_reasons']
    assert result['provenance'].get('request_count',0)==0


def test_https_only_and_unaffected_advisory_checks_are_explicitly_not_applicable():
    from posture.inventory import annotate
    from posture.model import not_reevaluated
    inventory=controls(ROOT)
    rows=not_reevaluated([r for r in inventory if not r.get('coverage_only')],set(),'fixture','2026-10-26T00:00:00Z')
    native={'provenance':{'internal_evidence':{'core':{'branch':'405','version':'2099010100'}}}}
    annotate(rows,inventory,native)
    selected=[r for r in rows if r['finding_id'] in ('AUTH-007','TRANSPORT-004') or r['finding_id'].startswith('ADV-')]
    assert selected and all(r['current_state']=='NOT_APPLICABLE' for r in selected)
    assert all(r['check_result']=='NOT_APPLICABLE' and r['severity'] is None for r in selected)


def test_frozen_behavioral_package_unchanged_by_reassessment(tmp_path):
    from behavioral_runtime.package import verify
    package=ROOT/'outputs/branch2/accepted_behavioral_v2'
    before=file_hashes(package)
    manifest=verify(package)
    assert manifest  # Actual frozen package verifier, no model fitting or traffic.
    engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativeFixture())
    engine.start(mode='PASSIVE_BASELINE',background=False,zap_enabled=False)
    assert file_hashes(package)==before


def test_failed_latest_attempt_cannot_make_old_success_current(application):
    from demo.backend.app import create_app
    from test_posture_demo_patch import SyntheticZap
    engine=application.posture_service; engine.providers['zap']=SyntheticZap()
    first=engine.start(mode='PASSIVE_BASELINE',background=False)
    class Failed(NativeFixture):
        def start_assessment(self,*a,**kw): return {'status':'FAILED','findings':[],'provenance':{}}
    engine.providers['native']=Failed(); engine.providers['zap'].fail=True
    second=engine.start(mode='PASSIVE_BASELINE',background=False)
    assert second['status']=='FAILED' and engine.current() is None
    assert engine.retained_zap()['assessment_id']==first['assessment_id']
    assert application.current_posture_quality() is None
    app=create_app(application=application,config=application.config)
    assert request(app,'/api/scanners/zap/findings?view=current').json()['items']==[]
    assert request(app,'/api/posture/findings?view=current').json()['items']==[]


def test_coverage_uses_deduplicated_current_verdict_not_last_source(tmp_path):
    from posture.model import row
    class DismissedZap:
        def start_assessment(self,aid,policy):
            return {'status':'COMPLETE','findings':[row('HDR-002','Security Headers','CSP','DISMISSED',
                None,'FALSE_POSITIVE','OWASP_ZAP',aid,'2026-10-26T00:00:00Z',weakness_key='HDR-002')], 'provenance':{}}
    engine=PostureAssessmentOrchestrator(tmp_path,CATALOG,native=NativeFixture(),zap=DismissedZap())
    job=engine.start(mode='PASSIVE_BASELINE',background=False)
    assert next(c for c in job['check_coverage'] if c['finding_id']=='HDR-002')['current_state']=='FAIL'
