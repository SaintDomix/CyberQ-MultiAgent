"""M1E fixture/transport tests: sockets are forbidden; no servers are started."""
import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit, urlencode
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import requests
from branch1 import Context, run
from branch1.active import Registry, SafetyPolicy, run_active
from branch1.active.advanced import AccessControl, SQLInjection, UnsafeReflection, AccountEnumeration
from branch1.active.models import RequestSpec
from branch1.active.runtime import RuntimeContext
from branch1.active.safety import Executor, SafetyError
from branch1.adapters.moodle_sessions import BootstrapError, LoginTransport, verified_sessions
from branch1.common import Document
from branch1.reporting import write_report


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


app = module('m1e_app', 'lab/branch1_validator_benchmark/app.py')
bench = module('m1e_bench', 'lab/branch1_validator_benchmark/run.py')
moodle = module('m1e_moodle', 'scripts/run_branch1_moodle_acceptance.py')
BENCH = ROOT / 'lab/branch1_validator_benchmark'
ROLE = ROOT / 'docs/acceptance/m1e_moodle_role_context.template.json'
TARGET = 'http://192.168.226.132/moodle/'
SOURCE = ROOT / 'outputs/branch1_unified_live_smoke/findings.json'


class HTTPResponse:
    def __init__(self, status=200, body=b'', headers=None):
        self.status_code, self.headers = status, headers or {}
        self.body = body.encode() if isinstance(body, str) else body
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def iter_content(self, size):
        for start in range(0, len(self.body), size): yield self.body[start:start+size]


class FixtureSession:
    def __init__(self, handler):
        self.handler = handler
        self.headers = {}
        self.cookies = requests.cookies.RequestsCookieJar()
        self.calls = []
        self.closed = False
    def get(self, url, **kwargs): return self.request('GET', url, **kwargs)
    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.handler(self, method, url, kwargs)
    def close(self): self.closed = True


class OfflineTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('socket.socket', side_effect=AssertionError('Network forbidden')))


class BenchmarkTests(OfflineTest):
    def handle(self, path, value):
        return app.Application().handle(path, urlencode({'q': value}))

    def test_sql_positive_actual_parser_error_and_repeatable(self):
        self.assertEqual(self.handle('/sql/vulnerable', 'lesson')[0], 200)
        a = self.handle('/sql/vulnerable', "lesson'")
        self.assertEqual(a[0], 500)
        self.assertIn(b'sqlite3.OperationalError', a[2])
        self.assertEqual(a, self.handle('/sql/vulnerable', "lesson'"))

    def test_parameterized_sql_negative_identical(self):
        self.assertEqual(self.handle('/sql/safe', 'lesson'), self.handle('/sql/safe', "lesson'"))

    def test_unsafe_reflection_preserves_inert_delimiters(self):
        marker = 'B1inert<\'"&>'
        response = self.handle('/xss/unsafe', marker)
        self.assertEqual(response[1], 'text/html')
        self.assertIn(('value="' + marker).encode(), response[2])

    def test_encoded_reflection_escapes_delimiters(self):
        response = self.handle('/xss/encoded', 'B1inert<\'"&>')
        self.assertIn(b'B1inert&lt;&#x27;&quot;&amp;&gt;', response[2])
        self.assertNotIn(b'B1inert<', response[2])

    def test_enumeration_pairs(self):
        self.assertNotEqual(self.handle('/accounts/distinct', 'bench-present'), self.handle('/accounts/distinct', 'bench-absent'))
        self.assertEqual(self.handle('/accounts/normalized', 'bench-present'), self.handle('/accounts/normalized', 'bench-absent'))

    def test_fixture_state_and_no_persistence_or_unrestricted_payloads(self):
        before = sorted(p.name for p in BENCH.iterdir())
        baseline = self.handle('/sql/vulnerable', 'lesson')
        for _ in range(5): self.handle('/sql/vulnerable', "lesson'")
        self.assertEqual(self.handle('/sql/vulnerable', 'lesson'), baseline)
        self.assertEqual(before, sorted(p.name for p in BENCH.iterdir()))
        self.assertEqual(self.handle('/sql/vulnerable', "' UNION SELECT secret")[0], 400)
        self.assertEqual(app.Application().handle('/sql/safe', 'q=lesson&q=lesson')[0], 400)
        self.assertEqual(self.handle('/xss/unsafe', 'x'*129)[0], 400)

    def engine(self, budget=24, active=True):
        spec = Document.load(BENCH/'expected_outcomes.json', ROOT)
        parents = bench.parents_from_spec(spec)
        runtime = RuntimeContext(**json.loads((BENCH/'runtime_context.template.json').read_text()))
        policy = SafetyPolicy('http://127.0.0.1:8765/', active, active, budget, 5, .5)
        application = app.Application()
        def handler(session, method, url, options):
            self.assertEqual(method, 'GET')
            self.assertFalse(options['allow_redirects'])
            self.assertEqual(options['timeout'], 5)
            parts = urlsplit(url)
            status, ctype, body = application.handle(parts.path, parts.query)
            return HTTPResponse(status, body, {'Content-Type': ctype})
        session = FixtureSession(handler)
        executor = Executor(policy, session=session, runtime=runtime, clock=lambda: 0, sleep=MagicMock()) if active else None
        ctx = Context(ROOT)
        originals = copy.deepcopy([p.to_dict() for p in parents])
        summary = run_active(ctx, parents, policy, registry=Registry((SQLInjection(),UnsafeReflection(),AccountEnumeration())), executor=executor, runtime=runtime)
        self.assertEqual(originals, [p.to_dict() for p in parents])
        return spec, parents, ctx, summary, session, executor

    def test_six_fixtures_via_normal_engine_match_expected_linked_evidence(self):
        spec, parents, ctx, summary, session, executor = self.engine()
        checks = bench.comparison(spec.payload, ctx.artifacts['active_validation_results.json'])
        self.assertTrue(all(r['matched'] is True for r in checks), checks)
        self.assertEqual(summary['requests_used'], 22)
        self.assertEqual(summary['active_evidence_count'], 6)
        self.assertEqual(len(session.calls), 22)
        self.assertEqual(executor.sleep.call_count, 21)
        ids = {p.evidence_id for p in parents}
        for row in ctx.artifacts['active_validation_results.json']:
            self.assertIn(row['parent_evidence_id'], ids)
            self.assertEqual(row['applicability'], 'APPLICABLE')
            self.assertEqual(row['execution_status'], 'EXECUTED')
        exported = json.dumps(ctx.artifacts)
        self.assertNotIn('bench-present', exported)
        self.assertNotIn('bench-absent', exported)

    def test_small_budget_does_not_count_skipped_experiment_as_negative(self):
        spec, _, ctx, summary, _, _ = self.engine(4)
        checks = bench.comparison(spec.payload, ctx.artifacts['active_validation_results.json'])
        self.assertEqual(summary['requests_used'], 4)
        self.assertTrue(all(c['matched'] is None for c in checks[1:]))

    def test_planning_is_network_free_and_not_measured(self):
        with patch('requests.Session', side_effect=AssertionError('No client')):
            spec, _, ctx, summary, _, _ = self.engine(active=False)
        self.assertEqual(summary['requests_used'], 0)
        self.assertTrue(all(c['matched'] is None for c in bench.comparison(spec.payload, ctx.artifacts['active_validation_results.json'])))

    def test_benchmark_cli_offline_writes_expectations_separate_from_measurements(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(bench, 'ROOT', Path(directory)), patch.dict(os.environ, {'B1_BENCH_CONTEXT':(BENCH/'runtime_context.template.json').read_text()}), patch('requests.Session', side_effect=AssertionError('No client')), patch.object(sys, 'argv', ['run.py','--target','http://127.0.0.1:8765/','--out',str(Path(directory)/'outputs/plan')]):
            self.assertEqual(bench.main(), 0)
            data = json.loads((Path(directory)/'outputs/plan/benchmark_comparison.json').read_text())
            self.assertTrue(all(not r['evaluated'] and r['matched'] is None for r in data))

    def test_benchmark_cli_mocked_transport_full_artifacts(self):
        application = app.Application()
        def handler(session, method, url, options):
            parts = urlsplit(url)
            status, ctype, body = application.handle(parts.path, parts.query)
            return HTTPResponse(status, body, {'Content-Type':ctype})
        fixture = FixtureSession(handler)
        executor_factory = lambda policy, runtime=None: Executor(policy,session=fixture,runtime=runtime,clock=lambda:0,sleep=MagicMock())
        with tempfile.TemporaryDirectory() as directory, patch.object(bench,'ROOT',Path(directory)), patch.dict(os.environ,{'B1_BENCH_CONTEXT':(BENCH/'runtime_context.template.json').read_text()}), patch('branch1.active.orchestration.Executor',side_effect=executor_factory), patch.object(sys,'argv',['run.py','--target','http://127.0.0.1:8765/','--active','--authorized','--out',str(Path(directory)/'outputs/run')]):
            self.assertEqual(bench.main(),0)
            rows=json.loads((Path(directory)/'outputs/run/benchmark_comparison.json').read_text())
            self.assertTrue(all(row['matched'] is True for row in rows))
            self.assertEqual(len(fixture.calls),22)


class MoodleTests(OfflineTest):
    def setUp(self):
        super().setUp()
        self.runtime = RuntimeContext(**json.loads(ROLE.read_text()))
        self.context = self.runtime.mappings['ROLE-student-security_report']['access_control']
        self.policy = SafetyPolicy(TARGET, True, True, 20, 5, .25, 262144)
        self.stack.enter_context(patch.dict(os.environ, {'B1_STUDENT_USERNAME':'fixture-student', 'B1_STUDENT_PASSWORD':'secret-student-password', 'B1_ADMIN_USERNAME':'fixture-admin', 'B1_ADMIN_PASSWORD':'secret-admin-password'}))
        for name in ('B1_STUDENT_COOKIE','B1_ADMIN_COOKIE'): os.environ.pop(name, None)

    def login_session(self, role, *, fail=False, marker=None, external=False, cookie=None, domain=None, token=True):
        def handler(session, method, url, options):
            self.assertEqual(options['timeout'], 5)
            self.assertFalse(options['allow_redirects'])
            if method == 'POST':
                if fail: return HTTPResponse(200, 'Invalid login')
                session.cookies.set('MoodleSession', cookie or role+'-private-session', domain=domain or '192.168.226.132', path='/moodle/')
                # Moodle emits a host-only cookie (no Domain attribute).
                for c in session.cookies: c.domain_specified = bool(domain)
                return HTTPResponse(302, headers={'Location':'http://outside.invalid/' if external else TARGET+'my/'})
            if url == TARGET+'login/index.php':
                return HTTPResponse(200, '<form id="login" method="post" action="'+url+'">'+('<input name="logintoken" value="secret-login-token">' if token else '')+'</form>')
            return HTTPResponse(200, marker if marker is not None else self.context['identity_markers'][role])
        return FixtureSession(handler)

    def bootstrap(self, sessions, **kwargs):
        return verified_sessions(self.policy, self.runtime, self.context, session_factory=MagicMock(side_effect=sessions), clock=lambda: 0, sleep=MagicMock(), **kwargs)

    def test_verified_sessions_ephemeral_distinct_and_cleaned_up(self):
        sessions = [self.login_session('restricted'), self.login_session('privileged')]
        with self.bootstrap(sessions) as metadata:
            self.assertTrue(metadata['identity_verified'])
            self.assertEqual(metadata['requests_used'], 8)
            self.assertNotEqual(self.runtime.cookie('student-test'), self.runtime.cookie('administrator-test'))
            self.assertNotIn('private-session', json.dumps(metadata))
            self.assertNotIn('secret-', json.dumps(metadata))
        self.assertFalse(self.runtime.session_available('student-test'))
        self.assertFalse(self.runtime.session_available('administrator-test'))
        self.assertTrue(all(s.closed and len(s.cookies)==0 for s in sessions))
        for s in sessions: self.assertEqual(sum(c[0]=='POST' for c in s.calls), 1)

    def test_missing_credentials_no_requests(self):
        os.environ.pop('B1_ADMIN_PASSWORD')
        session = self.login_session('restricted')
        with self.assertRaisesRegex(BootstrapError, 'credentials unavailable'):
            with self.bootstrap([session]): pass
        self.assertEqual(session.calls, [])

    def test_login_failure_no_retry_and_no_secret_error(self):
        session = self.login_session('restricted', fail=True)
        with self.assertRaisesRegex(BootstrapError, 'no retry') as exc:
            with self.bootstrap([session]): pass
        self.assertNotIn('secret', str(exc.exception))
        self.assertEqual([c[0] for c in session.calls], ['GET','POST'])
        self.assertTrue(session.closed)

    def test_swapped_accounts_and_generic_200_identity_rejected(self):
        for marker in ('Generic HTTP 200', self.context['identity_markers']['privileged']):
            with self.subTest(marker=marker), self.assertRaisesRegex(BootstrapError, 'identity verification'):
                with self.bootstrap([self.login_session('restricted', marker=marker)]): pass

    def test_distinct_accounts_cookies_roles_and_environment_references_required(self):
        with patch.dict(os.environ, {'B1_ADMIN_USERNAME':'fixture-student'}), self.assertRaisesRegex(BootstrapError, 'Distinct student'):
            with self.bootstrap([]): pass
        sessions = [self.login_session('restricted', cookie='same-session'),self.login_session('privileged', cookie='same-session')]
        with self.assertRaisesRegex(BootstrapError, 'sessions must be distinct'):
            with self.bootstrap(sessions): pass
        self.runtime.sessions['student-test']['role']='administrator'
        with self.assertRaisesRegex(BootstrapError, 'role reference mismatch'):
            with self.bootstrap([]): pass
        self.runtime.sessions['student-test']['role']='student'
        self.runtime.sessions['administrator-test']['cookie_env']='B1_STUDENT_COOKIE'
        with self.assertRaisesRegex(BootstrapError, 'Distinct ephemeral'):
            with self.bootstrap([self.login_session('restricted'),self.login_session('privileged')]): pass
        self.assertNotIn('B1_STUDENT_COOKIE', os.environ)

    def test_no_external_redirect_cookie_domain_or_missing_token(self):
        for options in ({'external':True},{'domain':'.192.168.226.132'},{'token':False}):
            session = self.login_session('restricted', **options)
            with self.subTest(options=options), self.assertRaises(ValueError):
                with self.bootstrap([session]): pass
            self.assertTrue(all(urlsplit(c[1]).hostname=='192.168.226.132' for c in session.calls))

    def test_bootstrap_authorization_budget_rate_cap_and_post_scope(self):
        with self.assertRaises(SafetyError): LoginTransport(SafetyPolicy(TARGET))
        transport = LoginTransport(self.policy,clock=lambda:0,sleep=MagicMock())
        session = FixtureSession(lambda *args: HTTPResponse(200, b'x'*262145))
        with self.assertRaisesRegex(BootstrapError, 'size/time'): transport.request(session,'GET', TARGET+'my/')
        with self.assertRaises(BootstrapError): transport.request(session,'POST', TARGET+'my/', {'password':'secret'})
        transport.used = 16
        with self.assertRaisesRegex(BootstrapError, 'budget'): transport.request(session,'GET', TARGET+'my/')
        self.assertEqual(len(session.calls), 1)
        sessions = [self.login_session('restricted'),self.login_session('privileged')]
        sleeper = MagicMock()
        with verified_sessions(self.policy,self.runtime,self.context,session_factory=MagicMock(side_effect=sessions),clock=lambda:0,sleep=sleeper): pass
        self.assertEqual(sleeper.call_count, 7)
        sleeper.assert_called_with(4.0)

    def test_credential_post_cannot_be_repeated_or_leak_on_transport_error(self):
        transport=LoginTransport(self.policy,clock=lambda:0,sleep=MagicMock())
        session=self.login_session('restricted',fail=True)
        data={'username':'fixture-student','password':'secret-student-password','logintoken':'secret-login-token'}
        transport.request(session,'POST',transport.login_url,data)
        with self.assertRaisesRegex(BootstrapError,'retry prohibited'):
            transport.request(session,'POST',transport.login_url,data)
        self.assertEqual(len(session.calls),1)
        failing=FixtureSession(MagicMock(side_effect=requests.Timeout('password=secret-student-password')))
        with self.assertRaisesRegex(BootstrapError,'Bounded login request failed') as exc:
            transport.request(failing,'GET',transport.login_url)
        self.assertNotIn('secret-student-password',str(exc.exception))

    def role_engine(self, high=None, low=None, dismissed=False, low_status=404):
        parent = moodle.load_parent(SOURCE)
        if dismissed:
            parents, _, _ = run(Context(ROOT))
            parent = next(p for p in parents if p.confirmation_status=='FALSE_POSITIVE')
            self.runtime.mappings[parent.finding_id]={'access_control':self.context}
        original = copy.deepcopy(parent.to_dict())
        high = high or self.context['identity_markers']['privileged']+'<table id="securityreporttable">security checks</table>'+'x'*150000
        low = low or 'Access denied '+self.context['identity_markers']['restricted']
        def handler(session, method, url, options):
            cookie = options['headers']['Cookie']
            return HTTPResponse(low_status if 'restricted' in cookie else 200, low if 'restricted' in cookie else high)
        session = FixtureSession(handler)
        executor = Executor(self.policy,session=session,runtime=self.runtime,clock=lambda:0,sleep=MagicMock())
        ctx=Context(ROOT)
        with patch.dict(os.environ, {'B1_STUDENT_COOKIE':'MoodleSession=restricted-private-session','B1_ADMIN_COOKIE':'MoodleSession=privileged-private-session'}):
            summary = run_active(ctx,[parent],self.policy,registry=Registry((AccessControl(),)),executor=executor,runtime=self.runtime)
        self.assertEqual(parent.to_dict(), original)
        return parent, ctx, summary, executor

    def test_denial_with_large_admin_comparator_and_no_secret_export(self):
        parent, ctx, summary, ex = self.role_engine()
        result = ctx.artifacts['active_validation_results.json'][0]
        self.assertEqual((result['outcome'],result['check_result'],result['confirmation_status']),('ROLE_DENIED','PASS','NOT_CONFIRMED'))
        self.assertEqual(summary['requests_used'],4)
        self.assertTrue(result['characteristics']['privileged_comparator_verified'])
        with tempfile.TemporaryDirectory() as directory:
            ctx.project = Path(directory)
            ctx.output = Path(directory)/'outputs/acceptance'
            write_report(ctx,[parent],{'roles':1},{parent.evidence_id:'roles'},active_summary=summary)
            exported = ''.join(p.read_text() for p in ctx.output.iterdir() if p.is_file())
            for secret in ('restricted-private-session','privileged-private-session','secret-student-password','secret-login-token'):
                self.assertNotIn(secret, exported)

    def test_denial_without_verified_privileged_comparator_not_accepted(self):
        _,ctx,_,_=self.role_engine(high='Generic home HTTP 200')
        result=ctx.artifacts['active_validation_results.json'][0]
        self.assertEqual(result['confirmation_status'],'NOT_TESTED')
        self.assertEqual(result['check_result'],'NOT_TESTED')

    def test_generic_200_and_actual_privileged_content_are_distinct(self):
        identity=self.context['identity_markers']['restricted']
        _,ctx,_,_=self.role_engine(low=identity+'<h1>Home</h1>',low_status=200)
        self.assertEqual(ctx.artifacts['active_validation_results.json'][0]['outcome'],'INCONCLUSIVE')
        _,ctx,_,_=self.role_engine(low=identity+'<table id="securityreporttable">checks</table>',low_status=200)
        self.assertEqual(ctx.artifacts['active_validation_results.json'][0]['confirmation_status'],'LIKELY')

    def test_role_cli_mocked_bootstrap_engine_budget_and_secret_free_exports(self):
        sessions=[self.login_session('restricted'),self.login_session('privileged')]
        def handler(session,method,url,options):
            if 'restricted-private-session' in options['headers']['Cookie']:
                return HTTPResponse(404,'Access denied '+self.context['identity_markers']['restricted'])
            return HTTPResponse(200,self.context['identity_markers']['privileged']+'<table id="securityreporttable">checks</table>')
        fixture=FixtureSession(handler)
        def bootstrap(policy,runtime,context,**options):
            return verified_sessions(policy,runtime,context,session_factory=MagicMock(side_effect=sessions),clock=lambda:0,sleep=MagicMock(),**options)
        executor_factory=lambda policy,runtime: Executor(policy,runtime=runtime,session=fixture,clock=lambda:0,sleep=MagicMock())
        with tempfile.TemporaryDirectory() as directory, patch.object(moodle,'ROOT',Path(directory)), patch.dict(os.environ,{'B1_ACTIVE_CONTEXT':ROLE.read_text()}), patch.object(moodle,'verified_sessions',side_effect=bootstrap), patch.object(moodle,'Executor',side_effect=executor_factory), patch.object(sys,'argv',['acceptance.py','--target',TARGET,'--parent-findings',str(SOURCE),'--active','--authorized','--out',str(Path(directory)/'outputs/run')]):
            self.assertEqual(moodle.main(),0)
            output=Path(directory)/'outputs/run'
            summary=json.loads((output/'branch1_summary.json').read_text())['active_validation']
            self.assertEqual(summary['total_requests_used'],12)
            self.assertEqual(summary['total_budget'],20)
            self.assertEqual(summary['bootstrap_requests_used'],8)
            comparison=json.loads((output/'moodle_acceptance_comparison.json').read_text())
            self.assertTrue(comparison['matched'])
            exported=''.join(p.read_text() for p in output.iterdir())
            for secret in ('restricted-private-session','privileged-private-session','secret-student-password','secret-admin-password','secret-login-token'):
                self.assertNotIn(secret,exported)
        self.assertNotIn('B1_STUDENT_COOKIE',os.environ)
        self.assertNotIn('B1_ADMIN_COOKIE',os.environ)

    def test_historical_false_positive_never_reactivated(self):
        _,ctx,summary,_=self.role_engine(dismissed=True)
        self.assertEqual(summary['requests_used'],0)
        self.assertEqual(ctx.artifacts['active_validation_plan.json'][0]['applicability'],'NOT_APPLICABLE')

    def test_explicit_response_cap_default_and_maximum(self):
        self.assertEqual(SafetyPolicy().max_response_bytes,65536)
        for invalid in (0,262145,True):
            with self.assertRaises(SafetyError): SafetyPolicy(max_response_bytes=invalid)

    def test_role_cli_offline_requires_no_credentials_or_session_clients(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(moodle,'ROOT',Path(directory)), patch.dict(os.environ,{'B1_ACTIVE_CONTEXT':ROLE.read_text()},clear=True), patch('requests.Session',side_effect=AssertionError('No client')), patch.object(sys,'argv',['acceptance.py','--target',TARGET,'--parent-findings',str(SOURCE),'--out',str(Path(directory)/'outputs/plan')]):
            self.assertEqual(moodle.main(),0)
            result=json.loads((Path(directory)/'outputs/plan/moodle_acceptance_comparison.json').read_text())
            self.assertIsNone(result['matched'])
            self.assertFalse(result['evaluated'])


if __name__=='__main__': unittest.main()
