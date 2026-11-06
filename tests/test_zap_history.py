"""No live ZAP or target access: typed history and response fixtures only."""
import json
from pathlib import Path
import sys
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from posture.policy import TARGET, PAGES, PassivePolicy
from posture.providers import StrictClient, ZapPassiveProvider, ZapAPI
from posture.zap_history import (
    USER_AGENT, MAX_HISTORY_MESSAGES, ancestors, control_url, review_history,
)

ORIGIN = 'http://127.0.0.1:8081'
TARGET_URLS = [TARGET + p for p in PAGES]
TRANSCRIPT = [{'method': 'GET', 'url': u, 'status': 303 if p in ('my/', 'admin/') else 200}
              for p, u in zip(PAGES, TARGET_URLS)]


def message(url, ident=1, kind=1, status=200, method='GET', **extra):
    m = {'id': str(ident), 'type': str(kind), 'timestamp': '0' if kind == 0 else '1792120204005',
         'rtt': '0' if kind == 0 else '20', 'requestBody': '', 'responseBody': '' if kind == 0 else 'fixture',
         'requestHeader': f'{method} {url} HTTP/1.1\r\nHost: {urlsplit(url).netloc}\r\nUser-Agent: {USER_AGENT}\r\nCookie: DO_NOT_PERSIST\r\nAuthorization: DO_NOT_PERSIST\r\n\r\n',
         'responseHeader': f'HTTP/1.1 {status} Fixture\r\nSet-Cookie: DO_NOT_PERSIST\r\n\r\n'}
    m.update(extra)
    return m


def target_messages():
    return [message(r['url'], i + 1, status=r['status']) for i, r in enumerate(TRANSCRIPT)]


def internal_messages():
    return [message(u, i + 20, kind=0, status=0) for i, u in enumerate(sorted(ancestors(TARGET_URLS)))]


def inspect(messages=None, issued=None, urls=None, expected=TRANSCRIPT, reported=None):
    messages = target_messages() + internal_messages() if messages is None else messages
    urls = [m['requestHeader'].split()[1] for m in messages] if urls is None else urls
    return review_history(messages, urls, expected, issued or [], len(messages) if reported is None else reported)


@pytest.fixture(autouse=True)
def no_network_or_fit(monkeypatch):
    def forbidden(*a, **kw): raise AssertionError('No network or model fitting')
    for name in ('socket.create_connection', 'socket.getaddrinfo', 'socket.socket.connect',
                 'sklearn.svm.OneClassSVM.fit', 'xgboost.XGBClassifier.fit'):
        monkeypatch.setattr(name, forbidden)


def test_real_eleven_record_shape_has_five_targets_six_unsent_ancestors():
    diag, classes = inspect()
    assert diag['result'] == 'PASS'
    assert diag['total_history_messages'] == 11 and diag['target_messages'] == 5
    assert diag['ignored_internal_messages'] == 6 and diag['control_plane_messages'] == 0
    assert diag['unexpected_messages'] == 0
    assert {m['path'] for m in diag['history_messages'] if m['classification'] == 'INTERNAL_SITE_TREE_ANCESTOR'} == {
        '', '/moodle', '/moodle/login', '/moodle/my', '/moodle/course', '/moodle/admin'}
    assert all(classes[url] == 'TARGET' for url in TARGET_URLS)


def test_five_approved_requests_and_exact_issued_control_messages_pass():
    issued = [control_url(ORIGIN, 'core', 'view', 'version', {}),
              control_url(ORIGIN, 'core', 'action', 'setMode', {'mode': 'safe'})]
    records = target_messages() + [message(u, i + 40) for i, u in enumerate(issued)]
    diag, _ = inspect(records, issued)
    assert diag['result'] == 'PASS' and diag['target_messages'] == 5
    assert diag['control_plane_messages'] == 2


@pytest.mark.parametrize('url', ['http://evil.test/moodle/', 'http://192.168.226.133/moodle/',
    'http://192.168.226.132/', TARGET + 'report/security/index.php', TARGET + 'login/index.php?token=DO_NOT_PERSIST'])
def test_actual_proxied_off_scope_or_unreviewed_request_fails(url):
    diag, _ = inspect(target_messages() + [message(url, ident=90)])
    assert diag['result'] == 'FAIL' and diag['unexpected_messages'] == 1
    assert 'DO_NOT_PERSIST' not in json.dumps(diag)


@pytest.mark.parametrize('change', [
    {'type': '1'}, {'timestamp': '1792120204005'}, {'rtt': '1'},
    {'requestBody': 'DO_NOT_PERSIST'}, {'responseBody': 'DO_NOT_PERSIST'},
    {'responseHeader': 'HTTP/1.1 200 OK\r\n\r\n'},
])
def test_internal_exception_requires_all_unsent_metadata(change):
    records = target_messages() + internal_messages()
    records[-1].update(change)
    diag, _ = inspect(records)
    assert diag['result'] == 'FAIL' and diag['unexpected_messages'] == 1
    assert 'DO_NOT_PERSIST' not in json.dumps(diag)


def test_temporary_unrelated_url_is_not_exempt_and_urls_need_history_proof():
    records = target_messages() + [message(TARGET + 'private', 90, kind=0, status=0)]
    assert inspect(records)[0]['result'] == 'FAIL'
    # A tree ancestor URL alone is not proof: a matching typed message is required.
    assert inspect(target_messages(), urls=TARGET_URLS + ['http://192.168.226.132'])[0]['result'] == 'FAIL'


def test_control_lookalikes_unissued_actions_and_query_values_fail():
    issued = [control_url(ORIGIN, 'core', 'action', 'setMode', {'mode': 'safe'})]
    for url in (ORIGIN + '/JSON/core/action/setMode/?mode=attack',
                ORIGIN + '/JSON/ascan/action/scan/',
                'http://evil.test:8081/JSON/core/action/setMode/?mode=safe',
                ORIGIN + '/JSON/core/action/setMode/?mode=safe&token=DO_NOT_PERSIST'):
        diag, _ = inspect(target_messages() + [message(url, 91)], issued)
        assert diag['result'] == 'FAIL' and 'DO_NOT_PERSIST' not in json.dumps(diag)
    records = target_messages() + [message(issued[0], 91), message(issued[0], 92)]
    assert inspect(records, issued)[0]['result'] == 'FAIL'  # One issued call cannot explain two records.


def test_extra_same_target_traffic_and_preexisting_target_history_fail():
    records = target_messages()
    diag, _ = inspect(records + [message(TARGET, 90)])
    assert diag['result'] == 'FAIL' and diag['unexpected_messages'] == 1
    diag, _ = inspect(records, expected=[])
    assert diag['result'] == 'FAIL' and diag['unexpected_messages'] == 5


@pytest.mark.parametrize('method', ['POST', 'OPTIONS', 'DELETE', 'HEAD'])
def test_non_collection_methods_never_accepted(method):
    records = target_messages(); records[0] = message(TARGET, method=method)
    assert inspect(records)[0]['result'] == 'FAIL'


def test_redirect_response_is_valid_but_extra_redirect_navigation_is_not():
    records = target_messages()
    records[2]['responseHeader'] += 'Location: https://evil.test/?token=DO_NOT_PERSIST\r\n'
    diag, _ = inspect(records)
    assert diag['result'] == 'PASS' and 'DO_NOT_PERSIST' not in json.dumps(diag)
    assert inspect(records + [message(TARGET + 'login/index.php', 90)])[0]['result'] == 'FAIL'


def test_history_bounds_incompleteness_and_duplicate_ids_fail_closed():
    assert inspect(reported=100)[0]['result'] == 'FAIL'
    records = target_messages(); records[1]['id'] = records[0]['id']
    assert inspect(records)[0]['result'] == 'FAIL'
    assert inspect([message(TARGET, i + 1) for i in range(MAX_HISTORY_MESSAGES + 1)])[0]['result'] == 'FAIL'


def test_malformed_or_conflicting_host_headers_fail_without_secret_export():
    for header in ('DO_NOT_PERSIST', f'GET {TARGET} HTTP/1.1\r\nHost: evil.test\r\n'):
        records = target_messages(); records[0]['requestHeader'] = header
        diag, _ = inspect(records, urls=TARGET_URLS)
        assert diag['result'] == 'FAIL' and 'DO_NOT_PERSIST' not in json.dumps(diag)


class API:
    origin = ORIGIN
    def __init__(self, extra=None, shared=False, scanner=False, spider=False, control_alert=False):
        self.calls = []; self.urls_reads = 0
        self.extra, self.shared, self.scanner, self.spider = extra or [], shared, scanner, spider
        self.control_alert = control_alert
    def records(self):
        records = target_messages() + internal_messages() + self.extra if self.shared or self.urls_reads > 1 else []
        controls = [control_url(ORIGIN, c, k, n, kw) for c, k, n, kw in self.calls]
        return records + [message(u, i + 100) for i, u in enumerate(controls)]
    def call(self, c, k, n, **kw):
        self.calls.append((c, k, n, kw))
        if n == 'version': return {'version': '2.17.0'}
        if n == 'newSession':
            self.shared = False; self.urls_reads = 0; self.calls = [(c, k, n, kw)]
            return {'Result': 'OK'}
        if n == 'urls':
            self.urls_reads += 1
            return {'urls': [m['requestHeader'].split()[1] for m in self.records()]}
        if n == 'numberOfMessages': return {'numberOfMessages': str(len(self.records()))}
        if n == 'messages': return {'messages': self.records()}
        if n == 'scans': return {'scans': ['1'] if (c == 'ascan' and self.scanner or c == 'spider' and self.spider) else []}
        if n == 'mode': return {'mode': 'safe'}
        if n == 'recordsToScan': return {'recordsToScan': '0'}
        if n == 'alerts':
            if kw.get('count') == '1': return {'alerts': []}
            result = [{'pluginId': '10038', 'riskcode': '2', 'confidence': '2', 'url': TARGET,
                       'id': '1', 'evidence': 'DO_NOT_PERSIST'}]
            if self.control_alert:
                result += [dict(result[0], url=ORIGIN+'/JSON/core/action/setMode/?mode=safe', id='2'),
                           dict(result[0], url='http://192.168.226.132/moodle', id='3')]
            return {'alerts': result}
        return {'Result': 'OK'}


def client_factory(policy, proxy):
    s = Mock(); s.headers = {}; s.proxies = {}
    def send(method, url, **kw):
        r = requests.Response(); r.url = url
        r.status_code = next(item['status'] for item in TRANSCRIPT if item['url'] == url)
        r._content = b'fixture'; r._content_consumed = True
        if r.status_code == 303: r.headers['Location'] = TARGET + 'login/index.php'
        return r
    s.request.side_effect = send
    return StrictClient(policy, proxy=proxy, session=s)


def test_provider_accepts_typed_history_and_303_with_control_evidence_excluded():
    api = API(control_alert=True)
    result = ZapPassiveProvider(api, client_factory).start_assessment('fixture', PassivePolicy())
    assert result['status'] == 'COMPLETE'
    diag = result['scope_integrity']
    assert diag['result'] == 'PASS' and diag['target_messages'] == 5
    assert diag['ignored_internal_messages'] == 6 and diag['control_plane_messages'] > 0
    assert result['urls_observed'] == 5 and result['provenance']['request_count'] == 5
    assert [r['status'] for r in result['provenance']['requests']] == [200, 200, 303, 200, 303]
    assert result['excluded_non_target_alert_count'] == 2
    assert len(result['findings']) == len(result['sanitized_alerts']) == 1
    assert result['findings'][0]['url'] == TARGET
    assert 'DO_NOT_PERSIST' not in json.dumps(result)
    assert all(not (c in ('ascan', 'spider') and k == 'action') for c, k, _, _ in api.calls)


@pytest.mark.parametrize('kwargs', [
    {'extra': [message('https://evil.test/moodle/', 91)]},
    {'extra': [message(TARGET + 'report/security/index.php', 91)]},
    {'scanner': True}, {'spider': True},
])
def test_provider_scope_failure_is_diagnostic_and_keeps_findings_empty(kwargs):
    api = API(**kwargs)
    result = ZapPassiveProvider(api, client_factory).start_assessment('fixture', PassivePolicy())
    assert result['status'] == 'FAILED' and result['error_code'] == 'SCOPE_INTEGRITY_FAILURE'
    assert result['scope_integrity']['result'] == 'FAIL' and result['findings'] == []
    assert 'DO_NOT_PERSIST' not in json.dumps(result)
    if kwargs.get('shared') or kwargs.get('scanner') or kwargs.get('spider'):
        assert result['provenance'].get('request_count', 0) == 0


def test_api_history_view_is_read_only_and_pagination_is_fixed():
    api = ZapAPI(ORIGIN, 'DO_NOT_PERSIST', session=Mock())
    for kw in ({}, {'count': '-1'}, {'start': '10', 'count': '101'}, {'start': '0', 'count': '9999'}):
        with pytest.raises(ValueError): api.call('core', 'view', 'messages', **kw)
    api.session.get.assert_not_called()
