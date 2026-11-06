"""Monotonic fake time and mocked HTTP only; no laboratory requests or sleeps."""
import json
from pathlib import Path
import socket
import sys
from unittest.mock import Mock

import pytest
import requests
from urllib3.exceptions import ReadTimeoutError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from posture.policy import TARGET, PAGES, PassivePolicy
from posture.providers import (
    StrictClient, NativePostureProvider, ZapAPI, ZapPassiveProvider, ProviderFailure,
)


class Clock:
    value = 0.0
    def __call__(self): return self.value
    def advance(self, seconds): self.value += seconds


def response(body=b'fixture', status=200, headers=None):
    r = requests.Response()
    r.status_code = status; r.url = TARGET
    r.headers.update(headers or {})
    r._content = body; r._content_consumed = True
    return r


def http_session(clock, delay=0, body=b'fixture', status=200):
    s = Mock(); s.headers = {}; s.proxies = {}
    def send(*args, **kwargs):
        clock.advance(delay)
        return response(body, status)
    s.request.side_effect = send; s.get.side_effect = send
    return s


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError('Mocked transports only')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)


@pytest.mark.parametrize('delay', [2.5, 4.0])
def test_ordinary_moodle_latency_is_accepted_with_three_eight_budget(delay):
    clock = Clock(); s = http_session(clock, delay)
    client = StrictClient(PassivePolicy(), session=s, clock=clock)
    assert client.get(TARGET).status_code == 200
    timeout = s.request.call_args.kwargs['timeout']
    assert timeout.connect_timeout == 3.0
    assert timeout.read_timeout == timeout.total == 8.0
    assert client.deadline == 60.0 and client.transcript[0]['status'] == 200
    assert s.request.call_args.kwargs['allow_redirects'] is False


def test_native_provider_accepts_realistic_slow_first_page_without_substitution():
    clock = Clock(); s = http_session(clock)
    send = s.request.side_effect
    def slow_first(*args, **kwargs):
        if s.request.call_count == 1: clock.advance(4)
        return send(*args, **kwargs)
    s.request.side_effect = slow_first
    p = NativePostureProvider(lambda policy: StrictClient(policy, session=s, clock=clock))
    result = p.start_assessment('slow-fixture', PassivePolicy())
    assert result['status'] == 'COMPLETE' and result['error_code'] is None
    assert result['provenance']['fresh_execution'] is True
    assert all(row['assessment_id'] == 'slow-fixture' for row in result['findings'])
    assert 1 < result['provenance']['request_count'] <= 20


@pytest.mark.parametrize('delay', [8.0, 8.1])
def test_response_at_or_beyond_request_deadline_fails_even_if_transport_returns(delay):
    clock = Clock(); s = http_session(clock, delay)
    client = StrictClient(PassivePolicy(), session=s, clock=clock)
    with pytest.raises(ProviderFailure, match='READ_TIMEOUT'): client.get(TARGET)
    assert client.transcript[0]['error_code'] == 'READ_TIMEOUT'
    assert 'response_sha256' not in client.transcript[0]


def test_streaming_timeout_and_size_bounds_are_not_relaxed():
    clock = Clock(); s = http_session(clock)
    def chunks():
        yield b'initial'
        clock.advance(8.1)
        yield b'late'
    r = response(); r.iter_content = lambda *args: chunks()
    s.request.side_effect = lambda *args, **kw: r
    client = StrictClient(PassivePolicy(), session=s, clock=clock)
    with pytest.raises(ProviderFailure, match='READ_TIMEOUT'): client.get(TARGET)
    s = http_session(Clock(), body=b'123456')
    client = StrictClient(PassivePolicy(max_response_bytes=5), session=s)
    with pytest.raises(ProviderFailure, match='RESPONSE_SIZE_LIMIT'): client.get(TARGET)


@pytest.mark.parametrize('error,code', [
    (requests.ConnectTimeout('DO_NOT_PERSIST'), 'CONNECT_TIMEOUT'),
    (requests.ReadTimeout('DO_NOT_PERSIST'), 'READ_TIMEOUT'),
    (requests.ConnectionError(ReadTimeoutError(None, 'secret-url', 'DO_NOT_PERSIST')), 'READ_TIMEOUT'),
    (requests.ConnectionError('DO_NOT_PERSIST'), 'TARGET_UNREACHABLE'),
    (requests.HTTPError('DO_NOT_PERSIST'), 'HTTP_ERROR'),
])
def test_native_failure_provenance_is_specific_secret_free_and_never_historical(error, code):
    clock = Clock(); s = http_session(clock); s.request.side_effect = error
    p = NativePostureProvider(lambda policy: StrictClient(policy, session=s, clock=clock))
    result = p.start_assessment('failed-fixture', PassivePolicy())
    assert result['status'] == 'FAILED' and result['findings'] == []
    assert result['error_code'] == code
    assert result['provenance']['failure_codes'] == [code]
    assert result['provenance']['request_count'] == 1
    assert 'no historical result substituted' in result['error']
    assert 'DO_NOT_PERSIST' not in json.dumps(result)
    assert 'secret-url' not in json.dumps(result)


def test_native_base_http_error_preserves_status_without_response_body():
    clock = Clock(); s = http_session(clock, body=b'password=DO_NOT_PERSIST', status=503)
    p = NativePostureProvider(lambda policy: StrictClient(policy, session=s, clock=clock))
    result = p.start_assessment('http-failure', PassivePolicy())
    assert result['error_code'] == 'HTTP_ERROR' and result['findings'] == []
    assert result['provenance']['requests'][0]['status'] == 503
    assert 'DO_NOT_PERSIST' not in json.dumps(result)


def test_remaining_assessment_budget_caps_request_and_blocks_late_success_and_more_sends():
    clock = Clock(); s = http_session(clock, 4)
    client = StrictClient(PassivePolicy(), session=s, clock=clock)
    clock.advance(57)
    with pytest.raises(ProviderFailure, match='ASSESSMENT_DEADLINE_EXCEEDED'): client.get(TARGET)
    timeout = s.request.call_args.kwargs['timeout']
    assert timeout.total == timeout.connect_timeout == timeout.read_timeout == 3
    with pytest.raises(ProviderFailure, match='ASSESSMENT_DEADLINE_EXCEEDED'): client.get(TARGET)
    assert s.request.call_count == 1 and client.deadline == 60


def test_twenty_request_limit_is_unchanged():
    clock = Clock(); s = http_session(clock)
    client = StrictClient(PassivePolicy(), session=s, clock=clock)
    for _ in range(20): assert client.get(TARGET).status_code == 200
    with pytest.raises(ProviderFailure, match='REQUEST_BUDGET_EXCEEDED'): client.get(TARGET)
    assert s.request.call_count == 20


def test_scope_failure_code_redirect_never_sent():
    clock = Clock(); s = http_session(clock)
    s.request.side_effect = lambda *a, **kw: response(status=303, headers={'Location': 'https://evil.test/?token=DO_NOT_PERSIST'})
    client = StrictClient(PassivePolicy(), session=s, clock=clock)
    with pytest.raises(ProviderFailure, match='SCOPE_INTEGRITY_FAILURE'): client.get(TARGET)
    assert s.request.call_count == 1
    assert 'DO_NOT_PERSIST' not in json.dumps(client.transcript)


@pytest.mark.parametrize('delay', [2.5, 4.0])
def test_zap_api_healthy_slow_control_response_has_same_bounded_timeout(delay):
    clock = Clock(); s = http_session(clock, delay, b'{"version":"2.17.0"}')
    api = ZapAPI('http://127.0.0.1:8081', 'DO_NOT_PERSIST', session=s, clock=clock)
    assert api.call('core', 'view', 'version')['version'] == '2.17.0'
    timeout = s.get.call_args.kwargs['timeout']
    assert timeout.connect_timeout == 3 and timeout.read_timeout == timeout.total == 8
    assert s.get.call_args.kwargs['allow_redirects'] is False


@pytest.mark.parametrize('error,code', [
    (requests.ConnectTimeout('DO_NOT_PERSIST'), 'CONNECT_TIMEOUT'),
    (requests.ReadTimeout('DO_NOT_PERSIST'), 'READ_TIMEOUT'),
    (requests.ConnectionError('DO_NOT_PERSIST'), 'TARGET_UNREACHABLE'),
])
def test_unavailable_zap_has_control_reason_and_no_historical_findings(error, code):
    clock = Clock(); s = http_session(clock); s.get.side_effect = error
    api = ZapAPI('http://127.0.0.1:8081', 'DO_NOT_PERSIST', session=s, clock=clock)
    z = ZapPassiveProvider(api, clock=clock)
    result = z.start_assessment('unavailable-fixture', PassivePolicy())
    assert result['status'] == 'UNAVAILABLE' and result['findings'] == []
    assert result['error_code'] == 'ZAP_API_UNAVAILABLE' and result['cause_code'] == code
    assert 'DO_NOT_PERSIST' not in json.dumps(result)


@pytest.mark.parametrize('delay,status,body,cause', [
    (8.1, 200, b'{"version":"2.17.0"}', 'READ_TIMEOUT'),
    (0, 503, b'DO_NOT_PERSIST', 'HTTP_ERROR'),
    (0, 200, b'DO_NOT_PERSIST', 'PROTOCOL_ERROR'),
])
def test_zap_api_timeout_http_error_and_malformed_response_fail_closed(delay, status, body, cause):
    clock = Clock(); s = http_session(clock, delay, body, status)
    api = ZapAPI('http://127.0.0.1:8081', 'DO_NOT_PERSIST', session=s, clock=clock)
    with pytest.raises(ProviderFailure) as caught: api.call('core', 'view', 'version')
    assert caught.value.code == 'ZAP_API_UNAVAILABLE' and caught.value.cause_code == cause
    assert 'DO_NOT_PERSIST' not in str(caught.value)


class PassiveAPI:
    origin = 'http://127.0.0.1:8081'
    def __init__(self, clock, queue=False, shared=False):
        self.clock, self.queue, self.shared = clock, queue, shared
        self.urls_reads = 0; self.enabled = False
    def call(self, component, kind, name, **kw):
        if name == 'version':
            self.clock.advance(4)
            return {'version': '2.17.0'}
        if name == 'newSession':
            self.urls_reads = 0
            return {'Result': 'OK'}
        if name == 'urls':
            self.urls_reads += 1
            return {'urls': [TARGET] if self.shared else [TARGET+p for p in PAGES] if self.urls_reads > 1 else []}
        if name == 'scans': return {'scans': []}
        if name == 'mode': return {'mode': 'safe'}
        if name == 'setEnabled': self.enabled = True
        if name == 'recordsToScan': return {'recordsToScan': '1' if self.queue and self.enabled else '0'}
        if name == 'alerts': return {'alerts': []}
        if name == 'numberOfMessages': return {'numberOfMessages': '0' if self.urls_reads < 2 else '5'}
        if name == 'messages':
            return {'messages': [] if self.urls_reads < 2 else [
                {'id': str(i+1), 'type': '1', 'requestHeader': f'GET {TARGET+p} HTTP/1.1\r\nHost: 192.168.226.132\r\nUser-Agent: Moodle-Operational-Posture/2.0\r\n\r\n',
                 'responseHeader': 'HTTP/1.1 200 OK\r\n\r\n', 'requestBody': '', 'responseBody': 'fixture'}
                for i,p in enumerate(PAGES)]}
        return {'Result': 'OK'}


def test_zap_queue_deadline_includes_availability_and_has_specific_failure():
    clock = Clock(); api = PassiveAPI(clock, queue=True); s = http_session(clock)
    z = ZapPassiveProvider(api, lambda p, proxy: StrictClient(p, proxy=proxy, session=s, clock=clock),
                           clock=clock, pause=clock.advance)
    result = z.start_assessment('queue-fixture', PassivePolicy())
    assert clock.value == 60  # Four-second availability probe is inside the same 60s budget.
    assert result['status'] == 'FAILED' and result['findings'] == []
    assert result['error_code'] == 'PASSIVE_QUEUE_TIMEOUT'
    assert result['provenance']['policy']['max_duration_seconds'] == 60
    assert s.request.call_count == len(PAGES)


def test_zap_proxy_accepts_four_second_reviewed_page_responses():
    clock = Clock(); s = http_session(clock, delay=4)
    z = ZapPassiveProvider(PassiveAPI(clock),
        lambda p, proxy: StrictClient(p, proxy=proxy, session=s, clock=clock), clock=clock)
    result = z.start_assessment('slow-proxy', PassivePolicy())
    assert result['status'] == 'COMPLETE' and result['passive_queue_complete']
    assert s.request.call_count == len(PAGES) and clock.value == 24
    assert all(call.kwargs['timeout'].total == 8 for call in s.request.call_args_list)


def test_zap_availability_request_is_capped_by_remaining_provider_deadline():
    clock = Clock(); s = http_session(clock, delay=4, body=b'{"version":"2.17.0"}')
    api = ZapAPI('http://127.0.0.1:8081', 'DO_NOT_PERSIST', session=s, clock=clock)
    result = ZapPassiveProvider(api, clock=clock).availability(control_deadline=2)
    assert result['status'] == 'UNAVAILABLE'
    assert result['cause_code'] == 'ASSESSMENT_DEADLINE_EXCEEDED'
    assert s.get.call_args.kwargs['timeout'].total == 2


def test_zap_proxy_and_scope_failures_are_distinguished_and_sanitized():
    clock = Clock(); s = http_session(clock); s.request.side_effect = requests.ReadTimeout('DO_NOT_PERSIST')
    z = ZapPassiveProvider(PassiveAPI(clock),
        lambda p, proxy: StrictClient(p, proxy=proxy, session=s, clock=clock), clock=clock)
    result = z.start_assessment('proxy-fixture', PassivePolicy())
    assert result['error_code'] == 'ZAP_PROXY_FAILURE' and result['cause_code'] == 'READ_TIMEOUT'
    assert result['provenance']['requests'][0]['error_code'] == 'READ_TIMEOUT'
    assert result['findings'] == [] and 'DO_NOT_PERSIST' not in json.dumps(result)
    result = ZapPassiveProvider(PassiveAPI(clock, shared=True), clock=clock).start_assessment('shared', PassivePolicy())
    assert result['error_code'] == 'SCOPE_INTEGRITY_FAILURE' and result['findings'] == []
