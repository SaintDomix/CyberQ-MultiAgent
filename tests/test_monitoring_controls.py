"""Actual monitoring API/lifecycle with fake children only; no live operations."""
from unittest.mock import Mock
import signal
import pytest
from demo.backend.app import create_app
from demo.backend.config import Config
from demo.backend.preview import preview_application
from demo.backend.runtime import LiveControl
from test_ux_clarity import request


@pytest.fixture
def fixture(tmp_path):
    apache = tmp_path / 'access.log'; apache.write_text('')
    config = Config(mode='LIVE_LAB', apache_source=str(apache))
    service = preview_application(config); service.preview_read_only = False
    service.model = Mock(return_value={'integrity': 'VERIFIED'})
    child = Mock(); child.poll.return_value = None
    child.wait.side_effect = lambda **kw: setattr(child.poll, 'return_value', 0) or 0
    factory = Mock(return_value=child)
    service.control = LiveControl(config, factory=factory)
    return service, child, factory, create_app(config, service)


def test_status_reads_lifecycle_without_reading_historical_evidence(fixture):
    service, _, factory, app = fixture
    service.snapshot = Mock(side_effect=AssertionError('Journal is not process ownership'))
    value = request(app, 'GET', '/api/runtime/control').json()
    assert value['schema_version'] == 'monitor-control-1.0'
    assert value['scope'] == 'APPLICATION_OWNED_MONITOR'
    assert value['process_running'] is False and value['start_available']
    assert not value['stop_available']
    factory.assert_not_called(); service.snapshot.assert_not_called()


def test_existing_start_stop_and_duplicate_guard_with_fake_child(fixture):
    service, child, factory, app = fixture
    header = {'X-Product-Control': '1'}
    assert request(app, 'POST', '/api/runtime/start', json={}).status_code == 403
    factory.assert_not_called()
    assert request(app, 'POST', '/api/runtime/start', headers=header, json={}).status_code == 200
    state = request(app, 'GET', '/api/runtime/control').json()
    assert state['process_running'] and state['stop_available'] and not state['start_available']
    assert request(app, 'POST', '/api/runtime/start', headers=header, json={}).status_code == 503
    factory.assert_called_once()
    assert request(app, 'POST', '/api/runtime/stop', headers=header, json={}).status_code == 200
    child.send_signal.assert_called_once_with(signal.SIGINT)
    state = request(app, 'GET', '/api/runtime/control').json()
    assert not state['process_running'] and state['start_available'] and not state['stop_available']


@pytest.mark.parametrize('reason', ['MODEL_INTEGRITY_FAILED', 'APACHE_SOURCE_UNREADABLE', 'LIVE_LAB_REQUIRED'])
def test_unavailable_prerequisites_are_explicit(fixture, reason):
    service, _, factory, _ = fixture
    if reason == 'MODEL_INTEGRITY_FAILED': service.model.return_value = {'integrity': 'FAILED'}
    elif reason == 'APACHE_SOURCE_UNREADABLE':
        from pathlib import Path
        Path(service.config.apache_source).unlink()
    else: service.current_mode = 'ACCEPTED_REPLAY'
    app = create_app(service.config, service)
    state = request(app, 'GET', '/api/runtime/control').json()
    assert not state['start_available'] and state['unavailable_reason'] == reason
    factory.assert_not_called()


def test_preview_keeps_operational_requests_blocked(fixture):
    service, _, factory, _ = fixture
    app = create_app(service.config, service, read_only=True)
    state = request(app, 'GET', '/api/runtime/control').json()
    assert not state['start_available'] and not state['stop_available']
    assert state['unavailable_reason'] == 'READ_ONLY_PREVIEW'
    assert request(app, 'POST', '/api/runtime/start', headers={'X-Product-Control': '1'}, json={}).status_code == 403
    factory.assert_not_called()


def test_unknown_controller_is_not_reported_stopped(fixture):
    service, _, factory, _ = fixture
    service.control.status = lambda: {'process_running': None, 'process_state': 'UNKNOWN', 'last_error': None}
    state = request(create_app(service.config, service), 'GET', '/api/runtime/control').json()
    assert state['process_running'] is None and not state['start_available'] and not state['stop_available']
    factory.assert_not_called()
