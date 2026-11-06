"""Launcher compatibility; no real server, monitor or scanner is started."""
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from scripts import run_demo, start_cyberquality


@pytest.mark.parametrize('selected', [None, 'demo/frontend/final-assets'])
def test_normal_factory_receives_selected_assets(tmp_path, monkeypatch, selected):
    assets = tmp_path / (selected or 'demo/frontend/dist')
    assets.mkdir(parents=True)
    (assets / 'index.html').write_text('verified build')
    monkeypatch.setattr(run_demo, 'ROOT', tmp_path)
    monkeypatch.setattr('sys.argv', ['run_demo.py', '--port', '8000'] +
        (['--frontend-dir', selected] if selected else []))
    from demo.backend import app
    import uvicorn
    create = Mock(return_value=object()); serve = Mock()
    monkeypatch.setattr(app, 'create_app', create)
    monkeypatch.setattr(uvicorn, 'run', serve)
    run_demo.main()
    assert create.call_args.kwargs == {'frontend_dir': assets}
    assert serve.call_args.kwargs['host'] == '127.0.0.1'
    assert serve.call_args.kwargs['port'] == 8000


def test_frontend_cannot_escape_repository(tmp_path, monkeypatch):
    monkeypatch.setattr(run_demo, 'ROOT', tmp_path)
    monkeypatch.setattr('sys.argv', ['run_demo.py', '--frontend-dir', '../outside'])
    with pytest.raises(ValueError): run_demo.main()


@pytest.fixture
def startup_config(tmp_path, monkeypatch):
    monkeypatch.setattr(start_cyberquality, 'ROOT', tmp_path)
    recovery = tmp_path / 'private-recovery'; recovery.mkdir()
    key = recovery / 'RECOVERY.key'; key.write_text('test-only-key'); key.chmod(0o600)
    assets = tmp_path / 'demo/frontend/final'; assets.mkdir(parents=True)
    (assets / 'index.html').write_text('final')
    config = tmp_path / 'runtime/demo_control'; config.mkdir(parents=True)
    (config / 'cyberquality_startup.json').write_text(json.dumps({
        'recovery_directory': str(recovery), 'mode': 'LIVE_LAB', 'port': 8000,
        'retained_session': 'runtime/behavioral_v2/retained', 'frontend_dir': 'demo/frontend/final'}))
    manifest = tmp_path / 'outputs/ux/final_stabilization_20261104_06'
    manifest.mkdir(parents=True)
    (manifest / 'preview_assets_sha256.json').write_text(json.dumps({
        'demo/frontend/final/index.html': hashlib.sha256(b'final').hexdigest()}))
    decrypt = Mock(return_value=SimpleNamespace(returncode=0, stdout=b'{"POSTURE_ZAP_API_ORIGIN":"http://127.0.0.1:8081","UNRELATED_SECRET":"test-only"}'))
    monkeypatch.setattr(start_cyberquality.subprocess, 'run', decrypt)
    from demo import operations
    launch = Mock(return_value=0); monkeypatch.setattr(operations, 'main', launch)
    # Keep startup environment edits local to this test.
    monkeypatch.setattr(start_cyberquality.os, 'environ', dict(start_cyberquality.os.environ))
    return key, assets, decrypt, launch


def test_restart_uses_existing_lifecycle_explicit_retained_session(startup_config):
    _, _, decrypt, launch = startup_config
    assert start_cyberquality.startup() == 0
    assert launch.call_args.args[0] == ['start', '--mode', 'LIVE_LAB', '--port', '8000',
        '--retained-session', 'runtime/behavioral_v2/retained', '--frontend-dir', 'demo/frontend/final']
    assert start_cyberquality.os.environ['PRODUCT_FACTORY_ONLY'] == '1'
    assert 'UNRELATED_SECRET' not in start_cyberquality.os.environ
    assert decrypt.call_args.kwargs['capture_output']


def test_public_key_permissions_block_restart(startup_config):
    key, _, decrypt, launch = startup_config; key.chmod(0o644)
    with pytest.raises(ValueError): start_cyberquality.startup()
    decrypt.assert_not_called(); launch.assert_not_called()


def test_changed_assets_block_restart(startup_config):
    _, assets, _, launch = startup_config
    (assets / 'index.html').write_text('unexpected')
    with pytest.raises(ValueError): start_cyberquality.startup()
    launch.assert_not_called()


def test_restart_verifies_explicit_patch_manifest(startup_config, tmp_path):
    _, _, _, launch = startup_config
    path = tmp_path / 'runtime/demo_control/cyberquality_startup.json'
    config = json.loads(path.read_text())
    original = tmp_path / 'outputs/ux/final_stabilization_20261104_06/preview_assets_sha256.json'
    manifest = tmp_path / 'runtime/demo_control/patched_assets.json'
    manifest.write_bytes(original.read_bytes())
    config['frontend_manifest'] = str(manifest.relative_to(tmp_path))
    path.write_text(json.dumps(config)); original.unlink()
    assert start_cyberquality.startup() == 0
    launch.assert_called_once()
