"""Operational readiness probes; never reads Apache contents or trains models."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import tempfile
from .backend.config import Config, ROOT
from .backend.services import Application


def preflight(mode='ACCEPTED_REPLAY', port=8000, config=None, check_port=True):
    config = config or Config()
    if mode not in ('ACCEPTED_REPLAY', 'LIVE_LAB') or not 1024 <= port <= 65535:
        raise ValueError('Invalid mode or port')
    checks = []
    def add(name, passed, detail, required=True):
        checks.append({'check': name, 'status': 'PASS' if passed else 'FAIL' if required else 'WARNING', 'detail': detail})
    app = Application(config)
    model = app.model()
    add('accepted_model', model['integrity'] == 'VERIFIED', model.get('package_id') or model.get('error'))
    add('python_dependencies', all(importlib.util.find_spec(n) for n in ('fastapi','uvicorn','numpy','sklearn','xgboost')), 'Required imports discoverable; no fitting invoked')
    index = ROOT / 'demo/frontend/dist/index.html'
    assets = []
    if index.is_file():
        import re
        assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', index.read_text())
    add('frontend', bool(assets) and all((index.parent / a.lstrip('/')).is_file() for a in assets), 'Built index and referenced local assets')
    source = Path(config.apache_source)
    add('apache_exists', source.is_file(), 'Apache source exists; contents were not opened', mode == 'LIVE_LAB')
    add('apache_readable', source.is_file() and os.access(source, os.R_OK), 'Read permission only; no permission/group changes', mode == 'LIVE_LAB')
    runtime = Path(config.repository) / 'runtime'
    try:
        runtime.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='preflight-', dir=runtime) as tmp:
            db = sqlite3.connect(Path(tmp) / 'probe.sqlite3')
            db.execute('CREATE TABLE probe (value INTEGER)'); db.execute('INSERT INTO probe VALUES (1)'); db.commit(); db.close()
            p = Path(tmp) / 'checkpoint.json'; p.write_text('{}\n'); assert json.loads(p.read_text()) == {}
        add('runtime_sqlite_checkpoint_probe', True, 'Temporary SQLite commit and checkpoint read/write succeeded; existing journals untouched')
    except (OSError, sqlite3.Error):
        add('runtime_sqlite_checkpoint_probe', False, 'Runtime storage is not writable')
    if config.runtime_session:
        path = Path(config.repository) / config.runtime_session / 'checkpoint.json'
        add('selected_checkpoint', path.is_file() and os.access(path, os.R_OK | os.W_OK), 'Configured checkpoint permissions; file not modified', mode == 'LIVE_LAB')
    if check_port:
        try:
            with socket.socket() as probe:
                # Match Uvicorn's listener semantics: closed TCP connections can
                # remain in TIME_WAIT after graceful shutdown. This does not
                # permit binding over an existing listening backend.
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(('127.0.0.1', port))
            add('api_port', True, f'Loopback port {port} available')
        except OSError:
            add('api_port', False, f'Loopback port {port} is unavailable or binding is prohibited')
    free = shutil.disk_usage(config.repository).free
    add('disk_minimum', free >= 200 * 1024**2, f'{free} free bytes; operational minimum 200 MiB')
    add('disk_recommended', free >= 1024**3, 'Recommended free space >=1 GiB', False)
    try:
        app.research(); s = app.snapshot(replay='BENIGN_TEST')
        add('accepted_evidence', bool(s['observations']) and not s['status'].last_error, 'Locked posture, blind benign and attack evidence verified; metrics not recomputed')
    except (OSError, ValueError, KeyError):
        add('accepted_evidence', False, 'Locked research/evidence prerequisite failed')
    result = 'FAIL' if any(c['status'] == 'FAIL' for c in checks) else 'PASS_WITH_WARNINGS' if any(c['status'] == 'WARNING' for c in checks) else 'PASS'
    return {'result': result, 'mode': mode, 'port': port, 'checks': checks, 'disk_free_bytes': free,
        'model_package_id': model.get('package_id'), 'accepted_root_sha256': model.get('root_sha256'),
        'training_performed': False, 'apache_contents_opened': False,
        'apache_remediation': ['Ask the host administrator to confirm the log-reading group with: stat -c "%A %U %G" /var/log/apache2/access.log',
            'If the group is adm, ask the administrator to run: sudo usermod -aG adm "$USER"',
            'Log out and back in; verify with: id; test -r /var/log/apache2/access.log',
            'Use accepted replay while permission is unavailable. Do not chmod 777 or run the application as root.']}
