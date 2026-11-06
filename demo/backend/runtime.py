"""Read-only accepted runtime journal plus explicit loopback process controls."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import uuid
import os
import time
from .config import confined, ROOT


class SourceUnavailable(ValueError):
    pass


def read_journal(root, package_id, schema_hash, *, include_features=False):
    root = Path(root)
    manifest = json.loads((root / 'session_manifest.json').read_text())
    if manifest['model_id'] != package_id or manifest['schema_sha256'] != schema_hash:
        raise SourceUnavailable('Runtime package identity does not match accepted Behavioral v2')
    import os
    # Copied journals are snapshots: immutable avoids creating WAL/SHM sidecars.
    changing_coursework_store = root.resolve().is_relative_to(ROOT/'runtime/coursework')
    query = '?mode=ro&immutable=1' if os.getenv('COURSEWORK_OFFLINE') == '1' and not changing_coursework_store else '?mode=ro'
    db = sqlite3.connect((root / 'journal.sqlite3').as_uri() + query, uri=True, timeout=2)
    try:
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        predictions, incidents = [], []
        for sequence, rid, payload, expected in db.execute('SELECT sequence,record_id,payload,sha256 FROM results ORDER BY sequence'):
            if hashlib.sha256(payload.encode()).hexdigest() != expected:
                raise SourceUnavailable('Runtime observation journal integrity failed')
            stored = json.loads(payload)
            p = stored['prediction']
            if (sequence != len(predictions) + 1 or p['sequence'] != sequence or p['record_id'] != rid
                    or p['model_id'] != package_id or p['schema_sha256'] != schema_hash or p['training_performed'] is not False):
                raise SourceUnavailable('Runtime observation identity failed')
            if include_features:
                from .explanation_sources import live_window_evidence
                values, evidence = live_window_evidence(stored, package_id, schema_hash, expected)
                p['_explanation_features'] = values
                p['_explanation_evidence'] = evidence
            predictions.append(p)
        for payload, expected in db.execute('SELECT payload,sha256 FROM incidents ORDER BY episode_id'):
            if hashlib.sha256(payload.encode()).hexdigest() != expected:
                raise SourceUnavailable('Runtime incident integrity failed')
            p = json.loads(payload)
            if p['model_id'] != package_id or p['successful_exploitation_confirmed'] is not False:
                raise SourceUnavailable('Runtime incident identity failed')
            incidents.append(p)
        cursor = db.execute('SELECT sequence FROM episode_cursor WHERE singleton=1').fetchone()[0]
        if cursor != len(predictions):
            raise SourceUnavailable('Incident projection is catching up; retry next poll')
    finally:
        db.close()
    checkpoint = json.loads((root / 'checkpoint.json').read_text())
    summary_path = root / 'session_summary.json'
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}
    return predictions, incidents, {'available': True, 'session_id': manifest['session_id'],
        'sqlite_status': 'VERIFIED_READ_ONLY', 'source': manifest['source_path'],
        'reader_offset': checkpoint['source']['read_offset'], 'safe_offset': checkpoint['source']['safe_offset'],
        'checkpoint_at': checkpoint['updated_at_utc'], 'observations_processed': len(predictions),
        'incidents_created': len(incidents), 'last_observation': predictions[-1]['window_end'] if predictions else None,
        'integrity_status': checkpoint['integrity_status'], 'last_error': summary.get('stop_reason') if summary.get('integrity_status') not in (None, 'OK') else None,
        'process_running': None, 'process_state': 'EXTERNALLY_MANAGED_UNKNOWN',
        'note': 'An available journal is not proof a monitoring process is running.'}


class LiveControl:
    """Own only the child started here. No arbitrary frontend arguments or paths."""
    def __init__(self, config, factory=subprocess.Popen):
        self.config, self.factory = config, factory
        self.process = None
        self.session = confined(config.repository, config.runtime_session) if config.runtime_session else None
        self.lock = threading.RLock()
        self.startup_error = None

    def status(self):
        code = self.process.poll() if self.process else None
        return {'process_running': self.process is not None and code is None,
                'process_state': 'RUNNING' if self.process and code is None else 'ERROR' if code not in (None, 0) else 'STOPPED' if self.process else 'NOT_STARTED_BY_APPLICATION',
                'exit_code': code, 'session': self.session.name if self.session else None,
                'last_error': self.startup_error or ('Owned inference process exited unsuccessfully; inspect retained runtime audit.' if code not in (None, 0) else None)}

    def start(self):
        from coursework.isolation import require_live_owner
        require_live_owner()
        with self.lock:
            if self.process and self.process.poll() is None:
                raise SourceUnavailable('Monitoring is already running')
            source = Path(self.config.apache_source)
            if not source.is_file():
                raise SourceUnavailable('Apache source is unavailable')
            # Test readability, without opening or consuming raw log records.
            import os
            if not os.access(source, os.R_OK):
                raise SourceUnavailable('Apache source is not readable by the application account')
            base=confined(self.config.repository,'runtime/coursework/behavioral_v2')
            if base!=Path(self.config.repository).resolve()/'runtime/coursework/behavioral_v2':
                raise SourceUnavailable('MONITOR_PATH_INVALID: runtime parent resolves through a symlink')
            base.mkdir(parents=True,exist_ok=True,mode=0o700)
            session = base/('ui-'+uuid.uuid4().hex)
            diagnostic=base/(session.name+'.worker.log')
            argv = [sys.executable, '-B', str(ROOT / 'scripts/run_behavioral_v2_live.py'), 'run',
                    '--accepted', str(confined(self.config.repository, self.config.accepted)),
                    '--source', str(source), '--out', str(session)]
            self.session = session
            self.startup_error=None
            stage='spawn'
            try:
                # DEVNULL and writable pipe descriptors are correctly forbidden
                # by the write boundary. Use an empty private file for EOF stdin
                # and a separate private file for worker diagnostics.
                fd=os.open(diagnostic,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as log:
                    input_fd=os.open(base/(session.name+'.stdin'),os.O_RDONLY|os.O_CREAT|os.O_EXCL,0o600)
                    with os.fdopen(input_fd,'rb') as empty_input:
                        self.process = self.factory(argv,cwd=ROOT,shell=False,stdin=empty_input,stdout=log,stderr=log)
                if self.process.stdin:self.process.stdin.close()
                stage='registration'
                if self.process.poll() is not None:raise ChildProcessError('Worker exited before registration')
                from coursework.lab import register_worker
                register_worker(self.process.pid)
                stage='initialization'
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    require_live_owner()
                    if self.process.poll() is not None:raise ChildProcessError('Worker exited during initialization')
                    manifest=session/'session_manifest.json';checkpoint=session/'checkpoint.json'
                    if manifest.is_file() and checkpoint.is_file() and (session/'journal.sqlite3').is_file():
                        m=json.loads(manifest.read_bytes());c=json.loads(checkpoint.read_bytes())
                        if (m['session_id']!=c['session_id'] or m['model_id']!=c['model_id']
                                or m['schema_sha256']!=c['schema_sha256'] or m['feature_count']!=83
                                or c['integrity_status']!='OK'):
                            raise SourceUnavailable('MONITOR_STARTUP_IDENTITY_INVALID')
                        status=self.status()
                        if not status['process_running']:raise ChildProcessError('Worker exited before readiness acknowledgment')
                        return status
                    time.sleep(.05)
                raise TimeoutError('Worker did not publish startup state within 15 seconds')
            except (OSError,ValueError) as exc:
                # API diagnostics contain only safe classifications and paths,
                # never stderr, credentials or Apache request content.
                code=str(exc) if str(exc).startswith(('COURSEWORK_','MONITOR_')) and str(exc).replace('_','').isalnum() else type(exc).__name__
                failure=session.with_suffix('.failure.json')
                if failure.is_file():
                    recorded=json.loads(failure.read_bytes())
                    code=recorded.get('code',recorded.get('exception_type',code))
                self.startup_error=f'MONITOR_STARTUP_FAILED: stage={stage}; cause={code}; diagnostic={diagnostic.relative_to(ROOT)}'
                if self.process and self.process.poll() is None:
                    from coursework.lab import owned_worker
                    if owned_worker(self.process.pid):self.stop()
                raise SourceUnavailable(self.startup_error) from exc

    def stop(self):
        with self.lock:
            if self.process and self.process.poll() is None:
                import signal
                self.process.send_signal(signal.SIGINT)
                try:
                    self.process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    try: self.process.wait(timeout=3)
                    except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=3)
            return self.status()

    def close(self):
        self.stop()
