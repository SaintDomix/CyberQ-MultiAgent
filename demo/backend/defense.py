"""Actual application backend in a non-operational, read-only parallel process.

No fixture adapters or proxy to port8000. The process-local audit boundary is
additional protection for reviewed Python code, not an untrusted-code sandbox.
"""
from collections import Counter
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit,parse_qs,unquote

ROOT=Path(__file__).resolve().parents[2]


class CandidateBoundary:
    def __init__(self,state_dir,journal):
        self.state=Path(state_dir).resolve();self.journal=Path(journal).resolve();self.denied=Counter()
        if self.state==Path('/tmp') or not self.state.is_relative_to(Path('/tmp')) or self.state.is_relative_to(ROOT):
            raise ValueError('Independent temporary state directory required')
    def reject(self,code):
        self.denied[code]+=1
        raise PermissionError(code)
    def writable(self,path):
        if isinstance(path,int):return path in (0,1,2)  # no writable pre-opened evidence handles
        try:return Path(os.fsdecode(path)).resolve().is_relative_to(self.state)
        except (TypeError,ValueError,OSError):return False
    def __call__(self,event,args):
        if event=='open':
            path,mode,flags=args
            if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND) and not self.writable(path):
                self.reject('CANDIDATE_FILESYSTEM_READ_ONLY')
        elif event in ('os.mkdir','os.remove','os.rmdir','os.chmod','os.chown','os.truncate','os.utime'):
            if not self.writable(args[0]):self.reject('CANDIDATE_FILESYSTEM_READ_ONLY')
        elif event in ('os.rename','os.replace'):
            if not all(self.writable(p) for p in args[:2]):self.reject('CANDIDATE_FILESYSTEM_READ_ONLY')
        elif event in ('os.link','os.symlink'):self.reject('CANDIDATE_LINKS_DISABLED')
        elif event=='sqlite3.connect':
            value=os.fsdecode(args[0])
            if value==':memory:':return
            url=urlsplit(value)
            if (url.scheme!='file' or parse_qs(url.query)!={'mode':['ro']}
                    or Path(unquote(url.path)).resolve()!=self.journal):
                self.reject('CANDIDATE_SQLITE_READ_ONLY')
        elif event=='socket.connect':self.reject('CANDIDATE_OUTBOUND_NETWORK_DISABLED')
        elif event=='socket.getaddrinfo' and args[0] not in ('127.0.0.1','localhost',None):
            self.reject('CANDIDATE_DNS_DISABLED')
        elif event=='socket.bind' and args[1]!=('127.0.0.1',18010):self.reject('CANDIDATE_LOOPBACK_PORT_ONLY')
        elif event in ('subprocess.Popen','os.system','os.posix_spawn','os.fork','os.exec'):
            self.reject('CANDIDATE_SUBPROCESS_DISABLED')
        elif event=='os.kill' and args[0]!=os.getpid():self.reject('CANDIDATE_EXTERNAL_SIGNAL_DISABLED')
        elif event=='os.killpg':self.reject('CANDIDATE_EXTERNAL_SIGNAL_DISABLED')


def create_candidate(assets,session,state_dir,*,install_boundary=True):
    assets=Path(assets).resolve();session=Path(session).resolve()
    if (not assets.is_relative_to(ROOT/'demo/frontend') or assets==ROOT/'demo/frontend/dist'
            or not (assets/'index.html').is_file()):raise ValueError('Verified separate frontend assets required')
    if not session.is_relative_to(ROOT/'runtime/behavioral_v2') or not (session/'journal.sqlite3').is_file():
        raise ValueError('Existing accepted journal required; never creates a live session')
    import hashlib,json
    manifest=json.loads((ROOT/'outputs/ux/final_stabilization_20261104_06/preview_assets_sha256.json').read_text())
    actual={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in assets.rglob('*') if p.is_file()}
    if actual!=manifest or any(p.is_symlink() for p in assets.rglob('*')):raise ValueError('Candidate asset identity mismatch')
    boundary=CandidateBoundary(state_dir,session/'journal.sqlite3')
    if install_boundary:sys.addaudithook(boundary)
    # Never adopt the main process's ZAP ownership or credentials.
    for key in ('POSTURE_ZAP_OWNED_EPHEMERAL','POSTURE_ZAP_API_KEY','POSTURE_ZAP_API_ORIGIN'):
        os.environ.pop(key,None)
    # Guard is installed before real backend/provider constructors are imported.
    from fastapi import APIRouter
    from .config import Config
    from .services import Application
    from .app import create_app
    config=Config(mode='LIVE_LAB',runtime_session=str(session.relative_to(ROOT)))
    service=Application(config)  # real LiveControl and real PostureAssessmentOrchestrator
    service.preview_read_only=True  # existing UI capability field, not a fixture flag
    if service.model()['integrity']!='VERIFIED':raise ValueError('Accepted package integrity failure')
    assert service.control.process is None and not service.posture_service.jobs
    assert service.posture_service.providers['zap'].owned_ephemeral is False
    app=create_app(config,application=service,frontend_dir=assets,read_only=True)
    info=APIRouter()
    def status():
        return {'candidate':'PARALLEL_REAL_BACKEND_READ_ONLY','port':18010,'bind':'127.0.0.1',
            'application_class':type(service).__name__,'posture_class':type(service.posture_service).__name__,
            'control_class':type(service.control).__name__,'fixtures_used':False,'proxy_to_original':False,
            'operational_authorization':False,'mutations':'BLOCKED','scanner_probes':'BLOCKED',
            'outbound_network':'BLOCKED','subprocesses':'BLOCKED','protected_filesystem':'READ_ONLY',
            'assets':str(assets),'journal':str(session/'journal.sqlite3'),'sqlite':'mode=ro; query_only=ON',
            'temporary_state':str(boundary.state),'owned_monitor':service.control.process is not None,
            'owned_jobs':len(service.posture_service.jobs),'boundary_denials':dict(boundary.denied),
            'model_root':service.model()['root_sha256'],
            'note':'External journal availability does not establish candidate-owned monitoring. Operations require separate authorization and isolation review.'}
    def scanner():
        latest=service.posture_service.latest()
        return {'runtime_status':'NOT_PROBED','assessment_readiness':'BLOCKED_PARALLEL_READ_ONLY',
            'status':'NOT_PROBED','mode':(latest or {}).get('mode','STANDARD'),'version':None,
            'target':(latest or {}).get('target'),'latest_attempt_status':(latest or {}).get('status','NONE'),
            'last_successful_assessment':service.posture_service.retained_zap(),
            'reason_code':'NO_ZAP_OWNERSHIP_OR_OPERATIONAL_AUTHORIZATION','authenticated_coverage':'NOT_VALIDATED'}
    info.add_api_route('/api/candidate/status',status,methods=['GET'])
    info.add_api_route('/api/scanners/zap',scanner,methods=['GET'])
    info.add_api_route('/api/scanners/zap/status',scanner,methods=['GET'])
    info.add_api_route('/api/scanners',lambda:{'items':[], 'profiles':['STANDARD','FULL_AUTHORIZED','PASSIVE_BASELINE'],
        'runtime_status':'NOT_PROBED','reason':'Existing production scanner implementations retained; network probes and operations blocked in this parallel process.'},methods=['GET'])
    app.router.routes[:]=list(info.routes)+app.router.routes
    app.state.candidate_boundary=boundary
    return app
