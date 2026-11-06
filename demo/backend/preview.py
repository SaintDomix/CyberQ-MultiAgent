"""Read-only UX preview: no monitoring controller, scanner provider or live API client."""
from pathlib import Path
from threading import RLock
from posture.orchestration import PostureAssessmentOrchestrator
from .config import Config,ROOT,confined
from .services import Application


class EvidenceStore(PostureAssessmentOrchestrator):
    def __init__(self,project):
        # Reuse only the hash-verified immutable read methods, without constructing
        # any Native/ZAP provider, active validator or execution orchestrator.
        self.project=Path(project).resolve();self.root=self.project/'runtime/posture'
        self.lock=RLock();self.jobs={}
    def start(self,*args,**kwargs):raise ValueError('Read-only preview')
    def cancel(self,*args,**kwargs):raise ValueError('Read-only preview')
    def scanners(self):return []


class JournalReader:
    process=None
    def __init__(self,config):
        self.session=confined(config.repository,config.runtime_session) if config.runtime_session else None
    def status(self):return {'process_running':None,'process_state':'NOT_PROBED_IN_READ_ONLY_PREVIEW','exit_code':None,'last_error':None}
    def close(self):pass
    def start(self):raise ValueError('No monitoring controller in UX preview')
    def stop(self):raise ValueError('No monitoring controller in UX preview')


def preview_application(config):
    s=Application(config,control=JournalReader(config),posture_service=EvidenceStore(config.repository))
    s.preview_read_only=True
    return s


def create_preview(frontend_dir,session=None):
    from fastapi import APIRouter
    from .app import create_app
    path=Path(frontend_dir).resolve()
    if not path.is_relative_to(ROOT/'demo/frontend') or path==ROOT/'demo/frontend/dist':
        raise ValueError('Isolated preview assets required')
    config=Config(mode='LIVE_LAB' if session else 'ACCEPTED_REPLAY',runtime_session=session)
    service=preview_application(config)
    app=create_app(config,application=service,frontend_dir=path,read_only=True)
    # Existing scanner diagnostics inspect providers; the preview has none.
    # Replace only GET routes with an explicit not-probed response, never a fake failure.
    original=list(app.router.routes)
    def scanner():return {'status':'NOT_PROBED','runtime_status':'NOT_PROBED','assessment_readiness':'READ_ONLY_PREVIEW',
        'mode':'STANDARD','version':None,'target':None,'latest_attempt_status':'NOT_PROBED',
        'last_successful_assessment':service.posture_service.retained_zap(),
        'reason_code':'RUNTIME_PROBES_DISABLED_IN_PREVIEW','authenticated_coverage':'NOT_VALIDATED'}
    r=APIRouter();r.add_api_route('/api/scanners/zap/status',scanner,methods=['GET'])
    r.add_api_route('/api/scanners',lambda:{'items':[],'reason':'RUNTIME_PROBES_DISABLED_IN_PREVIEW'},methods=['GET'])
    app.router.routes[:]=list(r.routes)+original
    return app
