"""Loopback application API: immutable research projections, explicit passive controls."""
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit
from fastapi import FastAPI, Query, Body, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .config import Config, ROOT, confined
from .services import Application
from .runtime import SourceUnavailable
from .schemas import (Mode, Replay, Page, PostureFinding, BehaviorObservation, Incident,
    FusionEvent, CQI, Dimension, State, EmptyAction, ModelInfo, Evidence, ResearchComparison, ApplicationSnapshot,
    RuntimeStatus, Evaluation, Health, Explanation, ProcessState, ModeAction)
from .posture_api import router as posture_router
from .normalization_api import router as normalization_router
from .cqi_api import router as cqi_router
from .product_api import router as product_router
from .research_api import router as research_router


def create_app(config=None, application=None, *, frontend_dir=None, read_only=False):
    config = config or Config.environment()
    service = application or Application(config)

    @asynccontextmanager
    async def lifespan(app):
        yield
        service.control.close()

    app = FastAPI(title='Cybersecurity Quality / Application API', version='2.0',
                  docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.service = service
    app.include_router(posture_router(service))
    app.include_router(normalization_router)
    app.include_router(cqi_router(service))
    app.include_router(product_router(service))
    app.include_router(research_router)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', 'testserver'])

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return JSONResponse(status_code=422, content={'error': 'INVALID_REQUEST', 'message': 'Use supported modes, filters and bounded pagination. Request values are withheld.'})

    @app.exception_handler(SourceUnavailable)
    async def unavailable(request, exc):
        return JSONResponse(status_code=503, content={'error': 'SOURCE_UNAVAILABLE', 'message': str(exc)})

    @app.exception_handler(ValueError)
    @app.exception_handler(OSError)
    async def invalid_source(request, exc):
        return JSONResponse(status_code=503, content={'error': 'SOURCE_INTEGRITY', 'message': 'The required source is missing, invalid or outside its allowed location.'})

    @app.middleware('http')
    async def safety(request: Request, call_next):
        if read_only and request.method not in ('GET','HEAD','OPTIONS'):
            return JSONResponse(status_code=403,content={'error':'READ_ONLY_UX_PREVIEW','message':'Operational controls are disabled in this isolated preview.'})
        if request.method == 'POST':
            origin = request.headers.get('origin')
            try:
                parsed = urlsplit(origin) if origin else None
                allowed = not parsed or (parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1') and not parsed.username and not parsed.password)
            except ValueError:
                allowed = False
            if request.headers.get('X-Product-Control') != '1' or not allowed:
                return JSONResponse(status_code=403, content={'error': 'LOCAL_CONTROL_REQUIRED', 'message': 'Explicit loopback control required.'})
        response = await call_next(request)
        response.headers.update({'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'"})
        return response

    def snapshot(mode=None, replay='ATTACK_HOLDOUT', run_id=None):
        return service.snapshot(mode, replay, run_id)

    def page(items, mode, offset, limit):
        return {'items': items[offset:offset + limit], 'total': len(items), 'offset': offset, 'limit': limit, 'mode': mode or service.current_mode}

    @app.get('/api/health', response_model=Health)
    def health():
        return {'status': 'ok', 'model_integrity': service.model()['integrity'],
            'training_performed': False, 'automatic_execution': False, 'capabilities': ['ACCEPTED_REPLAY', 'LIVE_LAB'], 'mode':service.current_mode,
            'preview_read_only':read_only}

    @app.post('/api/demo/mode')
    def select_mode(body:ModeAction):
        if body.mode=='ACCEPTED_REPLAY' and service.control.process is not None:
            service.control.stop()
        service.current_mode=body.mode
        return {'mode':service.current_mode,'automatic_execution':False}

    @app.get('/api/demo/scenarios')
    def scenarios():
        benign=service.snapshot(mode='ACCEPTED_REPLAY',replay='BENIGN_TEST')
        attack=service.snapshot(mode='ACCEPTED_REPLAY',replay='ATTACK_HOLDOUT')
        normal=next(o.evidence['run_id'] for o in benign['observations'] if o.reconciled_label=='BENIGN')
        known=next(o.evidence['run_id'] for o in attack['observations'] if o.reconciled_label=='SQLI_ATTEMPT')
        unknown=next(o.evidence['run_id'] for o in benign['observations'] if o.reconciled_label=='UNKNOWN_ANOMALY')
        return {'mode':'ACCEPTED_REPLAY','source_label':'ACCEPTED EVIDENCE REPLAY','items':[
            {'id':'NORMAL_BENIGN','title':'A · Normal benign','replay':'BENIGN_TEST','run_id':normal},
            {'id':'KNOWN_ATTEMPT','title':'B · Known attempt','replay':'ATTACK_HOLDOUT','run_id':known},
            {'id':'UNKNOWN_OBSERVATION','title':'C · Suppressed UNKNOWN observation','replay':'BENIGN_TEST','run_id':unknown}],
            'reset':'Selecting a scenario resets evidence/run selection; no traffic, model fitting or state mutation'}

    @app.get('/api/report/final')
    def final_report_metadata():
        base=confined(config.repository,'outputs/reports')
        return {'available':(base/'behavioral_v2_final_report.md').is_file(),
            'markdown_url':'/reports/behavioral-v2.md','json_url':'/reports/behavioral-v2.json',
            'historical_v1_url':'/report.html','scope':'Accepted Behavioral v2 narrative; frozen research evidence only'}

    @app.get('/reports/behavioral-v2.md')
    @app.get('/reports/behavioral-v2.json')
    def final_report(request:Request):
        suffix='json' if request.url.path.endswith('.json') else 'md'
        path=confined(config.repository,'outputs/reports/behavioral_v2_final_report.'+suffix)
        if not path.is_file():raise SourceUnavailable('Final Behavioral v2 report has not been generated')
        return FileResponse(path,media_type='application/json' if suffix=='json' else 'text/plain; charset=utf-8')

    @app.get('/api/system/status', response_model=State)
    def status(mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None):
        return snapshot(mode, replay, run_id)['status']

    @app.get('/api/model', response_model=ModelInfo)
    def model(): return service.model()

    @app.get('/api/application/snapshot', response_model=ApplicationSnapshot)
    def bundle(mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None):
        value = snapshot(mode, replay, run_id)
        return {k: value[k] for k in ('status', 'model', 'posture', 'incidents', 'fusion', 'cqi')} | {
            'observations': list(reversed(value['observations']))[:200]}

    @app.get('/api/model/evaluation', response_model=Evaluation)
    def evaluation(): return service.research()

    @app.get('/api/research/benign-comparison', response_model=ResearchComparison)
    def benign_comparison(): return service.research()['benign']

    @app.get('/api/research/attack-comparison', response_model=ResearchComparison)
    def attack_comparison(): return service.research()['attack']

    @app.get('/api/posture/findings', response_model=Page[PostureFinding])
    def findings(status: str | None = None, category: str | None = None, dimension: str | None = None,
                 severity: str | None = None, mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None,
                 source: str | None = None, assessment_id: str | None = None, view: str | None = None, multi_source: bool | None = None,
                 limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
        if view not in (None, 'current', 'historical'): raise ValueError('Unknown posture view')
        if view == 'current' or assessment_id:
            job = service.posture_service.get(assessment_id) if assessment_id else service.posture_service.current()
            from .adapters import finding
            rows = [finding(f) for f in job.get('findings', [])] if job else []
        else:
            rows = snapshot('ACCEPTED_REPLAY' if view == 'historical' else mode, replay, run_id)['posture']
        for key, value in (('status', status), ('category', category), ('dimension', dimension), ('severity', severity)):
            if value is not None: rows = [r for r in rows if getattr(r, key) == value]
        if source is not None: rows = [r for r in rows if source == r.source or source in r.evidence_sources]
        if multi_source is not None: rows = [r for r in rows if r.multi_source == multi_source]
        return page(rows, mode, offset, limit)

    @app.get('/api/posture/findings/{finding_id}', response_model=PostureFinding)
    def finding_detail(finding_id: str, mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None,
                       view: str | None = None, assessment_id: str | None = None):
        matches = [f for f in findings(mode=mode, replay=replay, run_id=run_id, view=view,
            assessment_id=assessment_id, limit=200, offset=0)['items'] if f.finding_id == finding_id or f.canonical_finding_id == finding_id]
        if not matches: return JSONResponse(status_code=404, content={'error': 'FINDING_NOT_FOUND'})
        return matches[0]

    @app.get('/api/behavior/observations', response_model=Page[BehaviorObservation])
    def observations(label: str | None = None, status: str | None = None, mode: Mode | None = None,
                     replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None,
                     limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
        rows = list(reversed(snapshot(mode, replay, run_id)['observations']))
        if label: rows = [r for r in rows if r.reconciled_label == label]
        if status: rows = [r for r in rows if r.presentation_state == status]
        return page(rows, mode, offset, limit)

    @app.get('/api/behavior/incidents', response_model=Page[Incident])
    def incidents(label: str | None = None, severity: str | None = None, status: str | None = None,
                  mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None,
                  limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
        rows = sorted(snapshot(mode, replay, run_id)['incidents'], key=lambda r: (r.start_time, r.episode_id), reverse=True)
        for key, value in (('behavior_class', label), ('severity', severity), ('status', status)):
            if value: rows = [r for r in rows if getattr(r, key) == value]
        return page(rows, mode, offset, limit)

    @app.get('/api/behavior/incidents/{episode_id}', response_model=Incident)
    def incident_detail(episode_id: str, mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None):
        found = [e for e in snapshot(mode, replay, run_id)['incidents'] if e.episode_id == episode_id]
        if not found: return JSONResponse(status_code=404, content={'error': 'INCIDENT_NOT_FOUND'})
        return found[0]

    @app.get('/api/fusion/events', response_model=Page[FusionEvent])
    def fusion(mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None,
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
        return page(snapshot(mode, replay, run_id)['fusion'], mode, offset, limit)

    @app.get('/api/cqi', response_model=CQI)
    def cqi(mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None):
        result = snapshot(mode, replay, run_id)['cqi']
        if result is None: raise SourceUnavailable('CQI snapshot unavailable; waiting for valid behavioral evidence. No perfect score is substituted.')
        return result

    @app.get('/api/cqi/dimensions', response_model=list[Dimension])
    def dimensions(mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None):
        return cqi(mode, replay, run_id).dimensions

    @app.get('/api/runtime/status', response_model=RuntimeStatus)
    def runtime(mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None):
        return snapshot(mode, replay, run_id)['status'].runtime

    @app.get('/api/runtime/control')
    def monitoring_control():
        # Saved evidence status is independent of this application's child owner.
        # Do not adopt, signal or infer a process from an existing journal.
        state = service.control.status()
        preview = read_only or getattr(service, 'preview_read_only', False)
        source = Path(config.apache_source)
        readable = source.is_file() and os.access(source, os.R_OK)
        from coursework.lab import available
        reason = ('COURSEWORK_LAB_LOCKED' if os.getenv('COURSEWORK_OFFLINE') == '1' and not available() else
            'READ_ONLY_PREVIEW' if preview else
            'LIVE_LAB_REQUIRED' if service.current_mode != 'LIVE_LAB' else
            'MODEL_INTEGRITY_FAILED' if service.model()['integrity'] != 'VERIFIED' else
            'APACHE_SOURCE_UNREADABLE' if not readable else None)
        return {'schema_version': 'monitor-control-1.0', 'scope': 'APPLICATION_OWNED_MONITOR',
            **state, 'start_available': reason is None and state['process_running'] is False,
            'stop_available': not preview and state['process_running'] is True,
            'unavailable_reason': reason}

    @app.get('/api/evidence/{identity}', response_model=Evidence)
    def evidence(identity: str, mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None):
        s = snapshot(mode, replay, run_id)
        for kind, field, rows in (('POSTURE', 'finding_id', s['posture']), ('OBSERVATION', 'observation_id', s['observations']),
                                  ('INCIDENT', 'episode_id', s['incidents']), ('FUSION', 'fusion_event_id', s['fusion'])):
            for row in rows:
                if getattr(row, field) == identity or (kind == 'POSTURE' and row.provenance.get('evidence_id') == identity):
                    return {'evidence_id': identity, 'type': kind, 'data': row.model_dump(by_alias=True)}
        return JSONResponse(status_code=404, content={'error': 'EVIDENCE_NOT_FOUND'})

    @app.get('/api/explainability/{observation_id}', response_model=Explanation)
    def explain(observation_id: str, mode: Mode | None = None, replay: Replay = 'ATTACK_HOLDOUT', run_id: str | None = None):
        for row in snapshot(mode, replay, run_id)['observations']:
            if row.observation_id == observation_id:
                return {'observation_id': observation_id, 'xgb_class': row.xgb_label,
                        'uncalibrated_score': row.xgb_score, **row.explanation}
        return JSONResponse(status_code=404, content={'error': 'OBSERVATION_NOT_FOUND'})

    @app.post('/api/runtime/start', response_model=ProcessState)
    def start(body: EmptyAction = Body(default=EmptyAction())):
        if service.model()['integrity'] != 'VERIFIED': raise SourceUnavailable('Model integrity failed; execution blocked')
        return service.control.start()

    @app.post('/api/runtime/stop', response_model=ProcessState)
    def stop(body: EmptyAction = Body(default=EmptyAction())): return service.control.stop()

    @app.get('/report.html')
    def historical_report():
        path = confined(config.repository, 'outputs/end_to_end/m3c_final_01/report.html')
        if not path.is_file(): raise SourceUnavailable('Historical Model v1 report is unavailable')
        return FileResponse(path, media_type='text/html')

    @app.get('/api/{unknown:path}')
    def unknown(unknown: str): return JSONResponse(status_code=404, content={'error': 'UNKNOWN_ENDPOINT'})

    dist = Path(frontend_dir) if frontend_dir is not None else ROOT / 'demo/frontend/dist'
    if dist.is_dir(): app.mount('/', StaticFiles(directory=dist, html=True), name='frontend')
    return app


import os
app = None if os.getenv('PRODUCT_FACTORY_ONLY') == '1' else create_app()
