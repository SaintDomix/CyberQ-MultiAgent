#!/usr/bin/env python3
"""Foreground coursework server. Stop this owned process with Ctrl-C."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'src')]
from coursework.isolation import install
boundary = install()


def create():
    from demo.backend.app import create_app
    from demo.backend.config import Config
    import json
    assets=ROOT/'demo/frontend/behavioral-controls-20261105'
    pointer=ROOT/'runtime/coursework/frontend/current.json'
    if pointer.is_file():
        selected=(ROOT/json.loads(pointer.read_text())['path']).resolve()
        if not selected.is_relative_to(ROOT/'runtime/coursework/frontend') or not (selected/'index.html').is_file():
            raise ValueError('Coursework frontend build path is invalid')
        assets=selected
    from coursework.lab import available
    app = create_app(Config(mode='LIVE_LAB' if available() else 'ACCEPTED_REPLAY'), frontend_dir=assets)
    from coursework.multiagent.engine import Coordinator
    from coursework.multiagent.api import router as multiagent_router
    engine=Coordinator(application=app.state.service)
    app.state.multiagent=engine
    routes=list(multiagent_router(engine).routes)
    app.router.routes[:0]=routes
    from fastapi.exceptions import RequestValidationError
    previous_invalid=app.exception_handlers[RequestValidationError]
    @app.exception_handler(RequestValidationError)
    async def invalid_multiagent(request,exc):
        if request.url.path.startswith('/api/multiagent/'):
            engine.store.reject('INVALID_REQUEST_SCHEMA','multiagent-api')
        return await previous_invalid(request,exc)

    @app.middleware('http')
    async def lab_gate(request, call_next):
        if request.method == 'POST' and (
            request.url.path.startswith(('/api/runtime/', '/api/posture/assessments', '/api/scanners/'))
        ):
            # Cleanup can stop only this application's owned monitor, even if
            # its lease expired. Every start/scan still requires a valid lease.
            owned_cleanup=(request.url.path=='/api/runtime/stop' and
                           app.state.service.control.status()['process_running'] is True)
            if not available() and not owned_cleanup:
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=423, content={'error': 'COURSEWORK_LAB_LOCKED',
                    'message': 'Live operations require a separate authorized exclusive lab handoff.'})
        return await call_next(request)

    @app.get('/api/coursework/isolation')
    def isolation_status():
        return {'workspace': str(ROOT), 'port': 8001, 'bind': '127.0.0.1',
                'write_root': str(ROOT/'runtime/coursework'), 'live_access': 'AUTHORIZED_LEASE' if available() else 'LOCKED',
                'database': 'No live database opened; copied journals immutable read-only',
                'boundary_denials': dict(boundary.denials)}
    # Place the diagnostic before the application's unknown-API and static routes.
    app.router.routes.insert(0, app.router.routes.pop())

    # Imported operational snapshots remain inspectable without becoming current
    # coursework assessments or process ownership records.
    from posture.orchestration import PostureAssessmentOrchestrator
    from demo.backend.privacy import sanitize
    service = app.state.service
    archive = PostureAssessmentOrchestrator(ROOT, service.posture_service.catalog)

    from fastapi import Query
    @app.get('/api/coursework/history')
    def copied_history(limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
        rows = archive.history()
        keys = ('assessment_id', 'started_at', 'completed_at', 'status', 'target', 'mode')
        return {'scope': 'IMPORTED_HISTORICAL_ONLY', 'counted_as_current': False,
                'total': len(rows), 'limit': limit, 'offset': offset,
                'items': sanitize([{k: row.get(k) for k in keys} for row in rows[offset:offset+limit]])}
    app.router.routes.insert(0, app.router.routes.pop())

    @app.get('/api/coursework/history/{assessment_id}')
    def copied_assessment(assessment_id: str):
        return {'scope': 'IMPORTED_HISTORICAL_ONLY', 'counted_as_current': False,
                'assessment': sanitize(archive.get(assessment_id))}
    app.router.routes.insert(0, app.router.routes.pop())
    return app


if __name__ == '__main__':
    import uvicorn
    app=create()
    try:uvicorn.run(app, host='127.0.0.1', port=8001, access_log=False, log_level='warning')
    finally:app.state.multiagent.close()
