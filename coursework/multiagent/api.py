"""Loopback task API; attached only to the coursework launcher, before SPA fallback."""
from typing import Annotated
from fastapi import APIRouter, HTTPException, Path
from .agents import specifications
from .models import TaskRequest, TaskError
from .store import public_state
from .engine import call_distribution

TaskId=Annotated[str,Path(pattern=r'^ma-[0-9a-f]{32}$')]


def router(engine):
    r=APIRouter(prefix='/api/multiagent',tags=['coursework-multiagent'])

    @r.get('/spec')
    def spec():
        from coursework.lab import available
        return {'schema_version':'cqma-api-1.0','agents':specifications(),
            'tools':[{'name':name,'owner':entry[0],'integration':entry[1],
                      'input_contract':'ToolArguments','output_contract':'ToolResult'} for name,entry in engine.registry.items()],
            'task_schema':TaskRequest.model_json_schema(),
            'scenarios':list(TaskRequest.model_fields['scenario'].annotation.__args__),
            'live_gate':'AUTHORIZED_LEASE' if available() else 'LOCKED','llm':'No LLM calls; deterministic specialists and existing frozen ML',
            'modes':['OFFLINE_EVIDENCE','LIVE_LAB'],
            'live_behavioral_source':'Existing application-owned monitor journal; no replay fallback or monitor lifecycle actions',
            'external_integrations':['Preserved filesystem artifact store','Immutable SQLite observation journal'],
            'deadline_semantics':'Cooperative tool/task deadlines; late results discarded. Native ML calls are not forcibly interrupted.',
            'storage':'runtime/coursework/multiagent/tasks.sqlite3'}

    @r.post('/tasks',status_code=202)
    def start(body:TaskRequest):
        try:return public_state(engine.submit(body))
        except TaskError as exc:
            engine.store.reject(exc.code,'multiagent-api')
            raise HTTPException(409,detail={'code':exc.code,'message':exc.safe_message}) from None

    @r.get('/tasks')
    def tasks():
        return {'items':[{'task_id':s.task_id,'scenario':s.request.scenario,'mode':s.request.mode,
                           'status':s.status,'created_at':s.created_at} for s in engine.store.list()]}

    @r.get('/official')
    def official():
        state=engine.store.official()
        return {'task_id':state.task_id,'completed_at':state.updated_at,'mode':state.request.mode,
                'cqi':state.result['cqi']} if state else {'task_id':None,'cqi':None}

    @r.get('/tasks/{task_id}/assessment')
    def assessment(task_id:TaskId):
        from .views import assessment_view
        try:return assessment_view(engine.store.get(task_id))
        except TaskError as exc:raise HTTPException(404,detail=exc.code) from None

    @r.get('/tasks/{task_id}')
    def task(task_id:TaskId):
        try:
            value=public_state(engine.store.get(task_id))
            value['distribution']=call_distribution(engine.store.events(task_id))
            return value
        except TaskError as exc:raise HTTPException(404,detail=exc.code) from None

    @r.get('/tasks/{task_id}/events')
    def events(task_id:TaskId):
        try:
            engine.store.get(task_id)
            return {'task_id':task_id,'items':engine.store.events(task_id)}
        except TaskError as exc:raise HTTPException(409 if exc.code=='AUDIT_INTEGRITY_FAILED' else 404,detail=exc.code) from None

    @r.get('/tasks/{task_id}/export')
    def export(task_id:TaskId):
        try:return engine.store.export(task_id)
        except TaskError as exc:raise HTTPException(404,detail=exc.code) from None

    return r
