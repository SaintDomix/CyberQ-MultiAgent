"""Orchestration-only Coordinator: DAG, bounded calls, state, audit and delivery."""
import fcntl
from pathlib import Path
import threading
import time
import uuid
from pydantic import ValidationError
from coursework.isolation import STATE, require_live_owner
from .agents import AGENTS, specifications
from .models import (TaskRequest, TaskState, Message, AgentResult, ToolArguments, ToolResult,
                     Failure, TaskError, SPECIALISTS, TERMINAL, now)
from .store import Store, digest
from .tools import TOOLS


def call_distribution(events):
    def category(kind):
        counts={a:sum(e['event']==kind and e['agent']==a for e in events) for a in SPECIALISTS}
        total=sum(counts.values())
        return {'denominator':total,'counts':counts,
                'percentages':{a:100*c/total if total else None for a,c in counts.items()}}
    tool=category('tool.started');llm=category('llm.started')
    counts={a:tool['counts'][a]+llm['counts'][a] for a in SPECIALISTS}
    total=sum(counts.values())
    percentages={a:100*c/total if total else None for a,c in counts.items()}
    return {'all_specialist_calls':{'denominator':total,'counts':counts,'percentages':percentages},
            'tool_only':tool,'llm_only':llm,
            'max_specialist_percent':max(percentages.values()) if total else None,
            'within_40_percent':all(v<=40 for v in percentages.values()) if total else None,
            'coordinator_tool_calls':sum(e['event'] in ('tool.started','llm.started') and e['agent']=='coordinator' for e in events),
            'coordinator_dispatches':sum(e['event']=='message.sent' and e.get('message',{}).get('kind')=='DISPATCH' for e in events),
            'counting':'Every registered tool/LLM attempt counts when entered, including failed/retried attempts. Internal helper calls and audit persistence are not independent registered tool invocations.'}


class Context:
    def __init__(self, engine, state):
        self.engine,self.state=engine,state
        self.deadline=time.monotonic()+state.request.timeout_seconds
        self.tool_deadline=self.deadline
        self.active_agent='coordinator'
        self.active_tool=None
        self.live_cache={}

    def check(self):
        if time.monotonic()>=min(self.deadline,self.tool_deadline):
            raise TaskError('DEADLINE_EXCEEDED','Task/tool deadline expired; late results are discarded',status='TIMED_OUT')

    def output(self,name):
        if name not in self.state.tool_outputs:
            raise TaskError('DEPENDENCY_MISSING','Required prior tool output is unavailable')
        return self.state.tool_outputs[name]

    def invoke(self,agent,name):
        if self.state.request.mode=='LIVE_LAB':self.engine.live_adapter.require_authorized()
        specification=self.engine.registry.get(name)
        if specification is None or specification[0]!=agent:
            raise TaskError('TOOL_NOT_ALLOWED','Agent attempted an unregistered or foreign tool')
        self.active_agent,self.active_tool=agent,name
        args=ToolArguments(task_id=self.state.task_id,agent=agent,scenario=self.state.request.scenario,
            dependency_message_ids=[m.message_id for m in self.state.messages if m.kind=='DISPATCH' and m.recipient==agent][-1:])
        for attempt in range(1,self.state.request.max_retries+2):
            self.tool_deadline=self.deadline
            self.check()
            if self.state.steps>=self.state.request.max_steps:
                raise TaskError('STEP_BUDGET_EXCEEDED','No remaining registered tool attempts; task stopped',status='LIMIT_EXCEEDED')
            self.state.steps+=1
            call_id='call-'+uuid.uuid4().hex
            integration=specification[1]
            if self.state.request.mode=='LIVE_LAB':
                integration={'native.read_baseline':'EXISTING_AUTHORIZED_POSTURE_JOB_OR_EXPLICIT_SAVED_ID',
                    'zap.read_assessment':'SAME_POSTURE_JOB_SNAPSHOT','behavior.extract_features':'OWNED_MONITOR_SQLITE',
                    'behavior.infer':'REUSE_COMMITTED_MONITOR_INFERENCE','verify.artifacts':'TASK_SNAPSHOT_AND_MODEL_FILES',
                    'verify.journal':'OWNED_MONITOR_SQLITE_RECHECK'}.get(name,integration)
            self.engine.store.record(self.state,'tool.started',agent,tool=name,call_id=call_id,
                category='tool',integration=integration,attempt=attempt,arguments=args.model_dump(),
                implementation=specification[2].__module__+'.'+specification[2].__qualname__)
            start=time.monotonic()
            self.tool_deadline=min(self.deadline,start+self.state.request.tool_timeout_seconds)
            try:
                result=ToolResult.model_validate(specification[2](self))
                self.check()
            except Exception as exc:
                error=exc if isinstance(exc,TaskError) else TaskError(
                    'INVALID_TOOL_OUTPUT' if isinstance(exc,ValidationError) else 'TOOL_FAILURE',
                    'Registered tool failed; unsafe exception details withheld',retryable=False)
                self.engine.store.record(self.state,'tool.failed',agent,tool=name,call_id=call_id,
                    attempt=attempt,duration_seconds=round(time.monotonic()-start,6),
                    code=error.code,retryable=error.retryable)
                if error.retryable and attempt<=self.state.request.max_retries:
                    self.engine.store.record(self.state,'retry.scheduled',agent,tool=name,next_attempt=attempt+1)
                    self.tool_deadline=self.deadline
                    self.check()
                    continue
                raise error from None
            self.state.tool_outputs[name]=result
            self.engine.store.record(self.state,'tool.completed',agent,tool=name,call_id=call_id,
                attempt=attempt,duration_seconds=round(time.monotonic()-start,6),
                output_sha256=digest(result.model_dump(mode='json')),summary=result.summary,
                evidence_refs=[r.model_dump(mode='json') for r in result.evidence])
            self.tool_deadline=self.deadline
            return result


class Coordinator:
    def __init__(self, store=None, registry=None, *, application=None, live_adapter=None):
        self.store=store or Store()
        self.registry=dict(TOOLS if registry is None else registry)
        self.agents=[a() for a in AGENTS]
        from .live import LiveAssessmentAdapter
        self.live_adapter=live_adapter if live_adapter is not None else LiveAssessmentAdapter(application)
        for a in self.agents:
            if len(a.tools)>5 or any(self.registry.get(t,(None,))[0]!=a.agent_id for t in a.tools):
                raise ValueError('Agent tool allow-list is invalid')
        self.thread=None
        self.guard=threading.Lock()

    def _lease(self):
        # One coursework runner across API, CLI and multiple server processes.
        lock=(STATE/'multiagent-runner.lock').open('a')
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            lock.close()
            raise TaskError('RUNNER_BUSY','A coursework task already owns the runner; no concurrent task started') from None
        return lock

    def _prepare(self, request):
        request=TaskRequest.model_validate(request)
        previous=self.store.by_request(request.request_id)
        if previous:
            if previous.request!=request:raise TaskError('IDEMPOTENCY_CONFLICT','Request ID was already used with different parameters')
            if previous.status not in TERMINAL:
                try:stale_lock=self._lease()
                except TaskError:return previous,None
                try:
                    self.store.recover()
                    previous=self.store.get(previous.task_id)
                finally:stale_lock.close()
            return previous,None
        lock=self._lease()
        try:
            # Recheck after acquiring the cross-process lock.
            previous=self.store.by_request(request.request_id)
            if previous:
                lock.close()
                if previous.request!=request:raise TaskError('IDEMPOTENCY_CONFLICT','Request ID parameters differ')
                return previous,None
            self.store.recover()
            state=TaskState(task_id='ma-'+uuid.uuid4().hex,request=request,created_at=now(),updated_at=now(),
                warnings=['Offline evidence only; no shared laboratory operation was requested.' if request.mode=='OFFLINE_EVIDENCE' else
                          'Live work requires an authorized exclusive lease; monitoring never starts automatically.'])
            self.store.create(state)
            self.store.record(state,'task.created',request=request.model_dump(),agent_specifications=specifications())
            return state,lock
        except BaseException:
            lock.close();raise

    def submit(self,request):
        with self.guard:
            state,lock=self._prepare(request)
            if lock is not None:
                self.thread=threading.Thread(target=self._run,args=(state,lock),daemon=True,name='cqma-'+state.task_id)
                self.thread.start()
            return state

    def run_sync(self,request):
        with self.guard:state,lock=self._prepare(request)
        if lock is not None:self._run(state,lock)
        return self.store.get(state.task_id)

    def message(self,state,sender,recipient,kind,payload,depends=()):
        message=Message(message_id='msg-'+uuid.uuid4().hex,task_id=state.task_id,sender=sender,
                        recipient=recipient,kind=kind,created_at=now(),payload=payload,depends_on=list(depends))
        # A RESULT is validated against the explicit agent output contract too.
        if kind=='RESULT':
            result=AgentResult.model_validate(payload)
            if result.agent!=sender or recipient!='coordinator':
                raise TaskError('MESSAGE_IDENTITY','Specialist result sender does not match its contract')
        state.messages.append(message)
        self.store.record(state,'message.sent',sender,message=message.model_dump(mode='json'))
        return message

    def _run(self,state,lock):
        context=Context(self,state)
        try:
            state.status='RUNNING';state.agents['coordinator']='RUNNING'
            self.store.record(state,'task.started')
            if state.request.mode!='OFFLINE_EVIDENCE':
                self.live_adapter.require_authorized()
            completed={}
            for agent in self.agents:
                context.check()
                if any(d not in completed for d in agent.dependencies):
                    raise TaskError('DEPENDENCY_MISSING','Agent dependency has not completed')
                if agent.agent_id=='verification':state.status='VERIFYING'
                if agent.agent_id=='quality':state.status='SCORING'
                dependencies=[completed[d] for d in agent.dependencies]
                self.message(state,'coordinator',agent.agent_id,'DISPATCH',
                    {'scenario':state.request.scenario,'mode':state.request.mode,'allowed_tools':list(agent.tools),
                     'upstream_agents':list(agent.dependencies)},dependencies)
                state.agents[agent.agent_id]='RUNNING'
                self.store.record(state,'agent.started',agent.agent_id)
                context.active_agent=agent.agent_id
                result=AgentResult.model_validate(agent.run(context))
                message=self.message(state,agent.agent_id,'coordinator','RESULT',result.model_dump(mode='json'),dependencies)
                completed[agent.agent_id]=message.message_id
                state.outputs[agent.agent_id]=result
                state.agents[agent.agent_id]='COMPLETED'
                self.store.record(state,'agent.completed',agent.agent_id)
            context.check()
            state.result=context.output('quality.check_result').data
            state.distribution=call_distribution(self.store.events(state.task_id))
            if state.distribution['within_40_percent'] is not True:
                raise TaskError('WORKLOAD_DISTRIBUTION_FAILED','A specialist exceeded 40 percent; workflow is not rubric-compliant')
            state.status='COMPLETED';state.agents['coordinator']='COMPLETED'
            outcome=state.result.get('assessment_outcome','HISTORICAL_REANALYSIS_WITH_LIMITATIONS')
            self.message(state,'coordinator','coordinator','FINAL',{
                'quality_message_id':completed['quality'],'outcome':outcome,
                'result_source':'quality.check_result','distribution':state.distribution},[completed['quality']])
            self.store.record(state,'task.completed',assessment_outcome=outcome)
        except Exception as exc:
            error=exc if isinstance(exc,TaskError) else TaskError('INVALID_MESSAGE' if isinstance(exc,ValidationError) else 'COORDINATION_FAILURE',
                'Coordination stopped safely; no successful assessment is asserted')
            state.status=error.status
            state.result=None
            state.failure=Failure(code=error.code,message=error.safe_message,retryable=error.retryable,
                                  agent=context.active_agent,tool=context.active_tool)
            state.agents['coordinator']=state.status
            for agent,stage in state.agents.items():
                if stage=='RUNNING':state.agents[agent]=state.status
                elif stage=='PENDING':state.agents[agent]='SKIPPED'
            state.distribution=call_distribution(self.store.events(state.task_id))
            self.message(state,'coordinator','coordinator','FAILURE',state.failure.model_dump())
            self.store.record(state,'task.failed',code=error.code,terminal_status=state.status)
        finally:
            lock.close()

    def close(self):
        if self.thread and self.thread.is_alive():self.thread.join(timeout=125)
