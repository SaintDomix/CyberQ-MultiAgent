"""Real saved-evidence workflows and explicitly labelled contract/fault injections.

Fault tests mutate delivered in-memory claims or failing adapters, never source
artifacts, models, saved receipts, or existing audit logs.
"""
import json
import threading
import time
import uuid
import pytest
from pydantic import ValidationError
from coursework.isolation import STATE
from coursework.multiagent.engine import Coordinator,call_distribution
from coursework.multiagent.models import TaskRequest,TaskError,Message,TaskState,now
from coursework.multiagent.store import Store
from coursework.multiagent.tools import TOOLS
from coursework.multiagent.agents import specifications,NativeSecurityAgent


@pytest.fixture
def store():
    return Store(STATE/'assignment4/scenarios'/uuid.uuid4().hex)


def record(request,store,state,kind):
    receipt=store.root/'case-receipt.json'
    receipt.write_text(json.dumps(store.export(state.task_id),indent=2,allow_nan=False)+'\n')
    for key,value in [('task_id',state.task_id),('task_status',state.status),('case_kind',kind),
                      ('trace_path',str(receipt)),('max_specialist_percent',state.distribution.get('max_specialist_percent'))]:
        request.node.user_properties.append((key,value))


def registry_override(name,fn):
    result=dict(TOOLS);owner,integration,_=result[name]
    result[name]=(owner,integration,fn)
    return result


@pytest.mark.parametrize('scenario',['sqli_run','xss_run','traversal_run','bruteforce_run','benign_replay','attack_replay','unknown_run'])
def test_real_five_specialist_workflow(scenario,store,request):
    state=Coordinator(store).run_sync(TaskRequest(scenario=scenario))
    record(request,store,state,'ACTUAL_HISTORICAL_REANALYSIS')
    assert state.status=='COMPLETED',state.failure
    assert all(s=='COMPLETED' for s in state.agents.values())
    assert len(state.outputs)==5 and state.steps==12
    events=store.events(state.task_id)
    assert len([e for e in events if e['event']=='tool.started'])==12
    assert len([e for e in events if e['event']=='tool.completed'])==12
    assert state.distribution==call_distribution(events)
    assert state.distribution['max_specialist_percent']==25
    assert state.distribution['llm_only']['denominator']==0
    assert all(v is None for v in state.distribution['llm_only']['percentages'].values())
    assert state.distribution['within_40_percent'] is True
    assert state.distribution['coordinator_tool_calls']==0
    integrations={e.get('integration') for e in events if e['event']=='tool.started'}
    assert {'PRESERVED_FILES','IMMUTABLE_SQLITE','FROZEN_ML_CODE_EXECUTION'}<=integrations
    messages=[Message.model_validate(m) for m in state.messages]
    assert all(m.task_id==state.task_id for m in messages)
    results={m.sender:m.message_id for m in messages if m.kind=='RESULT'}
    verify=next(m for m in messages if m.kind=='DISPATCH' and m.recipient=='verification')
    assert set(verify.depends_on)=={results[a] for a in ('native','zap','behavioral')}
    assert next(m for m in messages if m.kind=='DISPATCH' and m.recipient=='quality').depends_on==[results['verification']]
    assert {v.status for v in state.verification}=={'VERIFIED','PARTIAL'}
    assert len(state.result['cqi']['dimensions'])==6
    assert state.result['consistency_with_existing_cqi']=='PASS'
    assert state.result['cqi']['is_probability'] is False
    assert state.tool_outputs['behavior.infer'].summary['shap_available']>0
    assert 'tool_outputs' not in store.export(state.task_id)['state']


def test_missing_evidence_is_not_success(store,request):
    def missing(ctx):
        result=TOOLS['native.read_baseline'][2](ctx)
        ref=result.evidence[0].model_copy(update={'path':'outputs/coursework_missing_evidence.json','ref_id':'ref-missing'})
        return result.model_copy(update={'evidence':result.evidence+[ref]})
    state=Coordinator(store,registry_override('native.read_baseline',missing)).run_sync(TaskRequest(scenario='sqli_run'))
    record(request,store,state,'SYNTHETIC_MISSING_REFERENCE_HANDLING')
    assert state.status=='FAILED' and state.failure.code=='EVIDENCE_REJECTED'
    assert any(v.status=='MISSING' for v in state.verification)
    assert state.result is None


def test_conflicting_delivered_evidence_is_not_success(store,request):
    def conflicting(ctx):
        result=TOOLS['native.read_baseline'][2](ctx).model_copy(deep=True)
        row=result.data['rows'][0]
        row['check_result']='FAIL' if row['check_result']!='FAIL' else 'PASS'
        return result
    state=Coordinator(store,registry_override('native.read_baseline',conflicting)).run_sync(TaskRequest(scenario='sqli_run'))
    record(request,store,state,'SYNTHETIC_CONFLICTING_MESSAGE_HANDLING')
    assert state.status=='FAILED' and state.result is None
    assert any(v.subject=='native-content' and v.status=='CONFLICTED' for v in state.verification)


def test_invalid_message_schema_is_terminal(store,request):
    class InvalidMessageNative(NativeSecurityAgent):
        def run(self,ctx):
            result=super().run(ctx).model_dump()
            return {**result,'unexpected':'controlled schema fault'}
    engine=Coordinator(store);engine.agents[0]=InvalidMessageNative()
    state=engine.run_sync(TaskRequest(scenario='sqli_run'))
    record(request,store,state,'SYNTHETIC_INVALID_MESSAGE_HANDLING')
    assert state.status=='FAILED' and state.failure.code=='INVALID_MESSAGE' and state.result is None
    assert state.steps==2 and state.agents['verification']=='SKIPPED'


def test_tool_failure_is_logged_and_terminal(store,request):
    def failure(ctx):raise TaskError('CONTROLLED_TOOL_FAILURE','Deliberate adapter failure for validation')
    state=Coordinator(store,registry_override('zap.check_profile',failure)).run_sync(TaskRequest(scenario='sqli_run'))
    record(request,store,state,'SYNTHETIC_TOOL_FAILURE_HANDLING')
    assert state.status=='FAILED' and state.failure.code=='CONTROLLED_TOOL_FAILURE'
    assert len([e for e in store.events(state.task_id) if e['event']=='tool.failed'])==1
    assert state.result is None


def test_actual_tool_timeout_discards_late_result(store,request):
    def slow(ctx):
        result=TOOLS['native.read_baseline'][2](ctx)
        time.sleep(.035)
        return result
    state=Coordinator(store,registry_override('native.read_baseline',slow)).run_sync(
        TaskRequest(scenario='sqli_run',tool_timeout_seconds=.01))
    record(request,store,state,'CONTROLLED_REAL_TIME_TIMEOUT_HANDLING')
    assert state.status=='TIMED_OUT' and state.failure.code=='DEADLINE_EXCEEDED'
    assert not state.tool_outputs and state.result is None


def test_retry_recovers_and_counts_failed_attempt(store,request):
    attempts=[]
    def transient(ctx):
        attempts.append(1)
        if len(attempts)==1:raise TaskError('TRANSIENT_ADAPTER_FAILURE','Controlled transient failure',retryable=True)
        return TOOLS['zap.check_profile'][2](ctx)
    state=Coordinator(store,registry_override('zap.check_profile',transient)).run_sync(TaskRequest(scenario='sqli_run',max_retries=1))
    record(request,store,state,'CONTROLLED_RETRY_RECOVERY_WITH_REAL_REANALYSIS')
    assert state.status=='COMPLETED' and len(attempts)==2 and state.steps==13
    assert state.distribution['tool_only']['denominator']==13
    assert state.distribution['tool_only']['counts']['zap']==3
    assert state.distribution['within_40_percent'] is True


def test_retry_exhaustion_is_bounded(store,request):
    attempts=[]
    def failing(ctx):
        attempts.append(1)
        raise TaskError('TRANSIENT_ADAPTER_FAILURE','Controlled recurring failure',retryable=True)
    state=Coordinator(store,registry_override('zap.check_profile',failing)).run_sync(TaskRequest(scenario='sqli_run',max_retries=1))
    record(request,store,state,'CONTROLLED_RETRY_EXHAUSTION_HANDLING')
    assert state.status=='FAILED' and len(attempts)==2 and state.result is None
    assert len([e for e in store.events(state.task_id) if e['event']=='retry.scheduled'])==1


@pytest.mark.parametrize('profile',['PASSIVE_BASELINE','STANDARD','FULL_AUTHORIZED'])
def test_laboratory_lock_is_never_bypassed(profile,store,request):
    state=Coordinator(store).run_sync(TaskRequest(scenario='sqli_run',mode='LIVE_LAB',zap_profile=profile))
    record(request,store,state,'ACTUAL_LAB_LOCK_HANDLING')
    assert state.status=='BLOCKED' and state.steps==0 and state.result is None
    assert state.failure.code=='LAB_LOCKED'
    assert state.distribution['tool_only']['denominator']==0


def test_step_workload_limit_is_enforced_and_distribution_is_not_hidden(store,request):
    state=Coordinator(store).run_sync(TaskRequest(scenario='sqli_run',max_steps=2))
    record(request,store,state,'ACTUAL_WORKLOAD_LIMIT_HANDLING')
    assert state.status=='LIMIT_EXCEEDED' and state.steps==2 and state.result is None
    assert state.distribution['max_specialist_percent']==100
    assert state.distribution['within_40_percent'] is False


def test_incomplete_input_and_extra_fields_rejected(store,request):
    before=len(store.list())
    for value in ({'mode':'OFFLINE_EVIDENCE'},{'scenario':'sqli_run','api_key':'DO_NOT_ACCEPT'}):
        with pytest.raises(ValidationError):TaskRequest.model_validate(value)
        store.reject('INVALID_REQUEST_SCHEMA','assignment4-validation')
    assert len(store.list())==before
    request.node.user_properties.extend([('case_kind','SCHEMA_REJECTION_NO_ASSESSMENT'),('task_status','REJECTED_BEFORE_TASK')])


def test_corrupted_cqi_output_is_rejected(store,request):
    def corrupted(ctx):
        result=TOOLS['quality.evaluate'][2](ctx).model_copy(deep=True)
        result.data['cqi']['overall']+=.5
        return result
    state=Coordinator(store,registry_override('quality.evaluate',corrupted)).run_sync(TaskRequest(scenario='sqli_run'))
    record(request,store,state,'CONTROLLED_CQI_CONSISTENCY_HANDLING')
    assert state.status=='FAILED' and state.failure.code=='CQI_INCONSISTENT' and state.result is None


def test_idempotency_prevents_duplicate_tool_writes(store,request):
    engine=Coordinator(store)
    body=TaskRequest(scenario='sqli_run',request_id='validation-'+uuid.uuid4().hex)
    first=engine.run_sync(body);before=store.events(first.task_id)
    second=engine.run_sync(body)
    assert first.task_id==second.task_id and before==store.events(first.task_id)
    with pytest.raises(TaskError,match='different parameters'):
        engine.run_sync(body.model_copy(update={'scenario':'xss_run'}))
    record(request,store,second,'IDEMPOTENCY_WITH_REAL_REANALYSIS')


def test_exclusive_runner_blocks_another_coordinator(store,request):
    entered=threading.Event();release=threading.Event()
    def held(ctx):
        entered.set()
        if not release.wait(3):raise TaskError('TEST_RELEASE_TIMEOUT','Validation release timed out')
        return TOOLS['native.read_baseline'][2](ctx)
    first=Coordinator(store,registry_override('native.read_baseline',held));state=first.submit(TaskRequest(scenario='sqli_run'))
    assert entered.wait(2)
    try:
        with pytest.raises(TaskError,match='already owns the runner'):
            Coordinator(store).run_sync(TaskRequest(scenario='xss_run'))
    finally:release.set();first.close()
    state=store.get(state.task_id)
    assert state.status=='COMPLETED'
    record(request,store,state,'EXCLUSIVE_RUNNER_WITH_REAL_REANALYSIS')


def test_interrupted_state_is_preserved_and_not_resumed(store,request):
    pending=TaskState(task_id='ma-'+uuid.uuid4().hex,request=TaskRequest(scenario='sqli_run'),created_at=now(),updated_at=now())
    store.create(pending);store.record(pending,'validation.created_unstarted_task')
    completed=Coordinator(store).run_sync(TaskRequest(scenario='sqli_run'))
    interrupted=store.get(pending.task_id)
    assert interrupted.status=='INTERRUPTED' and interrupted.steps==0 and interrupted.result is None
    record(request,store,completed,'INTERRUPTION_RECOVERY_WITH_REAL_REANALYSIS')


def test_registry_tool_limits_and_message_strictness():
    assert len(specifications())==6
    assert all(len(a['tools'])<=5 for a in specifications())
    with pytest.raises(ValidationError):Message.model_validate({'sender':'native','payload':{}})


def test_invalid_artifact_hash_is_explicitly_invalid(store,request):
    def invalid(ctx):
        result=TOOLS['native.read_baseline'][2](ctx).model_copy(deep=True)
        result.evidence[0].expected_sha256='0'*64
        return result
    state=Coordinator(store,registry_override('native.read_baseline',invalid)).run_sync(TaskRequest(scenario='sqli_run'))
    record(request,store,state,'CONTROLLED_INVALID_HASH_HANDLING')
    assert state.status=='FAILED' and state.result is None
    assert any(v.status=='INVALID' for v in state.verification)


def test_duplicate_delivered_evidence_is_reported(store,request):
    def duplicate(ctx):
        result=TOOLS['native.read_baseline'][2](ctx).model_copy(deep=True)
        result.data['rows'].append(dict(result.data['rows'][0]))
        return result
    state=Coordinator(store,registry_override('native.read_baseline',duplicate)).run_sync(TaskRequest(scenario='sqli_run'))
    record(request,store,state,'CONTROLLED_DUPLICATE_MESSAGE_HANDLING')
    assert state.status=='FAILED' and state.result is None
    assert any(v.subject=='native-identities' and 'exact duplicates: 1' in v.reasons[0] for v in state.verification)
