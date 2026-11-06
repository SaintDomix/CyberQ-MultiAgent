"""Safe local integration fixtures, never lab authorization or shared services.

The real existing LiveEngine processes a synthetic local file into its actual
83-feature/model/SHAP/incident store. Only the test adapter admits these explicit
fixtures. Production still uses require_live_owner unchanged and fails closed.
"""
from datetime import datetime,timedelta,timezone
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import uuid
from unittest.mock import patch

import pytest
from coursework.isolation import ROOT,STATE
from coursework.multiagent.engine import Coordinator
from coursework.multiagent.live import LiveAssessmentAdapter,MonitoringSnapshotReader
from coursework.multiagent.models import TaskRequest,TaskError
from coursework.multiagent.store import Store,canonical
from coursework.multiagent.tools import TOOLS
from demo.backend.config import Config
from demo.backend.services import Application
from demo.backend.runtime import read_journal
from behavioral_runtime.live import LiveEngine
from behavioral_runtime.package import load
from posture.orchestration import PostureAssessmentOrchestrator
from posture.model import row,deduplicate


class LocalFixtureAdapter(LiveAssessmentAdapter):
    """Test-only admission of fixtures, not an alternate production lab gate."""
    source_kind='TEST_ONLY_LOCAL_FIXTURE'

    def request_posture(self,ctx):
        # Explicit fixture admission only; production defaults to a fresh job.
        return self.application.posture_service.current()

    def require_authorized(self):
        source=Path(self.application.config.apache_source).resolve()
        assert (source.is_relative_to(STATE/'tmp') or source.is_relative_to(STATE/'integration')
                or source.is_relative_to(STATE/'assignment4') and 'tmp' in source.parts)
        assert self.application.control.test_only is True


class LocalControl:
    test_only=True
    def __init__(self,path):
        self.session=path;self.process=object();self.active=True
        self.start_calls=self.stop_calls=0
    def status(self):return {'process_running':self.active,'session':self.session.name}
    def start(self):
        self.start_calls+=1;raise AssertionError('An assessment must not start monitoring')
    def stop(self):
        self.stop_calls+=1;raise AssertionError('An assessment must not stop monitoring')


class FixturePosture(PostureAssessmentOrchestrator):
    def __init__(self,project,aid):
        super().__init__(project,[])
        self.aid=aid
    def current(self):return self.get(self.aid)


@pytest.fixture(scope='module')
def package():return load(ROOT/'outputs/branch2/accepted_behavioral_v2')


@pytest.fixture
def platform(tmp_path,package):
    source=tmp_path/'synthetic-apache.log';source.write_bytes(b'')
    timestamp=datetime.now(timezone.utc)
    start=datetime.fromtimestamp(int(timestamp.timestamp())//10*10,tz=timezone.utc)-timedelta(seconds=60)
    clock=[start]
    engine=LiveEngine(source,ROOT/'outputs/branch2/accepted_behavioral_v2',tmp_path/'monitor',
                      clock=lambda:clock[0],loader=lambda _:package)
    # Keep WAL open: readonly snapshot must see committed records in WAL. Using
    # immutable=1 would miss them and is deliberately not used by the live reader.
    engine.journal.db.execute('PRAGMA journal_mode=WAL')
    payload=[]
    for second in (1,11,21,31):
        at=start+timedelta(seconds=second)
        payload.append(f'192.0.2.1 - - [{at.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /moodle/my/ HTTP/1.1" 200 120 "-" "fixture"\n')
    source.write_text(''.join(payload))
    clock[0]=start+timedelta(seconds=52);engine.poll()
    assert engine.journal.sequence==4
    app=Application(Config(mode='LIVE_LAB',apache_source=str(source)))
    app.control=LocalControl(engine.root)
    # A separate local posture fixture follows the existing immutable manifest
    # contract. It has one synthetic check and explicitly partial coverage.
    project=tmp_path/'posture-fixture'
    aid='posture-'+timestamp.strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:12]
    root=project/'runtime/posture'/aid;root.mkdir(parents=True)
    completed=(timestamp-timedelta(seconds=1)).isoformat()
    native=[row('HDR-005','Security Headers','TEST ONLY header fixture','PASS',None,'CONFIRMED',
                'NATIVE_POSTURE',aid,completed,evidence={'test_only':True})]
    job={'assessment_id':aid,'started_at':start.isoformat(),'completed_at':completed,'status':'PARTIAL',
         'target':'http://192.168.226.132/moodle/','target_id':'moodle-local','mode':'STANDARD','assessment_profile':'STANDARD',
         'provider_statuses':{'native':'COMPLETE','zap':'COMPLETE'},'coverage':{'status':'PARTIAL'},
         'findings':deduplicate(native),'test_only':True}
    files={'request.json':job,'snapshot.json':job,'native.json':{'status':'COMPLETE','findings':native},
           'zap.json':{'status':'COMPLETE','findings':[]}}
    for name,value in files.items():(root/name).write_text(canonical(value))
    manifest={'assessment_id':aid,'version':'operational-posture-1.0','files':{
        name:{'sha256':hashlib.sha256((root/name).read_bytes()).hexdigest(),'bytes':(root/name).stat().st_size} for name in files}}
    (root/'artifact_manifest.json').write_text(canonical(manifest))
    app.posture_service=FixturePosture(project,aid)
    adapter=LocalFixtureAdapter(app)
    yield SimpleNamespace(app=app,adapter=adapter,engine=engine,clock=clock,source=source,posture=root,
                          coordinator=lambda registry=None:Coordinator(Store(tmp_path/('task-'+uuid.uuid4().hex)),registry,
                                                                       application=app,live_adapter=adapter))
    engine.stop()


def test_owned_live_fixture_runs_all_specialists_without_replay_or_lifecycle(platform,request):
    control=platform.app.control;owner=control.process
    coordinator=platform.coordinator()
    with patch.object(Application,'replay',side_effect=AssertionError('Live must never use historical replay')):
        state=coordinator.run_sync(TaskRequest(scenario='sqli_run',mode='LIVE_LAB'))
    destination=STATE/'integration'/('fixture-'+state.task_id+'.json')
    destination.write_text(json.dumps(coordinator.store.export(state.task_id),indent=2)+'\n')
    request.node.user_properties.extend([('task_id',state.task_id),('task_status',state.status),
        ('case_kind','TEST_ONLY_LOCAL_MONITOR_INTEGRATION'),('trace_path',str(destination)),
        ('max_specialist_percent',state.distribution.get('max_specialist_percent'))])
    assert state.status=='COMPLETED',state.failure
    assert state.steps==12 and len(state.outputs)==5
    assert state.distribution['max_specialist_percent']==25
    assert state.distribution['coordinator_tool_calls']==0 and state.distribution['coordinator_dispatches']==5
    assert state.result['assessment_outcome']=='TEST_ONLY_LIVE_INTEGRATION'
    assert state.result['source_kind']=='TEST_ONLY_LOCAL_FIXTURE'
    assert len(state.result['cqi']['dimensions'])==6
    assert state.result['consistency_with_existing_cqi']=='PASS'
    assert state.result['live_snapshot']['session_id']==platform.engine.session_id
    assert state.result['live_snapshot']['committed_highwater']==4
    assert state.result['live_snapshot']['sequence_start']==1 and state.result['live_snapshot']['sequence_end']==4
    assert state.result['live_snapshot']['byte_start']<state.result['live_snapshot']['byte_end']
    assert state.tool_outputs['behavior.infer'].summary['inference_reused_from_monitor'] is True
    assert state.tool_outputs['behavior.infer'].summary['shap_available']==4
    assert control.process is owner and control.active and control.start_calls==control.stop_calls==0
    assert all(len(a.tools)<=5 for a in platform.coordinator().agents)


def test_production_gate_still_blocks_even_with_local_active_fixture(platform):
    engine=Coordinator(Store(platform.engine.root.parent/'production-gate'),application=platform.app)
    state=engine.run_sync(TaskRequest(scenario='sqli_run',mode='LIVE_LAB'))
    assert state.status=='BLOCKED' and state.steps==0 and state.failure.code=='LAB_LOCKED'
    assert platform.app.control.active


def test_snapshot_is_bounded_and_readonly_and_standalone_reader_sees_wal(platform):
    reader=MonitoringSnapshotReader(platform.app,max_windows=2)
    before=platform.engine.journal.sequence
    value=reader.capture()
    assert len(value['records'])==2 and value['metadata']['sequence_start']==3
    predictions,_,_=read_journal(platform.engine.root,platform.engine.model_id,platform.engine.schema_hash)
    assert len(predictions)==before==4 and platform.engine.journal.sequence==before


def test_missing_owned_monitor_is_partial_without_replay_or_automatic_start(platform):
    platform.app.control.active=False
    state=platform.coordinator().run_sync(TaskRequest(scenario='sqli_run',mode='LIVE_LAB'))
    assert state.status=='COMPLETED',state.failure
    assert state.tool_outputs['behavior.extract_features'].summary['availability']=='UNAVAILABLE'
    assert state.result['assessment_summary']['behavior_windows']==0
    assert state.result['cqi']['behavioral']['available'] is False
    assert len(state.result['cqi']['dimensions'])==6
    assert platform.app.control.start_calls==platform.app.control.stop_calls==0


def test_retained_or_imported_session_is_not_ownership(platform):
    platform.app.control.session=ROOT/'runtime/behavioral_v2/imported'
    with pytest.raises(TaskError,match='inside coursework state'):platform.adapter.reader.capture()


def test_stale_and_empty_windows_are_insufficient(platform):
    with pytest.raises(TaskError,match='No recent complete'):
        platform.adapter.reader.capture(clock=lambda:datetime.now(timezone.utc)+timedelta(seconds=301))


def test_cross_session_records_rejected(platform):
    db=platform.engine.journal.db
    payload=json.loads(db.execute('SELECT payload FROM results WHERE sequence=4').fetchone()[0])
    payload['prediction']['session_id']='another-test-session'
    encoded=canonical(payload)
    db.execute('UPDATE results SET payload=?,sha256=? WHERE sequence=4',(encoded,hashlib.sha256(encoded.encode()).hexdigest()));db.commit()
    with pytest.raises(TaskError,match='owned monitoring session'):platform.adapter.reader.capture()


def test_future_windows_rejected(platform):
    with pytest.raises(TaskError,match='window/emission boundaries'):
        platform.adapter.reader.capture(clock=lambda:platform.clock[0]-timedelta(seconds=50))


def test_incident_projection_lag_blocks(platform):
    db=platform.engine.journal.db;db.execute('UPDATE episode_cursor SET sequence=3');db.commit()
    with pytest.raises(TaskError,match='projection has not reached'):platform.adapter.reader.capture()


def test_snapshot_has_a_serialized_byte_budget(platform):
    # Purpose-created local fixture only; whitespace keeps the JSON prediction
    # unchanged while exercising a genuinely oversized serialized record.
    db=platform.engine.journal.db
    payload=db.execute('SELECT payload FROM results WHERE sequence=4').fetchone()[0]+' '*(8*1024*1024)
    db.execute('UPDATE results SET payload=?,sha256=? WHERE sequence=4',(payload,hashlib.sha256(payload.encode()).hexdigest()));db.commit()
    with pytest.raises(TaskError,match='serialized-data budget'):platform.adapter.reader.capture()


def test_new_rows_after_capture_do_not_change_task_snapshot(platform):
    from coursework.multiagent.engine import Context
    from coursework.multiagent.models import TaskState,now
    ctx=Context(platform.coordinator(),TaskState(task_id='ma-'+uuid.uuid4().hex,
        request=TaskRequest(scenario='sqli_run',mode='LIVE_LAB'),created_at=now(),updated_at=now()))
    value,ref=platform.adapter.behavioral(ctx)
    platform.clock[0]+=timedelta(seconds=20)
    at=platform.clock[0]-timedelta(seconds=15)
    with platform.source.open('a') as handle:
        handle.write(f'192.0.2.1 - - [{at.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /moodle/my/ HTTP/1.1" 200 120 "-" "fixture"\n')
    platform.engine.poll()
    assert platform.engine.journal.sequence==5
    checked_value,_=platform.adapter.recheck_journal(ctx)
    assert checked_value['metadata']['committed_highwater']==value['metadata']['committed_highwater']==4
    assert checked_value==platform.adapter.check_reference(ctx,ref)


def test_conflicting_posture_time_rejected_by_verification(platform):
    # Change only this purpose-created local fixture and recompute its manifest.
    # Its bytes are valid, but its future timestamp is an unsupported assumption.
    for name in ('request.json','snapshot.json'):
        path=platform.posture/name;value=json.loads(path.read_text())
        value['completed_at']=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
        path.write_text(canonical(value))
    path=platform.posture/'artifact_manifest.json';manifest=json.loads(path.read_text())
    for name in manifest['files']:
        raw=(platform.posture/name).read_bytes();manifest['files'][name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
    path.write_text(canonical(manifest))
    state=platform.coordinator().run_sync(TaskRequest(scenario='sqli_run',mode='LIVE_LAB'))
    assert state.status=='FAILED' and state.failure.code=='EVIDENCE_REJECTED' and state.result is None
    assert any(v.subject=='live-temporal-alignment' and v.status=='CONFLICTED' for v in state.verification)
    assert platform.app.control.active

@pytest.fixture(scope='module')
def completed_full():
    store=Store(STATE/'integration'/('full-'+uuid.uuid4().hex))
    state=Coordinator(store).run_sync(TaskRequest(scenario='attack_replay'))
    assert state.status=='COMPLETED',state.failure
    return store,state


def test_full_assessment_projection_uses_exact_persisted_branch_records(completed_full):
    from coursework.multiagent.views import assessment_view
    store,state=completed_full
    view=assessment_view(store.get(state.task_id))
    assert view['context']['task_id']==view['context']['assessment_id']==state.task_id
    assert len(view['native']['findings'])==40
    assert view['zap']['assessment']['assessment_id']==state.tool_outputs['zap.read_assessment'].summary['assessment_id']
    assert {o['observation_id'] for o in view['behavioral']['observations']}=={
        p['record_id'] for p in state.tool_outputs['behavior.infer'].data['predictions']}
    assert view['context']['native_refs'] and view['context']['zap_refs'] and view['context']['behavioral_refs']
    assert view['result']['cqi']==state.result['cqi']
    # Rereading/navigation never selects newer global branch results or runs tools.
    assert assessment_view(store.get(state.task_id))==view
    assert state.steps==12 and state.distribution['max_specialist_percent']==25


def test_official_cqi_ignores_standalone_updates_and_failed_full_task(completed_full,platform):
    from coursework.multiagent.store import digest
    store,state=completed_full;original=digest(store.export(state.task_id))
    assert store.official().task_id==state.task_id
    # Controlled standalone provider update, not a new laboratory scan.
    platform.app.posture_service.jobs['test-only-standalone']={'status':'PARTIAL','test_only':True}
    platform.engine.poll()  # Existing real fixture monitor continues independently.
    assert store.official().task_id==state.task_id
    assert store.official().result['cqi']==state.result['cqi']
    blocked=Coordinator(store).run_sync(TaskRequest(scenario='attack_replay',mode='LIVE_LAB'))
    assert blocked.status=='BLOCKED' and blocked.result is None
    assert store.official().task_id==state.task_id
    assert digest(store.export(state.task_id))==original
    with pytest.raises(TaskError,match='immutable'):
        store.record(store.get(state.task_id),'unauthorized.rewrite')


def test_fresh_full_task_calls_existing_posture_start_once_and_never_monitor_lifecycle(platform):
    adapter=platform.adapter;calls=[];engine=platform.app.posture_service
    def local_start(*args,**kwargs):
        calls.append((args,kwargs));return engine.current()
    # Controlled start adapter returns the explicitly synthetic owned fixture;
    # production's existing job dispatch/wait path is exercised, no lab I/O.
    with patch.object(engine,'start',side_effect=local_start),patch.object(adapter,'request_posture',
            side_effect=lambda ctx:LiveAssessmentAdapter.request_posture(adapter,ctx)):
        state=platform.coordinator().run_sync(TaskRequest(scenario='attack_replay',mode='LIVE_LAB'))
    assert state.status=='COMPLETED',state.failure
    assert len(calls)==1 and calls[0][1]['authorized'] is True
    assert calls[0][0][2]=='STANDARD'
    assert state.branch_executions['posture']['assessment_id']==engine.aid
    assert platform.app.control.start_calls==platform.app.control.stop_calls==0


def test_complementary_posture_age_uses_own_policy_not_behavior_horizon(platform):
    # A twenty-minute-old posture is within the existing 24h posture policy,
    # though intentionally outside Behavioral's 300s window horizon.
    for name in ('request.json','snapshot.json'):
        path=platform.posture/name;value=json.loads(path.read_text())
        value['started_at']=(datetime.now(timezone.utc)-timedelta(minutes=21)).isoformat()
        value['completed_at']=(datetime.now(timezone.utc)-timedelta(minutes=20)).isoformat()
        path.write_text(canonical(value))
    for name in ('native.json','zap.json'):
        path=platform.posture/name;value=json.loads(path.read_text())
        for row in value['findings']:row['start_utc']=row['end_utc']=(datetime.now(timezone.utc)-timedelta(minutes=20,seconds=1)).isoformat()
        path.write_text(canonical(value))
    # Deliver the same Native records in the fixture's canonical snapshot too.
    path=platform.posture/'snapshot.json';value=json.loads(path.read_text())
    value['findings']=deduplicate(json.loads((platform.posture/'native.json').read_text())['findings']);path.write_text(canonical(value))
    path=platform.posture/'artifact_manifest.json';manifest=json.loads(path.read_text())
    for name in manifest['files']:
        raw=(platform.posture/name).read_bytes();manifest['files'][name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
    path.write_text(canonical(manifest))
    state=platform.coordinator().run_sync(TaskRequest(scenario='sqli_run',mode='LIVE_LAB'))
    assert state.status=='COMPLETED',state.failure
    assert any(v.subject=='live-temporal-alignment' and v.status=='VERIFIED' for v in state.verification)
    assert platform.app.control.active


def test_default_deny_lab_configuration_and_scope_are_not_ambient_flags():
    from coursework.lab import available,credentials,validate_records,TARGET,ORIGIN
    assert available() is False
    with pytest.raises(ValueError):credentials()
    stamp=datetime.now(timezone.utc).timestamp()
    ready={'status':'READY','blockers':[],'target':TARGET,'zap_origin':ORIGIN,
        'external_exclusion_basis':'TEST ONLY fixture, never an actual handoff','verified_at':stamp,
        **{k:True for k in ('original_jobs_quiescent','external_exclusion_verified','zap_key_verified',
                            'zap_8082_isolated','zap_queues_idle','apache_readonly_verified')}}
    approval={'authorization':'EXPLICIT_USER_AUTHORIZATION_AFTER_READINESS_AUDIT','target':TARGET,
        'zap_origin':ORIGIN,'profiles':['STANDARD'],'expires_at':stamp+300,
        'readiness_sha256':hashlib.sha256(json.dumps(ready,sort_keys=True).encode()).hexdigest()}
    lease={'target':TARGET,'zap_origin':ORIGIN,'issued_at':stamp,'expires_at':stamp+300,'heartbeat_at':stamp}
    assert validate_records(lease,approval,ready,at=stamp)==lease
    for invalid in ({**lease,'zap_origin':'http://127.0.0.1:8081'},
                    {**lease,'expires_at':stamp-1},{**lease,'heartbeat_at':stamp-6}):
        with pytest.raises(ValueError):validate_records(invalid,approval,ready,at=stamp)
    with pytest.raises(ValueError):validate_records(lease,approval,{**ready,'status':'BLOCKED'},at=stamp)

@pytest.mark.parametrize('zap_enabled',[False,True])
def test_existing_standalone_pipeline_publishes_results_without_official_cqi(completed_full,tmp_path,zap_enabled):
    store,state=completed_full;before=store.official().model_dump_json();calls=[]
    class Provider:
        def start_assessment(self,aid,policy):
            calls.append('native')
            return {'provider_id':'native','status':'COMPLETE','version':'TEST_ONLY',
                'findings':[row('HDR-005','Security Headers','TEST ONLY standalone Native','PASS',None,'CONFIRMED',
                    'NATIVE_POSTURE',aid,datetime.now(timezone.utc).isoformat(),evidence={'test_only':True})]}
    class Full:
        def run(self,aid,target,**kwargs):
            calls.append('zap')
            return {'provider_id':'zap','status':'COMPLETE','version':'TEST_ONLY','stages':{},
                'findings':[row('HDR-006','Security Headers','TEST ONLY standalone ZAP','PASS',None,'CONFIRMED',
                    'OWASP_ZAP',aid,datetime.now(timezone.utc).isoformat(),evidence={'test_only':True})]}
    class UnavailableStage:
        def run(self,*args,**kwargs):raise ValueError('TEST ONLY: no active validation transport')
    engine=PostureAssessmentOrchestrator(tmp_path/'standalone-fixture',[],native=Provider(),
        full_provider_factory=lambda *args:Full(),active_stage=UnavailableStage(),zap_active_stage=UnavailableStage())
    with patch('coursework.isolation.require_live_owner',return_value={'profiles':['STANDARD']}):
        result=engine.start('moodle-local',zap_enabled,'STANDARD' if zap_enabled else 'PASSIVE_BASELINE',
                            background=False,authorized=True)
    assert result['status']=='PARTIAL'  # Handling unavailable validators, not a complete security assessment.
    assert 'native' in calls and ('zap' in calls)==zap_enabled
    assert result['findings'] and engine.get(result['assessment_id'])['assessment_id']==result['assessment_id']
    assert store.official().model_dump_json()==before
    assert store.get(state.task_id).result['cqi']==state.result['cqi']


def test_full_authorized_keeps_existing_long_scan_budget_bounded():
    from posture.zap_full import FullBudget
    request=TaskRequest(scenario='attack_replay',mode='LIVE_LAB',zap_profile='FULL_AUTHORIZED')
    assert FullBudget().overall_seconds<request.tool_timeout_seconds<request.timeout_seconds<=10800
    assert request.max_steps==18
    normal=TaskRequest(scenario='attack_replay')
    assert normal.timeout_seconds==90 and normal.tool_timeout_seconds==30
