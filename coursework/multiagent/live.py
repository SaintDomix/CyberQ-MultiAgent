"""Read-only integration with the application's existing owned monitor/posture.

This module never starts/stops a process, reads Apache, contacts ZAP or grants a
lab lease. Production entry always uses the unchanged require_live_owner gate.
Tests inject a local-only adapter; it is never selectable through HTTP/config.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time

from coursework.isolation import ROOT, STATE, require_live_owner
from branch2.events import utc
from demo.backend.explanation_sources import live_window_evidence
from .models import EvidenceRef, TaskError, ToolResult, VerificationOutcome
from .store import canonical, digest


def blocked(code,message):
    raise TaskError(code,message,status='BLOCKED')


def checked(payload,expected):
    if hashlib.sha256(payload.encode()).hexdigest()!=expected:
        raise TaskError('LIVE_JOURNAL_INTEGRITY','Committed journal payload hash mismatch')
    return json.loads(payload)


class MonitoringSnapshotReader:
    """Bounded SQLite read transaction; never immutable=1 for a changing store."""
    def __init__(self, application, *, max_windows=200):
        if not 1<=max_windows<=200:raise ValueError('Bounded monitoring snapshot required')
        self.application=application
        self.max_windows=max_windows

    def binding(self):
        control=self.application.control
        owner=control.process
        if owner is None or control.status()['process_running'] is not True:
            blocked('LIVE_MONITOR_UNAVAILABLE','Start an authorized coursework monitor independently; assessment never starts one')
        if control.session is None:blocked('LIVE_MONITOR_UNAVAILABLE','Owned monitoring session is unavailable')
        root=Path(control.session).resolve()
        if not root.is_relative_to(STATE) or root==STATE or Path(control.session).is_symlink():
            blocked('LIVE_SESSION_NOT_COURSEWORK','Only an application-owned session inside coursework state can be assessed')
        for name in ('session_manifest.json','journal.sqlite3','checkpoint.json'):
            p=root/name
            if p.is_symlink() or not p.is_file():blocked('LIVE_STORE_UNAVAILABLE','Monitoring store or identity metadata is unavailable')
        return owner,root

    def capture(self, *, clock=None):
        owner,root=self.binding()
        model=self.application.model()
        if model.get('integrity')!='VERIFIED':blocked('LIVE_MODEL_INVALID','Accepted live model identity is unavailable')
        manifest=json.loads((root/'session_manifest.json').read_bytes())
        sid=manifest['session_id']
        if (manifest.get('model_id')!=model['package_id'] or manifest.get('schema_sha256')!=model['schema_sha256']
                or manifest.get('feature_count')!=83 or manifest.get('training_performed') is not False
                or Path(manifest['source_path']).resolve()!=Path(self.application.config.apache_source).resolve()):
            blocked('LIVE_SESSION_IDENTITY','Monitor source, package, schema or feature identity does not match the application')
        captured=(clock or (lambda:datetime.now(timezone.utc)))()
        from cqi_v2 import Policy
        horizon=min(self.application.config.lookback,Policy().behavior_horizon_seconds)
        # readonly mode also prevents creating a missing DB; a changing store must
        # participate in normal SQLite locking/WAL visibility, not immutable mode.
        db=sqlite3.connect((root/'journal.sqlite3').as_uri()+'?mode=ro',uri=True,timeout=2)
        try:
            sql_deadline=time.monotonic()+2
            db.set_progress_handler(lambda:int(time.monotonic()>sql_deadline),10000)
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            high=db.execute('SELECT COALESCE(MAX(sequence),0) FROM results').fetchone()[0]
            cursor=db.execute('SELECT sequence FROM episode_cursor WHERE singleton=1').fetchone()
            if not cursor or cursor[0]!=high:
                blocked('LIVE_PROJECTION_CATCHING_UP','Incident projection has not reached the committed observation watermark')
            sizes=db.execute('SELECT length(payload) FROM results ORDER BY sequence DESC LIMIT ?', (self.max_windows,)).fetchall()
            incident_sizes=db.execute('SELECT length(payload) FROM incidents LIMIT ?', (self.max_windows+1,)).fetchall()
            if sum(n[0] for n in sizes+incident_sizes)>8*1024*1024:
                blocked('LIVE_SNAPSHOT_BYTE_LIMIT','Bounded monitoring snapshot exceeds the 8 MiB serialized-data budget')
            entries=db.execute('SELECT sequence,record_id,payload,sha256 FROM results ORDER BY sequence DESC LIMIT ?',
                               (self.max_windows,)).fetchall()[::-1]
            incidents=db.execute('SELECT payload,sha256 FROM incidents LIMIT ?', (self.max_windows+1,)).fetchall()
            if len(incidents)>self.max_windows:
                blocked('LIVE_INCIDENT_LIMIT','Incident snapshot exceeds its bound; use a narrower owned monitoring session')
        except sqlite3.OperationalError:
            blocked('LIVE_STORE_NOT_READY','Monitoring store is unavailable or exceeded its bounded read budget; no replay was substituted')
        finally:db.close()
        records=[]
        for sequence,rid,payload,expected in entries:
            stored=checked(payload,expected);p=stored['prediction'];window=stored['window']
            if (p['sequence']!=sequence or p['record_id']!=rid or p.get('session_id')!=sid
                    or window.get('session_id')!=sid or p.get('model_id')!=model['package_id']
                    or p.get('schema_sha256')!=model['schema_sha256'] or p.get('training_performed') is not False
                    or p.get('run_id')!='live-'+sid):
                raise TaskError('LIVE_CROSS_SESSION','Journal records do not belong to the owned monitoring session/model')
            if (p.get('source_path')!=manifest['source_path'] or window.get('source_device')!=manifest.get('source_device')
                    or window.get('source_inode')!=manifest.get('source_inode')
                    or p.get('source_device')!=manifest.get('source_device') or p.get('source_inode')!=manifest.get('source_inode')):
                raise TaskError('LIVE_SOURCE_IDENTITY','Window source device/inode/path differs from the owned monitor manifest')
            start,end=utc(p['window_start']),utc(p['window_end'])
            if not start<end<=captured or (end-start).total_seconds()!=10 or utc(p['emitted_at_utc'])<end or utc(p['emitted_at_utc'])>captured:
                raise TaskError('LIVE_TIME_INVALID','Live window/emission boundaries are unsupported')
            age=(captured-end).total_seconds()
            if age>horizon:continue
            vector,evidence=live_window_evidence(stored,model['package_id'],model['schema_sha256'],expected)
            if evidence['status']!='RESOLVED' or len(vector)!=83:
                blocked('LIVE_FEATURES_INSUFFICIENT','The committed window does not retain a verified 83-feature vector')
            spans=window.get('source_byte_ranges')
            if not spans or spans!=p.get('source_byte_ranges') or any(
                type(s.get('start')) is not int or type(s.get('end')) is not int or not 0<=s['start']<s['end']
                or not isinstance(s.get('sha256'),str) or len(s['sha256'])!=64 for s in spans):
                raise TaskError('LIVE_BOUNDARIES_INVALID','Committed source byte boundaries are missing or inconsistent')
            if digest([{'byte_start':s['start'],'byte_end':s['end'],'record_sha256':s['sha256']} for s in spans])!=p.get('source_sha256'):
                raise TaskError('LIVE_SOURCE_DIGEST','Ordered source-byte digests differ from the committed inference source')
            records.append({'sequence':sequence,'record_id':rid,'payload':stored,'payload_sha256':expected})
        if not records:blocked('LIVE_DATA_INSUFFICIENT','No recent complete verified monitoring windows are available; replay is never substituted')
        ids={r['record_id'] for r in records};selected=[]
        for payload,expected in incidents:
            i=checked(payload,expected)
            if i.get('session_id')!=sid or i.get('model_id')!=model['package_id']:
                raise TaskError('LIVE_CROSS_SESSION','Incident belongs to another session or model')
            members=set(i['observation_ids'])
            if members&ids:
                if not members<=ids:blocked('LIVE_INCIDENT_BOUNDARY','An incident crosses the bounded snapshot; no partial episode is fabricated')
                selected.append(i)
        checkpoint=json.loads((root/'checkpoint.json').read_bytes())
        if checkpoint.get('session_id')!=sid or checkpoint.get('model_id')!=model['package_id'] or checkpoint.get('integrity_status')!='OK':
            raise TaskError('LIVE_CHECKPOINT_IDENTITY','Checkpoint session/model integrity is invalid')
        current_owner,current_root=self.binding()
        if current_owner is not owner or current_root!=root or manifest!=json.loads((root/'session_manifest.json').read_bytes()):
            blocked('LIVE_OWNER_CHANGED','Monitoring ownership or session identity changed during capture')
        spans=[s for r in records for s in r['payload']['window']['source_byte_ranges']]
        return {'metadata':{'session_id':sid,'journal_path':str((root/'journal.sqlite3').relative_to(ROOT)),
            'manifest_path':str((root/'session_manifest.json').relative_to(ROOT)),
            'source_path':manifest['source_path'],'source_device':manifest.get('source_device'),'source_inode':manifest.get('source_inode'),
            'captured_at':captured.isoformat(),'window_start':min(r['payload']['prediction']['window_start'] for r in records),
            'window_end':max(r['payload']['prediction']['window_end'] for r in records),
            'sequence_start':records[0]['sequence'],'sequence_end':records[-1]['sequence'],'committed_highwater':high,
            'incident_cursor':cursor[0],'max_windows':self.max_windows,'lookback_seconds':horizon,
            'max_snapshot_bytes':8*1024*1024,
            'byte_start':min(s['start'] for s in spans),'byte_end':max(s['end'] for s in spans),
            'checkpoint_at':checkpoint.get('updated_at_utc'),'checkpoint_sequence':checkpoint.get('last_emitted_sequence'),
            'model_id':model['package_id'],'schema_sha256':model['schema_sha256'],
            'manifest_sha256':digest(manifest),'monitor_started_by_assessment':False,'monitor_stopped_by_assessment':False},
            'records':records,'incidents':selected,'model':model}


class LiveAssessmentAdapter:
    source_kind='APPLICATION_OWNED_LIVE_MONITOR'

    def __init__(self, application):
        self.application=application
        self.reader=MonitoringSnapshotReader(application) if application is not None else None

    def require_authorized(self):
        # Unchanged hard lock: no environment/config/API flag can enable live use.
        try:require_live_owner()
        except ValueError:blocked('LAB_LOCKED','Live assessment requires separate authorization and verified exclusive lab ownership')
        if self.application is None:blocked('LIVE_APPLICATION_UNAVAILABLE','No application-owned monitoring control is connected')

    def persist(self,ctx,kind,value):
        folder=STATE/'multiagent/snapshots';folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        value={'task_id':ctx.state.task_id,'source_kind':self.source_kind,**value}
        path=folder/(ctx.state.task_id+'-'+kind+'.json')
        raw=canonical(value).encode()
        with path.open('xb') as handle:
            handle.write(raw);handle.flush();os.fsync(handle.fileno())
        hashed=hashlib.sha256(raw).hexdigest()
        ref=EvidenceRef(ref_id='ref-'+digest([str(path.relative_to(ROOT)),hashed])[:24],path=str(path.relative_to(ROOT)),
            expected_sha256=hashed,read_sha256=hashed,anchor='COURSEWORK_TASK_SNAPSHOT',
            observed_at=value.get('metadata',{}).get('captured_at') or value.get('assessment',{}).get('completed_at'),
            source_record_ids=[r['record_id'] for r in value.get('records',[])],temporal_scope='LIVE_MONITORING_SNAPSHOT')
        return value,ref


    def posture(self,ctx):
        self.require_authorized()
        if 'posture' in ctx.live_cache:return ctx.live_cache['posture']
        engine=self.application.posture_service
        job=self.request_posture(ctx)
        if not job:blocked('LIVE_POSTURE_UNAVAILABLE','Requested coursework posture is unavailable; no historical baseline is substituted')
        location=engine.location(job['assessment_id']).resolve()
        if not location.is_relative_to(STATE):blocked('LIVE_POSTURE_NOT_COURSEWORK','Imported dissertation assessments cannot be used as current coursework evidence')
        if job.get('mode')!=ctx.state.request.zap_profile:
            blocked('LIVE_PROFILE_MISMATCH','Current independent posture does not match the requested ZAP profile')
        if job.get('target')!='http://192.168.226.132/moodle/':
            blocked('LIVE_TARGET_MISMATCH','The accepted behavioral model is not validated for this posture target')
        if job.get('status') not in ('COMPLETE','PARTIAL'):
            blocked('LIVE_POSTURE_INCOMPLETE','Requested coursework posture did not publish completed evidence')
        # get() is the existing immutable assessment identity/hash verifier.
        job=engine.get(job['assessment_id'])
        native=json.loads((location/'native.json').read_bytes());zap=json.loads((location/'zap.json').read_bytes())
        value,ref=self.persist(ctx,'posture',{'assessment':job,'native':native,'zap':zap,
            'source_files':{str((location/n).relative_to(ROOT)):hashlib.sha256((location/n).read_bytes()).hexdigest()
                            for n in ('artifact_manifest.json','snapshot.json','native.json','zap.json')}})
        ctx.live_cache['posture']=(value,ref)
        return value,ref

    def request_posture(self,ctx):
        """Invoke the existing combined workflow once; never reimplement scanners.

        Native's tool starts the existing job. ZAP's tool joins that SAME job.
        Domain operations, job ID and progress are logged under this full task.
        """
        engine=self.application.posture_service
        if not ctx.state.request.fresh_posture:
            return engine.get(ctx.state.request.posture_assessment_id)
        if 'posture_job_id' not in ctx.live_cache:
            self.require_authorized()
            job=engine.start('moodle-local',True,ctx.state.request.zap_profile,
                target_url='http://192.168.226.132/moodle/',authorized=True)
            ctx.live_cache['posture_job_id']=job['assessment_id']
            ctx.state.branch_executions['posture']=job
            ctx.engine.store.record(ctx.state,'branch.execution.started',ctx.active_agent,
                assessment_id=job['assessment_id'],providers=['native','zap'],
                implementation='existing PostureAssessmentOrchestrator.start',fresh_requested=True)
        aid=ctx.live_cache['posture_job_id'];previous=None
        try:
            while True:
                self.require_authorized();ctx.check();job=engine.get(aid)
                progress={k:job.get(k) for k in ('status','provider_statuses','zap_progress')}
                ctx.state.branch_executions['posture']=job
                if progress!=previous:
                    ctx.engine.store.record(ctx.state,'branch.execution.progress',ctx.active_agent,
                        assessment_id=aid,progress=progress)
                    previous=progress
                if job['status']!='RUNNING':return job
                time.sleep(.2)
        except BaseException:
            # Cancel only the job created by this task; never cancel a foreign run.
            if engine.get(aid)['status']=='RUNNING':engine.cancel(aid)
            raise

    def behavioral(self,ctx):
        self.require_authorized()
        if 'behavioral' not in ctx.live_cache:
            try:value=self.reader.capture()
            except TaskError as exc:
                if exc.code not in ('LIVE_MONITOR_UNAVAILABLE','LIVE_STORE_UNAVAILABLE','LIVE_STORE_NOT_READY',
                        'LIVE_DATA_INSUFFICIENT','LIVE_FEATURES_INSUFFICIENT','LIVE_PROJECTION_CATCHING_UP'):
                    raise
                # Absence is recorded; no replay, fake session, windows or lifecycle calls.
                from cqi_v2 import Policy
                value={'metadata':{'availability':'UNAVAILABLE','reason':exc.code,'session_id':None,
                    'captured_at':datetime.now(timezone.utc).isoformat(),'lookback_seconds':Policy().behavior_horizon_seconds},
                    'records':[],'incidents':[],'model':self.application.model()}
            ctx.live_cache['behavioral']=self.persist(ctx,'behavioral',value)
        return ctx.live_cache['behavioral']

    def check_reference(self,ctx,ref):
        path=(ROOT/ref.path).resolve()
        folder=STATE/'multiagent/snapshots'
        if not path.is_relative_to(folder) or path.name not in (ctx.state.task_id+'-posture.json',ctx.state.task_id+'-behavioral.json') or path.is_symlink():
            raise TaskError('LIVE_REFERENCE_INVALID','Live evidence reference is outside its task snapshot boundary')
        raw=path.read_bytes();value=json.loads(raw)
        if value.get('task_id')!=ctx.state.task_id or value.get('source_kind')!=self.source_kind or hashlib.sha256(raw).hexdigest()!=ref.expected_sha256 or ref.expected_sha256!=ref.read_sha256:
            raise TaskError('LIVE_REFERENCE_INVALID','Task snapshot identity/hash does not match the delivered evidence')
        return value

    def recheck_journal(self,ctx):
        self.require_authorized()
        value,ref=self.behavioral(ctx);self.check_reference(ctx,ref)
        if value['metadata'].get('availability')=='UNAVAILABLE':return value,ref
        meta=value['metadata'];_,root=self.reader.binding()
        if str((root/'journal.sqlite3').relative_to(ROOT))!=meta['journal_path']:
            raise TaskError('LIVE_CROSS_SESSION','Application selected a different journal after snapshot capture')
        manifest=json.loads((root/'session_manifest.json').read_bytes())
        if digest(manifest)!=meta['manifest_sha256']:raise TaskError('LIVE_SESSION_CHANGED','Monitoring manifest changed after snapshot capture')
        db=sqlite3.connect((root/'journal.sqlite3').as_uri()+'?mode=ro',uri=True,timeout=2)
        try:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            for entry in value['records']:
                row=db.execute('SELECT record_id,payload,sha256 FROM results WHERE sequence=?',(entry['sequence'],)).fetchone()
                if not row or row[0]!=entry['record_id'] or row[2]!=entry['payload_sha256'] or checked(row[1],row[2])!=entry['payload']:
                    raise TaskError('LIVE_JOURNAL_CHANGED','Captured observation content changed; append-only growth alone is allowed')
        finally:db.close()
        return value,ref


def snapshot_outputs(ctx):
    adapter=ctx.engine.live_adapter
    posture,_=adapter.posture(ctx);behavior,_=adapter.behavioral(ctx)
    return posture,behavior


def live_tool(ctx,name):
    """Same registered roles/tools, consuming the existing monitoring store."""
    adapter=ctx.engine.live_adapter
    adapter.require_authorized()
    if name=='native.read_baseline':
        value,ref=adapter.posture(ctx)
        rows=value['native']['findings']
        return ToolResult(summary={'findings':len(rows),'scope':'CURRENT_COURSEWORK_POSTURE',
            'provider_status':value['native']['status'],
            'fresh_execution_requested':ctx.state.request.fresh_posture,
            'live_collection':bool(ctx.live_cache.get('posture_job_id') and value['native'].get('provenance',{}).get('fresh_execution'))},
            data={'rows':rows},evidence=[ref])
    if name=='zap.read_assessment':
        value,ref=adapter.posture(ctx);job=value['assessment'];zap=value['zap']
        return ToolResult(summary={'assessment_id':job['assessment_id'],'recorded_profile':job['mode'],
            'saved_findings':len(zap['findings']),'source_status':zap['status'],
            'fresh_execution_requested':ctx.state.request.fresh_posture,
            'new_scan_executed':bool(ctx.live_cache.get('posture_job_id') and zap.get('provenance',{}).get('fresh_execution')),
            'scope':'CURRENT_COURSEWORK_POSTURE'},data={'assessment':job,'findings':zap['findings']},evidence=[ref])
    if name=='zap.check_profile':
        source=ctx.output('zap.read_assessment')
        return ToolResult(summary={**source.summary,'requested_profile':ctx.state.request.zap_profile,
            'monitoring_started_by_task':False,'posture_job_started_by_task':bool(ctx.live_cache.get('posture_job_id')),
            'source_kind':adapter.source_kind},
            data={'target':source.data['assessment']['target']},evidence=source.evidence)
    if name=='behavior.extract_features':
        value,ref=adapter.behavioral(ctx)
        rows=[r['payload']['window']['row'] for r in value['records']]
        return ToolResult(summary={'feature_count':83,'windows':len(rows),'session_id':value['metadata']['session_id'],
            'availability':value['metadata'].get('availability','AVAILABLE'),'reason':value['metadata'].get('reason'),
            'source_kind':adapter.source_kind,'source':'APPLICATION_OWNED_MONITOR_STORE','replay_substituted':False},
            data={'rows':rows,'model':value['model'],'monitor_predictions':[r['payload']['prediction'] for r in value['records']],
                  'snapshot':value['metadata']},evidence=[ref])
    if name=='behavior.infer':
        source=ctx.output('behavior.extract_features')
        predictions=copy.deepcopy(source.data['monitor_predictions'])
        return ToolResult(summary={'windows_inferred':len(predictions),'models':['OCSVM','XGBoost'],
            'training_performed':False,'inference_reused_from_monitor':bool(predictions),
            'inference_executed_by_task':False,'second_inference_process_started':False,
            'shap_available':sum(p['shap_explanation']['status']=='AVAILABLE' for p in predictions)},
            data={'predictions':predictions},evidence=source.evidence)
    if name=='behavior.explain_incidents':
        from demo.backend.adapters import episode
        from demo.backend.explainability import explain
        value,ref=adapter.behavioral(ctx);source=ctx.output('behavior.infer')
        predictions=source.data['predictions']
        incidents=[episode(i,value['model']['package_id'],False).model_dump(mode='json') for i in value['incidents']]
        explanation=(explain(predictions[0],features=value['records'][0]['payload']['window']['row']['features'],
                            package_id=value['model']['package_id']) if predictions else None)
        return ToolResult(summary={**source.summary,'incidents':len(incidents),'session_id':value['metadata']['session_id']},
            data={'incidents':incidents,'example_explanation':explanation},evidence=[ref])
    if name=='verify.consistency':return verify_live(ctx)
    if name=='verify.journal':
        value,ref=adapter.recheck_journal(ctx)
        absent=value['metadata'].get('availability')=='UNAVAILABLE'
        ctx.state.verification.append(VerificationOutcome(subject='live-journal-watermark',status='PARTIAL' if absent else 'VERIFIED',
            reasons=['Behavioral monitoring unavailable; no journal/window evidence asserted' if absent else
                     'Captured committed payloads still match their immutable record hashes; later append-only growth is permitted'],related_refs=[ref.ref_id]))
        counts={s:sum(o.status==s for o in ctx.state.verification) for s in ('VERIFIED','PARTIAL','CONFLICTED','MISSING','INVALID')}
        status=next((s for s in ('INVALID','CONFLICTED','MISSING','PARTIAL') if counts[s]),'VERIFIED')
        return ToolResult(summary={'verification_status':status,'outcomes':counts,'journal_is_scored':True,
            'sqlite_status':'UNAVAILABLE' if absent else 'VERIFIED_READ_TRANSACTION'},data={'permitted_for_live_cqi':not any(counts[s] for s in ('INVALID','CONFLICTED','MISSING'))},evidence=[ref])
    if name=='quality.evaluate':
        if not ctx.output('verify.journal').data.get('permitted_for_live_cqi'):
            raise TaskError('EVIDENCE_REJECTED','Live verification rejected unsupported source/session/time assumptions')
        result=live_quality(ctx)
        return ToolResult(summary={'overall':result['overall'],'policy':result['policy']['version'],
            'dimension_count':6,'scope':'BOUNDED_OWNED_MONITOR_SNAPSHOT'},data={'cqi':result})
    if name=='quality.check_result':
        from .tools import assessment_summary
        result=ctx.output('quality.evaluate').data['cqi'];reference=live_quality(ctx)
        if result!=reference:raise TaskError('CQI_INCONSISTENT','Live result differs from the existing CQI implementation on the captured inputs')
        posture,value=snapshot_outputs(ctx)
        test_only=adapter.source_kind!='APPLICATION_OWNED_LIVE_MONITOR'
        return ToolResult(summary={**ctx.output('quality.evaluate').summary,'consistency_with_existing_cqi':'PASS'},
            data={'cqi':result,'verification':[o.model_dump() for o in ctx.state.verification],
            'live_snapshot':value['metadata'],'assessment_summary':assessment_summary(ctx),
            'assessment_outcome':'TEST_ONLY_LIVE_INTEGRATION' if test_only else 'LIVE_SNAPSHOT_ASSESSMENT',
            'source_kind':adapter.source_kind,'consistency_with_existing_cqi':'PASS',
            'warnings':(['TEST-ONLY local fixture; no shared laboratory operation was executed.'] if test_only else [])+
                ['Behavioral uses an existing monitor or explicitly records its absence; it never starts/stops monitoring.',
                 'Native/ZAP use the existing authorized posture workflow when fresh collection is requested; otherwise the explicit saved ID is used.',
                 'CQI uses the captured monitoring watermark and current verified coursework posture, not historical replay.']})
    raise TaskError('LIVE_TOOL_NOT_REGISTERED','No live adapter is registered for this role/tool')


def verify_live(ctx):
    from behavioral_v2.features31 import matrix
    from .tools import read, outcome
    adapter=ctx.engine.live_adapter;posture,value=snapshot_outputs(ctx)
    for key in ('posture','behavioral'):
        stored,ref=ctx.live_cache[key]
        if adapter.check_reference(ctx,ref)!=stored:raise TaskError('LIVE_SNAPSHOT_CHANGED','Task snapshot content changed')
    outcomes=[]
    native=ctx.output('native.read_baseline').data['rows'];zap=ctx.output('zap.read_assessment').data['findings']
    if native!=posture['native']['findings'] or zap!=posture['zap']['findings']:
        outcomes.append(outcome('live-posture-content','CONFLICTED','Delivered Native/ZAP evidence differs from the captured assessment'))
    else:outcomes.append(outcome('live-posture-content','VERIFIED','Native/ZAP evidence comes from one current coursework assessment'))
    for path,expected in posture['source_files'].items():
        source=(ROOT/path).resolve()
        if not source.is_relative_to(STATE) or hashlib.sha256(source.read_bytes()).hexdigest()!=expected:
            outcomes.append(outcome('live-posture-artifact','INVALID','Current posture source file changed after capture'))
    job=posture['assessment'];meta=value['metadata'];as_of=utc(meta['captured_at'])
    allowed={'CONFIRMED','VERSION_BASED','LIKELY','CONTEXTUAL','NOT_CONFIRMED','NOT_APPLICABLE','NOT_TESTED','FALSE_POSITIVE'}
    for provider,records in (('Native',native),('ZAP',zap)):
        seen={}
        for record in records:
            rid=record.get('evidence_id')
            if not rid or record.get('assessment_id')!=job['assessment_id'] or record.get('confirmation_status') not in allowed:
                outcomes.append(outcome(provider+'-identity','INVALID','Finding ID, provider assessment ID or evidence status is unsupported'))
            signature=digest(record)
            if rid in seen:
                outcomes.append(outcome(provider+'-duplicate','PARTIAL' if seen[rid]==signature else 'CONFLICTED',
                    'Duplicate or contradictory identity within the current provider evidence'))
            seen[rid]=signature
            start,end=record.get('start_utc'),record.get('end_utc')
            if start and end and not utc(job['started_at'])<=utc(start)<=utc(end)<=utc(job['completed_at']):
                outcomes.append(outcome(provider+'-time','CONFLICTED','Provider finding timestamps fall outside its assessment interval'))
    from cqi_v2 import Policy
    if not utc(job['started_at'])<=utc(job['completed_at'])<=as_of:
        outcomes.append(outcome('live-temporal-alignment','CONFLICTED','Posture interval is reversed or future-dated'))
    elif (as_of-utc(job['completed_at'])).total_seconds()>Policy().posture_max_age_seconds:
        outcomes.append(outcome('live-temporal-alignment','PARTIAL','Posture exceeds its own CQI freshness policy; unchanged CQI handles unavailable controls'))
    else:outcomes.append(outcome('live-temporal-alignment','VERIFIED','Posture satisfies its own freshness policy; Behavioral has a separate window/session horizon'))
    extraction=ctx.output('behavior.extract_features');predictions=ctx.output('behavior.infer').data['predictions']
    expected=[r['payload']['prediction'] for r in value['records']]
    if predictions!=expected or extraction.data['rows']!=[r['payload']['window']['row'] for r in value['records']]:
        outcomes.append(outcome('live-inference-identity','CONFLICTED','Delivered vectors/inference do not match the committed monitor records'))
    else:outcomes.append(outcome('live-inference-identity','VERIFIED','83-feature vectors, inference and TreeSHAP are reused from committed monitor windows'))
    schema=read('outputs/branch2/accepted_behavioral_v2/model/feature_schema.json')
    matrix(extraction.data['rows'],schema)
    ids={p['record_id'] for p in predictions}
    if any(p.get('session_id')!=meta['session_id'] or p.get('model_id')!=meta['model_id'] for p in predictions):
        outcomes.append(outcome('live-session','INVALID','A delivered prediction belongs to another session/model'))
    if any(not set(i['observation_ids'])<=ids for i in ctx.output('behavior.explain_incidents').data['incidents']):
        outcomes.append(outcome('live-incident-membership','INVALID','An incident is not fully supported by captured windows'))
    if job.get('coverage',{}).get('status')!='FULL' or not native:
        outcomes.append(outcome('live-coverage','PARTIAL','Some posture controls/provider coverage are unavailable; missing evidence is not PASS'))
    if meta.get('availability')=='UNAVAILABLE':
        outcomes.append(outcome('behavioral-availability','PARTIAL','No eligible active Behavioral stream; existing CQI policy decides partial-evidence scoring'))
    elif meta.get('checkpoint_sequence')!=meta['committed_highwater']:
        outcomes.append(outcome('live-checkpoint-lag','PARTIAL','Checkpoint is not the transactional watermark; scoring uses the captured committed journal only'))
    ctx.state.verification.extend(outcomes)
    return ToolResult(summary={'consistency_checks':len(outcomes),'temporal_scope':'BOUNDED_OWNED_MONITOR_SNAPSHOT'},
                      data={'outcomes':[o.model_dump() for o in outcomes]})


def live_quality(ctx):
    from demo.backend.schemas import Incident
    posture,value=snapshot_outputs(ctx)
    # Bind the existing application calculation to this task's verified rows and
    # posture. It must not reselect latest/session/replay while the task runs.
    service=ctx.engine.live_adapter.application
    snap={'model':value['model'],'incidents':[Incident.model_validate(i) for i in ctx.output('behavior.explain_incidents').data['incidents']], 'cqi':None}
    evidence={'assessment':posture['assessment'],'rows':ctx.output('behavior.infer').data['predictions'],'historical':False}
    return service.scientific_quality('LIVE_LAB',as_of=value['metadata']['captured_at'],bound_snapshot=(snap,evidence))
