"""Passive M2D runtime: canonical append-only observations -> saved inference.

Durable replay begins before pending observations. A transactional on-disk result
journal makes replay idempotent without retaining historical events in memory.
"""
from datetime import datetime,timezone
import fcntl
import hashlib
import json
import math
import sqlite3
from pathlib import Path
import time
import uuid
import numpy as np
from .adapters.apache import parse_line
from .artifacts import load
from .features import extract,matrix
from .events import utc
from .windowing import windows
from .live_reader import AppendReader
from .live_storage import IntegrityFault,Journal,atomic_json,append_json,digest,sync_directory

VERSION='branch2-live-1.0'
SCHEMA_HASH='7f938a6f076339108cbf26e4a37c6f4aff0fe85836f44187b3dcf18b93692417'
CLASSES=['ADMIN_PROBING','BENIGN','BRUTE_FORCE','ENUMERATION_RECONNAISSANCE','PATH_TRAVERSAL_ATTEMPT','REQUEST_BURST_DOS_LIKE','SQLI_ATTEMPT','XSS_ATTEMPT']


def iso(value):return value.astimezone(timezone.utc).isoformat()


def epoch(value):return value.astimezone(timezone.utc).timestamp()


def latency_summary(values):
    return {'count':len(values),'min':float(min(values)),'median':float(np.median(values)),
            'p95':float(np.percentile(values,95)),'max':float(max(values)),'mean':float(np.mean(values))} if values else {'count':0}


class LiveEngine:
    def __init__(self,source,model,out,*,resume=False,grace=2.0,poll_interval=.5,explain=True,
                 max_parse_failures=10,max_pending=100000,clock=lambda:datetime.now(timezone.utc),
                 timer=time.perf_counter,loader=load,status=None):
        if not math.isfinite(grace) or not 0<=grace<=30:raise ValueError('Grace must be in [0,30] seconds')
        if not math.isfinite(poll_interval) or not .05<=poll_interval<=10:raise ValueError('Poll interval must be in [0.05,10] seconds')
        if isinstance(max_parse_failures,bool) or not isinstance(max_parse_failures,int) or not 0<=max_parse_failures<=100:raise ValueError('Invalid parse-failure bound')
        if isinstance(max_pending,bool) or not isinstance(max_pending,int) or not 1<=max_pending<=100000:raise ValueError('Invalid pending-event bound')
        self.clock,self.timer,self.status=clock,timer,status
        self.model_path=Path(model).resolve();self.root=Path(out).resolve()
        if self.root.is_relative_to(self.model_path) or self.model_path.is_relative_to(self.root) or Path(source).resolve().is_relative_to(self.root):
            raise ValueError('Session output must be separate from source/model artifacts')
        manifest_file=self.model_path/'package_manifest.json'
        model_manifest=json.loads(manifest_file.read_text())
        self.model_files=[manifest_file]+[self.model_path/name for name in model_manifest.get('files_sha256',{})]
        self.model_stats=self.model_fingerprint()
        self.package=loader(self.model_path)  # Strict package hashes/schema validated by loader.
        matrix([],self.package.feature_schema)
        if self.package.feature_schema['sha256']!=SCHEMA_HASH or self.package.feature_schema['window_seconds']!=10 or self.package.classes!=CLASSES or self.package.classifier is None or self.package.reconciliation['confidence_threshold']!=.8:
            raise IntegrityFault('FROZEN_MODEL_SCHEMA_OR_CLASS_MISMATCH')
        self.model_id=hashlib.sha256(manifest_file.read_bytes()).hexdigest()
        if self.model_stats!=self.model_fingerprint():raise IntegrityFault('MODEL_PACKAGE_CHANGED_DURING_LOAD')
        self.config={'grace_seconds':grace,'poll_interval_seconds':poll_interval,'explain':bool(explain),
                     'max_parse_failures':max_parse_failures,'max_pending_events':max_pending}
        self.pending=[];self.pending_bytes=0;self.unprocessed_offset=None;self.closed=False;self.integrity='OK'
        self.reader=None;self.journal=None;self.lock=None
        if self.root.exists() and not resume:raise ValueError('Existing session requires explicit --resume')
        if not self.root.exists() and resume:raise ValueError('Resume requires an existing session')
        if not resume:
            self.root.mkdir(parents=True);sync_directory(self.root.parent)
        self.lock=(self.root/'.runtime.lock').open('a')
        try:
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close();raise IntegrityFault('SESSION_ALREADY_RUNNING') from None
        try:
            now=self.clock()
            if now.tzinfo is None:raise IntegrityFault('WALL_CLOCK_TIMEZONE_REQUIRED')
            self.last_now=now;self.session_id=None
            if resume:
                if (self.root/'integrity_fault.json').exists():raise IntegrityFault('PRIOR_INTEGRITY_FAULT_REQUIRES_REVIEW')
                checkpoint=json.loads((self.root/'checkpoint.json').read_text())
                manifest=json.loads((self.root/'session_manifest.json').read_text())
                self.session_id=manifest['session_id']
                if checkpoint['manifest_sha256']!=digest(manifest):raise IntegrityFault('SESSION_MANIFEST_CHANGED')
                if manifest['model_id']!=self.model_id or manifest['model_path']!=str(self.model_path):raise IntegrityFault('MODEL_IDENTITY_CHANGED')
                if checkpoint['model_id']!=self.model_id or checkpoint['schema_sha256']!=SCHEMA_HASH or checkpoint['schema_version']!=self.package.feature_schema['version'] or checkpoint['window_seconds']!=10 or checkpoint['session_id']!=manifest['session_id']:raise IntegrityFault('CHECKPOINT_IDENTITY_CHANGED')
                if checkpoint['engine_version']!=VERSION or manifest['engine_version']!=VERSION:raise IntegrityFault('ENGINE_STATE_INCOMPATIBLE')
                if manifest['schema_sha256']!=self.package.feature_schema['sha256'] or manifest['config']!=self.config:raise IntegrityFault('SCHEMA_OR_CONFIG_CHANGED')
                if checkpoint['integrity_status']!='OK':raise IntegrityFault('PRIOR_INTEGRITY_FAULT_REQUIRES_REVIEW')
                if epoch(now)<epoch(utc(checkpoint['updated_at_utc'])):raise IntegrityFault('WALL_CLOCK_MOVED_BACKWARDS')
                if str(Path(source).resolve())!=manifest['source_path']:raise IntegrityFault('SOURCE_IDENTITY_CHANGED')
                self.reader=AppendReader(source,checkpoint['source'])
                self.manifest=manifest;self.session_id=manifest['session_id']
                self.first_window_start=manifest['first_complete_window_start_epoch']
                self.watermark=checkpoint['finalized_through_epoch']
                self.counters=checkpoint['counters'];self.counter_offset=checkpoint['counter_offset']
                self.replay_highwater=checkpoint['source']['read_offset']
            else:
                self.reader=AppendReader(source)
                self.session_id=uuid.uuid4().hex
                self.first_window_start=math.ceil(epoch(now)/10)*10
                self.watermark=self.first_window_start
                self.counters=dict.fromkeys(['bytes_consumed','complete_lines','canonical_events','excluded_dummy_events',
                    'cold_start_exclusions','preexisting_partial_exclusions','parse_failures','explanation_failures'],0)
                self.counter_offset=self.reader.cursor;self.replay_highwater=self.reader.cursor
                self.manifest={'engine_version':VERSION,'session_id':self.session_id,'started_at_utc':iso(now),
                    'source_path':str(self.reader.path),'source_device':self.reader.device,'source_inode':self.reader.inode,
                    'start_offset':self.reader.cursor,'startup_mode':'FIRST_START_AT_EOF','model_path':str(self.model_path),
                    'model_id':self.model_id,'schema_version':self.package.feature_schema['version'],
                    'schema_sha256':self.package.feature_schema['sha256'],'feature_count':65,'window_seconds':10,
                    'first_complete_window_start_epoch':self.first_window_start,'config':self.config,
                    'training_performed':False,'POST_bodies':'unavailable','confidence_calibrated':False,
                    'source_sha256_semantics':'per-window ordered record hash digest; never an invented whole-file hash',
                    'cold_start':'omit startup partial UTC interval; emit only nonempty complete post-start windows'}
                atomic_json(self.root/'session_manifest.json',self.manifest)
            self.journal=Journal(self.root)
            if resume and checkpoint['last_emitted_sequence']>self.journal.sequence:raise IntegrityFault('JOURNAL_BEHIND_CHECKPOINT')
            self.audit('RESUME' if resume else 'START',safe_offset=self.reader.cursor)
            self.checkpoint()
        except (OSError,ValueError,KeyError,sqlite3.Error) as error:
            self.audit('STARTUP_INTEGRITY_FAULT',code=str(error) if isinstance(error,IntegrityFault) else 'STATE_OR_FILESYSTEM_INVALID')
            if self.journal:self.journal.close()
            self.lock.close()
            raise

    def model_fingerprint(self):
        values=[]
        for path in self.model_files:
            stat=path.stat();values.append((stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns))
        return values

    def audit(self,reason,**safe):
        append_json(self.root/'audit.jsonl',{'reason':reason,'at_utc':iso(self.clock()),'session_id':self.session_id,**safe})

    def persist_fault(self):
        atomic_json(self.root/'integrity_fault.json',{'code':self.integrity,'at_utc':iso(self.clock()),'session_id':self.session_id,'automatic_resume_permitted':False})

    def checkpoint(self):
        offsets=[item[1] for item in self.pending]
        if self.reader.replay_guard is not None:offsets.append(self.reader.replay_guard[0])
        if self.unprocessed_offset is not None:offsets.append(self.unprocessed_offset)
        safe=min(offsets) if offsets else self.reader.cursor
        state={'engine_version':VERSION,'session_id':self.session_id,'manifest_sha256':digest(self.manifest),
            'model_id':self.model_id,'schema_version':self.package.feature_schema['version'],'schema_sha256':SCHEMA_HASH,
            'window_seconds':10,'updated_at_utc':iso(self.clock()),'source':self.reader.state(safe),
            'finalized_through_epoch':self.watermark,'last_emitted_sequence':self.journal.sequence,
            'counter_offset':self.counter_offset,'counters':self.counters,'integrity_status':self.integrity}
        atomic_json(self.root/'checkpoint.json',state)

    def poll(self):
        if self.closed:raise ValueError('Session is closed')
        if self.integrity!='OK':raise IntegrityFault('SESSION_INTEGRITY_FAULT')
        try:
            now=self.clock()
            if self.model_stats!=self.model_fingerprint():raise IntegrityFault('MODEL_PACKAGE_CHANGED_DURING_SESSION')
            if epoch(now)<epoch(self.last_now):raise IntegrityFault('WALL_CLOCK_MOVED_BACKWARDS')
            self.last_now=now
            for start,end,raw,preexisting in self.reader.poll():
                self.unprocessed_offset=start
                new=start>=self.counter_offset
                if new:self.counters['bytes_consumed']+=end-start;self.counters['complete_lines']+=1
                record_hash=hashlib.sha256(raw).hexdigest()
                if preexisting:
                    if new:self.counters['preexisting_partial_exclusions']+=1;self.audit('PREEXISTING_PARTIAL_DISCARDED',byte_start=start,byte_end=end,record_sha256=record_hash)
                else:
                    try:
                        # Byte-derived ordinal guarantees deterministic sort on replay,
                        # without counting/re-reading pre-start historical log lines.
                        event=parse_line(raw.decode('utf-8',errors='replace').rstrip('\r\n'),str(self.reader.path),record_hash,start+1)
                    except (ValueError,OverflowError):
                        if new:
                            self.counters['parse_failures']+=1
                            self.audit('MALFORMED_COMBINED_RECORD',byte_start=start,byte_end=end,record_sha256=record_hash)
                        if self.counters['parse_failures']>self.config['max_parse_failures']:raise IntegrityFault('PARSE_FAILURE_LIMIT_EXCEEDED')
                    else:
                        if event.infrastructure_dummy:
                            if new:self.counters['excluded_dummy_events']+=1
                        else:
                            if new:self.counters['canonical_events']+=1
                            tick=math.floor(epoch(event.timestamp)/10)*10
                            if tick<self.first_window_start:
                                if new:self.counters['cold_start_exclusions']+=1
                            else:
                                if tick+10<=self.watermark:
                                    known=end<=self.replay_highwater and self.journal.observed(self.record_id(event),start,end,record_hash)
                                    if not known:raise IntegrityFault('LATE_EVENT_FOR_FINALIZED_WINDOW')
                                    if new:self.counter_offset=end
                                    self.unprocessed_offset=None
                                    continue
                                if epoch(event.timestamp)>epoch(now)+60:raise IntegrityFault('FUTURE_TIMESTAMP_BOUND_EXCEEDED')
                                self.pending.append((event,start,end,record_hash));self.pending_bytes+=end-start
                                if self.pending_bytes>16*1024*1024:raise IntegrityFault('PENDING_BYTE_BOUND_EXCEEDED')
                                if len(self.pending)>self.config['max_pending_events']:raise IntegrityFault('PENDING_EVENT_BOUND_EXCEEDED')
                if new:self.counter_offset=end
                self.unprocessed_offset=None
            self.reader.ack()
            # Do not close while a byte backlog or partial final line remains.
            if self.reader.drained:
                through=max(self.watermark,math.floor((epoch(now)-self.config['grace_seconds'])/10)*10)
                self.finalize(through)
                self.watermark=through
            self.checkpoint()
        except IntegrityFault as error:
            self.integrity=str(error);self.persist_fault();self.audit('INTEGRITY_FAULT',code=self.integrity)
            raise
        except (OSError,ValueError,KeyError,sqlite3.Error):
            self.integrity='SOURCE_OR_ARTIFACT_IO_FAILURE';self.persist_fault();self.audit('INTEGRITY_FAULT',code=self.integrity)
            raise IntegrityFault(self.integrity) from None

    def record_id(self,event):
        group=next(windows([event],10))
        return digest({'engine':VERSION,'session_id':self.session_id,'source_device':self.reader.device,
            'source_inode':self.reader.inode,'window_start':group['window_start'],'client_id':group['client_id'],
            'user_agent_id':group['user_agent_id'],'model_id':self.model_id})

    def finalize(self,through):
        eligible=[item for item in self.pending if epoch(item[0].timestamp)//10*10+10<=through]
        positions={item[0].line_number:item for item in eligible}
        for group in windows([item[0] for item in eligible],10):
            events=group.pop('events');items=[positions[e.line_number] for e in events]
            record_id=self.record_id(events[0])
            started=self.timer()
            source_hash=digest([{'byte_start':item[1],'byte_end':item[2],'record_sha256':item[3]} for item in items])
            row={**group,'run_id':'live-'+self.session_id,'source_file':str(self.reader.path),'source_sha256':source_hash,
                'feature_schema_version':self.package.feature_schema['version'],'schema_sha256':SCHEMA_HASH,
                'features':extract(events,10,self.package.feature_schema['path_rules'])}
            window={'record_id':record_id,'session_id':self.session_id,'source_device':self.reader.device,'source_inode':self.reader.inode,
                'observation_count':len(events),'source_byte_ranges':[{'start':i[1],'end':i[2],'sha256':i[3]} for i in items],
                'adapter_position_semantics':'byte_start+1; not an asserted absolute Apache line number','row':row}
            if not self.journal.existing(record_id,window):
                prediction=self.package.predict([row],explain=self.config['explain'])[0]
                duration=(self.timer()-started)*1000
                emitted=self.clock()
                if epoch(emitted)<epoch(self.last_now):raise IntegrityFault('WALL_CLOCK_MOVED_BACKWARDS')
                if not math.isfinite(duration) or duration<0:raise IntegrityFault('PROCESSING_TIMER_INVALID')
                prediction.update(record_id=record_id,session_id=self.session_id,source_path=str(self.reader.path),
                    source_device=self.reader.device,source_inode=self.reader.inode,source_byte_ranges=window['source_byte_ranges'],
                    client_id=group['client_id'],user_agent_id=group['user_agent_id'],observation_count=len(events),
                    emitted_at_utc=iso(emitted),model_id=self.model_id,feature_schema_version=self.package.feature_schema['version'],
                    schema_sha256=SCHEMA_HASH,confidence_calibrated=False,training_performed=False,
                    processing_duration_ms=duration,window_close_to_emission_ms=(epoch(emitted)-epoch(utc(group['window_end'])))*1000,
                    if_score_semantics=self.package.metadata['if_decision_semantics'])
                shap=prediction['shap_explanation']
                if self.config['explain'] and (shap['status']!='AVAILABLE' or not shap['top_features']):
                    self.counters['explanation_failures']+=1;self.audit('EXPLANATION_UNAVAILABLE',record_id=record_id,status=shap['status'])
                self.journal.persist(window,prediction)
                if self.status:self.status(prediction)
        emitted={item[1] for item in eligible}
        self.pending=[item for item in self.pending if item[1] not in emitted]
        self.pending_bytes=sum(item[2]-item[1] for item in self.pending)

    def stop(self,reason='GRACEFUL_STOP'):
        if self.closed:return
        try:
            # Never force open windows closed on stop; checkpoint retains replay.
            try:self.checkpoint()
            except (OSError,IntegrityFault):
                if self.integrity=='OK':self.integrity='CHECKPOINT_SOURCE_CONTINUITY_FAILURE'
                self.persist_fault();self.audit('CHECKPOINT_NOT_ADVANCED',code=self.integrity)
            summaries,explanation_failures=self.journal.summaries()
            atomic_json(self.root/'latency_summary.json',{**summaries,'semantics':'measured inference processing; fixed windows plus grace; not instant detection'})
            atomic_json(self.root/'session_summary.json',{'session_id':self.session_id,**self.counters,
                'windows':self.journal.sequence,'prediction_records':self.journal.sequence,
                'logical_model_inference_count':self.journal.sequence,'pending_events':len(self.pending),
                'explanation_failures':explanation_failures,'integrity_status':self.integrity,'stop_reason':reason,
                'stopped_at_utc':iso(self.clock()),'training_performed':False,'fit_calls':0,
                'replay_semantics':'journaled results do not reinfer; unjournaled work may be recomputed after a crash'})
            self.audit('SHUTDOWN',stop_reason=reason,integrity_status=self.integrity)
        finally:
            self.closed=True;self.journal.close();self.lock.close()

    def run(self,duration=None,sleep=time.sleep):
        if duration is not None and (not math.isfinite(duration) or not .1<=duration<=86400):
            self.stop('INVALID_DURATION');raise ValueError('Duration must be in [0.1,86400] seconds')
        start=self.timer();reason='DURATION_COMPLETE'
        try:
            while duration is None or self.timer()-start<duration:
                self.poll();sleep(self.config['poll_interval_seconds'])
        except KeyboardInterrupt:reason='CTRL_C'
        except IntegrityFault:
            reason='INTEGRITY_FAULT';raise
        finally:self.stop(reason)
