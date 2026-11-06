"""Passive v2 engine using the accepted M2D reader, journal and continuity logic.

Only package/bootstrap identity and the frozen feature/prediction boundary differ.
The inherited reader/poll/run/stop implementation is not forked or modified.
"""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import time
import uuid
from branch2.live import LiveEngine as BaselineEngine, iso, epoch, CLASSES
from branch2.live_reader import AppendReader
from branch2.live_storage import IntegrityFault, Journal, atomic_json, digest, sync_directory
from branch2.windowing import windows
from branch2.events import utc
from behavioral_v2.features31 import matrix, extract
from behavioral_v2.platforms import MoodleBehaviorAdapter, GenericHTTPBehaviorAdapter
from .package import load, verify, PROJECT
from .incidents import Incidents

VERSION = 'behavioral-v2-live-1.0'


def adapter_for(schema):
    identity=schema['adapter']
    if identity['platform_id']=='moodle':return MoodleBehaviorAdapter(identity['mount'])
    if identity['platform_id']=='generic_http':return GenericHTTPBehaviorAdapter(identity['routes'])
    raise IntegrityFault('PLATFORM_ADAPTER_UNAVAILABLE')


class LiveEngine(BaselineEngine):
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
        manifest_file=self.model_path/'accepted_manifest.json'
        model_manifest=verify(self.model_path)
        self.model_files=[manifest_file]+[self.model_path/name for name in model_manifest.get('files_sha256',{})]
        self.model_files += [PROJECT/name for name in model_manifest['code_sha256']]
        self.model_stats=self.model_fingerprint()
        self.package=loader(self.model_path)  # Strict package hashes/schema validated by loader.
        matrix([],self.package.feature_schema)
        self.schema_hash=self.package.feature_schema['sha256']
        self.adapter=adapter_for(self.package.feature_schema)
        if self.package.feature_schema['window_seconds']!=10 or self.package.classes!=CLASSES or self.package.classifier is None or self.package.config['confidence_threshold']!=.8 or self.package.config['selected_model']!='OCSVM' or self.package.config['persistence']!=2:
            raise IntegrityFault('FROZEN_MODEL_SCHEMA_OR_CLASS_MISMATCH')
        self.model_id=model_manifest['package_id']
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
                if checkpoint['model_id']!=self.model_id or checkpoint['schema_sha256']!=self.schema_hash or checkpoint['schema_version']!=self.package.feature_schema['version'] or checkpoint['window_seconds']!=10 or checkpoint['session_id']!=manifest['session_id']:raise IntegrityFault('CHECKPOINT_IDENTITY_CHANGED')
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
                    'schema_sha256':self.package.feature_schema['sha256'],'feature_count':83,'window_seconds':10,
                    'first_complete_window_start_epoch':self.first_window_start,'config':self.config,
                    'training_performed':False,'POST_bodies':'unavailable','confidence_calibrated':False,
                    'source_sha256_semantics':'per-window ordered record hash digest; never an invented whole-file hash',
                    'cold_start':'omit startup partial UTC interval; emit only nonempty complete post-start windows'}
                atomic_json(self.root/'session_manifest.json',self.manifest)
            self.journal=Journal(self.root)
            if resume and checkpoint['last_emitted_sequence']>self.journal.sequence:raise IntegrityFault('JOURNAL_BEHIND_CHECKPOINT')
            self.incidents=Incidents(self.journal,self.package.config['persistence'],self.model_id)
            self.audit('RESUME' if resume else 'START',safe_offset=self.reader.cursor)
            self.checkpoint()
        except (OSError,ValueError,KeyError,sqlite3.Error) as error:
            self.audit('STARTUP_INTEGRITY_FAULT',code=str(error) if isinstance(error,IntegrityFault) else 'STATE_OR_FILESYSTEM_INVALID')
            if self.journal:self.journal.close()
            self.lock.close()
            raise

    def checkpoint(self):
        offsets = [item[1] for item in self.pending]
        if self.reader.replay_guard is not None:
            offsets.append(self.reader.replay_guard[0])
        if self.unprocessed_offset is not None:
            offsets.append(self.unprocessed_offset)
        safe = min(offsets) if offsets else self.reader.cursor
        atomic_json(self.root / 'checkpoint.json', {
            'engine_version': VERSION, 'session_id': self.session_id,
            'manifest_sha256': digest(self.manifest), 'model_id': self.model_id,
            'schema_version': self.package.feature_schema['version'], 'schema_sha256': self.schema_hash,
            'window_seconds': 10, 'updated_at_utc': iso(self.clock()), 'source': self.reader.state(safe),
            'finalized_through_epoch': self.watermark, 'last_emitted_sequence': self.journal.sequence,
            'counter_offset': self.counter_offset, 'counters': self.counters, 'integrity_status': self.integrity})

    def record_id(self, event):
        group = next(windows([event], 10))
        return digest({'engine': VERSION, 'session_id': self.session_id,
                       'source_device': self.reader.device, 'source_inode': self.reader.inode,
                       'window_start': group['window_start'], 'client_id': group['client_id'],
                       'user_agent_id': group['user_agent_id'], 'model_id': self.model_id})

    def finalize(self, through):
        eligible = [item for item in self.pending if epoch(item[0].timestamp) // 10 * 10 + 10 <= through]
        positions = {item[0].line_number: item for item in eligible}
        for group in windows([item[0] for item in eligible], 10):
            events = group.pop('events')
            items = [positions[e.line_number] for e in events]
            record_id = self.record_id(events[0])
            started = self.timer()
            source_hash = digest([{'byte_start': i[1], 'byte_end': i[2], 'record_sha256': i[3]} for i in items])
            row = {**group, 'run_id': 'live-' + self.session_id, 'source_file': str(self.reader.path),
                   'source_sha256': source_hash, 'feature_schema_version': self.package.feature_schema['version'],
                   'schema_sha256': self.schema_hash, 'features': extract(events, self.adapter)}
            window = {'record_id': record_id, 'observation_id': record_id, 'session_id': self.session_id,
                      'source_device': self.reader.device, 'source_inode': self.reader.inode,
                      'observation_count': len(events),
                      'source_byte_ranges': [{'start': i[1], 'end': i[2], 'sha256': i[3]} for i in items],
                      'adapter_position_semantics': 'byte_start+1; not an absolute Apache line number', 'row': row}
            if not self.journal.existing(record_id, window):
                p = self.package.predict([row], explain=self.config['explain'])[0]
                duration = (self.timer() - started) * 1000
                emitted = self.clock()
                if epoch(emitted) < epoch(self.last_now):
                    raise IntegrityFault('WALL_CLOCK_MOVED_BACKWARDS')
                if not math.isfinite(duration) or duration < 0:
                    raise IntegrityFault('PROCESSING_TIMER_INVALID')
                if not p['shap_explanation']:
                    p['shap_explanation'] = {'status': 'NOT_REQUESTED', 'top_features': [], 'causal': False}
                p.update(record_id=record_id, observation_id=record_id, session_id=self.session_id,
                         source_path=str(self.reader.path), source_device=self.reader.device,
                         source_inode=self.reader.inode, source_byte_ranges=window['source_byte_ranges'],
                         observation_count=len(events), emitted_at_utc=iso(emitted), model_id=self.model_id,
                         accepted_package_id=self.model_id, schema_sha256=self.schema_hash,
                         feature_schema_version=self.package.feature_schema['version'],
                         novelty_state='ANOMALOUS' if p['novelty_anomalous'] else 'NORMAL',
                         model_disagreement=p['reconciliation']['model_disagreement'],
                         confidence_calibrated=False, training_performed=False,
                         processing_duration_ms=duration,
                         window_close_to_emission_ms=(epoch(emitted) - epoch(utc(group['window_end']))) * 1000,
                         novelty_score_semantics='Frozen OCSVM score_samples < frozen cutoff; not a probability')
                shap = p['shap_explanation']
                if self.config['explain'] and (shap['status'] != 'AVAILABLE' or not shap['top_features']):
                    self.counters['explanation_failures'] += 1
                    self.audit('EXPLANATION_UNAVAILABLE', record_id=record_id, status=shap['status'])
                self.journal.persist(window, p)
                self.incidents.sync()
                if self.status:
                    self.status(p)
        emitted_offsets = {item[1] for item in eligible}
        self.pending = [item for item in self.pending if item[1] not in emitted_offsets]
        self.pending_bytes = sum(item[2] - item[1] for item in self.pending)
