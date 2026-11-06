"""M2D append-only TEMP log fixtures. No Apache host access or generated traffic."""
import copy
from datetime import datetime,timedelta,timezone
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from branch2.live import LiveEngine,IntegrityFault,SCHEMA_HASH,CLASSES
from branch2.live_reader import AppendReader,MAX_LINE
from branch2.live_storage import atomic_json,Journal
from branch2.features import FEATURES,schema,extract,matrix
from branch2.windowing import windows
from branch2.adapters.apache import parse_line
from branch2.reconciliation import reconcile
from branch2.artifacts import load
MODEL=ROOT/'outputs/branch2/m2c_final_01'


def line(second=14,client='192.0.2.1',agent='FixtureAgent',query='?q=lesson',method='GET',path='/moodle/course/index.php'):
    return f'{client} - - [07/Oct/2026:12:00:{second:02d} +0000] "{method} {path}{query} HTTP/1.1" 200 100 "-" "{agent}"\n'.encode()


class Clock:
    def __init__(self):self.now=datetime(2026,10,7,12,0,3,tzinfo=timezone.utc)
    def __call__(self):return self.now
    def at(self,seconds):self.now=datetime(2026,10,7,12,0,tzinfo=timezone.utc)+timedelta(seconds=seconds)


class Package:
    """Prediction stub for protocol tests only; never creates fitted artifacts."""
    def __init__(self):
        self.feature_schema=schema();self.classes=list(CLASSES);self.classifier=object()
        self.reconciliation={'confidence_threshold':.8};self.metadata={'if_decision_semantics':'score_samples-offset_; <0 anomalous'}
        self.calls=[];self.shap_status='AVAILABLE'
    def predict(self,rows,explain=True):
        matrix(rows,self.feature_schema);self.calls+=copy.deepcopy(rows)
        result=[]
        for row in rows:
            shap={'method':'SHAP','backend':'TEST_STUB','status':self.shap_status if explain else 'NOT_REQUESTED',
                  'output_space':'raw model margin','causal':False,'top_features':[{'feature':'request_count','contribution':.1}] if explain and self.shap_status=='AVAILABLE' else []}
            result.append({k:row[k] for k in ('run_id','window_start','window_end','source_file','source_sha256')})
            result[-1].update(label=None,scenario=None,if_anomalous=False,if_decision_function=.1,if_raw_anomaly_score=.4,
                xgb_label='BENIGN',xgb_confidence=.95,xgb_scores=[.95 if c=='BENIGN' else .05/7 for c in CLASSES],
                reconciliation=reconcile(False,'BENIGN',.95,.8),robust_explanation={'causal':False,'top_features':[{'feature':'request_count','absolute_deviation':1}]},
                shap_explanation=shap,semantic_confirmation='CONTEXTUAL',semantic_scope='behavioral evidence, not compromise')
        return result
    def fit(self,*a,**kw):raise AssertionError('No fitting in live runtime')


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('socket.socket',side_effect=AssertionError('No network')))
        self.directory=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.source=self.directory/'fixture-access.log';self.source.touch()
        self.out=self.directory/'session';self.clock=Clock();self.package=Package();self.engines=[]
        self.addCleanup(self.close_engines)
    def close_engines(self):
        for engine in self.engines:
            if not engine.closed:engine.stop('TEST_END')
    def engine(self,**kw):
        engine=LiveEngine(self.source,MODEL,self.out,clock=self.clock,loader=lambda p:self.package,**kw)
        self.engines.append(engine);return engine
    def append(self,raw):
        with self.source.open('ab') as handle:handle.write(raw)
    def records(self,name='predictions.jsonl'):
        return [json.loads(r) for r in (self.out/name).read_text().splitlines()]
    def emit(self,engine=None):
        engine=engine or self.engine();self.append(line());self.clock.at(15);engine.poll();self.clock.at(22);engine.poll();return engine
    def abandon(self,engine):
        engine.journal.close();engine.lock.close();engine.closed=True  # Simulated process death; NO checkpoint.

    def test_eof_start_ignores_history_and_only_reads_appended_complete_lines(self):
        self.source.write_bytes(line(1));engine=self.engine();baseline=self.source.stat().st_size
        self.assertEqual(engine.reader.cursor,baseline);engine.poll()
        self.assertEqual(engine.counters['complete_lines'],0)
        self.append(line());self.clock.at(15);engine.poll()
        self.assertEqual(engine.reader.cursor,self.source.stat().st_size);self.assertEqual(engine.counters['complete_lines'],1)
        self.assertEqual(len(engine.pending),1);self.assertEqual(self.package.calls,[])

    def test_partial_trailing_line_waits_for_newline_with_exact_offsets(self):
        engine=self.engine();raw=line();half=len(raw)//2;self.append(raw[:half]);self.clock.at(15);engine.poll()
        self.assertEqual(engine.reader.cursor,0);self.assertEqual(engine.counters['complete_lines'],0)
        self.append(raw[half:]);engine.poll()
        self.assertEqual(engine.reader.cursor,len(raw));self.assertEqual(engine.counters['complete_lines'],1)

    def test_initial_partial_history_remainder_is_explicitly_discarded(self):
        raw=line(1);self.source.write_bytes(raw[:20]);engine=self.engine()
        self.append(raw[20:]+line());self.clock.at(15);engine.poll()
        self.assertEqual(engine.counters['preexisting_partial_exclusions'],1)
        self.assertEqual(len(engine.pending),1)
        self.assertIn('PREEXISTING_PARTIAL_DISCARDED',[e['reason'] for e in self.records('audit.jsonl')])

    def test_source_identity_and_byte_provenance(self):
        engine=self.emit();record=self.records()[0];stat=self.source.stat()
        self.assertEqual(record['source_device'],stat.st_dev);self.assertEqual(record['source_inode'],stat.st_ino)
        self.assertEqual(record['source_byte_ranges'][0]['start'],0)
        self.assertEqual(record['source_byte_ranges'][0]['end'],len(line()))
        self.assertEqual(record['source_byte_ranges'][0]['sha256'],hashlib.sha256(line()).hexdigest())

    def test_truncation_fails_closed_without_reset(self):
        engine=self.engine();self.append(line());self.clock.at(15);engine.poll();cursor=engine.reader.cursor
        self.source.write_bytes(b'')
        with self.assertRaisesRegex(IntegrityFault,'TRUNCATED'):engine.poll()
        self.assertEqual(engine.reader.cursor,cursor)

    def test_rotation_replacement_fails_closed(self):
        engine=self.engine();self.source.rename(self.directory/'retained-old.log');self.source.touch()
        with self.assertRaisesRegex(IntegrityFault,'ROTATED'):engine.poll()

    def test_rewritten_same_inode_continuity_detected(self):
        engine=self.engine();self.append(line());self.clock.at(15);engine.poll()
        self.source.write_bytes(line(agent='RewrittenAAA'))
        with self.assertRaises(IntegrityFault):engine.poll()

    def test_parser_and_65_features_equal_offline_for_same_observations(self):
        engine=self.engine();raw=line(query='?q=%27SELECT+lesson--');self.append(raw);self.clock.at(22);engine.poll()
        row=self.records('windows.jsonl')[0]['row']
        event=parse_line(raw.decode().rstrip('\n'),'fixture',hashlib.sha256(raw).hexdigest(),1)
        self.assertEqual(row['features'],extract([event],10,self.package.feature_schema['path_rules']))
        self.assertEqual(set(row['features']),set(FEATURES));self.assertEqual(len(row['features']),65)
        self.assertEqual(row['schema_sha256'],SCHEMA_HASH);self.assertNotIn('label',row)
        self.assertIsNone(self.records()[0]['label'])

    def test_exact_dummy_exclusion_no_foreign_client_filter(self):
        engine=self.engine()
        dummy=b'::1 - - [07/Oct/2026:12:00:14 +0000] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache (internal dummy connection)"\n'
        self.append(dummy+line(client='192.168.226.132',agent='MoodleBot/4.5'))
        self.clock.at(22);engine.poll()
        self.assertEqual(engine.counters['excluded_dummy_events'],1)
        self.assertEqual(self.records()[0]['observation_count'],1)

    def test_no_empty_windows_or_open_window_early_prediction(self):
        engine=self.engine();self.clock.at(12);engine.poll();self.assertEqual(self.records(),[])
        self.append(line());self.clock.at(19);engine.poll();self.assertEqual(self.records(),[])
        self.clock.at(21.9);engine.poll();self.assertEqual(self.records(),[])
        self.clock.at(22);engine.poll();self.assertEqual(len(self.records()),1)
        self.clock.at(45);engine.poll();self.assertEqual(len(self.records()),1)

    def test_exact_utc_windows_and_separate_client_user_agent_groups(self):
        engine=self.engine();self.append(line(14)+line(20)+line(14,agent='Other'))
        self.clock.at(22);engine.poll();self.assertEqual(len(self.records()),2)
        self.assertTrue(all(r['window_start'].endswith('12:00:10+00:00') for r in self.records()))
        self.clock.at(32);engine.poll();self.assertEqual(len(self.records()),3)

    def test_cold_start_omits_partial_startup_interval(self):
        engine=self.engine();self.append(line(5)+line(14));self.clock.at(22);engine.poll()
        self.assertEqual(engine.counters['cold_start_exclusions'],1);self.assertEqual(len(self.records()),1)
        self.assertEqual(self.records()[0]['observation_count'],1)

    def test_pending_safe_replay_offset_and_no_loss_on_resume(self):
        engine=self.engine();self.append(line());self.clock.at(15);engine.poll()
        checkpoint=json.loads((self.out/'checkpoint.json').read_text())
        self.assertEqual(checkpoint['source']['safe_offset'],0);self.assertEqual(checkpoint['source']['read_offset'],len(line()))
        engine.stop();resumed=self.engine(resume=True);resumed.poll()
        self.assertEqual(len(resumed.pending),1);self.clock.at(22);resumed.poll()
        self.assertEqual(len(self.records()),1);self.assertEqual(resumed.counters['complete_lines'],1)

    def test_completed_resume_has_no_duplicate_inference(self):
        engine=self.emit();before=(self.out/'predictions.jsonl').read_bytes();engine.stop()
        resumed=self.engine(resume=True);self.clock.at(25);resumed.poll()
        self.assertEqual(before,(self.out/'predictions.jsonl').read_bytes());self.assertEqual(len(self.package.calls),1)

    def test_crash_after_prediction_before_checkpoint_idempotent(self):
        engine=self.engine();self.append(line());self.clock.at(15);engine.poll()
        original=engine.journal.persist
        def crash(window,prediction):original(window,prediction);raise RuntimeError('Simulated process death')
        with patch.object(engine.journal,'persist',crash):
            self.clock.at(22)
            with self.assertRaises(RuntimeError):engine.poll()
        self.abandon(engine);resumed=self.engine(resume=True);resumed.poll()
        self.assertEqual(len(self.records()),1);self.assertEqual(len(self.package.calls),1)
        self.assertEqual(self.records()[0]['sequence'],1)

    def test_missing_projection_suffix_recovers_from_transaction_journal(self):
        engine=self.engine();self.append(line());self.clock.at(15);engine.poll()
        from branch2 import live_storage
        append=live_storage.append_json
        def crash(path,value):
            if Path(path).name=='predictions.jsonl':raise RuntimeError('Simulated crash')
            append(path,value)
        with patch.object(live_storage,'append_json',crash):
            self.clock.at(22)
            with self.assertRaises(RuntimeError):engine.poll()
        self.abandon(engine);resumed=self.engine(resume=True);resumed.poll()
        self.assertEqual(len(self.records()),1);self.assertEqual(len(self.records('windows.jsonl')),1)
        self.assertEqual(len(self.package.calls),1)

    def test_interleaved_pending_replay_skips_only_proven_committed_observations(self):
        engine=self.engine();self.append(line(24)+line(14));self.clock.at(25);engine.poll()
        self.assertEqual(len(self.records()),1);self.assertEqual(len(engine.pending),1)
        engine.stop();resumed=self.engine(resume=True);resumed.poll()
        self.assertEqual(len(resumed.pending),1);self.clock.at(32);resumed.poll()
        self.assertEqual(len(self.records()),2);self.assertEqual(resumed.counters['complete_lines'],2)

    def test_repeated_restart_before_replay_keeps_original_highwater(self):
        engine=self.engine();self.append(line(24)+line(14));self.clock.at(25);engine.poll();engine.stop()
        resumed=self.engine(resume=True);resumed.stop()  # Stop before any re-read.
        again=self.engine(resume=True);again.poll();self.clock.at(32);again.poll()
        self.assertEqual(len(self.records()),2);self.assertEqual(again.counters['complete_lines'],2)

    def test_new_late_event_fails_without_mutating_emitted_window(self):
        engine=self.emit();before=(self.out/'predictions.jsonl').read_bytes()
        self.append(line(15));self.clock.at(23)
        with self.assertRaisesRegex(IntegrityFault,'LATE_EVENT'):engine.poll()
        self.assertEqual(before,(self.out/'predictions.jsonl').read_bytes())

    def test_deterministic_record_id_after_resume(self):
        engine=self.engine();self.append(line());self.clock.at(15);engine.poll()
        expected=engine.record_id(engine.pending[0][0]);engine.stop()
        resumed=self.engine(resume=True);resumed.poll()
        self.assertEqual(expected,resumed.record_id(resumed.pending[0][0]))

    def test_schema_mismatch_fails_before_prediction(self):
        self.package.feature_schema['feature_order'].reverse()
        with self.assertRaises(ValueError):self.engine()
        self.assertEqual(self.package.calls,[]);self.assertFalse(self.out.exists())

    def test_resume_changed_model_identity_rejected(self):
        engine=self.engine();engine.stop();other=self.directory/'other-model';other.mkdir()
        (other/'package_manifest.json').write_text('{}')
        with self.assertRaisesRegex(IntegrityFault,'MODEL_IDENTITY_CHANGED'):
            LiveEngine(self.source,other,self.out,resume=True,clock=self.clock,loader=lambda p:self.package)

    def test_resume_source_identity_schema_config_and_engine_version_checked(self):
        engine=self.engine();engine.stop()
        with self.assertRaises(IntegrityFault):self.engine(resume=True,grace=3)
        self.source.rename(self.directory/'old');self.source.touch()
        with self.assertRaises(IntegrityFault):self.engine(resume=True)

    def test_version_and_smoke_session_resume_rejected(self):
        engine=self.engine();engine.stop();checkpoint=json.loads((self.out/'checkpoint.json').read_text())
        checkpoint['engine_version']='incompatible';atomic_json(self.out/'checkpoint.json',checkpoint)
        with self.assertRaisesRegex(IntegrityFault,'ENGINE_STATE_INCOMPATIBLE'):self.engine(resume=True)

    def test_existing_output_requires_resume_and_concurrent_writer_rejected(self):
        engine=self.engine()
        with self.assertRaises(ValueError):self.engine()
        with self.assertRaisesRegex(IntegrityFault,'ALREADY_RUNNING'):self.engine(resume=True)
        engine.stop()

    def test_output_append_latest_convenience_and_atomic_checkpoint(self):
        engine=self.emit();first=(self.out/'predictions.jsonl').read_bytes()
        (self.out/'latest.json').write_text('{"convenience":"not truth"}')
        engine.stop();resumed=self.engine(resume=True)
        self.assertEqual(json.loads((self.out/'latest.json').read_text()),self.records()[0])
        self.append(line(24));self.clock.at(32);resumed.poll()
        self.assertTrue((self.out/'predictions.jsonl').read_bytes().startswith(first))
        self.assertEqual([r['sequence'] for r in self.records()],[1,2])
        self.assertFalse(list(self.out.glob('.checkpoint.json.*')))
        checkpoint=json.loads((self.out/'checkpoint.json').read_text())
        self.assertEqual(checkpoint['last_emitted_sequence'],2)

    def test_torn_prediction_output_fails_closed_without_deletion(self):
        engine=self.emit();engine.stop()
        with (self.out/'predictions.jsonl').open('ab') as handle:handle.write(b'{"torn":')
        before=(self.out/'predictions.jsonl').read_bytes()
        with self.assertRaisesRegex(IntegrityFault,'UNJOURNALED_OUTPUT'):self.engine(resume=True)
        self.assertEqual(before,(self.out/'predictions.jsonl').read_bytes())

    def test_malformed_line_hash_audit_and_bound_preserve_privacy(self):
        engine=self.engine(max_parse_failures=1);self.append(b'bad password=private-secret cookie=private-cookie\n');engine.poll()
        self.assertEqual(engine.counters['parse_failures'],1)
        self.assertNotIn('private-',(self.out/'audit.jsonl').read_text())
        self.append(b'bad second line\n')
        with self.assertRaisesRegex(IntegrityFault,'PARSE_FAILURE_LIMIT'):engine.poll()

    def test_secrets_in_query_and_referrer_not_exported(self):
        engine=self.engine();self.append(line(query='?password=private-secret&token=private-token',agent='private-agent-secret'))
        self.clock.at(22);engine.poll();engine.stop()
        for path in self.out.glob('*.json*'):
            self.assertNotIn('private-',path.read_text())

    def test_explanation_success_failure_and_no_explain_diagnostic(self):
        engine=self.emit();record=self.records()[0]
        self.assertFalse(record['confidence_calibrated']);self.assertFalse(record['shap_explanation']['causal'])
        self.assertTrue(record['shap_explanation']['top_features']);self.assertTrue(record['robust_explanation']['top_features'])
        self.package.shap_status='INCOMPATIBLE_IMPLEMENTATION';self.append(line(24));self.clock.at(32);engine.poll()
        self.assertEqual(self.records()[1]['shap_explanation']['status'],'INCOMPATIBLE_IMPLEMENTATION')
        self.assertIn('EXPLANATION_UNAVAILABLE',[r['reason'] for r in self.records('audit.jsonl')])

    def test_real_finite_latency_and_summary_actual_records(self):
        engine=self.emit();record=self.records()[0];engine.stop()
        self.assertGreaterEqual(record['processing_duration_ms'],0);self.assertEqual(record['window_close_to_emission_ms'],2000)
        self.assertLess(record['processing_duration_ms'],float('inf'))
        result=json.loads((self.out/'latency_summary.json').read_text())
        self.assertEqual(result['processing_duration_ms']['count'],1)
        self.assertEqual(result['processing_duration_ms']['mean'],record['processing_duration_ms'])

    def test_ctrl_c_graceful_stop_does_not_force_open_window(self):
        engine=self.engine();self.append(line());self.clock.at(15)
        def interrupt(seconds):raise KeyboardInterrupt
        engine.run(sleep=interrupt)
        self.assertTrue(engine.closed);self.assertEqual(self.records(),[])
        summary=json.loads((self.out/'session_summary.json').read_text())
        self.assertEqual(summary['stop_reason'],'CTRL_C');self.assertEqual(summary['pending_events'],1)
        self.assertEqual(json.loads((self.out/'checkpoint.json').read_text())['source']['safe_offset'],0)

    def test_bounds_oversized_line_and_future_timestamp_fail(self):
        for kwargs in ({'grace':-1},{'poll_interval':0},{'max_pending':0}):
            with self.assertRaises(ValueError):self.engine(**kwargs)
        engine=self.engine();self.append(b'x'*(MAX_LINE+1))
        with self.assertRaisesRegex(IntegrityFault,'LINE_BOUND'):engine.poll()

    def test_no_explain_diagnostic_and_pending_event_bound(self):
        engine=self.engine(explain=False,max_pending=1)
        self.append(line());self.clock.at(22);engine.poll()
        self.assertEqual(self.records()[0]['shap_explanation']['status'],'NOT_REQUESTED')
        self.append(line(24)+line(25));self.clock.at(26)
        with self.assertRaisesRegex(IntegrityFault,'PENDING_EVENT_BOUND'):engine.poll()

    def test_clock_backwards_future_event_and_duration_bounds(self):
        engine=self.engine();self.append(line(59));self.clock.at(15)
        # Fixture timestamp 59 is inside the explicit 60-second future bound.
        engine.poll();self.clock.at(14)
        with self.assertRaisesRegex(IntegrityFault,'BACKWARDS'):engine.poll()

    def test_checkpoint_identity_and_invalid_offsets_rejected(self):
        engine=self.engine();engine.stop()
        state=json.loads((self.out/'checkpoint.json').read_text());state['schema_sha256']='wrong'
        atomic_json(self.out/'checkpoint.json',state)
        with self.assertRaisesRegex(IntegrityFault,'CHECKPOINT_IDENTITY'):self.engine(resume=True)
        state['schema_sha256']=SCHEMA_HASH;state['source']['safe_offset']=-1
        atomic_json(self.out/'checkpoint.json',state)
        with self.assertRaisesRegex(IntegrityFault,'OFFSET_STATE'):self.engine(resume=True)

    def test_checkpoint_atomic_failure_preserves_old_bytes(self):
        engine=self.engine();path=self.out/'checkpoint.json';before=path.read_bytes()
        with patch('branch2.live_storage.os.replace',side_effect=OSError('test replacement failure')):
            with self.assertRaises(OSError):atomic_json(path,{'uncommitted':'value'})
        self.assertEqual(before,path.read_bytes());self.assertFalse(list(self.out.glob('.checkpoint.json.*')))

    def test_source_resume_truncation_and_torn_canonical_projection_fail(self):
        engine=self.emit();engine.stop()
        with (self.out/'windows.jsonl').open('ab') as handle:handle.write(b'{')
        before=(self.out/'windows.jsonl').read_bytes()
        with self.assertRaises(IntegrityFault):self.engine(resume=True)
        self.assertEqual(before,(self.out/'windows.jsonl').read_bytes())

    def test_ctrl_c_after_batch_read_cannot_lose_unparsed_observations(self):
        engine=self.engine();self.append(line()+line(15));self.clock.at(16)
        with patch('branch2.live.parse_line',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):engine.poll()
        engine.stop('CTRL_C')
        self.assertEqual(json.loads((self.out/'checkpoint.json').read_text())['source']['safe_offset'],0)
        resumed=self.engine(resume=True);self.clock.at(22);resumed.poll()
        self.assertEqual(self.records()[0]['observation_count'],2)

    def test_output_cannot_overlap_frozen_model(self):
        with self.assertRaises(ValueError):LiveEngine(self.source,MODEL,MODEL,resume=True,clock=self.clock,loader=lambda p:self.package)

    def test_model_files_monitored_without_hot_reload(self):
        model=self.directory/'fixture-model';model.mkdir()
        (model/'package_manifest.json').write_text('{"files_sha256":{}}')
        engine=LiveEngine(self.source,model,self.out,clock=self.clock,loader=lambda p:self.package)
        self.engines.append(engine)
        (model/'package_manifest.json').write_text('{"files_sha256":{},"changed":true}')
        with self.assertRaisesRegex(IntegrityFault,'MODEL_PACKAGE_CHANGED_DURING_SESSION'):engine.poll()
        self.assertEqual(self.package.calls,[])

    def test_fault_persists_when_source_checkpoint_cannot_advance(self):
        engine=self.engine();self.append(line());self.clock.at(15);engine.poll();original=self.source.read_bytes()
        self.source.write_bytes(b'')
        with self.assertRaises(IntegrityFault):engine.poll()
        engine.stop();self.source.write_bytes(original)  # Same inode/content restored, but fault stays visible.
        with self.assertRaisesRegex(IntegrityFault,'PRIOR_INTEGRITY_FAULT'):self.engine(resume=True)

    def test_standalone_live_import_has_no_project_trainers(self):
        code="import sys;sys.path.insert(0,'src');import branch2.live;assert 'branch2.models' not in sys.modules;assert 'branch2.final_pipeline' not in sys.modules"
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_native_saved_final_package_fixture_integration_no_fitting(self):
        from sklearn.ensemble import IsolationForest
        from xgboost import XGBClassifier
        protected={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in MODEL.iterdir() if p.is_file()}
        with patch.object(IsolationForest,'fit',side_effect=AssertionError('NO FIT')),patch.object(XGBClassifier,'fit',side_effect=AssertionError('NO FIT')):
            engine=LiveEngine(self.source,MODEL,self.out,clock=self.clock)
            self.engines.append(engine);self.append(line(query='?b2_lab_q=%27SELECT+lesson--'))
            self.clock.at(22);engine.poll();engine.stop()
            resumed=LiveEngine(self.source,MODEL,self.out,resume=True,clock=self.clock)
            self.engines.append(resumed);resumed.poll();resumed.stop()
        records=self.records();self.assertEqual(len(records),1)
        self.assertEqual(records[0]['shap_explanation']['status'],'AVAILABLE')
        self.assertEqual(records[0]['shap_explanation']['backend'],'XGBOOST_NATIVE_EXACT_TREE_SHAP')
        self.assertTrue(records[0]['robust_explanation']['top_features'])
        self.assertFalse(records[0]['training_performed']);self.assertEqual(len(records[0]['xgb_scores']),8)
        self.assertEqual(protected,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in MODEL.iterdir() if p.is_file()})


if __name__=='__main__':unittest.main()
