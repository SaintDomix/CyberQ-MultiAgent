"""Measured saved-evidence performance and temporary-copy runtime reliability."""
import asyncio
from contextlib import ExitStack, redirect_stdout
import copy
from datetime import timedelta
import io
import hashlib
import json
from pathlib import Path
import resource
import shutil
import sys
import tempfile
import time
from unittest.mock import patch
import numpy as np
from .backend.config import ROOT, Config
from .backend.app import create_app
from behavioral_runtime.package import load, verify
from behavioral_runtime.live import LiveEngine, adapter_for
from behavioral_v2.features31 import extract, matrix
from behavioral_v2.episodes import episodes
from branch2.adapters.apache import read_log, parse_line
from branch2.windowing import windows
from branch2.events import utc
from branch2.reconciliation import reconcile
from branch2.live_storage import Journal, digest
sys.path.insert(0,str(ROOT/'scripts'))
from verify_behavioral_v2_replay import replay, same_prediction

ACCEPTED=ROOT/'outputs/branch2/accepted_behavioral_v2'
ATTACK=ROOT/'outputs/branch2/m5_final_day/fresh_attack_holdout_01'
CAPTURE=ROOT/'evidence/branch2_captures/m5_fresh_attack_holdout_01'


def guard():
    stack=ExitStack()
    for name in ('sklearn.svm.OneClassSVM.fit','sklearn.ensemble.IsolationForest.fit',
                 'sklearn.neighbors.LocalOutlierFactor.fit','sklearn.preprocessing.RobustScaler.fit','xgboost.XGBClassifier.fit',
                 'socket.socket.connect','socket.create_connection','socket.getaddrinfo','socket.socket.sendto'):
        stack.enter_context(patch(name,side_effect=AssertionError('Training/network forbidden in release replay')))
    return stack


def statistics(values):
    if not values or not np.isfinite(values).all() or min(values)<0:raise ValueError('Invalid measurements')
    return {'count':len(values),'mean':float(np.mean(values)),'median':float(np.median(values)),
            'p95':float(np.percentile(values,95)),'max':float(max(values)),'unit':'milliseconds'}


def feature_evidence(package):
    adapter=adapter_for(package.feature_schema);rows=[];events=[]
    plan=json.loads((ATTACK/'predeclared_plan.json').read_text())
    for run in plan['runs']:
        path=CAPTURE/run['run_id']/'access.log';es,errors,h=read_log(path,str(path))
        if errors:raise ValueError('Locked source malformed')
        events.extend(es)
        for w in windows(es):
            group=w.pop('events')
            rows.append({**w,'run_id':run['run_id'],'features':extract(group,adapter),
                         'schema_sha256':package.feature_schema['sha256']})
    return rows,events


def performance():
    with guard():
        package=load(ACCEPTED);rows,events=feature_evidence(package);adapter=adapter_for(package.feature_schema)
        samples={};wall=time.perf_counter();cpu=time.process_time()
        def measure(stage,fn):
            start=time.perf_counter_ns();result=fn();samples.setdefault(stage,[]).append((time.perf_counter_ns()-start)/1e6);return result
        plan=json.loads((ATTACK/'predeclared_plan.json').read_text())
        for run in plan['runs']:
            path=CAPTURE/run['run_id']/'access.log'
            source_hash=hashlib.sha256(path.read_bytes()).hexdigest()
            for i,line in enumerate(path.read_text().splitlines(),1):
                measure('parsing',lambda:parse_line(line,str(path),source_hash,i))
        for run in plan['runs']:
            es=[e for e in events if e.source_file==str(CAPTURE/run['run_id']/'access.log')]
            for w in windows(es):measure('feature_extraction',lambda:extract(w['events'],adapter))
        for r in rows:
            x=matrix([r],package.feature_schema);novelty=package.models['OCSVM']
            value=measure('ocsvm_with_frozen_scaler',lambda:novelty['model'].score_samples(novelty['scaler'].transform(x)))
            vector=measure('xgboost',lambda:package.classifier.predict_proba(x))
            i=int(vector.argmax(axis=1)[0]);confidence=float(vector[0,i])
            measure('reconciliation',lambda:reconcile(bool(value[0]<package.config['thresholds']['OCSVM']),package.classes[i],confidence,package.config['confidence_threshold']))
            measure('saved_prediction_including_SHAP',lambda:package.predict([r],explain=True))
        saved=json.loads((ATTACK/'predictions.json').read_text())['candidate']
        for _ in range(20):measure('episode_aggregation_68_windows',lambda:episodes(saved,package.config['persistence']))
        runtime=ROOT/'runtime';runtime.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='release-perf-',dir=runtime) as tmp:
            j=Journal(tmp)
            try:
                for i,raw in enumerate(saved):
                    p=copy.deepcopy(raw);p['record_id']=digest(['benchmark',i]);p['observation_id']=p['record_id']
                    measure('sqlite_journal_commit_and_projections',lambda:j.persist({'record_id':p['record_id']},p))
                db_bytes=(Path(tmp)/'journal.sqlite3').stat().st_size
            finally:j.close()
        async def api_times():
            import httpx
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()),base_url='http://testserver') as client:
                for endpoint in ('health','system/status','application/snapshot','behavior/observations','behavior/incidents','cqi'):
                    # One explicitly excluded warm-up per endpoint.
                    response=await client.get('/api/'+endpoint);assert response.status_code==200
                    for _ in range(20):
                        start=time.perf_counter_ns();response=await client.get('/api/'+endpoint)
                        if response.status_code!=200:raise ValueError('API benchmark prerequisite failed')
                        samples.setdefault('api_'+endpoint.replace('/','_'),[]).append((time.perf_counter_ns()-start)/1e6)
        asyncio.run(api_times())
        return {'status':'MEASURED','stages':{name:statistics(v) for name,v in sorted(samples.items())},
            'api_transport':'In-process ASGI; serialization/middleware included; TCP/browser latency excluded',
            'model_timings':'Single-window saved inference; no fit; full saved prediction also measures upstream SHAP and auxiliary frozen novelty observations',
            'first_model_use_included':True,'api_warmup_excluded_per_endpoint':1,'feature_windows':len(rows),'source_records':len(events),
            'peak_process_RSS_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            'RSS_semantics':'Linux ru_maxrss: peak process RSS, includes loaded libraries/models, not incremental per-window memory',
            'runtime_DB_bytes':db_bytes,'accepted_package_bytes':sum(p.stat().st_size for p in ACCEPTED.rglob('*') if p.is_file()),
            'wall_seconds':time.perf_counter()-wall,'process_CPU_seconds':time.process_time()-cpu,
            'CPU_percent':None,'CPU_note':'No instantaneous CPU percentage inferred',
            'detection_latency_semantics':'Up to a 10-second aggregation window + 2-second close grace + polling/processing/emission overhead. UNKNOWN persistence two can add one adjacent window. Inference timing alone is not detection latency.',
            'training_performed':False,'network_requests':0,'accepted_package_id':package.accepted_manifest['package_id']}


def reliability():
    with guard():
        original=verify(ACCEPTED);package=load(ACCEPTED)
        with tempfile.TemporaryDirectory(prefix='release-reliability-') as temp:
            temp=Path(temp)
            with redirect_stdout(io.StringIO()):base=replay(temp/'full_replay.json')
            corrupt=temp/'corrupt';shutil.copytree(ACCEPTED,corrupt)
            with (corrupt/'model/xgboost.json').open('ab') as f:f.write(b'X')
            corruption=False
            try:LiveEngine(temp/'absent.log',corrupt,temp/'bad-runtime')
            except ValueError:corruption=True
            missing=False
            try:LiveEngine(temp/'absent.log',ACCEPTED,temp/'missing-runtime')
            except OSError:missing=True
            plan=json.loads((ATTACK/'predeclared_plan.json').read_text())
            selected=next(r for r in plan['runs'] if r['label']=='SQLI_ATTEMPT')
            expected=[p for p in json.loads((ATTACK/'predictions.json').read_text())['candidate'] if p['run_id']==selected['run_id']]
            raw=(CAPTURE/selected['run_id']/'access.log').read_bytes()
            es,errors,h=read_log(CAPTURE/selected['run_id']/'access.log','saved');assert not errors
            first=utc(expected[0]['window_start']);boundary=first+timedelta(seconds=20)
            cut=sum(len(line) for line,e in zip(raw.splitlines(keepends=True),es) if e.timestamp<boundary)
            source=temp/'source.log';source.write_bytes(b'');clock=[first]
            engine=LiveEngine(source,ACCEPTED,temp/'continued',clock=lambda:clock[0],explain=False)
            try:
                source.write_bytes(raw[:cut]);clock[0]=boundary+timedelta(seconds=2);engine.poll();before=engine.journal.sequence
            finally:engine.stop()
            with source.open('ab') as f:f.write(raw[cut:])
            clock[0]=max(utc(p['window_end']) for p in expected)+timedelta(seconds=12)
            resumed=LiveEngine(source,ACCEPTED,temp/'continued',resume=True,clock=lambda:clock[0],explain=False)
            try:
                resumed.poll();ps=[e['prediction'] for e in resumed.journal.entries()]
                for a,b in zip(ps,expected):same_prediction(a,b)
                count=resumed.journal.sequence;ids=[p['record_id'] for p in ps];episode_ids=[e['episode_id'] for e in resumed.incidents.values()]
                resumed.poll();idempotent=resumed.journal.sequence==count
            finally:resumed.stop()
            stopped=json.loads((temp/'continued/session_summary.json').read_text())['stop_reason']=='GRACEFUL_STOP'
            checks={'deterministic_saved_replay':base['status']=='PASS','restart_resume_no_duplicate':base['restart_resume_match'],
                'continued_after_restart':0<before<count==len(expected),'prediction_identity_after_continuation':len(ids)==len(set(ids)),
                'incident_identity_after_continuation':len(episode_ids)==len(set(episode_ids)),
                'idempotent_poll':idempotent,'sqlite_journal_persisted':count==len(expected),
                'clean_shutdown':stopped,'temporary_package_corruption_rejected':corruption,'missing_source_rejected':missing,
                'benign_replay_no_incident_storm':base['benign_incidents']==0,'accepted_package_unchanged':verify(ACCEPTED)==original}
        return {'status':'PASS' if all(checks.values()) else 'FAIL','checks':checks,'replay':base,
            'temporary_corruption_artifacts_deleted':True,'training_performed':False,'network_requests':0,
            'live_human_acceptance':'NEEDS_OPERATOR; no browsing fabricated'}
