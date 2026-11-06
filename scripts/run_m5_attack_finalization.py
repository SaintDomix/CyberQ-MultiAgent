#!/usr/bin/env python3
"""Frozen saved-model fresh attack evaluation; never trains or generates traffic."""
from collections import Counter,defaultdict
from contextlib import ExitStack
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
from unittest.mock import patch
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
from behavioral_v2.data import sha,write
from behavioral_v2.browser_capture import digest
from behavioral_v2.study31 import verify_freeze
from behavioral_v2.platforms import MoodleBehaviorAdapter
from behavioral_v2.features31 import schema,extract
from behavioral_v2.episodes import episodes
from branch2.capture.verification import verify
from branch2.adapters.apache import read_log
from branch2.events import utc
from branch2.windowing import windows
from branch2.features import extract as v1_extract,schema as v1_schema
from branch2.artifacts import load as load_v1
from branch2.final_pipeline import multiclass
from branch2.dataset import CLASSES
from run_m5_blind_benign_evaluation import FITTING_METHODS,aligned_predictions,key

EXPECTED_EVIDENCE='4bc2226a54f333355c5caf8f80fa4331aa9df3e9b77ba32fe7eb1cd3754f977a'
EXPECTED_PLAN='549ee00ebb163bb826667ab34b7a3ba2bcfd27d4c33534218546d860e8502d74'
EXPECTED_CANDIDATE='0493bd3ec93b58d288269a736abb51a400c89cf66a05e44bd45e75a2e65cc6c1'


def attack_metrics(predictions,classes,persistence,candidate):
    if not predictions or any(p['label']=='BENIGN' or p['label'] not in CLASSES for p in predictions):raise ValueError('Attack-only labelled evidence required')
    grouped=defaultdict(list)
    for p in predictions:grouped[p['run_id']].append(p)
    es=episodes(predictions,persistence);runs=[]
    for rid,rows in sorted(grouped.items()):
        rows=sorted(rows,key=lambda p:(p['window_start'],p['window_end'],tuple(p['xgb_scores'])))
        truth={p['label'] for p in rows}
        if len(truth)!=1:raise ValueError('Inconsistent run label')
        true=next(iter(truth));scores=np.mean([p['xgb_scores'] for p in rows],axis=0)
        label=classes[int(np.argmax(scores))];res=[e for e in es if e['run_id']==rid and e['alert']]
        runs.append({'run_id':rid,'true_class':true,'windows':len(rows),
            'novelty_any_anomaly':any(p['novelty_anomalous'] if candidate else p['if_anomalous'] for p in rows),
            'xgb_mean_score_class':label,'xgb_correct_class':label==true,'xgb_missed_as_BENIGN':label=='BENIGN',
            'xgb_detected_wrong_class':label not in ('BENIGN',true),'alerted':bool(res),'alert_episodes':len(res),
            'correct_known_alert':any(e['behavior_class']==true for e in res),
            'unknown_alert':any(e['state']=='UNKNOWN_ANOMALY_EPISODE' for e in res)})
    decisions=Counter(p['reconciliation']['decision'] for p in predictions)
    per_class={}
    for label in sorted(set(p['label'] for p in predictions)):
        ps=[p for p in predictions if p['label']==label];rs=[r for r in runs if r['true_class']==label]
        detected=sum(p['reconciliation']['decision'] not in ('BENIGN','UNCERTAIN') for p in ps)
        per_class[label]={'runs':len(rs),'windows':len(ps),'detected_runs':sum(r['alerted'] for r in rs),
            'run_recall':sum(r['alerted'] for r in rs)/len(rs),'detected_windows':detected,'window_recall':detected/len(ps),
            'xgb_correct_runs':sum(r['xgb_correct_class'] for r in rs),
            'correct_known_alert_runs':sum(r['correct_known_alert'] for r in rs)}
    anomaly=sum(p['novelty_anomalous'] if candidate else p['if_anomalous'] for p in predictions)
    detected=sum(p['reconciliation']['decision'] not in ('BENIGN','UNCERTAIN') for p in predictions)
    xgb=multiclass([p['label'] for p in predictions],[p['xgb_label'] for p in predictions],classes)
    xgb['macro_f1_present_attack_classes']=float(np.mean([v['f1-score'] for v in xgb['per_class'].values() if v['support']>0]))
    xgb['macro_scope_note']='Original eight-taxonomy macro includes zero-support BENIGN; present-attack-class macro reported separately'
    return {'windows':len(predictions),'runs':len(runs),
        'novelty':{'anomaly_windows':anomaly,'normal_windows':len(predictions)-anomaly,'window_recall':anomaly/len(predictions),
            'detected_runs':sum(r['novelty_any_anomaly'] for r in runs),'run_recall':sum(r['novelty_any_anomaly'] for r in runs)/len(runs)},
        'xgboost':{'window_metrics':xgb,'BENIGN_miss_windows':sum(p['xgb_label']=='BENIGN' for p in predictions),
            'wrong_attack_class_windows':sum(p['xgb_label'] not in ('BENIGN',p['label']) for p in predictions),
            'correct_class_windows':sum(p['xgb_label']==p['label'] for p in predictions),
            'correct_class_runs':sum(r['xgb_correct_class'] for r in runs),
            'detected_wrong_class_runs':sum(r['xgb_detected_wrong_class'] for r in runs),
            'BENIGN_miss_runs':sum(r['xgb_missed_as_BENIGN'] for r in runs),
            'run_metrics':multiclass([r['true_class'] for r in runs],[r['xgb_mean_score_class'] for r in runs],classes),
            'aggregation':'Mean uncalibrated class-score vectors; argmax, sorted class ties','confidence_calibrated':False},
        'reconciled':{'detected_windows':detected,'window_recall':detected/len(predictions),
            'BENIGN_miss_windows':decisions['BENIGN'],'UNCERTAIN_windows':decisions['UNCERTAIN'],
            'UNKNOWN_ANOMALY_windows':decisions['UNKNOWN_ANOMALY'],'window_decisions':dict(sorted(decisions.items())),
            'detected_runs':sum(r['alerted'] for r in runs),'missed_runs':sum(not r['alerted'] for r in runs),
            'run_recall':sum(r['alerted'] for r in runs)/len(runs),'alert_episodes':sum(r['alert_episodes'] for r in runs),
            'correct_known_alert_runs':sum(r['correct_known_alert'] for r in runs),
            'UNKNOWN_detected_runs':sum(r['unknown_alert'] for r in runs),'persistence':persistence},
        'per_class':per_class,'run_results':runs,'episodes':es,'successful_exploitation_confirmed':False}


def evaluate(project):
    project=Path(project);root=project/'outputs/branch2/m5_final_day';out=root/'fresh_attack_holdout_01'
    cap=project/'evidence/branch2_captures/m5_fresh_attack_holdout_01';frozen=root/'candidate_freeze_01'
    if (out/'evaluation_integrity.json').exists():raise ValueError('Refuse overwrite of prior holdout evaluation')
    evidence_file=out/'evidence_sha256_20261015.txt'
    if sha(evidence_file)!=EXPECTED_EVIDENCE or sha(out/'predeclared_plan.json')!=EXPECTED_PLAN:raise ValueError('Holdout manifest/plan changed')
    evidence_hashes={}
    for line in evidence_file.read_text().splitlines():
        expected,name=line.split(None,1);path=(project/name.lstrip('*')).resolve()
        if not path.is_relative_to(cap) or sha(path)!=expected:raise ValueError('Attack evidence changed')
        evidence_hashes[str(path.relative_to(project))]=expected
    actual={str(p.relative_to(project)) for p in cap.rglob('*') if p.is_file()}
    if actual!=set(evidence_hashes):raise ValueError('Attack evidence file membership changed')
    if sha(cap/'schedule.json')!=EXPECTED_PLAN:raise ValueError('Authoritative schedule differs from predeclared plan')
    f,model=verify_freeze(frozen/'freeze_manifest.json')
    if f['root_sha256']!=EXPECTED_CANDIDATE:raise ValueError('Candidate changed')
    baseline=load_v1(project/'outputs/branch2/m2c_final_01')
    benign_root=root/'blind_benign_test_01'
    if sha(benign_root/'test_evidence_manifest.json')!='807a14cbb6b2d26897709a71de2316f4b01c53fde85e836e9b25c344d84711a4':raise ValueError('Benign holdout changed')
    benign_artifacts=json.loads((benign_root/'evaluation/artifact_manifest.json').read_text())
    for name,value in benign_artifacts['files'].items():
        if sha(benign_root/'evaluation'/name)!=value['sha256']:raise ValueError('Locked benign evaluation changed')
    qa=verify(cap)
    if not qa['verified'] or qa['verified_runs']!=14:raise ValueError('Attack capture QA failed')
    plan=json.loads((out/'predeclared_plan.json').read_text())
    forbidden=set(f['config']['train_ids']+f['config']['validation_ids']+f['reserved_fresh_test_ids'])
    historical=json.loads((project/'data/branch2_v2/final_candidate_01/dataset.json').read_text())
    forbidden|={r['run_id'] for r in historical['rows']}
    if forbidden&{r['run_id'] for r in plan['runs']}:raise ValueError('Holdout reused a development or old TEST run')
    write(out/'evaluation_integrity.json',{'status':'PASS','candidate_root_sha256':f['root_sha256'],
        'evidence_hash_manifest_sha256':EXPECTED_EVIDENCE,'plan_sha256':EXPECTED_PLAN,'files_verified':evidence_hashes,
        'capture_qa':qa,'model_v1_manifest_sha256':sha(project/'outputs/branch2/m2c_final_01/package_manifest.json'),
        'benign_metrics_sha256':sha(benign_root/'evaluation/metrics.json'),
        'predictions_calculated':False,'checked_at_utc':datetime.now(timezone.utc).isoformat(),
        'decision_protocol':'Research judgment after per-class failures and benign comparison; no predeclared automatic numeric promotion threshold'})
    adapter=MoodleBehaviorAdapter();s=schema(adapter);rows=[];old=[];manifest=[]
    for run in plan['runs']:
        rid=run['run_id'];m=json.loads((cap/rid/'manifest.json').read_text());path=cap/rid/'access.log'
        if utc(m['actual_start_precise_utc'])<=utc(f['frozen_at_utc']):raise ValueError('Attack capture predates freeze')
        events,errors,h=read_log(path,str(path))
        if errors or h!=m['access_sha256']:raise ValueError('Attack source changed')
        count=0
        for window in windows(events):
            es=window.pop('events');base={**window,'run_id':rid,'label':run['label'],'partition':'FRESH_ATTACK_TEST',
                'source_file':str(path),'source_sha256':h,'line_numbers':[e.line_number for e in es]}
            rows.append({**base,'features':extract(es,adapter),'schema_sha256':s['sha256']})
            old.append({**base,'features':v1_extract(es),'schema_sha256':v1_schema()['sha256']});count+=1
        manifest.append({'run_id':rid,'true_class':run['label'],'requests':len(events),'windows':count,
            'source_sha256':h,'capture_manifest_sha256':sha(cap/rid/'manifest.json'),
            'candidate_schema_sha256':s['sha256'],'v1_schema_sha256':baseline.feature_schema['sha256'],
            'candidate_package':str(frozen/'v2_final_candidate'),'v1_package':str(project/'outputs/branch2/m2c_final_01'),
            'provenance_reference':str(cap/rid/'manifest.json')})
    if [key(r) for r in rows]!=[key(r) for r in old]:raise ValueError('Window alignment failed')
    if set(r['label'] for r in rows)!=set(CLASSES)-{'BENIGN'}:raise ValueError('Seven supported attack classes required')
    cp=aligned_predictions(model,rows);bp=aligned_predictions(baseline,old)
    candidate=attack_metrics(cp,model.classes,model.config['persistence'],True)
    v1=attack_metrics(bp,baseline.classes,1,False)
    write(out/'holdout_manifest.json',{'runs':manifest,'total_windows':len(rows),'window_alignment':'EXACT accepted run/time/client/agent/source record membership',
        'candidate_root_sha256':f['root_sha256'],'no_retraining':True,'no_holdout_based_tuning':True})
    write(out/'candidate_metrics.json',candidate);write(out/'v1_metrics.json',v1)
    write(out/'predictions.json',{'candidate':cp,'model_v1':bp})
    benign=json.loads((benign_root/'evaluation/metrics.json').read_text())
    table=[]
    for name,field in (('attack_run_recall','run_recall'),('attack_window_recall','window_recall'),
        ('attack_runs_missed','missed_runs'),('correct_known_alert_runs','correct_known_alert_runs'),
        ('UNKNOWN_detected_runs','UNKNOWN_detected_runs'),('attack_alert_episodes','alert_episodes')):
        c=candidate['reconciled'][field];b=v1['reconciled'][field]
        table.append({'metric':name,'candidate':c,'model_v1':b,'delta':c-b})
    for name,field in (('known_class_correct_runs','correct_class_runs'),):
        c=candidate['xgboost'][field];b=v1['xgboost'][field]
        table.append({'metric':name,'candidate':c,'model_v1':b,'delta':c-b})
    paired={'fresh_attack_comparison':table,'locked_benign_comparison':benign['paired_difference'],
        'per_class':{c:{'candidate':candidate['per_class'][c],'model_v1':v1['per_class'][c]} for c in candidate['per_class']},
        'no_statistical_significance_claimed':True,'no_threshold_or_model_changes':True,
        'v1_episode_policy':'Existing M5 comparator persistence=1; candidate frozen persistence=2',
        'no_predeclared_numeric_promotion_threshold':True}
    write(out/'paired_comparison.json',paired)
    _,reload_model=verify_freeze(frozen/'freeze_manifest.json')
    if aligned_predictions(reload_model,rows)!=cp or aligned_predictions(load_v1(project/'outputs/branch2/m2c_final_01'),old)!=bp:
        raise ValueError('Saved-model replay mismatch')
    write(out/'replay_consistency.json',{'candidate_matched':True,'model_v1_matched':True,'windows':len(rows),'fit_calls':0})
    print(json.dumps({'candidate':{k:candidate[k] for k in ('windows','runs','novelty','reconciled','per_class')},
        'v1':{k:v1[k] for k in ('novelty','reconciled','per_class')}}))
    return candidate,v1,paired


def main():
    with ExitStack() as stack:
        for method in FITTING_METHODS:stack.enter_context(patch(method,side_effect=AssertionError('Fitting forbidden')))
        for method in ('socket.socket.connect','socket.socket.connect_ex','socket.create_connection','socket.getaddrinfo','socket.socket.sendto'):
            stack.enter_context(patch(method,side_effect=AssertionError('Network forbidden')))
        evaluate(ROOT)


if __name__=='__main__':main()
