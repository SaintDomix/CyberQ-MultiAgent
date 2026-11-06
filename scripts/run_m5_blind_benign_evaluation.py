#!/usr/bin/env python3
"""Read-only saved-model blind BENIGN comparison. No fitting or tuning allowed."""
from collections import Counter,defaultdict
from contextlib import ExitStack
from datetime import datetime,timezone
from fractions import Fraction
import json
from pathlib import Path
import sys
from unittest.mock import patch
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
import run_m5_blind_test_capture as capture_tool
from behavioral_v2.browser_capture import verify_capture,digest
from behavioral_v2.study31 import load_browser_session,verify_freeze
from behavioral_v2.data import sha,write
from behavioral_v2.episodes import episodes
from branch2.artifacts import load as load_v1

EXPECTED_EVIDENCE_SHA='807a14cbb6b2d26897709a71de2316f4b01c53fde85e836e9b25c344d84711a4'
FITTING_METHODS=('sklearn.ensemble.IsolationForest.fit','sklearn.svm.OneClassSVM.fit',
    'sklearn.neighbors.LocalOutlierFactor.fit','sklearn.preprocessing.RobustScaler.fit',
    'xgboost.XGBClassifier.fit')


def score_summary(values):
    a=np.asarray(values,dtype=float)
    if not len(a) or not np.isfinite(a).all():raise ValueError('Missing/nonfinite model scores')
    return {'min':float(a.min()),'median':float(np.median(a)),'mean':float(a.mean()),'max':float(a.max()),
        'is_probability':False}


def key(row):
    return tuple(row.get(k) for k in ('run_id','window_start','window_end','client_id','user_agent_id',
        'source_file','source_sha256'))+(tuple(row.get('line_numbers',[])),)


def aligned_predictions(model,rows):
    predictions=model.predict(rows)
    if len(predictions)!=len(rows):raise ValueError('Prediction count mismatch')
    for r,p in zip(rows,predictions):
        # Provenance-only attachment for v1, whose output omits these fields.
        for field in ('client_id','user_agent_id','line_numbers','partition'):
            p[field]=r.get(field)
        if p['run_id']!=r['run_id'] or p['window_start']!=r['window_start'] or p['window_end']!=r['window_end']:
            raise ValueError('Prediction/window linkage mismatch')
    return predictions


def summarize(predictions,persistence,confidence_threshold,*,candidate):
    if not predictions or any(p.get('label')!='BENIGN' for p in predictions):
        raise ValueError('This evaluation accepts verified BENIGN windows only')
    groups=defaultdict(list)
    for p in predictions:groups[p['run_id']].append(p)
    es=episodes(predictions,persistence)
    anomaly=lambda p:p['novelty_anomalous'] if candidate else p['if_anomalous']
    raw_score=lambda p:p['novelty_score'] if candidate else p['if_raw_anomaly_score']
    anomalies=sum(anomaly(p) for p in predictions);raw_runs=sum(any(anomaly(p) for p in rs) for rs in groups.values())
    alerted={e['run_id'] for e in es if e['alert']};decisions=Counter(p['reconciliation']['decision'] for p in predictions)
    raw_classes=Counter(p['xgb_label'] for p in predictions if p['xgb_label']!='BENIGN')
    known={c:n for c,n in sorted(decisions.items()) if c not in ('BENIGN','UNCERTAIN','UNKNOWN_ANOMALY')}
    return {'windows':len(predictions),'runs':len(groups),
        'novelty':{'anomalous_windows':anomalies,'normal_windows':len(predictions)-anomalies,
            'benign_false_positive_count':anomalies,'window_FPR':anomalies/len(predictions),
            'score_summary':score_summary([raw_score(p) for p in predictions]),
            'score_semantics':'OCSVM score_samples; lower is less normal' if candidate else 'Negative IF score_samples; higher is more anomalous',
            'threshold':predictions[0]['novelty_threshold'] if candidate else None,
            'decision_semantics':'score_samples < frozen cutoff' if candidate else 'Frozen IF decision_function < 0',
            'raw_any_anomalous_runs':raw_runs,'raw_run_FPR':raw_runs/len(groups)},
        'xgboost':{'BENIGN_windows':sum(p['xgb_label']=='BENIGN' for p in predictions),
            'false_known_attack_windows':sum(raw_classes.values()),'false_classes':dict(sorted(raw_classes.items())),
            'uncalibrated_score_summary':score_summary([p['xgb_confidence'] for p in predictions]),
            'below_frozen_confidence_threshold_windows':sum(p['xgb_confidence']<confidence_threshold for p in predictions),
            'confidence_threshold':confidence_threshold,'confidence_calibrated':False},
        'reconciliation':{'BENIGN':decisions['BENIGN'],'UNCERTAIN':decisions['UNCERTAIN'],
            'UNKNOWN_ANOMALY':decisions['UNKNOWN_ANOMALY'],'known_attempt_classes':known,
            'false_known_attempt_windows':sum(known.values()),
            'disagreement_windows':sum(p['reconciliation']['model_disagreement'] for p in predictions)},
        'episode':{'persistence':persistence,'alert_episodes':sum(e['alert'] for e in es),
            'benign_runs_alerted':len(alerted),'run_false_alert_rate':len(alerted)/len(groups),
            'unknown_alert_episodes':sum(e['state']=='UNKNOWN_ANOMALY_EPISODE' for e in es),
            'known_attempt_alert_episodes':sum(e['state']=='KNOWN_THREAT_ATTEMPT_EPISODE' for e in es),
            'episodes':es},'successful_exploitation_confirmed':False}


def classification(candidate,v1,rule,expected_runs):
    if rule is None:return {'result':'BENIGN_TEST_DESCRIPTIVE_ONLY','reason':'No prospective rule; no post-hoc cutoff introduced'}
    if rule!=capture_tool.CLASSIFICATION_RULE:raise ValueError('Unsupported predeclared rule; do not reinterpret after TEST')
    c=candidate;n=c['windows'];runs=c['runs']
    raw=Fraction(c['novelty']['anomalous_windows'],n)
    alerts=Fraction(c['episode']['benign_runs_alerted'],runs)
    baseline=Fraction(v1['episode']['benign_runs_alerted'],v1['runs'])
    # "Known-attack windows" uses raw XGB non-BENIGN classifications, retaining
    # weak classifier mistakes even if reconciliation suppresses the claim.
    known=Fraction(c['xgboost']['false_known_attack_windows'],n)
    fail={'raw_novelty_FPR_at_least_50_percent':raw>=Fraction(1,2),
        'episode_run_alert_rate_at_least_50_percent':alerts>=Fraction(1,2),
        'false_known_classification_rate_at_least_10_percent':known>=Fraction(1,10),
        'episode_rate_regression_at_least_one_third':alerts-baseline>=Fraction(1,3)}
    passed=(runs==expected_runs and known==0 and alerts==0 and raw<=Fraction(1,20) and alerts<=baseline)
    result='BENIGN_TEST_FAIL' if any(fail.values()) else 'BENIGN_TEST_PASS' if passed else 'BENIGN_TEST_MIXED'
    return {'result':result,'predeclared_rule':rule,'fail_checks':fail,'pass_criteria_met':passed,
        'known_classification_semantics':'Raw XGB non-BENIGN; final confident-known count reported separately',
        'no_promotion':True,'statistical_significance_claimed':False}


def paired(candidate,v1,protocols,cpersistence,cconfidence,vconfidence):
    left={key(p):p for p in candidate};right={key(p):p for p in v1}
    if len(left)!=len(candidate) or len(right)!=len(v1) or set(left)!=set(right):
        raise ValueError('Cannot manufacture window alignment')
    windows=[]
    for k in sorted(left,key=str):
        c,b=left[k],right[k]
        windows.append({'paired_window_id':'paired-'+digest(list(k))[:24],
            **{name:c[name] for name in ('run_id','window_start','window_end','client_id','user_agent_id','source_file','source_sha256','line_numbers')},
            'candidate':{'anomalous':c['novelty_anomalous'],'xgb_class':c['xgb_label'],'decision':c['reconciliation']['decision']},
            'v1':{'anomalous':b['if_anomalous'],'xgb_class':b['xgb_label'],'decision':b['reconciliation']['decision']}})
    sessions=[]
    for sid in sorted(protocols):
        c=summarize([p for p in candidate if p['run_id']==sid],cpersistence,cconfidence,candidate=True)
        b=summarize([p for p in v1 if p['run_id']==sid],1,vconfidence,candidate=False)
        def compact(m):return {'windows':m['windows'],'novelty_anomalous_windows':m['novelty']['anomalous_windows'],
            'xgb_non_benign_windows':m['xgboost']['false_known_attack_windows'],
            'UNKNOWN_ANOMALY_windows':m['reconciliation']['UNKNOWN_ANOMALY'],
            'known_attempt_windows':m['reconciliation']['false_known_attempt_windows'],
            'alert_episodes':m['episode']['alert_episodes'],'run_alerted':bool(m['episode']['benign_runs_alerted'])}
        cs,bs=compact(c),compact(b)
        sessions.append({'session_id':sid,'protocol':protocols[sid],'candidate':cs,'v1':bs,
            'candidate_minus_v1':{k:int(cs[k])-int(bs[k]) for k in cs if k!='windows'}})
    return windows,sessions


def report(metrics,sessions):
    c,b=metrics['candidate'],metrics['model_v1']
    text=['# Fresh blind BENIGN TEST — frozen candidate vs accepted Model v1','',
        'Saved models only. No retraining, tuning, promotion or successful-exploitation claim.',
        f"All {c['windows']} windows represent the same accepted events; 83-feature candidate and 65-feature v1 transforms independently replayed.",
        'Candidate persistence=2; v1 uses the existing paired-evaluation reporting convention persistence=1. Both group contiguous same-class windows.',
        'Raw scores differ in direction/scale and are not compared numerically across models. All XGBoost scores are uncalibrated.',
        '', '| Metric | Model v1 | Candidate v3.1 | Candidate − v1 |','|---|---:|---:|---:|']
    for row in metrics['paired_difference']:text.append(f"| {row['metric']} | {row['model_v1']} | {row['candidate']} | {row['difference']} |")
    text+=['','## Per-session results','',
        '| Session | Protocol | Windows | Candidate anomaly / UNKNOWN / XGB non-benign / episodes / alerted | v1 anomaly / UNKNOWN / XGB non-benign / episodes / alerted |',
        '|---|---|---:|---|---|']
    for s in sessions:
        def fmt(m):return ' / '.join(str(m[k]) for k in ('novelty_anomalous_windows','UNKNOWN_ANOMALY_windows','xgb_non_benign_windows','alert_episodes','run_alerted'))
        text.append(f"| {s['session_id']} | {s['protocol']} | {s['candidate']['windows']} | {fmt(s['candidate'])} | {fmt(s['v1'])} |")
    text+=['','## Model details','',
        f"Candidate OCSVM frozen cutoff: {c['novelty']['threshold']}. Normality score summary: {json.dumps(c['novelty']['score_summary'],sort_keys=True)}.",
        f"Candidate XGBoost: {c['xgboost']['BENIGN_windows']}/{c['windows']} BENIGN; false classes: {json.dumps(c['xgboost']['false_classes'],sort_keys=True)}.",
        f"Candidate uncalibrated score summary: {json.dumps(c['xgboost']['uncalibrated_score_summary'],sort_keys=True)}.",
        f"v1 uncalibrated score summary: {json.dumps(b['xgboost']['uncalibrated_score_summary'],sort_keys=True)}.",
        '', '## Prospective classification','',metrics['classification']['result'],
        '```json',json.dumps(metrics['classification'],indent=2,sort_keys=True),'```',
        '', '## Limitations','',
        'Six controlled student-role Moodle sessions do not establish population FPR or statistical significance.',
        'The comparison combines feature/model/preprocessing and episode-policy differences; it does not isolate a causal improvement.',
        'Apache combined logs omit POST bodies. Attack labels elsewhere are attempt patterns, not exploitation.',
        'Fresh controlled attack holdout has not run. No candidate promotion is authorized.','']
    return '\n'.join(text)


def evaluate(project):
    project=Path(project);root=project/'outputs/branch2/m5_final_day';candidate=root/'candidate_freeze_01'
    blind=root/'blind_benign_test_01';out=blind/'evaluation';dataset=project/'data/branch2_v3/development_freeze_01/dataset.json'
    if out.exists():raise ValueError('Refuse overwrite of blind evaluation')
    plan,f,gate=capture_tool.integrity(root,candidate,dataset,project,require_absence=False)
    evidence_path=blind/'test_evidence_manifest.json'
    if sha(evidence_path)!=EXPECTED_EVIDENCE_SHA or (blind/'test_evidence_manifest.sha256').read_text().strip()!=EXPECTED_EVIDENCE_SHA:
        raise ValueError('Unexpected TEST evidence hash')
    evidence=json.loads(evidence_path.read_text());pre=json.loads((blind/'pre_test_integrity.json').read_text())
    if (evidence['sha256']!=digest({k:v for k,v in evidence.items() if k!='sha256'})
        or pre['sha256']!=digest({k:v for k,v in pre.items() if k!='sha256'})
        or evidence['pre_test_integrity_sha256']!=sha(blind/'pre_test_integrity.json')
        or evidence['candidate_canonical_root_sha256']!=f['root_sha256']
        or evidence['candidate_freeze_file_sha256']!=sha(candidate/'freeze_manifest.json')
        or evidence['feature_schema_sha256']!=f['schema_sha256']
        or evidence['capture_plan_sha256']!=plan['sha256'] or evidence['models_evaluated_before_lock'] is not False
        or pre.get('test_captures_absent_at_gate') is not True):
        raise ValueError('Evidence lock/pre-test receipt mismatch')
    # Read the prospective rule before any prediction call. Never select from TEST.
    rule=pre.get('classification_rule')
    if rule is not None and rule!=capture_tool.CLASSIFICATION_RULE:raise ValueError('Unrecognized prospective rule')
    reserved={s['session_id']:s for s in plan['sessions'] if s['partition']=='TEST'}
    if {r['session_id'] for r in evidence['sessions']}!=set(reserved) or len(evidence['sessions'])!=6:
        raise ValueError('Locked cohort changed')
    rows=[];v1rows=[];verifications=[];bindings={}
    for record in evidence['sessions']:
        sid=record['session_id'];base=root/'browser_sessions'/sid
        if record['state']!='COMPLETE' or record['verified'] is not True:raise ValueError('Incomplete TEST cohort')
        if set(record['artifact_hashes'])!={'manifest.json','features.json','v1_features.json'}:raise ValueError('Incomplete capture hashes')
        for name,value in record['artifact_hashes'].items():
            if sha(base/name)!=value:raise ValueError('Locked capture changed')
            bindings[str(base/name)]=value
        checked=verify_capture(root,plan,sid)
        if not checked['verified'] or not checked['source_bytes_verified'] or not checked['ownership_filtering_reproduced']:
            raise ValueError('Independent capture replay failed')
        new,old,m=load_browser_session(root,reserved[sid],plan)
        if datetime.fromisoformat(m['provenance']['start_utc'])<=max(datetime.fromisoformat(f['frozen_at_utc']),datetime.fromisoformat(pre['prepared_at_utc'])):
            raise ValueError('TEST predates freeze/integrity gate')
        if any(r['partition']!='TEST' or r['label']!='BENIGN' for r in new+old):raise ValueError('Non-benign/non-TEST evidence')
        if [key(r) for r in new]!=[key(r) for r in old]:raise ValueError('Raw accepted event/window alignment mismatch')
        rows.extend(new);v1rows.extend(old);verifications.append(checked)
    if (len(rows)!=33 or sum(v['accepted_records'] for v in verifications)!=923
        or sum(v['foreign_records'] for v in verifications)!=18):raise ValueError('Unexpected locked cohort totals')
    if len({key(r) for r in rows})!=33:raise ValueError('Duplicated TEST observation/window')
    out.mkdir()
    integrity={'version':'m5-blind-evaluation-integrity-1.0','status':'PASS',**gate,
        'test_evidence_file_sha256':EXPECTED_EVIDENCE_SHA,'verified_test_sessions':verifications,
        'capture_files_sha256':bindings,'classification_rule_inspected_before_metrics':rule,
        'predictions_calculated':False,'checked_at_utc':datetime.now(timezone.utc).isoformat()}
    write(out/'integrity_receipt.json',integrity)
    _,model=verify_freeze(candidate/'freeze_manifest.json');baseline=load_v1(project/'outputs/branch2/m2c_final_01')
    cp=aligned_predictions(model,rows);bp=aligned_predictions(baseline,v1rows)
    cm=summarize(cp,model.config['persistence'],model.config['confidence_threshold'],candidate=True)
    bm=summarize(bp,1,baseline.reconciliation['confidence_threshold'],candidate=False)
    windows,sessions=paired(cp,bp,{sid:s['protocol'] for sid,s in reserved.items()},
        model.config['persistence'],model.config['confidence_threshold'],baseline.reconciliation['confidence_threshold'])
    metrics={'version':'m5-fresh-blind-benign-evaluation-1.0','candidate_id':f['candidate_id'],
        'candidate':cm,'model_v1':bm,'classification':classification(cm,bm,rule,6),
        'window_alignment':'Exact run/time/client/agent/source hash/accepted byte-position membership',
        'v1_episode_policy':'Existing M5 paired comparator: contiguous same-class grouping, persistence=1; no new v1 model threshold',
        'raw_events_replayed':True,'accepted_records':923,'ambient_records_excluded':18,
        'candidate_features':83,'v1_features':65,'no_retraining':True,'no_test_based_tuning':True,
        'fresh_attack_holdout_run':False,'promotion_authorized':False}
    getters={'window_anomaly_FPR':lambda m:m['novelty']['window_FPR'],
        'UNKNOWN_ANOMALY_windows':lambda m:m['reconciliation']['UNKNOWN_ANOMALY'],
        'false_XGB_known_attack_windows':lambda m:m['xgboost']['false_known_attack_windows'],
        'false_final_known_attempt_windows':lambda m:m['reconciliation']['false_known_attempt_windows'],
        'alert_episodes':lambda m:m['episode']['alert_episodes'],
        'benign_runs_alerted':lambda m:m['episode']['benign_runs_alerted'],
        'run_false_alert_rate':lambda m:m['episode']['run_false_alert_rate']}
    metrics['paired_difference']=[{'metric':name,'model_v1':fn(bm),'candidate':fn(cm),'difference':fn(cm)-fn(bm)} for name,fn in getters.items()]
    write(out/'candidate_predictions.json',cp);write(out/'model_v1_predictions.json',bp)
    write(out/'paired_windows.json',windows);write(out/'per_session_comparison.json',sessions);write(out/'metrics.json',metrics)
    with (out/'report.md').open('x') as handle:handle.write(report(metrics,sessions))
    _,reloaded=verify_freeze(candidate/'freeze_manifest.json')
    replay=aligned_predictions(reloaded,rows);v1replay=aligned_predictions(load_v1(project/'outputs/branch2/m2c_final_01'),v1rows)
    if cp!=replay or bp!=v1replay:raise ValueError('Saved-model replay mismatch')
    write(out/'replay_consistency.json',{'candidate_matched':True,'model_v1_matched':True,'windows_each':33,'fit_calls':0})
    capture_tool.integrity(root,candidate,dataset,project,require_absence=False)
    if sha(evidence_path)!=EXPECTED_EVIDENCE_SHA or any(sha(name)!=value for name,value in bindings.items()):raise ValueError('Inputs changed during evaluation')
    write(out/'post_evaluation_integrity.json',{'status':'PASS','candidate_unchanged':True,'test_evidence_unchanged':True,
        'model_v1_unchanged':True,'development_dataset_unchanged':True,'capture_plan_unchanged':True,
        'no_retraining':True,'fit_methods_blocked':list(FITTING_METHODS),'network_blocked':True})
    write(out/'artifact_manifest.json',{'files':{p.name:{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(out.iterdir())},
        'self_hash_convention':'artifact_manifest.json excludes itself'})
    return metrics


def main():
    try:
        with ExitStack() as stack:
            for method in FITTING_METHODS:stack.enter_context(patch(method,side_effect=AssertionError('Fitting prohibited during blind evaluation')))
            for method in ('socket.socket.connect','socket.socket.connect_ex','socket.create_connection','socket.getaddrinfo','socket.socket.sendto'):
                stack.enter_context(patch(method,side_effect=AssertionError('Network prohibited during blind evaluation')))
            result=evaluate(ROOT)
        print(json.dumps({'classification':result['classification']['result'],'windows':result['candidate']['windows']}));return 0
    except Exception:
        print('Blind evaluation stopped: integrity, source replay, schema or saved-model inference failure. No model changes or substitute results.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
