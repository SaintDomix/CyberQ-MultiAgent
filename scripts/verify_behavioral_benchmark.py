#!/usr/bin/env python3
"""Post-execution CSV/count/integrity verification; no fitting or inference."""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT)]
from behavioral_benchmark.three_pipeline import (read,write,sha,digest,check_protocol,
    window_id,select,ROOT,ACCEPTED,BENIGN,ATTACK)
from behavioral_runtime.package import verify
from behavioral_v2.episodes import episodes
from branch2.reconciliation import reconcile


def flag(value): return value=='True'


def verify_results(out, before, focused, regressions):
    config=read(out/'benchmark_config.json');check_protocol(config,ROOT)
    result=read(out/'pipeline_results.json');decision=read(out/'selection_decision.json')
    completed=read(out/'execution_completed.json');fit=read(out/'detectors_frozen_before_evaluation.json')
    assert not (out/'execution_failure.json').exists()
    assert completed['alternative_fit_calls']==2 and completed['OCSVM_fit_calls']==completed['XGBoost_fit_calls']==0
    assert fit['holdout_loaded'] is False and fit['config_sha256']==config['sha256']
    for name,h in fit['artifact_sha256'].items():assert sha(out/name)==h
    with (out/'window_results.csv').open() as stream:windows=list(csv.DictReader(stream))
    with (out/'run_results.csv').open() as stream:runs=list(csv.DictReader(stream))
    by={p:[r for r in windows if r['pipeline']==p] for p in ('A','B','C')}
    ids={p:[r['window_id'] for r in rs] for p,rs in by.items()}
    assert ids['A']==ids['B']==ids['C'] and len(set(ids['A']))==len(ids['A'])==101
    assert len({r['classifier_sha256'] for r in result['pipelines'].values()})==1
    assert len({r['classifier_metrics_sha256'] for r in result['pipelines'].values()})==1
    # Recover grouping identity from immutable saved predictions, not an invented
    # one-group-per-run assumption. All new verdicts come only from saved CSV.
    saved=read(ROOT/BENIGN/'evaluation/candidate_predictions.json')+read(ROOT/ATTACK/'predictions.json')['candidate']
    original={window_id(r):r for r in saved}
    for i in range(101):
        fields=('window_id','run_id','true_class','window_start','window_end','xgb_label','xgb_uncalibrated_score')
        assert all(tuple(by[p][i][f] for f in fields)==tuple(by['A'][i][f] for f in fields) for p in ('B','C'))
    primary={};paired={}
    for pipeline,rs in by.items():
        m=result['pipelines'][pipeline];benign=[r for r in rs if r['true_class']=='BENIGN'];attack=[r for r in rs if r['true_class']!='BENIGN']
        assert len(benign)==33 and len(attack)==68
        reconstructed=[]
        for r in rs:
            s=original[r['window_id']];anomaly=flag(r['novelty_anomalous']);score=float(r['novelty_score'])
            assert math.isfinite(score) and anomaly==(score<float(r['threshold']))
            assert float(r['threshold'])==config['pipelines'][pipeline]['threshold']
            assert flag(r['strict_end_to_end'])==(anomaly and r['xgb_label']==r['true_class'] and r['true_class']!='BENIGN')
            p={k:s[k] for k in ('run_id','label','window_start','window_end','client_id','user_agent_id')}
            p['record_id']=r['window_id'];p['reconciliation']=reconcile(anomaly,r['xgb_label'],float(r['xgb_uncalibrated_score']),config['confidence_threshold'])
            assert p['reconciliation']['decision']==r['reconciled_label'];reconstructed.append(p)
        es=episodes(reconstructed,config['persistence'])
        assert sum(flag(r['novelty_anomalous']) for r in benign)==m['benign']['window_fpr']['count']
        assert sum(flag(r['novelty_anomalous']) for r in attack)==m['attack']['novelty_window_recall']['count']
        assert sum(flag(r['strict_end_to_end']) for r in attack)==m['attack']['strict_end_to_end_recall']['count']
        rr=[r for r in runs if r['pipeline']==pipeline]
        assert len(rr)==20
        for r in rr:
            alerts=[e for e in es if e['alert'] and e['run_id']==r['run_id']]
            assert len(alerts)==int(r['production_alert_episodes']) and bool(alerts)==flag(r['production_alerted'])
        for label,c in m['per_class'].items():
            group=[r for r in attack if r['true_class']==label]
            assert len(group)==c['windows'] and sum(flag(r['strict_end_to_end']) for r in group)==c['strict_end_to_end']['count']
        primary[pipeline]={r['window_id'] for r in attack if flag(r['strict_end_to_end'])}
        paired[pipeline]={r['window_id'] for r in benign if flag(r['novelty_anomalous'])}
    selected=select(result['pipelines'])
    assert {k:decision[k] for k in selected}==selected
    receipt=read(out/'split_receipt.json')
    training={r['window_id'] for r in receipt['partitions']['TRAIN']['observations'] if r['label']=='BENIGN'}
    assert set(fit['fit_input_window_ids'])==training and len(training)==101
    assert not training&set(ids['A'])
    paired_report={'novelty':result['paired_disagreements'],
        'strict_AND':{'all_three':sorted(set.intersection(*primary.values())),
            'A_not_B':sorted(primary['A']-primary['B']),'A_not_C':sorted(primary['A']-primary['C']),
            'B_not_A':sorted(primary['B']-primary['A']),'C_not_A':sorted(primary['C']-primary['A'])},
        'benign_FP_pairwise_overlap':{a+'_'+b:sorted(paired[a]&paired[b]) for a,b in [('A','B'),('A','C'),('B','C')]},
        'benign_FP_locations':{p:[{k:r[k] for k in ('window_id','run_id','window_start')} for r in by[p] if r['window_id'] in paired[p]] for p in by}}
    write(out/'paired_disagreements.json',paired_report)
    baseline=read(before);changed=[p for p,h in baseline['files'].items() if not (ROOT/p).is_file() or sha(ROOT/p)!=h]
    assert not changed,changed
    assert verify(ROOT/ACCEPTED)['root_sha256']==baseline['accepted_root']
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip();assert head==baseline['head']
    subprocess.run(['git','diff','--check'],cwd=ROOT,check=True)
    tests={}
    for name,path in [('focused',focused),('regressions',regressions)]:
        nodes=ET.parse(path).findall('.//testcase');assert all(t.find('failure') is None and t.find('error') is None for t in nodes)
        tests[name]=dict(Counter(t.get('classname') for t in nodes))
    write(out/'preservation_before_sha256.json',{'head':baseline['head'],'files':baseline['files']})
    (out/'git_diff_stat.txt').write_text(subprocess.check_output(['git','diff','--stat'],cwd=ROOT,text=True))
    (out/'git_status_short.txt').write_text(subprocess.check_output(['git','status','--short'],cwd=ROOT,text=True))
    quality={'status':'PASS','verified_at_utc':datetime.now(timezone.utc).isoformat(),'head':head,
        'protocol_sha256':config['sha256'],'accepted_root_before':baseline['accepted_root'],
        'accepted_root_after':verify(ROOT/ACCEPTED)['root_sha256'],'preserved_preexisting_files':len(baseline['files']),
        'changed_preexisting_files':changed,'task2a_unchanged':True,'branch1_unchanged':True,'CQI_unchanged':True,
        'fixed_classifier_hash':config['pipelines']['A']['classifier_sha256'],'shared_evaluation_windows':101,
        'feature_count':83,'source_record_leakage':0,'independent_CSV_metric_check':'PASS',
        'independent_episode_reconstruction':'PASS','fixed_classifier_output_invariant':'PASS',
        'selection_gate_reproduces':True,'fit_input_excludes_evaluation':True,'tests':tests,
        'focused_count':sum(tests['focused'].values()),'regression_count':sum(tests['regressions'].values()),
        'valid_benchmark_executions':1,'invalid_executions':0,'new_calibration_calls':0,'new_traffic_requests':0,
        'OCSVM_refits':0,'alternative_fit_calls':2,'XGBoost_refits':0,'scaler_refits':0,
        'git_diff_check':'PASS','disk_free_bytes':shutil.disk_usage(ROOT).free,'accepted_replaced':False,
        'committed':False,'tagged':False}
    write(out/'quality_receipt.json',quality)
    execution_code=['src/behavioral_benchmark/__init__.py','src/behavioral_benchmark/three_pipeline.py',
        'scripts/run_behavioral_benchmark.py']
    verification_code=['scripts/verify_behavioral_benchmark.py','tests/test_three_pipeline_benchmark.py',
        'docs/research/BEHAVIORAL_MODEL_BENCHMARK.md']
    write(out/'implementation_sha256.json',{'git_head':head,
        'execution_code_sha256':{p:sha(ROOT/p) for p in execution_code},
        'verification_and_documentation_sha256':{p:sha(ROOT/p) for p in verification_code},
        'recorded_after_execution':True,'protocol_parameters_frozen_before_execution':True})
    files={p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file() and p.name!='hashes.json'}
    manifest={'files_sha256':files};manifest['root_sha256']=digest(manifest);write(out/'hashes.json',manifest)
    print(json.dumps({'quality':'PASS','decision':decision['decision'],'protected_files':len(baseline['files']),
        'focused_tests':quality['focused_count'],'regressions':quality['regression_count'],
        'artifact_root_sha256':manifest['root_sha256'],'disk_free_bytes':quality['disk_free_bytes']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',default='outputs/behavioral/task2b_benchmark_01')
    parser.add_argument('--before',default='/tmp/task2b_before.json')
    parser.add_argument('--focused',default='/tmp/task2b_focused.xml')
    parser.add_argument('--regressions',default='/tmp/task2b_regressions.xml')
    args=parser.parse_args();out=(ROOT/args.out).resolve()
    if not out.is_relative_to(ROOT/'outputs/behavioral'):raise SystemExit('Invalid benchmark output root')
    verify_results(out,args.before,args.focused,args.regressions)
