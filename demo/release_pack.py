"""Read-only frozen research exports and new explicitly scoped demo snapshots."""
import csv
import hashlib
import json
from pathlib import Path
from .backend.config import ROOT, Config
from .backend.services import Application


def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def write_new(path, value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as f:
        f.write(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n' if not isinstance(value,str) else value)


def table(path, rows):
    path=Path(path);write_new(path.with_suffix('.json'),rows)
    keys=sorted({k for r in rows for k in r})
    with path.with_suffix('.csv').open('x',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=keys);writer.writeheader()
        writer.writerows({k:json.dumps(v,sort_keys=True) if isinstance(v,(dict,list)) else v for k,v in r.items()} for r in rows)


def frozen(name):
    origin=json.loads((ROOT/'outputs/branch2/accepted_behavioral_v2/candidate_freeze.json').read_text())
    path=ROOT/'outputs/branch2/m5_final_day/candidate_freeze_01'/name
    if sha(path)!=origin['artifact_files_sha256'][name]:raise ValueError('Frozen development artifact changed')
    return json.loads(path.read_text())


def snapshots(app):
    from fusion.adapters import posture
    from fusion.dedup import clusters
    from fusion.cqi import dimensions,score
    raw=json.loads((ROOT/Config().posture).read_text());p=posture(raw,Config().posture);grouped=clusters(p)
    dims=dimensions(p,grouped);partial=score(dims)
    result=[{'id':'POSTURE_ONLY_PARTIAL','overall_cqi':partial['cqi'],'status':partial['score_status'],
        'dimensions':dims,'contributors':grouped,'active_incidents':None,'as_of':None,
        'source_evidence':[Config().posture],
        'time_semantics':'No posture timestamp is available; none invented',
        'limitation':'D6 INSUFFICIENT_EVIDENCE, not 100. Available five dimensions renormalized by frozen policy. This partial index is not a like-for-like six-dimension comparison.'}]
    benign=app.snapshot(replay='BENIGN_TEST');attack=app.snapshot(replay='ATTACK_HOLDOUT')
    normal=next(o.evidence['run_id'] for o in benign['observations'] if o.reconciled_label=='BENIGN')
    known=next(o.evidence['run_id'] for o in attack['observations'] if o.reconciled_label=='SQLI_ATTEMPT')
    unknown=next(o.evidence['run_id'] for o in benign['observations'] if o.reconciled_label=='UNKNOWN_ANOMALY')
    for name,source,rid in [('NORMAL_BENIGN','BENIGN_TEST',normal),('KNOWN_ATTEMPT','ATTACK_HOLDOUT',known),
                            ('UNKNOWN_OBSERVATION','BENIGN_TEST',unknown),('ALL_ATTACK_RECENT','ATTACK_HOLDOUT',None)]:
        s=app.snapshot(replay=source,run_id=rid);q=s['cqi']
        result.append({'id':name,'mode':'ACCEPTED_REPLAY','source_label':'ACCEPTED EVIDENCE REPLAY',
            'run_id':rid,'overall_cqi':q.overall,'status':q.overall_status,
            'dimensions':s['artifacts']['dimensions'],'contributors':q.contributors,
            'active_incidents':q.active_behavioral_impact['active_incident_count'],'as_of':q.as_of,
            'source_evidence':[Config().posture,s['status'].runtime['source']],
            'time_semantics':s['status'].runtime['time_semantics'],
            'model_package_id':s['model']['package_id'],'snapshot_generation':s['status'].source_generation})
    return {'policy_unchanged':True,'weights':'1/6 each; available-only renormalization for partial evidence',
        'is_probability':False,'snapshots':result}


def narrative(app, research, development, validation, run_metrics):
    model=app.model();b=research['benign'];a=research['attack']
    bp=b['candidate'];b1=b['model_v1'];ap=a['candidate'];a1=a['model_v1']
    report={'schema':'behavioral-v2-final-narrative-1.0','model':model,
        'research_problem':'Reduce nuisance anomaly alerts in realistic authenticated Moodle browser behavior while retaining controlled attack-pattern sensitivity.',
        'baseline':'Accepted Model v1: 65 features, benign-trained Isolation Forest and XGBoost. Preserved as the paired baseline.',
        'diagnostic':{'source':'docs/branch2/m5/M5A_LIVE_GENERALIZATION_DIAGNOSTIC.md',
            'sha256':sha(ROOT/'docs/branch2/m5/M5A_LIVE_GENERALIZATION_DIAGNOSTIC.md'),
            'finding':'Ordinary-looking navigation/AJAX/resource windows showed IF anomaly with high XGB BENIGN scores; quote/encoding/query and resource deviations were associated evidence, not causal proof.',
            'data_role':'Diagnostic-only session; excluded from training and threshold selection'},
        'development_counts':development['counts'],'validation':{'xgboost_window':validation['xgboost'],'xgboost_run':run_metrics['xgboost']},
        'blind_benign_test':b,'fresh_attack_holdout':a,'accepted_architecture':'10-second windows → 83 frozen features → OCSVM + XGBoost → frozen reconciliation → observation → UNKNOWN persistence two → incident',
        'live_design':'Incremental append reader, source-byte continuity, transactional SQLite journal, checkpoint/restart and stable observation/episode IDs.',
        'explainability':'Upstream native exact TreeSHAP explains classifier raw margins; robust TRAIN-reference deviations are associated evidence, not causal OCSVM attribution.',
        'limitations':model['limitations'],'statistical_significance_claimed':False,'scores_calibrated':False,
        'successful_exploitation_confirmed':False,'training_performed':False,
        'conclusion':'Scoped local-laboratory acceptance: substantial blind benign false-alert reduction with preserved 14/14 fresh run detection. No claim of universal LMS, population-level or unseen-threat accuracy.'}
    md=f'''# Accepted Behavioral v2 — final research report

## 1. Research problem
{report['research_problem']}

## 2. Model v1 baseline
{report['baseline']}

## 3. Observed realistic-browser domain shift
{report['diagnostic']['finding']} The original diagnostic remains an external,
diagnostic-only observation, not labelled development data. Apache evidence alone
does not independently prove authenticated identity or human intent.

## 4. Development protocol
Complete run/session partitions prevent adjacent-window leakage. Development used
{development['counts']['TRAIN']['runs']} TRAIN runs / {development['counts']['TRAIN']['windows']} windows and
{development['counts']['VALIDATION']['runs']} VALIDATION runs / {development['counts']['VALIDATION']['windows']} windows.
Novelty models fit BENIGN TRAIN only; validation alone selected the detector,
cutoff and episode settings. Historical TEST and the external diagnostic were
excluded. Failed captures remain immutable excluded evidence.

## 5. Frozen v3.1 candidate
Package origin: {model['candidate_origin_id']}. Schema: {model['schema_version']},
{model['feature_count']} features. Selected {model['novelty_detector']} cutoff
{model['novelty_threshold']}; XGBoost uncalibrated score threshold
{model['confidence_threshold']}; UNKNOWN persistence {model['persistence']}.
All decisions were frozen before fresh TEST and attempt holdout. No subsequent
feature, threshold, model or reconciliation adjustment occurred.

## 6. Fresh blind BENIGN TEST
{bp['runs']} sessions / {bp['windows']} windows. Candidate novelty anomalies:
{bp['novelty']['anomalous_windows']}/{bp['windows']} ({bp['novelty']['window_FPR']*100:.2f}%).
Episode-aware alerted sessions {bp['episode']['benign_runs_alerted']}/{bp['runs']};
alert episodes {bp['episode']['alert_episodes']}; UNKNOWN observations
{bp['reconciliation']['UNKNOWN_ANOMALY']}. XGBoost BENIGN
{bp['xgboost']['BENIGN_windows']}/{bp['windows']}. Isolated UNKNOWN remains visible
without becoming an incident.

## 7. Fresh controlled ATTACK holdout
{ap['runs']} fresh runs, two per seven classes; {ap['windows']} windows. Candidate
detected {ap['reconciled']['detected_runs']}/{ap['runs']} runs and
{ap['reconciled']['detected_windows']}/{ap['windows']} windows
({ap['reconciled']['window_recall']*100:.2f}% reconciled window recall).
XGBoost mean-score run class correct {ap['xgboost']['correct_class_runs']}/{ap['runs']}.
Raw classifier errors remain: {ap['xgboost']['BENIGN_miss_windows']} BENIGN window
and {ap['xgboost']['wrong_attack_class_windows']} wrong attack-class window.
Reconciliation retained {ap['reconciled']['UNKNOWN_ANOMALY_windows']} UNKNOWN
observation rather than silently turning all classifier misses benign.
SQLI/XSS/PATH labels mean observable attempts, not successful exploitation.

## 8. Paired Model v1 versus Behavioral v2

| Metric | Model v1 | Behavioral v2 |
|---|---:|---:|
| Benign novelty window FPR | {b1['novelty']['window_FPR']*100:.2f}% | {bp['novelty']['window_FPR']*100:.2f}% |
| Benign sessions alerted | {b1['episode']['benign_runs_alerted']}/{b1['runs']} | {bp['episode']['benign_runs_alerted']}/{bp['runs']} |
| Benign alert episodes | {b1['episode']['alert_episodes']} | {bp['episode']['alert_episodes']} |
| Fresh attack runs detected | {a1['reconciled']['detected_runs']}/{a1['runs']} | {ap['reconciled']['detected_runs']}/{ap['runs']} |
| Reconciled attack window recall | {a1['reconciled']['window_recall']*100:.2f}% | {ap['reconciled']['window_recall']*100:.2f}% |

The exact same accepted raw evidence underlies paired comparisons; each model
uses its own frozen schema. Controlled repetitions are not independent real
users. Episode-policy differences are explicit: v1 comparator persistence one,
accepted v2 UNKNOWN persistence two. No statistical significance is claimed.

## 9. Accepted architecture
{report['accepted_architecture']}. Accepted ID {model['package_id']}.
Canonical root SHA256: {model['root_sha256']}. The candidate and v1 packages remain
unchanged, separate baselines. Other LMS accuracy has not been demonstrated.

## 10. Live inference
{report['live_design']} Runtime replay acceptance is distinct from an operator's
prospective live browsing acceptance, which may remain pending. No attacks are
generated by the dashboard. Observation is not incident.

## 11. Explainability
{report['explainability']} Scores are not calibrated probabilities. CQI is explained
directly by frozen ordinal contributions, deduplication and equal dimension weights.

## 12. Limitations
'''+''.join('- '+l+'\n' for l in model['limitations'])+f'''
Apache combined logs omit POST bodies. CQI is a quality index, not a probability
of attack, compromise or security; its coefficients are policy-derived.

## 13. Conclusion
{report['conclusion']}
'''
    return report,md


def export_pack():
    app=Application(Config());research=app.research();dev=frozen('development_manifest.json')
    val=frozen('validation_metrics.json');run=frozen('validation_run_metrics.json');nov=frozen('validation_novelty_comparison.json')
    perf=json.loads((ROOT/'outputs/benchmarks/final/performance.json').read_text())
    reliability=json.loads((ROOT/'outputs/reliability/final_acceptance.json').read_text())
    snaps=snapshots(app);report,md=narrative(app,research,dev,val,run)
    write_new(ROOT/'outputs/demo/cqi_snapshots.json',snaps)
    write_new(ROOT/'outputs/reports/behavioral_v2_final_report.json',report)
    write_new(ROOT/'outputs/reports/behavioral_v2_final_report.md',md)
    out=ROOT/'outputs/research_pack/final';out.mkdir(parents=True,exist_ok=False)
    tables={}
    tables['01_dataset_distribution']=[{'partition':partition,'class':label,'runs':c['class_runs'][label],
        'windows':c['class_windows'][label]} for partition,c in dev['counts'].items() for label in sorted(c['class_runs'])]
    b=research['benign'];a=research['attack']
    for tag,source in [('FRESH_BLIND_BENIGN',b['candidate']),('FRESH_ATTACK_HOLDOUT',a['candidate'])]:
        if tag=='FRESH_BLIND_BENIGN':tables['01_dataset_distribution'].append({'partition':tag,'class':'BENIGN','runs':source['runs'],'windows':source['windows']})
        else:tables['01_dataset_distribution'] += [{'partition':tag,'class':c,'runs':v['runs'],'windows':v['windows']} for c,v in source['per_class'].items()]
    tables['02_novelty_validation_comparison']=[{'model':name,'threshold':v['threshold'],'unit':unit,**v[key]}
        for name,v in nov.items() for unit,key in [('WINDOW','window'),('RUN_ANY_ANOMALY','run_any_anomalous_window')]]
    tables['03_xgb_validation_metrics']=[{'unit':unit,'class':label,**v,'macro_f1':m['macro_f1'],'accuracy':m['accuracy']}
        for unit,m in [('WINDOW',val['xgboost']),('RUN',run['xgboost'])] for label,v in m['per_class'].items()]
    tables['04_blind_benign_v1_vs_v2']=[{'model':name,'runs':v['runs'],'windows':v['windows'],
        'novelty_FPR':v['novelty']['window_FPR'],'sessions_alerted':v['episode']['benign_runs_alerted'],
        'alert_episodes':v['episode']['alert_episodes'],'UNKNOWN_ANOMALY':v['reconciliation']['UNKNOWN_ANOMALY']}
        for name,v in [('Model v1',b['model_v1']),('Behavioral v2',b['candidate'])]]
    tables['05_fresh_attack_v1_vs_v2']=[{'model':name,'runs':v['runs'],'windows':v['windows'],**v['reconciled'],
        'xgb_correct_run_classes':v['xgboost']['correct_class_runs']} for name,v in [('Model v1',a['model_v1']),('Behavioral v2',a['candidate'])]]
    tables['06_fresh_attack_per_class']=[{'model':name,'class':label,**v} for name,m in [('Model v1',a['model_v1']),('Behavioral v2',a['candidate'])] for label,v in m['per_class'].items()]
    tables['07_alert_episode_comparison']=[{'model':name,'scope':'BENIGN','episodes':m['episode']['alert_episodes'],'runs':m['runs']}
        for name,m in [('Model v1',b['model_v1']),('Behavioral v2',b['candidate'])]]+[
        {'model':name,'scope':'ATTACK_ATTEMPT','episodes':m['reconciled']['alert_episodes'],'runs':m['runs']} for name,m in [('Model v1',a['model_v1']),('Behavioral v2',a['candidate'])]]
    tables['08_cqi_dimensions']=[{'snapshot':s['id'],'overall_cqi':s['overall_cqi'],'dimension':d['dimension'],'quality':d['quality'],
        'risk':d['risk'],'status':d['score_status'],'weight':d['baseline_weight'],'as_of':s['as_of']} for s in snaps['snapshots'] for d in s['dimensions']]
    tables['09_performance']=[{'stage':k,**v} for k,v in perf['stages'].items()]
    tables['10_reliability_summary']=[{'check':name,'passed':value} for name,value in reliability['checks'].items()]
    for name,rows in tables.items():table(out/name,rows)
    figures(out,tables,val['xgboost'],snaps)
    write_new(out/'provenance.json',{'accepted_package_id':app.model()['package_id'],'accepted_root':app.model()['root_sha256'],
        'sources':{str(p.relative_to(ROOT)):sha(p) for p in [ROOT/'outputs/branch2/accepted_behavioral_v2/blind_benign_metrics.json',
            ROOT/'outputs/branch2/accepted_behavioral_v2/fresh_attack_metrics.json',ROOT/'outputs/branch2/m5_final_day/fresh_attack_holdout_01/v1_metrics.json',
            ROOT/'outputs/branch2/m5_final_day/candidate_freeze_01/development_manifest.json',ROOT/'outputs/branch2/m5_final_day/candidate_freeze_01/validation_metrics.json',
            ROOT/'outputs/benchmarks/final/performance.json',ROOT/'outputs/reliability/final_acceptance.json']},
        'no_statistical_significance_claimed':True,'no_retraining':True,'tables_are_exports_not_new_ML_evaluations':True})
    write_new(out/'artifact_manifest.json',{'self_hash_excluded':True,'files':{p.name:{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(out.iterdir()) if p.is_file()}})
    pending=ROOT/'outputs/demo/live_acceptance/latest.json'
    if not pending.exists():write_new(pending,{'status':'NEEDS_OPERATOR','operator_browsing_confirmed':False,'new_observations':None,'new_incidents':None,
        'model_package_id':app.model()['package_id'],'instructions':'Run scripts/live_acceptance.py begin, browse normally, then finish. No live result is asserted.'})
    return {'research_pack':str(out.relative_to(ROOT)),'tables':len(tables),'figures':len(list(out.glob('*.png'))),'snapshots':len(snaps['snapshots'])}


def figures(out,tables,xgb,snaps):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,'axes.spines.right':False,'figure.dpi':150})
    def save(fig,name):fig.tight_layout();fig.savefig(out/(name+'.png'),dpi=240,bbox_inches='tight');plt.close(fig)
    def bars(name,title,labels,values,unit='%',maximum=100):
        fig,ax=plt.subplots(figsize=(7,4));ax.bar(labels,values,color=['#536b88','#88a89a']);ax.set_ylim(0,maximum);ax.set_ylabel(unit);ax.set_title(title)
        for i,v in enumerate(values):ax.text(i,v+maximum*.02,f'{v:.2f}' if unit=='%' else str(v),ha='center')
        save(fig,name)
    b=tables['04_blind_benign_v1_vs_v2'];a=tables['05_fresh_attack_v1_vs_v2']
    bars('benign_novelty_fpr','Fresh blind BENIGN novelty FPR (33 windows; 6 sessions)',[r['model'] for r in b],[100*r['novelty_FPR'] for r in b])
    bars('benign_alerted_sessions','Fresh BENIGN sessions producing alert episodes',[r['model'] for r in b],[r['sessions_alerted'] for r in b],'sessions',7)
    bars('attack_run_recall','Fresh controlled ATTEMPT run recall (14 runs)',[r['model'] for r in a],[100*r['run_recall'] for r in a])
    fig,ax=plt.subplots(figsize=(10,5));labels=list(xgb['classes']);image=ax.imshow(xgb['confusion_matrix'],cmap='Blues',vmin=0);fig.colorbar(image,ax=ax,label='Windows')
    ax.set_xticks(range(len(labels)),labels,rotation=60,ha='right');ax.set_yticks(range(len(labels)),labels);ax.set_xlabel('Predicted class');ax.set_ylabel('True class');ax.set_title('Frozen XGBoost VALIDATION confusion matrix (selection data)')
    for i,row in enumerate(xgb['confusion_matrix']):
        for j,v in enumerate(row):ax.text(j,i,str(v),ha='center',va='center',fontsize=8)
    save(fig,'xgb_validation_confusion_matrix')
    per=tables['06_fresh_attack_per_class'];classes=sorted({r['class'] for r in per});fig,ax=plt.subplots(figsize=(10,5));pos=np.arange(len(classes))
    for shift,model,color in [(-.18,'Model v1','#536b88'),(.18,'Behavioral v2','#88a89a')]:
        ax.bar(pos+shift,[next(r['run_recall']*100 for r in per if r['model']==model and r['class']==c) for c in classes],width=.36,label=model,color=color)
    ax.set_ylim(0,105);ax.set_yticks([0,25,50,75,100]);ax.set_ylabel('Run recall (%)');ax.set_xticks(pos,classes,rotation=40,ha='right');ax.set_title('Fresh controlled attempt recall: two runs per class');ax.legend();save(fig,'fresh_attack_per_class_recall')
    fig,ax=plt.subplots(figsize=(9,4));pos=np.arange(6)
    for shift,name,color in [(-.18,'NORMAL_BENIGN','#88a89a'),(.18,'KNOWN_ATTEMPT','#536b88')]:
        s=next(s for s in snaps['snapshots'] if s['id']==name);ax.bar(pos+shift,[d['quality'] for d in s['dimensions']],width=.36,label=name,color=color)
    ax.set_ylim(0,105);ax.set_yticks([0,25,50,75,100]);ax.set_xticks(pos,['D1','D2','D3','D4','D5','D6']);ax.set_ylabel('Quality index (0–100)');ax.set_title('Frozen CQI policy: representative accepted replay states');ax.legend();save(fig,'cqi_six_dimensions')
    rows=tables['09_performance'];fig,ax=plt.subplots(figsize=(10,6));ax.barh([r['stage'] for r in rows],[r['p95'] for r in rows],color='#536b88');ax.set_xlim(left=0);ax.set_xlabel('Measured p95 milliseconds (linear axis)');ax.set_title('Saved-evidence component and in-process API timing');save(fig,'performance_latency')


import numpy as np
