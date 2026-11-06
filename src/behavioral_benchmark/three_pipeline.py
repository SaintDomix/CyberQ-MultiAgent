"""Three fixed novelty detectors, one accepted classifier, immutable inputs.

Preparation never opens holdout outcomes. Execution refits only the two historical
alternative configurations on benign TRAIN, then opens held-out evidence once.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import importlib.metadata
import json
from pathlib import Path
import pickle
import platform
import shutil
import time
import joblib
import numpy as np
from scipy.stats import binomtest
from sklearn.base import clone
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from behavioral_runtime.package import load, verify, ORIGIN_ROOT
from behavioral_v2.features31 import matrix
from behavioral_v2.episodes import episodes
from branch2.reconciliation import reconcile
from branch2.dataset import CLASSES
from demo.backend.explanation_sources import replay_features, key
from demo.backend.config import SOURCE_HASHES

ROOT = Path(__file__).resolve().parents[2]
ACCEPTED = 'outputs/branch2/accepted_behavioral_v2'
DEVELOPMENT = 'outputs/branch2/m5_final_day/candidate_freeze_01'
BENIGN = 'outputs/branch2/m5_final_day/blind_benign_test_01'
ATTACK = 'outputs/branch2/m5_final_day/fresh_attack_holdout_01'
EXPECTED_ROOT = '59a8c7c5d3d51632d0afe45f8cd2fe50570b7af2943d26bb313888327ea9f436'
PIPELINES = {'A': 'OCSVM', 'B': 'LOF', 'C': 'IF'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''): h.update(part)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n')


def disk_guard(path):
    if shutil.disk_usage(path).free < 500 * 1024 * 1024:
        raise ValueError('Less than 500 MiB free; stop artifact generation')


def bound(root, path, expected):
    if sha(Path(root) / path) != expected: raise ValueError('Input hash mismatch: ' + path)
    return read(Path(root) / path)


def window_id(row):
    # Input identity, not model outputs: identical across A/B/C.
    return 'window-' + digest({k: row.get(k) for k in ('run_id','window_start','window_end',
        'client_id','user_agent_id','source_sha256','line_numbers')})


def development(root, package):
    """Only TRAIN/VALIDATION; called before holdout loading."""
    freeze = read(Path(root) / ACCEPTED / 'candidate_freeze.json')
    if freeze['root_sha256'] != ORIGIN_ROOT or digest({k:v for k,v in freeze.items() if k!='root_sha256'}) != ORIGIN_ROOT:
        raise ValueError('Frozen development origin mismatch')
    dataset = bound(root, DEVELOPMENT+'/development_dataset.json', freeze['development_dataset_sha256'])
    bound(root, DEVELOPMENT+'/development_manifest.json', freeze['development_manifest_sha256'])
    rows = dataset['rows']
    if set(r['partition'] for r in rows) != {'TRAIN','VALIDATION'}:
        raise ValueError('Holdout leaked into development dataset')
    for partition, config_key in [('TRAIN','train_ids'),('VALIDATION','validation_ids')]:
        if {r['run_id'] for r in rows if r['partition']==partition} != set(package.config[config_key]):
            raise ValueError('Accepted run split mismatch')
    train = [r for r in rows if r['partition']=='TRAIN' and r['label']=='BENIGN']
    require_training(train, package.config['benign_fit_ids'])
    matrix(rows, package.feature_schema)
    return dataset, freeze


def require_training(rows, expected_ids):
    if not rows or any(r.get('partition')!='TRAIN' or r.get('label')!='BENIGN' for r in rows):
        raise ValueError('Novelty fitting requires BENIGN TRAIN exclusively')
    if {r['run_id'] for r in rows} != set(expected_ids):
        raise ValueError('Wrong benign TRAIN identities')


def prepare(out, root=ROOT):
    out = Path(out); root = Path(root); disk_guard(root)
    if out.exists(): raise FileExistsError('Refuse to overwrite a benchmark protocol')
    package = load(root/ACCEPTED); accepted = verify(root/ACCEPTED)
    if accepted['root_sha256'] != EXPECTED_ROOT: raise ValueError('Wrong accepted baseline')
    dataset, freeze = development(root, package)
    inputs = {ACCEPTED+'/'+name: h for name,h in accepted['files_sha256'].items()}
    inputs[ACCEPTED+'/accepted_manifest.json'] = sha(root/ACCEPTED/'accepted_manifest.json')
    inputs[DEVELOPMENT+'/development_dataset.json'] = freeze['development_dataset_sha256']
    inputs[DEVELOPMENT+'/development_manifest.json'] = freeze['development_manifest_sha256']
    for path in (BENIGN+'/test_evidence_manifest.json', BENIGN+'/evaluation/artifact_manifest.json',
                 BENIGN+'/evaluation/candidate_predictions.json', ATTACK+'/artifact_hashes.json',
                 ATTACK+'/predictions.json', ATTACK+'/predeclared_plan.json'):
        inputs[path] = sha(root/path)  # Integrity only: no holdout contents inspected.
    configs = {identity: {'detector':name, 'parameters':package.models[name]['model'].get_params(),
        'threshold':package.config['thresholds'][name], 'classifier_sha256':sha(root/ACCEPTED/'model/xgboost.json'),
        'classifier_path':ACCEPTED+'/model/xgboost.json',
        'scaler_source':ACCEPTED+'/model/novelty.joblib', 'scaler_sha256':sha(root/ACCEPTED/'model/novelty.joblib'),
        'fit': 'SAVED_ACCEPTED_NO_REFIT' if identity=='A' else 'ONCE_BENIGN_TRAIN_HISTORICAL_CONFIG'}
        for identity,name in PIPELINES.items()}
    protocol = {'version':'task2b-three-pipeline-1.0','prepared_at_utc':datetime.now(timezone.utc).isoformat(),
        'accepted_root':EXPECTED_ROOT,'pipelines':configs,'feature_schema':package.feature_schema,
        'input_sha256':inputs,'fit_run_ids':package.config['benign_fit_ids'],
        'preprocessing':'Exact saved accepted RobustScaler; transform only, never refit. XGBoost uses raw features.',
        'threshold_origin':'Exact frozen per-detector validation-selected cutoffs from pre-test M5; no new calibration',
        'calibration_calls':0,'new_search_candidates':0,'confidence_threshold':package.config['confidence_threshold'],
        'persistence':package.config['persistence'],'classes':sorted(CLASSES),
        'historical_configuration_source':'src/behavioral_v2/study31.py:train_freeze; accepted model/config.json',
        'metric_semantics':{'strict_end_to_end':'novelty_anomalous AND raw XGBoost label == true known class; no confidence gate added',
            'production':'Frozen reconcile(confidence_threshold=0.8) + episodes(persistence=2); confident known class may alert with normal novelty',
            'strict_run_detection':'At least one strict-correct window in a run',
            'raw_run_detection':'At least one novelty anomaly in a run',
            'classifier_run_prediction':'Majority window class; ties by sorted canonical class name',
            'interval':'95% Wilson, no continuity correction. Window intervals assume independence and are descriptive with within-run correlation.'},
        'replacement_gate':['strictly fewer benign false-positive windows',
            'no more false benign incident sessions under frozen production episodes',
            'no fewer strict-correct attack runs AND no fewer production alerted attack runs',
            'no fewer novelty-detected attack windows',
            'no fewer strict-correct attack windows AND no lower fixed classifier metrics'],
        'meaningful_nonregression':'No loss of even one strict-correct window/run; no post-hoc tolerance',
        'eligible_tie_break':'Fewer false incident sessions, fewer benign FP windows, more strict-correct attack runs/windows, more novelty attack windows; exact ties IF before LOF (fixed, no timing-based selection)',
        'preferred_benign_window_fpr':.05,'warm_inference_repetitions':3,
        'fit_time_A':'NOT_RECORDED; accepted OCSVM is not refitted for timing',
        'holdout_status':'Previously opened accepted evaluation evidence; paired reproducibility study, not a new blind trial',
        'detector_refits':{'OCSVM':0,'LOF':1,'IF':1},'classifier_refits':0,'scaler_refits':0,
        'execution_limit':'One valid execution; marker prevents rerunning in the same output directory'}
    protocol['sha256'] = digest(protocol)
    out.mkdir(parents=True)
    write(out/'benchmark_config.json',protocol)
    return protocol


def check_protocol(config, root):
    if digest({k:v for k,v in config.items() if k!='sha256'}) != config['sha256']:
        raise ValueError('Benchmark protocol changed')
    if {k:v['detector'] for k,v in config['pipelines'].items()} != PIPELINES:
        raise ValueError('Exactly the three declared pipelines are required')
    if config['accepted_root'] != EXPECTED_ROOT or config['persistence'] != 2:
        raise ValueError('Accepted architecture changed')
    for name, expected in config['input_sha256'].items():
        if sha(Path(root)/name) != expected: raise ValueError('Declared input changed: '+name)
    package=load(Path(root)/ACCEPTED)
    if config['feature_schema'] != package.feature_schema or config['classes'] != package.classes or config['confidence_threshold'] != package.config['confidence_threshold']:
        raise ValueError('Feature/classifier policy differs from accepted baseline')
    classifier_hash=sha(Path(root)/ACCEPTED/'model/xgboost.json')
    for identity,name in PIPELINES.items():
        p=config['pipelines'][identity]
        if (p['parameters'] != package.models[name]['model'].get_params()
                or p['threshold'] != package.config['thresholds'][name]
                or p['classifier_sha256'] != classifier_hash):
            raise ValueError('Frozen configuration or classifier binding changed')


def fit_alternative(name, train, package):
    if name not in ('LOF','IF'): raise ValueError('Accepted OCSVM cannot be refitted')
    require_training(train, package.config['benign_fit_ids'])
    values = matrix(train,package.feature_schema)
    scaler = package.models['OCSVM']['scaler']
    estimator = clone(package.models[name]['model'])
    start = time.perf_counter(); estimator.fit(scaler.transform(values))
    return estimator, (time.perf_counter()-start)*1000


def load_evaluation(root, package, config):
    root = Path(root)
    lock = bound(root, BENIGN+'/test_evidence_manifest.json', config['input_sha256'][BENIGN+'/test_evidence_manifest.json'])
    if sha(root/BENIGN/'test_evidence_manifest.json') != '807a14cbb6b2d26897709a71de2316f4b01c53fde85e836e9b25c344d84711a4':
        raise ValueError('Wrong locked benign evidence')
    plan = bound(root, ATTACK+'/predeclared_plan.json', config['input_sha256'][ATTACK+'/predeclared_plan.json'])
    if sha(root/ATTACK/'predeclared_plan.json') != '549ee00ebb163bb826667ab34b7a3ba2bcfd27d4c33534218546d860e8502d74':
        raise ValueError('Wrong authoritative attack plan')
    reserved = set(read(root/ACCEPTED/'candidate_freeze.json')['reserved_fresh_test_ids'])
    benign_ids = {s['session_id'] for s in lock['sessions'] if s['verified'] and s['state']=='COMPLETE'}
    if benign_ids != reserved: raise ValueError('Reserved blind split mismatch')
    truth = {r['run_id']:r['label'] for r in plan['runs']}
    data = []; saved = []
    for source, path, manifest, binding in [
        ('BENIGN_TEST',BENIGN+'/evaluation/candidate_predictions.json',BENIGN+'/evaluation/artifact_manifest.json','benign_manifest'),
        ('ATTACK_HOLDOUT',ATTACK+'/predictions.json',ATTACK+'/artifact_hashes.json','attack_manifest')]:
        artifact = bound(root,manifest,SOURCE_HASHES[binding])
        value = bound(root,path,artifact['files'][Path(path).name]['sha256'])
        predictions = value if source=='BENIGN_TEST' else value['candidate']
        allowed = benign_ids if source=='BENIGN_TEST' else set(truth)
        if {p['run_id'] for p in predictions} != allowed: raise ValueError('Evaluation run set mismatch')
        vectors = replay_features(root,predictions,source,package.feature_schema['sha256'])
        for p in sorted(predictions,key=lambda p:key(p)):
            label = 'BENIGN' if source=='BENIGN_TEST' else truth[p['run_id']]
            if p['label'] != label: raise ValueError('Authoritative class mismatch')
            if key(p) not in vectors: raise ValueError('Full verified 83-feature evaluation vector unavailable')
            row = {**{k:p[k] for k in ('run_id','window_start','window_end','client_id','user_agent_id','source_sha256','line_numbers')},
                'partition':source,'label':label,'features':vectors[key(p)],'schema_sha256':package.feature_schema['sha256']}
            row['record_id'] = window_id(row)
            data.append(row); saved.append(p)
    matrix(data,package.feature_schema)
    return data,saved


def split_receipt(development_rows, evaluation, package):
    rows = development_rows+evaluation; parts = sorted({r['partition'] for r in rows})
    run_parts = {}; footprints = defaultdict(set); numeric_duplicates = defaultdict(list)
    ids = [window_id(r) for r in rows]
    if len(ids) != len(set(ids)): raise ValueError('Duplicated input window')
    for r in rows:
        if r['run_id'] in run_parts and run_parts[r['run_id']] != r['partition']:
            raise ValueError('Run crosses partitions')
        run_parts[r['run_id']] = r['partition']
        for n in r['line_numbers']: footprints[r['partition']].add((r['source_sha256'], n))
        numeric_duplicates[digest(r['features'])].append(r['partition'])
    for i,a in enumerate(parts):
        for b in parts[i+1:]:
            if footprints[a]&footprints[b]: raise ValueError('Raw source records cross partitions')
    return {'schema_sha256':package.feature_schema['sha256'],'feature_order':package.feature_schema['feature_order'],
        'feature_count':83,'partitions':{part:{'run_ids':sorted(rid for rid,p in run_parts.items() if p==part),
            'runs':len({r['run_id'] for r in rows if r['partition']==part}),
            'windows':sum(r['partition']==part for r in rows),
            'class_counts':dict(sorted(Counter(r['label'] for r in rows if r['partition']==part).items())),
            'observations':[{'window_id':window_id(r),'run_id':r['run_id'],'label':r['label'],
                'window_start':r['window_start'],'window_end':r['window_end'],'source_sha256':r['source_sha256'],
                'input_feature_sha256':digest(r['features'])} for r in rows if r['partition']==part]} for part in parts},
        'benign_fit':{'partition':'TRAIN','run_ids':package.config['benign_fit_ids'],
            'windows':sum(r['partition']=='TRAIN' and r['label']=='BENIGN' for r in rows)},
        'same_evaluation_window_ids_for_all_pipelines':True,
        'run_partition_overlap':0,'duplicate_window_ids':0,'source_record_overlap_across_partitions':0,
        'identical_numeric_vectors_across_partitions':sum(len(set(ps))>1 for ps in numeric_duplicates.values()),
        'numeric_duplicate_semantics':'Identical numbers can arise in independent low-activity windows; not evidence reuse. Run/source-record identities remain disjoint.'}


def proportion(k,n):
    if n == 0: return {'count':k,'total':n,'rate':None,'wilson95':None}
    ci = binomtest(int(k),int(n)).proportion_ci(method='wilson')
    return {'count':int(k),'total':int(n),'rate':float(k/n),'wilson95':[float(ci.low),float(ci.high)]}


def make_predictions(rows, scores, cutoff, classes, confidences, confidence_threshold):
    result = []
    for row,score,label,confidence in zip(rows,scores,classes,confidences):
        anomalous = bool(score<cutoff)
        result.append({k:row[k] for k in ('record_id','run_id','partition','label','window_start','window_end','client_id','user_agent_id')})
        result[-1].update(novelty_score=float(score),novelty_anomalous=anomalous,
            xgb_label=str(label),xgb_confidence=float(confidence),
            strict_end_to_end=anomalous and label==row['label'] and row['label']!='BENIGN',
            reconciliation=reconcile(anomalous,str(label),float(confidence),confidence_threshold))
    return result


def summarize(predictions,persistence):
    benign = [p for p in predictions if p['label']=='BENIGN']; attack = [p for p in predictions if p['label']!='BENIGN']
    es = episodes(predictions,persistence)
    runs = []
    for rid in sorted({p['run_id'] for p in predictions}):
        group = [p for p in predictions if p['run_id']==rid]; counts = Counter(p['xgb_label'] for p in group)
        majority = min(counts,key=lambda k:(-counts[k],k))
        alert = [e for e in es if e['run_id']==rid and e['alert']]
        runs.append({'run_id':rid,'partition':group[0]['partition'],'true_class':group[0]['label'],
            'windows':len(group),'novelty_anomalous_windows':sum(p['novelty_anomalous'] for p in group),
            'any_novelty_anomaly':any(p['novelty_anomalous'] for p in group),
            'strict_correct_windows':sum(p['strict_end_to_end'] for p in group),
            'strict_detected':any(p['strict_end_to_end'] for p in group),
            'xgb_majority_class':majority,'xgb_run_correct':majority==group[0]['label'],
            'production_alerted':bool(alert),'production_alert_episodes':len(alert),
            'production_unknown_windows':sum(p['reconciliation']['decision']=='UNKNOWN_ANOMALY' for p in group),
            'production_known_windows':sum(p['reconciliation']['decision'] not in ('BENIGN','UNKNOWN_ANOMALY','UNCERTAIN') for p in group)})
    br = [r for r in runs if r['true_class']=='BENIGN']; ar = [r for r in runs if r['true_class']!='BENIGN']
    per_class = {}
    for label in sorted({p['label'] for p in attack}):
        ps = [p for p in attack if p['label']==label]; rs = [r for r in ar if r['true_class']==label]
        per_class[label] = {'windows':len(ps),'runs':len(rs),
            'novelty':proportion(sum(p['novelty_anomalous'] for p in ps),len(ps)),
            'strict_end_to_end':proportion(sum(p['strict_end_to_end'] for p in ps),len(ps)),
            'novelty_runs':proportion(sum(r['any_novelty_anomaly'] for r in rs),len(rs)),
            'strict_runs':proportion(sum(r['strict_detected'] for r in rs),len(rs)),
            'production_runs':proportion(sum(r['production_alerted'] for r in rs),len(rs))}
    return {'benign':{'windows':len(benign),'runs':len(br),
        'window_fpr':proportion(sum(p['novelty_anomalous'] for p in benign),len(benign)),
        'specificity':proportion(sum(not p['novelty_anomalous'] for p in benign),len(benign)),
        'raw_anomalous_runs':proportion(sum(r['any_novelty_anomaly'] for r in br),len(br)),
        'false_incident_sessions':proportion(sum(r['production_alerted'] for r in br),len(br)),
        'false_incident_episodes':sum(r['production_alert_episodes'] for r in br)},
        'attack':{'windows':len(attack),'runs':len(ar),
            'novelty_window_recall':proportion(sum(p['novelty_anomalous'] for p in attack),len(attack)),
            'novelty_run_recall':proportion(sum(r['any_novelty_anomaly'] for r in ar),len(ar)),
            'strict_end_to_end_recall':proportion(sum(p['strict_end_to_end'] for p in attack),len(attack)),
            'strict_run_detection':proportion(sum(r['strict_detected'] for r in ar),len(ar)),
            'classifier_correct_runs':proportion(sum(r['xgb_run_correct'] for r in ar),len(ar)),
            'production_run_recall':proportion(sum(r['production_alerted'] for r in ar),len(ar)),
            'production_alert_episodes':sum(r['production_alert_episodes'] for r in ar),
            'production_detected_windows':proportion(sum(p['reconciliation']['decision'] not in ('BENIGN','UNCERTAIN') for p in attack),len(attack))},
        'per_class':per_class,'run_rows':runs}


def classifier_metrics(rows, guesses, classes):
    def report(selected):
        actual = [rows[i]['label'] for i in selected]; predicted = [guesses[i] for i in selected]
        labels = sorted(set(actual))
        return {'support':len(actual),'correct':sum(a==b for a,b in zip(actual,predicted)),
            'accuracy':float(accuracy_score(actual,predicted)),
            'macro_F1':float(f1_score(actual,predicted,labels=labels,average='macro',zero_division=0)),
            'per_class':classification_report(actual,predicted,labels=classes,output_dict=True,zero_division=0),
            'macro_labels':labels,'confusion_matrix':confusion_matrix(actual,predicted,labels=classes).tolist()}
    return {'class_order':classes,'all_evaluation':report(list(range(len(rows)))),
        'attack_only':report([i for i,r in enumerate(rows) if r['label']!='BENIGN']),
        'semantics':'One shared classifier invocation; all-evaluation macro F1 over eight supported classes, attack-only macro F1 over seven supported true classes. Per-class table includes BENIGN predicted misses.'}


def replacement_gate(baseline,candidate):
    b,a = baseline,candidate
    return {'lower_benign_window_fpr':a['benign']['window_fpr']['count'] < b['benign']['window_fpr']['count'],
        'no_more_false_incident_sessions':a['benign']['false_incident_sessions']['count'] <= b['benign']['false_incident_sessions']['count'],
        'no_lower_attack_run_detection':a['attack']['strict_run_detection']['count'] >= b['attack']['strict_run_detection']['count'] and a['attack']['production_run_recall']['count'] >= b['attack']['production_run_recall']['count'],
        'no_lower_attack_window_recall':a['attack']['novelty_window_recall']['count'] >= b['attack']['novelty_window_recall']['count'],
        'no_lower_end_to_end_known_performance':a['attack']['strict_end_to_end_recall']['count'] >= b['attack']['strict_end_to_end_recall']['count'] and a['classifier_metrics_sha256']==b['classifier_metrics_sha256']}


def select(results):
    gates = {p:replacement_gate(results['A'],results[p]) for p in ('B','C')}
    eligible = [p for p,g in gates.items() if all(g.values())]
    if not eligible: selected = 'A'
    else:
        selected = min(eligible,key=lambda p:(results[p]['benign']['false_incident_sessions']['count'],
            results[p]['benign']['window_fpr']['count'],-results[p]['attack']['strict_run_detection']['count'],
            -results[p]['attack']['strict_end_to_end_recall']['count'],-results[p]['attack']['novelty_window_recall']['count'],
            0 if p=='C' else 1))
    return {'decision':{'A':'KEEP_OCSVM','B':'REPLACEMENT_RECOMMENDED_LOF','C':'REPLACEMENT_RECOMMENDED_ISOLATION_FOREST'}[selected],
        'selected_pipeline':selected,'gates':gates,'eligible_alternatives':eligible,
        'accepted_package_replaced':False,'no_significance_claim':True}


def write_csv(path, rows):
    if not rows: return
    with Path(path).open('w',newline='') as stream:
        writer = csv.DictWriter(stream,fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)


def cost(estimator,scaled,repetitions):
    estimator.score_samples(scaled[:1])
    timings = []
    for _ in range(repetitions):
        for row in scaled:
            start=time.perf_counter(); estimator.score_samples(row.reshape(1,-1))
            timings.append((time.perf_counter()-start)*1000)
    return {'warm_per_window_ms':{'count':len(timings),'mean':float(np.mean(timings)),
        'median':float(np.median(timings)),'p95':float(np.percentile(timings,95)),'max':max(timings)},
        'serialized_estimator_bytes':len(pickle.dumps(estimator,protocol=5)),
        'semantics':'Single-window score_samples on pre-scaled inputs, warm estimator; shared scaling and XGBoost excluded. Not end-to-end detection latency.'}


def execute(out, root=ROOT):
    out=Path(out);root=Path(root);disk_guard(root)
    config=read(out/'benchmark_config.json');check_protocol(config,root)
    marker=out/'execution_started.json'
    with marker.open('x') as stream:
        json.dump({'config_sha256':config['sha256'],'started_at_utc':datetime.now(timezone.utc).isoformat()},stream)
    package=load(root/ACCEPTED);dataset,_=development(root,package)
    train=[r for r in dataset['rows'] if r['partition']=='TRAIN' and r['label']=='BENIGN']
    validation=[r for r in dataset['rows'] if r['partition']=='VALIDATION']
    scaler=package.models['OCSVM']['scaler'];scaled_val=scaler.transform(matrix(validation,package.feature_schema))
    preprocessing=read(root/ACCEPTED/'preprocessing.json')
    if not np.array_equal(scaler.center_,preprocessing['center']) or not np.array_equal(scaler.scale_,preprocessing['scale']):
        raise ValueError('Saved scaler does not match accepted preprocessing')
    for fitted in package.models.values():
        if not np.array_equal(fitted['scaler'].center_,scaler.center_) or not np.array_equal(fitted['scaler'].scale_,scaler.scale_):
            raise ValueError('Detector preprocessing differs')
    estimators={'A':package.models['OCSVM']['model']};fit_ms={'A':None};reproduced={}
    for identity,name in [('B','LOF'),('C','IF')]:
        estimators[identity],fit_ms[identity]=fit_alternative(name,train,package)
        # LOF is evaluated only on unseen VALIDATION/holdout, never on fit samples.
        a=estimators[identity].score_samples(scaled_val);b=package.models[name]['model'].score_samples(scaled_val)
        reproduced[identity]=float(np.max(abs(a-b)))
        if not np.allclose(a,b,rtol=0,atol=1e-12): raise ValueError('Historical alternative did not reproduce')
        joblib.dump(estimators[identity],out/(name.lower()+'.joblib'),compress=3)
    write(out/'detectors_frozen_before_evaluation.json',{'config_sha256':config['sha256'],
        'artifact_sha256':{n:sha(out/n) for n in ('lof.joblib','if.joblib')},'validation_reproduction_max_error':reproduced,
        'thresholds':{p:v['threshold'] for p,v in config['pipelines'].items()},'holdout_loaded':False,
        'fit_input_window_ids':[window_id(r) for r in train],'fit_input_matrix_sha256':digest(matrix(train,package.feature_schema).tolist())})
    data,saved=load_evaluation(root,package,config)
    receipt=split_receipt(dataset['rows'],data,package);write(out/'split_receipt.json',receipt)
    raw=matrix(data,package.feature_schema);scaled=scaler.transform(raw)
    vectors=package.classifier.predict_proba(raw);indices=vectors.argmax(axis=1)
    guesses=[package.classes[int(i)] for i in indices];confidences=vectors[np.arange(len(data)),indices]
    if guesses != [p['xgb_label'] for p in saved] or not np.allclose(vectors,[p['xgb_scores'] for p in saved],rtol=1e-6,atol=1e-7):
        raise ValueError('Fixed classifier failed saved replay reproduction')
    classifier=classifier_metrics(data,guesses,package.classes);write(out/'confusion_matrix.json',classifier)
    results={};windows=[];runs=[];class_rows=[];by_pipeline={}
    for identity,name in PIPELINES.items():
        scores=estimators[identity].score_samples(scaled);cut=config['pipelines'][identity]['threshold']
        predictions=make_predictions(data,scores,cut,guesses,confidences,config['confidence_threshold'])
        by_pipeline[identity]=predictions
        if identity=='A':
            if [p['novelty_anomalous'] for p in predictions] != [p['novelty_anomalous'] for p in saved]:
                raise ValueError('Accepted OCSVM verdicts changed')
            if not np.allclose(scores,[p['novelty_score'] for p in saved],rtol=0,atol=1e-12):
                raise ValueError('Accepted OCSVM scores changed')
            if [p['reconciliation']['decision'] for p in predictions] != [p['reconciliation']['decision'] for p in saved]:
                raise ValueError('Accepted reconciliation changed')
        result=summarize(predictions,config['persistence'])
        result.update(detector=name,threshold=cut,parameters=config['pipelines'][identity]['parameters'],
            classifier_sha256=config['pipelines'][identity]['classifier_sha256'],classifier_metrics_sha256=digest(classifier),
            input_window_ids_sha256=digest([r['record_id'] for r in data]),
            fit_time_ms=fit_ms[identity],fit_time_semantics='Not recorded; accepted model never refit' if identity=='A' else 'One historical-configuration BENIGN TRAIN fit including shared-scaler transform',
            cost=cost(estimators[identity],scaled,config['warm_inference_repetitions']))
        if identity!='A': result['cost']['benchmark_artifact_sha256']=sha(out/(name.lower()+'.joblib'))
        results[identity]=result
        runs.extend(dict(pipeline=identity,**r) for r in result.pop('run_rows'))
        for p in predictions:
            windows.append({'pipeline':identity,'detector':name,'window_id':p['record_id'],'run_id':p['run_id'],
                'partition':p['partition'],'true_class':p['label'],'window_start':p['window_start'],'window_end':p['window_end'],
                'novelty_score':p['novelty_score'],'threshold':cut,'novelty_anomalous':p['novelty_anomalous'],
                'xgb_label':p['xgb_label'],'xgb_uncalibrated_score':p['xgb_confidence'],'strict_end_to_end':p['strict_end_to_end'],
                'reconciled_label':p['reconciliation']['decision'],'model_disagreement':p['reconciliation']['model_disagreement']})
        for label,c in result['per_class'].items():
            class_rows.append({'pipeline':identity,'class':label,'windows':c['windows'],'runs':c['runs'],
                'novelty_detected':c['novelty']['count'],'novelty_recall':c['novelty']['rate'],
                'strict_correct':c['strict_end_to_end']['count'],'strict_recall':c['strict_end_to_end']['rate'],
                'novelty_runs_detected':c['novelty_runs']['count'],'strict_runs_detected':c['strict_runs']['count'],
                'production_runs_alerted':c['production_runs']['count'],
                'xgb_precision':classifier['all_evaluation']['per_class'][label]['precision'],
                'xgb_recall':classifier['all_evaluation']['per_class'][label]['recall'],
                'xgb_F1':classifier['all_evaluation']['per_class'][label]['f1-score']})
    decision=select(results);decision['protocol_sha256']=config['sha256']
    attack_sets={p:{r['record_id'] for r in ps if r['label']!='BENIGN' and r['novelty_anomalous']} for p,ps in by_pipeline.items()}
    benign_sets={p:{r['record_id'] for r in ps if r['label']=='BENIGN' and r['novelty_anomalous']} for p,ps in by_pipeline.items()}
    disagreements={'attack_novelty_detected_by_all':sorted(set.intersection(*attack_sets.values())),
        'OCSVM_not_LOF':sorted(attack_sets['A']-attack_sets['B']),'OCSVM_not_IF':sorted(attack_sets['A']-attack_sets['C']),
        'LOF_not_OCSVM':sorted(attack_sets['B']-attack_sets['A']),'IF_not_OCSVM':sorted(attack_sets['C']-attack_sets['A']),
        'benign_fp_windows':{p:sorted(s) for p,s in benign_sets.items()},
        'benign_fp_overlap_all':sorted(set.intersection(*benign_sets.values()))}
    write(out/'pipeline_results.json',{'protocol_sha256':config['sha256'],'pipelines':results,'classifier':classifier,
        'paired_disagreements':disagreements,'shared_input_window_ids_sha256':digest([r['record_id'] for r in data]),
        'novelty_score_semantics':'Detector-specific score_samples; larger is more normal; score < frozen detector-specific threshold is anomalous. Scores are not probabilities and cannot be compared numerically between detectors.'})
    write(out/'selection_decision.json',decision)
    write_csv(out/'window_results.csv',windows);write_csv(out/'run_results.csv',runs);write_csv(out/'class_metrics.csv',class_rows)
    check_protocol(config,root);disk_guard(root)
    write(out/'execution_completed.json',{'completed_at_utc':datetime.now(timezone.utc).isoformat(),
        'decision':decision['decision'],'alternative_fit_calls':2,'OCSVM_fit_calls':0,'XGBoost_fit_calls':0,
        'scaler_fit_calls':0,'calibration_calls':0,'accepted_predictions_reproduced':True,'new_traffic_requests':0,
        'input_hashes_verified_after':True,'accepted_package_root_after':verify(root/ACCEPTED)['root_sha256'],
        'runtime':{n:importlib.metadata.version(n) for n in ('numpy','scipy','scikit-learn','xgboost','joblib')},
        'python':platform.python_version(),'platform':platform.platform()})
    render_report(out,config,results,decision,disagreements,classifier)
    return results,decision


def fmt(p):
    return f"{p['count']}/{p['total']} = {100*p['rate']:.2f}%" if p['rate'] is not None else 'not available'


def render_report(out,config,results,decision,disagreements,classifier):
    lines=['# Controlled three-pipeline Behavioral benchmark','',
        'Research question: can LOF or IF reduce benign false positives without losing attack sensitivity relative to accepted OCSVM?',
        '', 'One classifier, one 83-feature schema/scaler, identical run/window partitions, frozen cutoffs and persistence. No new calibration or search.',
        '', 'Strict AND metrics are intentionally stricter than production reconciliation. Confident known classes can alert with normal novelty in production.',
        '', '| Metric | A OCSVM | B LOF | C IF |','|---|---:|---:|---:|']
    for title,path in [('Benign window FPR',('benign','window_fpr')),('Benign any-anomaly runs',('benign','raw_anomalous_runs')),
        ('Benign incident sessions',('benign','false_incident_sessions')),('Novelty attack windows',('attack','novelty_window_recall')),
        ('Novelty attack runs',('attack','novelty_run_recall')),('Strict AND correct attack windows',('attack','strict_end_to_end_recall')),
        ('Strict AND detected runs',('attack','strict_run_detection')),('Production alerted attack runs',('attack','production_run_recall'))]:
        lines.append('| '+title+' | '+' | '.join(fmt(results[p][path[0]][path[1]]) for p in PIPELINES)+' |')
    lines+=['', '## Per-class support and recall', '', '| Class | Windows | A anomaly / strict | B anomaly / strict | C anomaly / strict |', '|---|---:|---|---|---|']
    for label in results['A']['per_class']:
        lines.append('| '+label+' | '+str(results['A']['per_class'][label]['windows'])+' | '+' | '.join(
            fmt(results[p]['per_class'][label]['novelty'])+' / '+fmt(results[p]['per_class'][label]['strict_end_to_end']) for p in PIPELINES)+' |')
    lines+=['', '## Shared classifier', '', f"Combined accuracy {classifier['all_evaluation']['accuracy']:.6f}; macro-F1 {classifier['all_evaluation']['macro_F1']:.6f}.",
        f"Attack-only accuracy {classifier['attack_only']['accuracy']:.6f}; seven-supported-class macro-F1 {classifier['attack_only']['macro_F1']:.6f}.",
        'All pipelines reference the same classifier metric hash and artifact. Scores are uncalibrated. See confusion_matrix.json.',
        '', '## Gate and decision', '', decision['decision'], '', '```json', json.dumps(decision,indent=2), '```',
        '', '## Paired disagreements (counts)', '', '```json',json.dumps({k:({p:len(s) for p,s in v.items()} if isinstance(v,dict) else len(v)) for k,v in disagreements.items()},indent=2),'```',
        '', '## Runtime cost', '', '| Pipeline | Fit ms | Warm window mean ms | Median ms | p95 ms | Serialized estimator bytes |', '|---|---:|---:|---:|---:|---:|']
    for p,r in results.items():
        t=r['cost']['warm_per_window_ms'];lines.append(f"| {p} {r['detector']} | {r['fit_time_ms'] if r['fit_time_ms'] is not None else 'not recorded; no refit'} | {t['mean']:.5f} | {t['median']:.5f} | {t['p95']:.5f} | {r['cost']['serialized_estimator_bytes']} |")
    lines+=['', '## Limitations', '',
        '- This reuses previously opened accepted holdouts; it is not an additional fresh blind validation.',
        '- Six benign sessions and two attack runs/class are limited support; windows within runs are correlated.',
        '- Wilson 95% intervals are stored for key proportions. Window-level intervals assume independent trials and are descriptive, not a population-significance claim.',
        '- Different detector scores are not comparable probabilities. Classifier scores are uncalibrated.',
        '- SQLI/XSS/PATH labels describe attempt patterns; Apache logs cannot establish successful exploitation or expose POST bodies.',
        '- Unchanged production reconciliation can mask novelty misses through confident known-class decisions; strict AND and novelty-only metrics are therefore separately reported.',
        '- Accepted OCSVM fit time was not recorded; no baseline refit is performed for timing.',
        '- No accepted package, Task 2A, Branch 1, UI, Fusion or CQI change is made.',
        '', 'Methods: [LOF unseen-data semantics](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html); [Wilson interval implementation](https://docs.scipy.org/doc/scipy-1.16.1/reference/generated/scipy.stats._result_classes.BinomTestResult.proportion_ci.html).']
    Path(out/'report.md').write_text('\n'.join(lines)+'\n')
