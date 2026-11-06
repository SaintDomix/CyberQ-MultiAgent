"""Development-only fitting and a fail-closed freeze/release boundary."""
from collections import Counter,defaultdict
from datetime import datetime,timezone
import hashlib
import io
import json
from pathlib import Path
import time
import platform
from importlib.metadata import version
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler
from xgboost import XGBClassifier
from branch2.models import IF_CONFIG,XGB_CONFIG
from branch2.dataset import CLASSES
from branch2.final_pipeline import binary,multiclass
from branch2.artifacts import load as load_v1
from branch2.adapters.apache import read_log
from .platforms import MoodleBehaviorAdapter
from .features31 import schema,extract,matrix,query_context
from .inference import robust_reference
from .model31 import Package31,load
from .calibration import threshold
from .episodes import episodes,episode_metrics
from .browser_capture import validate_plan,digest,validate_capture_attribution
from .data import write,sha
from .development_review import require_development_review


def verify_freeze(path):
    path=Path(path);freeze=json.loads(path.read_text())
    if freeze.get('version') not in ('m5-final-day-freeze-1.0','m5-final-day-freeze-1.1'):raise ValueError('Missing freeze')
    if freeze['version']=='m5-final-day-freeze-1.1':
        if freeze.get('root_sha256')!=digest({k:v for k,v in freeze.items() if k!='root_sha256'}):raise ValueError('Freeze root hash mismatch')
        base=(path.parent/freeze.get('artifact_location','.')).resolve()
        if not base.is_relative_to(path.parent.resolve()):raise ValueError('Unsafe freeze artifact location')
        actual={str(p.relative_to(base)) for p in base.rglob('*') if p.is_file() and p!=base/'freeze_manifest.json'}
        if actual!=set(freeze['artifact_files_sha256']):raise ValueError('Frozen artifact membership changed')
        for name,expected in freeze['artifact_files_sha256'].items():
            file=(base/name).resolve()
            if not file.is_relative_to(base) or sha(file)!=expected:raise ValueError('Frozen artifact changed')
    package=(path.parent/freeze.get('package_location','v2_final_candidate')).resolve()
    if not package.is_relative_to(path.parent.resolve()):raise ValueError('Unsafe frozen package location')
    if sha(package/'package_manifest.json')!=freeze['package_manifest_sha256']:raise ValueError('Frozen package changed')
    for name,digest_value in freeze['code_sha256'].items():
        if sha(Path(__file__).resolve().parents[2]/name)!=digest_value:raise ValueError('Frozen inference implementation changed')
    restored=load(package)
    if restored.feature_schema['sha256']!=freeze['schema_sha256']:raise ValueError('Frozen schema changed')
    return freeze,restored


def load_browser_session(root,s,plan):
    base=Path(root)/'browser_sessions'/s['session_id'];manifest=json.loads((base/'manifest.json').read_text())
    if manifest.get('status')!='COMPLETE' or manifest.get('label')!='BENIGN' or manifest['plan_sha256']!=plan['sha256']:
        raise ValueError('Unverified/invalid browser protocol')
    if manifest['partition']!=s['partition'] or manifest['protocol']!=s['protocol'] or manifest['session_id']!=s['session_id']:
        raise ValueError('Reserved session membership changed')
    provenance=manifest['provenance']
    if provenance['malformed_records'] or provenance.get('outside_capture_time_records',0):
        raise ValueError('Contaminated capture cannot be labelled BENIGN')
    if manifest.get('version')=='m5-browser-capture-1.1' or provenance['foreign_records']:
        validate_capture_attribution(provenance,s['session_id'],manifest.get('actor_id'))
        if manifest.get('authenticated_identity_verified') is not True:
            raise ValueError('Authenticated browser identity was not verified')
    for filename,key in (('features.json','features_sha256'),('v1_features.json','v1_features_sha256')):
        if sha(base/filename)!=manifest[key]:raise ValueError('Captured feature hash mismatch')
    rows=json.loads((base/'features.json').read_text());old=json.loads((base/'v1_features.json').read_text())
    if not rows or len(rows)!=manifest['windows'] or len(old)!=len(rows):raise ValueError('Incomplete capture')
    if any(r['run_id']!=s['session_id'] or r['partition']!=s['partition'] or r['label']!='BENIGN' for r in rows):
        raise ValueError('Captured feature partition changed')
    return rows,old,manifest


def build_development(root,v1_dataset,v1_split,project):
    root=Path(root);plan=validate_plan(json.loads((root/'predeclared_capture_plan.json').read_text()))
    review=require_development_review(root,plan)
    included={s['session_id'] for s in review['included_browser_sessions']}
    adapter=MoodleBehaviorAdapter();feature_schema=schema(adapter);rows=[];sources={};cache={}
    train_ids=set(v1_split['train_runs']);val_ids=set(v1_split['validation_runs'])
    if train_ids&val_ids:raise ValueError('Historical run leakage')
    # Historical TEST remains available only as retrospective evidence; it does
    # not enter the new fitting/selection table. Fresh TEST files are not opened.
    for r in v1_dataset['rows']:
        if r['run_id'] not in train_ids|val_ids:continue
        if r['run_id'].startswith('TEST-'):raise ValueError('Smoke test leaked')
        name=r['source_file']
        if name not in cache:
            events,errors,filehash=read_log(Path(project)/name,name)
            if errors or filehash!=r['source_sha256']:raise ValueError('Historical capture hash mismatch')
            cache[name]={e.line_number:e for e in events};sources[name]=filehash
        es=[cache[name][n] for n in r['line_numbers']]
        rows.append({**r,'partition':'TRAIN' if r['run_id'] in train_ids else 'VALIDATION',
            'features':extract(es,adapter),'schema_sha256':feature_schema['sha256'],'feature_schema_version':feature_schema['version'],
            'query_context':query_context(es,adapter)})
    capture_manifest_hashes={};intervals=[];observations=set()
    for s in plan['sessions']:
        if s['partition']=='TEST' or s['session_id'] not in included:continue
        new,old,manifest=load_browser_session(root,s,plan)
        rows.extend(new);capture_manifest_hashes[s['session_id']]=sha(root/'browser_sessions'/s['session_id']/'manifest.json')
        p=manifest['provenance'];a,b=p['offset_start'],p['offset_end'];identity=(p['source_device'],p['source_inode'])
        if any(identity==k and a<d and c<b for k,c,d in intervals):raise ValueError('Browser source-range overlap')
        intervals.append((identity,a,b))
        for item in p['source_byte_ranges']:
            key=(*identity,item['start'],item['end'],item['sha256'])
            if key in observations:raise ValueError('Shared browser source observation')
            observations.add(key)
    matrix(rows,feature_schema)
    ids={p:{r['run_id'] for r in rows if r['partition']==p} for p in ('TRAIN','VALIDATION')}
    if ids['TRAIN']&ids['VALIDATION']:raise ValueError('Session leakage')
    if any(r['label'] not in CLASSES or r['run_id'].startswith('live-') for r in rows):raise ValueError('External/unknown-label data leaked')
    reserved=[s['session_id'] for s in plan['sessions'] if s['partition']=='TEST']
    if set(reserved)&(ids['TRAIN']|ids['VALIDATION']):raise ValueError('Fresh TEST leaked')
    grouped=defaultdict(list);observed={};hash_runs={}
    for row in rows:
        grouped[row['run_id']].append(row)
        for line in row['line_numbers']:
            key=(row['source_file'],row['source_sha256'],line)
            if key in observed:raise ValueError('Duplicated source observation in development')
            observed[key]=row['run_id']
        source=row['source_sha256']
        if source in hash_runs and hash_runs[source]!=row['run_id']:
            raise ValueError('Shared capture hash across development runs')
        hash_runs[source]=row['run_id']
    runs=[]
    for rid,rs in sorted(grouped.items()):
        if len({r['partition'] for r in rs})!=1 or len({r['label'] for r in rs})!=1:
            raise ValueError('Run label/partition inconsistency')
        r=rs[0];browser=rid in included
        runs.append({'run_id':rid,'partition':r['partition'],'class':r['label'],'windows':len(rs),
            'source_type':'BROWSER_CAPTURE' if browser else 'HISTORICAL_CAPTURE',
            'source_file':r['source_file'],'source_sha256':r['source_sha256'],
            'provenance_reference':'browser_sessions/'+rid+'/manifest.json' if browser else r['source_file']})
    counts={part:{'runs':len(ids[part]),'windows':sum(r['partition']==part for r in rows),
        'class_runs':dict(Counter(r['class'] for r in runs if r['partition']==part)),
        'class_windows':dict(Counter(r['label'] for r in rows if r['partition']==part))}
        for part in ('TRAIN','VALIDATION')}
    manifest={'dataset_version':'dataset-v3.1','feature_schema_version':feature_schema['version'],
        'feature_schema_sha256':feature_schema['sha256'],'adapter':feature_schema['adapter'],
        'runs':runs,'counts':counts,'development_review_sha256':review['sha256'],
        'excluded_sources':review['excluded_browser_sessions']+[
            {'source_type':'HISTORICAL_TEST','run_ids':sorted(v1_split['test_runs']),'reason':'TEST excluded from development'},
            {'source_type':'EXTERNAL_DIAGNOSTIC_AND_FRESH_HOLDOUT','reason':'Not development data; not opened'}],
        'checks':{'run_partition_overlap':False,'duplicate_source_observations':False,
            'shared_capture_hashes':False,'browser_capture_interval_overlap':False,
            'fresh_test_opened':False,'historical_test_used':False,'external_diagnostics_used':False}}
    manifest['sha256']=digest(manifest)
    return {'dataset_version':'dataset-v3.1','feature_schema':feature_schema,'rows':rows,'sources':sources,
        'development_review_sha256':review['sha256'],'development_manifest':manifest,
        'capture_plan_sha256':plan['sha256'],'capture_manifest_sha256':capture_manifest_hashes,
        'split_manifest':{'train_runs':sorted(ids['TRAIN']),'validation_runs':sorted(ids['VALIDATION']),
            'fresh_test_reserved_ids':sorted(reserved),'historical_reused_test_not_used':v1_split['test_runs'],
            'external_20261009_used_for_fit':False,'fresh_test_files_opened':False},
        'qa':{'runs':len(ids['TRAIN']|ids['VALIDATION']),'windows':len(rows),'feature_count':len(feature_schema['feature_order']),
            'class_run_counts':dict(Counter(next(r['label'] for r in rows if r['run_id']==rid) for rid in ids['TRAIN']|ids['VALIDATION']))}}


def report_predictions(predictions,persistence,classes):
    truth=[p['label'] for p in predictions];es=episodes(predictions,persistence)
    sessions=sorted({p['run_id'] for p in predictions})
    benign={p['run_id'] for p in predictions if p['label']=='BENIGN'}
    def observation(p):
        if p.get('model_observation'):return p['model_observation']
        if p['reconciliation']['model_disagreement']:return 'MODEL_DISAGREEMENT'
        if p['reconciliation']['decision'] not in ('BENIGN','UNCERTAIN','UNKNOWN_ANOMALY'):return 'KNOWN_PATTERN'
        return 'NOVEL_OBSERVATION' if p['if_anomalous'] else 'NORMAL'
    return {'window_count':len(predictions),'session_count':len(sessions),
        'observation_counts':dict(Counter(observation(p) for p in predictions)),
        'benign_windows':sum(p['reconciliation']['decision']=='BENIGN' for p in predictions),
        'unknown_observation_windows':sum(p['reconciliation']['decision']=='UNKNOWN_ANOMALY' for p in predictions),
        'known_pattern_windows':sum(p['reconciliation']['decision'] not in ('BENIGN','UNCERTAIN','UNKNOWN_ANOMALY') for p in predictions),
        'reconciliation_counts':dict(Counter(p['reconciliation']['decision'] for p in predictions)),
        'model_disagreements':sum(p['reconciliation']['model_disagreement'] for p in predictions),
        'novelty_binary':binary([c!='BENIGN' for c in truth],[p['if_anomalous'] for p in predictions]),
        'xgboost':multiclass(truth,[p['xgb_label'] for p in predictions],classes),
        'reconciled':multiclass(truth,[p['reconciliation']['decision'] for p in predictions],classes),
        'episode_any_alert_by_run':episode_metrics(predictions,persistence),
        'false_security_episodes':sum(e['alert'] and e['run_id'] in benign for e in es),
        'false_alert_episodes_per_benign_session':sum(e['alert'] and e['run_id'] in benign for e in es)/len(benign) if benign else None,
        'observed_benign_session_false_alert_rate':sum(any(e['alert'] and e['run_id']==r for e in es) for r in benign)/len(benign) if benign else None,
        'false_alert_window_seconds':sum((datetime.fromisoformat(e['end'])-datetime.fromisoformat(e['start'])).total_seconds() for e in es if e['alert'] and e['run_id'] in benign),
        'observed_false_alert_state_wall_seconds':None,
        'state_time_unavailable_reason':'Offline evaluation has no observed live alert-on/off timestamps; window coverage is a retrospective proxy.',
        'unknown_persistence_additional_window_delay_seconds':10*(persistence-1),
        'time_semantics':'covered nonempty fixed-window duration, not measured incident onset or population FPR',
        'episodes':es,'successful_exploitation_confirmed':False}


def validation_run_metrics(predictions,classes):
    groups=defaultdict(list)
    for p in predictions:groups[p['run_id']].append(p)
    truth=[];guesses=[];runs=[]
    for rid,rows in sorted(groups.items()):
        rows=sorted(rows,key=lambda r:(r['window_start'],r.get('window_end',''),r.get('client_id') or '',tuple(r['xgb_scores'])))
        labels={r['label'] for r in rows}
        if len(labels)!=1:raise ValueError('Inconsistent run label')
        scores=np.mean([r['xgb_scores'] for r in rows],axis=0)
        guess=classes[int(np.argmax(scores))];label=next(iter(labels))
        truth.append(label);guesses.append(guess)
        runs.append({'run_id':rid,'label':label,'windows':len(rows),'xgb_label':guess,'mean_uncalibrated_scores':scores.tolist()})
    ordered=[groups[rid] for rid in sorted(groups)]
    return {'xgboost':multiclass(truth,guesses,classes),'runs':runs,
        'aggregation':'Mean uncalibrated class-score vector per complete run; argmax; sorted class order breaks ties',
        'novelty_any_window':binary([g[0]['label']!='BENIGN' for g in ordered],
            [any(p['novelty_anomalous'] for p in g) for g in ordered])}


def train_freeze(dataset,root,out):
    root=Path(root);out=Path(out)
    if out.exists():raise ValueError('Refuse overwrite or post-test retuning in existing study')
    plan=validate_plan(json.loads((root/'predeclared_capture_plan.json').read_text()))
    review=require_development_review(root,plan)
    if dataset.get('development_review_sha256')!=review['sha256']:raise ValueError('Dataset review binding mismatch')
    if plan['sha256']!=dataset['capture_plan_sha256']:raise ValueError('Development capture plan changed')
    expected={s['session_id'] for s in review['included_browser_sessions']}
    if set(dataset['capture_manifest_sha256'])!=expected:raise ValueError('All planned development browser sessions must be verified before fitting')
    for s in plan['sessions']:
        if s['partition']=='TEST' or s['session_id'] not in expected:continue
        if sha(root/'browser_sessions'/s['session_id']/'manifest.json')!=dataset['capture_manifest_sha256'][s['session_id']]:
            raise ValueError('Development capture manifest changed')
        recorded,_,_=load_browser_session(root,s,plan)
        selected=[r for r in dataset['rows'] if r['run_id']==s['session_id']]
        if recorded!=selected:raise ValueError('Development rows differ from captured session')
    train=[r for r in dataset['rows'] if r['partition']=='TRAIN'];val=[r for r in dataset['rows'] if r['partition']=='VALIDATION']
    if not train or not val or any(r['partition'] not in ('TRAIN','VALIDATION') for r in dataset['rows']):raise ValueError('TEST/external fit input forbidden')
    split=dataset['split_manifest'];train_ids={r['run_id'] for r in train};val_ids={r['run_id'] for r in val}
    if (train_ids|val_ids)&{s['session_id'] for s in review['excluded_browser_sessions']}:
        raise ValueError('Excluded INVALID session leaked into development')
    if train_ids&val_ids or train_ids!=set(split['train_runs']) or val_ids!=set(split['validation_runs']):raise ValueError('Complete-run split mismatch')
    if (train_ids|val_ids)&set(split['fresh_test_reserved_ids']) or any(rid.startswith(('TEST-','live-','M5-HUMAN-')) for rid in train_ids|val_ids):
        raise ValueError('TEST/external session leaked into development')
    if sorted(split['fresh_test_reserved_ids'])!=sorted(s['session_id'] for s in plan['sessions'] if s['partition']=='TEST'):
        raise ValueError('Fresh holdout reservations changed')
    grouped=defaultdict(list)
    for r in dataset['rows']:grouped[r['run_id']].append(r)
    for rid,rs in grouped.items():
        if len({r['label'] for r in rs})!=1:raise ValueError('Run has inconsistent labels')
        keys=[(r['window_start'],r['window_end'],r.get('client_id'),r.get('user_agent_id')) for r in rs]
        if len(keys)!=len(set(keys)):raise ValueError('Duplicated window in development')
    if set(r['label'] for r in train)!=set(CLASSES):raise ValueError('Eight TRAIN classes required')
    if set(r['label'] for r in val)!=set(CLASSES):raise ValueError('Eight VALIDATION classes required')
    benign=[r for r in train if r['label']=='BENIGN'];feature_schema=dataset['feature_schema']
    if len(benign)<10 or len({r['run_id'] for r in benign})<2:raise ValueError('Insufficient BENIGN TRAIN')
    x=matrix(benign,feature_schema);v=matrix(val,feature_schema);scaler=RobustScaler().fit(x);scaled=scaler.transform(x)
    out.mkdir(parents=True);write(out/'selection_protocol.json',{'capture_plan_sha256':dataset['capture_plan_sha256'],
        'fit':'TRAIN only; novelty/scaling/reference BENIGN TRAIN only','selection':'VALIDATION only; targets <=5% and realized benign FPR <=5%; max novelty attack recall; min benign episode run FPR; max attack episode run recall; shortest persistence; IF/OCSVM/LOF ties',
        'grid':{'FPR':[.01,.02,.05,.10],'persistence':[1,2,3]},'confidence_threshold':.8,'seed':42,
        'fresh_test_used':False,'historical_test_used':False,'old_external_used':False})
    models={
        'IF':{'model':IsolationForest(**IF_CONFIG,random_state=42).fit(scaled),'scaler':scaler},
        'OCSVM':{'model':OneClassSVM(kernel='rbf',nu=.1,gamma='scale').fit(scaled),'scaler':scaler},
        'LOF':{'model':LocalOutlierFactor(n_neighbors=min(20,len(x)-1),novelty=True,n_jobs=1).fit(scaled),'scaler':scaler}}
    classes=sorted(CLASSES);classifier=XGBClassifier(**XGB_CONFIG,random_state=42,num_class=8)
    classifier.fit(matrix(train,feature_schema),np.asarray([classes.index(r['label']) for r in train]))
    normality={n:f['model'].score_samples(f['scaler'].transform(v)) for n,f in models.items()}
    benign_val=np.asarray([r['label']=='BENIGN' for r in val])
    if not benign_val.any() or benign_val.all():raise ValueError('Validation benign and attacks required')
    cuts={n:threshold(s[benign_val],.05) for n,s in normality.items()}
    config={'selected_model':'IF','thresholds':cuts,'confidence_threshold':.8,'persistence':1,
        'schema_sha256':feature_schema['sha256'],'seed':42,'train_ids':sorted({r['run_id'] for r in train}),
        'benign_fit_ids':sorted({r['run_id'] for r in benign}),'validation_ids':sorted({r['run_id'] for r in val}),
        'fresh_test_used_for_selection':False,'inference_training_performed':False}
    package=Package31(models,classifier,classes,robust_reference(x),feature_schema,config)
    candidates=[]
    for name in ('IF','OCSVM','LOF'):
        for target in (.01,.02,.05,.10):
            cut=threshold(normality[name][benign_val],target)
            ps=package.predict(val,model=name,threshold=cut,explain=False)
            bm=binary(~benign_val,normality[name]<cut)
            for persistence in (1,2,3):
                em=episode_metrics(ps,persistence)
                candidates.append({'model':name,'target':target,'threshold':cut,'persistence':persistence,
                    'novelty_validation':bm,'episode_validation':em})
    eligible=[c for c in candidates if c['target']<=.05 and c['novelty_validation']['FPR']<=.05]
    chosen=max(eligible,key=lambda c:(c['novelty_validation']['recall'] or 0,-c['episode_validation']['FPR'],
        c['episode_validation']['recall'] or 0,-c['persistence'],-('IF','OCSVM','LOF').index(c['model']),-c['target']))
    # Each alternative receives its own validation-selected cutoff for fair reports.
    for name in models:
        best=max([c for c in eligible if c['model']==name],key=lambda c:(c['novelty_validation']['recall'] or 0,-c['novelty_validation']['FPR'],-c['target']))
        config['thresholds'][name]=best['threshold']
    config.update(selected_model=chosen['model'],persistence=chosen['persistence'])
    config['thresholds'][chosen['model']]=chosen['threshold']
    predictions=package.predict(val)
    comparison={}
    for name,fitted in models.items():
        ps=package.predict(val,model=name,explain=False)
        comparison[name]={'threshold':config['thresholds'][name],
            'parameters':fitted['model'].get_params(),
            'window':binary([p['label']!='BENIGN' for p in ps],[p['novelty_anomalous'] for p in ps]),
            'run_any_anomalous_window':validation_run_metrics(ps,classes)['novelty_any_window'],
            'run_semantics':'Any raw novelty-anomalous window; separate from reconciled alert episodes'}
    write(out/'validation_novelty_comparison.json',comparison)
    write(out/'validation_run_metrics.json',validation_run_metrics(predictions,classes))
    stability=[]
    if_target=min(c['target'] for c in eligible if c['model']=='IF' and c['threshold']==config['thresholds']['IF'])
    for seed in (42,43,44):
        forest=models['IF']['model'] if seed==42 else IsolationForest(**IF_CONFIG,random_state=seed).fit(scaled)
        raw=forest.score_samples(scaler.transform(v));cut=threshold(raw[benign_val],if_target)
        stability.append({'seed':seed,'validation_metrics':binary(~benign_val,raw<cut),
            'threshold':cut,'target_benign_FPR':if_target,'fit':'TRAIN BENIGN only','seed_used_for_final_model':seed==42})
    write(out/'validation_stability.json',{'IF':stability,'OCSVM_LOF':'deterministic estimators; no stochastic seed selection','TEST_used':False})
    costs={}
    for name,fitted in models.items():
        durations=[]
        for _ in range(10):
            start=time.perf_counter();fitted['model'].score_samples(fitted['scaler'].transform(v));durations.append((time.perf_counter()-start)*1000/len(val))
        buf=io.BytesIO();joblib.dump(fitted,buf)
        costs[name]={'median_validation_ms_per_window':float(np.median(durations)),'serialized_bytes':len(buf.getvalue()),
            'semantics':'ten warm validation batches; descriptive, not SLA or selection input'}
    write(out/'validation_runtime_cost.json',costs)
    write(out/'validation_tuning.json',{'candidates':candidates,'selected':chosen,'benign_validation_windows':int(benign_val.sum()),'resolution':1/int(benign_val.sum())})
    write(out/'validation_predictions.json',predictions)
    write(out/'validation_metrics.json',report_predictions(predictions,config['persistence'],classes))
    from .diagnostics import redundancy
    from .schema import FEATURES
    write(out/'feature_analysis_train_only.json',{**redundancy(train,FEATURES),
        'xgb_importance':dict(zip(FEATURES,map(float,classifier.feature_importances_))),
        'query_context_by_window':[{'run_id':r['run_id'],'window_start':r['window_start'],'context':r.get('query_context',{})} for r in train],
        'robust_benign_distribution':robust_reference(x),
        'decision':'retain 83 features; no TEST-driven pruning or additional lexical indicators'})
    write(out/'training_provenance.json',{'train_ids':config['train_ids'],'benign_fit_ids':config['benign_fit_ids'],
        'validation_ids':config['validation_ids'],'train_windows':len(train),'validation_windows':len(val),
        'benign_train_windows':len(benign),'sources':dataset['sources'],'capture_manifest_sha256':dataset['capture_manifest_sha256'],
        'schema':feature_schema,'IF_config':models['IF']['model'].get_params(),'XGB_config':{**XGB_CONFIG,'random_state':42,'num_class':8}})
    write(out/'development_dataset.json',dataset)
    write(out/'development_manifest.json',dataset.get('development_manifest',{}))
    write(out/'development_review.json',review)
    write(out/'preprocessing.json',{'fit':'BENIGN TRAIN only','transform':'RobustScaler for all novelty models; unscaled XGBoost',
        'center':scaler.center_.tolist(),'scale':scaler.scale_.tolist(),'parameters':scaler.get_params(),
        'benign_train_windows':len(benign),'benign_validation_windows':int(benign_val.sum()),
        'validation_attack_windows':int((~benign_val).sum())})
    package.save(out/'v2_final_candidate');replay=load(out/'v2_final_candidate').predict(val)
    if predictions!=replay:raise ValueError('No-retrain replay mismatch')
    write(out/'replay_consistency.json',{'matched':True,'windows':len(val),'fit_calls':0})
    project=Path(__file__).resolve().parents[2]
    code=sorted(Path(__file__).parent.glob('*.py'))+[project/'src/branch2/reconciliation.py',project/'src/branch2/features.py']
    limitations=['Limited browser BENIGN sample size; student role only',
        'Controlled laboratory runs are not independent real users',
        'Moodle validated; equal accuracy on other LMS platforms not demonstrated',
        'Apache combined logs omit POST bodies; URL-visible labels mean attempt/pattern, not exploitation',
        'Novelty scores and SHAP are not causal security explanations; XGBoost scores are uncalibrated',
        'Validation estimates used for selection are not held-out final-performance estimates',
        'No fresh TEST or fresh attack holdout evaluated; candidate not promoted']
    write(out/'limitations.json',limitations)
    freeze={'version':'m5-final-day-freeze-1.1','frozen_at_utc':datetime.now(timezone.utc).isoformat(),
        'package_manifest_sha256':sha(out/'v2_final_candidate/package_manifest.json'),
        'candidate_id':'m5-v3.1-'+sha(out/'v2_final_candidate/package_manifest.json')[:20],
        'development_dataset_sha256':sha(out/'development_dataset.json'),
        'development_manifest_sha256':sha(out/'development_manifest.json'),
        'development_review_sha256':review['sha256'],
        'schema_sha256':feature_schema['sha256'],'adapter':feature_schema['adapter'],'config':config,
        'runtime':{'python':platform.python_version(),'dependencies':{n:version(n) for n in ('numpy','scikit-learn','xgboost','shap','joblib')}},
        'limitations':limitations,'TEST_ACCESSED_BEFORE_FREEZE':False,'TEST_USED_FOR_SELECTION':False,
        'FRESH_ATTACK_HOLDOUT_USED_FOR_SELECTION':False,
        'capture_plan_sha256':dataset['capture_plan_sha256'],'reserved_fresh_test_ids':dataset['split_manifest']['fresh_test_reserved_ids'],
        'code_sha256':{str(p.relative_to(project)):sha(p) for p in code},
        'test_opened':False,'no_retuning_after_freeze':True}
    freeze['artifact_files_sha256']={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()}
    freeze['root_sha256']=digest(freeze)
    write(out/'freeze_manifest.json',freeze)
    # A write-once root pointer supports the requested one-path freeze gate.
    if out==root/'candidate_01':
        pointer={**freeze,'package_location':'candidate_01/v2_final_candidate','artifact_location':'candidate_01'}
        pointer['root_sha256']=digest({k:v for k,v in pointer.items() if k!='root_sha256'})
        write(root/'freeze_manifest.json',pointer)
    return freeze


def evaluate_fresh(root,freeze_path,out):
    root=Path(root);out=Path(out);freeze,package=verify_freeze(freeze_path)
    plan=validate_plan(json.loads((root/'predeclared_capture_plan.json').read_text()))
    if freeze['capture_plan_sha256']!=plan['sha256']:raise ValueError('Fresh test reservations changed')
    sessions=[s for s in plan['sessions'] if s['partition']=='TEST']
    if sorted(s['session_id'] for s in sessions)!=freeze['reserved_fresh_test_ids']:raise ValueError('Fresh TEST changed')
    # Validate every reserved session before opening a new evaluation directory.
    rows=[];v1rows=[]
    for session in sessions:
        new,old,manifest=load_browser_session(root,session,plan)
        if datetime.fromisoformat(manifest['provenance']['start_utc'])<=datetime.fromisoformat(freeze['frozen_at_utc']):
            raise ValueError('Fresh TEST capture predates model freeze')
        rows.extend(new);v1rows.extend(old)
    if any(r['run_id'] in package.config['train_ids']+package.config['validation_ids'] for r in rows):raise ValueError('Fresh holdout leakage')
    out.mkdir(parents=True,exist_ok=False)
    started=time.perf_counter();predictions=package.predict(rows);elapsed=time.perf_counter()-started
    v1=load_v1(Path(__file__).resolve().parents[2]/'outputs/branch2/m2c_final_01')
    old=v1.predict(v1rows);result={'evaluation':'FRESH_BENIGN_RESERVED_BROWSER_SESSIONS',
        'v1':report_predictions(old,1,v1.classes),'candidate':report_predictions(predictions,package.config['persistence'],package.classes),
        'freeze_sha256':sha(freeze_path),'fresh_test_used_for_selection':False,'population_FPR_claimed':False}
    write(out/'v1_predictions.json',old);write(out/'candidate_predictions.json',predictions);write(out/'metrics.json',result)
    write(out/'timing.json',{'candidate_batch_seconds_with_SHAP':elapsed,'windows':len(rows),
        'batch_mean_ms_per_window':elapsed*1000/len(rows),'post_window_emission_latency_ms':None,
        'semantics':'offline batch processing measurement; no live-emission latency claim'})
    return result
