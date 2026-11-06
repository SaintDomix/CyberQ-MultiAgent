"""M5 predeclared offline paired study; external inference follows policy freezing."""
from collections import Counter,defaultdict
from pathlib import Path
import json
import time
import joblib
import io
import numpy as np
from xgboost import XGBClassifier
from branch2.dataset import CLASSES
from branch2.models import XGB_CONFIG
from branch2.artifacts import load as load_v1
from branch2.features import schema as v1_schema
from branch2.final_pipeline import binary, multiclass, aggregate_runs, metrics as v1_metrics
from .schema import FEATURES, BASE, matrix
from .data import sha,write,new_dir,validate_partitions
from .calibration import fit_novelty,calibrate,scores,require
from .episodes import episodes,episode_metrics,select_persistence
from .inference import Package,load,robust_reference
from .diagnostics import redundancy

PROTOCOL={
    'version':'m5-paired-study-1.0','seed':42,'models':['IF','OCSVM','LOF'],
    'IF_seeds_for_stability':[42,43,44],
    'FPR_targets':[.01,.02,.05,.10],'operational_validation_FPR_ceiling':.05,
    'model_selection':'validation attack recall within <=5% observed benign window FPR; lower FPR; simpler IF, OCSVM, LOF on ties',
    'threshold_selection':'targets<=5%; max validation attack recall; min realized benign FPR; lower target',
    'persistence_grid':[1,2,3],'persistence_selection':'min validation benign any-alert run FPR; max attack run recall; shortest persistence',
    'confidence_threshold':.8,'confidence_calibrated':False,
    'split':'same accepted M2C seeded complete-run manifest, 50/16/16; reused TEST is paired reanalysis, not a new blind test',
    'external_use':'not fitting/calibration/policy selection; earlier diagnostic informed feature hypotheses, so not fully blind',
    'promotion':'no automatic promotion; inadequate realistic benign coverage => B TRADE-OFF / INCONCLUSIVE',
}


def summarize(predictions,classes,persistence):
    truth=[p['label'] for p in predictions]
    return {'novelty':binary([c!='BENIGN' for c in truth],[p['if_anomalous'] for p in predictions]),
        'xgboost':multiclass(truth,[p['xgb_label'] for p in predictions],classes),
        'reconciliation':multiclass(truth,[p['reconciliation']['decision'] for p in predictions],classes),
        'episode_any_alert_by_run':episode_metrics(predictions,persistence),
        'disagreement_count':sum(p['reconciliation']['model_disagreement'] for p in predictions),
        'decision_counts':dict(Counter(p['reconciliation']['decision'] for p in predictions))}


def run_predictions(predictions,package):
    grouped=defaultdict(list)
    for p in predictions:grouped[p['run_id']].append(p)
    result=[]
    from branch2.reconciliation import reconcile
    for rid,rows in sorted(grouped.items()):
        mean=np.mean([p['xgb_scores'] for p in rows],axis=0);k=int(mean.argmax())
        label=package.classes[k];normality=float(np.mean([p['normality_score'] for p in rows]));cut=rows[0]['threshold']
        result.append({'run_id':rid,'label':rows[0]['label'],'windows':len(rows),'normality_score':normality,
            'threshold':cut,'if_anomalous':normality<cut,'xgb_label':label,'xgb_confidence':float(mean[k]),
            'xgb_scores':mean.tolist(),'reconciliation':reconcile(normality<cut,label,float(mean[k]),package.config['confidence_threshold'])})
    return result


def run_metrics(predictions,package):
    ps=run_predictions(predictions,package);truth=[p['label'] for p in ps]
    return {'novelty':binary([c!='BENIGN' for c in truth],[p['if_anomalous'] for p in ps]),
        'xgboost':multiclass(truth,[p['xgb_label'] for p in ps],package.classes),
        'reconciliation':multiclass(truth,[p['reconciliation']['decision'] for p in ps],package.classes),
        'aggregation':'XGB mean uncalibrated vector; ties saved class order. Novelty mean raw normality score compared to selected window cutoff; run FPR is measured, not calibrated.',
        'predictions':ps}


def fit_classifier(train):
    require(train,'TRAIN')
    classes=sorted(CLASSES)
    if {r['label'] for r in train}!=set(classes):raise ValueError('Eight TRAIN classes required')
    classifier=XGBClassifier(**XGB_CONFIG,random_state=42,num_class=8)
    classifier.fit(matrix(train),np.asarray([classes.index(r['label']) for r in train]))
    return classifier,classes


def train_study(dataset,split,v1_dataset,v1_model,out):
    out=new_dir(out);write(out/'predeclared_protocol.json',PROTOCOL)
    train,val,test=validate_partitions(dataset,split)
    benign=[r for r in train if r['label']=='BENIGN']
    novelty={};tuning={}
    for name in PROTOCOL['models']:
        novelty[name]=fit_novelty(name,benign);tuning[name]=calibrate(novelty[name],val)
    selected=max(PROTOCOL['models'],key=lambda n:(tuning[n]['validation']['recall'] or 0,
        -tuning[n]['validation']['FPR'],-PROTOCOL['models'].index(n)))
    classifier,classes=fit_classifier(train)
    config={'version':PROTOCOL['version'],'schema_identity':dataset['feature_schema']['sha256'],
        'selected_model':selected,'thresholds':{n:t['threshold'] for n,t in tuning.items()},
        'confidence_threshold':.8,'confidence_calibrated':False,
        'fit_run_ids':sorted({r['run_id'] for r in train}),
        'benign_fit_run_ids':sorted({r['run_id'] for r in benign}),
        'validation_run_ids':sorted({r['run_id'] for r in val}),
        'frozen_test_run_ids':sorted({r['run_id'] for r in test}),
        'test_used_for_selection':False,'external_used_for_selection':False}
    package=Package(novelty,classifier,classes,robust_reference(matrix(benign)),config)
    validation_predictions=package.predict(val)
    policy=select_persistence(validation_predictions);config['persistence']=policy['persistence']
    write(out/'validation_selection.json',{'novelty':tuning,'selected_model':selected,'episode_policy':policy})
    write(out/'validation_predictions.json',validation_predictions)
    write(out/'split_manifest.json',split)
    write(out/'feature_analysis_train_only.json',{**redundancy(train,FEATURES),
        'xgboost_gain_importance':dict(zip(FEATURES,map(float,classifier.feature_importances_)))})
    # Candidate bytes and selection hash are sealed BEFORE TEST or EXTERNAL.
    package.save(out/'v2_candidate_01')
    write(out/'selection_freeze.json',{'phase':'SELECTION_COMPLETE_BEFORE_TEST_AND_EXTERNAL',
        'config_sha256':sha(out/'v2_candidate_01/config.json'),
        'protocol_sha256':sha(out/'predeclared_protocol.json'),
        'model_package_sha256':sha(out/'v2_candidate_01/package_manifest.json')})
    predictions=package.predict(test,explain=True)
    performance=summarize(predictions,classes,config['persistence'])
    comparisons={}
    for name in PROTOCOL['models']:
        ps=package.predict(test,model=name)
        buf=io.BytesIO();joblib.dump(novelty[name],buf)
        measurements=[]
        for _ in range(20):
            start=time.perf_counter();scores(novelty[name],test);measurements.append((time.perf_counter()-start)*1000/len(test))
        candidates=[]
        for c in tuning[name]['candidates']:
            cp=package.predict(test,model=name,threshold=c['threshold'])
            candidates.append({**c,'test_reporting_only':summarize(cp,classes,1),
                'unsupervised_only_episode_any_alert_by_run':episode_metrics([
                    {**p,'reconciliation':{**p['reconciliation'],'decision':'UNKNOWN_ANOMALY' if p['if_anomalous'] else 'BENIGN'}} for p in cp],1)})
        comparisons[name]={'validation_selection':tuning[name],'test':summarize(ps,classes,config['persistence']),
            'test_run_level':run_metrics(ps,package),'threshold_candidates':candidates,
            'model_size_bytes':len(buf.getvalue()),'normality_score_direction':'higher normal; strict < cutoff anomalous',
            'novelty_only_latency_ms_per_window_median':float(np.median(measurements)),
            'latency_measurement':'20 batches; warm local CPU; includes schema-source hash/matrix/scaler; excludes SHAP/XGB/artifact I/O; not SLA'}
    stability=[]
    for seed in PROTOCOL['IF_seeds_for_stability']:
        fitted=novelty['IF'] if seed==42 else fit_novelty('IF',benign,seed)
        calibrated=calibrate(fitted,val)
        test_scores=scores(fitted,test)
        stability.append({'seed':seed,'validation_selected':calibrated,
            'test_reporting_only':binary([r['label']!='BENIGN' for r in test],test_scores<calibrated['threshold'])})
    v1=load_v1(v1_model)
    oldtest=[r for r in v1_dataset['rows'] if r['run_id'] in split['test_runs']]
    oldpred=v1.predict(oldtest,explain=False)
    old_metrics=v1_metrics(oldpred,v1.classes)
    oldrun=v1_metrics(aggregate_runs(oldpred,v1.classes,v1.reconciliation['confidence_threshold']),v1.classes)
    # Same fitted IF trees; old-style training quantile threshold uses actual
    # accepted v1 contamination (0.15), not the inaccurately recalled 0.10.
    oldcut=float(np.percentile(scores(novelty['IF'],benign),100*v1.metadata['selected_contamination']))
    oldstyle=package.predict(test,model='IF',threshold=oldcut)
    calibrated_if=package.predict(test,model='IF')
    ablation={'V1_FROZEN_PACKAGE':{'window':old_metrics,'run':oldrun,'actual_contamination':v1.metadata['selected_contamination']},
        'V2_FEATURES_TRAIN_QUANTILE_OLD_STYLE':{'cutoff':oldcut,'contamination':v1.metadata['selected_contamination'],
            'window':summarize(oldstyle,classes,1)},
        'V2_FEATURES_CALIBRATED_IF':{'window':summarize(calibrated_if,classes,1)},
        'V2_SELECTED_WITH_EPISODE_POLICY':{'window':performance},
        'interpretation':'Paired observational ablation; semantic schema and scaling/threshold/policy differ; not causal attribution.'}
    replay=load(out/'v2_candidate_01').predict(test,explain=True)
    if replay!=predictions:raise ValueError('Saved-model replay mismatch')
    write(out/'test_predictions.json',predictions)
    write(out/'test_metrics.json',performance)
    write(out/'run_level_test_metrics.json',run_metrics(predictions,package))
    write(out/'unsupervised_comparison.json',comparisons)
    write(out/'seed_stability.json',stability)
    write(out/'ablation.json',ablation)
    write(out/'episode_policy_test_reporting.json',[{'persistence':n,'test':episode_metrics(predictions,n)} for n in (1,2,3)])
    write(out/'replay_consistency.json',{'predictions_identical':True,'fit_calls':0,'windows':len(test)})
    write(out/'explainability_qa.json',{'windows':len(predictions),'SHAP_available':sum(p['shap']['status']=='AVAILABLE' for p in predictions),
        'nonempty_SHAP':sum(bool(p['shap']['top_features']) for p in predictions),'causal':False})
    write(out/'training_provenance.json',{'protocol':PROTOCOL,'config':config,'if_config':novelty['IF']['model'].get_params(),
        'xgb_config':{**XGB_CONFIG,'random_state':42,'num_class':8},'benign_train_windows':len(benign),'train_windows':len(train),
        'validation_windows':len(val),'test_windows':len(test),'dataset_sources':dataset['sources'],
        'v1_package_manifest_sha256':sha(Path(v1_model)/'package_manifest.json'),
        'phase_order':['TRAIN_FIT','VALIDATION_SELECTION','PACKAGE_FROZEN','FROZEN_TEST_REPORTING','REPLAY'],
        'test_interpretation':'Reused accepted v1 TEST; paired reanalysis, not a new independent blind evaluation'})
    return package


def external_compare(rows,original_predictions,study,v1_model,out):
    """Inference only after sealed selection; deliberately no train/calibrate calls."""
    out=new_dir(out);study=Path(study)
    freeze=json.loads((study/'selection_freeze.json').read_text())
    if sha(study/'v2_candidate_01/config.json')!=freeze['config_sha256']:raise ValueError('Selection freeze changed')
    package=load(study/'v2_candidate_01');v2=package.predict(rows,explain=True)
    v1=load_v1(v1_model);oldrows=[]
    for row in rows:
        oldrows.append({**row,'features':{k:row['features'][k] for k in BASE},'schema_sha256':v1_schema()['sha256']})
    v1pred=v1.predict(oldrows,explain=False)
    if any(p['reconciliation']!=q['reconciliation'] or p['if_decision_function']!=q['if_decision_function'] for p,q in zip(v1pred,original_predictions)):
        raise ValueError('External accepted v1 replay mismatch')
    for p,row in zip(v1pred,rows):
        p.update(client_id=row['client_id'],user_agent_id=row['user_agent_id'],record_id=row['record_id'],sequence=row['sequence'])
    def describe(ps,persistence):
        es=episodes(ps,persistence);counts=Counter(p['reconciliation']['decision'] for p in ps)
        return {'windows':len(ps),'decisions':dict(counts),'decision_rates':{k:v/len(ps) for k,v in counts.items()},
            'anomalous_windows':sum(p['if_anomalous'] for p in ps),
            'alert_episodes':sum(e['alert'] for e in es),'episodes':es,
            'model_disagreements':sum(p['reconciliation']['model_disagreement'] for p in ps),
            'known_attempt_windows':sum(p['reconciliation']['decision'] not in ('BENIGN','UNKNOWN_ANOMALY','UNCERTAIN') for p in ps)}
    comparison={'classification':'B. V2 TRADE-OFF / INCONCLUSIVE',
        'reason':'Single diagnostic session influenced feature hypotheses; insufficient realistic browser benign training. No independent blind external replication or promotion.',
        'ground_truth':'OPERATOR_REPORTED_LEGITIMATE; HTTP-compatible behavior, not independently adjudicated labels',
        'v1':describe(v1pred,1),'v2':describe(v2,package.config['persistence']),
        'v1_replay_matches_live':True,'fit_calls':0,'policy_freeze':freeze,
        'selected_model':package.config['selected_model'],'persistence':package.config['persistence'],
        'no_promotion':True,'external_used_for_threshold_selection':False}
    alternatives={name:package.predict(rows,model=name) for name in package.novelty}
    comparison['alternative_model_reporting_only']={name:describe(ps,package.config['persistence']) for name,ps in alternatives.items()}
    oldcut=json.loads((study/'ablation.json').read_text())['V2_FEATURES_TRAIN_QUANTILE_OLD_STYLE']['cutoff']
    comparison['external_ablation_reporting_only']={
        'V2_IF_OLD_STYLE':describe(package.predict(rows,model='IF',threshold=oldcut),1),
        'V2_IF_CALIBRATED':describe(alternatives['IF'],1),
        'V2_SELECTED_PERSISTENCE_1':describe(v2,1),
        'V2_SELECTED_VALIDATION_PERSISTENCE':describe(v2,package.config['persistence'])}
    latency={}
    for name,fn in (('v1',lambda:v1.predict(oldrows,explain=False)),('v2',lambda:package.predict(rows,explain=False))):
        samples=[]
        for _ in range(10):
            start=time.perf_counter();fn();samples.append((time.perf_counter()-start)*1000/len(rows))
        latency[name]={'median_ms_per_window':float(np.median(samples)),
            'semantics':'10 warm batches, schema validation + model decisions + robust deviations; excludes SHAP and data/artifact I/O; not SLA'}
    write(out/'latency.json',latency)
    write(out/'alternative_predictions.json',alternatives)
    write(out/'comparison.json',comparison);write(out/'v1_predictions.json',v1pred);write(out/'v2_predictions.json',v2)
    return comparison
