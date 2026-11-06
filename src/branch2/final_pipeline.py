"""M2C offline protocol: train -> validation selection -> frozen test -> replay.

No log collection. Run-level IF averages score_samples then subtracts fitted offset;
XGB averages uncalibrated vectors. Reconciliation uses these two parallel signals.
"""
from collections import Counter,defaultdict
from datetime import datetime,timezone
from dataclasses import replace
import hashlib
from pathlib import Path
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score
from .dataset import CLASSES,digest,sufficiency
from .features import matrix
from .models import ModelPackage,IF_CONFIG,XGB_CONFIG
from .explanation import benign_reference
from .reconciliation import DEFAULT,reconcile
from .evaluation import binary_metrics,summary
from .splitting import split_final_runs,partition_final
from .artifacts import save,load,write_json

STAGE='M2C_FINAL_CONTROLLED_LAB_EVALUATION'
CONTAMINATIONS=(.05,.10,.15,.20)
CONFIDENCES=(.60,.70,.80,.90)


def binary(truth,pred):
    result=binary_metrics(truth,pred)
    tn,fp,tp,fn=(result[k] for k in ('TN','FP','TP','FN'))
    specificity=tn/(tn+fp) if tn+fp else None
    sensitivity=tp/(tp+fn) if tp+fn else None
    result.update(specificity=specificity,FPR=result['false_positive_rate'],
                  balanced_accuracy=(specificity+sensitivity)/2 if specificity is not None and sensitivity is not None else None,
                  class_support={'BENIGN':tn+fp,'ANOMALOUS':tp+fn})
    return result


def multiclass(truth,pred,classes):
    labels=list(classes)+sorted(set(pred)-set(classes))
    report=classification_report(truth,pred,labels=labels,output_dict=True,zero_division=0)
    known=classification_report(truth,pred,labels=classes,output_dict=True,zero_division=0)
    return {'classes':labels,'confusion_matrix':confusion_matrix(truth,pred,labels=labels).tolist(),
        'per_class':{c:report[c] for c in labels},'macro_precision':known['macro avg']['precision'],
        'macro_recall':known['macro avg']['recall'],'macro_f1':known['macro avg']['f1-score'],
        'weighted_f1':known['weighted avg']['f1-score'],'balanced_accuracy':known['macro avg']['recall'],
        'accuracy':float(accuracy_score(truth,pred)),'support':len(truth),
        'macro_scope':'eight known ground-truth classes; UNKNOWN_ANOMALY/UNCERTAIN count as wrong predictions',
        'confidence_calibrated':False,'zero_division':0}


def metrics(predictions,classes):
    truth=[p['label'] for p in predictions]
    result={'evaluation_stage':STAGE,'isolation_forest':binary([c!='BENIGN' for c in truth],[p['if_anomalous'] for p in predictions]),
            'xgboost':multiclass(truth,[p['xgb_label'] for p in predictions],classes),
            'reconciled':multiclass(truth,[p['reconciliation']['decision'] for p in predictions],classes)}
    grouped=defaultdict(list)
    for p in predictions:grouped[p['label']].append(p['if_raw_anomaly_score'])
    result['isolation_forest']['score_distributions']={c:summary(v) for c,v in sorted(grouped.items())}
    result['reconciled']['disagreement_count']=sum(p['reconciliation']['model_disagreement'] for p in predictions)
    result['reconciled']['disagreement_reasons']=dict(Counter(p['reconciliation']['reason'] for p in predictions if p['reconciliation']['model_disagreement']))
    result['reconciled']['decision_reasons']=dict(Counter(p['reconciliation']['reason'] for p in predictions))
    return result


def aggregate_runs(predictions,classes,threshold):
    grouped=defaultdict(list)
    for p in predictions:grouped[p['run_id']].append(p)
    results=[]
    for run_id,rows in sorted(grouped.items()):
        rows=sorted(rows,key=lambda r:(r['window_start'],r.get('window_end',''),r.get('source_file',''),r['if_raw_anomaly_score'],tuple(r['xgb_scores'])))
        labels={p.get('label') for p in rows}
        if len(labels)!=1:raise ValueError('Run ground truth inconsistent')
        means=np.mean(np.asarray([p['xgb_scores'] for p in rows]),axis=0)
        if means.shape!=(len(classes),):raise ValueError('Run classifier vector incompatible')
        index=int(np.argmax(means));label=classes[index];confidence=float(means[index])
        decision=float(np.mean([p['if_decision_function'] for p in rows]));anomalous=decision<0
        results.append({'run_id':run_id,'label':next(iter(labels)),'windows':len(rows),
            'if_anomalous':anomalous,'if_decision_function':decision,
            'if_raw_anomaly_score':float(np.mean([p['if_raw_anomaly_score'] for p in rows])),
            'xgb_scores':means.tolist(),'xgb_label':label,'xgb_confidence':confidence,
            'reconciliation':reconcile(anomalous,label,confidence,threshold)})
    return results


def fit_training(dataset,train_rows,seed):
    """No validation/test inputs or statistics in fitting."""
    from xgboost import XGBClassifier
    classes=sorted(CLASSES)
    if set(r['label'] for r in train_rows)!=set(classes):raise ValueError('All eight TRAIN classes required')
    benign=[r for r in train_rows if r['label']=='BENIGN']
    if len(benign)<10 or len({r['run_id'] for r in benign})<2:raise ValueError('Insufficient TRAIN BENIGN')
    benign_values=matrix(benign,dataset['feature_schema'])
    classifier=XGBClassifier(**XGB_CONFIG,random_state=seed,num_class=8)
    classifier.fit(matrix(train_rows,dataset['feature_schema']),np.asarray([classes.index(r['label']) for r in train_rows]))
    reference=benign_reference(benign_values)
    metadata={'package_version':'branch2-model-package-1.0','protocol_version':'m2c-1.0','evaluation_stage':STAGE,
        'seed':seed,'xgb_config':{**XGB_CONFIG,'random_state':seed,'num_class':8},
        'xgb_classes':classes,'xgb_confidence_calibrated':False,'classifier_status':'TRAINED',
        'if_training_run_ids':sorted({r['run_id'] for r in benign}),'if_training_labels':['BENIGN'],
        'if_training_windows':len(benign),'xgb_training_run_ids':sorted({r['run_id'] for r in train_rows}),
        'xgb_training_windows':len(train_rows),'reference_training_run_ids':sorted({r['run_id'] for r in benign}),
        'training_only_preprocessing':'identity transform; BENIGN TRAIN only robust reference; no fit on validation/test',
        'if_decision_semantics':'decision_function=score_samples-offset_; <0 anomalous; offset_ fitted on BENIGN TRAIN only',
        'severity_semantics':'100/(1+exp(decision/benign_scale)); not an attack probability',
        'data_sources':dataset['sources']}
    return classifier,classes,reference,benign_values,metadata


def select_validation(dataset,train_rows,validation_rows,seed=42):
    classifier,classes,reference,benign_values,base=fit_training(dataset,train_rows,seed)
    tuning={'selection_data':'VALIDATION only','fit_data':'TRAIN only','contamination_candidates':[],
            'confidence_candidates':[],'if_grid':list(CONTAMINATIONS),'confidence_grid':list(CONFIDENCES),
            'if_selection':'max anomaly F1; min BENIGN FPR; max balanced accuracy; closest to 0.10; lower value if still tied',
            'confidence_selection':'max eight-class reconciled macro-F1; higher confidence threshold if tied',
            'validation_run_ids':sorted({r['run_id'] for r in validation_rows})}
    candidates=[]
    for value in CONTAMINATIONS:
        config={**IF_CONFIG,'contamination':value,'random_state':seed}
        forest=IsolationForest(**config).fit(benign_values)
        metadata={**base,'if_config':config,'if_offset':float(forest.offset_),
            'if_severity_scale':max(float(np.median(np.abs(forest.decision_function(benign_values)))),1e-6)}
        package=ModelPackage(forest,classifier,dataset['feature_schema'],classes,reference,dict(DEFAULT),metadata)
        predictions=package.predict(validation_rows,explain=False)
        performance=binary([p['label']!='BENIGN' for p in predictions],[p['if_anomalous'] for p in predictions])
        tuning['contamination_candidates'].append({'contamination':value,'metrics':performance,'if_offset':float(forest.offset_)})
        candidates.append((package,predictions,performance,value))
    package,predictions,_,chosen=max(candidates,key=lambda item:(item[2]['f1'] or 0,-item[2]['FPR'],item[2]['balanced_accuracy'],
                                                               -round(abs(item[3]-.1),8),-item[3]))
    choices=[]
    for value in CONFIDENCES:
        updated=[{**p,'reconciliation':reconcile(p['if_anomalous'],p['xgb_label'],p['xgb_confidence'],value)} for p in predictions]
        performance=multiclass([p['label'] for p in updated],[p['reconciliation']['decision'] for p in updated],classes)
        tuning['confidence_candidates'].append({'confidence_threshold':value,'metrics':performance})
        choices.append((performance['macro_f1'],value,updated))
    _,confidence,predictions=max(choices,key=lambda item:(item[0],item[1]))
    package=replace(package,reconciliation={**DEFAULT,'confidence_threshold':confidence})
    tuning.update(selected_contamination=chosen,selected_confidence_threshold=confidence)
    return package,tuning,predictions


def explanation_qa(predictions):
    statuses=Counter(p['shap_explanation']['status'] for p in predictions)
    available=statuses.get('AVAILABLE',0)
    return {'SHAP_status':'AVAILABLE' if available==len(predictions) else 'PARTIAL' if available else 'UNAVAILABLE_OR_INCOMPATIBLE',
        'status_counts':dict(statuses),
        'backend_counts':dict(Counter(p['shap_explanation'].get('backend','PYTHON_SHAP_TREE_EXPLAINER') for p in predictions)),
        'python_treeexplainer_status_counts':dict(Counter(p['shap_explanation'].get('python_treeexplainer_status',p['shap_explanation']['status']) for p in predictions)),
        'number_of_explained_test_windows':available,
        'number_with_nonempty_SHAP_contributions':sum(bool(p['shap_explanation']['top_features']) for p in predictions),
        'number_with_robust_deviations':sum(any(f['absolute_deviation']>0 for f in p['robust_explanation']['top_features']) for p in predictions),
        'number_with_robust_reference_explanations':sum(bool(p['robust_explanation']['top_features']) for p in predictions),
        'failures':[{'run_id':p['run_id'],'window_start':p['window_start'],'status':p['shap_explanation']['status']} for p in predictions if p['shap_explanation']['status']!='AVAILABLE'],
        'output_space':'raw model margin','causal':False}


def run_final(dataset,dataset_path,output,project,seed=42):
    if seed!=42:raise ValueError('Final declared M2C seed is 42')
    output=Path(output)
    if output.exists():raise ValueError('Never overwrite prior experiment output')
    # Revalidate actual dataset source bytes, not just its summary QA assertion.
    for name,expected in dataset['sources'].items():
        path=Path(name) if Path(name).is_absolute() else Path(project)/name
        if digest(path)!=expected:raise ValueError('Dataset source provenance hash mismatch')
    split=split_final_runs(dataset,seed)
    train_rows,validation_rows,test_rows=partition_final(dataset['rows'],split)
    phases=['SPLIT_FROZEN','TRAIN_FIT_AND_VALIDATION_SELECTION']
    package,tuning,validation_predictions=select_validation(dataset,train_rows,validation_rows,seed)
    phases.append('SELECTION_COMPLETE')
    # Nothing above predicts or computes performance on TEST.
    package.metadata.update(training_run_manifest=split['partitions']['train']['runs'],
        validation_run_manifest=split['partitions']['validation']['runs'],test_run_manifest=split['partitions']['test']['runs'],
        selected_contamination=tuning['selected_contamination'],selected_confidence_threshold=tuning['selected_confidence_threshold'])
    phases.append('FROZEN_TEST_INFERENCE_ONCE')
    predictions=package.predict(test_rows)
    window_metrics=metrics(predictions,package.classes)
    run_predictions=aggregate_runs(predictions,package.classes,package.reconciliation['confidence_threshold'])
    run_metrics=metrics(run_predictions,package.classes)
    run_metrics['aggregation']={'IF':'mean decision_function (equivalently mean score_samples minus fitted offset); negative means anomalous',
        'XGB':'argmax mean uncalibrated class-score vector; exact ties choose first saved class mapping entry',
        'reconciled':'existing reconcile(mean IF decision <0, argmax mean XGB vector, max mean score, selected threshold); no window majority vote',
        'ties':'IF mean exactly zero is normal; XGB argmax ties use saved class order; aggregation never uses truth'}
    qa=explanation_qa(predictions)
    training_manifest={**package.metadata,'dataset_sha256':digest(dataset_path),
        'created_utc':datetime.now(timezone.utc).isoformat(),'phase_order':phases,
        'selection_grids_predeclared':True,'test_used_for_selection':False,
        'code_sha256':{str(p.relative_to(project)):digest(p) for p in list((Path(project)/'src/branch2').glob('*.py'))+[Path(project)/'scripts/run_branch2.py']},
        'limitations':['Controlled repeated lab runs, not independent users/platforms.',
            'Historical and M2B captures intentionally combined; S03 label reconstruction/protocol conflict retained.',
            'Window observations within a run are correlated; run-level sample size is 16.',
            'Capture-level attempt labels imply no successful exploitation; POST bodies unavailable.',
            'No score calibration, confidence intervals or ROC-AUC claimed.']}
    extras={'training_manifest.json':training_manifest,'validation_tuning.json':tuning,
        'validation_metrics.json':metrics(validation_predictions,package.classes),'validation_predictions.json':validation_predictions,
        'validation_run_manifest.json':split['partitions']['validation']['runs'],
        'test_metrics.json':window_metrics,'run_level_test_metrics.json':run_metrics,
        'test_predictions.json':predictions,'run_level_test_predictions.json':run_predictions,
        'explainability_qa.json':qa,'sufficiency.json':sufficiency(dataset['runs'])}
    save(package,output,split,window_metrics,predictions,digest(dataset_path),extra_artifacts=extras)
    restored=load(output)
    replay=restored.predict(test_rows)
    # Exact JSON-compatible inference output, including vectors/explanations/provenance.
    matched=replay==predictions
    report={'status':'PASS' if matched else 'FAIL','predictions_identical':matched,'windows':len(test_rows),
        'fit_calls':0,'evaluation':'Saved-model inference consistency only; not a second held-out evaluation'}
    write_json(output/'replay_consistency.json',report)
    # Seal the newly produced package including replay evidence; never touches old output.
    import json
    manifest=json.loads((output/'package_manifest.json').read_text())
    manifest['files_sha256']={p.name:digest(p) for p in sorted(output.iterdir()) if p.name!='package_manifest.json'}
    (output/'package_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    load(output)  # Validate final sealed artifact hashes, no fitting or evaluation.
    if not matched:raise ValueError('Saved-model replay differs; final package failed consistency')
    return {'split':{p:split['partitions'][p]['run_count'] for p in ('train','validation','test')},
        'selected_contamination':tuning['selected_contamination'],'selected_confidence_threshold':tuning['selected_confidence_threshold'],
        'test_metrics':window_metrics,'run_level_test_metrics':run_metrics,'explainability_qa':qa,'replay':report}
