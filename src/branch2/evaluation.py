"""Held-out observations only; undefined ratios are explicit nulls."""
from collections import defaultdict
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


def ratio(a,b): return float(a/b) if b else None


def binary_metrics(truth, predicted):
    truth=np.asarray(truth,dtype=bool);predicted=np.asarray(predicted,dtype=bool)
    tp=int(np.sum(truth&predicted));tn=int(np.sum(~truth&~predicted));fp=int(np.sum(~truth&predicted));fn=int(np.sum(truth&~predicted))
    return {'TP':tp,'TN':tn,'FP':fp,'FN':fn,'precision':ratio(tp,tp+fp),'recall':ratio(tp,tp+fn),
        'f1':ratio(2*tp,2*tp+fp+fn),'false_positive_rate':ratio(fp,fp+tn),'accuracy':ratio(tp+tn,len(truth)),
        'support':len(truth),'undefined_ratio':'null when denominator is zero'}


def summary(values):
    return {'count':len(values),'min':float(np.min(values)),'median':float(np.median(values)),
        'mean':float(np.mean(values)),'max':float(np.max(values)),'std':float(np.std(values))} if len(values) else {'count':0}


def evaluate(predictions, classes):
    truth=[p['label']!='BENIGN' for p in predictions]
    result={'isolation_forest':binary_metrics(truth,[p['if_anomalous'] for p in predictions]),
            'evaluation_stage':'PROVISIONAL_DATASET_V2_EXISTING_CAPTURES',
            'limitations':['Capture-level labels do not verify each request/window intent or exploitation.',
                'Windows are correlated; independent experimental sample size is run count, not window count.',
                'Run holdout does not prove cross-user, cross-platform or unseen-scenario generalization.',
                'S03 labels reconstructed from generator/log pattern; protocol CSV conflict retained.']}
    grouped=defaultdict(list);perrun=defaultdict(list)
    for p in predictions: grouped[p['label']].append(p['if_raw_anomaly_score']);perrun[p['run_id']].append(p)
    result['isolation_forest']['score_distributions']={label:summary(scores) for label,scores in sorted(grouped.items())}
    result['isolation_forest']['per_run']={run:binary_metrics([p['label']!='BENIGN' for p in rows],[p['if_anomalous'] for p in rows]) for run,rows in sorted(perrun.items())}
    eligible=[p for p in predictions if p['label'] in classes and p['xgb_label'] is not None]
    if not eligible:
        result['xgboost']={'status':'NOT_EVALUATED','reason':'Dependency/class prerequisites unavailable; no substitute classifier'}
    else:
        true=[p['label'] for p in eligible];pred=[p['xgb_label'] for p in eligible]
        report=classification_report(true,pred,labels=classes,output_dict=True,zero_division=0)
        result['xgboost']={'status':'EVALUATED_PROVISIONALLY','classes':classes,'confusion_matrix':confusion_matrix(true,pred,labels=classes).tolist(),
            'per_class':{c:report[c] for c in classes},'macro_f1':report['macro avg']['f1-score'],
            'weighted_f1':report['weighted avg']['f1-score'],'overall_accuracy':float(accuracy_score(true,pred)),
            'support':len(eligible),'excluded_ineligible_windows':len(predictions)-len(eligible),
            'attack_vs_benign':binary_metrics([x!='BENIGN' for x in true],[x!='BENIGN' for x in pred]),
            'undefined_class_metrics':'sklearn zero_division=0; inspect support and predicted counts',
            'confidence_calibrated':False}
    return result
