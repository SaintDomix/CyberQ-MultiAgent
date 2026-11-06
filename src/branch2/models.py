"""Independent fitted models and strict schema-checked inference, no raw log imports."""
import numpy as np
from sklearn.ensemble import IsolationForest
from .features import matrix
from .explanation import benign_reference
from .reconciliation import DEFAULT
from .splitting import partition
from .inference import ModelPackage

IF_CONFIG={'n_estimators':200,'max_samples':'auto','contamination':.1,'n_jobs':1}
XGB_CONFIG={'n_estimators':200,'max_depth':3,'learning_rate':.05,'min_child_weight':1,
    'subsample':1.0,'colsample_bytree':1.0,'reg_lambda':1.0,'tree_method':'hist',
    'n_jobs':1,'objective':'multi:softprob','eval_metric':'mlogloss'}



def train(dataset, split, *, if_only=False, seed=42, contamination=.1, confidence_threshold=.8):
    if seed!=split['seed']: raise ValueError('Training/split seeds must match')
    if not 0<contamination<=.5: raise ValueError('Invalid fixed IF contamination')
    if not 0<=confidence_threshold<=1: raise ValueError('Invalid confidence threshold')
    train_rows,test_rows=partition(dataset['rows'],split)
    benign=[r for r in train_rows if r['label']=='BENIGN']
    if len({r['run_id'] for r in benign})<2 or len(benign)<10:
        raise ValueError('At least two benign training runs and ten windows required')
    if not any(r['label']=='BENIGN' for r in test_rows): raise ValueError('Held-out benign evidence required')
    classes=split['eligible_xgb_classes']
    if not if_only:
        if 'BENIGN' not in classes or len(classes)<2: raise ValueError('At least BENIGN and one eligible attack class required; additional captures needed')
        try: from xgboost import XGBClassifier
        except ImportError: raise ValueError('XGBoost unavailable. Install requirements/branch2.txt; no substitute classifier') from None
    values=matrix(benign,dataset['feature_schema'])
    config={**IF_CONFIG,'contamination':contamination,'random_state':seed}
    forest=IsolationForest(**config).fit(values)
    classifier=None;classifier_rows=[]
    if not if_only:
        classifier_rows=[r for r in train_rows if r['label'] in classes]
        encoded=[classes.index(r['label']) for r in classifier_rows]
        classifier=XGBClassifier(**XGB_CONFIG,random_state=seed,num_class=len(classes))
        classifier.fit(matrix(classifier_rows,dataset['feature_schema']),np.asarray(encoded))
    reference=benign_reference(values)
    metadata={'package_version':'branch2-model-package-1.0','evaluation_stage':dataset['evaluation_stage'],
        'seed':seed,'training_only_preprocessing':'identity transform; all features numerical; no fit on held-out data',
        'if_config':config,'xgb_config':{**XGB_CONFIG,'random_state':seed,'num_class':len(classes)} if classifier is not None else None,
        'if_training_run_ids':sorted({r['run_id'] for r in benign}),'if_training_labels':['BENIGN'],
        'if_training_windows':len(benign),'xgb_training_run_ids':sorted({r['run_id'] for r in classifier_rows}),
        'xgb_training_windows':len(classifier_rows),'xgb_classes':classes if classifier is not None else [],
        'if_decision_semantics':'decision_function=score_samples-offset_; <0 anomalous; offset_ fitted on benign training only',
        'if_offset':float(forest.offset_),'if_severity_scale':max(float(np.median(np.abs(forest.decision_function(values)))),1e-6),
        'severity_semantics':'100/(1+exp(decision/benign_scale)); boundary 50; not an attack probability or calibrated severity',
        'classifier_status':'TRAINED' if classifier is not None else 'EXPLICIT_IF_ONLY_PARTIAL_PACKAGE',
        'xgb_confidence_calibrated':False,'data_sources':dataset['sources'],
        'training_run_manifest':[r for r in dataset['runs'] if r['run_id'] in split['train_runs']],
        'test_run_manifest':[r for r in dataset['runs'] if r['run_id'] in split['test_runs']]}
    package=ModelPackage(forest,classifier,dataset['feature_schema'],classes if classifier is not None else [],reference,
        {**DEFAULT,'confidence_threshold':confidence_threshold},metadata)
    return package,test_rows
