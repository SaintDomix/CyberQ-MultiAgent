"""Bounded benchmark contracts; no real holdout experiment or fitting here."""
import copy
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import numpy as np
import pytest
from behavioral_benchmark.three_pipeline import (ROOT,ACCEPTED,PIPELINES,EXPECTED_ROOT,prepare,
    read,sha,digest,check_protocol,require_training,fit_alternative,window_id,split_receipt,
    make_predictions,summarize,classifier_metrics,replacement_gate,select,proportion,execute)
from behavioral_runtime.package import load,verify
from demo.backend.explainability import baseline,explain,canonical


@pytest.fixture(scope='module')
def package():
    return load(ROOT/ACCEPTED)


@pytest.fixture(scope='module')
def protocol(tmp_path_factory):
    with patch('sklearn.svm.OneClassSVM.fit',side_effect=AssertionError('No accepted refit')), \
         patch('xgboost.XGBClassifier.fit',side_effect=AssertionError('No classifier fit')):
        return prepare(tmp_path_factory.mktemp('protocol')/'new-study')


def toy(n=2, label='SQLI_ATTEMPT', partition='ATTACK_HOLDOUT', run='attack'):
    rows=[]
    for i in range(n):
        minute,second=divmod(i*10,60); em,es=divmod((i+1)*10,60)
        rows.append({'record_id':f'{run}-{i}','run_id':run,'partition':partition,'label':label,
            'window_start':f'2020-01-01T00:{minute:02d}:{second:02d}+00:00',
            'window_end':f'2020-01-01T00:{em:02d}:{es:02d}+00:00',
            'client_id':'actor','user_agent_id':'browser', 'source_sha256':run,'line_numbers':[i+1],
            'features':{'fixture':i}})
    return rows


def ps(rows, anomalous, labels=None, scores=None):
    return make_predictions(rows,[-1 if x else 1 for x in anomalous],0,
        labels or [r['label'] for r in rows],scores or [.95]*len(rows),.8)


def example(benign_flags=(True,False),attack_flags=(True,True)):
    b=toy(len(benign_flags),'BENIGN','BENIGN_TEST','benign');a=toy(len(attack_flags))
    value=summarize(ps(b,list(benign_flags))+ps(a,list(attack_flags)),2)
    value['classifier_metrics_sha256']='one-shared-classifier'
    return value


def test_exactly_three_pipelines(protocol):
    assert PIPELINES=={'A':'OCSVM','B':'LOF','C':'IF'}
    assert {p:r['detector'] for p,r in protocol['pipelines'].items()}==PIPELINES


def test_A_accepted_not_refitted(protocol,package):
    assert protocol['accepted_root']==EXPECTED_ROOT
    assert protocol['pipelines']['A']['fit']=='SAVED_ACCEPTED_NO_REFIT'
    assert protocol['pipelines']['A']['parameters']==package.models['OCSVM']['model'].get_params()
    with pytest.raises(ValueError):fit_alternative('OCSVM',[],package)


def test_single_xgb_artifact_hash_across_three(protocol):
    hashes={p['classifier_sha256'] for p in protocol['pipelines'].values()}
    assert hashes=={'9d3acb8e87d44d13f2b62ede413e073fb51c3f264db48a6d4d229964f0e6150d'}
    assert len({p['classifier_path'] for p in protocol['pipelines'].values()})==1
    assert protocol['classifier_refits']==0


def test_identical_83_feature_order_scaling(protocol,package):
    assert protocol['feature_schema']==package.feature_schema
    assert len(protocol['feature_schema']['feature_order'])==83
    assert len({p['scaler_sha256'] for p in protocol['pipelines'].values()})==1
    assert protocol['scaler_refits']==0


def test_protocol_locks_existing_cutoffs_no_new_calibration(protocol,package):
    for p,name in PIPELINES.items():assert protocol['pipelines'][p]['threshold']==package.config['thresholds'][name]
    assert protocol['calibration_calls']==protocol['new_search_candidates']==0
    assert 'holdout' not in protocol['threshold_origin'].lower()


def test_parameters_cannot_be_changed_even_if_protocol_is_rehashed(protocol):
    modified=copy.deepcopy(protocol);modified['pipelines']['B']['threshold']-=1
    modified['sha256']=digest({k:v for k,v in modified.items() if k!='sha256'})
    with pytest.raises(ValueError,match='configuration'):check_protocol(modified,ROOT)


@pytest.mark.parametrize('partition',['VALIDATION','BENIGN_TEST','ATTACK_HOLDOUT','EXTERNAL'])
def test_no_nontrain_fitting(partition):
    with pytest.raises(ValueError):require_training(toy(2,'BENIGN',partition,'fit'),['fit'])


def test_no_attack_training_or_changed_train_ids():
    with pytest.raises(ValueError):require_training(toy(2,'SQLI_ATTEMPT','TRAIN','fit'),['fit'])
    with pytest.raises(ValueError):require_training(toy(2,'BENIGN','TRAIN','foreign'),['fit'])


def test_alternative_fit_sees_only_checked_benign_train(package):
    train=toy(2,'BENIGN','TRAIN','fixture')
    for r in train:
        r['features']=dict.fromkeys(package.feature_schema['feature_order'],0.)
        r['schema_sha256']=package.feature_schema['sha256']
    fake=SimpleNamespace(config={'benign_fit_ids':['fixture']},feature_schema=package.feature_schema,
        models={'OCSVM':{'scaler':Mock(transform=lambda x:x)},'LOF':{'model':Mock()}})
    estimator=Mock()
    with patch('behavioral_benchmark.three_pipeline.clone',return_value=estimator):
        returned,_=fit_alternative('LOF',train,fake)
    assert returned is estimator and estimator.fit.call_count==1
    assert estimator.fit.call_args.args[0].shape==(2,83)


def test_LOF_unseen_semantics(protocol):
    params=protocol['pipelines']['B']['parameters']
    assert params['novelty'] is True and params['n_neighbors']==20
    assert params['metric']=='minkowski' and params['p']==2
    assert params['contamination']=='auto'


def test_IF_fixed_historical_config(protocol):
    params=protocol['pipelines']['C']['parameters']
    assert params['random_state']==42 and params['n_estimators']==200
    assert params['max_samples']=='auto' and params['max_features']==1
    assert params['contamination']==.1 and params['n_jobs']==1


def test_persistence_is_shared(protocol):
    assert protocol['persistence']==2 and protocol['confidence_threshold']==.8
    assert 'episodes(predictions,persistence)' in inspect.getsource(summarize)


def test_benign_denominator_and_specificity():
    result=example()
    assert result['benign']['window_fpr']['count']==1
    assert result['benign']['window_fpr']['total']==2
    assert result['benign']['window_fpr']['rate']==.5
    assert result['benign']['specificity']['rate']==.5


def test_contiguous_unknown_persistence_gives_false_incident_session():
    isolated=example((True,False))
    contiguous=example((True,True))
    assert isolated['benign']['raw_anomalous_runs']['count']==1
    assert isolated['benign']['false_incident_sessions']['count']==0
    assert contiguous['benign']['false_incident_sessions']['count']==1
    assert contiguous['benign']['false_incident_episodes']==1


def test_novelty_window_and_run_metrics():
    result=example(attack_flags=(True,False))
    assert result['attack']['novelty_window_recall']['rate']==.5
    assert result['attack']['novelty_run_recall']['count']==1
    assert result['attack']['novelty_run_recall']['total']==1


def test_strict_AND_requires_anomaly_and_correct_class_not_confidence():
    rows=toy(3)
    values=make_predictions(rows,[-1,1,-1],0,['SQLI_ATTEMPT','SQLI_ATTEMPT','XSS_ATTEMPT'],[.4,.99,.99],.8)
    assert [p['strict_end_to_end'] for p in values]==[True,False,False]
    assert values[0]['reconciliation']['decision']=='UNKNOWN_ANOMALY'
    assert values[1]['reconciliation']['decision']=='SQLI_ATTEMPT'


def test_classifier_only_invariant_ignores_detector():
    rows=toy(2);guesses=['SQLI_ATTEMPT','BENIGN']
    a=classifier_metrics(rows,guesses,['BENIGN','SQLI_ATTEMPT'])
    b=classifier_metrics(copy.deepcopy(rows),list(guesses),['BENIGN','SQLI_ATTEMPT'])
    assert a==b and a['attack_only']['accuracy']==.5


def test_all_perclass_support_is_retained():
    result=summarize(ps(toy(3),[True,False,True]),2)
    assert result['per_class']['SQLI_ATTEMPT']['windows']==3
    assert result['per_class']['SQLI_ATTEMPT']['novelty']['count']==2
    assert result['per_class']['SQLI_ATTEMPT']['strict_end_to_end']['total']==3


def test_gate_requires_lower_fp_and_no_regression():
    a=example();good=example((False,False))
    assert all(replacement_gate(a,good).values())
    bad=example((False,False),(True,False))
    assert replacement_gate(a,bad)['no_lower_attack_window_recall'] is False
    assert select({'A':a,'B':bad,'C':bad})['decision']=='KEEP_OCSVM'


def test_lower_fpr_cannot_hide_worse_false_incidents():
    a=example((True,False,True,False,True,False),(True,False))
    bad=example((True,True,False,False,False,False),(True,True))
    gate=replacement_gate(a,bad)
    assert gate['lower_benign_window_fpr'] and not gate['no_more_false_incident_sessions']
    assert select({'A':a,'B':bad,'C':a})['decision']=='KEEP_OCSVM'


def test_selection_deterministic_and_all_decision_states_possible():
    a=example();good=example((False,False));bad=example((False,False),(True,False))
    assert select({'A':a,'B':good,'C':bad})['decision']=='REPLACEMENT_RECOMMENDED_LOF'
    assert select({'A':a,'B':bad,'C':good})['decision']=='REPLACEMENT_RECOMMENDED_ISOLATION_FOREST'
    assert select({'C':good,'B':good,'A':a})==select({'A':a,'B':good,'C':good})


def test_split_receipt_rejects_cross_partition_run_and_raw_record(package):
    train=toy(2,'BENIGN','TRAIN','one');val=toy(2,'BENIGN','VALIDATION','one')
    with pytest.raises(ValueError):split_receipt(train,val,package)
    val=toy(2,'BENIGN','VALIDATION','two')
    for r in val:r['source_sha256']='one'
    with pytest.raises(ValueError,match='Raw source'):split_receipt(train,val,package)


def test_window_identity_ignores_model_and_is_shared():
    row=toy(1)[0];changed=dict(row,novelty_score=999,xgb_label='BENIGN')
    assert window_id(row)==window_id(changed)
    changed['run_id']='different';assert window_id(row)!=window_id(changed)


def test_execution_refuses_rerun_before_any_fit(tmp_path,protocol):
    (tmp_path/'benchmark_config.json').write_text(json.dumps(protocol))
    (tmp_path/'execution_started.json').write_text('{}')
    with patch('behavioral_benchmark.three_pipeline.fit_alternative') as fit:
        with pytest.raises(FileExistsError):execute(tmp_path)
    fit.assert_not_called()


def test_accepted_outputs_not_overwritten_and_explainability_unchanged(package):
    before=verify(ROOT/ACCEPTED)['root_sha256']
    p={'xgb_label':'BENIGN','xgb_confidence':.98,'novelty_anomalous':False,'novelty_score':2,
       'reconciliation':{'decision':'BENIGN','model_disagreement':False},'robust_deviations':[]}
    vector={k:r['median'] for k,r in baseline()['features'].items()}
    first=canonical(explain(p,features=vector,package_id=package.accepted_manifest['package_id']))
    summarize(ps(toy(2),[True,False]),2)
    assert first==canonical(explain(p,features=vector,package_id=package.accepted_manifest['package_id']))
    assert verify(ROOT/ACCEPTED)['root_sha256']==before==EXPECTED_ROOT


def test_wilson_intervals_zero_total_and_small_support():
    assert proportion(0,0)['wilson95'] is None
    zero=proportion(0,6);one=proportion(1,33)
    assert zero['wilson95'][0]==0 and .39<zero['wilson95'][1]<.40
    assert one['wilson95'][0]<1/33<one['wilson95'][1]
