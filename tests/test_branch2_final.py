"""M2C protocol tests. Artificial numeric fixtures are tests, never experiments."""
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from branch2.dataset import CLASSES,sufficiency
from branch2.features import FEATURES,schema,matrix
from branch2.splitting import split_final_runs,partition_final
from branch2.models import ModelPackage
from branch2.final_pipeline import select_validation,aggregate_runs,run_final,explanation_qa,metrics
from branch2.artifacts import load


def fixture(directory=None):
    feature_schema=schema();runs=[];rows=[];sources={};number=0
    for label in CLASSES:
        for index in range(12 if label=='BENIGN' else 10):
            number+=1;rid=f'fixture-{label}-{index}'
            path=Path(directory)/f'{number}.txt' if directory else Path(f'/fixture/{number}.txt')
            raw=f'Artificial unit-test fixture {number}\n'.encode();sha=hashlib.sha256(raw).hexdigest()
            if directory:path.write_bytes(raw)
            sources[str(path)]=sha
            start=datetime(2020,1,1,tzinfo=timezone.utc)+timedelta(seconds=number*60)
            run={'run_id':rid,'label':label,'scenario':f'fixture-scenario-{index%2}','included':True,'windows':2,
                 'included_events':2,'source_file':str(path),'source_sha256':sha,'capture_start':start.isoformat(),
                 'capture_end':(start+timedelta(seconds=20)).isoformat()}
            runs.append(run)
            for window in range(2):
                features=dict.fromkeys(FEATURES,0.0);features['request_count']=float(number)
                features['sql_token_count']=float(CLASSES.index(label))
                rows.append({'run_id':rid,'label':label,'scenario':run['scenario'],'source_file':str(path),
                             'source_sha256':sha,'window_start':(start+timedelta(seconds=10*window)).isoformat(),
                             'window_end':(start+timedelta(seconds=10*(window+1))).isoformat(),
                             'line_numbers':[window+1],'schema_sha256':feature_schema['sha256'],'features':features})
    runs.append({'run_id':'TEST-run01','label':None,'scenario':'TEST','included':False,'windows':0})
    return {'runs':runs,'rows':rows,'sources':sources,'feature_schema':feature_schema,'evaluation_stage':'UNIT_TEST_FIXTURE'}


class FinalTests(unittest.TestCase):
    def setUp(self):
        blocker=patch('socket.socket',side_effect=AssertionError('No network'))
        blocker.start();self.addCleanup(blocker.stop)

    def test_exact_real_dataset_split_50_16_16_and_all_eight_classes(self):
        data=json.loads((ROOT/'data/branch2_v2/final_candidate_01/dataset.json').read_text())
        split=split_final_runs(data)
        self.assertEqual([split['partitions'][p]['run_count'] for p in ('train','validation','test')],[50,16,16])
        self.assertEqual(sum(p['window_count'] for p in split['partitions'].values()),392)
        for name in ('train','validation','test'):
            self.assertEqual(set(split['partitions'][name]['class_counts']),set(CLASSES))
        self.assertEqual(split['excluded_run_ids'],['TEST-run01'])

    def test_seeded_split_reproducibility_and_changed_membership(self):
        data=fixture();a=split_final_runs(data)
        self.assertEqual(a,split_final_runs(data))
        self.assertNotEqual(a['test_runs'],split_final_runs(data,43)['test_runs'])
        for name in ('train','validation','test'):
            self.assertEqual(len(a[name+'_runs']),len(split_final_runs(data,43)[name+'_runs']))

    def test_complete_run_and_window_isolation(self):
        data=fixture();split=split_final_runs(data);partitions=partition_final(data['rows'],split)
        ids=[{r['run_id'] for r in rows} for rows in partitions]
        self.assertFalse(ids[0]&ids[1]);self.assertFalse(ids[1]&ids[2]);self.assertFalse(ids[0]&ids[2])
        self.assertEqual(sum(len(r) for r in partitions),len(data['rows']))
        self.assertTrue(all(sum(row['run_id'] in s for s in ids)==1 for row in data['rows']))
        bad=copy.deepcopy(split);bad['test_runs'].append(split['train_runs'][0])
        with self.assertRaises(ValueError):partition_final(data['rows'],bad)

    def test_smoke_test_rows_and_insufficient_class_fail_closed(self):
        data=fixture();data['rows'].append({**data['rows'][0],'run_id':'TEST-run01'})
        with self.assertRaises(ValueError):split_final_runs(data)
        data=fixture();data['runs'][0]['included']=False
        with self.assertRaises(ValueError):split_final_runs(data)

    def test_overlap_duplicate_source_and_observation_rejected(self):
        for mutation in ('capture','source','observation','row','interval'):
            data=fixture()
            if mutation=='capture':data['runs'][1]['source_sha256']=data['runs'][0]['source_sha256']
            if mutation=='source':data['runs'][1]['source_file']=data['runs'][0]['source_file']
            if mutation=='observation':data['rows'][1]['line_numbers']=data['rows'][0]['line_numbers']
            if mutation=='row':data['rows'].append(copy.deepcopy(data['rows'][0]))
            if mutation=='interval':data['runs'][1]['capture_start']=data['runs'][0]['capture_start']
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):split_final_runs(data)

    def test_sufficiency_target_provisional_and_insufficient(self):
        data=fixture();report=sufficiency(data['runs'])
        self.assertTrue(all(r['readiness']=='CAPTURE_TARGET_MET' for r in report.values()))
        partial=sufficiency([r for r in data['runs'] if r.get('label')=='BENIGN'][:3])
        self.assertEqual(partial['BENIGN']['readiness'],'PROVISIONAL_ONLY')
        self.assertEqual(partial['SQLI_ATTEMPT']['readiness'],'INSUFFICIENT')

    def test_fits_only_train_and_validation_never_test(self):
        from sklearn.ensemble import IsolationForest
        from xgboost import XGBClassifier
        data=fixture();split=split_final_runs(data);train,val,test=partition_final(data['rows'],split)
        if_inputs=[];xgb_inputs=[];predicted=[]
        real_if=IsolationForest.fit;real_xgb=XGBClassifier.fit;real_predict=ModelPackage.predict
        def if_fit(model,values,*a,**kw):if_inputs.append(values.copy());return real_if(model,values,*a,**kw)
        def xgb_fit(model,values,*a,**kw):xgb_inputs.append(values.copy());return real_xgb(model,values,*a,**kw)
        def predict(model,rows,**kw):predicted.extend(r['run_id'] for r in rows);return real_predict(model,rows,**kw)
        with patch.object(IsolationForest,'fit',if_fit),patch.object(XGBClassifier,'fit',xgb_fit),patch.object(ModelPackage,'predict',predict):
            package,tuning,_=select_validation(data,train,val)
        expected=matrix([r for r in train if r['label']=='BENIGN'],data['feature_schema'])
        self.assertEqual(len(if_inputs),4);self.assertEqual(len(xgb_inputs),1)
        for values in if_inputs:np.testing.assert_array_equal(values,expected)
        np.testing.assert_array_equal(xgb_inputs[0],matrix(train,data['feature_schema']))
        self.assertEqual(set(predicted),set(split['validation_runs']))
        self.assertFalse(set(predicted)&set(split['test_runs']))
        self.assertEqual(set(package.classes),set(CLASSES));self.assertEqual(len(tuning['confidence_candidates']),4)
        self.assertEqual(len(tuning['contamination_candidates']),4)
        self.assertEqual(package.metadata['if_training_run_ids'],sorted({r['run_id'] for r in train if r['label']=='BENIGN'}))
        self.assertEqual(package.reference['median'],np.median(expected,axis=0).tolist())

    def test_fit_missing_training_class_fails_closed(self):
        data=fixture();split=split_final_runs(data);train,val,_=partition_final(data['rows'],split)
        with self.assertRaises(ValueError):select_validation(data,[r for r in train if r['label']!='SQLI_ATTEMPT'],val)

    def test_reconciliation_unknown_counts_as_wrong_known_class(self):
        from branch2.final_pipeline import multiclass
        result=multiclass(['BENIGN','SQLI_ATTEMPT'],['BENIGN','UNKNOWN_ANOMALY'],['BENIGN','SQLI_ATTEMPT'])
        self.assertEqual(result['accuracy'],.5);self.assertEqual(result['macro_f1'],.5)
        self.assertEqual(result['per_class']['SQLI_ATTEMPT']['recall'],0)
        self.assertIn('UNKNOWN_ANOMALY',result['classes'])

    def test_run_aggregation_deterministic_mean_threshold_and_ties(self):
        def row(window,decision,scores):
            return {'run_id':'fixture','label':'BENIGN','window_start':str(window),'if_decision_function':decision,
                    'if_raw_anomaly_score':.5-decision,'xgb_scores':scores}
        rows=[row(1,-.2,[.9,.1]),row(2,.4,[.3,.7])]
        result=aggregate_runs(rows,['BENIGN','SQLI_ATTEMPT'],.7)
        self.assertEqual(result,aggregate_runs(list(reversed(rows)),['BENIGN','SQLI_ATTEMPT'],.7))
        self.assertFalse(result[0]['if_anomalous']);self.assertEqual(result[0]['xgb_label'],'BENIGN')
        tied=aggregate_runs([row(1,0,[.5,.5])],['BENIGN','SQLI_ATTEMPT'],.7)
        self.assertFalse(tied[0]['if_anomalous']);self.assertEqual(tied[0]['xgb_label'],'BENIGN')
        changed=[{**r,'label':'SQLI_ATTEMPT'} for r in rows]
        other=aggregate_runs(changed,['BENIGN','SQLI_ATTEMPT'],.7)[0]
        self.assertEqual(other['reconciliation'],result[0]['reconciliation'])

    def test_run_reconciliation_preserves_known_attack_disagreement(self):
        row={'run_id':'fixture','label':'BENIGN','window_start':'1','if_decision_function':.1,'if_raw_anomaly_score':.4,'xgb_scores':[.01,.99]}
        result=aggregate_runs([row],['BENIGN','SQLI_ATTEMPT'],.8)[0]
        self.assertEqual(result['reconciliation']['decision'],'SQLI_ATTEMPT')
        self.assertTrue(result['reconciliation']['model_disagreement'])
        row['if_decision_function']=-.1;row['xgb_scores']=[.5,.5]
        self.assertEqual(aggregate_runs([row],['BENIGN','SQLI_ATTEMPT'],.8)[0]['reconciliation']['decision'],'UNKNOWN_ANOMALY')

    def test_truthful_explainability_qa_unavailable(self):
        predictions=[{'run_id':'fixture','window_start':'0','shap_explanation':{'status':'DEPENDENCY_UNAVAILABLE','top_features':[]},
                      'robust_explanation':{'top_features':[{'absolute_deviation':1}]}}]
        qa=explanation_qa(predictions)
        self.assertEqual(qa['SHAP_status'],'UNAVAILABLE_OR_INCOMPATIBLE')
        self.assertEqual(qa['number_with_nonempty_SHAP_contributions'],0)
        self.assertEqual(len(qa['failures']),1);self.assertFalse(qa['causal'])

    def test_final_package_order_shap_and_no_fit_replay(self):
        from sklearn.ensemble import IsolationForest
        from xgboost import XGBClassifier
        from branch2 import final_pipeline
        with tempfile.TemporaryDirectory() as directory:
            data=fixture(directory);dataset_path=Path(directory)/'dataset.json';dataset_path.write_text(json.dumps(data))
            output=Path(directory)/'model';calls=[];select=final_pipeline.select_validation;predict=ModelPackage.predict
            selection_done=False;test_ids=set(split_final_runs(data)['test_runs'])
            def select_spy(*args,**kw):
                nonlocal selection_done
                result=select(*args,**kw);selection_done=True;calls.append('selection_complete');return result
            def predict_spy(model,rows,**kw):
                if any(r['run_id'] in test_ids for r in rows):
                    self.assertTrue(selection_done);calls.append('test_or_replay')
                return predict(model,rows,**kw)
            with patch.object(final_pipeline,'select_validation',select_spy),patch.object(ModelPackage,'predict',predict_spy):
                report=run_final(data,dataset_path,output,ROOT)
            self.assertEqual(calls,['selection_complete','test_or_replay','test_or_replay'])
            self.assertEqual(report['replay']['status'],'PASS')
            restored=load(output);_,_,test=partition_final(data['rows'],split_final_runs(data))
            with patch.object(IsolationForest,'fit',side_effect=AssertionError('No fit')),patch.object(XGBClassifier,'fit',side_effect=AssertionError('No fit')):
                replay=restored.predict(test)
            self.assertEqual(replay,json.loads((output/'test_predictions.json').read_text()))
            qa=json.loads((output/'explainability_qa.json').read_text())
            self.assertEqual(qa['SHAP_status'],'AVAILABLE');self.assertEqual(qa['number_with_nonempty_SHAP_contributions'],len(test))
            self.assertTrue(all(p['shap_explanation']['output_space']=='raw model margin' and not p['shap_explanation']['causal'] for p in replay))
            with self.assertRaises(ValueError):run_final(data,dataset_path,output,ROOT)

    def test_final_seed_locked_and_source_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            data=fixture(directory);path=Path(directory)/'dataset.json';path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):run_final(data,path,Path(directory)/'model',ROOT,43)
            Path(next(iter(data['sources']))).write_text('changed fixture')
            with self.assertRaises(ValueError):run_final(data,path,Path(directory)/'model',ROOT)


if __name__=='__main__':unittest.main()
