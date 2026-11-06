"""Offline Branch 2 tests; fixtures are test observations, never capture evidence."""
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import copy
import csv
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import numpy as np
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from branch2.events import CanonicalBehavioralEvent, identifier
from branch2.adapters.apache import parse_line, read_log
from branch2.windowing import windows
from branch2.features import FEATURES, extract, schema, matrix
from branch2.dataset import build, digest, sufficiency
from branch2.splitting import split_runs, partition
from branch2.models import train, IF_CONFIG, XGB_CONFIG
from branch2.artifacts import save, load, new_output
from branch2.evaluation import evaluate, binary_metrics
from branch2.reconciliation import reconcile
from branch2.explanation import benign_reference, deviations, ShapExplainer

LINE='192.0.2.1 - - [05/Sep/2026:17:02:03 +0000] "GET /app/course?id=7 HTTP/1.1" 200 50 "-" "TestAgent"'


def event(second=0, **fields):
    e=parse_line(LINE,'fixture.log','a'*64,1)
    return replace(e,timestamp=datetime(2026,9,5,17,2,second,tzinfo=timezone.utc),**fields)


def actual(): return build(ROOT,ROOT/'experiments/experiment_metadata.csv',ROOT/'experiments/branch2_v2_labels.json')


class Offline(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('socket.socket',side_effect=AssertionError('Network prohibited')))


class ParserTests(Offline):
    def test_canonical_combined_observables_and_provenance(self):
        e=parse_line(LINE,'sample.log','a'*64,19)
        self.assertEqual(e.path,'/app/course');self.assertEqual(e.query,'id=7')
        self.assertEqual(e.timestamp.isoformat(),'2026-09-05T17:02:03+00:00')
        self.assertEqual(e.client_id,identifier('192.0.2.1'));self.assertEqual(e.line_number,19)
        self.assertEqual(e.response_bytes,50);self.assertIsNone(e.authenticated_user_id)
        self.assertIsNone(e.session_id);self.assertIsNone(e.role)

    def test_timezone_converts_to_utc(self):
        e=parse_line(LINE.replace('17:02:03 +0000','22:02:03 +0500'),'a','b',1)
        self.assertEqual(e.timestamp.hour,17)

    def test_optional_bytes_and_auth_identity(self):
        e=parse_line(LINE.replace(' - - [',' - alice [').replace('200 50','200 -'),'a','b',1)
        self.assertIsNone(e.response_bytes)
        self.assertEqual(e.authenticated_user_id,identifier('alice'))
        self.assertIsNone(e.role)
        f=extract([e]);self.assertEqual(f['identity_observed_ratio'],1)
        self.assertEqual(f['response_bytes_observed_ratio'],0)

    def test_malformed_lines_are_rejected_not_invented(self):
        for line in ('nonsense',LINE.replace('05/Sep','35/Sep'),LINE.replace('200 50','999 50'),LINE.replace('HTTP/1.1','nonsense'),LINE.replace('200 50','200 -1')):
            with self.subTest(line=line), self.assertRaises(ValueError): parse_line(line,'a','b',1)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sample.log';path.write_text(LINE+'\nbad line\n')
            rows,errors,sha=read_log(path)
            self.assertEqual(len(rows),1);self.assertEqual(errors[0]['line_number'],2)
            self.assertNotIn('bad line',json.dumps(errors));self.assertEqual(sha,digest(path))

    def test_apache_escaped_query_does_not_disappear(self):
        line=LINE.replace('/app/course?id=7',r'/app/course?q=\x27OR\x201=1--')
        e=parse_line(line,'a','b',1)
        self.assertIn("'OR 1=1--",e.query)
        self.assertGreater(extract([e])['sql_token_count'],0)

    def test_dummy_only_specific_infrastructure_signature(self):
        dummy='::1 - - [05/Sep/2026:17:02:03 +0000] "OPTIONS * HTTP/1.0" 200 126 "-" "Apache (internal dummy connection)"'
        self.assertTrue(parse_line(dummy,'a','b',1).infrastructure_dummy)
        self.assertFalse(parse_line(dummy.replace('::1','192.0.2.1'),'a','b',1).infrastructure_dummy)
        self.assertFalse(parse_line(LINE,'a','b',1).infrastructure_dummy)

    def test_no_post_body_role_or_secret_export(self):
        e=event(method='POST',query='password=private-value',referrer='https://host/?token=private-token')
        self.assertIsNone(e.role);self.assertIsNone(e.session_id)
        evidence=json.dumps(e.safe_evidence())
        self.assertNotIn('private-value',evidence);self.assertNotIn('private-token',evidence)
        self.assertNotIn('request_body',e.safe_evidence())


class WindowFeatureTests(Offline):
    def test_epoch_fixed_windows_boundary_and_order(self):
        observations=[event(10),event(9),event(0)]
        a=list(windows(observations));b=list(windows(reversed(observations)))
        self.assertEqual(a,b);self.assertEqual(len(a),2)
        self.assertEqual(len(a[0]['events']),2)
        self.assertEqual(a[0]['window_start'],'2026-09-05T17:02:00+00:00')
        self.assertEqual(a[1]['window_end'],'2026-09-05T17:02:20+00:00')
        self.assertEqual(list(windows([])),[])
        with self.assertRaises(ValueError): list(windows(observations,0))

    def test_client_and_agent_groups_are_deterministic(self):
        observations=[event(1),event(1,client_id='other'),event(1,user_agent='Other')]
        self.assertEqual(len(list(windows(observations))),3)

    def test_feature_determinism_and_semantics(self):
        observations=[event(2,status=404),event(0,method='POST'),event(4,path='/app/admin/index.php')]
        f=extract(observations)
        self.assertEqual(f,extract(list(reversed(observations))))
        self.assertEqual(list(f),list(FEATURES));self.assertEqual(f['request_count'],3)
        self.assertEqual(f['request_rate'],.3);self.assertEqual(f['active_span'],4)
        self.assertAlmostEqual(f['client_error_ratio'],1/3)
        self.assertEqual(f['response_bytes_total'],150)
        self.assertEqual(f['admin_request_count'],1)

    def test_security_query_indicators_and_double_encoding(self):
        e=event(query="q=%27+UNION+SELECT+1--&x=%3Cscript%3E&file=%252e%252e%252fetc")
        f=extract([e]);self.assertGreater(f['quote_count'],0)
        self.assertGreater(f['comment_sequence_count'],0);self.assertGreater(f['sql_token_count'],0)
        self.assertGreater(f['xss_marker_count'],0);self.assertGreater(f['traversal_count'],0)
        self.assertGreater(f['url_encoded_ratio'],0);self.assertEqual(f['parameter_count_total'],3)
        self.assertEqual(f['suspicious_query_ratio'],1)

    def test_optional_missing_neutral_and_not_role_inferred_from_path(self):
        f=extract([event(path='/admin/index.php',query='',response_bytes=None)])
        for key in ('identity_observed_ratio','unique_users','session_observed_ratio','unique_sessions','role_observed_ratio','unique_roles','privileged_role_request_ratio'):
            self.assertEqual(f[key],0)
        self.assertEqual(f['admin_request_count'],1)
        self.assertEqual(f['response_bytes_observed_ratio'],0)

    def test_observed_session_and_role_supported_by_future_adapter(self):
        f=extract([event(authenticated_user_id='u',session_id='s',role='administrator')])
        self.assertEqual(f['unique_sessions'],1);self.assertEqual(f['unique_roles'],1)
        self.assertEqual(f['privileged_role_request_ratio'],1)

    def test_feature_order_and_schema_hash_compatibility(self):
        s=schema();row={'schema_sha256':s['sha256'],'features':extract([event()])}
        self.assertEqual(matrix([row],s).shape,(1,len(FEATURES)))
        reversed_schema=copy.deepcopy(s);reversed_schema['feature_order'].reverse()
        with self.assertRaises(ValueError): matrix([row],reversed_schema)
        row['schema_sha256']='wrong'
        with self.assertRaises(ValueError): matrix([row],s)


class DatasetTests(Offline):
    @classmethod
    def setUpClass(cls): cls.data=actual()

    def test_real_inventory_windows_and_dummy_outside_handling(self):
        self.assertEqual(self.data['qa']['run_count'],14)
        self.assertEqual(len(self.data['rows']),72)
        self.assertEqual(sum(r['excluded_dummy_events'] for r in self.data['runs']),5)
        self.assertEqual(sum(r['outside_capture_events'] for r in self.data['runs']),1)
        self.assertEqual(sum(r['included_events'] for r in self.data['runs']),961)
        self.assertFalse(next(r for r in self.data['runs'] if r['scenario']=='TEST')['included'])
        for row in self.data['rows']:
            self.assertIn('source_sha256',row);self.assertTrue(row['line_numbers'])
        self.assertTrue(any(r['duration_discrepancy'] for r in self.data['runs']))

    def test_class_sufficiency_does_not_create_missing_classes(self):
        report=self.data['sufficiency']
        self.assertTrue(report['BRUTE_FORCE']['provisional_eligible'])
        self.assertFalse(report['ENUMERATION_RECONNAISSANCE']['provisional_eligible'])
        self.assertEqual(report['SQLI_ATTEMPT']['independent_runs'],0)
        self.assertEqual(report['SQLI_ATTEMPT']['additional_runs_required'],10)
        self.assertEqual(report['BENIGN']['additional_runs_required'],5)

    def test_split_complete_runs_isolated_reproducible(self):
        a=split_runs(self.data);self.assertEqual(a,split_runs(self.data))
        self.assertFalse(set(a['train_runs'])&set(a['test_runs']))
        train_rows,test_rows=partition(self.data['rows'],a)
        self.assertFalse({r['run_id'] for r in train_rows}&{r['run_id'] for r in test_rows})
        self.assertEqual(len(train_rows)+len(test_rows),len(self.data['rows']))
        self.assertEqual(set(a['eligible_xgb_classes']),{'BENIGN','BRUTE_FORCE'})

    def test_singleton_strata_excluded_and_overlap_rejected(self):
        d=copy.deepcopy(self.data)
        d['runs'][0].update(included=True,label='BENIGN',windows=1)
        split=split_runs(d)
        self.assertIn('TEST-run01',split['unassigned_runs'])
        bad={'train_runs':['a'],'test_runs':['a']}
        with self.assertRaises(ValueError): partition([],bad)

    def test_historical_sources_remain_byte_identical(self):
        paths=list((ROOT/'data/raw').glob('*'))+list((ROOT/'experiments').glob('*.csv'))+list((ROOT/'outputs/behavioral_v3').glob('*'))
        paths=[p for p in paths if p.is_file()]
        before={str(p):digest(p) for p in paths}
        self.assertEqual(actual(),actual())
        self.assertEqual(before,{str(p):digest(p) for p in paths})

    def test_duplicate_manifest_run_and_unknown_scenario_fail_closed(self):
        metadata=ROOT/'experiments/experiment_metadata.csv'
        with tempfile.TemporaryDirectory() as directory:
            copied=Path(directory)/'meta.csv';copied.write_text(metadata.read_text()+metadata.read_text().splitlines()[1]+'\n')
            with self.assertRaisesRegex(ValueError,'Duplicate run'): build(ROOT,copied,ROOT/'experiments/branch2_v2_labels.json')
            labels=json.loads((ROOT/'experiments/branch2_v2_labels.json').read_text());del labels['scenarios']['B01']
            mapped=Path(directory)/'labels.json';mapped.write_text(json.dumps(labels))
            with self.assertRaisesRegex(ValueError,'Explicit scenario'): build(ROOT,metadata,mapped)

    def test_reused_capture_and_overlapping_run_intervals_rejected(self):
        metadata=ROOT/'experiments/experiment_metadata.csv'
        with metadata.open() as f: records=list(csv.DictReader(f))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'manifest.csv'
            for mode in ('duplicate','overlap'):
                changed=copy.deepcopy(records)
                if mode=='duplicate': changed[2]['access_file']=changed[1]['access_file']
                else:
                    changed[4]['start_utc']=changed[1]['start_utc']
                    changed[4]['end_utc']=changed[1]['end_utc']
                with path.open('w',newline='') as f:
                    writer=csv.DictWriter(f,fieldnames=records[0].keys());writer.writeheader();writer.writerows(changed)
                with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'Duplicate capture|Overlapping capture'):
                    build(ROOT,path,ROOT/'experiments/branch2_v2_labels.json')

    def test_outputs_never_overwrite_historical_files(self):
        for path in (ROOT/'outputs/behavioral_v3/new',ROOT/'legacy/new',ROOT/'data/raw/new',ROOT/'outputs/branch2'):
            with self.assertRaises(ValueError): new_output(path,ROOT)


class ModelTests(Offline):
    @classmethod
    def setUpClass(cls):
        cls.data=actual();cls.split=split_runs(cls.data)
        cls.package,cls.test_rows=train(cls.data,cls.split,if_only=True)

    def test_if_only_benign_training_and_no_test_fitting(self):
        metadata=self.package.metadata
        self.assertEqual(metadata['if_training_labels'],['BENIGN'])
        self.assertFalse(set(metadata['if_training_run_ids'])&set(self.split['test_runs']))
        train_rows,_=partition(self.data['rows'],self.split)
        self.assertEqual(metadata['if_training_windows'],sum(r['label']=='BENIGN' for r in train_rows))
        self.assertEqual(metadata['if_config']['n_jobs'],1)

    def test_fixed_seed_training_reproducibility(self):
        second,rows=train(self.data,self.split,if_only=True)
        self.assertEqual(self.package.predict(rows),second.predict(rows))

    def test_saved_model_inference_without_retraining_preserves_predictions(self):
        predictions=self.package.predict(self.test_rows)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'package'
            save(self.package,path,self.split,evaluate(predictions,[]),predictions,'dataset-test-digest')
            loaded=load(path)
            with patch('sklearn.ensemble.IsolationForest.fit',side_effect=AssertionError('Inference must not fit')):
                self.assertEqual(predictions,loaded.predict(self.test_rows))
            manifest=json.loads((path/'package_manifest.json').read_text())
            self.assertFalse(manifest['complete_parallel_package'])
            self.assertFalse((path/'xgboost.json').exists())
            with self.assertRaises(ValueError): save(self.package,path,self.split,{},[],'d')
            (path/'feature_schema.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'integrity'): load(path)

    def test_unavailable_xgboost_explicit_failure_no_substitute(self):
        with patch.dict(sys.modules,{'xgboost':None}), self.assertRaisesRegex(ValueError,'XGBoost unavailable'):
            train(self.data,self.split)

    def test_xgb_training_interface_eligible_classes_seed_and_benign_if_parallel(self):
        mock=MagicMock()
        fake=SimpleNamespace(XGBClassifier=mock)
        with patch.dict(sys.modules,{'xgboost':fake}):
            package,_=train(self.data,self.split)
        self.assertEqual(mock.call_args.kwargs['objective'],'multi:softprob')
        self.assertEqual(mock.call_args.kwargs['num_class'],2)
        self.assertEqual(mock.call_args.kwargs['random_state'],42)
        x,y=mock.return_value.fit.call_args.args
        self.assertEqual(set(y),{0,1});self.assertEqual(x.shape[1],len(FEATURES))
        self.assertEqual(package.metadata['if_training_run_ids'],self.package.metadata['if_training_run_ids'])
        self.assertFalse(set(package.metadata['xgb_training_run_ids'])&set(self.split['test_runs']))

    @unittest.skipUnless(importlib.util.find_spec('xgboost') is not None,'Real XGBoost integration requires requirements/branch2.txt; no substitute')
    def test_real_xgboost_save_load_predictions(self):
        package,rows=train(self.data,self.split)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'full';predictions=package.predict(rows)
            save(package,path,self.split,evaluate(predictions,package.classes),predictions,'d')
            loaded=load(path)
            self.assertEqual(predictions,loaded.predict(rows))

    def test_metrics_raw_scores_and_undefined_ratios_reported(self):
        p=self.package.predict(self.test_rows)
        metrics=evaluate(p,[])
        self.assertEqual(metrics['xgboost']['status'],'NOT_EVALUATED')
        self.assertEqual(metrics['isolation_forest']['support'],len(p))
        self.assertEqual(binary_metrics([False],[False])['precision'],None)
        self.assertFalse(p[0]['anomaly_severity_is_probability'])
        self.assertIsNone(p[0]['xgb_confidence'])

    def test_multiclass_metric_artifacts_and_ineligible_exclusion(self):
        predictions=[]
        for index,(truth,predicted) in enumerate([('BENIGN','BENIGN'),('BRUTE_FORCE','BENIGN'),('SQLI_ATTEMPT','BRUTE_FORCE')]):
            predictions.append({'label':truth,'xgb_label':predicted,'if_anomalous':truth!='BENIGN',
                'if_raw_anomaly_score':.5,'run_id':'fixture-'+str(index)})
        metrics=evaluate(predictions,['BENIGN','BRUTE_FORCE'])['xgboost']
        self.assertEqual(metrics['confusion_matrix'],[[1,0],[1,0]])
        self.assertEqual(metrics['support'],2)
        self.assertEqual(metrics['excluded_ineligible_windows'],1)
        self.assertEqual(metrics['overall_accuracy'],.5)
        self.assertEqual(metrics['per_class']['BRUTE_FORCE']['recall'],0)

    def test_inference_rejects_incompatible_future_schema(self):
        rows=copy.deepcopy(self.test_rows)
        rows[0]['schema_sha256']='future-version'
        with self.assertRaisesRegex(ValueError,'schema mismatch'): self.package.predict(rows)

    def test_inference_does_not_require_ground_truth_labels(self):
        rows=copy.deepcopy(self.test_rows)
        for row in rows: row.pop('label');row.pop('scenario')
        results=self.package.predict(rows)
        expected=self.package.predict(self.test_rows)
        self.assertTrue(all(r['label'] is None and r['scenario'] is None for r in results))
        self.assertEqual([r['if_decision_function'] for r in results],[r['if_decision_function'] for r in expected])

    def test_train_rejects_seed_change_and_missing_benign(self):
        with self.assertRaisesRegex(ValueError,'seeds'): train(self.data,self.split,if_only=True,seed=7)
        d=copy.deepcopy(self.data)
        d['rows']=[r for r in d['rows'] if r['label']!='BENIGN']
        with self.assertRaisesRegex(ValueError,'benign training'): train(d,self.split,if_only=True)


class ReconciliationExplainTests(Offline):
    def test_all_parallel_reconciliation_branches(self):
        self.assertEqual(reconcile(True,'SQLI_ATTEMPT',.9)['reason'],'KNOWN_ATTACK_WITH_ANOMALY_SUPPORT')
        self.assertEqual(reconcile(True,'SQLI_ATTEMPT',.2)['decision'],'UNKNOWN_ANOMALY')
        self.assertEqual(reconcile(True,'BENIGN',.9)['decision'],'UNKNOWN_ANOMALY')
        self.assertTrue(reconcile(True,'BENIGN',.9)['model_disagreement'])
        self.assertEqual(reconcile(False,'SQLI_ATTEMPT',.9)['decision'],'SQLI_ATTEMPT')
        self.assertTrue(reconcile(False,'SQLI_ATTEMPT',.9)['model_disagreement'])
        self.assertEqual(reconcile(False,'BENIGN',.9)['decision'],'BENIGN')
        self.assertEqual(reconcile(False,'BENIGN',.2)['decision'],'UNCERTAIN')
        self.assertEqual(reconcile(True,None,None)['decision'],'UNKNOWN_ANOMALY')
        self.assertEqual(reconcile(False,None,None)['decision'],'UNCERTAIN')
        with self.assertRaises(ValueError): reconcile(False,'BENIGN',float('nan'))

    def test_robust_deviation_zero_mad_feature_not_hidden(self):
        reference=benign_reference(np.zeros((10,len(FEATURES))))
        value=np.zeros(len(FEATURES));value[FEATURES.index('sql_token_count')]=4
        result=deviations(value,reference)
        self.assertEqual(result['top_features'][0]['feature'],'sql_token_count')
        self.assertEqual(result['top_features'][0]['absolute_deviation'],4)
        self.assertFalse(result['causal'])

    def test_shap_missing_and_incompatible_fallback(self):
        x=np.zeros((2,len(FEATURES)))
        with patch.dict(sys.modules,{'shap':None}):
            results=ShapExplainer(object()).explain(x,[0,1])
        self.assertEqual(results[0]['status'],'DEPENDENCY_UNAVAILABLE')
        fake=SimpleNamespace(TreeExplainer=MagicMock(side_effect=RuntimeError('incompatible')))
        self.assertEqual(ShapExplainer(object(),fake).explain(x,[0,1])[0]['status'],'INCOMPATIBLE_IMPLEMENTATION')

    def test_shap_top_contributions_modern_and_legacy_multiclass_shapes(self):
        x=np.zeros((2,len(FEATURES)))
        array=np.zeros((2,len(FEATURES),2));array[0,3,0]=7;array[1,5,1]=-9
        for raw in (array,[array[:,:,0],array[:,:,1]]):
            explainer=MagicMock();explainer.shap_values.return_value=raw
            fake=SimpleNamespace(TreeExplainer=MagicMock(return_value=explainer))
            result=ShapExplainer(object(),fake).explain(x,[0,1])
            self.assertEqual(result[0]['top_features'][0]['feature'],FEATURES[3])
            self.assertEqual(result[1]['top_features'][0]['contribution'],-9)
            self.assertFalse(result[0]['causal'])


if __name__=='__main__':unittest.main()
