"""Synthetic paired-evaluation tests; no real TEST records, models or requests."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('blind_benign_eval',ROOT/'scripts/run_m5_blind_benign_evaluation.py')
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)


def predictions(run='UNIT-1',n=3,anomalous=(),decisions=None,label='BENIGN'):
    rows=[]
    for i in range(n):
        decision=decisions[i] if decisions else ('UNKNOWN_ANOMALY' if i in anomalous else 'BENIGN')
        rows.append({'run_id':run,'label':'BENIGN','partition':'TEST',
            'window_start':f'2021-01-01T00:00:{i*10:02d}+00:00',
            'window_end':f'2021-01-01T00:00:{(i+1)*10:02d}+00:00',
            'client_id':'UNIT-CLIENT','user_agent_id':'UNIT-AGENT','source_file':'UNIT-LOG',
            'source_sha256':'a'*64,'line_numbers':[i+1],
            'novelty_anomalous':i in anomalous,'if_anomalous':i in anomalous,
            'novelty_score':.1 if i in anomalous else .5,'novelty_threshold':.3,
            'if_raw_anomaly_score':.6 if i in anomalous else .2,
            'xgb_label':label,'xgb_confidence':.9,
            'reconciliation':{'decision':decision,'model_disagreement':i in anomalous}})
    return rows


class PairedMetricTests(unittest.TestCase):
    def test_raw_anomalies_separate_from_persistence_alerts(self):
        m=tool.summarize(predictions(anomalous=(1,)),2,.8,candidate=True)
        self.assertEqual(m['novelty']['anomalous_windows'],1)
        self.assertEqual(m['novelty']['raw_run_FPR'],1)
        self.assertEqual(m['reconciliation']['UNKNOWN_ANOMALY'],1)
        self.assertEqual(m['episode']['alert_episodes'],0)

    def test_contiguous_unknown_windows_form_single_alert_episode(self):
        m=tool.summarize(predictions(anomalous=(0,1)),2,.8,candidate=True)
        self.assertEqual(m['episode']['alert_episodes'],1)
        self.assertEqual(m['episode']['benign_runs_alerted'],1)

    def test_false_known_classifications_not_hidden_by_reconciliation(self):
        ps=predictions(label='SQLI_ATTEMPT',decisions=['UNCERTAIN']*3)
        for p in ps:p['xgb_confidence']=.4
        m=tool.summarize(ps,2,.8,candidate=True)
        self.assertEqual(m['xgboost']['false_known_attack_windows'],3)
        self.assertEqual(m['reconciliation']['false_known_attempt_windows'],0)
        self.assertEqual(m['xgboost']['false_classes'],{'SQLI_ATTEMPT':3})

    def test_nonbenign_truth_rejected(self):
        ps=predictions();ps[0]['label']='SQLI_ATTEMPT'
        with self.assertRaises(ValueError):tool.summarize(ps,2,.8,candidate=True)

    def test_score_summary_direction_is_explicit_not_probability(self):
        m=tool.summarize(predictions(),1,.8,candidate=False)
        self.assertIn('higher is more anomalous',m['novelty']['score_semantics'])
        self.assertFalse(m['novelty']['score_summary']['is_probability'])

    def test_exact_paired_window_alignment_and_order(self):
        ps=predictions();b=list(reversed(copy.deepcopy(ps)))
        windows,sessions=tool.paired(ps,b,{'UNIT-1':'UNIT-PROTOCOL'},2,.8,.8)
        self.assertEqual(len(windows),3);self.assertEqual(len(sessions),1)
        b[0]['line_numbers']=[99]
        with self.assertRaises(ValueError):tool.paired(ps,b,{'UNIT-1':'UNIT-PROTOCOL'},2,.8,.8)

    def test_duplicate_windows_not_manufactured_as_pairs(self):
        ps=predictions();ps.append(copy.deepcopy(ps[0]))
        with self.assertRaises(ValueError):tool.paired(ps,ps,{'UNIT-1':'UNIT-PROTOCOL'},2,.8,.8)

    def test_predeclared_pass_mixed_fail_and_no_rule(self):
        ps=sum((predictions(run=f'UNIT-{i}') for i in range(6)),[])
        normal=tool.summarize(ps,2,.8,candidate=True)
        self.assertEqual(tool.classification(normal,normal,tool.capture_tool.CLASSIFICATION_RULE,6)['result'],'BENIGN_TEST_PASS')
        mixed=copy.deepcopy(normal);mixed['novelty']['anomalous_windows']=1
        self.assertEqual(tool.classification(mixed,normal,tool.capture_tool.CLASSIFICATION_RULE,6)['result'],'BENIGN_TEST_MIXED')
        failed=copy.deepcopy(normal);failed['episode']['benign_runs_alerted']=3
        self.assertEqual(tool.classification(failed,normal,tool.capture_tool.CLASSIFICATION_RULE,6)['result'],'BENIGN_TEST_FAIL')
        self.assertEqual(tool.classification(normal,normal,None,6)['result'],'BENIGN_TEST_DESCRIPTIVE_ONLY')
        with self.assertRaises(ValueError):tool.classification(normal,normal,{'PASS':'post-hoc'},6)

    def test_regression_boundary_uses_exact_fraction(self):
        ps=sum((predictions(run=f'UNIT-{i}') for i in range(6)),[])
        m=tool.summarize(ps,2,.8,candidate=True);c=copy.deepcopy(m);c['episode']['benign_runs_alerted']=2
        self.assertTrue(tool.classification(c,m,tool.capture_tool.CLASSIFICATION_RULE,6)['fail_checks']['episode_rate_regression_at_least_one_third'])


class EvaluationArtifactTests(unittest.TestCase):
    def test_refuses_existing_evaluation_before_any_model_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'outputs/branch2/m5_final_day/blind_benign_test_01/evaluation').mkdir(parents=True)
            with patch.object(tool.capture_tool,'integrity',side_effect=AssertionError('No models before overwrite guard')):
                with self.assertRaises(ValueError):tool.evaluate(tmp)

    def test_main_blocks_all_fit_methods_and_network_connections(self):
        def checked(root):
            import socket
            from sklearn.svm import OneClassSVM
            from sklearn.neighbors import LocalOutlierFactor
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import RobustScaler
            from xgboost import XGBClassifier
            for model in (OneClassSVM(),LocalOutlierFactor(novelty=True),IsolationForest(),RobustScaler(),XGBClassifier()):
                with self.assertRaises(AssertionError):model.fit([[0],[1]])
            with self.assertRaises(AssertionError):socket.create_connection(('example.invalid',80))
            return {'classification':{'result':'UNIT'},'candidate':{'windows':0}}
        with patch.object(tool,'evaluate',side_effect=checked),patch('builtins.print'):
            self.assertEqual(tool.main(),0)

    def test_paired_provenance_attachment_preserves_model_decisions(self):
        rows=predictions();model=SimpleNamespace(predict=lambda values:[{k:v for k,v in p.items() if k not in ('client_id','user_agent_id','line_numbers','partition')} for p in values])
        original=copy.deepcopy(rows);result=tool.aligned_predictions(model,rows)
        self.assertEqual(rows,original);self.assertEqual([tool.key(p) for p in result],[tool.key(p) for p in rows])
        self.assertEqual([p['reconciliation'] for p in result],[p['reconciliation'] for p in rows])


if __name__=='__main__':unittest.main()
