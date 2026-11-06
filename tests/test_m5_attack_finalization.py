"""Synthetic attack reporting contracts; no real evidence, fitting or traffic."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('attack_finalization',ROOT/'scripts/run_m5_attack_finalization.py')
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
from branch2.dataset import CLASSES
from branch2.reconciliation import reconcile


def fixture(label='SQLI_ATTEMPT',guess='SQLI_ATTEMPT',anomaly=False):
    classes=sorted(CLASSES);values=[]
    for i in range(2):
        scores=[.01]*len(classes);scores[classes.index(guess)]=.93
        values.append({'run_id':'UNRELATED-NAME','label':label,'window_start':f'2020-01-01T00:00:{10*i:02d}+00:00',
            'window_end':f'2020-01-01T00:00:{10*(i+1):02d}+00:00','client_id':'fixture','user_agent_id':'fixture',
            'novelty_anomalous':anomaly,'if_anomalous':anomaly,'xgb_label':guess,'xgb_scores':scores,
            'reconciliation':reconcile(anomaly,guess,.93,.8)})
    return values


class AttackFinalizationTests(unittest.TestCase):
    def test_plan_label_truth_not_run_prefix_and_novelty_separate(self):
        m=tool.attack_metrics(fixture(),sorted(CLASSES),2,True)
        self.assertEqual(m['per_class']['SQLI_ATTEMPT']['runs'],1)
        self.assertEqual(m['novelty']['detected_runs'],0)
        self.assertEqual(m['reconciled']['detected_runs'],1)
        self.assertEqual(m['xgboost']['correct_class_runs'],1)

    def test_unknown_detection_separate_from_correct_known_class(self):
        m=tool.attack_metrics(fixture(guess='BENIGN',anomaly=True),sorted(CLASSES),2,True)
        self.assertEqual(m['reconciled']['UNKNOWN_detected_runs'],1)
        self.assertEqual(m['reconciled']['correct_known_alert_runs'],0)
        self.assertEqual(m['xgboost']['BENIGN_miss_windows'],2)

    def test_wrong_known_class_detected_but_not_correct(self):
        m=tool.attack_metrics(fixture(guess='XSS_ATTEMPT'),sorted(CLASSES),2,True)
        self.assertEqual(m['reconciled']['detected_runs'],1)
        self.assertEqual(m['xgboost']['detected_wrong_class_runs'],1)
        self.assertEqual(m['reconciled']['correct_known_alert_runs'],0)

    def test_isolated_unknown_observation_not_incident(self):
        m=tool.attack_metrics(fixture(guess='BENIGN',anomaly=True)[:1],sorted(CLASSES),2,True)
        self.assertEqual(m['reconciled']['detected_windows'],1)
        self.assertEqual(m['reconciled']['detected_runs'],0)
        self.assertEqual(m['reconciled']['missed_runs'],1)


if __name__=='__main__':unittest.main()
