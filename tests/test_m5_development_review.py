"""Development gates and freeze integrity: synthetic fixtures, never real TEST."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from behavioral_v2.browser_capture import make_plan,digest
from behavioral_v2.development_review import review_development,require_development_review
from behavioral_v2.study31 import build_development,verify_freeze,validation_run_metrics
import test_m5_final_day as fixtures
from test_m5_final_day import unit_development_review


class DevelopmentReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.plan=make_plan()
        (self.root/'predeclared_capture_plan.json').write_text(json.dumps(self.plan))
        for s in self.plan['sessions']:
            if s['partition']=='TEST':continue
            p=self.root/'browser_sessions'/s['session_id'];p.mkdir(parents=True)
            m={'session_id':s['session_id'],'partition':s['partition'],'protocol':s['protocol'],
                'status':'COMPLETE','label':'BENIGN','windows':1,'error_code':None}
            (p/'manifest.json').write_text(json.dumps(m))
            (p/'features.json').write_text('[]');(p/'v1_features.json').write_text('[]')
        self.review=unit_development_review(self.root,self.plan)

    def test_pass_review_required_before_any_source_rebuild(self):
        (self.root/'development_review.json').unlink()
        with patch('behavioral_v2.study31.read_log',side_effect=AssertionError('No raw read before gate')):
            with self.assertRaises(OSError):build_development(self.root,{'rows':[]},{},self.root)

    def test_review_pass_and_capture_hashes_bound(self):
        checked=require_development_review(self.root,self.plan)
        self.assertEqual(checked['status'],'PASS');self.assertEqual(len(checked['capture_files_sha256']),54)
        self.assertFalse(checked['selection_metrics_consulted'])
        p=self.root/'browser_sessions/M5FD-20261014-004/features.json';p.write_text('[1]')
        with self.assertRaisesRegex(ValueError,'Reviewed capture changed'):require_development_review(self.root,self.plan)

    def test_review_fail_and_changed_checksum_refused(self):
        r=copy.deepcopy(self.review);r['status']='FAIL';r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        (self.root/'development_review.json').write_text(json.dumps(r))
        with self.assertRaises(ValueError):require_development_review(self.root,self.plan)
        r=copy.deepcopy(self.review);r['included_browser_sessions'][0]['partition']='TEST'
        (self.root/'development_review.json').write_text(json.dumps(r))
        with self.assertRaises(ValueError):require_development_review(self.root,self.plan)

    def test_original_plan_byte_changes_refused(self):
        p=self.root/'predeclared_capture_plan.json';p.write_text(p.read_text()+'\n')
        with self.assertRaises(ValueError):require_development_review(self.root,self.plan)

    def test_collection_summary_mutation_refused(self):
        (self.root/'unit_collection.json').write_text('{}')
        with self.assertRaises(ValueError):require_development_review(self.root,self.plan)

    def test_explicit_invalid_exclusions_and_no_test_replay(self):
        excluded=['M5FD-20261014-001','M5FD-20261014-002','M5FD-20261014-003']
        for sid in excluded:
            p=self.root/'browser_sessions'/sid/'manifest.json';m=json.loads(p.read_text())
            m.update(status='INVALID',label=None,windows=0,error_code='UNIT_FAILURE');p.write_text(json.dumps(m))
        summary=json.loads((self.root/'unit_collection.json').read_text())
        summary['verification_receipts']=[r for r in summary['verification_receipts'] if r['session_id'] not in excluded]
        (self.root/'unit_collection.json').write_text(json.dumps(summary));calls=[]
        def verified(unused,plan,sid):
            calls.append(sid);self.assertNotIn(sid,excluded)
            self.assertNotEqual(next(s['partition'] for s in plan['sessions'] if s['session_id']==sid),'TEST')
            return {'verified':True,'accepted_records':1,'foreign_records':0,'ownership_filtering_reproduced':True,
                'source_bytes_verified':True,'network_requests':0}
        with patch('behavioral_v2.development_review.verify_capture',side_effect=verified),patch('behavioral_v2.development_review.frozen_core_unchanged',return_value=True):
            result=review_development(self.root,self.root/'unit_collection.json',excluded,self.root)
        self.assertEqual(result['status'],'PASS');self.assertEqual(len(calls),15)
        self.assertEqual(len(result['excluded_browser_sessions']),3)

    def test_failed_core_check_blocks_review(self):
        with patch('behavioral_v2.development_review.verify_capture',return_value={
            'verified':True,'accepted_records':1,'foreign_records':0,'ownership_filtering_reproduced':True,
            'source_bytes_verified':True,'network_requests':0}),patch('behavioral_v2.development_review.frozen_core_unchanged',return_value=False):
            r=review_development(self.root,self.root/'unit_collection.json',[],self.root)
        self.assertEqual(r['status'],'FAIL')


class CompleteFreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=fixtures.ModelFreezeTests;cls.fixture.setUpClass()
    @classmethod
    def tearDownClass(cls):cls.fixture.tearDownClass()

    def test_freeze_hash_table_and_pretest_flags(self):
        p=self.fixture.root/'candidate_01';f=json.loads((p/'freeze_manifest.json').read_text())
        self.assertEqual(f['root_sha256'],digest({k:v for k,v in f.items() if k!='root_sha256'}))
        self.assertTrue(f['candidate_id'].startswith('m5-v3.1-'))
        for name in ('TEST_ACCESSED_BEFORE_FREEZE','TEST_USED_FOR_SELECTION','FRESH_ATTACK_HOLDOUT_USED_FOR_SELECTION'):
            self.assertIs(f[name],False)
        for name,value in f['artifact_files_sha256'].items():
            self.assertEqual(hashlib.sha256((p/name).read_bytes()).hexdigest(),value)
        self.assertIn('validation_run_metrics.json',f['artifact_files_sha256'])

    def test_metric_tamper_or_extra_file_invalidates_freeze(self):
        for mode in ('changed','extra'):
            with tempfile.TemporaryDirectory() as tmp:
                dest=Path(tmp)/'candidate';shutil.copytree(self.fixture.root/'candidate_01',dest)
                (dest/('validation_metrics.json' if mode=='changed' else 'extra.json')).write_text('{}')
                with self.assertRaises(ValueError):verify_freeze(dest/'freeze_manifest.json')

    def test_validation_run_aggregation_is_order_invariant(self):
        rows=[r for r in self.fixture.data['rows'] if r['partition']=='VALIDATION']
        ps=self.fixture.package.predict(rows,explain=False)
        self.assertEqual(validation_run_metrics(ps,self.fixture.package.classes),validation_run_metrics(list(reversed(ps)),self.fixture.package.classes))

    def test_missing_freeze_rejected_without_training(self):
        with patch('sklearn.ensemble.IsolationForest.fit',side_effect=AssertionError('No fitting')):
            with self.assertRaises(OSError):verify_freeze(self.fixture.root/'missing.json')


if __name__=='__main__':unittest.main()
