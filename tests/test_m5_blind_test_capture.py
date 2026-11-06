"""Blind TEST orchestration fixtures only: no real logs, traffic or inference."""
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('blind_capture_tool',ROOT/'scripts/run_m5_blind_test_capture.py')
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
from behavioral_v2.browser_capture import make_plan


class BlindCollectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.project=Path(self.tmp.name);self.root=self.project/'outputs/branch2/m5_final_day'
        self.candidate=self.root/'candidate_freeze_01';self.candidate.mkdir(parents=True)
        (self.candidate/'freeze_manifest.json').write_text('{}')
        self.dataset=self.project/'data/dataset.json';self.dataset.parent.mkdir();self.dataset.write_text('{}')
        self.out=self.root/'blind_benign_test_01';self.plan=make_plan()
        self.sessions=sorted((s for s in self.plan['sessions'] if s['partition']=='TEST'),key=lambda s:s['session_id'])
        self.freeze={'candidate_id':tool.EXPECTED_ID,'root_sha256':tool.EXPECTED_ROOT,
            'frozen_at_utc':'2020-01-01T00:00:00+00:00','schema_sha256':'UNIT-SCHEMA'}
        self.checked={'status':'PASS','candidate_id':tool.EXPECTED_ID,'candidate_canonical_root_sha256':tool.EXPECTED_ROOT,
            'classification_rule':tool.CLASSIFICATION_RULE}
        with patch.object(tool,'integrity',return_value=(self.plan,self.freeze,self.checked)):
            tool.prepare(self.root,self.candidate,self.dataset,self.out,self.project)
        self.calls=[];self.verifications=[];self.outcomes={};self.verify_failure=None
        self.ready={'target_authorized':True,'credentials_present':True,'identity_marker_present':True}

    def capture(self,plan,sid,out,*,authorized,actor,freeze_path):
        self.assertIn(sid,{s['session_id'] for s in self.sessions});self.assertTrue(authorized)
        self.assertEqual(freeze_path,self.candidate/'freeze_manifest.json')
        self.calls.append(sid);s=next(s for s in self.sessions if s['session_id']==sid)
        base=Path(out)/sid;base.mkdir(parents=True,exist_ok=False)
        status,code=self.outcomes.get(sid,('COMPLETE',None))
        m={'session_id':sid,'partition':'TEST','protocol':s['protocol'],'plan_sha256':plan['sha256'],
            'status':status,'error_code':code,'windows':1 if status=='COMPLETE' else 0,
            'label':'BENIGN' if status=='COMPLETE' else None,
            'provenance':{'start_utc':'2030-01-01T00:00:00+00:00','slice_sha256':'a'*64,
                'source_device':1,'source_inode':2,'offset_start':0,'offset_end':10,
                'attribution_policy':'capture-marker-and-actor-v1','session_marker_sha256':'b'*64,
                'observed_records':3,'accepted_records':2,'foreign_records':1},'fixture':'UNIT_TEST_ONLY'}
        for name,value in (('manifest.json',m),('features.json',[]),('v1_features.json',[])):
            (base/name).write_text(json.dumps(value))
        return m

    def verify(self,root,plan,sid):
        self.verifications.append(sid)
        if sid==self.verify_failure:raise ValueError('fixture-password token')
        return {'verified':True,'ownership_filtering_reproduced':True,'windows':1,'accepted_records':2,'foreign_records':1}

    def run_capture(self,**kwargs):
        with patch.object(tool,'integrity',return_value=(self.plan,self.freeze,self.checked)), \
            patch.object(tool,'capture',side_effect=self.capture),patch.object(tool,'verify_capture',side_effect=self.verify), \
            patch.object(tool,'readiness',return_value=self.ready),patch('builtins.print'), \
            patch.dict(tool.os.environ,{},clear=True),patch('socket.socket',side_effect=AssertionError('No network')):
            return tool.collect(self.root,self.candidate,self.dataset,self.out,self.project,**kwargs)

    def test_exact_six_test_sessions_verified_then_locked_without_metrics(self):
        result=self.run_capture(authorized=True)
        self.assertEqual(self.calls,[s['session_id'] for s in self.sessions]);self.assertEqual(self.calls,self.verifications)
        self.assertEqual(result['counts']['verified'],6);self.assertFalse(result['models_evaluated'])
        manifest=json.loads((self.out/'test_evidence_manifest.json').read_text())
        self.assertEqual(manifest['feature_schema_sha256'],'UNIT-SCHEMA')
        self.assertFalse(manifest['models_evaluated_before_lock']);self.assertTrue(manifest['no_test_to_development_transfer'])
        self.assertEqual(manifest['sha256'],tool.digest({k:v for k,v in manifest.items() if k!='sha256'}))
        self.assertEqual((self.out/'test_evidence_manifest.sha256').read_text().strip(),tool.sha(self.out/'test_evidence_manifest.json'))

    def test_resume_reverifies_without_recapture_or_lock_overwrite(self):
        self.run_capture(authorized=True);path=self.out/'test_evidence_manifest.json';raw=path.read_bytes()
        self.calls.clear();self.verifications.clear();self.run_capture(authorized=True)
        self.assertEqual(self.calls,[]);self.assertEqual(len(self.verifications),6);self.assertEqual(path.read_bytes(),raw)

    def test_missing_credentials_before_capture_or_new_outputs(self):
        self.ready['credentials_present']=False
        with self.assertRaises(tool.CaptureError):self.run_capture(authorized=True)
        self.assertEqual(self.calls,[]);self.assertFalse((self.out/'collection_runs').exists())

    def test_authorization_and_receipt_required(self):
        with self.assertRaises(tool.CaptureError):self.run_capture()
        (self.out/'pre_test_integrity.json').unlink()
        with self.assertRaises(OSError):self.run_capture(authorized=True)

    def test_dry_run_has_no_capture_verification_or_writes(self):
        a=self.run_capture(dry_run=True);b=self.run_capture(dry_run=True)
        self.assertEqual(a,b);self.assertEqual(a['network_requests'],0)
        self.assertEqual(self.calls,[]);self.assertEqual(self.verifications,[])
        self.assertFalse((self.out/'collection_runs').exists())

    def test_unavailable_kept_invalid_no_replacement(self):
        self.outcomes[self.sessions[0]['session_id']]=('INVALID','REQUIRED_RESOURCE_UNAVAILABLE')
        result=self.run_capture(authorized=True)
        self.assertEqual(result['counts']['INVALID'],1);self.assertEqual(result['counts']['verified'],5)
        self.assertEqual(result['counts']['unavailable'],1);self.assertEqual(len(self.calls),6)

    def test_unexpected_failure_stops_then_explicit_resume_preserves_failed_attempt(self):
        sid=self.sessions[0]['session_id'];self.outcomes[sid]=('INVALID','CONTAMINATED_CAPTURE')
        r=self.run_capture(authorized=True);self.assertEqual(r['status'],'STOPPED');self.assertEqual(len(self.calls),1)
        path=self.root/'browser_sessions'/sid/'manifest.json';raw=path.read_bytes();self.calls.clear()
        r=self.run_capture(authorized=True)
        self.assertNotIn(sid,self.calls);self.assertEqual(path.read_bytes(),raw)
        self.assertEqual(r['counts']['INVALID'],1);self.assertEqual(r['counts']['verified'],5)

    def test_verification_failure_stops_without_evidence_lock_or_secret_export(self):
        self.verify_failure=self.sessions[0]['session_id'];r=self.run_capture(authorized=True)
        self.assertEqual(r['status'],'STOPPED');self.assertFalse((self.out/'test_evidence_manifest.json').exists())
        self.assertNotIn('fixture-password',json.dumps(r))

    def test_locked_capture_mutation_blocks_before_any_new_requests(self):
        self.run_capture(authorized=True);self.calls.clear()
        (self.root/'browser_sessions'/self.sessions[0]['session_id']/'features.json').write_text('[1]')
        with self.assertRaises(tool.CaptureError):self.run_capture(authorized=True)
        self.assertEqual(self.calls,[])

    def test_train_validation_files_are_never_read_or_changed(self):
        for s in self.plan['sessions']:
            if s['partition']=='TEST':continue
            p=self.root/'browser_sessions'/s['session_id'];p.mkdir(parents=True)
            (p/'manifest.json').write_text('INVALID JSON MUST NOT BE OPENED')
        self.run_capture(authorized=True)
        for s in self.plan['sessions']:
            if s['partition']!='TEST':self.assertEqual((self.root/'browser_sessions'/s['session_id']/'manifest.json').read_text(),'INVALID JSON MUST NOT BE OPENED')

    def test_receipt_predeclares_classification_without_tuning(self):
        r=json.loads((self.out/'pre_test_integrity.json').read_text())
        self.assertTrue(r['test_captures_absent_at_gate'])
        self.assertIs(r['classification_rule']['selection_or_tuning_authorized'],False)


class PreTestGateTests(unittest.TestCase):
    def test_bad_freeze_blocks_before_any_test_directory_access(self):
        with patch.object(tool,'verify_freeze',side_effect=ValueError('Changed freeze')), \
            patch.object(Path,'exists',side_effect=AssertionError('TEST checked too early')):
            with self.assertRaises(ValueError):tool.integrity(Path('/fixture'),Path('/candidate'),Path('/dataset'),Path('/project'),require_absence=True)

    def test_wrong_candidate_root_or_identity_rejected(self):
        for f in ({'root_sha256':'wrong','candidate_id':tool.EXPECTED_ID},
            {'root_sha256':tool.EXPECTED_ROOT,'candidate_id':'wrong'}):
            with patch.object(tool,'verify_freeze',return_value=(f,None)):
                with self.assertRaises(tool.CaptureError):tool.integrity('/fixture','/candidate','/dataset','/project',require_absence=True)


if __name__=='__main__':unittest.main()
