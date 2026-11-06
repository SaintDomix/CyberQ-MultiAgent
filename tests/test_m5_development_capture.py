"""Synthetic coordinator tests: no browser, Apache log, TEST reads or ML fitting."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from behavioral_v2.browser_capture import CaptureError,make_plan
from behavioral_v2.development_capture import collect_development


class DevelopmentCollectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.plan=make_plan()
        self.ids={p:sorted(s['session_id'] for s in self.plan['sessions'] if s['partition']==p)
            for p in ('TRAIN','VALIDATION','TEST')}
        self.sessions={s['session_id']:s for s in self.plan['sessions']}
        self.calls=[];self.verified=[];self.outcomes={};self.verify_failure=None
        self.ready={'target_authorized':True,'credentials_present':True,'identity_marker_present':True}

    def existing(self,sid,status='COMPLETE',error=None):
        session=self.sessions[sid];base=self.root/'browser_sessions'/sid
        base.mkdir(parents=True,exist_ok=False)
        m={'session_id':sid,'partition':session['partition'],'protocol':session['protocol'],
            'plan_sha256':self.plan['sha256'],'status':status,'error_code':error,'fixture':'UNIT_TEST_ONLY'}
        (base/'manifest.json').write_text(json.dumps(m));return base/'manifest.json'

    def capture(self,plan,sid,out,*,authorized,actor):
        self.assertNotEqual(self.sessions[sid]['partition'],'TEST')
        self.assertEqual(Path(out),self.root/'browser_sessions');self.assertTrue(authorized)
        self.calls.append(sid)
        outcome=self.outcomes.get(sid,('COMPLETE',None))
        if isinstance(outcome,Exception):raise outcome
        status,error=outcome;self.existing(sid,status,error)
        return {'status':status,'error_code':error}

    def verify(self,root,plan,sid):
        self.assertNotEqual(self.sessions[sid]['partition'],'TEST')
        self.assertTrue((Path(root)/'browser_sessions'/sid/'manifest.json').is_file())
        self.verified.append(sid)
        if sid==self.verify_failure:raise RuntimeError('fixture-secret cookie token')
        return {'session_id':sid,'verified':True,'source_bytes_verified':True,
            'ownership_filtering_reproduced':True,'network_requests':0,'windows':1,
            'source_records':2,'accepted_records':1,'foreign_records':1,
            'attribution_policy':'capture-marker-and-actor-v1'}

    def run_collection(self,**kwargs):
        with patch('behavioral_v2.development_capture.capture',side_effect=self.capture), \
            patch('behavioral_v2.development_capture.verify_capture',side_effect=self.verify), \
            patch('behavioral_v2.development_capture.readiness',return_value=self.ready), \
            patch.dict(os.environ,{},clear=True), \
            patch('socket.socket',side_effect=AssertionError('Network forbidden')):
            return collect_development(self.root,self.plan,**kwargs)

    def test_collects_only_development_in_partition_order(self):
        r=self.run_collection(authorized=True)
        self.assertEqual(self.calls,self.ids['TRAIN']+self.ids['VALIDATION'])
        self.assertEqual(self.verified,self.calls);self.assertEqual(r['status'],'COMPLETE')
        self.assertFalse(r['test_files_opened']);self.assertFalse(r['models_invoked'])
        self.assertEqual(r['counts']['TRAIN']['verified_complete'],12)
        self.assertEqual(r['counts']['VALIDATION']['verified_complete'],6)

    def test_real_pattern_invalid_001_003_complete_004_preserved_and_skipped(self):
        saved=[]
        for sid,code in zip(self.ids['TRAIN'][:3],('OFF_ORIGIN_REQUEST','CONTAMINATED_CAPTURE','REQUIRED_RESOURCE_UNAVAILABLE')):
            p=self.existing(sid,'INVALID',code);saved.append((p,p.read_bytes()))
        p=self.existing(self.ids['TRAIN'][3]);saved.append((p,p.read_bytes()))
        r=self.run_collection(authorized=True)
        self.assertEqual(self.calls,self.ids['TRAIN'][4:]+self.ids['VALIDATION'])
        self.assertEqual(self.verified[0],self.ids['TRAIN'][3])
        self.assertEqual(r['counts']['TRAIN']['invalid'],3)
        self.assertEqual(r['counts']['TRAIN']['unavailable'],1)
        self.assertEqual(r['status'],'COMPLETE_WITH_EXCLUSIONS')
        for p,raw in saved:self.assertEqual(p.read_bytes(),raw)

    def test_rerun_verifies_all_complete_without_recapture_or_summary_overwrite(self):
        self.run_collection(authorized=True)
        old=self.root/'development_collection_runs/collection_001/summary.json';raw=old.read_bytes()
        self.calls.clear();self.verified.clear();self.run_collection(authorized=True)
        self.assertEqual(self.calls,[]);self.assertEqual(len(self.verified),18)
        self.assertEqual(old.read_bytes(),raw)
        self.assertTrue((self.root/'development_collection_runs/collection_002/summary.json').is_file())

    def test_dry_run_deterministic_zero_capture_verification_or_writes(self):
        a=self.run_collection(dry_run=True);b=self.run_collection(dry_run=True)
        self.assertEqual(a,b);self.assertEqual(a['network_requests'],0);self.assertEqual(a['log_reads'],0)
        self.assertEqual(self.calls,[]);self.assertEqual(self.verified,[])
        self.assertEqual(list(self.root.iterdir()),[])

    def test_authorization_required(self):
        with self.assertRaisesRegex(CaptureError,'EXPLICIT_AUTHORIZATION_REQUIRED'):self.run_collection()
        self.assertEqual(list(self.root.iterdir()),[])

    def test_missing_credentials_stops_before_existing_verification_or_artifacts(self):
        self.existing(self.ids['TRAIN'][3]);self.ready['credentials_present']=False
        with self.assertRaisesRegex(CaptureError,'MISSING_CREDENTIALS'):self.run_collection(authorized=True)
        self.assertEqual(self.calls,[]);self.assertEqual(self.verified,[])
        self.assertFalse((self.root/'development_collection_runs').exists())

    def test_partial_existing_directory_fails_closed(self):
        (self.root/'browser_sessions'/self.ids['TRAIN'][0]).mkdir(parents=True)
        with self.assertRaisesRegex(CaptureError,'PARTIAL_EXISTING'):self.run_collection(authorized=True)
        self.assertEqual(self.calls,[])

    def test_wrong_partition_manifest_fails_closed(self):
        p=self.existing(self.ids['TRAIN'][0]);m=json.loads(p.read_text());m['partition']='VALIDATION';p.write_text(json.dumps(m))
        with self.assertRaisesRegex(CaptureError,'MEMBERSHIP_MISMATCH'):self.run_collection(authorized=True)

    def test_new_resource_unavailable_preserved_no_protocol_substitution(self):
        sid=self.ids['TRAIN'][0];self.outcomes[sid]=('INVALID','REQUIRED_RESOURCE_UNAVAILABLE')
        original=copy.deepcopy(self.plan);r=self.run_collection(authorized=True)
        self.assertEqual(r['counts']['TRAIN']['unavailable'],1)
        self.assertEqual(r['counts']['TRAIN']['invalid'],1)
        self.assertEqual(self.plan,original);self.assertEqual(len(self.calls),18)
        self.assertNotIn(sid,self.verified)

    def test_unexpected_integrity_failure_stops_before_next_capture(self):
        self.outcomes[self.ids['TRAIN'][0]]=('INVALID','CONTAMINATED_CAPTURE')
        r=self.run_collection(authorized=True)
        self.assertEqual(r['status'],'STOPPED');self.assertEqual(len(self.calls),1)
        self.assertEqual(r['counts']['VALIDATION']['pending'],6)
        self.assertFalse(r['invalid_sessions_eligible_for_dataset'])

    def test_existing_independent_verification_failure_prevents_new_requests(self):
        sid=self.ids['TRAIN'][3];p=self.existing(sid);raw=p.read_bytes();self.verify_failure=sid
        r=self.run_collection(authorized=True)
        self.assertEqual(r['status'],'STOPPED');self.assertEqual(self.calls,[])
        self.assertEqual(p.read_bytes(),raw);self.assertNotIn('fixture-secret',json.dumps(r))

    def test_new_independent_verification_failure_stops_and_preserves_capture(self):
        sid=self.ids['TRAIN'][0];self.verify_failure=sid;r=self.run_collection(authorized=True)
        self.assertEqual(r['status'],'STOPPED');self.assertEqual(self.calls,[sid])
        self.assertEqual(r['counts']['TRAIN']['verification_failed'],1)
        self.assertEqual(json.loads((self.root/'browser_sessions'/sid/'manifest.json').read_text())['status'],'COMPLETE')

    def test_exception_details_never_persist_or_emit(self):
        self.outcomes[self.ids['TRAIN'][0]]=RuntimeError('fixture-secret password cookie token')
        emitted=[];r=self.run_collection(authorized=True,emit=emitted.append)
        self.assertEqual(r['status'],'STOPPED');self.assertEqual(r['counts']['TRAIN']['capture_failed'],1)
        text=json.dumps(r)+json.dumps(emitted)+''.join(p.read_text() for p in self.root.rglob('*.json'))
        self.assertNotIn('fixture-secret',text)

    def test_receipts_bind_actual_manifest_hashes(self):
        r=self.run_collection(authorized=True)
        self.assertEqual(len(r['verification_receipts']),18)
        for receipt in r['verification_receipts']:
            raw=(self.root/'browser_sessions'/receipt['session_id']/'manifest.json').read_bytes()
            self.assertEqual(receipt['capture_manifest_sha256'],hashlib.sha256(raw).hexdigest())

    def test_test_files_never_opened_even_if_present_and_invalid(self):
        for sid in self.ids['TEST']:
            base=self.root/'browser_sessions'/sid;base.mkdir(parents=True)
            (base/'manifest.json').write_text('NOT VALID JSON: MUST NEVER BE READ')
        before={p:p.read_bytes() for sid in self.ids['TEST'] for p in (self.root/'browser_sessions'/sid).iterdir()}
        self.run_collection(authorized=True)
        for p,raw in before.items():self.assertEqual(p.read_bytes(),raw)

    def test_cli_accepts_one_development_command_and_rejects_test_partition_option(self):
        spec=importlib.util.spec_from_file_location('m5_collect_cli',ROOT/'scripts/run_m5_browser_capture.py')
        cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        cli.ROOT=self.root;root=self.root/'outputs/branch2/m5_final_day';root.mkdir(parents=True)
        (root/'predeclared_capture_plan.json').write_text(json.dumps(self.plan))
        with patch('builtins.print'),patch('socket.socket',side_effect=AssertionError('No network')):
            self.assertEqual(cli.main(['collect-development','--dry-run']),0)
            with patch('sys.stderr'),self.assertRaises(SystemExit):
                cli.main(['collect-development','--partition','TEST','--authorized'])


if __name__=='__main__':unittest.main()
