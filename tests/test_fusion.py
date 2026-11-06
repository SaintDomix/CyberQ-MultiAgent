"""Synthetic offline tests; no accepted research output is written or scored."""
import copy
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from fractions import Fraction

from src.fusion.schema import Evidence, BEHAVIOR, CONFIRMATION, RESULT, SEVERITY, dumps, utc
from src.fusion.adapters import posture, behavior, recent
from src.fusion.dedup import clusters
from src.fusion.cqi import dimensions, score, sensitivity, WEIGHTS
from src.fusion.correlation import correlate
from src.fusion.pipeline import assemble, evaluate, validate_provenance


def finding(fid='TLS-001', category='Transport Security', result='FAIL', confirmation='CONFIRMED', severity='HIGH', **kwargs):
    return dict(finding_id=fid, evidence_id='source-'+fid, category=category, finding_type=kwargs.pop('finding_type', fid),
                check_result=result, confirmation_status=confirmation, severity=severity,
                confidence=None, evidence='Synthetic observed evidence', provenance={'fixture': True},
                recommendation='Review synthetic control', **kwargs)


def prediction(seq=1, decision='BENIGN', reason=None, emitted='2026-01-01T00:05:00+00:00', **kwargs):
    reason = reason or {'BENIGN':'BOTH_BENIGN_NORMAL', 'UNKNOWN_ANOMALY':'ANOMALY_WITHOUT_CONFIDENT_KNOWN_ATTACK',
                       'UNCERTAIN':'NORMAL_IF_WITH_UNCERTAIN_OR_UNAVAILABLE_CLASSIFIER'}.get(decision, 'KNOWN_ATTACK_WITH_ANOMALY_SUPPORT')
    anomalous=reason in ('ANOMALY_WITHOUT_CONFIDENT_KNOWN_ATTACK','KNOWN_ATTACK_WITH_ANOMALY_SUPPORT')
    label=decision if decision not in ('UNKNOWN_ANOMALY','UNCERTAIN') else 'BENIGN'
    return dict(record_id='record-'+str(seq), sequence=seq, emitted_at_utc=emitted, label=None,
                confidence_calibrated=False, training_performed=False, xgb_confidence=.99, xgb_label=label, if_anomalous=anomalous,
                reconciliation={'decision':decision, 'reason':reason, 'confidence_calibrated':False,
                                'confidence_threshold':.8, 'if_anomalous':anomalous, 'xgb_label':label, 'xgb_confidence':.99}, **kwargs)


def p(rows): return posture(rows, '/synthetic/posture.json')
def b(rows): return behavior(rows, '/synthetic/predictions.jsonl')
def quality(rows):
    items=p(rows)
    return score(dimensions(items, clusters(items)))['cqi']


class AdaptersTests(unittest.TestCase):
    def test_fail_confirmed(self): self.assertEqual(p([finding()])[0].contribution, .75)
    def test_pass_zero(self): self.assertEqual(p([finding(result='PASS')])[0].contribution, 0)
    def test_partial_half(self): self.assertEqual(p([finding(result='PARTIAL')])[0].contribution, .375)
    def test_dismissed(self): self.assertEqual(p([finding(result='DISMISSED')])[0].contribution, 0)
    def test_version_based(self): self.assertAlmostEqual(p([finding(confirmation='VERSION_BASED')])[0].contribution, .525)
    def test_not_confirmed(self): self.assertAlmostEqual(p([finding(confirmation='NOT_CONFIRMED')])[0].contribution, .2625)
    def test_false_positive(self): self.assertEqual(p([finding(confirmation='FALSE_POSITIVE')])[0].contribution, 0)
    def test_not_applicable(self): self.assertEqual(p([finding(result='NOT_APPLICABLE')])[0].contribution, 0)
    def test_not_tested_excluded(self):
        for kwargs in ({'result':'NOT_TESTED'}, {'confirmation':'NOT_TESTED'}):
            item=p([finding(**kwargs)])[0]; self.assertFalse(item.score_eligible); self.assertIsNone(item.contribution)
    def test_unknown_severity(self): self.assertFalse(p([finding(severity=None)])[0].score_eligible)
    def test_info_zero(self): self.assertEqual(p([finding(severity='INFO')])[0].contribution, 0)
    def test_unknown_confirmation_explicit(self):
        item=p([finding(confirmation='LIKELY')])[0]
        self.assertFalse(item.score_eligible); self.assertIn('UNKNOWN_CONFIRMATION',item.exclusions)
    def test_unmapped_retained(self):
        item=p([finding(category='new category')])[0]
        self.assertIsNone(item.dimension); self.assertIn('UNMAPPED_CATEGORY', item.exclusions)
    def test_no_timestamp_invention(self): self.assertEqual(p([finding()])[0].timestamps, {'start_utc':None,'end_utc':None})
    def test_no_confidence_multiplier(self):
        a=p([finding()])[0]; row=finding();row['confidence']=.1;c=p([row])[0]
        self.assertEqual(a.contribution,c.contribution); self.assertIsNone(a.coefficients['confidence_multiplier'])
    def test_behavior_factors(self):
        for name, factor in BEHAVIOR.items():
            item=b([prediction(decision=name)])[0]
            self.assertEqual(item.contribution,factor); self.assertFalse(item.causal)
            self.assertFalse(item.successful_exploitation_confirmed)
    def test_classifier_only_lower_support(self):
        self.assertAlmostEqual(b([prediction(decision='SQLI_ATTEMPT',reason='KNOWN_ATTACK_MODEL_DISAGREEMENT')])[0].contribution,.6)
    def test_confidence_not_probability(self):
        row=prediction(decision='SQLI_ATTEMPT'); low=copy.deepcopy(row);low['xgb_confidence']=.9;low['reconciliation']['xgb_confidence']=.9
        self.assertEqual(b([row])[0].contribution,b([low])[0].contribution)
    def test_ground_truth_not_consumed(self):
        row=prediction();row['label']='SQLI_ATTEMPT'
        self.assertEqual(b([row])[0].behavior_class,'BENIGN')
    def test_invalid_semantics_rejected(self):
        for row in (prediction(decision='SQLI_ATTEMPT',reason='BOTH_BENIGN_NORMAL'),prediction(decision='COMPROMISED')):
            with self.assertRaises(ValueError):b([row])
    def test_contradictory_if_fails(self):
        row=prediction(decision='SQLI_ATTEMPT');row['if_anomalous']=False
        with self.assertRaises(ValueError):b([row])
    def test_invalid_classifier_score(self):
        row=prediction();row['xgb_confidence']=float('nan')
        with self.assertRaises(ValueError):b([row])
    def test_duplicate_behavior_fails(self):
        with self.assertRaises(ValueError):b([prediction(),prediction()])
    def test_conflicting_posture_identity_fails(self):
        with self.assertRaises(ValueError):p([finding(),finding(result='PASS')])
    def test_canonical_schema_rejects_causality(self):
        data=p([finding()])[0].export();data['causal']=True
        with self.assertRaises(ValueError):Evidence(**data)


class DedupScoreTests(unittest.TestCase):
    def test_plaintext_four_members_cross_dimension(self):
        rows=[finding('TLS-001',affected_asset='http://fixture/'),finding('TLS-003'),
              finding('HDR-001',category='Security Headers'),finding('COOKIE-MoodleSession-SECURE',category='Authentication & Session')]
        c=clusters(p(rows)); self.assertEqual(len(c),1); self.assertEqual(c[0]['member_count'],4)
        self.assertEqual(c[0]['rule_id'],'PLAINTEXT_TRANSPORT');self.assertEqual(c[0]['dimension'],'D1')
    def test_patch_max_and_breadth(self):
        c=clusters(p([finding('PATCH-001',category='Patch & Vulnerability Intelligence'),
             finding('ADV-MSA-26-0031',category='Patch & Vulnerability Intelligence',confirmation='VERSION_BASED'),
             finding('ADV-MSA-26-0020',category='Patch & Vulnerability Intelligence',severity='MEDIUM')]))[0]
        self.assertEqual(c['rule_id'],'MOODLE_PATCH_LEVEL');self.assertEqual(c['contribution'],.75)
        self.assertEqual(len(c['advisory_ids']),2);self.assertEqual(c['severity_breadth'],['HIGH','MEDIUM'])
    def test_permissions_max(self):
        c=clusters(p([finding('FS-001',category='Server-side Configuration'),finding('FS-002',category='Server-side Configuration',severity='LOW')]))
        self.assertEqual(len(c),1);self.assertEqual(c[0]['contribution'],.75)
    def test_headers_distinct(self):
        self.assertEqual(len(clusters(p([finding(x,category='Security Headers') for x in ('HDR-002','HDR-005','HDR-007','HDR-008')]))),4)
    def test_duplicate_invariance(self):
        row=finding();self.assertEqual(quality([row]),quality([row,row,row]))
    def test_copy_member_different_evidence_same_rule(self):
        a=finding();other=copy.deepcopy(a);other['evidence_id']='copy-evidence'
        self.assertEqual(quality([a]),quality([a,other]))
    def test_complementary_product(self):
        self.assertAlmostEqual(quality([finding('a',severity='MEDIUM'),finding('b',severity='LOW')]),37.5)
    def test_monotonic(self): self.assertLess(quality([finding('a'),finding('b')]),quality([finding('a')]))
    def test_zero_additions_invariant(self):
        for kwargs in ({'result':'PASS'},{'result':'DISMISSED'},{'confirmation':'FALSE_POSITIVE'}):
            self.assertEqual(quality([finding('a')]),quality([finding('a'),finding('b',**kwargs)]))
    def test_critical_bounded(self): self.assertEqual(quality([finding(severity='CRITICAL')]),0)
    def test_not_tested_coverage_only(self):
        rows=[finding('a'),finding('b',result='NOT_TESTED')]
        artifacts=assemble(rows,[prediction()],'/p','/b')
        self.assertEqual(artifacts['coverage']['branch1']['not_tested'],1)
        self.assertEqual(quality(rows),quality(rows[:1]))
    def test_equal_weights_exact(self): self.assertEqual(sum(WEIGHTS.values()),Fraction(1))
    def test_insufficient_not_perfect(self):
        ds=dimensions([],[]);self.assertTrue(all(x['quality'] is None for x in ds));self.assertIsNone(score(ds)['cqi'])
    def test_score_range_policy(self):
        for severity in SEVERITY:
            value=quality([finding(severity=severity)]);self.assertTrue(0<=value<=100)
        self.assertFalse(score(dimensions([],[]))['is_probability'])
    def test_order_determinism(self):
        rows=[finding('a'),finding('b')];self.assertEqual(quality(rows),quality(rows[::-1]))


class HorizonCorrelationSensitivityTests(unittest.TestCase):
    def test_default_evidence_time(self):
        items=b([prediction(),prediction(2,emitted='2026-01-01T00:10:00Z')]);_,h=recent(items)
        self.assertEqual(h['as_of'],'2026-01-01T00:10:00+00:00')
    def test_inclusive_boundary_old_future(self):
        items=b([prediction(1,emitted='2026-01-01T00:00:00Z'),prediction(2,emitted='2025-12-31T23:59:59Z'),
                 prediction(3,emitted='2026-01-01T00:05:00Z'),prediction(4,emitted='2026-01-01T00:05:01Z')])
        chosen,h=recent(items,'2026-01-01T00:05:00Z',300)
        self.assertEqual(sorted(x.source_record_id for x in chosen),['record-1','record-3'])
        self.assertEqual(h['excluded_older_count'],1);self.assertEqual(h['excluded_future_count'],1)
    def test_invalid_horizon(self):
        for seconds in (0,-1,1.5):
            with self.assertRaises(ValueError):recent(b([prediction()]),lookback=seconds)
        with self.assertRaises(ValueError):utc('2026-01-01T00:00:00')
    def test_sql_context(self):
        cs=correlate(p([finding('ADV-MSA-26-0031',confirmation='VERSION_BASED')]),b([prediction(decision='SQLI_ATTEMPT')]))
        self.assertEqual(len(cs),1);self.assertEqual(cs[0]['score_effect'],'NONE');self.assertFalse(cs[0]['exploit_confirmed'])
    def test_no_fabricated_path_match(self):self.assertEqual(correlate(p([finding()]),b([prediction(decision='PATH_TRAVERSAL_ATTEMPT')])),[])
    def test_xss_dos_auth_exposure_matches(self):
        cases=[('XSS_ATTEMPT',finding(finding_type='Reflected XSS')),('REQUEST_BURST_DOS_LIKE',finding(finding_type='DoS risk')),
               ('BRUTE_FORCE',finding(category='Authentication & Session')),('ADMIN_PROBING',finding(category='Access Control')),
               ('ENUMERATION_RECONNAISSANCE',finding(category='Exposure')),
               ('PATH_TRAVERSAL_ATTEMPT',finding(category='Exposure',finding_type='Exposed Environment file'))]
        for name,row in cases:self.assertEqual(len(correlate(p([row]),b([prediction(decision=name)]))),1)
    def test_correlation_cannot_modify_score(self):
        a=assemble([finding('ADV-MSA-26-0031')],[prediction(decision='SQLI_ATTEMPT')],'/p','/b')
        original=copy.deepcopy(a['cqi']);a['correlations']=[];self.assertEqual(a['cqi'],original)
    def test_sensitivity_twelve(self):
        ds=dimensions(p([finding()]),clusters(p([finding()])))
        s=sensitivity(ds);self.assertEqual(len(s['variants']),12)
        for v in s['variants']:self.assertAlmostEqual(sum(v['weights'].values()),1)
        self.assertLessEqual(s['min_cqi'],s['baseline_cqi']);self.assertGreaterEqual(s['max_cqi'],s['baseline_cqi'])
        self.assertEqual(s,sensitivity(ds))
    def test_sensitivity_focal_change(self):
        s=sensitivity(dimensions([],[]))
        self.assertAlmostEqual(s['variants'][0]['weights']['D1'],(1/6)*.8)
        self.assertAlmostEqual(s['variants'][1]['weights']['D1'],(1/6)*1.2)


class PipelineSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.manifest={'version':'branch2-model-package-1.0','complete_parallel_package':True,
            'files_sha256':{x:'a'*64 for x in ('feature_schema.json','isolation_forest.joblib','xgboost.json','reconciliation.json')}}
        self.mp=self.root/'package_manifest.json';self.mp.write_text(dumps(self.manifest))
        self.mh=hashlib.sha256(self.mp.read_bytes()).hexdigest()
        self.rows=[prediction(model_id=self.mh,schema_sha256='b'*64,feature_schema_version='dataset-v2-features-1.0',
            source_file='/var/log/apache2/access.log',source_sha256='c'*64,
            source_byte_ranges=[{'start':1,'end':10,'sha256':'d'*64}])]
        self.acceptance={'acceptance':'PASS','training_performed':False,'model_id':self.mh,'schema_sha256':'b'*64,
                         'live_integrity':{'predictions':1,'unique_record_ids':1,'duplicates':0,'sequence_holes':[]}}
        self.ap=self.root/'acceptance.json';self.ap.write_text(dumps(self.acceptance))
        self.pp=self.root/'posture.json';self.pp.write_text(dumps([finding()]))
        self.bp=self.root/'predictions.jsonl';self.bp.write_text(dumps(self.rows[0])+'\n')
    def run_pipeline(self,name='out'):
        return evaluate(self.pp,self.bp,self.mp,self.ap,self.root/name)
    def test_hashes_provenance(self):
        a=self.run_pipeline()
        self.assertEqual(a['provenance']['inputs']['model_manifest']['sha256'],self.mh)
        self.assertEqual(len(a['provenance']['inputs']),4)
    def test_no_overwrite(self):
        self.run_pipeline()
        with self.assertRaises(FileExistsError):self.run_pipeline()
    def test_byte_determinism(self):
        self.run_pipeline('one');self.run_pipeline('two')
        for path in (self.root/'one').iterdir():self.assertEqual(path.read_bytes(),(self.root/'two'/path.name).read_bytes())
    def test_inputs_unchanged(self):
        paths=[self.mp,self.ap,self.pp,self.bp];before=[x.read_bytes() for x in paths]
        self.run_pipeline();self.assertEqual(before,[x.read_bytes() for x in paths])
    def test_no_network_training_or_apache(self):
        import builtins
        original=builtins.open
        def guard(path,*args,**kwargs):
            if str(path).startswith('/var/log/apache2'):raise AssertionError('Apache access forbidden')
            return original(path,*args,**kwargs)
        with patch('socket.socket',side_effect=AssertionError('network')),patch('builtins.open',side_effect=guard),\
             patch.object(Path,'open',autospec=True,side_effect=lambda path,*a,**kw:guard(str(path),*a,**kw)):
            self.run_pipeline()
        result=subprocess.run([sys.executable,'-B','-c',
            'import sys; import src.fusion.pipeline; assert not any(x.startswith(("src.branch1", "src.branch2", "xgboost", "sklearn")) for x in sys.modules)'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
    def test_host_log_argument_rejected_before_read(self):
        with patch.object(Path,'read_bytes',side_effect=AssertionError('must not read')):
            with self.assertRaises(ValueError):evaluate('/var/log/apache2/access.log',self.bp,self.mp,self.ap,self.root/'out')
    def test_bad_model_identity(self):
        self.rows[0]['model_id']='wrong'
        with self.assertRaises(ValueError):validate_provenance(self.rows,self.manifest,self.mh,self.acceptance)
    def test_bad_schema_identity(self):
        self.rows[0]['schema_sha256']='wrong'
        with self.assertRaises(ValueError):validate_provenance(self.rows,self.manifest,self.mh,self.acceptance)
    def test_bad_acceptance(self):
        self.acceptance['acceptance']='FAIL'
        with self.assertRaises(ValueError):validate_provenance(self.rows,self.manifest,self.mh,self.acceptance)
    def test_missing_byte_provenance(self):
        self.rows[0]['source_byte_ranges']=[]
        with self.assertRaises(ValueError):validate_provenance(self.rows,self.manifest,self.mh,self.acceptance)
    def test_cli_synthetic(self):
        result=subprocess.run([sys.executable,'-B','scripts/run_fusion.py','evaluate','--branch1',str(self.pp),'--branch2',str(self.bp),
            '--model-manifest',str(self.mp),'--live-acceptance',str(self.ap),'--out',str(self.root/'cli')],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('not probability',result.stdout)
    def test_output_artifacts(self):
        self.run_pipeline()
        self.assertEqual(len(list((self.root/'out').glob('*.json'))),11)
    def test_invalid_input_no_output(self):
        self.bp.write_text('{bad json')
        with self.assertRaises(ValueError):self.run_pipeline()
        self.assertFalse((self.root/'out').exists())


if __name__=='__main__':unittest.main()


class BehavioralEpisodeTests(unittest.TestCase):
    def rows(self, count=5, decision='SQLI_ATTEMPT', offset=0):
        from datetime import datetime, timedelta, timezone
        start=datetime(2026,1,1,0,0,0,tzinfo=timezone.utc)
        return [prediction(i+1,decision=decision,window_start=(start+timedelta(seconds=offset+i*10)).isoformat(),
                    window_end=(start+timedelta(seconds=offset+(i+1)*10)).isoformat(),
                    client_id='client',user_agent_id='agent',session_id='session',run_id='live-run',
                    source_file='/synthetic/apache.log',source_path='/synthetic/apache.log',
                    source_device=1,source_inode=2) for i in range(count)]

    def d6(self, rows):
        a=assemble([],rows,'/p','/b')
        return next(d for d in a['dimensions'] if d['dimension']=='D6')

    def test_five_sqli_windows_one_episode(self):
        c=clusters(b(self.rows()))
        self.assertEqual(len(c),1);self.assertEqual(c[0]['rule_id'],'TEMPORALLY_CORRELATED_BEHAVIOR_EPISODE')
        self.assertEqual(c[0]['member_count'],5);self.assertEqual(c[0]['member_sequences'],[1,2,3,4,5])
        self.assertEqual(c[0]['episode_start'],'2026-01-01T00:00:00+00:00')
        self.assertEqual(c[0]['episode_end'],'2026-01-01T00:00:50+00:00')
        self.assertEqual(c[0]['contribution'],.75)

    def test_episode_max_support_not_product(self):
        rows=self.rows()
        rows[0]['reconciliation']['reason']='KNOWN_ATTACK_MODEL_DISAGREEMENT'
        rows[0]['reconciliation']['if_anomalous']=False;rows[0]['if_anomalous']=False
        c=clusters(b(rows));self.assertEqual(len(c),1);self.assertEqual(c[0]['max_contribution'],.75)

    def test_fragmentation_invariant_quality(self):
        self.assertEqual(self.d6(self.rows(1))['quality'],self.d6(self.rows(5))['quality'])
        self.assertEqual(self.d6(self.rows(5))['quality'],25.)

    def test_gap_separates_and_increases_risk(self):
        rows=self.rows(2);last=self.rows(1,offset=40)[0];last['sequence']=3;last['record_id']='record-3';rows.append(last)
        c=clusters(b(rows));self.assertEqual(len(c),2)
        self.assertLess(self.d6(rows)['quality'],self.d6(rows[:2])['quality'])

    def test_classes_distinct(self):
        rows=self.rows(1,decision='UNCERTAIN')+self.rows(2,offset=10)
        for i,row in enumerate(rows):row['sequence']=i+1;row['record_id']='record-'+str(i+1)
        c=clusters(b(rows));self.assertEqual(len(c),2)
        self.assertEqual(sorted(x['behavior_class'] for x in c),['SQLI_ATTEMPT','UNCERTAIN'])

    def test_unknown_anomalies_one_episode(self):
        c=clusters(b(self.rows(decision='UNKNOWN_ANOMALY')))
        self.assertEqual(len(c),1);self.assertEqual(c[0]['contribution'],.4)

    def test_benign_zero(self):
        c=clusters(b(self.rows(decision='BENIGN')))
        self.assertTrue(all(x['contribution']==0 for x in c));self.assertEqual(self.d6(self.rows(decision='BENIGN'))['quality'],100)

    def test_benign_breaks_episode(self):
        rows=self.rows(1)+self.rows(1,decision='BENIGN',offset=10)+self.rows(1,offset=20)
        for i,row in enumerate(rows):row['sequence']=i+1;row['record_id']='record-'+str(i+1)
        c=clusters(b(rows));self.assertEqual(sum(x['rule_id']=='TEMPORALLY_CORRELATED_BEHAVIOR_EPISODE' for x in c),2)

    def test_correlation_episode_members(self):
        cs=correlate(p([finding('ADV-MSA-26-0031')]),b(self.rows()))
        self.assertEqual(len(cs),1);self.assertEqual(len(cs[0]['behavior_record_ids']),5)
        self.assertEqual(cs[0]['score_effect'],'NONE');self.assertFalse(cs[0]['causal']);self.assertFalse(cs[0]['exploit_confirmed'])
        self.assertEqual(cs[0]['confidence_semantics'],'CONTEXTUAL')

    def test_correlation_no_score_effect(self):
        rows=self.rows();a=assemble([finding('ADV-MSA-26-0031')],rows,'/p','/b')
        before=copy.deepcopy(a['cqi']);a['correlations']=[];self.assertEqual(a['cqi'],before)
        with patch('src.fusion.pipeline.correlate',return_value=[]):
            no=assemble([finding('ADV-MSA-26-0031')],rows,'/p','/b')
        self.assertEqual(before,no['cqi'])

    def test_order_and_ids_deterministic(self):
        items=b(self.rows());self.assertEqual(clusters(items),clusters(items[::-1]))
        self.assertEqual(correlate(p([finding('ADV-MSA-26-0031')]),items),
                         correlate(p([finding('ADV-MSA-26-0031')]),items[::-1]))

    def test_raw_evidence_and_coverage_preserved(self):
        a=assemble([],self.rows(),'/p','/b');cov=a['coverage']['branch2']
        self.assertEqual(cov['total_predictions'],5);self.assertEqual(cov['recent_selected_predictions'],5)
        self.assertEqual(cov['known_attack_attempts'],5);self.assertEqual(len(a['canonical_evidence']),5)
        self.assertEqual(len(a['fusion_clusters']),1)

    def test_dismissed_unknown_severity_quality_not_exclusion(self):
        row=finding('dismissed',result='DISMISSED',confirmation='FALSE_POSITIVE',severity=None)
        item=p([row])[0];self.assertTrue(item.score_eligible);self.assertEqual(item.contribution,0)
        self.assertIsNone(item.severity);self.assertEqual(item.exclusions,[])
        a=assemble([row],[prediction()],'/p','/b');cov=a['coverage']
        self.assertEqual(cov['branch1']['score_eligible'],1);self.assertEqual(cov['branch1']['excluded_from_scoring'],0)
        self.assertEqual(cov['exclusions'],[]);self.assertEqual(cov['branch1']['unknown_severities'],['None'])
        self.assertEqual(cov['data_quality_observations'][0]['observations'],['UNKNOWN_SEVERITY'])

    def test_unknown_fail_still_excluded(self):
        a=assemble([finding(severity=None)],[prediction()],'/p','/b')
        self.assertEqual(a['coverage']['branch1']['excluded_from_scoring'],1)
        self.assertEqual(a['coverage']['exclusions'][0]['reasons'],['UNKNOWN_SEVERITY'])

    def test_client_session_source_separation(self):
        for key,value in [('client_id','other'),('session_id','other'),('source_inode',3),('user_agent_id','other')]:
            rows=self.rows(2);rows[1][key]=value
            self.assertEqual(len(clusters(b(rows))),2)

    def test_missing_identity_or_timing_no_invented_merge(self):
        for key in ('client_id','session_id','window_start'):
            rows=self.rows(2)
            for row in rows:row.pop(key)
            self.assertEqual(len(clusters(b(rows))),2)

    def test_no_adjacency_tolerance(self):
        rows=self.rows(2);rows[1]['window_start']='2026-01-01T00:00:11+00:00';rows[1]['window_end']='2026-01-01T00:00:21+00:00'
        with self.assertRaises(ValueError):clusters(b(rows))

    def test_no_reconciliation_support_split(self):
        rows=self.rows(2)
        rows[1]['reconciliation']['reason']='KNOWN_ATTACK_MODEL_DISAGREEMENT'
        rows[1]['reconciliation']['if_anomalous']=False;rows[1]['if_anomalous']=False
        self.assertEqual(len(clusters(b(rows))),1)
