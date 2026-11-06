"""M5 unit experiments are synthetic fixtures, never dissertation result data."""
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from branch2.events import CanonicalBehavioralEvent,identifier
from branch2.features import extract as base_extract, schema as base_schema
from branch2.dataset import CLASSES
from branch2.splitting import split_final_runs
from behavioral_v2.semantics import classify,semantic_features,CATEGORIES
from behavioral_v2.schema import schema,FEATURES,BASE,ADDED,extract,matrix
from behavioral_v2.data import validate_partitions,write,sha,discover,external,rebuild
from behavioral_v2.calibration import threshold,calibrate,fit_novelty,scores
from behavioral_v2.episodes import episodes,episode_metrics,select_persistence
from behavioral_v2.inference import Package,robust_reference,load
from behavioral_v2.experiment import fit_classifier,run_predictions,PROTOCOL
from behavioral_v2.capture_plan import plan


def event(path='/moodle/my/',method='GET',status=200,query=''):
    return CanonicalBehavioralEvent(datetime(2020,1,1,tzinfo=timezone.utc),'client',method,path,query,status,100,None,None,'fixture','sha',1,'record')


def rows(partition='TRAIN',count=16,label='BENIGN'):
    result=[];start=datetime(2020,1,1,tzinfo=timezone.utc)
    for i in range(count):
        f=dict.fromkeys(FEATURES,0.);f['request_count']=float(i%5+1);f['request_rate']=f['request_count']/10
        result.append({'run_id':'fixture-'+partition+str(i//2),'partition':partition,'label':label,
            'window_start':(start+timedelta(seconds=10*i)).isoformat(),'window_end':(start+timedelta(seconds=10*(i+1))).isoformat(),
            'schema_sha256':schema()['sha256'],'features':f,'client_id':'fixture','user_agent_id':'fixture'})
    return result


def prediction(index,decision='UNKNOWN_ANOMALY',label='BENIGN',run='fixture',partition='VALIDATION'):
    start=datetime(2020,1,1,tzinfo=timezone.utc)+timedelta(seconds=index*10)
    return {'run_id':run,'label':label,'partition':partition,'client_id':'client','user_agent_id':'agent',
        'window_start':start.isoformat(),'window_end':(start+timedelta(seconds=10)).isoformat(),
        'reconciliation':{'decision':decision,'model_disagreement':True}}


class SemanticTests(unittest.TestCase):
    def test_category_rules(self):
        cases={'/moodle/login/index.php':'AUTH_LOGIN','/moodle/login/logout.php':'AUTH_LOGOUT',
            '/moodle/my/':'DASHBOARD','/moodle/course/view.php?id=3':'COURSE_VIEW','/moodle/mod/quiz/view.php':'QUIZ_ACTIVITY',
            '/moodle/user/profile.php':'PROFILE','/moodle/admin/index.php':'ADMIN','/moodle/report/log/index.php':'ADMIN',
            '/moodle/lib/ajax/service.php':'AJAX_SERVICE','/moodle/lib/javascript.php':'STATIC_ASSET',
            '/moodle/lib/requirejs.php/a.js':'STATIC_ASSET','/moodle/theme/image.php/x':'THEME_RESOURCE',
            '/moodle/webservice/rest/server.php':'APPLICATION_API','/moodle/':'OTHER_NAVIGATION','/outside/a.php':'UNKNOWN'}
        self.assertEqual(set(cases.values()),set(CATEGORIES))
        for path,expected in cases.items():
            with self.subTest(path=path):self.assertEqual(classify(path),expected)

    def test_query_does_not_determine_semantics_or_label(self):
        self.assertEqual(classify('/moodle/my/?class=SQLI_ATTEMPT'),classify('/moodle/my/'))

    def test_assets_and_ajax_are_retained_separately(self):
        es=[event('/moodle/theme/styles.php'),event('/moodle/lib/ajax/service.php','POST'),event()]
        f=extract(es)
        self.assertEqual(f['request_count'],3);self.assertEqual(f['asset_request_count'],1)
        self.assertEqual(f['semantic_request_count'],2);self.assertEqual(f['ajax_request_count'],1)
        self.assertEqual(f['navigation_count'],1);self.assertEqual(f['asset_ratio'],1/3)

    def test_all_65_baseline_features_unchanged(self):
        es=[event(query='q=%27+select+--'),event('/moodle/login/index.php','POST',303)]
        f=extract(es);self.assertEqual({k:f[k] for k in BASE},base_extract(es))

    def test_additive_schema_83(self):
        self.assertEqual(len(FEATURES),83);self.assertEqual(len(ADDED),18)
        self.assertEqual(schema()['version'],'dataset-v3-features-2.0')
        self.assertEqual(schema(),schema())

    def test_schema_order_and_hash_fail_closed(self):
        good=rows();self.assertEqual(matrix(good).shape,(16,83))
        wrong=copy.deepcopy(schema());wrong['feature_order'].reverse()
        with self.assertRaises(ValueError):matrix(good,wrong)
        good[0]['schema_sha256']='bad'
        with self.assertRaises(ValueError):matrix(good)

    def test_missing_identity_remains_unobserved(self):
        f=extract([event()]);self.assertEqual(f['identity_observed_ratio'],0)
        self.assertEqual(f['session_observed_ratio'],0);self.assertEqual(f['role_observed_ratio'],0)

    def test_privacy_only_features_exported(self):
        f=extract([event(query='password=fixture-secret&token=fixture-token')])
        text=json.dumps(f)
        self.assertNotIn('fixture-secret',text);self.assertNotIn('fixture-token',text)

    def test_no_assets_or_unknown_discarded(self):
        f=extract([event('/outside/'),event('/moodle/pix/a.svg')])
        self.assertEqual(f['request_count'],2);self.assertEqual(f['unknown_semantic_ratio'],.5)


class SplitTests(unittest.TestCase):
    def fixture(self):
        # Reuse the accepted synthetic split fixture, not actual research data.
        from test_branch2_final import fixture
        d=fixture()
        for row in d['rows']:
            row.update(features={**row['features'],**dict.fromkeys(ADDED,0.)},schema_sha256=schema()['sha256'])
        return d

    def test_same_run_groups_exact_50_16_16(self):
        d=self.fixture();s=split_final_runs(d);parts=validate_partitions(d,s)
        self.assertEqual([len(s[n+'_runs']) for n in ('train','validation','test')],[50,16,16])
        self.assertTrue(all({r['label'] for r in p}==set(CLASSES) for p in parts))

    def test_no_leakage_deterministic_and_smoke_excluded(self):
        d=self.fixture();a=split_final_runs(d);self.assertEqual(a,split_final_runs(d))
        self.assertIn('TEST-run01',a['excluded_run_ids'])
        bad=copy.deepcopy(a);bad['test_runs'].append(a['train_runs'][0])
        with self.assertRaises(ValueError):validate_partitions(d,bad)

    def test_external_run_and_capture_excluded(self):
        d=self.fixture();s=split_final_runs(d)
        with self.assertRaises(ValueError):validate_partitions(d,s,[d['rows'][0]])
        ext={**d['rows'][0],'run_id':'external-session'}
        with self.assertRaises(ValueError):validate_partitions(d,s,[ext])

    def test_different_seed_changes_runs(self):
        d=self.fixture();self.assertNotEqual(split_final_runs(d)['test_runs'],split_final_runs(d,43)['test_runs'])


class CalibrationTests(unittest.TestCase):
    def test_empirical_fpr_bound_and_ties(self):
        for n in (5,17,100):
            values=np.arange(n,dtype=float)
            for target in (.01,.02,.05,.1):
                cut=threshold(values,target);self.assertLessEqual(float(np.mean(values<cut)),target)
        self.assertFalse(np.any(np.ones(10)<threshold(np.ones(10),.1)))

    def test_bad_calibration_inputs_fail(self):
        for values in ([],[np.nan],[np.inf]):
            with self.assertRaises(ValueError):threshold(values,.05)

    def test_no_test_or_external_selection(self):
        for p in ('TEST','EXTERNAL_DIAGNOSTIC_HOLDOUT','TRAIN'):
            with self.assertRaises(ValueError):calibrate({},rows(p))

    def test_if_ocsvm_lof_fit_benign_train_only(self):
        for name in ('IF','OCSVM','LOF'):
            for part,label in (('TEST','BENIGN'),('VALIDATION','BENIGN'),('TRAIN','SQLI_ATTEMPT')):
                with self.subTest(name=name,part=part,label=label),self.assertRaises(ValueError):
                    fit_novelty(name,rows(part,label=label))

    def test_fitting_scaler_observes_train_only(self):
        tr=rows();original=np.asarray(matrix(tr))
        for name in ('IF','OCSVM','LOF'):
            fitted=fit_novelty(name,tr)
            self.assertEqual(fitted['fit_labels'],['BENIGN'])
            self.assertEqual(fitted['scaler'].center_.tolist(),np.median(original,axis=0).tolist())

    def test_seed_reproduces_if_scores(self):
        tr=rows();a=fit_novelty('IF',tr);b=fit_novelty('IF',tr)
        self.assertEqual(scores(a,tr).tolist(),scores(b,tr).tolist())

    def test_validation_grid_and_ceiling(self):
        tr=rows();v=rows('VALIDATION')+rows('VALIDATION',label='SQLI_ATTEMPT')
        fit=fit_novelty('IF',tr);result=calibrate(fit,v)
        self.assertEqual(len(result['candidates']),4)
        self.assertLessEqual(result['validation']['FPR'],.05)
        self.assertFalse(result['test_used_for_selection'])

    def test_xgb_train_all_classes_only(self):
        with self.assertRaises(ValueError):fit_classifier(rows('TEST'))
        with self.assertRaises(ValueError):fit_classifier(rows('TRAIN'))
        tr=[r for c in CLASSES for r in rows('TRAIN',count=2,label=c)]
        fit,classes=fit_classifier(tr);self.assertEqual(set(classes),set(CLASSES));self.assertEqual(fit.n_jobs,1)


class EpisodeTests(unittest.TestCase):
    def test_persistence_1_2_3_and_no_hidden_disagreement(self):
        ps=[prediction(0)]
        for n in (1,2,3):
            es=episodes(ps,n);self.assertTrue(es[0]['model_disagreement_visible'])
            self.assertEqual(es[0]['alert'],n==1)
        self.assertEqual(episodes(ps,2)[0]['state'],'NOVEL_OBSERVATION')

    def test_two_contiguous_and_gap(self):
        ps=[prediction(0),prediction(1),prediction(4)]
        es=episodes(ps,2);self.assertEqual([e['member_count'] for e in es],[2,1])
        self.assertEqual([e['alert'] for e in es],[True,False])

    def test_different_clients_classes_runs_do_not_merge(self):
        ps=[prediction(0),prediction(1,'SQLI_ATTEMPT'),prediction(2,run='other')]
        self.assertEqual(len(episodes(ps,2)),3)

    def test_known_attempt_not_suppressed_by_persistence(self):
        es=episodes([prediction(0,'SQLI_ATTEMPT')],3)
        self.assertTrue(es[0]['alert']);self.assertFalse(es[0]['successful_exploitation_confirmed'])

    def test_policy_validation_only(self):
        with self.assertRaises(ValueError):select_persistence([prediction(0,partition='TEST')])
        ps=[prediction(0),prediction(0,'SQLI_ATTEMPT','SQLI_ATTEMPT','attack')]
        chosen=select_persistence(ps)
        self.assertEqual(chosen['persistence'],2) # same FPR as 3, less delay
        self.assertEqual(len(chosen['candidates']),3)

    def test_episode_order_deterministic(self):
        ps=[prediction(0),prediction(1),prediction(4)]
        self.assertEqual(episodes(ps,2),episodes(list(reversed(ps)),2))

    def test_benign_never_alert(self):
        self.assertFalse(episodes([prediction(0,'BENIGN')],1)[0]['alert'])


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.train=[r for c in CLASSES for r in rows('TRAIN',count=2,label=c)]
        for i,r in enumerate(cls.train):r['features']['sql_token_count']=float(i)
        cls.classifier,cls.classes=fit_classifier(cls.train)
        benign=rows('TRAIN');cls.novelty={'IF':fit_novelty('IF',benign)}
        cls.package=Package(cls.novelty,cls.classifier,cls.classes,robust_reference(matrix(benign)),
            {'selected_model':'IF','thresholds':{'IF':-.6},'confidence_threshold':.8,'persistence':2})

    def test_save_load_preserves_predictions_no_fit(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'candidate';self.package.save(target)
            with patch('sklearn.ensemble.IsolationForest.fit',side_effect=AssertionError('No fitting')), \
                 patch('xgboost.XGBClassifier.fit',side_effect=AssertionError('No fitting')):
                restored=load(target);self.assertEqual(self.package.predict(rows('TEST')),restored.predict(rows('TEST')))

    def test_package_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):self.package.save(tmp)

    def test_package_integrity_rejects_modification(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'candidate';self.package.save(target)
            (target/'config.json').write_text('{}')
            with self.assertRaises(ValueError):load(target)

    def test_real_shap_truthful_additivity(self):
        ps=self.package.predict(rows('TEST'),explain=True)
        self.assertTrue(all(p['shap']['causal'] is False for p in ps))
        for p in ps:
            if p['shap']['status']=='AVAILABLE':self.assertLess(p['shap']['additivity_max_absolute_error'],1e-4)
            else:self.assertEqual(p['shap']['top_features'],[])

    def test_shap_failure_not_fabricated(self):
        with patch.object(self.classifier,'get_booster',side_effect=ValueError('fixture')):
            es=self.package.shap(matrix(rows()),np.zeros(16,dtype=int))
        self.assertTrue(all(e['status']=='UNAVAILABLE_OR_INCOMPATIBLE' and not e['top_features'] for e in es))

    def test_inference_no_network_or_raw_logs(self):
        with patch('socket.socket',side_effect=AssertionError('No network')):
            ps=self.package.predict(rows('TEST'))
        self.assertEqual(len(ps),16)

    def test_run_aggregation_deterministic_no_truth_in_decision(self):
        ps=self.package.predict(rows('TEST'));a=run_predictions(ps,self.package)
        self.assertEqual(a,run_predictions(list(reversed(ps)),self.package))
        changed=[{**p,'label':'SQLI_ATTEMPT'} for p in ps]
        b=run_predictions(changed,self.package)
        self.assertEqual([p['reconciliation'] for p in a],[p['reconciliation'] for p in b])


class ProvenanceTests(unittest.TestCase):
    def source_fixture(self,tmp):
        root=Path(tmp);session=root/'live';session.mkdir()
        line='192.0.2.1 - - [01/Jan/2020:00:00:01 +0000] "GET /moodle/my/?token=fixture-secret HTTP/1.1" 200 100 "-" "FixtureBrowser"\n'
        source=root/'source.log';source.write_text(line);raw=source.read_bytes();digest=sha(source)
        from branch2.adapters.apache import parse_line
        e=parse_line(line,str(source),digest,1)
        row={**rows(count=1)[0],'run_id':'external-fixture','label':None,'features':base_extract([e]),
             'source_file':str(source),'source_sha256':digest,'client_id':e.client_id}
        ranges=[{'start':0,'end':len(raw),'sha256':digest}]
        stat=source.stat()
        p={'record_id':'record','source_path':str(source),'source_file':str(source),'source_sha256':digest,
           'source_inode':stat.st_ino,'source_device':stat.st_dev,'source_byte_ranges':ranges,
           'client_id':e.client_id,'window_start':row['window_start'],'window_end':row['window_end'],
           'observation_count':1,'sequence':1}
        (session/'predictions.jsonl').write_text(json.dumps(p)+'\n')
        (session/'windows.jsonl').write_text(json.dumps({'record_id':'record','row':row,'source_byte_ranges':ranges})+'\n')
        return session,source

    def test_bounded_external_recovery_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            session,source=self.source_fixture(tmp)
            before=sha(source);rs,ps,es=external(session)
            self.assertEqual(before,sha(source));self.assertEqual(len(rs),1)
            self.assertNotIn('fixture-secret',json.dumps(rs));self.assertIsNone(rs[0]['label'])
            self.assertEqual(rs[0]['partition'],'EXTERNAL_DIAGNOSTIC_HOLDOUT')

    def test_external_byte_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            session,source=self.source_fixture(tmp);source.write_bytes(source.read_bytes().replace(b'200',b'201'))
            with self.assertRaises(ValueError):external(session)

    def test_unrecoverable_source_never_guesses_features(self):
        with tempfile.TemporaryDirectory() as tmp:
            session,source=self.source_fixture(tmp)
            with patch('pathlib.Path.open',side_effect=FileNotFoundError):
                with self.assertRaises(FileNotFoundError):external(session)

    def test_browser_plan_deterministic_no_network(self):
        with patch('socket.socket',side_effect=AssertionError('No network')):
            a=plan(42);b=plan(42)
        self.assertEqual(a,b);self.assertEqual(len(a['runs']),24)
        self.assertEqual(len({r['run_id'] for r in a['runs']}),24)
        self.assertTrue(all(r['label_proposal']=='BENIGN_PENDING_PROTOCOL_REVIEW' for r in a['runs']))
        self.assertNotEqual(a,plan(43));self.assertEqual(a['network_requests_made'],0)

    def test_discover_latest_by_evidence_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            for session,date in (('new','2026-10-09'),('old','2026-10-08')):
                d=Path(tmp)/session/'live_001';d.mkdir(parents=True)
                (d/'predictions.jsonl').write_text(json.dumps({'emitted_at_utc':date+'T20:00:00+00:00'})+'\n')
            self.assertEqual(discover(tmp).parent.name,'new')

    def test_write_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'artifact.json';write(path,{'value':1})
            with self.assertRaises(FileExistsError):write(path,{'value':2})

    def test_protocol_declares_test_external_exclusion(self):
        self.assertIn('not fully blind',PROTOCOL['external_use'])
        self.assertEqual(PROTOCOL['seed'],42)


class StudyIntegrationTests(unittest.TestCase):
    def test_selection_freezes_before_test_fit_provenance_and_replay(self):
        from test_branch2_final import fixture
        from branch2.models import train
        from branch2.artifacts import save
        from behavioral_v2.experiment import train_study
        old=fixture();old['feature_schema']=base_schema()
        d=copy.deepcopy(old);d['feature_schema']=schema()
        for row in d['rows']:
            row.update(features={**row['features'],**dict.fromkeys(ADDED,0.)},schema_sha256=schema()['sha256'])
        split=split_final_runs(d)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);v1,_=train(old,split,contamination=.15)
            v1.metadata['selected_contamination']=.15
            save(v1,root/'v1',split,{},[],'fixture')
            output=root/'study';original=Package.predict;observed=[]
            def tracked(package,rs,**kwargs):
                if rs and rs[0].get('partition')=='TEST':
                    self.assertTrue((output/'selection_freeze.json').exists())
                    observed.append('TEST_AFTER_FREEZE')
                return original(package,rs,**kwargs)
            with patch.object(Package,'predict',tracked),patch('socket.socket',side_effect=AssertionError('No network')):
                package=train_study(d,split,old,root/'v1',output)
            self.assertTrue(observed)
            self.assertEqual(package.config['fit_run_ids'],split['train_runs'])
            self.assertFalse(package.config['test_used_for_selection'])
            self.assertTrue(all(r in split['train_runs'] for r in package.config['benign_fit_run_ids']))
            self.assertEqual(set(package.classes),set(CLASSES))
            self.assertTrue(json.loads((output/'replay_consistency.json').read_text())['predictions_identical'])


if __name__=='__main__':unittest.main()
