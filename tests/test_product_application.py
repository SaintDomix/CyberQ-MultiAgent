"""Application contracts use temporary sources; no live jobs or network traffic."""
import asyncio
from contextlib import ExitStack
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo.backend.app import create_app
from demo.backend.config import Config
from demo.backend.services import Application, SOURCE_HASHES
from demo.backend.adapters import finding, observation
from demo.backend.runtime import LiveControl, read_journal, SourceUnavailable
from branch2.live_storage import Journal, atomic_json
from behavioral_runtime.incidents import Incidents


def hashfile(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class ProductApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Application(Config())
        cls.real = cls.source.snapshot()
        cls.root_manifest = json.loads((ROOT / 'demo/artifact_sources.json').read_text())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # Copy accepted bytes into temporary roots; tests never modify originals.
        for name in ('accepted', 'benign', 'attack'):
            source = getattr(Config(), name)
            target = self.root / name
            if name == 'accepted': shutil.copytree(ROOT / source, target)
            else:
                target.mkdir()
                selected = ['candidate_predictions.json', 'artifact_manifest.json'] if name == 'benign' else [
                    'predictions.json', 'artifact_hashes.json', 'candidate_metrics.json', 'v1_metrics.json']
                for filename in selected: shutil.copyfile(ROOT / source / filename, target / filename)
        shutil.copyfile(ROOT / Config().posture, self.root / 'posture.json')
        self.config = Config(repository=self.root, accepted='accepted', posture='posture.json', benign='benign', attack='attack')
        self.service = Application(self.config)
        self.app = create_app(self.config, self.service)
        self.guards = ExitStack()
        for name in ('socket.create_connection', 'socket.socket.connect', 'socket.getaddrinfo',
                     'sklearn.svm.OneClassSVM.fit', 'sklearn.ensemble.IsolationForest.fit',
                     'xgboost.XGBClassifier.fit'):
            self.guards.enter_context(patch(name, side_effect=AssertionError('Forbidden network/training')))

    def tearDown(self):
        self.guards.close()
        self.tmp.cleanup()

    def request(self, path, method='GET', **kwargs):
        async def perform():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url='http://testserver') as c:
                return await c.request(method, path, **kwargs)
        return asyncio.run(perform())

    def test_health_and_model_identity(self):
        self.assertEqual(self.request('/api/health').status_code, 200)
        m = self.request('/api/model').json()
        self.assertEqual(m['integrity'], 'VERIFIED'); self.assertEqual(m['feature_count'], 83)
        self.assertEqual(m['root_sha256'], self.config.expected_root)
        self.assertEqual(m['novelty_detector'], 'OCSVM'); self.assertEqual(m['persistence'], 2)

    def test_all_required_read_routes(self):
        for route in ('system/status','model/evaluation','posture/findings','behavior/observations',
                      'behavior/incidents','fusion/events','cqi','cqi/dimensions','runtime/status',
                      'research/benign-comparison','research/attack-comparison','application/snapshot'):
            with self.subTest(route=route): self.assertEqual(self.request('/api/' + route).status_code, 200)

    def test_all_posture_states_and_missing_severity_preserved(self):
        rows = self.request('/api/posture/findings').json()['items']
        self.assertEqual(len(rows), 40)
        from collections import Counter
        self.assertEqual(Counter(r['status'] for r in rows), {'FAIL':21,'PASS':15,'PARTIAL':3,'DISMISSED':1})
        dismissed = next(r for r in rows if r['status'] == 'DISMISSED')
        self.assertIsNone(dismissed['severity']); self.assertIsNone(dismissed['created_at'])

    def test_posture_pagination_and_filters(self):
        rows = self.request('/api/posture/findings?status=FAIL&dimension=D1&limit=2&offset=1').json()
        self.assertEqual(len(rows['items']), 2); self.assertGreater(rows['total'], 2)
        self.assertTrue(all(r['status']=='FAIL' and r['dimension']=='D1' for r in rows['items']))

    def test_details_evidence_and_no_arbitrary_files(self):
        self.assertEqual(self.request('/api/posture/findings/TLS-001').json()['finding_id'], 'TLS-001')
        self.assertEqual(self.request('/api/evidence/TLS-001').json()['type'], 'POSTURE')
        self.assertEqual(self.request('/api/evidence/not-a-file').status_code, 404)
        self.assertEqual(self.request('/api/evidence/%2e%2e%2fconfig.php').status_code, 404)

    def test_query_validation_does_not_echo_secrets(self):
        r = self.request('/api/behavior/observations?limit=PASSWORD_SECRET&mode=bad')
        self.assertEqual(r.status_code, 422); self.assertNotIn('PASSWORD_SECRET', r.text)
        self.assertEqual(self.request('/api/behavior/observations?limit=201').status_code, 422)

    def test_isolated_benign_anomaly_is_not_incident(self):
        s = self.service.snapshot(replay='BENIGN_TEST')
        isolated = [o for o in s['observations'] if o.reconciled_label == 'UNKNOWN_ANOMALY']
        self.assertEqual(len(isolated), 1); self.assertEqual(s['incidents'], [])
        self.assertFalse(isolated[0].actionable)
        self.assertEqual(isolated[0].presentation_state, 'SUPPRESSED_ISOLATED_ANOMALY')
        self.assertIsNone(isolated[0].episode_id)

    def test_behavior_filter_and_real_upstream_explanation(self):
        d = self.request('/api/behavior/observations?label=SQLI_ATTEMPT&limit=2').json()
        self.assertTrue(all(o['reconciled_label']=='SQLI_ATTEMPT' for o in d['items']))
        oid = d['items'][0]['observation_id']
        explanation = self.request('/api/explainability/' + oid).json()
        self.assertEqual(explanation['shap']['status'], 'AVAILABLE')
        self.assertEqual(explanation['shap']['output_space'], 'raw model margin')
        self.assertFalse(explanation['causal'])
        self.assertIn('not causal', explanation['robust_semantics'])

    def test_incident_details_context_and_attempt_semantics(self):
        e = self.request('/api/behavior/incidents?label=SQLI_ATTEMPT').json()['items'][0]
        self.assertEqual(e['class'], 'SQLI_ATTEMPT'); self.assertGreater(e['observation_count'], 1)
        self.assertFalse(e['successful_exploitation_confirmed'])
        d = self.request('/api/behavior/incidents/' + e['episode_id']).json()
        self.assertEqual(d, e)

    def test_fusion_is_contextual_and_cannot_change_cqi(self):
        s = self.service.snapshot(run_id='SQ01-run71')
        self.assertTrue(any('ADV-MSA-26-0031' in f.related_posture_finding_ids for f in s['fusion']))
        for f in s['fusion']:
            self.assertFalse(f.causal); self.assertFalse(f.exploit_confirmed); self.assertEqual(f.score_effect, 'NONE')
        original = s['cqi'].overall
        s['fusion'].clear()
        self.assertEqual(self.service.snapshot(run_id='SQ01-run71')['cqi'].overall, original)

    def test_cqi_is_frozen_formula_and_six_bounded_dimensions(self):
        s = self.service.snapshot()
        q = s['cqi']; self.assertFalse(q.is_probability)
        self.assertFalse(q.policy['weights_are_empirically_calibrated'])
        self.assertEqual(q.overall, s['artifacts']['cqi']['cqi'])
        self.assertEqual(len(q.dimensions), 6)
        self.assertTrue(all(0<=d.score<=100 and d.policy_weight==1/6 for d in q.dimensions))
        self.assertAlmostEqual(sum(d.policy_weight for d in q.dimensions), 1)
        self.assertEqual(len(q.sensitivity['variants']), 12)

    def test_unknown_suppression_does_not_silently_change_cqi(self):
        s = self.service.snapshot(replay='BENIGN_TEST', run_id='M5FD-20261014-023')
        # Assert from actual selected evidence rather than inventing an anomaly location.
        for rid in s['status'].runtime['available_runs']:
            selected = self.service.snapshot(replay='BENIGN_TEST', run_id=rid)
            if any(o.reconciled_label=='UNKNOWN_ANOMALY' for o in selected['observations']):
                self.assertEqual(len(selected['incidents']), 0)
                self.assertLess(selected['cqi'].dimensions[5].score, 100)
                break
        else: self.fail('Expected locked isolated anomaly')

    def test_research_metrics_are_loaded_unchanged(self):
        b = self.request('/api/research/benign-comparison').json()
        a = self.request('/api/research/attack-comparison').json()
        self.assertEqual(b['candidate']['novelty']['anomalous_windows'], 1)
        self.assertEqual(b['model_v1']['novelty']['anomalous_windows'], 31)
        self.assertEqual(b['candidate']['episode']['benign_runs_alerted'], 0)
        self.assertEqual(a['candidate']['reconciled']['detected_runs'], 14)
        self.assertEqual(a['candidate']['reconciled']['window_recall'], 1)

    def test_missing_runtime_no_silent_replay(self):
        s = self.request('/api/application/snapshot?mode=LIVE_LAB').json()
        self.assertEqual(s['observations'], []); self.assertEqual(s['incidents'], [])
        self.assertIsNone(s['cqi']); self.assertIn('not substituted', s['status']['last_error'])
        self.assertEqual(self.request('/api/cqi?mode=LIVE_LAB').status_code, 503)

    def test_model_corruption_visible_and_start_blocked(self):
        self.service.model()
        with (self.root/'accepted/model/xgboost.json').open('ab') as f: f.write(b' ')
        self.assertEqual(self.request('/api/model').json()['integrity'], 'FAILED')
        s = self.request('/api/application/snapshot').json()
        self.assertEqual(s['observations'], []); self.assertIsNone(s['cqi'])
        self.assertEqual(self.request('/api/runtime/start', 'POST', headers={'X-Product-Control':'1'}, json={}).status_code, 503)

    def test_missing_or_changed_source_unavailable(self):
        (self.root/'attack/predictions.json').unlink()
        s = self.service.snapshot()
        self.assertEqual(s['observations'], []); self.assertIsNone(s['cqi'])
        (self.root/'posture.json').write_text('[]')
        self.assertEqual(self.request('/api/posture/findings').status_code, 503)

    def test_read_only_sources_and_cache_determinism(self):
        before = {str(p):hashfile(p) for p in self.root.rglob('*') if p.is_file()}
        first = self.service.snapshot(); second = self.service.snapshot()
        self.assertEqual(first['status'].source_generation, second['status'].source_generation)
        self.assertEqual(first['cqi'], second['cqi'])
        self.assertEqual(before, {str(p):hashfile(p) for p in self.root.rglob('*') if p.is_file()})

    def test_path_scope_and_symlink_escape(self):
        with self.assertRaises(ValueError): Config(repository=self.root, posture='../outside.json')
        with self.assertRaises(ValueError): Config(repository=self.root, runtime_session='outputs/branch2/m2c_final_01')
        (self.root/'outside').symlink_to('/tmp')
        with self.assertRaises(ValueError): Config(repository=self.root, posture='outside/secret')

    def test_controls_require_explicit_local_request_and_empty_body(self):
        self.assertEqual(self.request('/api/runtime/start', 'POST', json={}).status_code, 403)
        self.assertEqual(self.request('/api/runtime/start', 'POST', headers={'X-Product-Control':'1','origin':'http://evil.example'},json={}).status_code,403)
        r=self.request('/api/runtime/start','POST',headers={'X-Product-Control':'1'},json={'password':'PRIVATE'})
        self.assertEqual(r.status_code,422); self.assertNotIn('PRIVATE',r.text)

    def test_controls_safe_command_stop_and_duplicate_prevention(self):
        source=self.root/'apache.log';source.write_text('')
        config=Config(repository=self.root,apache_source=str(source))
        proc=Mock();proc.poll.return_value=None
        factory=Mock(return_value=proc);control=LiveControl(config,factory)
        self.assertTrue(control.start()['process_running'])
        args,options=factory.call_args
        self.assertIsInstance(args[0],list);self.assertFalse(options['shell'])
        self.assertIn('run_behavioral_v2_live.py',args[0][2]);self.assertNotIn('train',' '.join(args[0]))
        with self.assertRaises(SourceUnavailable):control.start()
        control.stop();proc.send_signal.assert_called_once();proc.wait.assert_called_once()

    def test_no_secret_fields_in_domain_adapter(self):
        row=json.loads((self.root/'posture.json').read_text())[0]
        row['evidence']={'password':'PRIVATE','cookie':'PRIVATE','url':'https://example.test/moodle/?token=PRIVATE'}
        row['explanation']='password=PRIVATE'
        value=finding(row).model_dump_json()
        self.assertNotIn('PRIVATE',value)
        self.assertNotIn('raw_record',value)

    def test_sqlite_live_projection_and_new_data_changes_snapshot(self):
        model=self.service.model();path=self.root/'runtime/behavioral_v2/synthetic';path.mkdir(parents=True)
        raw=copy.deepcopy(json.loads((self.root/'attack/predictions.json').read_text())['candidate'][0])
        raw.update(model_id=model['package_id'],schema_sha256=model['schema_sha256'],session_id='synthetic',
                   record_id='synthetic-observation',observation_id='synthetic-observation',emitted_at_utc=raw['window_end'])
        atomic_json(path/'session_manifest.json',{'model_id':model['package_id'],'schema_sha256':model['schema_sha256'],
            'session_id':'synthetic','source_path':'/synthetic/access.log'})
        atomic_json(path/'checkpoint.json',{'source':{'read_offset':120,'safe_offset':120},'updated_at_utc':raw['window_end'],'integrity_status':'OK'})
        journal=Journal(path)
        incidents=Incidents(journal,2,model['package_id'])
        self.service.control.session=path
        empty=self.service.snapshot(mode='LIVE_LAB');self.assertIsNone(empty['cqi'])
        journal.persist({'record_id':raw['record_id']},raw);incidents.sync();journal.close()
        before={str(p):hashfile(p) for p in path.iterdir() if p.is_file()}
        populated=self.service.snapshot(mode='LIVE_LAB')
        self.assertEqual(len(populated['observations']),1);self.assertIsNotNone(populated['cqi'])
        self.assertNotEqual(empty['status'].source_generation,populated['status'].source_generation)
        self.assertEqual(before,{str(p):hashfile(p) for p in path.iterdir() if p.is_file()})
        self.assertEqual(populated['status'].runtime['sqlite_status'],'VERIFIED_READ_ONLY')

    def test_replay_ids_and_selected_run_deterministic(self):
        a=self.service.snapshot(run_id='SQ01-run71');b=self.service.snapshot(run_id='SQ01-run71')
        self.assertEqual(a['observations'],b['observations'])
        self.assertTrue(all(o.evidence['run_id']=='SQ01-run71' for o in a['observations']))
        invalid=self.service.snapshot(run_id='not-reserved')
        self.assertEqual(invalid['observations'],[])

    def test_owned_process_crash_visible_and_no_unrelated_stop(self):
        process=Mock();process.poll.return_value=7
        control=LiveControl(self.config);control.process=process
        result=control.status()
        self.assertEqual(result['process_state'],'ERROR');self.assertFalse(result['process_running'])
        self.assertIsNotNone(result['last_error'])
        control.stop();process.send_signal.assert_not_called()

    def test_runtime_payload_corruption_fails_read_only(self):
        model=self.service.model();path=self.root/'runtime/behavioral_v2/corrupt';path.mkdir(parents=True)
        atomic_json(path/'session_manifest.json',{'model_id':model['package_id'],'schema_sha256':model['schema_sha256']})
        j=Journal(path)
        with j.db:
            j.db.execute('INSERT INTO results VALUES (1,?,?,?)',('bad','{}','bad'))
            j.db.execute('CREATE TABLE incidents (payload TEXT,sha256 TEXT)')
        j.close()
        before=hashfile(path/'journal.sqlite3')
        with self.assertRaises(SourceUnavailable):read_journal(path,model['package_id'],model['schema_sha256'])
        self.assertEqual(hashfile(path/'journal.sqlite3'),before)

    def test_structurally_corrupt_manifest_reports_failed_not_verified(self):
        manifest=self.root/'accepted/accepted_manifest.json'
        manifest.write_text('[]')
        result=self.request('/api/model')
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json()['integrity'],'FAILED')

    def test_replay_scenarios_use_actual_reserved_evidence(self):
        d=self.request('/api/demo/scenarios').json()
        self.assertEqual(d['mode'],'ACCEPTED_REPLAY');self.assertEqual(len(d['items']),3)
        for s in d['items']:
            value=self.service.snapshot(replay=s['replay'],run_id=s['run_id'])
            self.assertTrue(value['observations'])
            if s['id']=='UNKNOWN_OBSERVATION':
                self.assertEqual(value['incidents'],[])
                self.assertTrue(any(o.reconciled_label=='UNKNOWN_ANOMALY' for o in value['observations']))

    def test_final_report_links_are_fixed_and_separate_from_history(self):
        meta=self.request('/api/report/final').json();self.assertFalse(meta['available'])
        out=self.root/'outputs/reports';out.mkdir(parents=True)
        (out/'behavioral_v2_final_report.md').write_text('# Accepted Behavioral v2\n')
        (out/'behavioral_v2_final_report.json').write_text('{"scope":"frozen evidence"}')
        self.assertTrue(self.request('/api/report/final').json()['available'])
        self.assertEqual(self.request(meta['markdown_url']).status_code,200)
        self.assertEqual(self.request(meta['json_url']).status_code,200)
        self.assertEqual(meta['historical_v1_url'],'/report.html')

    def test_health_declares_configured_mode(self):
        self.assertEqual(self.request('/api/health').json()['mode'],'ACCEPTED_REPLAY')

    def test_explicit_mode_selection_updates_health_without_starting_job(self):
        response=self.request('/api/demo/mode','POST',headers={'X-Product-Control':'1'},json={'mode':'LIVE_LAB'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.request('/api/health').json()['mode'],'LIVE_LAB')
        self.assertIsNone(self.service.control.process)
        self.assertEqual(self.request('/api/system/status').json()['mode'],'LIVE_LAB')


if __name__=='__main__':unittest.main()
