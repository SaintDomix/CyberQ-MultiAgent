"""Passive v2 contracts: synthetic HTTP records and temporary runtime state only."""
from contextlib import ExitStack
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from behavioral_runtime.package import load, verify
from behavioral_runtime.live import LiveEngine
from behavioral_runtime.incidents import Incidents
from branch2.live import LiveEngine as V1Engine
from branch2.live_storage import Journal, IntegrityFault
from branch2.reconciliation import reconcile

ACCEPTED = ROOT / 'outputs/branch2/accepted_behavioral_v2'
T = datetime(2020, 1, 1, tzinfo=timezone.utc)


def line(second=0):
    return (f'192.0.2.1 - - [01/Jan/2020:00:00:{second:02d} +0000] '
            '"GET /moodle/my/?password=SECRET&token=SECRET HTTP/1.1" 200 120 "-" "fixture cookie=SECRET"\n').encode()


def prediction(i, decision='UNKNOWN_ANOMALY'):
    anomaly = decision != 'BENIGN'
    guess = decision if decision not in ('UNKNOWN_ANOMALY', 'UNCERTAIN') else 'BENIGN'
    return {'record_id': f'record-{i}', 'observation_id': f'record-{i}', 'session_id': 'session',
            'client_id': 'client', 'user_agent_id': 'agent',
            'window_start': (T + timedelta(seconds=i * 10)).isoformat(),
            'window_end': (T + timedelta(seconds=(i + 1) * 10)).isoformat(),
            'reconciliation': reconcile(anomaly, guess, .99, .8)}


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.j = Journal(self.root)
        self.incidents = Incidents(self.j, 2, 'model')

    def tearDown(self):
        self.j.close()
        self.tmp.cleanup()

    def emit(self, p):
        self.j.persist({'record_id': p['record_id']}, p)
        self.incidents.sync()

    def test_isolated_unknown_is_observation_then_second_escalates(self):
        self.emit(prediction(0))
        self.assertEqual(self.incidents.values(), [])
        self.emit(prediction(1))
        e = self.incidents.values()[0]
        self.assertEqual(e['member_count'], 2)
        self.assertEqual(e['state'], 'UNKNOWN_ANOMALY_EPISODE')
        self.assertFalse(e['successful_exploitation_confirmed'])

    def test_known_attempt_can_alert_immediately_exact_frozen_semantics(self):
        self.emit(prediction(0, 'SQLI_ATTEMPT'))
        self.assertEqual(self.incidents.values()[0]['state'], 'KNOWN_THREAT_ATTEMPT_EPISODE')

    def test_gap_class_and_identity_break_contiguity(self):
        self.emit(prediction(0))
        self.emit(prediction(2))
        self.emit(prediction(3, 'BENIGN'))
        p = prediction(4); p['client_id'] = 'other'
        self.emit(p)
        self.assertEqual(self.incidents.values(), [])

    def test_recovery_after_observation_commit_before_incident_commit(self):
        self.j.persist({'record_id': 'record-0'}, prediction(0, 'XSS_ATTEMPT'))
        restored = Incidents(self.j, 2, 'model')
        self.assertEqual(len(restored.values()), 1)
        restored.sync()
        self.assertEqual(len(restored.values()), 1)

    def test_growth_updates_one_id_and_resume_is_idempotent(self):
        self.emit(prediction(0, 'SQLI_ATTEMPT'))
        episode_id = self.incidents.values()[0]['episode_id']
        self.emit(prediction(1, 'SQLI_ATTEMPT'))
        self.assertEqual(self.incidents.values()[0]['episode_id'], episode_id)
        self.assertEqual(self.incidents.values()[0]['member_count'], 2)
        restored = Incidents(self.j, 2, 'model')
        self.assertEqual(restored.values(), self.incidents.values())

    def test_corrupted_incident_hash_fails_closed(self):
        self.emit(prediction(0, 'SQLI_ATTEMPT'))
        self.j.db.execute("UPDATE incidents SET sha256='bad'"); self.j.db.commit()
        with self.assertRaises(IntegrityFault):
            self.incidents.values()


class AcceptedRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package = load(ACCEPTED)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source.log'; self.source.write_bytes(b'')
        self.now = T
        self.engines = []

    def tearDown(self):
        for engine in self.engines:
            engine.stop()
        self.tmp.cleanup()

    def engine(self, **kwargs):
        kwargs.setdefault('loader', lambda _: self.package)
        e = LiveEngine(self.source, ACCEPTED, self.root / 'session', clock=lambda: self.now, **kwargs)
        self.engines.append(e)
        return e

    def test_accepted_package_verifies_origin_and_schema(self):
        m = verify(ACCEPTED)
        self.assertEqual(m['decision'], 'A')
        self.assertEqual(len(self.package.feature_schema['feature_order']), 83)
        self.assertEqual(self.package.config['selected_model'], 'OCSVM')
        self.assertEqual(self.package.config['persistence'], 2)

    def test_corruption_rejected_before_source_or_runtime_creation(self):
        target = self.root / 'corrupt'
        shutil.copytree(ACCEPTED, target)
        with (target / 'model/xgboost.json').open('ab') as f: f.write(b' ')
        with self.assertRaises(ValueError):
            LiveEngine(self.source, target, self.root / 'bad', clock=lambda: self.now)
        self.assertFalse((self.root / 'bad').exists())

    def test_reuses_v1_reader_poll_stop_and_run(self):
        for method in ('poll', 'stop', 'run', 'model_fingerprint'):
            self.assertIs(getattr(LiveEngine, method), getattr(V1Engine, method))

    def test_saved_only_privacy_and_resume_no_duplicate(self):
        with ExitStack() as stack:
            for method in ('sklearn.svm.OneClassSVM.fit', 'sklearn.ensemble.IsolationForest.fit',
                           'sklearn.neighbors.LocalOutlierFactor.fit', 'sklearn.preprocessing.RobustScaler.fit',
                           'xgboost.XGBClassifier.fit', 'socket.create_connection', 'socket.socket.connect'):
                stack.enter_context(patch(method, side_effect=AssertionError('Forbidden')))
            e = self.engine(explain=False)
            self.source.write_bytes(line())
            self.now = T + timedelta(seconds=22); e.poll()
            self.assertEqual(e.journal.sequence, 1)
            before = (e.root / 'predictions.jsonl').read_bytes()
            incidents = e.incidents.values()
            e.stop()
            resumed = self.engine(resume=True, explain=False); resumed.poll()
            self.assertEqual(resumed.journal.sequence, 1)
            self.assertEqual((e.root / 'predictions.jsonl').read_bytes(), before)
            self.assertEqual(resumed.incidents.values(), incidents)
            for p in e.root.iterdir():
                if p.is_file(): self.assertNotIn(b'SECRET', p.read_bytes(), str(p))
            p = json.loads(before)
            self.assertEqual(p['observation_id'], p['record_id'])
            self.assertFalse(p['training_performed'])
            self.assertIn('novelty_score', p)

    def test_crash_before_checkpoint_recovers_observation_and_episode(self):
        e = self.engine(explain=False)
        self.source.write_bytes(line())
        self.now = T + timedelta(seconds=22)
        # Simulate process loss after journal commit and before caller checkpoint.
        with patch.object(e, 'checkpoint', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): e.poll()
        e.journal.close(); e.lock.close(); e.closed = True
        resumed = self.engine(resume=True, explain=False); resumed.poll()
        self.assertEqual(resumed.journal.sequence, 1)
        self.assertEqual(len((resumed.root / 'predictions.jsonl').read_text().splitlines()), 1)

    def test_duplicate_session_writer_rejected(self):
        self.engine(explain=False)
        with self.assertRaises(IntegrityFault): self.engine(resume=True, explain=False)

    def test_source_truncation_fails_closed(self):
        e = self.engine(explain=False)
        self.source.write_bytes(line())
        self.now = T + timedelta(seconds=22); e.poll()
        self.source.write_bytes(b'')
        with self.assertRaises(IntegrityFault): e.poll()

    def test_output_must_be_separate_from_source_and_package(self):
        with self.assertRaises(ValueError):
            LiveEngine(self.source, ACCEPTED, self.root, loader=lambda _: self.package)

    def test_schema_order_mismatch_rejected(self):
        p = copy.copy(self.package); p.feature_schema = copy.deepcopy(p.feature_schema)
        p.feature_schema['feature_order'].reverse()
        with self.assertRaises(ValueError): self.engine(loader=lambda _: p)


if __name__ == '__main__':
    unittest.main()
