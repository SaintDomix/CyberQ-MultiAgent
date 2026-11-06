"""Operational probes/lifecycle contracts; no real processes, traffic or fitting."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from demo.preflight import preflight
from demo.backend.config import Config
from demo.backend.services import Application
from demo import operations
from demo.release_benchmarks import statistics
from demo.release_pack import snapshots, table, frozen, narrative


class ReleaseOperationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.config=Config(repository=self.root,apache_source=str(self.root/'absent.log'))
        self.application=Mock();self.application.model.return_value={'integrity':'VERIFIED','package_id':'fixture','root_sha256':'fixture'}
        self.application.snapshot.return_value={'observations':[{}],'status':SimpleNamespace(last_error=None)}
        self.fake_app=patch('demo.preflight.Application',return_value=self.application);self.fake_app.start()

    def tearDown(self):self.fake_app.stop();self.tmp.cleanup()

    def check(self,mode='ACCEPTED_REPLAY'):
        with patch('demo.preflight.socket.socket') as socket:
            return preflight(mode,8000,self.config)

    def test_replay_unreadable_apache_is_warning_not_silent_live(self):
        result=self.check();self.assertEqual(result['result'],'PASS_WITH_WARNINGS')
        self.assertFalse(result['apache_contents_opened']);self.assertFalse(result['training_performed'])

    def test_live_missing_source_is_fail_closed(self):
        self.assertEqual(self.check('LIVE_LAB')['result'],'FAIL')

    def test_available_live_probe_is_pass_and_leaves_no_database(self):
        source=self.root/'apache.log';source.write_text('')
        self.config=Config(repository=self.root,apache_source=str(source))
        self.assertNotEqual(self.check('LIVE_LAB')['result'],'FAIL')
        self.assertEqual(list((self.root/'runtime').iterdir()),[])

    def test_corrupt_model_gates_preflight(self):
        self.application.model.return_value={'integrity':'FAILED','error':'invalid'}
        self.assertEqual(self.check()['result'],'FAIL')

    def test_occupied_port_fails(self):
        with patch('demo.preflight.socket.socket') as socket:
            socket.return_value.__enter__.return_value.bind.side_effect=OSError
            self.assertEqual(preflight(config=self.config)['result'],'FAIL')

    def test_port_probe_matches_server_reuse_without_reuseport(self):
        import socket as real_socket
        with patch('demo.preflight.socket.socket') as socket:
            preflight(config=self.config)
            socket.return_value.__enter__.return_value.setsockopt.assert_called_once_with(
                real_socket.SOL_SOCKET, real_socket.SO_REUSEADDR, 1)

    def test_disk_minimum_is_explicit(self):
        with patch('demo.preflight.shutil.disk_usage',return_value=SimpleNamespace(free=100)):
            self.assertEqual(self.check()['result'],'FAIL')

    def test_invalid_port_mode_rejected(self):
        with self.assertRaises(ValueError):preflight('arbitrary',8000,self.config)
        with self.assertRaises(ValueError):preflight(port=22,config=self.config)

    def test_pid_reuse_never_authorizes_signal(self):
        state={'pid':123,'start_ticks':'old','argv':['python','owned']}
        with patch('demo.operations.identity',return_value={'start_ticks':'new','argv':[b'python',b'owned']}):self.assertFalse(operations.owned(state))

    def test_already_stopped_does_not_signal(self):
        with patch('demo.operations.read_state',return_value={}),patch('demo.operations.owned',return_value=False),patch('demo.operations.os.kill') as kill:
            self.assertEqual(operations.stop()['status'],'ALREADY_STOPPED_OR_NOT_OWNED');kill.assert_not_called()

    def test_duplicate_start_refused(self):
        with patch('demo.operations.owned',return_value=True),patch('demo.operations.subprocess.Popen') as popen:
            with self.assertRaises(ValueError):operations.start('ACCEPTED_REPLAY',8000)
            popen.assert_not_called()

    def test_preflight_failure_never_starts_child(self):
        with patch('demo.operations.owned',return_value=False),patch('demo.operations.preflight',return_value={'result':'FAIL'}),patch('demo.operations.subprocess.Popen') as popen:
            with self.assertRaises(ValueError):operations.start('LIVE_LAB',8000)
            popen.assert_not_called()

    def test_owned_stop_targets_one_exact_pid(self):
        state={'pid':123,'port':8000,'argv':['python'],'start_ticks':'saved'}
        with patch('demo.operations.read_state',return_value=state),patch('demo.operations.owned',side_effect=[True,False,False]),patch('demo.operations.api'),patch('demo.operations.os.kill') as kill,patch('branch2.live_storage.atomic_json'):
            result=operations.stop();self.assertEqual(result['status'],'STOPPED')
            kill.assert_called_once();self.assertEqual(kill.call_args.args[0],123)

    def test_performance_statistics_actual_sample_formula(self):
        s=statistics([1.,2.,3.,4.]);self.assertEqual(s['mean'],2.5);self.assertEqual(s['median'],2.5);self.assertEqual(s['max'],4)
        self.assertAlmostEqual(s['p95'],3.85)
        with self.assertRaises(ValueError):statistics([])

    def test_export_table_refuses_overwrite(self):
        target=self.root/'table';table(target,[{'class':'BENIGN','support':2}])
        before=target.with_suffix('.json').read_bytes()
        with self.assertRaises(FileExistsError):table(target,[{'support':3}])
        self.assertEqual(target.with_suffix('.json').read_bytes(),before)

    def test_partial_posture_snapshot_never_invents_D6(self):
        values=snapshots(Application(Config()))['snapshots']
        partial=values[0];self.assertIsNone(partial['as_of'])
        self.assertIsNone(next(d['quality'] for d in partial['dimensions'] if d['dimension']=='D6'))
        self.assertEqual(partial['status'],'PARTIAL_EVIDENCE')
        normal=next(s for s in values if s['id']=='NORMAL_BENIGN');known=next(s for s in values if s['id']=='KNOWN_ATTEMPT')
        self.assertEqual(normal['active_incidents'],0);self.assertGreater(known['active_incidents'],0)
        self.assertTrue(all(normal['dimensions'][i]['quality']==known['dimensions'][i]['quality'] for i in range(5)))

    def test_final_narrative_reads_locked_results_without_fit(self):
        app=Application(Config());research=app.research()
        report,md=narrative(app,research,frozen('development_manifest.json'),frozen('validation_metrics.json'),frozen('validation_run_metrics.json'))
        self.assertFalse(report['training_performed']);self.assertFalse(report['statistical_significance_claimed'])
        self.assertIn('3.03%',md);self.assertIn('93.94%',md);self.assertIn('97.06%',md)
        self.assertIn('diagnostic-only',md);self.assertEqual(md.count('\n## '),13)


class OperatorAcceptanceTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('live_acceptance_tool',ROOT/'scripts/live_acceptance.py')
        self.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.tool)
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.pending=self.root/'pending.json'

    def tearDown(self):self.tmp.cleanup()

    def test_finish_requires_actual_operator_attestation(self):
        self.pending.write_text(json.dumps({'before':{'runtime':{'session_id':'fixture'}},'receipt_id':'fixture'}))
        with patch.object(self.tool,'PENDING',self.pending),patch.object(self.tool,'owned',return_value=True),patch.object(self.tool,'read_state',return_value={'port':8000}),patch('builtins.input',return_value='NO'):
            with self.assertRaises(ValueError):self.tool.run('finish')
        self.assertTrue(self.pending.exists())

    def test_no_closed_observations_is_pending_not_pass(self):
        before={'runtime':{'session_id':'fixture'},'observation_count':4,'incident_count':0}
        self.pending.write_text(json.dumps({'before':before,'receipt_id':'fixture'}))
        with patch.object(self.tool,'ROOT',self.root),patch.object(self.tool,'PENDING',self.pending),patch.object(self.tool,'owned',return_value=True),patch.object(self.tool,'read_state',return_value={'port':8000}),patch.object(self.tool,'api',return_value=before):
            result=self.tool.run('finish',confirm=True)
        self.assertEqual(result['status'],'PENDING_CLOSED_WINDOWS')
        self.assertEqual(result['new_observations'],0)


if __name__=='__main__':unittest.main()
