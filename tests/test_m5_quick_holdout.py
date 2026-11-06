"""Focused wrapper binding tests; no SSH, traffic, training or real holdout."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('quick_attack_wrapper',ROOT/'scripts/run_m5_fresh_attacks.py')
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
from branch2.capture.planning import schedule,sha
from branch2.dataset import CLASSES


class QuickHoldoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        context=json.loads((ROOT/'experiments/branch2_lab_context.template.json').read_text())
        self.plan=schedule(context,20261014,{c:0 if c=='BENIGN' else 1 for c in CLASSES},run_offset=60)
        self.remote=json.dumps({'package_manifest_sha256':'b'*64}).encode()
        self.plan['m5_freeze_sha256']=hashlib.sha256(self.remote).hexdigest()
        self.plan['schedule_sha256']=sha({k:v for k,v in self.plan.items() if k!='schedule_sha256'})
        p=self.root/'plan.json';p.write_text(json.dumps(self.plan))
        self.binding={'freeze_sha256':self.plan['m5_freeze_sha256'],
            'schedule_file_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
            'package_manifest_sha256':'b'*64,
            'freeze_relative_path':'outputs/branch2/m5_final_day/candidate_freeze_01/freeze_manifest.json',
            'worker_wrapper_sha256':hashlib.sha256((ROOT/'scripts/run_m5_fresh_attacks.py').read_bytes()).hexdigest()}

    def run_wrapper(self,*args):
        b=self.root/'binding.json';b.write_text(json.dumps(self.binding))
        return tool.main(['--plan',str(self.root/'plan.json'),'--binding',str(b),*args])

    def test_current_candidate_dry_run_zero_ssh_or_network(self):
        with patch.object(tool.subprocess,'run',side_effect=AssertionError('No SSH')),patch('socket.socket',side_effect=AssertionError('No HTTP')),patch('builtins.print'):
            self.assertEqual(self.run_wrapper('--dry-run'),0)

    def test_binding_rejects_arbitrary_remote_path(self):
        self.binding['freeze_relative_path']='../../outside; echo unsafe'
        with patch.object(tool.subprocess,'run',side_effect=AssertionError('No SSH')),patch('sys.stderr'):
            self.assertEqual(self.run_wrapper('--authorized'),2)

    def test_actual_remote_path_is_candidate_not_legacy_pointer(self):
        with patch.object(tool.subprocess,'run',return_value=type('Response',(),{'stdout':self.remote})()) as remote,patch.object(tool,'capture',return_value={'UNIT_TEST_ONLY':True}),patch('builtins.print'):
            self.assertEqual(self.run_wrapper('--authorized'),0)
        self.assertEqual(remote.call_args.args[0][-1],'/home/saintdomix/dissertation_model/outputs/branch2/m5_final_day/candidate_freeze_01/freeze_manifest.json')

    def test_changed_wrapper_rejected_before_ssh(self):
        self.binding['worker_wrapper_sha256']='0'*64
        with patch.object(tool.subprocess,'run',side_effect=AssertionError('No SSH')),patch('sys.stderr'):
            self.assertEqual(self.run_wrapper('--dry-run'),2)


if __name__=='__main__':unittest.main()
