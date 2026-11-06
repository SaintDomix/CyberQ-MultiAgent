"""Focused stopped-original handoff checks. Fixtures only, no live operations."""
import copy
import fcntl
import json
import os
from pathlib import Path
import time
from unittest.mock import Mock
from types import SimpleNamespace

import pytest
from coursework import lab
from scripts import coursework_lab as controller


@pytest.fixture
def proc(tmp_path):
    root=tmp_path/'proc'
    (root/'net').mkdir(parents=True)
    (root/'sys/kernel/random').mkdir(parents=True)
    (root/'sys/kernel/random/boot_id').write_text('test-boot')
    for name in ('tcp','tcp6'):(root/'net'/name).write_text('header\n')
    return root


def test_stopped_requires_no_listener_and_no_workers(proc):
    assert lab.stopped_original(proc=proc)=={'boot_id':'test-boot','port_8000_listening':False,'original_workers':[]}


@pytest.mark.parametrize('family',['tcp','tcp6'])
def test_listener_restart_fails_closed(proc,family):
    (proc/'net'/family).write_text('header\n 0: 00000000:1F40 00000000:0000 0A\n')
    with pytest.raises(ValueError,match='listener'):lab.stopped_original(proc=proc)


def test_worker_without_listener_fails_closed(proc):
    p=proc/'123';p.mkdir();(p/'cwd').mkdir()
    (p/'comm').write_text('python3')
    (p/'cmdline').write_bytes(b'/home/saintdomix/dissertation_model/.venv/bin/python\0scripts/run_behavioral_v2_live.py\0')
    with pytest.raises(ValueError,match='worker'):lab.stopped_original(proc=proc)


def test_http_failure_is_not_used_as_stopped_proof(proc,monkeypatch):
    monkeypatch.setattr(lab,'stopped_original',lambda:lab_stopped(proc=proc))
    ready={'external_exclusion_method':'STOPPED_ORIGINAL_BACKEND','original_boot_id':'test-boot'}
    assert lab.verify_exclusion(ready)['original_workers']==[]
    with pytest.raises(ValueError):lab.verify_exclusion({**ready,'original_boot_id':'old-boot'})
    with pytest.raises(ValueError):lab.verify_exclusion({'external_exclusion_verified':True})
    (proc/'net/tcp').write_text('header\n 0: 00000000:1F40 00000000:0000 0A\n')
    with pytest.raises(ValueError):lab.verify_exclusion(ready)


lab_stopped=lab.stopped_original


def test_release_can_read_realistic_sized_completed_posture_response(monkeypatch):
    payload=json.dumps({'status':'COMPLETE','test_only_padding':'x'*1200000}).encode()
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,limit):return payload[:limit]
    monkeypatch.setattr(controller.urllib.request,'build_opener',lambda *args:SimpleNamespace(open=lambda *args,**kwargs:Response()))
    assert controller.read_api(8001,'posture/assessments/latest')['status']=='COMPLETE'


def directory_proof():
    directory={'path':'/dev/shm/coursework-zap-test','uid':1000,'mode':0o700,'device':1,'inode':22,'symlink':False}
    return {'schema':'coursework-zap-directory-1','observed_at':time.time(),'loopback_8082':True,
            'owner':{'pid':99,'uid':1000,'directory':directory},'other_zap_directories':[]}


@pytest.mark.parametrize('fault',['none','shared','public','default','stale','external_listener'])
def test_direct_directory_evidence_is_required(fault):
    value=directory_proof()
    if fault=='none':assert lab.verify_zap_directory(value)==value['owner']['directory'];return
    if fault=='shared':value['other_zap_directories']=[copy.deepcopy(value['owner']['directory'])]
    if fault=='public':value['owner']['directory']['mode']=0o755
    if fault=='default':value['owner']['directory']['path']='/home/operator/.ZAP'
    if fault=='stale':value['observed_at']-=10801
    if fault=='external_listener':value['loopback_8082']=False
    with pytest.raises(ValueError):lab.verify_zap_directory(value)


def test_missing_kali_proof_cannot_generate_ready(monkeypatch):
    saved={}
    monkeypatch.setattr(controller,'stopped_original',lambda:{'boot_id':'test-boot'})
    monkeypatch.setattr(controller,'restart_audit',lambda:{'matching_service_or_cron_entries':[]})
    monkeypatch.setattr(controller,'private_json',Mock(side_effect=ValueError('missing direct probe')))
    monkeypatch.setattr(controller,'save',lambda name,value:saved.update({name:value}))
    assert controller.check_stopped() is False
    assert saved['readiness.json']['status']=='BLOCKED'
    assert 'external_exclusion_verified' not in saved['readiness.json']
    assert 'Kali directory' in saved['readiness.json']['blockers'][0]


@pytest.fixture
def recovery(tmp_path,monkeypatch):
    directory=tmp_path/'lab';directory.mkdir()
    lease=directory/'lease.json';lease.write_text(json.dumps({'status':'HELD','heartbeat_at':123}));lease.chmod(0o600)
    monkeypatch.setattr(controller,'DIRECTORY',directory)
    monkeypatch.setattr(controller,'idle',Mock())
    monkeypatch.setattr(controller,'zap_idle',Mock(return_value={'queues_idle':True}))
    monkeypatch.setattr(controller,'stopped_original',Mock(return_value={'original_workers':[]}))
    monkeypatch.setattr('sys.argv',['coursework_lab.py','recover'])
    monkeypatch.setattr(os,'kill',Mock(side_effect=AssertionError('No signals permitted in recovery')))
    return directory


def test_recovery_never_steals_live_controller_lock(recovery):
    with (recovery/'owner.lock').open('w') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):controller.main()
    assert json.loads((recovery/'lease.json').read_text())['status']=='HELD'


@pytest.mark.parametrize('busy',['idle','zap_idle'])
def test_recovery_requires_verified_cleanup(recovery,monkeypatch,busy):
    monkeypatch.setattr(controller,busy,Mock(side_effect=ValueError('busy')))
    with pytest.raises(ValueError):controller.main()
    assert json.loads((recovery/'lease.json').read_text())['status']=='HELD'


def test_recovery_releases_only_after_all_checks(recovery):
    controller.main()
    assert json.loads((recovery/'lease.json').read_text())=={'status':'RELEASED','heartbeat_at':0}
    assert 'ownership.recovered' in (recovery/'ownership-audit.jsonl').read_text()
    os.kill.assert_not_called()
