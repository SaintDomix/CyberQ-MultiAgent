"""Parallel real-backend safety; no real operations, sockets or shared writes."""
import json,os,sqlite3,subprocess,sys
from pathlib import Path
from unittest.mock import patch
import pytest
from demo.backend.defense import CandidateBoundary,create_candidate,ROOT
from demo.backend.config import Config
from demo.backend.services import Application
from demo.backend.runtime import LiveControl
from posture.orchestration import PostureAssessmentOrchestrator
from test_ux_clarity import request

SESSION=ROOT/'runtime/behavioral_v2/ui-e01c26a593174d42bec5d45faf703576'
ASSETS=ROOT/'demo/frontend/preview-final-stabilization-20261104'

@pytest.fixture(scope='module')
def real_app(tmp_path_factory):
    state=tmp_path_factory.mktemp('parallel-state')
    with patch('requests.sessions.Session.request',side_effect=AssertionError('No network')),patch('subprocess.Popen',side_effect=AssertionError('No workers')):
        return create_candidate(ASSETS,SESSION,state,install_boundary=False)


def test_real_classes_not_fixture_adapters(real_app):
    s=real_app.state.service
    assert type(s) is Application and type(s.control) is LiveControl
    assert type(s.posture_service) is PostureAssessmentOrchestrator
    assert s.control.process is None and not s.posture_service.jobs
    assert s.control.session==SESSION
    info=request(real_app,'GET','/api/candidate/status').json()
    assert info['fixtures_used'] is False and info['proxy_to_original'] is False
    assert info['operational_authorization'] is False


@pytest.mark.parametrize('path',['/api/runtime/start','/api/runtime/stop','/api/demo/mode',
 '/api/posture/assessments','/api/scanners/zap/passive-assessment','/api/ingestion/inspect',
 '/api/posture/assessments/anything/cancel'])
def test_all_writes_blocked_before_execution(real_app,path):
    with patch.object(real_app.state.service.control,'start',side_effect=AssertionError('No monitor')), \
         patch.object(real_app.state.service.posture_service,'start',side_effect=AssertionError('No scan')):
        result=request(real_app,'POST',path,headers={'X-Product-Control':'1'},json={})
    assert result.status_code==403


def test_scanner_gets_are_explicitly_not_probed(real_app):
    with patch('requests.sessions.Session.request',side_effect=AssertionError('No ZAP probe')):
        v=request(real_app,'GET','/api/scanners/zap/status').json()
        assert v['runtime_status']=='NOT_PROBED' and v['last_successful_assessment']['integrity_status']=='HASH_VERIFIED'
        assert request(real_app,'GET','/api/scanners').json()['profiles']==['STANDARD','FULL_AUTHORIZED','PASSIVE_BASELINE']


def test_actual_science_and_current_or_retained_journal(real_app):
    p=request(real_app,'GET','/api/product/assessment?mode=LIVE_LAB').json()
    assert p['scientific_cqi']['policy']['version']=='cqi-evidence-2.0'
    assert p['snapshot']['observations'] and p['snapshot']['model']['feature_count']==83
    assert p['latest_execution']['cancellation']['eligible'] is False
    r=request(real_app,'GET','/api/product/assessment?mode=ACCEPTED_REPLAY&replay=ATTACK_HOLDOUT').json()
    expected=real_app.state.service.snapshot('ACCEPTED_REPLAY','ATTACK_HOLDOUT')
    assert len(r['snapshot']['observations'])==68
    assert [e['episode_id'] for e in r['snapshot']['incidents']]==[e.episode_id for e in expected['incidents']]
    assert all(o['explanation']['anomaly'] for o in r['snapshot']['observations'])


@pytest.mark.parametrize('event,args',[
 ('open',('outputs/test.json','w',os.O_WRONLY|os.O_CREAT)),
 ('os.mkdir',('runtime/new',0o700,-1)),('os.rename',('/tmp/candidate/new','runtime/new',-1,-1)),
 ('os.remove',('evidence/test',-1)),('os.chmod',('data/file',0o600,-1)),
 ('os.symlink',('runtime','/tmp/candidate/link',-1)),('subprocess.Popen',('anything',[],None,{})),
 ('socket.connect',(None,('127.0.0.1',8081))),('socket.connect',(None,('192.168.226.132',80))),
 ('socket.bind',(None,('0.0.0.0',18010))),('os.kill',(99999,2)),
 ('sqlite3.connect',('file:'+str(SESSION/'journal.sqlite3')+'?mode=rw',)),
 ('sqlite3.connect',(':invalid:',))])
def test_boundary_rejects_side_effects(tmp_path,event,args):
    b=CandidateBoundary(tmp_path,SESSION/'journal.sqlite3')
    with pytest.raises(PermissionError):b(event,args)
    assert sum(b.denied.values())==1


def test_boundary_accepts_only_own_temp_writes_and_exact_ro_journal(tmp_path):
    b=CandidateBoundary(tmp_path,SESSION/'journal.sqlite3')
    b('open',(str(tmp_path/'state'),'w',os.O_WRONLY|os.O_CREAT))
    b('open',('outputs/known.json','r',os.O_RDONLY))
    b('sqlite3.connect',((SESSION/'journal.sqlite3').as_uri()+'?mode=ro',))
    b('socket.bind',(None,('127.0.0.1',18010)))
    assert not b.denied


def test_real_audit_hook_blocks_writes_in_separate_process(tmp_path):
    code='''import sys,sqlite3,socket
from pathlib import Path
from demo.backend.defense import CandidateBoundary
b=CandidateBoundary(sys.argv[1],sys.argv[2]);sys.addaudithook(b)
try:Path(sys.argv[3]).write_text('never written')
except PermissionError:pass
else:raise AssertionError('Write escaped')
try:sqlite3.connect(sys.argv[2])
except PermissionError:pass
else:raise AssertionError('Writable DB escaped')
try:socket.socket().connect(('127.0.0.1',8081))
except PermissionError:pass
else:raise AssertionError('Network escaped')
assert not Path(sys.argv[3]).exists()
print('PASS: audit enforced before side effects')
'''
    forbidden=ROOT/'runtime/parallel-boundary-must-not-exist'
    p=subprocess.run([sys.executable,'-B','-c',code,str(tmp_path),str(SESSION/'journal.sqlite3'),str(forbidden)],cwd=ROOT,capture_output=True,text=True,env={**os.environ,'PRODUCT_FACTORY_ONLY':'1','PYTHONDONTWRITEBYTECODE':'1'},timeout=20)
    assert p.returncode==0,p.stderr
    assert not forbidden.exists()


def test_shutdown_does_not_signal_or_adopt_external_monitor(real_app):
    control=real_app.state.service.control
    with patch('os.kill',side_effect=AssertionError('No external signals')), \
         patch('subprocess.Popen',side_effect=AssertionError('No child')):
        control.close()
    assert control.process is None and not real_app.state.service.posture_service.jobs


def test_real_startup_and_journal_under_installed_boundary(tmp_path):
    code='''import sys
from pathlib import Path
from demo.backend.defense import create_candidate
app=create_candidate(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
s=app.state.service
assert type(s).__name__=='Application'
p=s.snapshot('LIVE_LAB')
assert p['observations'] and s.control.process is None
# urllib3 import probes IPv6 by binding ::1:0; the strict boundary denies
# that optional capability check. It must not permit another listening port.
assert set(app.state.candidate_boundary.denied)<= {'CANDIDATE_LOOPBACK_PORT_ONLY'},dict(app.state.candidate_boundary.denied)
s.control.close()
print('PASS real backend startup and retained evidence under read-only boundary')
'''
    p=subprocess.run([sys.executable,'-B','-c',code,str(ASSETS),str(SESSION),str(tmp_path)],cwd=ROOT,capture_output=True,text=True,env={**os.environ,'PRODUCT_FACTORY_ONLY':'1','PYTHONDONTWRITEBYTECODE':'1','OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1','TMPDIR':str(tmp_path)},timeout=40)
    assert p.returncode==0,p.stderr
