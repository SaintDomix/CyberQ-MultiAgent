"""Local-only startup/race tests; no Apache input, monitor or lab operation."""
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock,patch

import pytest
from coursework.isolation import boundary
from demo.backend.config import Config
from demo.backend.runtime import LiveControl,SourceUnavailable


class Child:
    pid=123456789
    def __init__(self,code=None):
        self.code=code;self.stdin=SimpleNamespace(close=Mock());self.send_signal=Mock()
    def poll(self):return self.code
    def wait(self,timeout):self.code=0


def ready(out):
    out.mkdir()
    manifest={'session_id':'TEST_ONLY','model_id':'test','schema_sha256':'a'*64,'feature_count':83}
    checkpoint={**manifest,'integrity_status':'OK'}
    (out/'session_manifest.json').write_text(json.dumps(manifest))
    (out/'checkpoint.json').write_text(json.dumps(checkpoint))
    (out/'journal.sqlite3').touch()


@pytest.fixture
def setup(tmp_path,monkeypatch):
    source=tmp_path/'synthetic-apache.log';source.write_text('')
    config=Config(repository=tmp_path,apache_source=str(source))
    gate=Mock();register=Mock()
    monkeypatch.setattr('coursework.isolation.require_live_owner',gate)
    monkeypatch.setattr('coursework.lab.register_worker',register)
    return config,gate,register


def test_devnull_underlying_failure_without_any_external_write():
    seen=[]
    def guarded(path,flags,*args):
        seen.append((path,flags));boundary('open',(path,None,flags))
        raise AssertionError('Expected policy denial')
    with patch('subprocess.os.open',side_effect=guarded):
        with pytest.raises(PermissionError,match='COURSEWORK_WRITE_OUTSIDE_NEW_STATE'):
            subprocess.Popen._get_devnull(SimpleNamespace())
    assert seen==[(os.devnull,os.O_RDWR)]


def test_runtime_session_paths_remain_confined(tmp_path):
    for path in ('runtime/coursework/behavioral_v2/ui-test','runtime/behavioral_v2/historical'):
        assert Config(repository=tmp_path,runtime_session=path).runtime_session==path
    for path in ('runtime/coursework/behavioral_v2','runtime/unrelated/session','../outside'):
        with pytest.raises(ValueError):Config(repository=tmp_path,runtime_session=path)


def test_parent_created_private_diagnostics_and_verified_start(setup):
    config,gate,register=setup;child=Child();calls=[]
    def factory(argv,**kwargs):
        out=Path(argv[-1]);assert out.parent.is_dir() and not out.exists()
        assert kwargs['stdin'].read()==b'' and kwargs['stderr'] is kwargs['stdout']
        assert kwargs['shell'] is False
        class BeforeExec(Exception):pass
        # Exercise real Popen descriptor setup under the installed boundary,
        # stopping before exec/fork: no child, log source or lease bypass.
        with patch.object(subprocess.Popen,'_execute_child',side_effect=BeforeExec):
            with pytest.raises(BeforeExec):subprocess.Popen(argv,**kwargs)
        ready(out);calls.append(out);return child
    control=LiveControl(config,factory)
    assert control.start()['process_running'] is True
    register.assert_called_once_with(child.pid);child.stdin.close.assert_called_once()
    assert (calls[0].parent/(calls[0].name+'.worker.log')).stat().st_mode&0o777==0o600
    with pytest.raises(SourceUnavailable,match='already running'):control.start()
    assert len(calls)==1


def test_early_exit_is_not_registered_or_reported_running(setup):
    config,gate,register=setup;control=LiveControl(config,lambda *args,**kwargs:Child(2))
    with pytest.raises(SourceUnavailable,match='ChildProcessError'):control.start()
    register.assert_not_called();assert control.status()['process_running'] is False
    assert 'stage=registration' in control.status()['last_error']


def test_exit_during_registration_retains_actual_failure(setup):
    config,gate,register=setup;child=Child()
    def failed(pid):child.code=2;raise FileNotFoundError('Exited child /proc entry')
    register.side_effect=failed
    control=LiveControl(config,lambda *args,**kwargs:child)
    with pytest.raises(SourceUnavailable,match='FileNotFoundError'):control.start()
    assert control.status()['process_running'] is False
    child.send_signal.assert_not_called()


def test_startup_timeout_stops_only_registered_child(setup,monkeypatch):
    config,gate,register=setup;child=Child();control=LiveControl(config,lambda *a,**k:child)
    monkeypatch.setattr('demo.backend.runtime.time.monotonic',Mock(side_effect=[0,20]))
    monkeypatch.setattr('coursework.lab.owned_worker',lambda pid:pid==child.pid)
    with pytest.raises(SourceUnavailable,match='TimeoutError'):control.start()
    child.send_signal.assert_called_once();assert control.status()['process_running'] is False


def test_lease_denial_prevents_spawn_and_new_runtime(setup):
    config,gate,register=setup;gate.side_effect=ValueError('COURSEWORK_LAB_LOCKED')
    factory=Mock();control=LiveControl(config,factory)
    with pytest.raises(ValueError,match='LAB_LOCKED'):control.start()
    factory.assert_not_called()
    assert not (config.repository/'runtime/coursework/behavioral_v2').exists()
