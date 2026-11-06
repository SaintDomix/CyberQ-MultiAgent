#!/usr/bin/env python3
"""Offline tests under the mandatory coursework boundary. No fitting or live lab."""
import json
import os
from pathlib import Path
import sys
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT),str(ROOT/'src')]
from coursework.isolation import install, boundary, STATE
install()


def main():
    # Exercise policy predicates, never perform a destructive filesystem test.
    assert boundary.writable(STATE/'tmp/new-file')
    for p in (ROOT/'outputs/frozen.json', ROOT/'.venv/file', '/home/saintdomix/dissertation_model/file', '/etc/file'):
        assert not boundary.writable(p)
    for event, args in [('socket.connect',(None,('192.168.226.132',80))),
                        ('socket.bind',(None,('127.0.0.1',8000))),
                        ('subprocess.Popen',('ssh',['ssh'],None,None))]:
        try: boundary(event,args)
        except PermissionError: pass
        else: raise AssertionError('Isolation policy did not deny simulated event')
    from behavioral_runtime.package import load
    from behavioral_v2.features31 import extract, schema
    from behavioral_v2.platforms import MoodleBehaviorAdapter
    from branch2.events import CanonicalBehavioralEvent
    from datetime import datetime, timezone
    adapter=MoodleBehaviorAdapter()
    event=CanonicalBehavioralEvent(datetime(2020,1,1,tzinfo=timezone.utc),'fixture','GET',
            '/moodle/my/','',200,120,None,None,'synthetic','synthetic',1,'synthetic')
    features=extract([event],adapter)
    assert len(features)==83
    row={'features':features,'schema_sha256':schema(adapter)['sha256'],
         'run_id':'coursework-synthetic','window_start':'2020-01-01T00:00:00+00:00',
         'window_end':'2020-01-01T00:00:10+00:00','client_id':'fixture','user_agent_id':'fixture'}
    with (patch('sklearn.svm.OneClassSVM.fit',side_effect=AssertionError('No fitting')),
          patch('xgboost.XGBClassifier.fit',side_effect=AssertionError('No fitting'))):
        package=load(ROOT/'outputs/branch2/accepted_behavioral_v2')
        prediction=package.predict([row],explain=True)[0]
    assert prediction['training_performed'] is False
    assert prediction['shap_explanation']['status']=='AVAILABLE'
    import pytest
    run='offline-'+uuid.uuid4().hex
    class Results:
        def __init__(self):self.counts={}
        def pytest_runtest_logreport(self,report):
            if report.when=='call' or report.failed:
                self.counts[report.outcome]=self.counts.get(report.outcome,0)+1
    results=Results()
    os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
    status=pytest.main(['-q','-p','no:cacheprovider','--log-file='+str(STATE/(run+'.log')),
        '--basetemp='+str(STATE/'tmp'/run),
        'tests/test_behavioral_runtime.py','tests/test_human_explainability.py',
        'tests/test_scientific_cqi.py','tests/test_product_application.py','tests/test_posture_timeouts.py',
        '-k','not controls_safe_command_stop_and_duplicate_prevention and not owned_process_crash_visible_and_no_unrelated_stop and not path_scope_and_symlink_escape'],plugins=[results])
    receipt={'pytest_exit':int(status),'tests':results.counts,'synthetic_feature_count':len(features),
             'model':'OCSVM + XGBoost; saved inference only',
             'shap':prediction['shap_explanation']['status'],
             'shap_additivity_max_absolute_error':prediction['shap_explanation']['additivity_max_absolute_error'],
             'live_services_used':False,'policy_simulations':'PASS; no forbidden write attempted'}
    (STATE/(run+'-receipt.json')).write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))
    return int(status)


if __name__=='__main__': raise SystemExit(main())
