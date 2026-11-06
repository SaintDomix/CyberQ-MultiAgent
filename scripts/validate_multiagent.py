#!/usr/bin/env python3
"""Execute genuine workflows and labelled failure scenarios; retain all traces."""
import json
import os
from pathlib import Path
import sys
import uuid
import argparse

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from coursework.isolation import install,STATE
install()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',action='store_true',help='Also run explicitly local owned-monitor integration fixtures')
    args=parser.parse_args()
    import pytest
    run=STATE/'assignment4'/('validation-'+uuid.uuid4().hex)
    run.mkdir(parents=True)
    class Matrix:
        def __init__(self):self.rows=[]
        def pytest_runtest_logreport(self,report):
            if report.when=='call' or report.failed:
                self.rows.append({'test':report.nodeid,'outcome':report.outcome,
                    'duration_seconds':report.duration,**dict(report.user_properties)})
    matrix=Matrix();os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
    code=pytest.main(['-q','-p','no:cacheprovider','--log-file='+str(run/'pytest.log'),
        '--basetemp='+str(run/'tmp'),'tests/test_multiagent.py']+
        (['tests/test_platform_integration.py'] if args.platform else []),plugins=[matrix])
    report={'pytest_exit':int(code),'passed':sum(r['outcome']=='passed' for r in matrix.rows),
            'failed':sum(r['outcome']=='failed' for r in matrix.rows),'cases':matrix.rows,
            'distinction':'Passed failure-handling checks are not successful cybersecurity assessments.'}
    path=run/'matrix.json';path.write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    (STATE/'assignment4/latest-validation.json').write_text(json.dumps({'path':str(path.relative_to(ROOT))})+'\n')
    print(json.dumps({'matrix':str(path),'passed':report['passed'],'failed':report['failed'],'exit':int(code)},indent=2))
    return int(code)


if __name__=='__main__':raise SystemExit(main())
