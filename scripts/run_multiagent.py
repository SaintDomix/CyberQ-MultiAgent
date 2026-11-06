#!/usr/bin/env python3
"""Run all five specialists in one offline task; do not activate copied .venv."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from coursework.isolation import install,STATE
install()
from coursework.multiagent.engine import Coordinator
from coursework.multiagent.models import TaskRequest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario',default='sqli_run',choices=TaskRequest.model_fields['scenario'].annotation.__args__)
    parser.add_argument('--request-id')
    parser.add_argument('--export',action='store_true')
    args=parser.parse_args()
    engine=Coordinator()
    state=engine.run_sync(TaskRequest(scenario=args.scenario,request_id=args.request_id))
    report={'task_id':state.task_id,'status':state.status,
            'assessment_outcome':'HISTORICAL_REANALYSIS_WITH_LIMITATIONS' if state.result else 'NO_SUCCESSFUL_ASSESSMENT',
            'agents':state.agents,'steps':state.steps,'failure':state.failure.model_dump() if state.failure else None,
            'distribution':state.distribution,'overall_cqi':state.result['cqi']['overall'] if state.result else None}
    if args.export:
        path=STATE/'multiagent'/(state.task_id+'.json')
        exported=engine.store.export(state.task_id)
        if path.exists():
            if json.loads(path.read_text())!=exported:raise ValueError('Existing exported receipt differs; refusing overwrite')
        else:
            with path.open('x') as handle:json.dump(exported,handle,indent=2,allow_nan=False)
        report['export_path']=str(path)
    print(json.dumps(report,indent=2,allow_nan=False))
    return 0 if state.status=='COMPLETED' else 1


if __name__=='__main__':raise SystemExit(main())
