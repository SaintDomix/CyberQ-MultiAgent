#!/usr/bin/env python3
"""Export a real completed task for frontend checks; never manufacture a task."""
from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from coursework.isolation import install,STATE
install()
from coursework.multiagent.store import Store


def main():
    store=Store()
    state=next((s for s in store.list(100) if s.status=='COMPLETED'),None)
    if state is None:raise ValueError('Run a successful offline multi-agent task first')
    path=STATE/'assignment4/ui-task.json'
    from coursework.multiagent.views import assessment_view
    payload=store.export(state.task_id)
    payload['assessment_view']=assessment_view(state)
    path.write_text(json.dumps(payload,allow_nan=False)+'\n')
    print(json.dumps({'path':str(path),'actual_task_id':state.task_id}))


if __name__=='__main__':main()
