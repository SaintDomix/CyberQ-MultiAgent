"""Kali coordinates Ubuntu capture over SSH; Ubuntu alone stores authoritative evidence."""
import json
import re
import os
import shlex
import subprocess
import time
from .planning import TARGET
from .safety import validate_schedule
from .traffic import execute,ephemeral_inputs,check_worker


class RemoteAgent:
    def __init__(self,host,repo,root):
        raise ValueError('COURSEWORK_REMOTE_CAPTURE_DISABLED: no remote repository may be invoked')

    def call(self, action, payload):
        raise ValueError('COURSEWORK_REMOTE_CAPTURE_DISABLED')


def capture(plan,agent,authorized,interactive=False,worker=execute,sleep=time.sleep):
    if not authorized:raise ValueError('Explicit --authorized required')
    validate_schedule(plan)
    with ephemeral_inputs(plan,interactive):
        return execute_schedule(plan,agent,authorized,interactive,worker,sleep)


def execute_schedule(plan,agent,authorized,interactive,worker,sleep):
    if not authorized:raise ValueError('Explicit --authorized required')
    validate_schedule(plan)
    if worker is execute:check_worker()
    # Credentials only read by Kali worker, never sent over SSH/metadata.
    agent.call('init',plan)
    completed=[]
    for run in plan['runs']:
        agent.call('begin',{'run_id':run['run_id']})
        try:result=worker(run,plan['context'],authorized,interactive=interactive)
        except Exception:
            # Fail closed; preserve incomplete capture; do not leak exception locals/secrets.
            result={'run_id':run['run_id'],'label':run['label'],'actor_ip':plan['worker_ip'],
                    'status':'FAILED','actual_request_count':None,'requests':[],'error':'WORKER_ABORTED'}
        agent.call('finish',{'run_id':run['run_id'],'result':result})
        completed.append({'run_id':run['run_id'],'status':result['status']})
        if result['status']!='COMPLETE':raise ValueError('Run incomplete; stopped schedule, preserved capture')
        sleep(2)
    return {'completed':completed,'authoritative_capture_root':agent.root,'models_trained':False}
