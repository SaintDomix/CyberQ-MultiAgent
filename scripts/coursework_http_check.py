#!/usr/bin/env python3
"""Bounded loopback smoke run; starts/stops only its own coursework child.

Use system Python: the HTTP client is outside the server's no-egress boundary.
Never contacts port 8000, Moodle, Apache, SSH or ZAP.
"""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import uuid
import re
import argparse
from datetime import datetime
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import HTTPError, URLError

ROOT = Path('/mnt/assignment/cyberquality_multiagent')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--multiagent',action='store_true',help='Also run a real five-specialist task and verify locked live/schema handling')
    args=parser.parse_args()
    assert Path.cwd().resolve() == ROOT
    subprocess.run(['/usr/bin/python3','-I','-S',str(ROOT/'scripts/coursework_check.py')],check=True)
    # Refuse to adopt a listener or rely on an old PID receipt.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(('127.0.0.1',8001))
    opener = build_opener(ProxyHandler({}))
    results = {}
    def request(path, body=None, expected=200):
        req = Request('http://127.0.0.1:8001'+path, data=None if body is None else json.dumps(body).encode(),
                      headers={'Content-Type':'application/json','X-Product-Control':'1'})
        try:
            response = opener.open(req,timeout=20)
        except HTTPError as error: response = error
        with response:
            raw = response.read()
            assert response.status == expected, (path,response.status)
            results[('GET ' if body is None else 'POST ')+path] = {'http_status':response.status,'bytes':len(raw)}
            return json.loads(raw) if 'json' in response.headers.get('Content-Type','') else raw
    log = ROOT/'runtime/coursework/http-server.log'
    with log.open('ab') as handle:
        child = subprocess.Popen([str(ROOT/'.venv-coursework/bin/python'),'-I','-B',str(ROOT/'scripts/coursework_serve.py')],
                                 cwd=ROOT,stdin=subprocess.DEVNULL,stdout=handle,stderr=handle)
        try:
            deadline = time.monotonic()+30
            while True:
                if child.poll() is not None: raise RuntimeError('Owned coursework server exited; inspect confined server log')
                try:
                    request('/api/health'); break
                except (URLError, ConnectionError):
                    if time.monotonic() >= deadline: raise RuntimeError('Server readiness timeout')
                    time.sleep(.2)
            results['process']={'pid':child.pid,'cwd':str(Path('/proc',str(child.pid),'cwd').resolve()),
                                'executable':str(Path('/proc',str(child.pid),'exe').resolve())}
            assert results['process']['cwd'] == str(ROOT)
            model=request('/api/model')
            assert model['integrity']=='VERIFIED' and model['feature_count']==83 and model['novelty_detector']=='OCSVM'
            for path in ('/', '/api/coursework/isolation','/api/coursework/history','/api/system/status','/api/posture/findings',
                         '/api/posture/assessments','/api/scanners','/api/scanners/zap',
                         '/api/behavior/incidents','/api/cqi','/api/cqi/dimensions','/api/cqi/v2','/api/product/assessment','/api/product/history','/api/application/snapshot',
                         '/api/report/final','/reports/behavioral-v2.md','/reports/behavioral-v2.json','/report.html'):
                obj=request(path)
                if path=='/api/cqi/dimensions':assert len(obj)==6
                if path=='/api/product/history':assert obj['total'] > 0
                if path=='/api/coursework/history' and obj['items']:
                    request('/api/coursework/history/'+obj['items'][0]['assessment_id'])
            assert request('/api/posture/assessments/latest')['assessment_id'] is None
            observations=request('/api/behavior/observations')['items']
            assert observations
            request('/api/explainability/'+observations[0]['observation_id'])
            task_ids_before=[v['task_id'] for v in request('/api/multiagent/tasks')['items']]
            request('/api/runtime/control')
            request('/api/runtime/status')
            request('/api/runtime/start',{},expected=423)
            request('/api/runtime/stop',{},expected=423)
            request('/api/posture/assessments',{},expected=423)
            request('/api/scanners/zap/passive-assessment',{},expected=423)
            request('/api/posture/assessments',{'target_id':'moodle-local','mode':'PASSIVE_BASELINE','zap_enabled':False},expected=423)
            for profile in ('PASSIVE_BASELINE','STANDARD','FULL_AUTHORIZED'):
                request('/api/posture/assessments',{'mode':profile,'zap_enabled':True,'authorized':True},expected=423)
            assert [v['task_id'] for v in request('/api/multiagent/tasks')['items']]==task_ids_before
            results['independent_operations']={'read_status_pages':'PASS','task_created_by_standalone_operations':False,
                'native_only_and_zap_profiles':'LOCKED_HTTP_423','monitor_start_stop':'LOCKED_HTTP_423'}
            if args.multiagent:
                spec=request('/api/multiagent/spec')
                assert len(spec['agents'])==6 and all(len(a['tools'])<=5 for a in spec['agents'])
                task_started=time.monotonic()
                created=request('/api/multiagent/tasks',{'scenario':'sqli_run','request_id':'http-'+uuid.uuid4().hex},expected=202)
                task_id=created['task_id'];end=time.monotonic()+95
                while True:
                    task=request('/api/multiagent/tasks/'+task_id)
                    if task['status'] in ('COMPLETED','FAILED','TIMED_OUT','BLOCKED','LIMIT_EXCEEDED','INTERRUPTED'):break
                    if time.monotonic()>end:raise RuntimeError('Multi-agent HTTP task deadline exceeded')
                    time.sleep(.2)
                assert task['status']=='COMPLETED',task.get('failure')
                task_elapsed=time.monotonic()-task_started
                assert len(task['outputs'])==5 and task['steps']==12
                assert task['distribution']['within_40_percent'] is True
                events=request('/api/multiagent/tasks/'+task_id+'/events')['items']
                assert len([e for e in events if e['event']=='tool.started'])==12
                assert request('/api/multiagent/tasks/'+task_id+'/export')['state']['task_id']==task_id
                view=request('/api/multiagent/tasks/'+task_id+'/assessment')
                assert view['context']['task_id']==view['context']['assessment_id']==task_id
                assert view['context']['native_refs'] and view['context']['zap_refs'] and view['context']['behavioral_refs']
                assert view['native']['findings'] and view['zap']['findings'] and view['behavioral']['observations']
                official=request('/api/multiagent/official')
                assert official['task_id']==task_id and official['cqi']==task['result']['cqi']
                before=request('/api/multiagent/tasks/'+task_id+'/export')
                for endpoint,payload in [('/api/runtime/start',{}),('/api/runtime/stop',{}),
                        ('/api/posture/assessments',{'mode':'PASSIVE_BASELINE','zap_enabled':False}),
                        ('/api/posture/assessments',{'mode':'STANDARD','zap_enabled':True,'authorized':True})]:
                    request(endpoint,payload,expected=423)
                    assert request('/api/multiagent/official')==official
                invalid=request('/api/multiagent/tasks',{'mode':'OFFLINE_EVIDENCE'},expected=422)
                blocked=request('/api/multiagent/tasks',{'scenario':'sqli_run','mode':'LIVE_LAB'},expected=202)
                end=time.monotonic()+5
                while True:
                    blocked=request('/api/multiagent/tasks/'+blocked['task_id'])
                    if blocked['status']=='BLOCKED':break
                    if time.monotonic()>end:raise RuntimeError('Lab-lock response deadline exceeded')
                    time.sleep(.05)
                assert blocked['steps']==0 and blocked['result'] is None
                assert request('/api/multiagent/official')==official
                assert request('/api/multiagent/tasks/'+task_id+'/export')==before
                html=request('/').decode()
                assets=re.findall(r'(?:src|href)="(/assets/[^"]+)"',html)
                assert assets
                content=[request(a) for a in assets]
                assert any(b'Run Full Assessment' in v for v in content)
                results['multiagent']={'task_id':task_id,'specialists':5,'registered_attempts':12,
                    'max_share':task['distribution']['max_specialist_percent'],'llm_calls':0,
                    'schema_rejection':'PASS','live_lock':'BLOCKED_WITH_ZERO_ATTEMPTS',
                    'shared_assessment_projection':'PASS; UI rendering/navigation tested separately',
                    'official_cqi_unchanged_after_standalone_and_blocked_requests':'PASS',
                    'completed_snapshot_immutable':'PASS',
                    'task_elapsed_seconds':task_elapsed,
                    'agent_seconds':{agent:(datetime.fromisoformat(next(e['timestamp'] for e in events if e['event']=='agent.completed' and e['agent']==agent))-
                        datetime.fromisoformat(next(e['timestamp'] for e in events if e['event']=='agent.started' and e['agent']==agent))).total_seconds()
                        for agent in ('native','zap','behavioral','verification','quality')},
                    'tool_timings':[{'tool':e['tool'],'seconds':e['duration_seconds']} for e in events if e['event']=='tool.completed'],
                    'frontend_build_assets':'PASS'}
            results['live'] = 'LOCKED; no external requests authorized or attempted'
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try: child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.terminate();child.wait(timeout=5)
            results['owned_child_stopped'] = child.poll() is not None
    destination=ROOT/'runtime/coursework/http-receipt.json'
    destination.write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))


if __name__ == '__main__': main()
