"""Owned loopback demo lifecycle. PID reuse never authorizes killing a process."""
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.request import Request, urlopen
from .backend.config import ROOT, Config, confined
from .preflight import preflight

STATE = ROOT / 'runtime/demo_control/state.json'


def identity(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        if fields[0] == 'Z': return None
        return {'start_ticks': fields[19], 'argv': Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')[:-1]}
    except (OSError, IndexError): return None


def owned(state):
    current = identity(state.get('pid', -1))
    return bool(current and current['start_ticks'] == state.get('start_ticks') and
        current['argv'] == [s.encode() for s in state.get('argv', [])])


def api(port, path, action=False, timeout=15, body=None):
    if not 1024 <= port <= 65535 or not path.startswith('/api/') or '\n' in path:
        raise ValueError('Invalid local API')
    request = Request(f'http://127.0.0.1:{port}{path}', data=json.dumps(body or {}).encode() if action else None,
        headers={'Content-Type':'application/json','X-Product-Control':'1'})
    with urlopen(request, timeout=timeout) as response: return json.load(response)


def read_state():
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def status():
    state = read_state(); alive = owned(state)
    result = {'backend':'FAIL','frontend_dashboard':'FAIL','behavior_runtime':'FAIL','accepted_model_hash':'FAILED',
        'runtime_db':'FAIL','apache_source':'UNAVAILABLE','checkpoint':'FAIL','mode':state.get('mode','NOT_STARTED'),
        'last_observation':None,'active_incidents':None,'owned_backend_alive':alive}
    if not alive: return result
    try:
        health = api(state['port'], '/api/health')
        mode=health['mode']
        snapshot = api(state['port'], '/api/application/snapshot?mode='+mode)
        with urlopen(f"http://127.0.0.1:{state['port']}/", timeout=3) as response:
            result['frontend_dashboard'] = 'OK' if response.status == 200 else 'FAIL'
        r = snapshot['status']['runtime']; replay = mode == 'ACCEPTED_REPLAY'
        result.update(backend='OK',mode=mode,accepted_model_hash=health['model_integrity'],
            behavior_runtime='OK (not required in replay)' if replay else 'OK' if r.get('process_running') else 'FAIL',
            runtime_db='OK (locked evidence replay)' if replay else 'OK' if r.get('sqlite_status')=='VERIFIED_READ_ONLY' else 'FAIL',
            apache_source='AVAILABLE' if os.access('/var/log/apache2/access.log',os.R_OK) else 'UNAVAILABLE',
            checkpoint='OK (not required in replay)' if replay else 'OK' if r.get('checkpoint_at') else 'FAIL',
            last_observation=snapshot['observations'][0]['window_end'] if snapshot['observations'] else None,
            active_incidents=snapshot['cqi']['active_behavioral_impact']['active_incident_count'] if snapshot['cqi'] else None,
            dashboard_url=f"http://127.0.0.1:{state['port']}", error=snapshot['status']['last_error'])
        if not replay and state.get('retained_session') and not r.get('process_running'):
            result['behavior_runtime']='NOT_STARTED (read-only retained session)'
    except (OSError, ValueError, KeyError): result['error']='Owned backend or required source is unavailable'
    return result


def start(mode, port, retained_session=None, frontend_dir=None):
    raise ValueError('COURSEWORK_LEGACY_LIFECYCLE_DISABLED: use scripts/coursework_serve.py; never adopt copied state')
    if owned(read_state()): raise ValueError('Demo already running; use demo_status.sh')
    if frontend_dir and not (confined(ROOT,frontend_dir)/'index.html').is_file():
        raise ValueError('Selected frontend build is unavailable')
    if retained_session:
        if mode!='LIVE_LAB': raise ValueError('Retained runtime requires LIVE_LAB')
        config=Config(mode=mode,runtime_session=retained_session)
        from .backend.services import Application
        from .backend.runtime import read_journal
        model=Application(config).model()
        if model['integrity']!='VERIFIED': raise ValueError('Accepted package verification failed')
        read_journal(confined(ROOT,retained_session),model['package_id'],model['schema_sha256'])
    result = preflight(mode, port)
    if result['result']=='FAIL': raise ValueError('Preflight failed; run demo_preflight.py for exact prerequisites')
    argv = [sys.executable,'-B',str(ROOT/'scripts/run_demo.py'),'--port',str(port)]
    if frontend_dir: argv.extend(['--frontend-dir',frontend_dir])
    env = dict(os.environ); env['PRODUCT_MODE'] = mode
    env.pop('PRODUCT_RUNTIME_SESSION', None)  # New owned session; never silently adopt/kill an unrelated monitor.
    if retained_session: env['PRODUCT_RUNTIME_SESSION']=retained_session
    with (STATE.parent/'backend.log').open('ab') as log:
        process = subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    info = identity(process.pid)
    if info is None: raise ValueError('Backend did not start')
    state={'pid':process.pid,'start_ticks':info['start_ticks'],'argv':argv,'mode':mode,'port':port,
           'model_package_id':result['model_package_id'],'status':'STARTING'}
    if retained_session: state['retained_session']=retained_session
    if frontend_dir: state['frontend_dir']=frontend_dir
    from branch2.live_storage import atomic_json
    atomic_json(STATE,state)
    try:
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            if process.poll() is not None: raise ValueError('Backend exited; inspect runtime/demo_control/backend.log')
            try:
                if api(port,'/api/health',timeout=1)['model_integrity']=='VERIFIED': break
            except (OSError,ValueError,KeyError): time.sleep(.2)
        else: raise ValueError('Backend readiness timed out')
        if mode=='LIVE_LAB' and not retained_session:
            api(port,'/api/runtime/start',action=True)
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                s=api(port,'/api/system/status?mode=LIVE_LAB')
                if s['runtime'].get('sqlite_status')=='VERIFIED_READ_ONLY' and s['runtime'].get('process_running'):break
                if s['runtime'].get('process_state')=='ERROR':raise ValueError('Passive runtime startup failed')
                time.sleep(.3)
            else:raise ValueError('Passive runtime readiness timed out')
        state['status']='READY';atomic_json(STATE,state)
    except Exception:
        stop();raise
    return status()


def stop():
    raise ValueError('COURSEWORK_LEGACY_LIFECYCLE_DISABLED: use scripts/coursework_serve.py; never adopt copied state')
    state=read_state()
    if not owned(state): return {'status':'ALREADY_STOPPED_OR_NOT_OWNED','unrelated_processes_touched':False}
    try: api(state['port'],'/api/runtime/stop',action=True)
    except (OSError,ValueError): pass
    os.kill(state['pid'],signal.SIGINT)
    deadline=time.monotonic()+20
    while owned(state) and time.monotonic()<deadline: time.sleep(.2)
    if owned(state): raise ValueError('Owned backend did not stop; state retained for operator inspection. No broad kill performed.')
    from branch2.live_storage import atomic_json
    state['status']='STOPPED';atomic_json(STATE,state)
    return {'status':'STOPPED','journals_preserved':True,'unrelated_processes_touched':False}


def main(argv=None):
    raise ValueError('COURSEWORK_LEGACY_LIFECYCLE_DISABLED: use scripts/coursework_serve.py; never adopt copied state')
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['start','stop','status'])
    parser.add_argument('--mode',choices=['ACCEPTED_REPLAY','LIVE_LAB'],default='ACCEPTED_REPLAY')
    parser.add_argument('--port',type=int,default=8001)
    parser.add_argument('--retained-session',help='Explicit read-only LIVE journal; do not start or adopt a monitor')
    parser.add_argument('--frontend-dir',help='Existing built assets inside the repository; original dist is preserved')
    args=parser.parse_args(argv)
    STATE.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (STATE.parent/'control.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        try:result=start(args.mode,args.port,args.retained_session,args.frontend_dir) if args.action=='start' else stop() if args.action=='stop' else status()
        except (OSError,ValueError,KeyError):
            print('Demo control failed. Run demo_preflight.py and inspect the retained control/runtime state.',file=sys.stderr);return 2
    print(json.dumps(result,indent=2));return 0
