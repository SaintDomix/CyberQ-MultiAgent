#!/usr/bin/env python3
"""Owned parallel actual-backend service; operations locked, original app untouched."""
import argparse,fcntl,json,os,signal,socket,subprocess,sys,time
from pathlib import Path
from urllib.request import urlopen
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
STATE=Path('/tmp/cyberquality-defense-18010')
ASSETS='demo/frontend/preview-final-stabilization-20261104'

def identity(pid):
    try:
        p=Path('/proc')/str(pid);fields=(p/'stat').read_text().rsplit(')',1)[1].split()
        if fields[0]=='Z':return None
        return {'start_ticks':fields[19],'argv':[s.decode() for s in (p/'cmdline').read_bytes().split(b'\0') if s]}
    except (OSError,ValueError,IndexError):return None

def owned(state):return bool(state.get('pid') and identity(state['pid'])=={k:state[k] for k in ('start_ticks','argv')})
def read():return json.loads((STATE/'state.json').read_text()) if (STATE/'state.json').is_file() else {}
def write(value):
    p=STATE/'state.next';p.write_text(json.dumps(value,indent=2)+'\n');p.replace(STATE/'state.json')
def get(path):
    with urlopen('http://127.0.0.1:18010'+path,timeout=20) as r:return json.load(r)

def status():
    value=read();value={**value,'owned_process_alive':owned(value)}
    if value['owned_process_alive']:value['backend']=get('/api/candidate/status')
    return value

def stop():
    value=read()
    if not owned(value):return {'status':'NOT_RUNNING_OR_NOT_OWNED','other_processes_signaled':False}
    os.kill(value['pid'],signal.SIGINT);deadline=time.monotonic()+20
    while owned(value) and time.monotonic()<deadline:time.sleep(.2)
    if owned(value):raise ValueError('Candidate still running; do not signal any unrelated process')
    value['status']='STOPPED';write(value)
    return {'status':'STOPPED','pid':value['pid'],'other_processes_signaled':False,'original_app':'http://127.0.0.1:8000/'}

def start(session,assets):
    if owned(read()):raise ValueError('Candidate already running; no duplicate started')
    with socket.socket() as s:s.bind(('127.0.0.1',18010))
    import hashlib,shutil
    if shutil.disk_usage(ROOT).free<500*1024**2:raise ValueError('Less than 500 MiB free')
    manifest=json.loads((ROOT/'outputs/ux/final_stabilization_20261104_06/preview_assets_sha256.json').read_text())
    if Path(assets).is_absolute() or (ROOT/assets).resolve()!=ROOT/ASSETS:raise ValueError('Use the verified candidate assets')
    actual={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/assets).rglob('*') if p.is_file()}
    if actual!=manifest:raise ValueError('Candidate asset verification failed')
    source=(ROOT/session).resolve()
    if not source.is_relative_to(ROOT/'runtime/behavioral_v2') or not (source/'journal.sqlite3').is_file():raise ValueError('Existing confined journal required')
    argv=[str(ROOT/'.venv/bin/python'),'-B',str(Path(__file__).resolve()),'serve','--retained-session',str(source.relative_to(ROOT)),'--assets',assets]
    env={k:v for k,v in os.environ.items() if not k.startswith(('POSTURE_ZAP_','B1_ACTIVE_','PRODUCT_'))}
    env.update(PRODUCT_FACTORY_ONLY='1',PYTHONDONTWRITEBYTECODE='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',TMPDIR=str(STATE/'tmp'))
    (STATE/'tmp').mkdir(exist_ok=True,mode=0o700)
    with (STATE/'backend.log').open('ab') as log:
        process=subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    owner=identity(process.pid)
    if owner is None:raise ValueError('Candidate exited immediately')
    value={'pid':process.pid,**owner,'port':18010,'url':'http://127.0.0.1:18010/','assets':assets,'retained_session':str(source.relative_to(ROOT)),'status':'STARTING'};write(value)
    deadline=time.monotonic()+40
    try:
        while time.monotonic()<deadline:
            if process.poll() is not None:raise ValueError('Candidate startup failed; inspect only its /tmp backend.log')
            try:
                info=get('/api/candidate/status')
                if info['candidate']=='PARALLEL_REAL_BACKEND_READ_ONLY' and not info['owned_monitor'] and not info['owned_jobs']:break
            except OSError:time.sleep(.25)
        else:raise ValueError('Candidate startup deadline')
        value['status']='READY_READ_ONLY_REAL_BACKEND';write(value);return status()
    except Exception:
        stop();raise

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['start','stop','status','serve']);p.add_argument('--retained-session');p.add_argument('--assets',default=ASSETS);a=p.parse_args()
    if a.action in ('start','serve') and not a.retained_session:p.error('Explicit existing retained journal required')
    if STATE.is_symlink():p.error('Candidate state must not be a symlink')
    STATE.mkdir(exist_ok=True,mode=0o700)
    if STATE.stat().st_uid!=os.getuid() or STATE.stat().st_mode&0o077:p.error('Candidate state must be private and owned')
    os.environ['PRODUCT_FACTORY_ONLY']='1';sys.dont_write_bytecode=True
    if a.action=='serve':
        from demo.backend.defense import create_candidate
        app=create_candidate(ROOT/a.assets,ROOT/a.retained_session,STATE)
        import uvicorn
        uvicorn.run(app,host='127.0.0.1',port=18010,access_log=False,log_level='warning',timeout_graceful_shutdown=5)
        return
    with (STATE/'control.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        result=start(a.retained_session,a.assets) if a.action=='start' else stop() if a.action=='stop' else status()
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
