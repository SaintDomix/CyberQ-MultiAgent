#!/usr/bin/env python3
"""Operator-only preparation/lease controller. Never starts scans or monitors.

Run using system Python -I -S. Hold requires a separately reviewed READY receipt
and explicit authorization; development never creates or acquires these grants.
"""
import argparse
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import subprocess
import urllib.request
import urllib.error
sys.dont_write_bytecode = True

ROOT=Path('/mnt/assignment/cyberquality_multiagent')
sys.path.insert(0,str(ROOT))
from coursework.lab import (DIRECTORY,TARGET,ORIGIN,PROFILES,private_json,fingerprint,validate_records,
                            available,stopped_original,verify_exclusion,verify_zap_directory)


def save(name,value):
    DIRECTORY.mkdir(mode=0o700,parents=True,exist_ok=True)
    if DIRECTORY.is_symlink() or DIRECTORY.resolve()!=DIRECTORY:raise ValueError('Invalid lab directory')
    path=DIRECTORY/name;temporary=DIRECTORY/(name+'.'+str(os.getpid()))
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)


def read_api(port,path):
    # Fixed loopback read-only endpoints only. No redirects, environment proxy,
    # raw log records, original files, remote commands or service mutations.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    try:
        with opener.open('http://127.0.0.1:'+str(port)+'/api/'+path,timeout=2) as response:
            limit=8*1024*1024
            raw=response.read(limit+1)
            if len(raw)>limit:raise ValueError('Readiness response too large')
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        if exc.code==404 and path=='posture/assessments/latest':return None
        raise


def idle(port):
    control=read_api(port,'runtime/control')
    job=read_api(port,'posture/assessments/latest')
    if control.get('schema_version')!='monitor-control-1.0' or control.get('process_running') is not False:
        raise ValueError('Monitoring is active or ownership cannot be verified')
    if job and (job.get('status') in ('RUNNING','QUEUED') or any(
        v in ('RUNNING','QUEUED') for v in job.get('provider_statuses',{}).values())):
        raise ValueError('A posture operation is active')
    if port==8001 and any(task['status'] in ('QUEUED','RUNNING','VERIFYING','SCORING')
                         for task in read_api(port,'multiagent/tasks')['items']):
        raise ValueError('A full assessment is active')
    if port==8001:
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():continue
            try:
                args=(proc/'cmdline').read_bytes().split(b'\0')
                if any(arg.endswith(b'/run_behavioral_v2_live.py') or arg==b'scripts/run_behavioral_v2_live.py' for arg in args):
                    if (proc/'cwd').resolve()==ROOT:raise ValueError('An owned or orphan coursework monitor still exists')
            except (FileNotFoundError,ProcessLookupError):continue


def zap_idle(*,fresh=False):
    config=private_json(DIRECTORY/'zap-private.json')
    if config.get('origin')!=ORIGIN or not config.get('api_key'):raise ValueError('Invalid coursework ZAP configuration')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def get(endpoint):
        request=urllib.request.Request(ORIGIN+'/JSON/'+endpoint+'/',headers={'X-ZAP-API-Key':config['api_key']})
        with opener.open(request,timeout=4) as response:return json.loads(response.read(1048576))
    version=get('core/view/version')['version'];mode=get('core/view/mode')['mode']
    for name in ('ascan','spider'):
        scans=get(name+'/view/scans')['scans']
        if fresh and scans or any(int(scan['progress'])!=100 for scan in scans):
            raise ValueError('ZAP scan/spider work is not quiescent')
    if get('ajaxSpider/view/status')['status']!='stopped' or int(get('pscan/view/recordsToScan')['recordsToScan'])!=0:
        raise ValueError('ZAP browser/passive work is not quiescent')
    if fresh and mode!='safe':raise ValueError('Existing profile requires an initially Safe owned ZAP runtime')
    return {'version':version,'mode':mode,'queues_idle':True,'authenticated_api_reached':True}


def restart_audit():
    matches=[];complete=True
    for user in (False,True):
        scope=['systemctl']+(['--user'] if user else [])
        result=subprocess.run(scope+['list-unit-files','--type=service','--no-legend','--no-pager'],capture_output=True,text=True,timeout=5)
        if result.returncode:complete=False;continue
        names=[line.split()[0] for line in result.stdout.splitlines() if line.strip() and line.split()[0].endswith('.service')]
        templates=[name for name in names if '@.service' in name]
        names=[name for name in names if name not in templates]
        # Template definitions have no runnable identity until instantiated;
        # inspect their unit text instead of passing invalid names to show.
        if templates:
            template=subprocess.run(scope+['cat','--no-pager','--']+templates,capture_output=True,text=True,timeout=5)
            if template.returncode:complete=False
            if any(k in template.stdout.lower() for k in ('dissertation_model','cyberquality','run_behavioral','zaproxy')):
                matches.append('service template definition')
        if not names:continue
        result=subprocess.run(scope+['show','--property=Id,ExecStart,Restart','--no-pager','--']+names,capture_output=True,text=True,timeout=5)
        if result.returncode:complete=False;continue
        for block in result.stdout.split('\n\n'):
            if '/home/saintdomix/dissertation_model' in block or any(k in block.lower() for k in ('cyberquality','run_behavioral','zaproxy')):
                matches.append(next((line[3:] for line in block.splitlines() if line.startswith('Id=')),'unidentified service'))
    result=subprocess.run(['crontab','-l'],capture_output=True,text=True,timeout=5)
    if result.returncode not in (0,1):complete=False
    if any(s in result.stdout.lower() for s in ('dissertation_model','cyberquality','run_behavioral','zaproxy')):matches.append('user crontab')
    for path in [Path('/etc/crontab'),*Path('/etc/cron.d').glob('*')]:
        if path.is_file() and any(s in path.read_text(errors='replace').lower() for s in ('dissertation_model','cyberquality','run_behavioral','zaproxy')):
            matches.append(str(path))
    if not complete or matches:raise ValueError('Automatic restart configuration is present or could not be fully inspected')
    return {'matching_service_or_cron_entries':[],'checked_at':time.time(),
            'limitation':'Trusted operators must not restart the original; every lab operation rechecks absence'}


def check_stopped():
    """Generate readiness only from successful measurements, never an override."""
    value={'status':'BLOCKED','verified_at':time.time(),'target':TARGET,'zap_origin':ORIGIN,'blockers':[]}
    stage='Original listener/worker absence'
    try:
        observed=stopped_original();value['original_observation']=observed
        stage='Service/cron automatic restart inspection'
        value['restart_audit']=restart_audit()
        stage='Direct Kali directory proof: private zap-directory.json'
        directory=verify_zap_directory(private_json(DIRECTORY/'zap-directory.json'))
        stage='Authenticated ZAP idle queues and initial Safe Mode'
        value['zap_directory']=directory;value['zap_observation']=zap_idle(fresh=True)
        stage='Read-only Apache input availability'
        if not os.access('/var/log/apache2/access.log',os.R_OK):raise ValueError('Read-only Apache input is unavailable')
        stopped_original()  # Recheck after external observations.
        value.update(status='READY',original_boot_id=observed['boot_id'],external_exclusion_method='STOPPED_ORIGINAL_BACKEND',
            external_exclusion_basis='Measured port/worker absence; continuous per-operation restart detection; operator keeps original stopped',
            **{k:True for k in ('original_jobs_quiescent','external_exclusion_verified','zap_key_verified','zap_8082_isolated','zap_queues_idle','apache_readonly_verified')})
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        value['blockers']=[stage+' could not be verified; no access granted']
    save('readiness.json',value)
    print(json.dumps(value,indent=2));return value['status']=='READY'


def audit(event,**details):
    path=DIRECTORY/'ownership-audit.jsonl'
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as stream:
        stream.write(json.dumps({'event':event,'at':time.time(),**details})+'\n');stream.flush();os.fsync(stream.fileno())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('status','configure-zap','check-stopped','authorize','hold','recover','restart-check'))
    parser.add_argument('--seconds',type=int,default=1800)
    args=parser.parse_args()
    if Path.cwd().resolve()!=ROOT:raise ValueError('Exact coursework root required')
    if args.action=='status':
        print(json.dumps({'live_access':'AUTHORIZED_LEASE' if available() else 'LOCKED',
            'target':TARGET,'zap_origin':ORIGIN,'approval_not_granted_by_this_command':True}));return
    if args.action=='configure-zap':
        key=getpass.getpass('Coursework ZAP API key (hidden): ')
        if len(key)<16:raise ValueError('Use an authenticated high-entropy key of at least 16 characters')
        save('zap-private.json',{'origin':ORIGIN,'api_key':key});print('Private coursework configuration saved; live access remains gated.');return
    if args.action=='check-stopped':
        if not check_stopped():raise ValueError('Readiness remains BLOCKED')
        return
    if args.action in ('recover','restart-check'):
        # No automatic takeover and no original signals. A live controller owns
        # this kernel lock, so recovery cannot race or bypass it.
        fd=os.open(DIRECTORY/'owner.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'r+') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            idle(8001);zap_idle();stopped_original()
            path=DIRECTORY/'lease.json';lease=private_json(path) if path.exists() else None
            if args.action=='recover' and lease:
                lease.update(status='RELEASED',heartbeat_at=0);save('lease.json',lease);audit('ownership.recovered_after_verified_cleanup')
            elif lease and lease.get('status')!='RELEASED':raise ValueError('Unreleased ownership; cleanup/recovery required')
        print('Coursework jobs and ZAP are idle; no lab lease is held. Original restart requires the operator; no process was started.')
        return
    if not 60<=args.seconds<=10800:raise ValueError('Lease must be 60–10800 seconds')
    readiness=private_json(DIRECTORY/'readiness.json')
    at=time.time()
    if args.action=='authorize':
        verify_exclusion(readiness)
        approval={'authorization':'EXPLICIT_USER_AUTHORIZATION_AFTER_READINESS_AUDIT',
            'target':TARGET,'zap_origin':ORIGIN,'profiles':list(PROFILES),
            'expires_at':at+args.seconds,'readiness_sha256':hashlib.sha256(json.dumps(readiness,sort_keys=True).encode()).hexdigest()}
        # Only the profile explicitly selected in the actual operator approval.
        profile=input('Approved profile (PASSIVE_BASELINE / STANDARD / FULL_AUTHORIZED): ').strip()
        if profile not in PROFILES:raise ValueError('Explicit supported profile required')
        approval['profiles']=[profile]
        print('Scope: coursework Native, independent monitoring, Full Assessment and the selected ZAP profile on the fixed Moodle target. No original services may be changed.')
        validate_records({'target':TARGET,'zap_origin':ORIGIN,'issued_at':at,'heartbeat_at':at,'expires_at':at+args.seconds},approval,readiness,at=at)
        if input('Separate approval received after readiness audit? Type AUTHORIZE COURSEWORK ONLY: ')!='AUTHORIZE COURSEWORK ONLY':
            raise ValueError('Explicit approval absent')
        save('authorization.json',approval);audit('authorization.recorded',profile=profile,expires_at=approval['expires_at']);return
    approval=private_json(DIRECTORY/'authorization.json')
    private_json(DIRECTORY/'zap-private.json')
    previous=DIRECTORY/'lease.json'
    if previous.exists() and private_json(previous).get('status')!='RELEASED':
        raise ValueError('Prior ownership is unreleased; verify residual jobs and reconcile with the operator before another grant')
    lockpath=DIRECTORY/'owner.lock'
    fd=os.open(lockpath,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        verify_exclusion(readiness)  # The original API need not exist when stopped.
        zap_idle(fresh=True)
        lease={'target':TARGET,'zap_origin':ORIGIN,'issued_at':at,'heartbeat_at':at,
            'expires_at':min(at+args.seconds,approval['expires_at']),'owner_pid':os.getpid(),
            'owner_start':fingerprint(os.getpid()),'status':'HELD'}
        validate_records(lease,approval,readiness);save('lease.json',lease);audit('ownership.acquired',expires_at=lease['expires_at'])
        print('Coursework ownership held. Start the coursework app separately. Stop owned jobs before Ctrl-C. No lab operation was started.')
        stopping=False
        while True:
            try:
                if time.time()>=lease['expires_at']:stopping=True
                verify_exclusion(readiness)
                if stopping:
                    idle(8001)
                    zap_idle()
                    if input('Owned ZAP scan/spider/passive queues verified empty? Type RELEASE VERIFIED: ')!='RELEASE VERIFIED':
                        raise ValueError('Remote quiescence not verified; ownership remains held')
                    lease.update(status='RELEASED',heartbeat_at=0);save('lease.json',lease);audit('ownership.released');break
                lease['heartbeat_at']=time.time();save('lease.json',lease);time.sleep(1)
            except KeyboardInterrupt:stopping=True
            except (OSError,ValueError,urllib.error.URLError):
                # Stop renewing authorization on competing work/error. Hold the
                # kernel lock until the operator verifies cleanup, even on expiry.
                stopping=True;print('BLOCKED: verify original/owned job quiescence; lease is not renewed or released.');time.sleep(1)


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,urllib.error.URLError):
        print('COURSEWORK_LAB_LOCKED: prerequisite, authorization, configuration or ownership check failed; no shared service changed.',file=sys.stderr)
        raise SystemExit(2)
