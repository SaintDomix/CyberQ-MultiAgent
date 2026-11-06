"""Coursework-only, expiring lab handoff. Default deny; never an ambient flag.

The unchanged dissertation cannot be forced to honor a coursework flock. A
verified external exclusion arrangement and operator approval are prerequisites,
not consequences of acquiring this local lease. No acquisition during development.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time

ROOT=Path('/mnt/assignment/cyberquality_multiagent')
DIRECTORY=ROOT/'runtime/coursework/lab'
TARGET='http://192.168.226.132/moodle/'
ORIGIN='http://127.0.0.1:8082'
PROFILES=('PASSIVE_BASELINE','STANDARD','FULL_AUTHORIZED')
ORIGINAL=Path('/home/saintdomix/dissertation_model')
def stopped_original(*,proc=Path('/proc')):
    """A closed API is insufficient: inspect listeners and actual worker processes.

    Never reads source files or sends signals. Trusted operators must keep the
    original stopped; this check revokes permission on a competing restart.
    """
    listeners=[];workers=[]
    for name in ('tcp','tcp6'):
        for line in (proc/'net'/name).read_text().splitlines()[1:]:
            fields=line.split()
            if fields[3]=='0A' and int(fields[1].rsplit(':',1)[1],16)==8000:listeners.append(name)
    for path in proc.iterdir():
        if not path.name.isdigit():continue
        try:
            argv=[os.fsdecode(a) for a in (path/'cmdline').read_bytes().split(b'\0') if a]
            comm=(path/'comm').read_text().strip()
            role=comm.startswith(('python','php','java','uvicorn','gunicorn','zaproxy')) or any(
                token in arg for arg in argv for token in ('run_behavioral','run_posture','start_cyberquality','capture_experiment'))
            if not role:continue  # Desktop/keyring processes are not lab workers.
            try:cwd=str((path/'cwd').resolve(strict=True))
            except PermissionError:
                if path.stat().st_uid==os.getuid():raise
                cwd=''
            linked=cwd==str(ORIGINAL) or cwd.startswith(str(ORIGINAL)+'/') or any(
                arg==str(ORIGINAL) or arg.startswith(str(ORIGINAL)+'/') for arg in argv)
            if linked and role:workers.append(int(path.name))
        except (FileNotFoundError,ProcessLookupError):continue
    if listeners or workers:raise ValueError('Original backend/listener or laboratory worker is present')
    return {'boot_id':(proc/'sys/kernel/random/boot_id').read_text().strip(),
            'port_8000_listening':False,'original_workers':[]}


def verify_exclusion(readiness):
    if readiness.get('external_exclusion_method')!='STOPPED_ORIGINAL_BACKEND':
        raise ValueError('Measured stopped-original exclusion proof required')
    current=stopped_original()
    if readiness.get('original_boot_id')!=current['boot_id']:
        raise ValueError('Handoff proof belongs to a different system boot')
    return current


def verify_zap_directory(value,*,at=None):
    at=time.time() if at is None else at
    if value.get('schema')!='coursework-zap-directory-1' or not 0<=at-value['observed_at']<=10800:
        raise ValueError('Fresh direct Kali directory observation required')
    owner=value['owner'];directory=owner['directory'];path=Path(directory['path'])
    if (value.get('loopback_8082') is not True or owner['uid']!=directory['uid']
            or directory['mode']&0o077 or directory.get('symlink') is not False
            or not path.is_absolute() or not any(path.is_relative_to(base) and path!=base for base in
                (Path('/tmp'),Path('/dev/shm'),Path('/run/user')/str(owner['uid'])))):
        raise ValueError('Coursework ZAP needs its own private temporary directory and loopback listener')
    identity=(directory['device'],directory['inode'])
    for other in value.get('other_zap_directories',[]):
        if other is None or (other['device'],other['inode'])==identity:
            raise ValueError('ZAP directory isolation from another instance is unverified')
    return directory


def private_json(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.resolve()!=path:
        raise ValueError('COURSEWORK_LAB_LOCKED: missing private lab record')
    info=path.stat()
    if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077 or info.st_size>65536:
        raise ValueError('COURSEWORK_LAB_LOCKED: lab record permissions/size invalid')
    return json.loads(path.read_bytes())


def fingerprint(pid):
    raw=Path('/proc/'+str(pid)+'/stat').read_text()
    return raw[raw.rfind(')')+2:].split()[19]


def validate_records(lease,approval,readiness,*,at=None):
    at=time.time() if at is None else at
    if (lease.get('target')!=TARGET or lease.get('zap_origin')!=ORIGIN
            or approval.get('target')!=TARGET or approval.get('zap_origin')!=ORIGIN
            or not 0<lease['expires_at']-lease['issued_at']<=10800
            or not lease['issued_at']<=at<min(lease['expires_at'],approval['expires_at'])
            or not 0<=at-lease['heartbeat_at']<=5
            or approval.get('authorization')!='EXPLICIT_USER_AUTHORIZATION_AFTER_READINESS_AUDIT'
            or not approval.get('profiles') or not set(approval['profiles'])<=set(PROFILES)
            or approval.get('readiness_sha256')!=hashlib.sha256(json.dumps(readiness,sort_keys=True).encode()).hexdigest()
            or readiness.get('status')!='READY' or readiness.get('blockers')
            or readiness.get('target')!=TARGET or readiness.get('zap_origin')!=ORIGIN
            or not readiness.get('external_exclusion_basis')
            or not 0<=at-readiness['verified_at']<=10800
            or any(readiness.get(k) is not True for k in ('original_jobs_quiescent','external_exclusion_verified',
                'zap_key_verified','zap_8082_isolated','zap_queues_idle','apache_readonly_verified'))):
        raise ValueError('COURSEWORK_LAB_LOCKED: authorization/readiness/lease invalid or expired')
    return lease


def require_owner():
    try:
        lease=private_json(DIRECTORY/'lease.json')
        approval=private_json(DIRECTORY/'authorization.json')
        readiness=private_json(DIRECTORY/'readiness.json')
        validate_records(lease,approval,readiness)
        # Checked on every allowed operation, not just the controller heartbeat.
        # A competing original restart revokes access immediately.
        verify_exclusion(readiness)
        if fingerprint(lease['owner_pid'])!=lease['owner_start']:
            raise ValueError('Lease controller identity changed')
        # A stale PID or copied receipt does not prove a held kernel lock.
        lockpath=DIRECTORY/'owner.lock'
        if lockpath.is_symlink():raise ValueError('Invalid ownership lock')
        with lockpath.open('r+') as handle:
            try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:pass
            else:
                fcntl.flock(handle,fcntl.LOCK_UN)
                raise ValueError('No live ownership controller holds the lab lock')
        return {**lease,'profiles':approval['profiles']}
    except (OSError,ValueError,KeyError,TypeError):
        raise ValueError('COURSEWORK_LAB_LOCKED: separate authorization and verified exclusive handoff required') from None


def available():
    try:require_owner();return True
    except ValueError:return False


def credentials():
    lease=require_owner();value=private_json(DIRECTORY/'zap-private.json')
    if value.get('origin')!=ORIGIN or not isinstance(value.get('api_key'),str) or len(value['api_key'])<16:
        raise ValueError('Private authenticated coursework ZAP configuration unavailable')
    return ORIGIN,value['api_key']


def check_address(address):
    require_owner()
    if address not in (('127.0.0.1',8082),('192.168.226.132',80)):
        raise PermissionError('COURSEWORK_LAB_SCOPE_REJECTED')


def session():
    import requests
    from urllib.parse import urlsplit
    class AuthorizedSession(requests.Session):
        def request(self,method,url,*args,**kwargs):
            require_owner();p=urlsplit(url)
            if p.username or p.password or p.fragment or not (
                p.scheme=='http' and p.hostname=='127.0.0.1' and p.port==8082 or
                p.scheme=='http' and p.hostname=='192.168.226.132' and p.port in (None,80)):
                raise PermissionError('COURSEWORK_LAB_SCOPE_REJECTED')
            self.trust_env=False
            return super().request(method,url,*args,**kwargs)
    return AuthorizedSession()


def worker_command(executable,argv,cwd):
    """Only the existing monitor worker, fixed source/model, confined fresh out."""
    lease=require_owner()
    args=list(argv)
    expected=[str(ROOT/'.venv-coursework/bin/python'),'-B',str(ROOT/'scripts/run_behavioral_v2_live.py'),'run',
        '--accepted',str(ROOT/'outputs/branch2/accepted_behavioral_v2'),
        '--source','/var/log/apache2/access.log','--out']
    if (str(cwd)!=str(ROOT) or args[:len(expected)]!=expected or len(args)!=len(expected)+1
            or str(executable)!=expected[0]):
        raise PermissionError('COURSEWORK_WORKER_COMMAND_REJECTED')
    out=Path(args[-1])
    if out.is_symlink() or not out.resolve().is_relative_to(ROOT/'runtime/coursework/behavioral_v2'):
        raise PermissionError('COURSEWORK_WORKER_OUTPUT_REJECTED')
    return lease


OWNED_WORKERS={}


def register_worker(pid):
    proc=Path('/proc')/str(pid)
    raw=(proc/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
    if int(fields[1])!=os.getpid():raise ValueError('Worker is not a child of this application')
    # Bind an actual child before checking cwd so failed startup can clean up
    # that child only. Reused/foreign PIDs never become signal targets.
    OWNED_WORKERS[pid]=fields[19]
    if (proc/'cwd').resolve(strict=True)!=ROOT:
        raise ValueError('Worker cwd mismatch')
    if fingerprint(pid)!=fields[19]:raise ValueError('Worker identity changed during registration')


def owned_worker(pid):
    try:return pid in OWNED_WORKERS and OWNED_WORKERS[pid]==fingerprint(pid)
    except OSError:return False
