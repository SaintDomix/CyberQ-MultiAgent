"""Fail-closed boundary for reviewed coursework Python, not a hostile-code sandbox.

Live access has deliberately no environment-variable override in this phase.
"""
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit, parse_qs, unquote

ROOT = Path('/mnt/assignment/cyberquality_multiagent')
STATE = ROOT / 'runtime/coursework'
FORBIDDEN = Path('/home/saintdomix/dissertation_model')
INSTALLED = False


class Boundary:
    def __init__(self):
        self.denials = {}

    def deny(self, reason):
        self.denials[reason] = self.denials.get(reason, 0) + 1
        raise PermissionError(reason)

    def writable(self, path, dir_fd=-1):
        if isinstance(path, int):
            if path in (1, 2): return True
            try:
                return Path(os.readlink('/proc/self/fd/' + str(path))).resolve().is_relative_to(STATE)
            except OSError:
                return False
        try:
            p = Path(os.fsdecode(path))
            if dir_fd not in (-1, None) and not p.is_absolute():
                parent = Path(os.readlink('/proc/self/fd/' + str(dir_fd))).resolve()
                if not parent.is_relative_to(STATE): return False
                p = parent / p
            p = p.resolve()
            return p.is_relative_to(STATE) and not STATE.is_symlink()
        except (OSError, TypeError, ValueError):
            return False

    def __call__(self, event, args):
        if event == 'open':
            path, mode, flags = args
            if not isinstance(path, int):
                p = Path(os.fsdecode(path)).resolve()
                if p.is_relative_to(FORBIDDEN):
                    self.deny('COURSEWORK_ORIGINAL_ACCESS_BLOCKED')
                if p == Path('/var/log/apache2/access.log'):
                    try:require_live_owner()
                    except ValueError:self.deny('COURSEWORK_LIVE_MONITORING_NOT_AUTHORIZED')
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                if not self.writable(path): self.deny('COURSEWORK_WRITE_OUTSIDE_NEW_STATE')
        elif event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.chown', 'os.truncate', 'os.utime'):
            fd = args[-1] if event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.chown', 'os.utime') else -1
            if not self.writable(args[0], fd): self.deny('COURSEWORK_WRITE_OUTSIDE_NEW_STATE')
        elif event in ('os.rename', 'os.replace'):
            if not all(self.writable(p) for p in args[:2]): self.deny('COURSEWORK_WRITE_OUTSIDE_NEW_STATE')
            if any(fd != -1 for fd in args[2:]): self.deny('COURSEWORK_DIR_FD_DISABLED')
        elif event in ('os.link', 'os.symlink'):
            self.deny('COURSEWORK_LINK_CREATION_DISABLED')
        elif event == 'sqlite3.connect':
            value = os.fsdecode(args[0])
            if value == ':memory:': return
            u = urlsplit(value)
            if u.scheme == 'file':
                p = Path(unquote(u.path)).resolve()
                query = parse_qs(u.query)
                if p.is_relative_to(ROOT) and query == {'mode': ['ro'], 'immutable': ['1']}: return
            else:
                p = Path(value).resolve()
            if not self.writable(p): self.deny('COURSEWORK_SQLITE_OUTSIDE_NEW_STATE')
        elif event in ('socket.connect', 'socket.connect_ex', 'socket.sendto'):
            from coursework.lab import check_address
            try:check_address(args[1])
            except (ValueError,PermissionError):self.deny('COURSEWORK_EXTERNAL_LAB_LOCKED')
        elif event == 'socket.getaddrinfo' and args[0] not in ('127.0.0.1', 'localhost', None):
            if args[0]!='192.168.226.132':self.deny('COURSEWORK_DNS_LOCKED')
            try:require_live_owner()
            except ValueError:self.deny('COURSEWORK_DNS_LOCKED')
        elif event == 'socket.bind' and args[1] != ('127.0.0.1', 8001):
            self.deny('COURSEWORK_PORT_8001_ONLY')
        elif event=='subprocess.Popen':
            from coursework.lab import worker_command
            try:worker_command(args[0],args[1],args[2])
            except (ValueError,PermissionError):self.deny('COURSEWORK_SUBPROCESS_DISABLED')
        elif event in ('os.system', 'os.posix_spawn', 'os.fork', 'os.exec', 'os.killpg'):
            self.deny('COURSEWORK_SUBPROCESS_DISABLED')
        elif event == 'os.kill' and args[0] != os.getpid():
            from coursework.lab import owned_worker
            import signal
            if not owned_worker(args[0]) or args[1] not in (signal.SIGINT,signal.SIGTERM,signal.SIGKILL):
                self.deny('COURSEWORK_EXTERNAL_SIGNAL_DISABLED')


boundary = Boundary()


def install():
    global INSTALLED
    if INSTALLED: return boundary
    if Path.cwd().resolve() != ROOT or Path(__file__).resolve().parents[1] != ROOT:
        raise RuntimeError('Exact coursework working directory required')
    if any(p.is_symlink() for p in (ROOT, ROOT/'runtime', STATE)):
        raise RuntimeError('Coursework runtime symlink rejected')
    if not (STATE/'tmp').is_dir():
        raise RuntimeError('Run the coursework preparation first')
    # Check before application imports, even when the launcher is invoked directly.
    import subprocess
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    top = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], cwd=ROOT, env=env, text=True).strip()
    remotes = subprocess.check_output(['git', 'remote', '-v'], cwd=ROOT, env=env)
    disk = subprocess.check_output(['findmnt', '-n', '-o', 'SOURCE', '-T', str(ROOT)], text=True).strip()
    if top != str(ROOT) or remotes or disk.split('[')[0] != '/dev/sdb':
        raise RuntimeError('Coursework Git/disk isolation preflight failed')
    for key in list(os.environ):
        if key.startswith(('PRODUCT_', 'POSTURE_', 'B1_', 'B2_', 'M5_')) or key.lower().endswith('_proxy'):
            os.environ.pop(key, None)
    os.environ.update(PRODUCT_FACTORY_ONLY='1', PRODUCT_MODE='ACCEPTED_REPLAY',
                      COURSEWORK_OFFLINE='1', PYTHONDONTWRITEBYTECODE='1',
                      TMPDIR=str(STATE/'tmp'), XDG_CACHE_HOME=str(STATE/'cache'),
                      MPLCONFIGDIR=str(STATE/'cache/matplotlib'), NUMBA_CACHE_DIR=str(STATE/'cache/numba'),
                      OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1')
    sys.dont_write_bytecode = True
    sys.addaudithook(boundary)
    INSTALLED = True
    return boundary


def require_live_owner():
    from coursework.lab import require_owner
    return require_owner()
