#!/usr/bin/env python3
"""Read-only static diagnostic. Use /usr/bin/python3 -I -S, not copied Python."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True

ROOT = Path('/mnt/assignment/cyberquality_multiagent')
SOURCE = Path('/home/saintdomix/dissertation_model')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preservation', action='store_true')
    parser.add_argument('--source-proof', action='store_true', help='Read-only original Git comparison; no optional Git locks')
    parser.add_argument('--host-processes', action='store_true', help='Read-only process/listener inventory; no commands or secrets printed')
    args = parser.parse_args()
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    def run(argv, cwd=ROOT):
        return subprocess.check_output(argv, cwd=cwd, env=env, stderr=subprocess.DEVNULL)
    assert Path.cwd().resolve() == ROOT, 'Wrong cwd'
    assert run(['git','rev-parse','--show-toplevel']).decode().strip() == str(ROOT), 'Wrong Git root'
    assert not run(['git','remote','-v']), 'Remotes forbidden'
    disk = run(['findmnt','-n','-o','SOURCE','-T',str(ROOT)]).decode().strip()
    assert disk.split('[')[0] == '/dev/sdb', 'Wrong disk'
    links = []
    for base, dirs, files in os.walk(ROOT, followlinks=False):
        dirs[:] = [d for d in dirs if d != '.git']
        for name in dirs + files:
            p = Path(base)/name
            if p.is_symlink():
                resolved = p.resolve()
                assert not resolved.is_relative_to(SOURCE), 'Source symlink forbidden'
                assert resolved.is_relative_to(ROOT) or resolved == Path('/usr/bin/python3.10'), 'External symlink forbidden'
                links.append(str(p.relative_to(ROOT)))
    for name in ('runtime', 'runtime/coursework', 'runtime/coursework/tmp', '.venv-coursework'):
        p = ROOT/name
        assert p.is_dir() and not p.is_symlink() and p.resolve().is_relative_to(ROOT), 'Unsafe coursework path'
    sys.path.insert(0,str(ROOT))
    from coursework.lab import available
    info = {'workspace':'PASS', 'git_remotes': [], 'disk': disk, 'port':8001,
            'bind':'127.0.0.1', 'live_gate':'AUTHORIZED_LEASE' if available() else 'LOCKED_NO_OVERRIDE',
            'write_root':str(ROOT/'runtime/coursework'),
            'new_databases':'runtime/coursework only; multiagent/tasks.sqlite3 stores orchestration, no live monitoring DB started',
            'historical_sqlite':'immutable read-only; WAL/SHM creation forbidden',
            'symlinks_checked':len(links),
            'host_process_ownership':'NOT_CHECKED; request --host-processes with host process visibility'}
    initial = json.loads((ROOT/'coursework/initial_inventory.json').read_text())
    if args.host_processes:
        matches=[]
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit(): continue
            try:
                cwd=(proc/'cwd').resolve()
                argv=(proc/'cmdline').read_bytes()
                if cwd.is_relative_to(SOURCE) or (str(SOURCE).encode() in argv and b'python' in argv.split(b'\0')[0]):
                    matches.append({'pid':int(proc.name),'cwd':str(cwd),'program':(proc/'comm').read_text().strip()})
            except (OSError, ValueError): pass
        listeners=[]
        for file in ('tcp','tcp6'):
            for line in (Path('/proc/net')/file).read_text().splitlines()[1:]:
                parts=line.split();port=int(parts[1].split(':')[1],16)
                if parts[3]=='0A' and port in (80,8000,8001,8081):
                    listeners.append({'port':port,'address_hex':parts[1].split(':')[0],'socket_inode':parts[9]})
        info['observed_source_processes']=matches
        info['observed_listeners']=listeners
        info['host_process_ownership']='READ_ONLY_OBSERVATION; never proves exclusive lab ownership'
        info['proc_1_program']=Path('/proc/1/comm').read_text().strip()
    if args.preservation:
        changed = [name for name,h in initial['preserved_artifacts'].items()
                   if not (ROOT/name).is_file() or hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != h]
        info['preserved_files_checked'] = len(initial['preserved_artifacts'])
        info['preservation'] = 'PASS' if not changed else 'FAILED'
        assert not changed, 'Preserved artifact bytes changed'
    if args.source_proof:
        for label, words in [('head',['rev-parse','HEAD']), ('status',['status','--porcelain=v1','--untracked-files=all'])]:
            raw = run(['git', *words], cwd=SOURCE)
            assert hashlib.sha256(raw).hexdigest() == initial['source_git'][label]['sha256'], 'Original Git changed since read-only baseline'
        info['original_git'] = 'UNCHANGED_SINCE_INITIAL_READ_ONLY_CHECK'
        info['source_commit'] = initial['source_git']['head']['commit']
    print(json.dumps(info, indent=2))


if __name__ == '__main__':
    main()
