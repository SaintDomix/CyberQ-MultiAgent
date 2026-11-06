#!/usr/bin/env python3
"""Read-only Kali /proc probe; run through SSH stdin. Never prints API keys."""
import sys
sys.dont_write_bytecode = True
import json
import os
from pathlib import Path
import stat
import time


def main():
    inodes=set();loopback=True
    for name in ('tcp','tcp6'):
        for line in (Path('/proc/net')/name).read_text().splitlines()[1:]:
            f=line.split();address,port=f[1].rsplit(':',1)
            if f[3]=='0A' and int(port,16)==8082:
                inodes.add(f[9]);loopback &= address in (
                '0100007F',
                '0000000000000000FFFF00000100007F',
                '00000000000000000000000001000000'
            )
    instances=[]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            args=[os.fsdecode(a) for a in (proc/'cmdline').read_bytes().split(b'\0') if a]
            if not any(a.endswith('org.zaproxy.zap.ZAP') or 'zap-' in a and a.endswith('.jar') for a in args):continue
            directory=None
            if '-dir' in args:
                raw=Path(args[args.index('-dir')+1]);path=raw if raw.is_absolute() else (proc/'cwd').resolve()/raw
                st=path.stat();directory={'path':str(path.resolve()),'uid':st.st_uid,
                    'mode':stat.S_IMODE(st.st_mode),'device':st.st_dev,'inode':st.st_ino,'symlink':path.is_symlink()}
            owns=any(fd.readlink().as_posix() in {'socket:['+i+']' for i in inodes} for fd in (proc/'fd').iterdir())
            instances.append({'pid':int(proc.name),'uid':proc.stat().st_uid,'directory':directory,'owns_8082':owns})
        except (FileNotFoundError,ProcessLookupError):continue
    owners=[p for p in instances if p['owns_8082']]
    if len(owners)!=1 or not owners[0]['directory']:raise ValueError('Cannot identify one explicit isolated ZAP -dir for listener 8082')
    return {'schema':'coursework-zap-directory-1','observed_at':time.time(),'loopback_8082':bool(inodes) and loopback,
            'owner':owners[0],'other_zap_directories':[p['directory'] for p in instances if not p['owns_8082']]}


if __name__=='__main__':
    try:print(json.dumps(main()))
    except (OSError,ValueError,IndexError):
        print(json.dumps({'status':'BLOCKED','reason':'Direct ZAP process/directory ownership could not be verified; no service changed'}))
        raise SystemExit(2)
