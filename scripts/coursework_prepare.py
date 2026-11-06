#!/usr/bin/env python3
"""Offline dependency relocation using system Python; never executes copied venv."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import venv

ROOT = Path('/mnt/assignment/cyberquality_multiagent')


def main():
    assert Path.cwd().resolve() == ROOT
    assert subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip() == str(ROOT)
    assert not subprocess.check_output(['git','remote','-v'])
    assert subprocess.check_output(['findmnt','-n','-o','SOURCE','-T',str(ROOT)],text=True).split('[')[0].strip() == '/dev/sdb'
    free = shutil.disk_usage(ROOT).free
    print('Available bytes before preparation:', free)
    target = ROOT/'.venv-coursework'
    if target.exists():
        assert not target.is_symlink()
        assert (target/'lib/python3.10/site-packages/coursework_isolation.pth').read_text() == 'import _coursework_guard\n'
        print('Existing coursework environment retained; no dependency installation performed.')
        return
    assert free > 4 * 1024**3, 'At least 4 GiB required; no install attempted'
    old = ROOT/'.venv/lib/python3.10/site-packages'
    assert sorted(p.name for p in old.glob('*.pth')) == ['distutils-precedence.pth']
    assert not list(old.glob('*.egg-link')) and not list(old.glob('*customize.py'))
    for base, dirs, files in os.walk(old):
        assert not any((Path(base)/n).is_symlink() for n in dirs+files), 'Dependency symlink requires review'
    state = ROOT/'runtime/coursework'
    for p in (ROOT/'runtime',state,state/'tmp',state/'cache',state/'cache/matplotlib',state/'cache/numba'):
        assert not p.is_symlink()
        p.mkdir(exist_ok=True,mode=0o700)
    venv.EnvBuilder(with_pip=False,symlinks=False).create(target)
    new = target/'lib/python3.10/site-packages'
    shutil.copytree(old,new,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    # .pth is needed: Ubuntu's stdlib sitecustomize precedes venv sitecustomize.
    (new/'_coursework_guard.py').write_text('import sys\nsys.path[:0] = ["'+str(ROOT)+'", "'+str(ROOT/'src')+'"]\ntry:\n    from coursework.isolation import install\n    install()\nexcept BaseException:\n    import os\n    os.write(2, b"Coursework isolation failed; Python aborted before application import.\\n")\n    os._exit(78)\n')
    (new/'coursework_isolation.pth').write_text('import _coursework_guard\n')
    print('Prepared new venv from local package payload. No downloads, original venv execution, or system installs.')


if __name__ == '__main__': main()
