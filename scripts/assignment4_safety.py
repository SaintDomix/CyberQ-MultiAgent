#!/usr/bin/env python3
"""Read-only source checks plus a coursework-owned final receipt. System Python only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path('/mnt/assignment/cyberquality_multiagent')
SOURCE=Path('/home/saintdomix/dissertation_model')


def main():
    assert Path.cwd().resolve()==ROOT
    raw=subprocess.check_output(['/usr/bin/python3','-I','-S',str(ROOT/'scripts/coursework_check.py'),
                                 '--preservation','--source-proof'],cwd=ROOT)
    diagnostic=json.loads(raw)
    baseline=json.loads((ROOT/'runtime/coursework/assignment4/before.json').read_text())
    initial=json.loads((ROOT/'coursework/initial_inventory.json').read_text())
    known={row['path']:row['sha256'] for row in initial['all_files']}
    known.update(baseline['files'])
    env=dict(os.environ,GIT_OPTIONAL_LOCKS='0')
    source={k:subprocess.check_output(['git','-C',str(SOURCE),*args],env=env).decode().strip()
        for k,args in [('head',['rev-parse','HEAD']),('tag_object',['rev-parse','cyberquality-defense-ready-20261105']),
                       ('tag_commit',['rev-parse','cyberquality-defense-ready-20261105^{commit}'])]}
    source['status_sha256']=hashlib.sha256(subprocess.check_output(['git','-C',str(SOURCE),'status','--porcelain=v1','--untracked-files=all'],env=env)).hexdigest()
    assert source==baseline['source'], 'Protected original Git commit/tag/status changed; stop modifications'
    assert source['head']==source['tag_commit']=='95513fc10dd4356352f9bc935ba8bcf63532a04e'
    protected={name:expected for name,expected in initial['preserved_artifacts'].items()
               if name.split('/')[0] in ('data','evidence','experiments','outputs','legacy')}
    mismatches=[]
    for name,expected in protected.items():
        p=SOURCE/name
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:mismatches.append(name)
    assert not mismatches, 'Original protected artifact differs from preserved copy baseline; stop modifications'
    assert not subprocess.check_output(['git','remote','-v'],cwd=ROOT)
    changed=[];added=[]
    for folder in ('coursework','scripts','demo/backend','demo/frontend/src','demo/frontend/scripts','docs','tests'):
        for p in (ROOT/folder).rglob('*'):
            if not p.is_file() or '__pycache__' in p.parts or p.name.endswith(('.pyc','.log')):continue
            name=str(p.relative_to(ROOT));previous=known.get(name)
            if previous is None:added.append(name)
            elif hashlib.sha256(p.read_bytes()).hexdigest()!=previous:changed.append(name)
    for name in ('README.md',):
        if (ROOT/name).exists() and name not in known:added.append(name)
    report={'diagnostic':diagnostic,'original_git_commit_tag_status':'UNCHANGED',
            'original':source,'changed_existing':sorted(changed),'added':sorted(added),
            'original_protected_artifact_files':len(protected),'original_protected_artifact_hashes':'MATCH_PRESERVED_COPY_BASELINE',
            'write_scope':'All task state/audit/builds/reports under runtime/coursework; implementation files inside coursework workspace',
            'services':'Live paths require a verified authorized lease; no shared-service operation was authorized or executed during this integration. Host observations are separate.',
            'no_remotes':True}
    path=ROOT/'runtime/coursework/assignment4/safety-receipt.json'
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
