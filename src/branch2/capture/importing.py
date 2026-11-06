"""Verified-only import into Ubuntu source of truth; historical files never overwritten."""
import csv
import json
from pathlib import Path
import shutil
from .verification import verify
from .server import write
from .planning import sha


def import_capture(project,root,name,allow_partial=False):
    project=Path(project).resolve();root=Path(root).resolve()
    if not root.is_relative_to(project/'evidence/branch2_captures'):raise ValueError('Import only source-of-truth capture evidence')
    report=verify(root)
    if not report['verified']:raise ValueError('Capture verification failed; import/build/training prohibited')
    plan=json.loads((root/'schedule.json').read_text())
    if plan['target_reduced'] and not allow_partial:raise ValueError('Reduced schedule requires explicit partial import')
    import re
    if not re.fullmatch(r'[a-zA-Z0-9_-]+',name):raise ValueError('Safe import name required')
    metadata=project/'experiments'/f'branch2_{name}_metadata.csv'
    labels=project/'experiments'/f'branch2_{name}_labels.json'
    receipt=project/'experiments'/f'branch2_{name}_import.json'
    if any(p.exists() for p in (metadata,labels,receipt)):raise ValueError('Import artifacts already exist')
    with (project/'experiments/experiment_metadata.csv').open() as f: rows=list(csv.DictReader(f))
    label_data=json.loads((project/'experiments/branch2_v2_labels.json').read_text())
    copies=[]
    for run in plan['runs']:
        directory=root/run['run_id'];m=json.loads((directory/'manifest.json').read_text())
        coarse='benign' if run['label']=='BENIGN' else 'suspicious'
        filename=f"{run['scenario_id']}_{coarse}_run{run['run_number']:02d}_access.log"
        destination=project/'data/raw'/filename
        if destination.exists():raise ValueError('Raw capture filename already exists; no historical overwrite')
        copies.append((directory/'access.log',destination))
        rows.append({'scenario_id':run['scenario_id'],'label':coarse,'run':f"{run['run_number']:02d}",
            'start_utc':m['start_utc'],'end_utc':m['end_utc'],'duration_seconds':run['duration_seconds'],
            'access_file':str(destination),'error_file':''})
        existing=label_data['scenarios'].get(run['scenario_id'])
        if existing and existing['label']!=run['label']:raise ValueError('Label conflict with historical scenario')
        label_data['scenarios'][run['scenario_id']]={'label':run['label'],'basis':
            (existing['basis']+'; ' if existing else '')+'Verified controlled M2B capture; manifest/protocol retained, not confirmed exploitation'}
    # Check interval/ID independence against preserved historical metadata before copying.
    from ..events import utc
    ids=set();intervals=[]
    for row in rows:
        rid=row['scenario_id']+'-run'+row['run'].zfill(2)
        if rid in ids:raise ValueError('Duplicate imported/historical run ID')
        ids.add(rid)
        if row['scenario_id']=='TEST':continue
        a,b=utc(row['start_utc']),utc(row['end_utc'])
        if any(a<d and c<b for c,d in intervals):raise ValueError('Historical/new intervals overlap')
        intervals.append((a,b))
    label_data['source_references']+= [str((root/'schedule.json').relative_to(project))]
    for run in plan['runs']:label_data['source_references'].append(str((root/run['run_id']/'manifest.json').relative_to(project)))
    for source,destination in copies:
        with destination.open('xb') as out,source.open('rb') as inp:shutil.copyfileobj(inp,out)
    with metadata.open('x',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=rows[0].keys());writer.writeheader();writer.writerows(rows)
    write(labels,label_data)
    write(receipt,{'verification':report,'capture_root':str(root.relative_to(project)),
        'schedule_sha256':plan['schedule_sha256'],'metadata':str(metadata),'labels':str(labels),
        'stage':'VALIDATED_CAPTURE_CANDIDATE; final model training requires separate review'})
    return {'metadata':str(metadata),'labels':str(labels),'receipt':str(receipt)}
