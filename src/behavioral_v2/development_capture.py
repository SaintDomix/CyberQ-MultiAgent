"""Resumable DEVELOPMENT collection only. No models, datasets or TEST access."""
from collections import Counter
import json
import os
from pathlib import Path

from .browser_capture import CaptureError,capture,readiness,validate_plan,verify_capture
from .data import sha,write


UNAVAILABLE_CODE='REQUIRED_RESOURCE_UNAVAILABLE'


def _snapshot(root,plan):
    records=[]
    # Filter reservations BEFORE any filesystem access. Never inspect TEST dirs.
    sessions=sorted((s for s in plan['sessions'] if s['partition'] in ('TRAIN','VALIDATION')),
        key=lambda s:(s['partition']!='TRAIN',s['session_id']))
    for s in sessions:
        base=root/'browser_sessions'/s['session_id']
        record={'session_id':s['session_id'],'partition':s['partition'],
            'protocol':s['protocol'],'role':s['role'],'state':'PENDING','unavailable':False}
        if base.exists():
            if base.is_symlink() or not base.is_dir() or not (base/'manifest.json').is_file():
                raise CaptureError('PARTIAL_EXISTING_DEVELOPMENT_CAPTURE')
            m=json.loads((base/'manifest.json').read_text())
            if (m.get('session_id'),m.get('partition'),m.get('protocol'),m.get('plan_sha256'))!=(
                s['session_id'],s['partition'],s['protocol'],plan['sha256']):
                raise CaptureError('EXISTING_DEVELOPMENT_MEMBERSHIP_MISMATCH')
            if m.get('status')=='COMPLETE':record['state']='AWAITING_VERIFICATION'
            elif m.get('status')=='INVALID':
                record['state']='PRESERVED_INVALID'
                record['unavailable']=m.get('error_code')==UNAVAILABLE_CODE
            else:raise CaptureError('UNKNOWN_EXISTING_DEVELOPMENT_STATUS')
        records.append(record)
    return sessions,records


def _summary(plan,records,status,receipts,error=None):
    counts={}
    for partition in ('TRAIN','VALIDATION'):
        subset=[r for r in records if r['partition']==partition]
        states=Counter(r['state'] for r in subset)
        counts[partition]={'verified_complete':states['VERIFIED_COMPLETE'],
            'invalid':states['PRESERVED_INVALID']+states['NEW_INVALID'],
            'unavailable':sum(r['unavailable'] for r in subset),
            'pending':states['PENDING'],'awaiting_verification':states['AWAITING_VERIFICATION'],
            'verification_failed':states['VERIFICATION_FAILED'],'capture_failed':states['CAPTURE_FAILED']}
    return {'version':'m5-development-collection-1.0','status':status,'error_code':error,
        'plan_sha256':plan['sha256'],'partitions':['TRAIN','VALIDATION'],
        'sessions':records,'counts':counts,'verification_receipts':receipts,
        'test_files_opened':False,'test_capture_performed':False,'models_invoked':False,
        'development_review_required_before_build':True,
        'invalid_sessions_eligible_for_dataset':False}


def _new_collection_dir(root):
    parent=root/'development_collection_runs'
    parent.mkdir(exist_ok=True)
    for number in range(1,10001):
        dest=parent/f'collection_{number:03d}'
        try:dest.mkdir();return dest
        except FileExistsError:continue
    raise CaptureError('COLLECTION_OUTPUT_BOUND')


def collect_development(root,plan,*,authorized=False,dry_run=False,actor='192.168.226.132',
    emit=None):
    """Run TRAIN then VALIDATION, verifying each usable capture independently."""
    root=Path(root);validate_plan(plan)
    if not dry_run and not authorized:raise CaptureError('EXPLICIT_AUTHORIZATION_REQUIRED')
    sessions,records=_snapshot(root,plan)
    if dry_run:
        result=_summary(plan,records,'DRY_RUN',[])
        result.update(network_requests=0,log_reads=0,
            estimated_remaining_browser_seconds=sum(s['duration_seconds']+15
                for s,r in zip(sessions,records) if r['state']=='PENDING'))
        return result
    # No browser, raw log verification or new artifacts before role preflight.
    for role in sorted({r['role'] for r in records if r['state']=='PENDING'}):
        info=readiness(role)
        if not info['target_authorized']:raise CaptureError('UNAUTHORIZED_TARGET')
        if not info['credentials_present'] or not info['identity_marker_present']:
            raise CaptureError('MISSING_CREDENTIALS_OR_IDENTITY_MARKER')
    if os.environ.get('DEBUG') or os.environ.get('PWDEBUG'):
        raise CaptureError('UNSAFE_DEBUG_ENVIRONMENT')
    dest=_new_collection_dir(root);receipts=[];error=None

    def verify(record):
        try:
            checked=verify_capture(root,plan,record['session_id'])
            if (checked.get('verified') is not True or checked.get('source_bytes_verified') is not True
                or checked.get('ownership_filtering_reproduced') is not True
                or checked.get('network_requests')!=0):
                raise CaptureError('INDEPENDENT_VERIFICATION_FAILED')
            receipt={k:checked[k] for k in ('session_id','verified','windows','source_records',
                'accepted_records','foreign_records','attribution_policy','ownership_filtering_reproduced',
                'source_bytes_verified','network_requests')}
            receipt['capture_manifest_sha256']=sha(root/'browser_sessions'/record['session_id']/'manifest.json')
            receipts.append(receipt);record['state']='VERIFIED_COMPLETE'
        except Exception:
            record['state']='VERIFICATION_FAILED'
            return 'INDEPENDENT_VERIFICATION_FAILED'
        return None

    # Validate every existing COMPLETE capture before generating new requests.
    for record in records:
        if record['state']=='AWAITING_VERIFICATION':
            error=verify(record)
            if error:break
    if not error:
        for session,record in zip(sessions,records):
            if record['state']!='PENDING':continue
            try:
                result=capture(plan,session['session_id'],root/'browser_sessions',
                    authorized=True,actor=actor)
                if result.get('status')=='COMPLETE':error=verify(record)
                elif result.get('status')=='INVALID':
                    record['state']='NEW_INVALID'
                    record['unavailable']=result.get('error_code')==UNAVAILABLE_CODE
                    if not record['unavailable']:error='UNEXPECTED_CAPTURE_FAILURE'
                else:
                    record['state']='CAPTURE_FAILED';error='UNEXPECTED_CAPTURE_STATUS'
            except Exception:
                record['state']='CAPTURE_FAILED';error='DEVELOPMENT_CAPTURE_OR_INTEGRITY_FAILURE'
            if emit is not None:emit(dict(record))
            if error:break
    status='STOPPED' if error else 'COMPLETE_WITH_EXCLUSIONS' if any(
        r['state'] in ('PRESERVED_INVALID','NEW_INVALID') for r in records) else 'COMPLETE'
    summary=_summary(plan,records,status,receipts,error)
    summary['collection_id']=dest.name
    summary['summary_relative_path']='development_collection_runs/'+dest.name+'/summary.json'
    write(dest/'summary.json',summary)
    return summary
