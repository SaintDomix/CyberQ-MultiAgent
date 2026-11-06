#!/usr/bin/env python3
"""Pre-test gate and TEST-only collection. Never fit, predict, tune or promote."""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from behavioral_v2.browser_capture import CaptureError,capture,readiness,validate_plan,verify_capture,digest
from behavioral_v2.data import sha,write
from behavioral_v2.development_review import frozen_core_unchanged
from behavioral_v2.study31 import verify_freeze

EXPECTED_ROOT='0493bd3ec93b58d288269a736abb51a400c89cf66a05e44bd45e75a2e65cc6c1'
EXPECTED_ID='m5-v3.1-b57550611aa11e00b4bb'
CLASSIFICATION_RULE={
    'scope':'Benign generalization only; no promotion; descriptive small-sample policy',
    'PASS':'All six reserved sessions verified; zero known-attack windows; zero alerted benign runs; raw novelty FPR <=0.05; episode run alert rate no worse than v1',
    'FAIL':'Integrity failure, or raw novelty FPR >=0.50, or episode run alert rate >=0.50, or false known-attack window rate >=0.10, or candidate episode run alert rate exceeds v1 by >=1/3',
    'MIXED':'All other evaluable cases, including unavailable/INVALID reservations',
    'integrity_failure_action':'Stop; do not calculate metrics',
    'selection_or_tuning_authorized':False}


def integrity(root,candidate,dataset,project,*,require_absence):
    """Freeze is validated before any TEST directory check or artifact read."""
    root=Path(root);candidate=Path(candidate);dataset=Path(dataset)
    f,_=verify_freeze(candidate/'freeze_manifest.json')
    if f['root_sha256']!=EXPECTED_ROOT or f['candidate_id']!=EXPECTED_ID:
        raise CaptureError('UNEXPECTED_BLIND_TEST_CANDIDATE')
    if len(f['artifact_files_sha256'])!=23:raise CaptureError('FROZEN_ARTIFACT_COUNT_CHANGED')
    for name,value in f['artifact_files_sha256'].items():
        if sha(candidate/name)!=value:raise CaptureError('FROZEN_ARTIFACT_CHANGED')
    if not frozen_core_unchanged(project):raise CaptureError('MODEL_V1_CORE_CHANGED')
    review=json.loads((candidate/'development_review.json').read_text())
    if sha(root/'predeclared_capture_plan.json')!=review['original_plan_file_sha256']:
        raise CaptureError('ORIGINAL_PLAN_CHANGED')
    if sha(dataset)!=f['development_dataset_sha256']:raise CaptureError('DEVELOPMENT_DATASET_CHANGED')
    if sha(dataset.parent/'development_manifest.json')!=f['development_manifest_sha256']:
        raise CaptureError('DEVELOPMENT_MANIFEST_CHANGED')
    if any(f.get(k) is not False for k in ('TEST_ACCESSED_BEFORE_FREEZE','TEST_USED_FOR_SELECTION','FRESH_ATTACK_HOLDOUT_USED_FOR_SELECTION')):
        raise CaptureError('DEVELOPMENT_BLINDNESS_NOT_PROVEN')
    v1=Path(project)/'outputs/branch2/m2c_final_01';v1_manifest=json.loads((v1/'package_manifest.json').read_text())
    for name,value in v1_manifest['files_sha256'].items():
        if Path(name).name!=name or sha(v1/name)!=value:raise CaptureError('MODEL_V1_ARTIFACT_CHANGED')
    plan=validate_plan(json.loads((root/'predeclared_capture_plan.json').read_text()))
    sessions=sorted((s for s in plan['sessions'] if s['partition']=='TEST'),key=lambda s:s['session_id'])
    if (plan['sha256']!=f['capture_plan_sha256'] or len(sessions)!=6
        or [s['session_id'] for s in sessions]!=f['reserved_fresh_test_ids']):
        raise CaptureError('TEST_RESERVATIONS_CHANGED')
    if require_absence and any((root/'browser_sessions'/s['session_id']).exists() for s in sessions):
        raise CaptureError('TEST_ALREADY_EXISTS_BEFORE_GATE')
    return plan,f,{'status':'PASS','candidate_id':f['candidate_id'],'candidate_canonical_root_sha256':f['root_sha256'],
        'candidate_freeze_file_sha256':sha(candidate/'freeze_manifest.json'),'frozen_artifacts_verified':23,
        'original_plan_file_sha256':sha(root/'predeclared_capture_plan.json'),
        'development_dataset_sha256':sha(dataset),'development_manifest_sha256':f['development_manifest_sha256'],
        'model_v1_manifest_sha256':sha(v1/'package_manifest.json'),'model_v1_core_unchanged':True,
        'reserved_test_sessions':[{k:s[k] for k in ('session_id','protocol','role','partition')} for s in sessions],
        'expected_sessions':6,'no_test_used_during_development':True,'classification_rule':CLASSIFICATION_RULE}


def prepare(root,candidate,dataset,out,project):
    _,_,checked=integrity(root,candidate,dataset,project,require_absence=True)
    result={'version':'m5-blind-benign-pretest-1.0',**checked,
        'prepared_at_utc':datetime.now(timezone.utc).isoformat(),'test_captures_absent_at_gate':True,
        'test_observations_opened':False,'models_evaluated':False}
    result['sha256']=digest(result)
    Path(out).mkdir(parents=True,exist_ok=False)
    write(Path(out)/'pre_test_integrity.json',result)
    return result


def collect(root,candidate,dataset,out,project,*,authorized=False,dry_run=False,actor='192.168.226.132'):
    root=Path(root);candidate=Path(candidate);out=Path(out)
    if not authorized and not dry_run:raise CaptureError('EXPLICIT_AUTHORIZATION_REQUIRED')
    plan,f,checked=integrity(root,candidate,dataset,project,require_absence=False)
    receipt=json.loads((out/'pre_test_integrity.json').read_text())
    if (receipt.get('version')!='m5-blind-benign-pretest-1.0'
        or receipt.get('sha256')!=digest({k:v for k,v in receipt.items() if k!='sha256'})
        or receipt.get('test_captures_absent_at_gate') is not True
        or any(receipt.get(k)!=value for k,value in checked.items())):
        raise CaptureError('PRE_TEST_RECEIPT_CHANGED')
    sessions=[s for s in plan['sessions'] if s['partition']=='TEST']
    sessions.sort(key=lambda s:s['session_id'])
    if dry_run:return {'status':'DRY_RUN','sessions':[s['session_id'] for s in sessions],
        'network_requests':0,'source_log_reads':0,'models_evaluated':False}
    preexisting={s['session_id'] for s in sessions if (root/'browser_sessions'/s['session_id']).exists()}
    locked=out/'test_evidence_manifest.json'
    if locked.exists():
        evidence=json.loads(locked.read_text())
        if (evidence.get('sha256')!=digest({k:v for k,v in evidence.items() if k!='sha256'})
            or (out/'test_evidence_manifest.sha256').read_text().strip()!=sha(locked)
            or evidence.get('candidate_canonical_root_sha256')!=f['root_sha256']):
            raise CaptureError('LOCKED_TEST_EVIDENCE_CHANGED')
        if {r['session_id'] for r in evidence['sessions']}!={s['session_id'] for s in sessions}:
            raise CaptureError('LOCKED_TEST_MEMBERSHIP_CHANGED')
        for record in evidence['sessions']:
            for name,value in record['artifact_hashes'].items():
                if name not in ('manifest.json','features.json','v1_features.json') or sha(root/'browser_sessions'/record['session_id']/name)!=value:
                    raise CaptureError('LOCKED_TEST_CAPTURE_CHANGED')
    for role in sorted({s['role'] for s in sessions if not (root/'browser_sessions'/s['session_id']).exists()}):
        r=readiness(role)
        if not r['target_authorized']:raise CaptureError('UNAUTHORIZED_TARGET')
        if not r['credentials_present'] or not r['identity_marker_present']:
            raise CaptureError('MISSING_CREDENTIALS_OR_IDENTITY_MARKER')
    if os.environ.get('DEBUG') or os.environ.get('PWDEBUG'):raise CaptureError('UNSAFE_DEBUG_ENVIRONMENT')
    attempts=out/'collection_runs';attempts.mkdir(exist_ok=True)
    for index in range(1,10001):
        dest=attempts/f'collection_{index:03d}'
        try:dest.mkdir();break
        except FileExistsError:continue
    else:raise CaptureError('COLLECTION_OUTPUT_BOUND')
    records=[];error=None
    for session in sessions:
        sid=session['session_id'];base=root/'browser_sessions'/sid
        record={'session_id':sid,'protocol':session['protocol'],'role':session['role'],
            'state':'PENDING','unavailable':False,'windows':0,'verified':False}
        records.append(record)
        try:
            if not base.exists():
                result=capture(plan,sid,root/'browser_sessions',authorized=True,actor=actor,
                    freeze_path=candidate/'freeze_manifest.json')
            else:
                if base.is_symlink() or not (base/'manifest.json').is_file():raise CaptureError('PARTIAL_EXISTING_TEST_CAPTURE')
                result=json.loads((base/'manifest.json').read_text())
            if (result.get('session_id')!=sid or result.get('partition')!='TEST'
                or result.get('protocol')!=session['protocol'] or result.get('plan_sha256')!=plan['sha256']):
                raise CaptureError('TEST_CAPTURE_MEMBERSHIP_CHANGED')
            # Even INVALID attempts cannot predate this prospective integrity gate.
            start=result.get('provenance',{}).get('start_utc')
            if start is None or datetime.fromisoformat(start)<=max(
                datetime.fromisoformat(f['frozen_at_utc']),datetime.fromisoformat(receipt['prepared_at_utc'])):
                raise CaptureError('TEST_CAPTURE_PREDATES_GATE_OR_FREEZE')
            if result.get('status')=='COMPLETE':
                verified=verify_capture(root,plan,sid)
                if not verified.get('verified') or not verified.get('ownership_filtering_reproduced'):
                    raise CaptureError('TEST_VERIFICATION_FAILED')
                record.update(state='COMPLETE',verified=True,windows=verified['windows'],
                    accepted_records=verified['accepted_records'],foreign_records=verified['foreign_records'])
            elif result.get('status')=='INVALID':
                record.update(state='INVALID',unavailable=result.get('error_code')=='REQUIRED_RESOURCE_UNAVAILABLE')
            else:raise CaptureError('UNKNOWN_TEST_CAPTURE_STATUS')
            record['artifact_hashes']={name:sha(base/name) for name in ('manifest.json','features.json','v1_features.json')}
            p=result['provenance'];record['provenance']={k:p.get(k) for k in (
                'slice_sha256','source_device','source_inode','offset_start','offset_end','attribution_policy',
                'session_marker_sha256','observed_records','accepted_records','foreign_records')}
            # New unexpected failures stop; existing INVALID attempts are preserved
            # on explicit resume without replacing the reservation or protocol.
            if record['state']=='INVALID' and not record['unavailable'] and sid not in preexisting:
                error='UNEXPECTED_TEST_CAPTURE_FAILURE'
        except Exception:
            error='TEST_CAPTURE_OR_VERIFICATION_FAILURE';record['state']='BLOCKED'
        print(json.dumps({k:v for k,v in record.items() if k not in ('artifact_hashes','provenance')}),flush=True)
        if error:break
    result={'version':'m5-blind-benign-collection-1.0','status':'STOPPED' if error else 'COMPLETE',
        'error_code':error,'candidate_id':f['candidate_id'],'candidate_canonical_root_sha256':f['root_sha256'],
        'sessions':records,'reserved_session_count':6,'models_evaluated':False,'training_performed':False,
        'counts':{'COMPLETE':sum(r['state']=='COMPLETE' for r in records),
            'INVALID':sum(r['state']=='INVALID' for r in records),'unavailable':sum(r['unavailable'] for r in records),
            'verified':sum(r['verified'] for r in records),'not_finished':6-sum(r['state'] in ('COMPLETE','INVALID') for r in records)}}
    write(dest/'summary.json',result)
    if not error:
        evidence={'version':'m5-blind-benign-evidence-1.0','candidate_id':f['candidate_id'],
            'candidate_canonical_root_sha256':f['root_sha256'],'candidate_freeze_file_sha256':sha(candidate/'freeze_manifest.json'),
            'pre_test_integrity_sha256':sha(out/'pre_test_integrity.json'),'capture_plan_sha256':plan['sha256'],
            'feature_schema_sha256':f['schema_sha256'],'sessions':records,'counts':result['counts'],
            'models_evaluated_before_lock':False,'no_test_to_development_transfer':True}
        evidence['sha256']=digest(evidence);path=out/'test_evidence_manifest.json'
        if path.exists():
            if json.loads(path.read_text())!=evidence:raise CaptureError('LOCKED_TEST_EVIDENCE_CHANGED')
        else:
            write(path,evidence)
            with (out/'test_evidence_manifest.sha256').open('x') as handle:handle.write(sha(path)+'\n')
        result['test_evidence_file_sha256']=sha(path)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','collect'])
    parser.add_argument('--authorized',action='store_true');parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args(argv)
    root=ROOT/'outputs/branch2/m5_final_day';candidate=root/'candidate_freeze_01'
    dataset=ROOT/'data/branch2_v3/development_freeze_01/dataset.json';out=root/'blind_benign_test_01'
    try:
        if args.action=='prepare':
            if args.dry_run:raise CaptureError('PREPARE_REQUIRES_WRITE_ONCE_RECEIPT')
            result=prepare(root,candidate,dataset,out,ROOT)
        else:result=collect(root,candidate,dataset,out,ROOT,authorized=args.authorized,dry_run=args.dry_run)
        print(json.dumps(result,indent=2));return 2 if result.get('status')=='STOPPED' else 0
    except (OSError,ValueError,KeyError):
        print('Blind TEST blocked: integrity, authorization, readiness or evidence failure. No secret details exported.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
