"""Explicit, hash-bound development review. No TEST observations or model fitting."""
import json
from pathlib import Path
import subprocess

from .browser_capture import validate_plan,verify_capture,digest
from .data import sha


VERSION='m5-development-review-1.0'


def frozen_core_unchanged(project):
    paths=['src/branch1','src/branch2','src/fusion','src/reporting']
    return not subprocess.check_output(['git','diff','milestone-3-end-to-end','--',*paths],cwd=project) and not subprocess.check_output(
        ['git','status','--porcelain','--',*paths],cwd=project)


def review_development(root,summary_path,excluded_ids,project):
    root=Path(root);summary_path=Path(summary_path)
    plan=validate_plan(json.loads((root/'predeclared_capture_plan.json').read_text()))
    summary=json.loads(summary_path.read_text());excluded_ids=set(excluded_ids)
    entries=[s for s in plan['sessions'] if s['partition'] in ('TRAIN','VALIDATION')]
    ids={s['session_id'] for s in entries};checks=[];included=[];excluded=[];bindings={}
    def check(name,passed):checks.append({'check':name,'status':'PASS' if passed else 'FAIL'})
    check('collection_complete',summary['status'] in ('COMPLETE','COMPLETE_WITH_EXCLUSIONS'))
    check('collection_plan_identity',summary['plan_sha256']==plan['sha256'])
    check('collection_no_test_or_models',all(summary.get(k) is False for k in ('test_files_opened','test_capture_performed','models_invoked')))
    check('exclusions_are_development_only',excluded_ids<=ids)
    check('frozen_v1_core_unchanged',frozen_core_unchanged(project))
    receipts={r['session_id']:r for r in summary['verification_receipts']}
    for s in sorted(entries,key=lambda s:s['session_id']):
        sid=s['session_id'];base=root/'browser_sessions'/sid
        m=json.loads((base/'manifest.json').read_text())
        for name in ('manifest.json','features.json','v1_features.json'):
            bindings[str(Path('browser_sessions')/sid/name)]=sha(base/name)
        if sid in excluded_ids:
            check(sid+'_invalid_exclusion',m['status']=='INVALID' and m['label'] is None and m['windows']==0)
            excluded.append({'session_id':sid,'partition':s['partition'],'protocol':s['protocol'],
                'reason':m['error_code'],'manifest_sha256':sha(base/'manifest.json')})
            continue
        verified=verify_capture(root,plan,sid)
        receipt=receipts.get(sid,{})
        check(sid+'_verified',verified['verified'] is True and receipt.get('verified') is True
            and receipt.get('capture_manifest_sha256')==sha(base/'manifest.json')
            and receipt.get('accepted_records')==verified['accepted_records']
            and receipt.get('foreign_records')==verified['foreign_records']
            and verified['ownership_filtering_reproduced'] is True
            and verified['source_bytes_verified'] is True and verified['network_requests']==0)
        included.append({**s,'manifest_sha256':sha(base/'manifest.json'),'verification':verified})
    check('all_development_accounted_for',{s['session_id'] for s in included}|excluded_ids==ids)
    check('train_validation_both_present',{s['partition'] for s in included}=={'TRAIN','VALIDATION'})
    result={'version':VERSION,'status':'PASS' if all(c['status']=='PASS' for c in checks) else 'FAIL',
        'checks':checks,'capture_plan_sha256':plan['sha256'],
        'original_plan_file_sha256':sha(root/'predeclared_capture_plan.json'),
        'collection_summary_relative_path':str(summary_path.resolve().relative_to(root.resolve())),
        'collection_summary_sha256':sha(summary_path),'capture_files_sha256':bindings,
        'included_browser_sessions':included,'excluded_browser_sessions':excluded,
        'reserved_test_ids':sorted(s['session_id'] for s in plan['sessions'] if s['partition']=='TEST'),
        'test_observations_opened':False,'test_used_for_selection':False,'fresh_attack_holdout_used':False,
        'exclusion_authority':'Explicit development review; INVALID attempts remain immutable, no relabeling or replacements',
        'selection_metrics_consulted':False}
    result['sha256']=digest(result)
    return result


def require_development_review(root,plan):
    root=Path(root);r=json.loads((root/'development_review.json').read_text())
    if (r.get('version')!=VERSION or r.get('status')!='PASS' or not r.get('checks')
        or any(c.get('status')!='PASS' for c in r['checks'])
        or r.get('sha256')!=digest({k:v for k,v in r.items() if k!='sha256'})
        or r.get('capture_plan_sha256')!=plan['sha256']
        or r.get('original_plan_file_sha256')!=sha(root/'predeclared_capture_plan.json')
        or r.get('test_observations_opened') is not False or r.get('test_used_for_selection') is not False
        or r.get('fresh_attack_holdout_used') is not False):
        raise ValueError('PASS development review required before dataset construction/fitting')
    allowed={s['session_id']:s for s in plan['sessions'] if s['partition'] in ('TRAIN','VALIDATION')}
    included={s['session_id'] for s in r['included_browser_sessions']}
    excluded={s['session_id'] for s in r['excluded_browser_sessions']}
    if included&excluded or included|excluded!=set(allowed):raise ValueError('Review membership mismatch')
    for s in r['included_browser_sessions']+r['excluded_browser_sessions']:
        if s['partition']!=allowed[s['session_id']]['partition']:raise ValueError('Review partition changed')
    expected={str(Path('browser_sessions')/sid/name) for sid in allowed
        for name in ('manifest.json','features.json','v1_features.json')}
    if set(r['capture_files_sha256'])!=expected:raise ValueError('Review source bindings incomplete')
    for name,expected_hash in r['capture_files_sha256'].items():
        if sha(root/name)!=expected_hash:raise ValueError('Reviewed capture changed')
    path=(root/r['collection_summary_relative_path']).resolve()
    if not path.is_relative_to(root.resolve()) or sha(path)!=r['collection_summary_sha256']:
        raise ValueError('Reviewed collection summary changed')
    return r
