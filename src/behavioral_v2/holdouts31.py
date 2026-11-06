"""Post-freeze controlled/human evidence; never automatically changes models."""
from datetime import datetime
import json
from pathlib import Path
from branch2.adapters.apache import read_log
from branch2.events import utc
from branch2.windowing import windows
from branch2.features import extract as v1_extract,schema as v1_schema
from branch2.artifacts import load as load_v1
from branch2.capture.verification import verify
from branch2.capture.planning import schedule,sha as plan_sha
from branch2.capture.safety import validate_schedule
from branch2.dataset import CLASSES
from .browser_capture import LogBoundary,feature_rows,now,TARGET
from .platforms import MoodleBehaviorAdapter
from .features31 import schema,extract
from .study31 import verify_freeze,report_predictions
from .data import sha,write


def attack_plan(freeze_path,context,out):
    freeze,package=verify_freeze(freeze_path)
    if context['target']!=TARGET:raise ValueError('Unauthorized attack target')
    counts={c:0 if c=='BENIGN' else 2 for c in CLASSES}
    # The accepted planner allows offsets only through60. Reuse its actual
    # bounded protocols, selecting later IDs from a larger OFFLINE plan;
    # no extra traffic is executed and no core safety bounds are changed.
    expanded=schedule(context,20261014,{c:0 if c=='BENIGN' else 12 for c in CLASSES},run_offset=60)
    chosen=[]
    for label in sorted(set(CLASSES)-{'BENIGN'}):
        candidates=sorted([r for r in expanded['runs'] if r['label']==label],key=lambda r:r['run_id'])
        chosen.extend(candidates[-2:])
    plan={**expanded,'runs':chosen,'requested_counts':counts,'target_reduced':True}
    offset=0
    for r in chosen:
        r['planned_start_offset_seconds']=offset;r['planned_end_offset_seconds']=offset+r['duration_seconds']
        offset+=r['duration_seconds']+4
    plan.update(estimated_requests=sum(r['planned_request_count'] for r in chosen),estimated_duration_seconds=offset,
        m5_freeze_sha256=sha(freeze_path))
    plan['schedule_sha256']=plan_sha({k:v for k,v in plan.items() if k!='schedule_sha256'})
    validate_schedule(plan)
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    write(out/'counts.json',counts);write(out/'schedule.json',plan)
    write(out/'freeze_binding.json',{'freeze_sha256':sha(freeze_path),'frozen_at_utc':freeze['frozen_at_utc'],
        'created_at_utc':now(),'schedule_file_sha256':sha(out/'schedule.json'),
        'package_manifest_sha256':freeze['package_manifest_sha256'],'execution_performed':False,
        'rule':'Generate these new run IDs only after this freeze; never train on them'})
    return {'planned_fresh_attack_runs':len(plan['runs']),'network_requests':0}


def evaluate_attacks(capture_root,freeze_path,out,project):
    freeze,package=verify_freeze(freeze_path);qa=verify(capture_root)
    if not qa['verified']:raise ValueError('Fresh attack capture verification failed')
    root=Path(capture_root);plan=json.loads((root/'schedule.json').read_text())
    rows=[];old=[];adapter=MoodleBehaviorAdapter();s=schema(adapter)
    if any(r['label']=='BENIGN' for r in plan['runs']):raise ValueError('Dedicated fresh attack holdout required')
    forbidden=set(package.config['train_ids']+package.config['validation_ids'])
    for run in plan['runs']:
        rid=run['run_id'];manifest=json.loads((root/rid/'manifest.json').read_text())
        if rid in forbidden:raise ValueError('Fresh attack run reused in development')
        if utc(manifest['actual_start_precise_utc'])<=utc(freeze['frozen_at_utc']):raise ValueError('Attack was generated before freeze')
        path=root/rid/'access.log'
        # Current coordinator records an absolute authoritative access_file.
        if not path.exists():path=Path(manifest['access_file'])
        events,errors,filehash=read_log(path,str(path))
        if errors or filehash!=manifest['access_sha256']:raise ValueError('Attack source hash/parse mismatch')
        for window in windows(events):
            es=window.pop('events');base={**window,'run_id':rid,'label':run['label'],'partition':'FRESH_ATTACK_TEST',
                'source_file':str(path),'source_sha256':filehash,'line_numbers':[e.line_number for e in es]}
            rows.append({**base,'features':extract(es,adapter),'schema_sha256':s['sha256']})
            old.append({**base,'features':v1_extract(es),'schema_sha256':v1_schema()['sha256']})
    if {r['label'] for r in rows}!=set(CLASSES)-{'BENIGN'}:raise ValueError('All seven fresh attempt classes required')
    out=Path(out);out.mkdir(parents=True,exist_ok=False);v1=load_v1(Path(project)/'outputs/branch2/m2c_final_01')
    new_predictions=package.predict(rows);old_predictions=v1.predict(old)
    result={'evaluation':'FRESH_POST_FREEZE_CONTROLLED_ATTEMPTS','freeze_sha256':sha(freeze_path),
        'capture_verification':qa,'candidate':report_predictions(new_predictions,package.config['persistence'],package.classes),
        'v1':report_predictions(old_predictions,1,v1.classes),'retuning_performed':False}
    write(out/'candidate_predictions.json',new_predictions);write(out/'v1_predictions.json',old_predictions);write(out/'metrics.json',result)
    return result


def human_start(root,session_id,freeze_path,actor,log=Path('/var/log/apache2/access.log')):
    if session_id not in ('H1','H2','H3'):raise ValueError('Reserved human holdout ID required')
    freeze,_=verify_freeze(freeze_path);base=Path(root)/'human_sessions'/session_id
    base.mkdir(parents=True,exist_ok=False);b=LogBoundary(log);b.handle.close()
    start={'session_id':session_id,'start_utc':b.started,'offset_start':b.start,
        'source_device':b.device,'source_inode':b.inode,'source_path':str(b.path),
        'actor_ip':actor,'agent_marker':'M5Human/'+session_id,'freeze_sha256':sha(freeze_path)}
    write(base/'start.json',start)
    return {'session_id':session_id,'state':'CAPTURE_STARTED','user_agent_suffix':start['agent_marker']}


def human_stop(root,session_id,freeze_path,*,protocol_complete=False):
    if session_id not in ('H1','H2','H3'):raise ValueError('Reserved human holdout ID required')
    freeze,_=verify_freeze(freeze_path);base=Path(root)/'human_sessions'/session_id
    start=json.loads((base/'start.json').read_text())
    if start['freeze_sha256']!=sha(freeze_path):raise ValueError('Human holdout freeze changed')
    if (base/'manifest.json').exists():raise ValueError('Human session already finalized')
    b=LogBoundary(Path(start['source_path']));b.start=start['offset_start'];b.started=start['start_utc']
    b.device=start['source_device'];b.inode=start['source_inode']
    events,provenance=b.close(session_id,start['actor_ip'],'marker:'+start['agent_marker'])
    valid=protocol_complete and bool(events) and not provenance['foreign_records'] and not provenance['malformed_records']
    s={'session_id':'M5-HUMAN-'+session_id,'protocol':session_id,'partition':'EXTERNAL_HUMAN_TEST'}
    rows,old=feature_rows(events,s,provenance) if valid else ([],[])
    write(base/'features.json',rows);write(base/'v1_features.json',old)
    manifest={'session_id':session_id,'status':'COMPLETE' if valid else 'INVALID',
        'provenance':provenance,'protocol_completed_by_operator':protocol_complete,
        'label':'BENIGN' if valid else None,'label_basis':'explicit human protocol attestation; no model-derived labels',
        'freeze_sha256':sha(freeze_path),'features_sha256':sha(base/'features.json'),'v1_features_sha256':sha(base/'v1_features.json')}
    write(base/'manifest.json',manifest);return {'session_id':session_id,'status':manifest['status'],'windows':len(rows)}


def evaluate_human(root,freeze_path,out,project):
    freeze,package=verify_freeze(freeze_path);rows=[];old=[]
    for session in ('H1','H2','H3'):
        base=Path(root)/'human_sessions'/session;m=json.loads((base/'manifest.json').read_text())
        if m['status']!='COMPLETE' or m['freeze_sha256']!=sha(freeze_path):raise ValueError('Incomplete human holdout')
        if sha(base/'features.json')!=m['features_sha256'] or sha(base/'v1_features.json')!=m['v1_features_sha256']:raise ValueError('Human capture changed')
        rows.extend(json.loads((base/'features.json').read_text()));old.extend(json.loads((base/'v1_features.json').read_text()))
    out=Path(out);out.mkdir(parents=True,exist_ok=False);v1=load_v1(Path(project)/'outputs/branch2/m2c_final_01')
    p=package.predict(rows);q=v1.predict(old)
    result={'evaluation':'THREE_POST_FREEZE_HUMAN_PROTOCOL_SESSIONS','ground_truth':'operator-attested controlled benign protocol; not population sampling',
        'candidate':report_predictions(p,package.config['persistence'],package.classes),
        'v1':report_predictions(q,1,v1.classes),'no_retuning':True}
    write(out/'metrics.json',result);write(out/'candidate_predictions.json',p);write(out/'v1_predictions.json',q)
    return result


def evaluate_old_external(session,freeze_path,out,project):
    """Additional diagnostic replication only; never supplies labels or tuning."""
    freeze,package=verify_freeze(freeze_path)
    from .data import external
    from .episodes import episodes
    rows,original,event_groups=external(session);adapter=MoodleBehaviorAdapter();s=schema(adapter)
    rebuilt=[{**r,'features':extract(event_groups[r['record_id']],adapter),'schema_sha256':s['sha256'],
        'feature_schema_version':s['version'],'partition':'EXTERNAL_DIAGNOSTIC_HOLDOUT','label':None} for r in rows]
    if {r['run_id'] for r in rebuilt}&set(package.config['train_ids']+package.config['validation_ids']):raise ValueError('External session leaked into development')
    out=Path(out);out.mkdir(parents=True,exist_ok=False);predictions=package.predict(rebuilt)
    def describe(ps,persistence):
        return {'windows':len(ps),'decisions':dict(__import__('collections').Counter(p['reconciliation']['decision'] for p in ps)),
            'disagreements':sum(p['reconciliation']['model_disagreement'] for p in ps),
            'alert_episodes':sum(e['alert'] for e in episodes(ps,persistence))}
    result={'evaluation':'OLD_DIAGNOSTIC_INFORMED_FEATURE_HYPOTHESES_NOT_BLIND',
        'v1':describe(original,1),'candidate':describe(predictions,package.config['persistence']),
        'ground_truth':None,'accuracy_or_population_FPR_claimed':False,'fit_calls':0,'freeze_sha256':sha(freeze_path)}
    write(out/'candidate_predictions.json',predictions);write(out/'comparison.json',result)
    return result
