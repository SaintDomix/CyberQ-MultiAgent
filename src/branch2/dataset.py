"""Build Dataset v2 from explicit captured-run and label manifests, never filenames."""
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from .adapters.apache import read_log
from .events import utc
from .features import extract, schema
from .windowing import windows

CLASSES=('BENIGN','BRUTE_FORCE','ENUMERATION_RECONNAISSANCE','ADMIN_PROBING','REQUEST_BURST_DOS_LIKE','SQLI_ATTEMPT','XSS_ATTEMPT','PATH_TRAVERSAL_ATTEMPT')


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sufficiency(runs, minimum=3, final_target=10):
    if minimum < 3 or final_target < minimum: raise ValueError('At least three independent runs for provisional class eligibility')
    result={}
    for label in CLASSES:
        valid=[r for r in runs if r['label']==label and r['windows']>0 and r['included']]
        count=len(valid); target=12 if label=='BENIGN' else final_target
        result[label]={'independent_runs':count,'events':sum(r['included_events'] for r in valid),'windows':sum(r['windows'] for r in valid),
            'provisional_eligible':count>=minimum,'minimum_provisional_runs':minimum,
            'final_capture_target':target,'additional_runs_required':max(0,target-count),
            'readiness':'CAPTURE_TARGET_MET' if count>=target else 'PROVISIONAL_ONLY' if count>=minimum else 'INSUFFICIENT',
            'run_ids':[r['run_id'] for r in valid]}
    return result


def build(project, metadata, label_manifest, seconds=10):
    project=Path(project).resolve();metadata=Path(metadata);label_manifest=Path(label_manifest)
    labels=json.loads(label_manifest.read_text())
    feature_schema=schema(seconds,labels.get('path_rules'))
    rows=[];runs=[];sources={str(metadata):digest(metadata),str(label_manifest):digest(label_manifest)}
    for name in labels.get('source_references',[]):
        sources[name]=digest(project/name)
    seen_ids=set();seen_files=set();seen_events={};intervals=[]
    with metadata.open(newline='') as handle:
        for record in csv.DictReader(handle):
            scenario=record['scenario_id'];run_id=scenario+'-run'+record['run'].zfill(2)
            if run_id in seen_ids: raise ValueError('Duplicate run ID')
            seen_ids.add(run_id)
            # Historical absolute paths are relocated ONLY by recorded basename under data/raw.
            path=project/'data/raw'/Path(record['access_file']).name
            if not path.is_file(): raise ValueError('Capture file missing; do not invent observations')
            mapping=labels['scenarios'].get(scenario)
            if mapping is None: raise ValueError('Explicit scenario-label mapping required')
            label=mapping['label']
            if label not in CLASSES and label is not None: raise ValueError('Unsupported intended class')
            start,end=utc(record['start_utc']),utc(record['end_utc'])
            if end<=start: raise ValueError('Invalid actual capture interval')
            events,failures,filehash=read_log(path,str(path.relative_to(project)))
            sources[str(path.relative_to(project))]=filehash
            error=project/'data/raw'/Path(record['error_file']).name
            if error.is_file(): sources[str(error.relative_to(project))]=digest(error)
            included=label is not None
            if included:
                if filehash in seen_files and events: raise ValueError('Duplicate capture content across runs')
                seen_files.add(filehash)
                if any(start<b and a<end for a,b in intervals): raise ValueError('Overlapping capture intervals: independent runs not established')
                intervals.append((start,end))
                for e in events:
                    if e.record_sha256 in seen_events and seen_events[e.record_sha256]!=run_id:
                        raise ValueError('Observation reused across runs')
                    seen_events[e.record_sha256]=run_id
            outside=[e for e in events if not start<=e.timestamp<end]
            inside=[e for e in events if start<=e.timestamp<end]
            dummy=[e for e in inside if e.infrastructure_dummy]
            accepted=[e for e in inside if not e.infrastructure_dummy] if included else []
            groups=list(windows(accepted,seconds))
            for window in groups:
                observations=window.pop('events')
                rows.append({'run_id':run_id,'scenario':scenario,'label':label,'ground_truth':'capture-level scenario label; not verified per-request exploit success',
                    **window,'source_file':str(path.relative_to(project)),'source_sha256':filehash,
                    'line_numbers':[e.line_number for e in observations], 'feature_schema_version':feature_schema['version'],
                    'schema_sha256':feature_schema['sha256'],'features':extract(observations,seconds,feature_schema['path_rules'])})
            runs.append({'run_id':run_id,'scenario':scenario,'label':label,'included':included,'label_basis':mapping['basis'],
                'capture_start':start.isoformat(),'capture_end':end.isoformat(),'actual_duration_seconds':(end-start).total_seconds(),
                'declared_duration_seconds':int(record['duration_seconds']),'duration_discrepancy':(end-start).total_seconds()!=int(record['duration_seconds']),
                'raw_lines':len(events)+len(failures),'parsed_events':len(events),'malformed_lines':failures,'outside_capture_events':len(outside),
                'excluded_dummy_events':len(dummy),'included_events':len(accepted),'windows':len(groups),'source_file':str(path.relative_to(project)),
                'source_sha256':filehash,'authenticated_user_observations':sum(e.authenticated_user_id is not None for e in accepted)})
    rows.sort(key=lambda r:(r['run_id'],r['window_start'],r['client_id'],r['user_agent_id']))
    return {'dataset_version':'2.0','evaluation_stage':'PROVISIONAL_DATASET_V2_EXISTING_CAPTURES','feature_schema':feature_schema,
        'label_manifest':labels,'sources':sources,'runs':runs,'rows':rows,'sufficiency':sufficiency(runs),
        'qa':{'leakage_check':'No duplicate run IDs, capture hashes, shared observations or overlapping capture intervals',
              'dummy_policy':'Exclude loopback OPTIONS * with Apache internal dummy connection UA; retain counts/hashes',
              'empty_windows':'not emitted; no invented idle observations', 'POST_bodies':'unavailable',
              'run_count':sum(r['included'] for r in runs),'window_count':len(rows)}}
