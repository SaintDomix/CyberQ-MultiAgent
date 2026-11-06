"""Strict capture QA gate, before import/build/model training."""
import json
from pathlib import Path
from urllib.parse import urlsplit, unquote
from collections import Counter
from ..adapters.apache import read_log
from ..events import utc,identifier
from ..windowing import windows
from .planning import WORKER, sha
from .safety import validate_schedule,validate_result,normalized


def verify(root):
    root=Path(root);plan=json.loads((root/'schedule.json').read_text());validate_schedule(plan)
    errors=[];runs=[];seen=set();intervals=[];counts=Counter()
    import hashlib
    for name,digest in plan['generator_files_sha256'].items():
        path=root/'generator_source'/name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:errors.append('Archived generator source hash mismatch')
    expected={r['run_id']:r for r in plan['runs']}
    found={p.parent.name for p in root.glob('*/manifest.json')}
    if found!=set(expected):errors.append('Missing/extra run manifests')
    if (root/'active.json').exists():errors.append('Unfinished active capture')
    for run_id,run in expected.items():
        try:
            directory=root/run_id
            m=json.loads((directory/'manifest.json').read_text())
            import hashlib
            if hashlib.sha256((directory/'manifest.json').read_bytes()).hexdigest()!=(directory/'manifest.sha256').read_text().strip():raise ValueError('Manifest hash mismatch')
            if m['run_id']!=run_id or m['parameter_profile_sha256']!=sha(run):raise ValueError('Manifest run/profile mismatch')
            result=m['worker_result']
            validate_result(result,run,plan['context'])
            if result['run_id']!=run_id or result['label']!=run['label'] or result['status']!='COMPLETE' or result['actor_ip']!=WORKER:raise ValueError('Incomplete worker or wrong identity/class')
            if not run['minimum_request_count']<=result['actual_request_count']<=run['maximum_request_count'] or len(result['requests'])!=result['actual_request_count']:raise ValueError('Incomplete request accounting')
            if any('error' in r for r in result['requests']):raise ValueError('Worker request errors')
            start,end=utc(m['start_utc']),utc(m['end_utc'])
            if end<=start or utc(m['actual_end_precise_utc'])<=utc(m['actual_start_precise_utc']):raise ValueError('Invalid capture boundary')
            if (end-start).total_seconds()>run['duration_seconds']+25:raise ValueError('Unbounded run duration')
            if any(start<b and a<end for a,b in intervals):raise ValueError('Capture intervals overlap')
            intervals.append((start,end))
            if m['offset_end']<m['offset_start'] or m['access_file']!='access.log':raise ValueError('Invalid byte offsets/path')
            events,malformed,digest=read_log(directory/'access.log')
            if digest!=m['access_sha256'] or (directory/'access.log').stat().st_size!=m['offset_end']-m['offset_start']:raise ValueError('Capture hash/size mismatch')
            if digest in seen:raise ValueError('Duplicate capture file')
            seen.add(digest)
            if not events or malformed:raise ValueError('Empty/malformed Apache slice')
            if any(e.infrastructure_dummy or e.client_id!=identifier(WORKER) or e.user_agent!=run['user_agent'] or not start<=e.timestamp<end for e in events):raise ValueError('Dummy/foreign-client/foreign-UA/outside-boundary contamination')
            expected_requests=Counter((r['method'],normalized(r['url'])) for r in result['requests'])
            actual_requests=Counter((e.method,normalized('http://lab'+e.path+('?' +e.query if e.query else ''))) for e in events)
            if expected_requests!=actual_requests:raise ValueError('Apache request set/count differs from worker accounting')
            if len(events)!=result['actual_request_count']:raise ValueError('Unexpected Apache request count')
            count_windows=len(list(windows(events)))
            if count_windows<1:raise ValueError('No usable Dataset v2 window')
            if len({e.timestamp.timestamp()//10 for e in events})<2:raise ValueError('Protocol compressed into fewer than two temporal windows')
            counts[run['label']]+=1
            runs.append({'run_id':run_id,'label':run['label'],'events':len(events),'windows':count_windows,'source_sha256':digest})
        except (ValueError,KeyError,OSError,TypeError) as exc:
            # Fixed descriptions only; no secret or raw server content in errors.
            errors.append({'run_id':run_id,'reason':str(exc) if isinstance(exc,ValueError) else 'Missing/invalid capture artifact'})
    counts={label:counts[label] for label in plan['requested_counts']}
    if counts!=plan['requested_counts']:errors.append('Verified class counts differ from schedule')
    return {'verified':not errors,'schedule_sha256':plan['schedule_sha256'],'expected_runs':len(expected),
        'verified_runs':len(runs),'class_counts':counts,'runs':runs,'errors':errors,
        'dummy_policy':'Strictly reject contaminated captures; never silently remove captured traffic'}
