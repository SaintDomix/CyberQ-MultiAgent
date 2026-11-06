"""Authoritative capture reconstruction and explicit external-holdout isolation."""
from collections import Counter
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from branch2.adapters.apache import read_log, parse_line
from branch2.events import utc
from branch2.features import extract as base_extract
from branch2.splitting import split_final_runs
from .schema import extract, schema


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    with Path(path).open('x', encoding='utf8') as f:
        json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)
        f.write('\n')


def new_dir(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=False)
    return path


def rebuild(v1, root):
    """Reconstruct precisely the original window observations, verifying base features."""
    split = split_final_runs(v1, 42)
    cache = {}
    for run in v1['runs']:
        if not run['included']: continue
        path = Path(root)/run['source_file']
        events, errors, digest = read_log(path, run['source_file'])
        if digest != run['source_sha256'] or errors:
            raise ValueError('Authoritative capture hash/parse failure')
        cache[run['run_id']] = {e.line_number: e for e in events}
    rows = []
    for row in v1['rows']:
        events = [cache[row['run_id']][n] for n in row['line_numbers']]
        if any(e.infrastructure_dummy or not utc(row['window_start']) <= e.timestamp < utc(row['window_end']) for e in events):
            raise ValueError('Window observation mismatch')
        if base_extract(events) != row['features']:
            raise ValueError('v1 feature replay mismatch')
        rows.append({**row, 'features': extract(events), 'schema_sha256': schema()['sha256'],
                     'feature_schema_version': schema()['version']})
    result = {**v1, 'dataset_version': '3.0', 'evaluation_stage': 'M5_PAIRED_REANALYSIS_NOT_NEW_BLIND_TEST',
              'feature_schema': schema(), 'rows': rows,
              'external_holdout': 'runtime observations excluded; no inferred benign labels'}
    return result, split, cache


def discover(root):
    choices = []
    for path in Path(root).glob('*/live_*/predictions.jsonl'):
        rows = [json.loads(s) for s in path.read_text().splitlines() if s.strip()]
        if rows: choices.append((max(utc(r['emitted_at_utc']) for r in rows), str(path.parent)))
    if not choices: raise ValueError('No real live predictions found')
    return Path(max(choices)[1])


def external(session, *, source=None):
    """Only bounded hash-verified source records; no raw request material exported.

    No whole-log read, HTTP, tailing, or writes. Unrecoverable bytes fail closed.
    """
    session = Path(session)
    predictions = [json.loads(s) for s in (session/'predictions.jsonl').read_text().splitlines() if s.strip()]
    windows = {r['record_id']: r for r in (json.loads(s) for s in (session/'windows.jsonl').read_text().splitlines())}
    if not predictions: raise ValueError('Empty external holdout')
    paths = {p['source_path'] for p in predictions}
    if len(paths) != 1: raise ValueError('Ambiguous holdout source')
    path = Path(source or next(iter(paths)))
    rows = []; event_groups = {}; seen = set()
    with path.open('rb') as f:
        stat = path.stat()
        for p in predictions:
            w = windows[p['record_id']]; old = w['row']
            if stat.st_ino != p['source_inode'] or stat.st_dev != p['source_device']:
                raise ValueError('External authoritative source identity changed')
            events = []
            for item in w['source_byte_ranges']:
                start, end = item['start'], item['end']
                if start < 0 or not 0 < end-start <= 1048576 or (start, end) in seen:
                    raise ValueError('Invalid/shared holdout observation')
                seen.add((start, end)); f.seek(start); raw = f.read(end-start)
                if hashlib.sha256(raw).hexdigest() != item['sha256']:
                    raise ValueError('External source byte hash mismatch')
                event = parse_line(raw.decode('utf8'), p['source_file'], p['source_sha256'], start+1)
                if event.client_id != p['client_id'] or not utc(p['window_start']) <= event.timestamp < utc(p['window_end']):
                    raise ValueError('External window/client mismatch')
                events.append(event)
            if len(events) != p['observation_count'] or base_extract(events) != old['features']:
                raise ValueError('External v1 feature replay mismatch')
            row = {**old, 'label': None, 'scenario': None, 'record_id': p['record_id'],
                   'sequence': p['sequence'], 'features': extract(events),
                   'schema_sha256': schema()['sha256'], 'feature_schema_version': schema()['version'],
                   'partition': 'EXTERNAL_DIAGNOSTIC_HOLDOUT',
                   'source_byte_ranges': w['source_byte_ranges']}
            rows.append(row); event_groups[p['record_id']] = events
    return rows, predictions, event_groups


def validate_partitions(dataset, split, external_rows=()):
    names = ('train', 'validation', 'test')
    groups = [set(split[n+'_runs']) for n in names]
    if any(groups[i] & groups[j] for i in range(3) for j in range(i)):
        raise ValueError('Run leakage')
    if {r['run_id'] for r in external_rows} & set.union(*groups): raise ValueError('External run leaked')
    sources = {r['source_sha256'] for r in dataset['rows']}
    if sources & {r['source_sha256'] for r in external_rows}: raise ValueError('External capture leaked')
    result = []
    for n, ids in zip(names, groups):
        rows = [{**r, 'partition': n.upper()} for r in dataset['rows'] if r['run_id'] in ids]
        if not rows or any(r['run_id'].startswith('TEST-') for r in rows): raise ValueError('Invalid partition')
        result.append(rows)
    if sum(map(len, result)) != len(dataset['rows']): raise ValueError('Unassigned rows')
    return tuple(result)
