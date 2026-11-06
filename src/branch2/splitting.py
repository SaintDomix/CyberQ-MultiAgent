"""Seeded, scenario-stratified complete-run holdout; adjacent windows never split."""
from collections import defaultdict
import random


def split_runs(dataset, seed=42, test_fraction=.3):
    if not 0 < test_fraction < 1: raise ValueError('Holdout fraction must be between zero and one')
    grouped=defaultdict(list)
    for run in dataset['runs']:
        if run['included'] and run['windows']:
            grouped[(run['label'],run['scenario'])].append(run['run_id'])
    train=[];test=[];unassigned=[]
    rng=random.Random(seed)
    for key,ids in sorted(grouped.items()):
        ids=sorted(ids);rng.shuffle(ids)
        if len(ids)<2:
            # Do not silently turn a singleton into either a valid train/test class.
            unassigned.extend(ids);continue
        n=max(1,min(len(ids)-1,round(len(ids)*test_fraction)))
        test.extend(ids[:n]);train.extend(ids[n:])
    if set(train)&set(test): raise ValueError('Run leakage')
    if not train or not test: raise ValueError('Independent held-out runs unavailable')
    return {'seed':seed,'test_fraction':test_fraction,'unit':'complete captured run',
        'stratification':'label and scenario; singleton strata excluded',
        'train_runs':sorted(train),'test_runs':sorted(test),'unassigned_runs':sorted(unassigned),
        'eligible_xgb_classes':sorted(c for c,v in dataset['sufficiency'].items() if v['provisional_eligible']
            and any(r['run_id'] in train and r['label']==c for r in dataset['runs'])
            and any(r['run_id'] in test and r['label']==c for r in dataset['runs']))}


def partition(rows,manifest):
    train=set(manifest['train_runs']);test=set(manifest['test_runs'])
    if train&test: raise ValueError('Run leakage')
    return ([r for r in rows if r['run_id'] in train],[r for r in rows if r['run_id'] in test])


def split_final_runs(dataset, seed=42):
    """M2C exact quotas, scenario-diverse seeded allocation; fail closed on leakage."""
    from collections import Counter
    from itertools import combinations
    from .dataset import CLASSES
    from .events import utc
    runs=dataset['runs'];rows=dataset['rows']
    if len({r['run_id'] for r in runs})!=len(runs):raise ValueError('Duplicate run ID')
    included={r['run_id']:r for r in runs if r['included'] and r['windows']>0}
    if any(r['run_id'].startswith('TEST-') or r['label'] not in CLASSES for r in included.values()):
        raise ValueError('Smoke test/unknown class cannot participate')
    if any(r['included'] and not r['windows'] for r in runs):raise ValueError('Included run has no usable windows')
    counts=Counter(r['label'] for r in included.values())
    expected={c:12 if c=='BENIGN' else 10 for c in CLASSES}
    if counts!=expected:raise ValueError('Final protocol requires 12 BENIGN and 10 runs per attack class')
    seen_hashes=set();seen_files=set();intervals=[]
    for r in included.values():
        if r['source_sha256'] in seen_hashes or r['source_file'] in seen_files:raise ValueError('Capture/source overlap')
        seen_hashes.add(r['source_sha256']);seen_files.add(r['source_file'])
        start,end=utc(r['capture_start']),utc(r['capture_end'])
        if end<=start or any(start<b and a<end for a,b in intervals):raise ValueError('Capture interval overlap')
        intervals.append((start,end))
    row_counts=Counter();observations=set();window_keys=set()
    for row in rows:
        r=included.get(row['run_id'])
        if r is None or any(row[k]!=r[k] for k in ('label','scenario','source_file','source_sha256')):
            raise ValueError('Excluded/mismatched run window')
        key=tuple(row.get(k) for k in ('run_id','window_start','window_end','client_id','user_agent_id'))
        if key in window_keys:raise ValueError('Duplicate window')
        window_keys.add(key);row_counts[r['run_id']]+=1
        if not row['line_numbers']:raise ValueError('Missing observation provenance')
        for line in row['line_numbers']:
            observation=(row['source_sha256'],line)
            if observation in observations:raise ValueError('Shared source observation')
            observations.add(observation)
    if any(row_counts[rid]!=r['windows'] for rid,r in included.items()):raise ValueError('Window inventory mismatch')
    rng=random.Random(seed);names=('train','validation','test');assigned={p:[] for p in names}
    for label in sorted(CLASSES):
        quotas={'train':8 if label=='BENIGN' else 6,'validation':2,'test':2}
        groups=defaultdict(list)
        for r in included.values():
            if r['label']==label:groups[r['scenario']].append(r['run_id'])
        used=Counter();scenario_counts={p:Counter() for p in names}
        for scenario,ids in sorted(groups.items(),key=lambda pair:(len(pair[1]),pair[0])):
            ids=sorted(ids);rng.shuffle(ids)
            for rid in ids:
                choices=[p for p in names if used[p]<quotas[p]];rng.shuffle(choices)
                choice=min(choices,key=lambda p:(scenario_counts[p][scenario],used[p]/quotas[p]))
                assigned[choice].append(rid);used[choice]+=1;scenario_counts[choice][scenario]+=1
    checks={f'{a}_{b}_run_overlap':sorted(set(assigned[a])&set(assigned[b])) for a,b in combinations(names,2)}
    if any(checks.values()):raise ValueError('Partition leakage')
    manifest={'version':'m2c-run-split-1.0','seed':seed,'unit':'complete independent experimental run',
        'algorithm':'label quotas; rare scenarios first; seeded ID shuffle; least scenario occupancy then quota fill ratio; seeded tie order',
        'allocation':{'BENIGN':[8,2,2],'each_attack':[6,2,2]},
        'excluded_run_ids':sorted(r['run_id'] for r in runs if r['run_id'] not in included),
        'overlap_checks':{**checks,'unique_capture_hashes':True,'unique_source_files':True,'unique_source_observations':True,'nonoverlapping_capture_intervals':True},
        'eligible_xgb_classes':sorted(CLASSES),'partitions':{}}
    for name in names:
        ids=sorted(assigned[name]);inventory=[included[rid] for rid in ids]
        manifest[name+'_runs']=ids
        manifest['partitions'][name]={'run_count':len(ids),'window_count':sum(row_counts[rid] for rid in ids),
            'class_counts':dict(sorted(Counter(r['label'] for r in inventory).items())),
            'scenario_counts':dict(sorted(Counter(r['scenario'] for r in inventory).items())),
            'class_window_counts':dict(sorted(Counter(row['label'] for row in rows if row['run_id'] in ids).items())),
            'runs':inventory}
        if set(manifest['partitions'][name]['class_counts'])!=set(CLASSES):raise ValueError('Class missing from partition')
    return manifest


def partition_final(rows, manifest):
    names=('train','validation','test');sets=[set(manifest[p+'_runs']) for p in names]
    if any(sets[i]&sets[j] for i in range(3) for j in range(i)):raise ValueError('Partition run overlap')
    if any(sum(row['run_id'] in ids for ids in sets)!=1 for row in rows):raise ValueError('Unassigned or multiply assigned row')
    return tuple([row for row in rows if row['run_id'] in ids] for ids in sets)
