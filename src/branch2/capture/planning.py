"""Deterministic class protocols, budgets and a full 68-run schedule."""
import hashlib
import json
import random
from pathlib import Path
from urllib.parse import urlencode, quote

VERSION='branch2-lab-generator-2.0'
TARGET='http://192.168.226.132/moodle/'
WORKER='192.168.226.129'
COUNTS={'BENIGN':5,'BRUTE_FORCE':7,'ENUMERATION_RECONNAISSANCE':8,'ADMIN_PROBING':10,
        'REQUEST_BURST_DOS_LIKE':8,'SQLI_ATTEMPT':10,'XSS_ATTEMPT':10,'PATH_TRAVERSAL_ATTEMPT':10}
SCENARIOS={'BRUTE_FORCE':('S01',4),'ENUMERATION_RECONNAISSANCE':('S02',3),'ADMIN_PROBING':('AP01',1),
 'REQUEST_BURST_DOS_LIKE':('RB01',1),'SQLI_ATTEMPT':('SQ01',1),'XSS_ATTEMPT':('XS01',1),'PATH_TRAVERSAL_ATTEMPT':('PT01',1)}


def sha(value): return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def source_files():
    directory=Path(__file__).resolve().parent
    return {**{'capture/'+p.name:p for p in directory.glob('*.py')},
            'run_branch2_capture.py':directory.parents[2]/'scripts/run_branch2_capture.py'}


def source_hashes():return {name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in sorted(source_files().items())}


def schedule(context, seed=42, counts=None, run_offset=0, only_run_id=None):
    if context['target']!=TARGET or context['worker_ip']!=WORKER: raise ValueError('Exact authorized lab target/worker required')
    if isinstance(run_offset,bool) or not isinstance(run_offset,int) or not 0<=run_offset<=60:raise ValueError('Run offset must be an integer in [0,60]')
    requested=dict(COUNTS)
    if counts is not None:
        if set(counts)!=set(COUNTS): raise ValueError('Explicit count required for every class')
        requested=counts
    if any(isinstance(n,bool) or not isinstance(n,int) or not 0<=n<=30 for n in requested.values()): raise ValueError('Class counts must be bounded integers')
    descriptors=[]
    benign=[('BN02',1,'resource'),('BN02',2,'mixed'),('B04',1,'admin_navigation'),('B04',2,'admin_navigation'),('B04',3,'admin_navigation')]
    for label,count in requested.items():
        for i in range(count):
            if label=='BENIGN': scenario,number,variant=benign[i] if i<len(benign) else ('BN02',i+1,'mixed')
            else: scenario,first=SCENARIOS[label];number=first+i;variant=('low','medium','high')[i%3]
            number+=run_offset
            if number>99:raise ValueError('Run number exceeds supported bound')
            run_id=f'{scenario}-run{number:02d}'
            run_seed=int(hashlib.sha256(f'{seed}:{run_id}'.encode()).hexdigest()[:8],16)
            descriptors.append(protocol(context,label,scenario,number,variant,run_seed))
    rng=random.Random(seed);rng.shuffle(descriptors)
    if only_run_id is not None:
        descriptors=[run for run in descriptors if run['run_id']==only_run_id]
        if len(descriptors)!=1:raise ValueError('Selected run ID must exist in the generated schedule')
        requested=dict.fromkeys(COUNTS,0)
        requested[descriptors[0]['label']]=1
    offset=0
    for run in descriptors:
        run['planned_start_offset_seconds']=offset
        run['planned_end_offset_seconds']=offset+run['duration_seconds']
        offset+=run['duration_seconds']+4
    result={'version':VERSION,'seed':seed,'run_offset':run_offset,'target':TARGET,'worker_ip':WORKER,'target_additional_counts':COUNTS,
        'requested_counts':requested,'target_reduced':requested!=COUNTS,'context':context,'context_sha256':sha(context),
        'generator_files_sha256':source_hashes(),'runs':descriptors,'estimated_requests':sum(r['planned_request_count'] for r in descriptors),
        'estimated_duration_seconds':offset,'duration_note':'Nominal HTTP schedule plus 4-second flush/cooldown per run; SSH/login latency may extend; fails at bounded worker deadline'}
    if only_run_id is not None:result['only_run_id']=only_run_id
    result['schedule_sha256']=sha(result)
    return result


def protocol(context,label,scenario,number,variant,seed):
    rng=random.Random(seed)
    duration=44; steps=[]; auth=None
    root=TARGET
    if label=='BENIGN':
        auth='administrator' if variant=='admin_navigation' else None
        pool=context['admin_navigation'] if auth else context['benign_'+variant]
        count=rng.choice([18,20,22]);rng.shuffle(pool:=list(pool))
        urls=[pool[i%len(pool)] for i in range(count)]
    elif label=='BRUTE_FORCE':
        attempts=rng.choice([5,6,7]);urls=[TARGET+'login/index.php']*attempts
    elif label in {'ENUMERATION_RECONNAISSANCE','ADMIN_PROBING'}:
        known=list(context['enumeration'] if label=='ENUMERATION_RECONNAISSANCE' else context['admin_probing'])
        rng.shuffle(known)
        missing=[TARGET+('admin/' if label=='ADMIN_PROBING' else '')+f'b2-lab-missing-{seed:x}-{i}.php' for i in range(rng.choice([3,5,7]))]
        pool=known+missing;rng.shuffle(pool)
        count=rng.choice([18,20,22]);urls=[pool[i%len(pool)] for i in range(count)]
    elif label=='REQUEST_BURST_DOS_LIKE':
        rate={'low':.75,'medium':1.25,'high':2.0}[variant]
        count={'low':18,'medium':24,'high':30}[variant]
        urls=[rng.choice(context['burst']) for _ in range(count)]
    else:
        count=rng.choice([18,20,22]);urls=[]
        for i in range(count):
            marker=f'b2-marker-{seed:x}-{i}'
            if label=='SQLI_ATTEMPT': value=rng.choice([f"{marker}' SELECT note --",f'{marker}" UNION note /* inert */',f'{marker} SELECT lesson --'])
            elif label=='XSS_ATTEMPT': value=rng.choice([f'<svg data-b2="{marker}"></svg>',f'<b2-marker title="{marker}">',f'" data-b2="{marker}" <svg>'])
            else: value='../'*rng.choice([1,2,3])+f'b2-fictitious-{marker}.txt'
            parameter=rng.choice(['b2_lab_q','b2_lab_input','b2_lab_filter'])
            encoded=quote(value,safe='')
            style=rng.choice(['single','double','literal_delimiters'])
            if style=='double': encoded=quote(encoded,safe='')
            elif style=='literal_delimiters': encoded=quote(value,safe="<>/'\"")
            urls.append(root+'?'+parameter+'='+encoded+'&b2_lab_note=lesson'+str(i%3))
    if label=='BRUTE_FORCE':
        for i,url in enumerate(urls):
            steps.append({'at_seconds':2+i*36/max(len(urls)-1,1),'operation':'failed_login','url':url,
                'identity':f'b2lab-fictitious-{seed:x}-{i%3}', 'identity_semantics':'unprovisioned/fictitious identities only'})
        count=len(urls)*2 # GET token + single POST; no redirects/retries.
    else:
        for i,url in enumerate(urls):
            if label=='REQUEST_BURST_DOS_LIKE':
                half=(len(urls)+1)//2
                at=2+(i if i<half else i-half)/rate+(0 if i<half else 24)
            else: at=2+i*38/max(len(urls)-1,1)+rng.uniform(-.15,.15)
            steps.append({'at_seconds':round(at,4),'operation':'get','url':url})
        count=len(urls)
    minimum=count+4 if auth else count
    if auth: count+=7 # upper bound: login GET/POST, up to four GET redirects, identity GET
    return {'run_id':f'{scenario}-run{number:02d}','scenario_id':scenario,'run_number':number,'label':label,'seed':seed,
        'variant':variant,'auth_role':auth,'generator_version':VERSION,'duration_seconds':duration,
        'planned_request_count':count,'maximum_request_count':count,'parameter_profile':{'variant':variant,'seed':seed,
            'burst_rate':rate if label=='REQUEST_BURST_DOS_LIKE' else None,'concurrency':1,'jitter_bound_seconds':.15,
            'requested_average_requests_per_second':round(count/duration,6)},
        'minimum_request_count':minimum,'steps':steps,'user_agent':f'Branch2-Lab/2.0 run={scenario}-run{number:02d}',
        'label_semantics':'Controlled traffic class, not successful exploitation or availability impact'}
