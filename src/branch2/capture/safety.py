"""Independent lab-generator limits; exact origin, finite sequential requests."""
import re
from urllib.parse import urlsplit, parse_qsl, unquote
from .planning import TARGET, WORKER, VERSION, COUNTS, sha

READ_ONLY_PATHS={'/moodle/','/moodle/index.php','/moodle/login/index.php','/moodle/course/index.php',
 '/moodle/course/view.php','/moodle/mod/resource/view.php','/moodle/mod/quiz/view.php','/moodle/my/',
 '/moodle/admin/','/moodle/admin/index.php','/moodle/report/security/index.php','/moodle/user/profile.php',
 '/moodle/pix/moodlelogo.svg','/moodle/pix/moodlelogo.png','/moodle/pix/i/course.svg','/moodle/pix/i/folder.svg','/moodle/pix/i/home.svg'}


def normalized(url):
    p=urlsplit(url)
    return unquote(p.path),unquote(p.query)


def check_url(url, context, synthetic=False):
    parts=urlsplit(url);base=urlsplit(TARGET)
    if (parts.scheme,parts.netloc)!=(base.scheme,base.netloc) or parts.username or parts.password or parts.fragment:
        raise ValueError('Exact authorized Moodle origin required')
    if not parts.path.startswith('/moodle/') or re.search(r'%2e|%2f|%5c|\\|\.\.|logout|delete|edit|reset|enrol|install|upgrade|submit',parts.path,re.I):
        raise ValueError('Unsafe route')
    pairs=parse_qsl(parts.query,keep_blank_values=True)
    missing=bool(re.fullmatch(r'/moodle/(?:admin/)?b2-lab-missing-[a-f0-9]+-\d+\.php',parts.path))
    if parts.path not in READ_ONLY_PATHS and not missing:raise ValueError('Endpoint lacks reviewed read-only route support')
    if any(re.search(r'password|token|sesskey|cookie|secret|username|email|action|confirm|redirect|setdefaulthome',k,re.I) for k,v in pairs):
        raise ValueError('Secret/mutation parameter prohibited')
    if synthetic:
        if parts.path!='/moodle/' or any(not k.startswith('b2_lab_') for k,v in pairs): raise ValueError('Markers only in ignored lab query context')
    elif url not in {u for key in ('benign_resource','benign_mixed','admin_navigation','enumeration','admin_probing','burst') for u in context[key]} and not re.fullmatch(r'/moodle/(?:admin/)?b2-lab-missing-[a-f0-9]+-\d+\.php',parts.path) and url!=TARGET+'login/index.php' and not (parts.path=='/moodle/login/index.php' and re.fullmatch(r'testsession=\d+',parts.query)):
        raise ValueError('URL lacks explicit reviewed context')


def validate_context(context):
    if context['target']!=TARGET or context['worker_ip']!=WORKER: raise ValueError('Wrong lab scope')
    allowed={'target','worker_ip','benign_resource','benign_mixed','admin_navigation','enumeration','admin_probing','burst','identity_markers','fictitious_identity_namespace_reserved','source_basis'}
    if set(context)!=allowed:raise ValueError('Only non-secret reviewed context fields are permitted')
    for key in ('benign_resource','benign_mixed','admin_navigation','enumeration','admin_probing','burst'):
        if not isinstance(context[key],list) or not context[key]: raise ValueError('Nonempty explicit endpoint lists required')
        for url in context[key]: check_url(url,context)
    if context['identity_markers']['administrator']==context['identity_markers']['student']: raise ValueError('Distinct role identity markers required')
    # Runtime templates carry references/markers only, never credential values.
    def reject(value):
        if isinstance(value,dict):
            for k,v in value.items():
                if re.search(r'password|cookie|token|secret|credential',k,re.I): raise ValueError('Secret values prohibited in context')
                reject(v)
        elif isinstance(value,list):
            for v in value: reject(v)
    reject(context)
    if context.get('fictitious_identity_namespace_reserved') is not True:raise ValueError('Reserved non-account identity namespace must be attested')


def validate_schedule(plan):
    validate_context(plan['context'])
    data=dict(plan);digest=data.pop('schedule_sha256')
    if sha(data)!=digest or sha(plan['context'])!=plan['context_sha256']: raise ValueError('Schedule hash mismatch')
    if plan['version']!=VERSION or plan['target']!=TARGET or plan['worker_ip']!=WORKER: raise ValueError('Scope/version mismatch')
    if plan['target_reduced']!=(plan['requested_counts']!=COUNTS):raise ValueError('Partial-plan flag mismatch')
    ids=set();counts=dict.fromkeys(COUNTS,0)
    for run in plan['runs']:
        validate_run(run,plan['context'])
        if run['run_id'] in ids: raise ValueError('Duplicate run ID')
        ids.add(run['run_id']);counts[run['label']]+=1
    if counts!=plan['requested_counts'] or plan['target_additional_counts']!=COUNTS: raise ValueError('Class counts mismatch')


def validate_run(run,context):
    if run['generator_version']!=VERSION or run['label'] not in COUNTS: raise ValueError('Invalid generator/class')
    if not re.fullmatch(r'[A-Z0-9]+-run\d{2}',run['run_id']) or run['run_id']!=f"{run['scenario_id']}-run{run['run_number']:02d}": raise ValueError('Invalid run identity')
    if run['user_agent']!=f"Branch2-Lab/2.0 run={run['run_id']}":raise ValueError('Exact non-secret run correlation UA required')
    if not 40<=run['duration_seconds']<=60 or not 1<=run['maximum_request_count']<=40 or run['maximum_request_count']!=run['planned_request_count']: raise ValueError('Bounded duration/request count required')
    if run['parameter_profile']['concurrency']!=1: raise ValueError('Sequential requests required')
    if run['parameter_profile']['burst_rate'] is not None and not 0<run['parameter_profile']['burst_rate']<=2: raise ValueError('Burst maximum exceeded')
    if run['auth_role'] not in {None,'administrator'} or (run['auth_role'] and run['label']!='BENIGN'): raise ValueError('Authentication restricted to benign navigation')
    times=[];count=7 if run['auth_role'] else 0
    synthetic=run['label'] in {'SQLI_ATTEMPT','XSS_ATTEMPT','PATH_TRAVERSAL_ATTEMPT'}
    for step in run['steps']:
        if not 0<=step['at_seconds']<run['duration_seconds']: raise ValueError('Invalid planned time')
        times.append(step['at_seconds']);check_url(step['url'],context,synthetic)
        if step['operation']=='failed_login':
            if run['label']!='BRUTE_FORCE' or step['url']!=TARGET+'login/index.php' or not re.fullmatch(r'b2lab-fictitious-[a-f0-9]+-[0-2]',step['identity']): raise ValueError('Fictitious login identities only')
            count+=2
        elif step['operation']=='get': count+=1
        else: raise ValueError('Unsupported operation')
        decoded=unquote(unquote(step['url']))
        if synthetic and re.search(r';|\b(?:drop|insert|update|delete|sleep|benchmark|information_schema)\b',decoded,re.I): raise ValueError('Unsafe query marker')
        if run['label']=='XSS_ATTEMPT' and re.search(r'script|javascript|onerror|onload|onclick',decoded,re.I): raise ValueError('Executable XSS payload prohibited')
        if run['label']=='PATH_TRAVERSAL_ATTEMPT' and ('b2-fictitious-' not in decoded or not re.search(r'\.\./',decoded) or re.search(r'etc|passwd|shadow|metadata',decoded,re.I)): raise ValueError('Fictitious traversal targets only')
    if times!=sorted(times) or count!=run['planned_request_count']: raise ValueError('Schedule ordering/budget mismatch')
    if run['minimum_request_count']!=count-(3 if run['auth_role'] else 0):raise ValueError('Invalid minimum request count')
    if any(b-a<.5 for a,b in zip(times,times[1:])): raise ValueError('Maximum two operations/second')


def validate_result(result,run,context):
    allowed={'run_id','label','status','requests','error','actual_request_count','elapsed_seconds','achieved_request_rate','achieved_peak_requests_per_second','actor_ip','peak_limit_requests_per_second','concurrency'}
    if set(result)-allowed or result['run_id']!=run['run_id'] or result['label']!=run['label'] or result['actor_ip']!=WORKER:
        raise ValueError('Invalid/non-secret worker result schema')
    unknown=result['status']=='FAILED' and result.get('error')=='WORKER_ABORTED' and result['actual_request_count'] is None and not result['requests']
    if result['status'] not in {'COMPLETE','FAILED'} or not unknown and (len(result['requests'])!=result['actual_request_count'] or result['actual_request_count']>run['maximum_request_count']):raise ValueError('Worker accounting mismatch')
    for i,record in enumerate(result['requests'],1):
        if set(record)-{'request_index','method','url','elapsed_seconds','status','response_bytes_observed','error'} or record['request_index']!=i:raise ValueError('Request evidence schema invalid')
        check_url(record['url'],context,run['label'] in {'SQLI_ATTEMPT','XSS_ATTEMPT','PATH_TRAVERSAL_ATTEMPT'})
        if record['method'] not in {'GET','POST'} or record['method']=='POST' and record['url']!=TARGET+'login/index.php':raise ValueError('Unsafe result method')
    if any(r.get('error') not in {None,'BOUNDED_REQUEST_FAILURE'} for r in result['requests']) or result.get('error') not in {None,'WORKER_ABORTED','PROTOCOL_OR_BOUNDED_HTTP_FAILURE'}:raise ValueError('Unredacted error values prohibited')
    if result['status']=='COMPLETE':
        records=result['requests']
        actual=[(r['method'],normalized(r['url'])) for r in records]
        expected=[]
        for step in run['steps']:
            expected.extend([('GET',normalized(step['url'])),('POST',normalized(step['url']))] if step['operation']=='failed_login' else [('GET',normalized(step['url']))])
        if run['auth_role']:
            prefix=actual[:-len(expected)]
            if not 4<=len(prefix)<=7 or [m for m,u in prefix].count('POST')!=1:raise ValueError('Unexpected authentication prefix')
            actual=actual[-len(expected):]
        if actual!=expected:raise ValueError('Worker sequence differs from planned controlled protocol')
