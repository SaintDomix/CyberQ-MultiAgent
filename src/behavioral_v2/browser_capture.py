"""Real-browser sessions and passive, byte-exact telemetry. No model invocation.

Playwright is imported only on authorized execution. Tests inject fixture pages;
no requests/curl fallback, HAR, screenshot, trace, cookie file or raw log export.
"""
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import re
import shutil
import time
from urllib.parse import urljoin,urlsplit,parse_qs,unquote
from branch2.adapters.apache import parse_line
from branch2.events import identifier
from branch2.windowing import windows
from branch2.features import extract as v1_extract, schema as v1_schema
from .platforms import MoodleBehaviorAdapter
from .features31 import extract,schema,query_context
from .data import write,sha

TARGET='http://192.168.226.132/moodle/'
PROTOCOLS={
    'BROWSER-B01':['login','dashboard','logout'],
    'BROWSER-B02':['login','dashboard','course','dashboard','logout'],
    'BROWSER-B03':['login','course','content','course','logout'],
    'BROWSER-B04':['login','profile','dashboard','logout'],
    'BROWSER-B05':['login','course','quiz','course','logout'],
    'BROWSER-B06':['one_wrong_login','login','dashboard','course','logout'],
    'BROWSER-B07':['login','dashboard','course','dashboard','course','dashboard','logout'],
    'BROWSER-B08':['login','dashboard','course','dashboard','logout'],
    'BROWSER-B09':['login','dashboard','dashboard_refresh','dashboard_refresh','logout'],
    'BROWSER-B10':['login','dashboard','logout','login','dashboard','logout'],
}
MAX_REQUESTS=2500
MAX_BYTES=16*1024*1024
MAX_BLOCKED_REQUEST_DIAGNOSTICS=100
ROLES=('student','teacher','admin')


class CaptureError(ValueError):
    """Messages are fixed codes, never interpolated browser/server content."""


def now():return datetime.now(timezone.utc).isoformat()


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def make_plan(seed=20261014,roles=('student',)):
    if not roles or len(set(roles))!=len(roles) or any(r not in ROLES for r in roles):raise CaptureError('INVALID_ROLE_PLAN')
    allocation={'TRAIN':list(PROTOCOLS)+['BROWSER-B07','BROWSER-B09'],
        'VALIDATION':['BROWSER-B01','BROWSER-B02','BROWSER-B06','BROWSER-B07','BROWSER-B08','BROWSER-B09'],
        'TEST':['BROWSER-B01','BROWSER-B02','BROWSER-B04','BROWSER-B06','BROWSER-B07','BROWSER-B09']}
    rng=random.Random(seed);sessions=[];index=0
    for partition,protocols in allocation.items():
        for protocol in protocols:
            index+=1
            sessions.append({'session_id':f'M5FD-{seed}-{index:03d}', 'partition':partition,'protocol':protocol,
                'role':roles[(index-1)%len(roles)],'role_availability':'OPERATOR_ACCOUNT_REQUIRED_NOT_ASSUMED',
                'seed':rng.randrange(2**32),'duration_seconds':120 if protocol!='BROWSER-B08' else 150,
                'cache_state':'FRESH_CONTEXT' if index%2 else 'WARM_PAGE_STATE',
                'cache_limitation':'Strict origin routing disables HTTP cache; warm means an additional counted dashboard visit, not disk cache.',
                'max_http_requests':MAX_REQUESTS,'model_result':None,'label':'BENIGN_PENDING_PROTOCOL_VERIFICATION'})
    rng.shuffle(sessions)
    value={'version':'m5-real-browser-plan-1.0','seed':seed,'target':TARGET,'sessions':sessions,
        'split_counts':dict(Counter(s['partition'] for s in sessions)),
        'estimated_browser_seconds':sum(s['duration_seconds']+15 for s in sessions),
        'independence':'fresh browser contexts/sessions, not independent users',
        'fresh_test_rule':'IDs reserved now; never moved to TRAIN; no model invocation during capture',
        'selection_policy':{'benign_validation_FPR_ceiling':.05,'FPR_grid':[.01,.02,.05,.10],
            'model_order':['IF','OCSVM','LOF'],'persistence_grid':[1,2,3],
            'objective':'within benign-window FPR ceiling: max validation attack recall; min benign any-alert run rate; shorter persistence; fixed simplicity tie order'},
        'attack_holdout':'new run IDs generated only after package freeze', 'network_requests_made':0}
    value['sha256']=digest(value);return value


def validate_plan(plan):
    if plan.get('version')!='m5-real-browser-plan-1.0' or plan.get('target')!=TARGET:
        raise CaptureError('UNAUTHORIZED_TARGET_OR_PLAN')
    if plan.get('sha256')!=digest({k:v for k,v in plan.items() if k!='sha256'}):raise CaptureError('PLAN_HASH_MISMATCH')
    ids=[s['session_id'] for s in plan['sessions']]
    if len(ids)!=24 or len(set(ids))!=24 or dict(Counter(s['partition'] for s in plan['sessions']))!={'TRAIN':12,'VALIDATION':6,'TEST':6}:
        raise CaptureError('RESERVED_SPLIT_MISMATCH')
    for s in plan['sessions']:
        if not re.fullmatch(r'M5FD-\d+-\d{3}',s['session_id']) or s['role'] not in ROLES or s['protocol'] not in PROTOCOLS:
            raise CaptureError('INVALID_SESSION_PROTOCOL')
        if s['max_http_requests']!=MAX_REQUESTS or not 90<=s['duration_seconds']<=180:
            raise CaptureError('SESSION_BOUND_EXCEEDED')
    return plan


def safe_url(url):
    try:
        p=urlsplit(url);t=urlsplit(TARGET);path=unquote(unquote(p.path))
        if (p.scheme,p.hostname,p.port or 80)!=(t.scheme,t.hostname,t.port or 80) or p.username or p.password:
            return False
        return (path==t.path.rstrip('/') or path.startswith(t.path)) and '\\' not in path and not any(segment in ('.','..') for segment in path.split('/'))
    except (ValueError,TypeError):return False


def readiness(role='student'):
    prefix='M5_'+role.upper()
    candidates=[shutil.which(n) for n in ('chromium','chromium-browser','google-chrome','google-chrome-stable')]
    project=Path(__file__).resolve().parents[2]
    bundled=sorted((project/'.tools/ms-playwright').glob('chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell'))
    executable=os.environ.get('M5_BROWSER_EXECUTABLE') or next((p for p in candidates if p),None) or (str(bundled[-1]) if bundled else None)
    return {'role':role,'credentials_present':bool(os.environ.get(prefix+'_USERNAME') and os.environ.get(prefix+'_PASSWORD')),
        'identity_marker_present':bool(os.environ.get(prefix+'_IDENTITY_MARKER')),
        'playwright_installed':importlib.util.find_spec('playwright') is not None,
        'browser_executable':executable,'browser_cache':str(project/'.tools/ms-playwright'),
        'local_library_path':str(project/'.tools/chromium-runtime/extracted/usr/lib/x86_64-linux-gnu'),
        'target_authorized':os.environ.get('M5_MOODLE_URL',TARGET)==TARGET}


def browser_environment(info):
    env={k:v for k,v in os.environ.items() if not re.search(r'PASSWORD|COOKIE|TOKEN|SECRET|SSLKEYLOG',k,re.I)}
    path=info['local_library_path']
    if Path(path).is_dir():env['LD_LIBRARY_PATH']=path
    return env


class Scope:
    def __init__(self,limit=MAX_REQUESTS,deadline=None):
        self.limit=limit;self.deadline=deadline;self.requests=0;self.error=None
        self.blocked_off_scope_requests_count=0;self.blocked_off_scope_requests=[]

    def record_blocked(self,request,navigation):
        """Diagnostics only: never retain queries, userinfo, bodies or arbitrary paths."""
        self.blocked_off_scope_requests_count+=1
        if len(self.blocked_off_scope_requests)>=MAX_BLOCKED_REQUEST_DIAGNOSTICS:return
        item={'scheme':None,'host':None,'path':None,'resource_type':'other',
            'is_navigation_request':navigation}
        try:
            p=urlsplit(request.url)
            if p.scheme in ('http','https'):
                item['scheme']=p.scheme
                if p.hostname and len(p.hostname)<=253 and re.fullmatch(r'[A-Za-z0-9.:-]+',p.hostname):
                    item['host']=p.hostname
                # Even URL path segments can carry credentials/tokens. Retain
                # only fixed technical paths; do not guess which others are safe.
                item['path']=p.path if p.path in ('/','/favicon.ico','/robots.txt') else '[REDACTED]'
            kind=request.resource_type
            if kind in ('document','stylesheet','image','media','font','script','texttrack',
                'xhr','fetch','eventsource','websocket','manifest','beacon','ping','cspreport','other'):
                item['resource_type']=kind
        except Exception:pass # Parsing failures must never export request/exception text.
        self.blocked_off_scope_requests.append(item)

    def audit(self):
        return {'blocked_off_scope_requests_count':self.blocked_off_scope_requests_count,
            'blocked_off_scope_requests':list(self.blocked_off_scope_requests),
            'blocked_off_scope_requests_omitted_count':self.blocked_off_scope_requests_count-len(self.blocked_off_scope_requests)}

    def route(self,route):
        r=route.request
        if self.error:route.abort();return
        if r.method not in ('GET','POST','HEAD'):self.error='UNEXPECTED_HTTP_METHOD'
        elif self.deadline is not None and time.monotonic()>self.deadline:self.error='SESSION_DEADLINE'
        elif self.requests>=self.limit:self.error='REQUEST_BUDGET'
        if self.error:route.abort();return
        if not safe_url(r.url):
            try:
                # Installed Playwright Request API: frame may not yet exist.
                # Treat every frame navigation conservatively, including popups.
                navigation=r.is_navigation_request()
                if type(navigation) is not bool:raise ValueError
            except Exception:
                self.error='REQUEST_CONTEXT_UNAVAILABLE';route.abort();return
            self.record_blocked(r,navigation)
            if navigation:self.error='OFF_SCOPE_NAVIGATION'
            route.abort();return
        self.requests+=1;route.continue_()


ATTRIBUTION_POLICY='capture-marker-and-actor-v1'


def attribute_slice(raw,path,start,started,ended,actor_id,marker,agent_sha256,policy):
    """Replay ownership from raw bytes. All record hashes survive exclusions."""
    if raw and not raw.endswith(b'\n'):raise CaptureError('INCOMPLETE_LOG_RECORD')
    lower=datetime.fromisoformat(started).replace(microsecond=0)
    upper=datetime.fromisoformat(ended).replace(microsecond=0)+timedelta(seconds=1)
    if lower>upper:raise CaptureError('INVALID_CAPTURE_INTERVAL')
    events=[];ranges=[];accepted=[];position=start;foreign=malformed=outside_time=0
    raw_hash=hashlib.sha256(raw).hexdigest()
    for line in raw.splitlines(keepends=True):
        item={'start':position,'end':position+len(line),'sha256':hashlib.sha256(line).hexdigest()}
        ranges.append(item)
        try:
            e=parse_line(line.decode('utf8'),str(path),raw_hash,position+1)
            in_time=lower<=e.timestamp<upper
            if not in_time:outside_time+=1
            ua=e.user_agent or ''
            marker_matches=marker is None or bool(ua.split() and ua.split()[-1]==marker)
            agent_matches=agent_sha256 is None or identifier(ua)==agent_sha256
            if e.client_id==actor_id and marker_matches and agent_matches and in_time and not e.infrastructure_dummy:
                events.append(e);accepted.append(item)
            else:foreign+=1
        except (ValueError,UnicodeError,OverflowError):malformed+=1
        position=item['end']
    metadata={'source_byte_ranges':ranges,'observed_records':len(ranges),
        'accepted_records':len(accepted),'accepted_source_byte_ranges':accepted,
        'foreign_records':foreign,'malformed_records':malformed,
        'outside_capture_time_records':outside_time,'ambient_traffic_present':bool(foreign),
        'attribution_policy':policy,'filtering_policy_version':policy,
        'ownership_filtering_enabled':True,'filtering_applied':bool(foreign or malformed),
        'session_marker':marker,'session_marker_sha256':identifier(marker),
        'expected_actor_id':actor_id,'expected_user_agent_sha256':agent_sha256,
        'dummy_filtering':True}
    # Keep candidate ownership provenance even when integrity forbids feature use.
    return ([] if malformed or outside_time else events),metadata


def validate_capture_attribution(provenance,session_id,actor_id):
    """Structural gate; authoritative source replay is performed by verify_capture."""
    p=provenance;marker='M5Capture/'+session_id
    if (p.get('attribution_policy')!=ATTRIBUTION_POLICY or p.get('filtering_policy_version')!=ATTRIBUTION_POLICY
        or p.get('session_marker')!=marker or p.get('session_marker_sha256')!=identifier(marker)
        or not actor_id or p.get('expected_actor_id')!=actor_id
        or not re.fullmatch(r'[0-9a-f]{64}',p.get('expected_user_agent_sha256') or '')
        or p.get('ownership_filtering_enabled') is not True):
        raise CaptureError('INVALID_CAPTURE_ATTRIBUTION')
    counts=[p.get(k) for k in ('accepted_records','foreign_records','malformed_records','observed_records')]
    if any(type(n) is not int or n<0 for n in counts):raise CaptureError('INVALID_CAPTURE_ATTRIBUTION')
    a,f,m,total=counts
    if (a<1 or a+f+m!=total or p.get('ambient_traffic_present')!=bool(f)
        or p.get('filtering_applied')!=bool(f or m)
        or len(p.get('source_byte_ranges',[]))!=total
        or len(p.get('accepted_source_byte_ranges',[]))!=a):
        raise CaptureError('INVALID_CAPTURE_ATTRIBUTION')
    raw_ranges=p['source_byte_ranges'];owned=p['accepted_source_byte_ranges']
    if [item for item in raw_ranges if item in owned]!=owned:
        raise CaptureError('INVALID_ACCEPTED_SOURCE_RANGES')


class LogBoundary:
    def __init__(self,path):
        self.path=Path(path)
        # Keep one descriptor; detect replacement/truncation before accepting.
        self.handle=self.path.open('rb');stat=os.fstat(self.handle.fileno())
        self.device,self.inode,self.start=stat.st_dev,stat.st_ino,stat.st_size
        self.started=now()

    def close(self,run_id,actor,agent):
        try:
            stat=self.path.stat();size=stat.st_size
            if (stat.st_dev,stat.st_ino)!=(self.device,self.inode) or size<self.start or size-self.start>MAX_BYTES:
                raise CaptureError('LOG_ROTATION_TRUNCATION_OR_BOUND')
            self.handle.seek(self.start);raw=self.handle.read(size-self.start)
        finally:self.handle.close()
        # Browser captures require both the session marker and exact in-memory
        # browser UA. Existing human/fixture callers retain their own UA contract.
        if agent.startswith('marker:'):
            marker=agent[7:];agent_hash=None;policy='human-marker-and-actor-v1'
        elif agent.split() and agent.split()[-1]=='M5Capture/'+run_id:
            marker='M5Capture/'+run_id;agent_hash=identifier(agent);policy=ATTRIBUTION_POLICY
        else:
            marker=None;agent_hash=identifier(agent);policy='exact-user-agent-and-actor-v1'
        ended=now()
        events,metadata=attribute_slice(raw,self.path,self.start,self.started,ended,
            identifier(actor),marker,agent_hash,policy)
        evidence={'source_path':str(self.path),'source_device':self.device,'source_inode':self.inode,
            'offset_start':self.start,'offset_end':size,'slice_sha256':hashlib.sha256(raw).hexdigest(),
            'start_utc':self.started,'end_utc':ended,'raw_log_persisted':False,**metadata}
        return events,evidence


class MoodleBrowserProtocol:
    """Read-only discovered routes; only intentional POST is credential login."""
    def __init__(self,page,role,seed,scope,credentials,marker):
        self.page=page;self.role=role;self.rng=random.Random(seed);self.scope=scope
        self.username,self.password=credentials;self.marker=marker;self.course=None;self.content=None;self.quiz=None
        self.identity_verified=False;self.actions=[]

    def navigate(self,url,action):
        if not safe_url(url):raise CaptureError('OFF_ORIGIN_NAVIGATION')
        response=self.page.goto(url,wait_until='domcontentloaded',timeout=20000)
        if self.scope.error:raise CaptureError(self.scope.error)
        if not safe_url(self.page.url) or response is None or response.status>=400:
            raise CaptureError('NAVIGATION_PROTOCOL_FAILURE')
        if action in ('course','content','quiz','profile') and urlsplit(self.page.url).path!=urlsplit(url).path:
            raise CaptureError('REQUIRED_RESOURCE_NOT_ACCESSIBLE')
        self.page.wait_for_timeout(1200)
        self.actions.append({'action':action,'completed_at_utc':now(),'status':response.status})

    def login(self,wrong=False):
        self.navigate(TARGET+'login/index.php','login_form')
        forms=self.page.locator('form');selected=[]
        for i in range(forms.count()):
            form=forms.nth(i);action=urljoin(self.page.url,form.get_attribute('action') or self.page.url)
            if (form.get_attribute('method') or 'get').lower()=='post' and action==TARGET+'login/index.php':
                if form.locator('input[name="username"]').count()==1 and form.locator('input[name="password"]').count()==1:
                    # Installed core/loginform has a separate guest protocol;
                    # reuse the accepted form-scoping distinction, not a global
                    # token count or an arbitrary "first form" selection.
                    if form.get_attribute('id')=='guestlogin' and all(form.locator('input[name="'+name+'"]').get_attribute('type')=='hidden' for name in ('username','password')):
                        continue
                    selected.append(form)
        if len(selected)!=1:raise CaptureError('AMBIGUOUS_LOGIN_FORM')
        form=selected[0];token=form.locator('input[name="logintoken"]')
        if token.count()!=1 or not (token.input_value() or '').strip():raise CaptureError('MISSING_LOGIN_STATE')
        form.locator('input[name="username"]').fill(self.username)
        invalid='M5-invalid-'+hashlib.sha256(str(self.rng.randrange(2**64)).encode()).hexdigest()[:24]
        if invalid==self.password:invalid+='x'
        form.locator('input[name="password"]').fill(invalid if wrong else self.password)
        form.locator('button[type="submit"],input[type="submit"]').first.click(timeout=20000)
        self.page.wait_for_load_state('domcontentloaded',timeout=20000)
        if self.scope.error or not safe_url(self.page.url):raise CaptureError(self.scope.error or 'OFF_ORIGIN_LOGIN')
        if wrong:
            if self.page.locator('#loginerrormessage,.loginerrors').count()<1:
                raise CaptureError('WRONG_LOGIN_NOT_OBSERVED')
            message=self.page.locator('#loginerrormessage,.loginerrors').first.inner_text().lower()
            if any(word in message for word in ('locked','lockout','too many','blocked')):
                raise CaptureError('ACCOUNT_LOCKOUT_WARNING')
            self.actions.append({'action':'one_incorrect_password','completed_at_utc':now(),'outcome':'EXPECTED_FAILURE'})
            return
        self.navigate(TARGET+'my/','verify_authenticated_dashboard')
        text=self.page.locator('body').inner_text(timeout=10000)
        logout=self.page.locator('a[href*="/login/logout.php"]')
        identity=self.marker in text if self.marker else False
        if self.marker and self.marker.startswith(TARGET):
            identity=self.marker in self.page.locator('a[href]').evaluate_all('(nodes)=>nodes.map(n=>n.href)')
        if not identity or logout.count()<1:
            raise CaptureError('AUTHENTICATED_IDENTITY_NOT_VERIFIED')
        self.identity_verified=True;self.discover_routes()

    def discover_routes(self):
        choices={'course':set(),'content':set(),'quiz':set()}
        for href in self.page.locator('a[href]').evaluate_all('(nodes)=>nodes.map(n=>n.href)'):
            if not safe_url(href):continue
            p=urlsplit(href)
            parameters=parse_qs(p.query);ids=parameters.get('id',[])
            if not ids or not ids[0].isdigit():continue
            if set(parameters)-{'id','section'} or any(not v.isdigit() for v in parameters.get('section',[])):continue
            if p.path=='/moodle/course/view.php':choices['course'].add(href)
            if p.path in ('/moodle/mod/resource/view.php','/moodle/mod/page/view.php'):choices['content'].add(href)
            if p.path=='/moodle/mod/quiz/view.php':choices['quiz'].add(href)
        for kind,urls in choices.items():
            if urls and getattr(self,kind) is None:setattr(self,kind,self.rng.choice(sorted(urls)))

    def run(self,session):
        started=time.monotonic();duration=session['duration_seconds']
        for action in PROTOCOLS[session['protocol']]:
            if self.scope.error:raise CaptureError(self.scope.error)
            if action=='login':self.login()
            elif action=='one_wrong_login':self.login(wrong=True)
            elif action=='logout':
                links=self.page.locator('a[href*="/login/logout.php"]')
                if links.count()<1:raise CaptureError('LOGOUT_CONTEXT_UNAVAILABLE')
                href=links.first.get_attribute('href');self.navigate(urljoin(self.page.url,href),'logout')
            elif action=='dashboard' or action=='dashboard_refresh':
                self.navigate(TARGET+'my/',action)
                if session['cache_state']=='WARM_PAGE_STATE':self.navigate(TARGET+'my/','counted_warm_page_visit')
            elif action=='profile':self.navigate(TARGET+'user/profile.php','profile')
            else:
                if self.course is None:
                    self.navigate(TARGET+'course/index.php','discover_course_listing');self.discover_routes()
                url=getattr(self,action,None)
                if not url:raise CaptureError('REQUIRED_RESOURCE_UNAVAILABLE')
                self.navigate(url,action);self.discover_routes()
            if action!='logout':
                # Spread navigation across several windows; variation is seeded.
                base=duration/max(len(PROTOCOLS[session['protocol']]),1)
                delay=min(base,self.rng.uniform(2,4) if session['protocol']=='BROWSER-B07' else self.rng.uniform(base*.65,base*1.1))
                if time.monotonic()-started+delay<duration:self.page.wait_for_timeout(delay*1000)
        remaining=duration-(time.monotonic()-started)
        if remaining>0:self.page.wait_for_timeout(remaining*1000)
        if not self.identity_verified:raise CaptureError('IDENTITY_UNVERIFIED')


def feature_rows(events,session,provenance):
    adapter=MoodleBehaviorAdapter();s=schema(adapter);rows=[];old=[]
    for w in windows(events):
        es=w.pop('events');base={**w,'run_id':session['session_id'],'scenario':session['protocol'],
            'label':'BENIGN','partition':session['partition'],'source_file':provenance['source_path'],
            'source_sha256':provenance['slice_sha256'],'line_numbers':[e.line_number for e in es]}
        rows.append({**base,'features':extract(es,adapter),'schema_sha256':s['sha256'],'feature_schema_version':s['version'],
            'query_context':query_context(es,adapter)})
        old.append({**base,'features':v1_extract(es),'schema_sha256':v1_schema()['sha256']})
    return rows,old


def capture(plan,session_id,out,*,authorized=False,actor='192.168.226.132',log=Path('/var/log/apache2/access.log'),browser_factory=None,freeze_path=None):
    validate_plan(plan)
    if not authorized:raise CaptureError('EXPLICIT_AUTHORIZATION_REQUIRED')
    session=next((s for s in plan['sessions'] if s['session_id']==session_id),None)
    if session is None:raise CaptureError('UNRESERVED_SESSION')
    if session['partition']=='TEST':
        if freeze_path is None:raise CaptureError('FROZEN_PACKAGE_REQUIRED_FOR_TEST_CAPTURE')
        from .study31 import verify_freeze
        frozen,_=verify_freeze(freeze_path)
        if frozen['capture_plan_sha256']!=plan['sha256'] or session_id not in frozen['reserved_fresh_test_ids']:
            raise CaptureError('FRESH_TEST_RESERVATIONS_CHANGED')
    prefix='M5_'+session['role'].upper();ready=readiness(session['role'])
    if not ready['target_authorized']:raise CaptureError('UNAUTHORIZED_TARGET')
    if not ready['credentials_present'] or not ready['identity_marker_present']:raise CaptureError('MISSING_CREDENTIALS_OR_IDENTITY_MARKER')
    if os.environ.get('DEBUG') or os.environ.get('PWDEBUG'):raise CaptureError('UNSAFE_DEBUG_ENVIRONMENT')
    out=Path(out)/session_id;out.mkdir(parents=True,exist_ok=False)
    boundary=None;context=None;browser=None;driver=None;scope=None;protocol=None;error=None;events=[];provenance={};actions=[]
    try:
        if browser_factory is None:
            from playwright.sync_api import sync_playwright
            os.environ.setdefault('PLAYWRIGHT_BROWSERS_PATH',ready['browser_cache'])
            driver=sync_playwright().start()
            browser=driver.chromium.launch(headless=True,executable_path=ready['browser_executable'],
                chromium_sandbox=True,env=browser_environment(ready),
                args=['--disable-background-networking','--disable-component-update','--disable-sync'])
        else:browser=browser_factory()
        probe=browser.new_context();p=probe.new_page();agent=p.evaluate('navigator.userAgent');probe.close()
        agent+=' M5Capture/'+session_id
        context=browser.new_context(user_agent=agent,service_workers='block',accept_downloads=False)
        scope=Scope(deadline=time.monotonic()+session['duration_seconds']+90)
        context.route('**/*',scope.route)
        if hasattr(context,'route_web_socket'):context.route_web_socket('**/*',lambda ws:ws.close())
        page=context.new_page();boundary=LogBoundary(log)
        protocol=MoodleBrowserProtocol(page,session['role'],session['seed'],scope,
            (os.environ[prefix+'_USERNAME'],os.environ[prefix+'_PASSWORD']),os.environ[prefix+'_IDENTITY_MARKER'])
        actions=protocol.actions;protocol.run(session)
        if not protocol.identity_verified:raise CaptureError('IDENTITY_UNVERIFIED')
        if scope.error:raise CaptureError(scope.error)
    except CaptureError as e:error=str(e)
    except Exception:error='BOUNDED_BROWSER_OR_TRANSPORT_FAILURE'
    finally:
        for resource in (context,browser,driver):
            if resource is not None:
                try:resource.stop() if resource is driver else resource.close()
                except Exception:error=error or 'BROWSER_CLEANUP_FAILURE'
        if boundary:
            try:events,provenance=boundary.close(session_id,actor,agent)
            except CaptureError as e:error=error or str(e)
            except OSError:error=error or 'LOG_READ_FAILURE'
    if provenance.get('malformed_records') or provenance.get('outside_capture_time_records'):error=error or 'CONTAMINATED_CAPTURE'
    if not events:error=error or 'NO_USABLE_OBSERVATIONS'
    manifest={'version':'m5-browser-capture-1.1','session_id':session_id,'plan_sha256':plan['sha256'],
        'partition':session['partition'],'protocol':session['protocol'],'declared_role':session['role'],
        'role_semantics':'configured authorized test account; no role inferred from Apache',
        'status':'INVALID' if error else 'COMPLETE','error_code':error,'provenance':provenance,
        'label':None if error else 'BENIGN','protocol_actions':actions,'seed':session['seed'],
        'authenticated_identity_verified':bool(protocol is not None and protocol.identity_verified),'actor_id':identifier(actor),
        'cache_state':session['cache_state'],'cache_limitation':session['cache_limitation'],
        'secrets_persisted':False,'model_invoked':False,'successful_exploitation_confirmed':False}
    manifest.update((scope or Scope()).audit())
    rows,old=feature_rows(events,session,provenance) if not error else ([],[])
    write(out/'features.json',rows);write(out/'v1_features.json',old)
    manifest['features_sha256']=sha(out/'features.json');manifest['v1_features_sha256']=sha(out/'v1_features.json')
    manifest['windows']=len(rows);write(out/'manifest.json',manifest)
    return manifest


def verify_capture(root,plan,session_id):
    """Independent bounded source replay. No requests, labels or artifact writes."""
    validate_plan(plan);s=next(s for s in plan['sessions'] if s['session_id']==session_id)
    from .study31 import load_browser_session
    rows,old,m=load_browser_session(root,s,plan);p=m['provenance'];path=Path(p['source_path']);stat=path.stat()
    start,end=p['offset_start'],p['offset_end']
    if (stat.st_dev,stat.st_ino)!=(p['source_device'],p['source_inode']) or stat.st_size<end or not 0<end-start<=MAX_BYTES:
        raise CaptureError('SOURCE_UNAVAILABLE_OR_CHANGED')
    with path.open('rb') as f:f.seek(start);raw=f.read(end-start)
    if hashlib.sha256(raw).hexdigest()!=p['slice_sha256']:raise CaptureError('SOURCE_SLICE_HASH_MISMATCH')
    validate_capture_attribution(p,session_id,m['actor_id'])
    events,replayed=attribute_slice(raw,path,start,p['start_utc'],p['end_utc'],
        m['actor_id'],'M5Capture/'+session_id,p['expected_user_agent_sha256'],ATTRIBUTION_POLICY)
    if any(p.get(key)!=value for key,value in replayed.items()):
        raise CaptureError('SOURCE_ATTRIBUTION_REPLAY_MISMATCH')
    if not events or replayed['malformed_records'] or replayed['outside_capture_time_records']:
        raise CaptureError('CAPTURE_INTEGRITY_FAILURE')
    current,baseline=feature_rows(events,s,p)
    if current!=rows or baseline!=old:raise CaptureError('FEATURE_REPLAY_MISMATCH')
    return {'session_id':session_id,'verified':True,'windows':len(rows),
        'source_records':replayed['observed_records'],'accepted_records':replayed['accepted_records'],
        'foreign_records':replayed['foreign_records'],'attribution_policy':ATTRIBUTION_POLICY,
        'ownership_filtering_reproduced':True,'source_bytes_verified':True,'network_requests':0}
