"""Kali-only bounded HTTP generator. No response bodies, passwords or cookies exported."""
import getpass
from contextlib import contextmanager
from html.parser import HTMLParser
import os
import time
import requests
from .planning import TARGET, WORKER
from .safety import validate_run, check_url


@contextmanager
def ephemeral_inputs(plan,interactive=False):
    required=[]
    if any(r['label']=='BRUTE_FORCE' for r in plan['runs']):required.append('B2_FICTITIOUS_PASSWORD')
    if any(r['auth_role'] for r in plan['runs']):required+=['B2_ADMIN_USERNAME','B2_ADMIN_PASSWORD']
    created=[]
    try:
        for name in required:
            if not os.environ.get(name):
                if not interactive:raise ValueError('Ephemeral credential inputs unavailable')
                value=getpass.getpass(name+' (hidden): ')
                if not value:raise ValueError('Empty credential input')
                os.environ[name]=value;created.append(name)
        yield
    finally:
        for name in created:os.environ.pop(name,None)


def check_worker():
    import subprocess,json
    try:
        addresses=json.loads(subprocess.run(['ip','-j','address','show'],capture_output=True,text=True,check=True).stdout)
        if WORKER not in {a['local'] for i in addresses for a in i.get('addr_info',[])}:raise ValueError('Wrong worker')
    except (OSError,subprocess.SubprocessError,ValueError):raise ValueError('Designated Kali worker interface must be present') from None


class Form(HTMLParser):
    """Select a complete, origin-scoped login form; token values stay ephemeral."""
    def __init__(self):
        super().__init__();self.token=None;self.token_count=0
        self._forms=[];self._current=None;self._malformed=False

    def handle_starttag(self,tag,attrs):
        attributes=dict(attrs)
        if tag in {'form','input'} and len(attributes)!=len(attrs):self._malformed=True
        if tag=='base':self._malformed=True  # Do not guess browser base-URL semantics.
        if tag=='form':
            if self._current is not None:self._malformed=True
            from urllib.parse import urljoin
            action=attributes.get('action','')
            try:
                approved=isinstance(action,str) and not any(c.isspace() for c in action) and urljoin(TARGET+'login/index.php',action)==TARGET+'login/index.php'
            except ValueError:approved=False
            method=attributes.get('method','get')
            self._current={'approved':approved and isinstance(method,str) and method.lower()=='post',
                           'id':attributes.get('id'),'controls':[], 'count':0,'token':None,'closed':False}
            self._forms.append(self._current)
        elif tag=='input' and self._current is not None:
            form=self._current
            if 'form' in attributes and attributes['form']!=form['id']:self._malformed=True
            name=attributes.get('name');kind=attributes.get('type','text')
            if not isinstance(kind,str):self._malformed=True;kind=''
            kind=kind.lower()
            if name in {'username','password'}:form['controls'].append((name,kind))
            if name=='logintoken' and form['approved']:
                form['count']+=1
                if form['count']==1 and 'disabled' not in attributes:form['token']=attributes.get('value')
        elif tag=='input' and 'form' in attributes:
            self._malformed=True  # External form-associated controls require review.

    def handle_endtag(self,tag):
        if tag=='form':
            if self._current is None:self._malformed=True
            else:self._current['closed']=True;self._current=None

    def close(self):
        super().close()
        # Moodle's distinct guest-login protocol has only hidden credentials.
        # Do not exclude any other competing POST form, even when its token matches.
        candidates=[f for f in self._forms if f['approved'] and not
                    (f['id']=='guestlogin' and sorted(f['controls'])==[('password','hidden'),('username','hidden')])]
        if self._malformed or self._current is not None or len(candidates)!=1:return
        selected=candidates[0];self.token_count=selected['count']
        if selected['closed'] and self.token_count==1 and isinstance(selected['token'],str) and selected['token'].strip():
            self.token=selected['token']

    def clear_tokens(self):
        self.token=None
        for form in self._forms:form['token']=None


class Transport:
    def __init__(self,run,context,authorized,session=None,clock=time.monotonic,sleep=time.sleep):
        if not authorized: raise ValueError('Explicit --authorized required')
        validate_run(run,context)
        self.run,self.context,self.clock,self.sleep=run,context,clock,sleep
        self.session=session or requests.Session();self.session.trust_env=False;self.session.auth=None
        if session is None:
            class SourceAdapter(requests.adapters.HTTPAdapter):
                def init_poolmanager(self,*args,**kwargs):
                    kwargs['source_address']=(WORKER,0)
                    return super().init_poolmanager(*args,**kwargs)
            self.session.mount('http://',SourceAdapter())
        self.session.headers.clear();self.session.headers['User-Agent']=run['user_agent']
        self.session.cookies.clear();self.used=0;self.last=None;self.start=clock();self.records=[]

    def request(self,method,url,data=None,retain=False):
        check_url(url,self.context,self.run['label'] in {'SQLI_ATTEMPT','XSS_ATTEMPT','PATH_TRAVERSAL_ATTEMPT'})
        if method=='POST' and (url!=TARGET+'login/index.php' or set(data or {})!={'username','password','logintoken'}): raise ValueError('Only controlled login POST allowed')
        if method not in {'GET','POST'}: raise ValueError('Read-only GET or controlled login only')
        if self.used>=self.run['maximum_request_count'] or self.clock()-self.start>self.run['duration_seconds']+10: raise ValueError('Request/deadline budget exhausted')
        if self.last is not None:
            wait=.5-(self.clock()-self.last)
            if wait>0:self.sleep(wait)
        self.last=self.clock();self.used+=1
        entry={'request_index':self.used,'method':method,'url':url,'elapsed_seconds':round(self.last-self.start,6)}
        self.records.append(entry)
        try:
            options={'timeout':5,'allow_redirects':False,'stream':True}
            if data is not None: options['data']=data
            with self.session.request(method,url,**options) as r:
                chunks=[];length=0
                for chunk in r.iter_content(16384):
                    length+=len(chunk)
                    if length>262144 or self.clock()-self.last>5: raise ValueError('Response bound exceeded')
                    if retain: chunks.append(chunk)
                entry.update(status=r.status_code,response_bytes_observed=length)
                if r.status_code>=500:raise ValueError('Server error stop condition')
                return r.status_code,dict(r.headers),b''.join(chunks).decode('utf-8',errors='replace')
        except (requests.RequestException,ValueError):
            entry['error']='BOUNDED_REQUEST_FAILURE'
            raise ValueError('Bounded request failed; no retry') from None

    def failed_login(self,identity):
        # Fictitious identity prefix is enforced; never guesses passwords for real users.
        password=os.environ.get('B2_FICTITIOUS_PASSWORD')
        if not password:raise ValueError('Ephemeral fictitious-identity password input required')
        self.session.cookies.clear()
        form=Form()
        try:
            status,_,text=self.request('GET',TARGET+'login/index.php',retain=True)
            form.feed(text);form.close()
            if status!=200 or form.token_count!=1 or not form.token or not form.token.strip():
                raise ValueError('Login token/context unavailable')
            status,headers,_=self.request('POST',TARGET+'login/index.php',{'username':identity,'password':password,'logintoken':form.token})
            if status==200:return
            # Moodle POST/redirect/GET after invalid login. Validate, NEVER follow:
            # the next scheduled attempt starts with its own fresh GET/token/jar.
            # This is protocol acceptance, not authentication success inference.
            from urllib.parse import urljoin,urlsplit
            locations=[v for k,v in headers.items() if k.lower()=='location']
            if status not in {302,303} or len(locations)!=1 or not isinstance(locations[0],str) or not locations[0] or any(c.isspace() for c in locations[0]):
                raise ValueError('Unexpected authentication transition')
            destination=urljoin(TARGET+'login/index.php',locations[0])
            parts=urlsplit(destination)
            if destination.split('?',1)[0]!=TARGET+'login/index.php' or parts.fragment or parts.query not in {'','loginredirect=0','loginredirect=1'}:
                raise ValueError('Unexpected authentication redirect destination')
        finally:
            form.clear_tokens();password=None;self.session.cookies.clear()

    def login_admin(self,interactive=False):
        username=os.environ.get('B2_ADMIN_USERNAME');password=os.environ.get('B2_ADMIN_PASSWORD')
        if interactive:
            username=username or getpass.getpass('Authorized admin username (hidden): ')
            password=password or getpass.getpass('Authorized admin password (hidden): ')
        if not username or not password: raise ValueError('Authorized administrator credentials unavailable')
        status,_,body=self.request('GET',TARGET+'login/index.php',retain=True)
        form=Form();form.feed(body);form.close()
        try:
            if status!=200 or not form.token: raise ValueError('Login token unavailable')
            status,headers,_=self.request('POST',TARGET+'login/index.php',{'username':username,'password':password,'logintoken':form.token})
        finally:
            password=None;form.clear_tokens()
        location=next((v for k,v in headers.items() if k.lower()=='location'),None)
        # Source-supported testsession redirect and at most four approved GET redirects.
        from urllib.parse import urljoin
        destination=urljoin(TARGET+'login/index.php',location or '')
        if status not in {302,303}: raise ValueError('Unexpected login redirect/failure')
        for _ in range(4):
            from urllib.parse import urlsplit
            import re
            p=urlsplit(destination)
            if destination not in {TARGET,TARGET+'my/'} and not (p.scheme=='http' and p.netloc=='192.168.226.132' and p.path=='/moodle/login/index.php' and re.fullmatch(r'testsession=\d+',p.query)):
                raise ValueError('Unexpected authentication redirect destination')
            status,headers,_=self.request('GET',destination)
            if status not in {302,303}:break
            location=next((v for k,v in headers.items() if k.lower()=='location'),None)
            destination=urljoin(destination,location or '')
        if status!=200:raise ValueError('Login redirect bound/failure')
        status,_,body=self.request('GET',TARGET+'my/',retain=True)
        markers=self.context['identity_markers']
        if status!=200 or markers['administrator'] not in body or markers['student'] in body: raise ValueError('Administrator identity verification failed')
        from urllib.parse import urlsplit
        if not self.session.cookies or any(c.domain.lstrip('.')!=urlsplit(TARGET).hostname or c.domain_specified or not '/moodle/'.startswith(c.path) for c in self.session.cookies): raise ValueError('Host-only origin-scoped cookies required')


def execute(run,context,authorized,*,interactive=False,session=None,clock=time.monotonic,sleep=time.sleep,worker_check=True):
    if not authorized: raise ValueError('Explicit --authorized required')
    if worker_check:
        check_worker()
    transport=Transport(run,context,authorized,session,clock,sleep)
    result={'run_id':run['run_id'],'label':run['label'],'status':'FAILED','requests':transport.records}
    try:
        if run['auth_role']: transport.login_admin(interactive)
        for step in run['steps']:
            wait=transport.start+step['at_seconds']-clock()
            if wait>0:sleep(wait)
            if step['operation']=='failed_login':transport.failed_login(step['identity'])
            else:transport.request('GET',step['url'])
        if not run['minimum_request_count']<=transport.used<=run['maximum_request_count']: raise ValueError('Incomplete protocol')
        remaining=transport.start+run['duration_seconds']-clock()
        if remaining>0:sleep(remaining)
        result['status']='COMPLETE'
    except (ValueError,requests.RequestException): result['error']='PROTOCOL_OR_BOUNDED_HTTP_FAILURE'
    finally:
        transport.session.cookies.clear();transport.session.close()
    elapsed=clock()-transport.start
    times=[r['elapsed_seconds'] for r in transport.records]
    peak=max((sum(0<=x-t<1-1e-6 for x in times) for t in times),default=0)
    result.update(actual_request_count=transport.used,elapsed_seconds=round(elapsed,6),achieved_request_rate=transport.used/max(elapsed,1e-9),actor_ip=WORKER,
                  achieved_peak_requests_per_second=peak,peak_limit_requests_per_second=2,concurrency=1)
    return result
