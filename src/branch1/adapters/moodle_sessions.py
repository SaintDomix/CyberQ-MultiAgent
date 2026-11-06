"""Authorized Moodle test-session bootstrap. No secret logging, files or retries."""
from contextlib import contextmanager
import getpass
from html.parser import HTMLParser
import os
import time
from urllib.parse import urljoin, urlsplit

import requests

from branch1.active.models import RequestSpec
from branch1.active.safety import Response


class BootstrapError(ValueError):
    """Messages contain fixed descriptions only, never credentials/server bodies."""


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inside = False
        self.action = self.method = self.token = None
        self.count = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form' and attrs.get('id') == 'login':
            self.inside = True
            self.count += 1
            self.action, self.method = attrs.get('action'), attrs.get('method', '').lower()
        if self.inside and tag == 'input' and attrs.get('name') == 'logintoken':
            self.token = attrs.get('value')

    def handle_endtag(self, tag):
        if tag == 'form': self.inside = False


class LoginTransport:
    """Shared bootstrap budget/rate; POST allowed only to the exact login interface."""
    def __init__(self, policy, *, clock=time.monotonic, sleep=time.sleep):
        policy.require_execution()
        if policy.request_budget < 10:
            raise BootstrapError('Budget must reserve at least four role requests plus bootstrap')
        self.policy = policy
        self.clock, self.sleep = clock, sleep
        self.used, self.last_request = 0, None
        self.posted_sessions = set()
        self.base = policy.target.rstrip('/') + '/'
        self.login_url = urljoin(self.base, 'login/index.php')

    def check_url(self, url):
        self.policy.check(RequestSpec(url, 'authorized session bootstrap GET scope'))
        if not urlsplit(url).path.startswith(urlsplit(self.base).path):
            raise BootstrapError('Bootstrap URL outside authorized Moodle base path')

    def request(self, session, method, url, data=None):
        self.check_url(url)
        if method not in {'GET','POST'} or method == 'POST' and (url != self.login_url or set(data or {}) != {'username','password','logintoken'}):
            raise BootstrapError('Only one credential POST per identity to the exact login URL is supported')
        if method == 'POST' and id(session) in self.posted_sessions:
            raise BootstrapError('Credential POST retry prohibited')
        if self.used >= self.policy.request_budget - 4:
            raise BootstrapError('Bootstrap budget exhausted; active comparison budget reserved')
        if self.last_request is not None:
            delay = 1/self.policy.requests_per_second - (self.clock()-self.last_request)
            if delay > 0: self.sleep(delay)
        self.last_request = self.clock()
        self.used += 1
        if method == 'POST': self.posted_sessions.add(id(session))
        try:
            kwargs = dict(timeout=self.policy.timeout,allow_redirects=False,stream=True)
            if method == 'POST': kwargs['data'] = data
            with session.request(method,url,**kwargs) as response:
                chunks=[];length=0
                for chunk in response.iter_content(16384):
                    length += len(chunk)
                    if length > self.policy.max_response_bytes or self.clock()-self.last_request > self.policy.timeout:
                        raise BootstrapError('Bootstrap response exceeded size/time bound')
                    chunks.append(chunk)
                return Response(response.status_code,url,dict(response.headers),b''.join(chunks))
        except requests.RequestException:
            raise BootstrapError('Bounded login request failed') from None

    def follow(self, session, response):
        for _ in range(4):
            if response.status not in {301,302,303,307,308}: return response
            # Even 307/308 are followed only by GET, never replay credentials.
            location=next((v for k,v in response.headers.items() if k.lower()=='location'),None)
            if not location: raise BootstrapError('Login redirect lacks a destination')
            url=urljoin(response.url,location)
            response=self.request(session,'GET',url)
        if response.status in {301,302,303,307,308}: raise BootstrapError('Login redirect bound exceeded')
        return response


def credentials(role, interactive=False):
    prefix='B1_STUDENT' if role=='student' else 'B1_ADMIN'
    username=os.environ.get(prefix+'_USERNAME')
    password=os.environ.get(prefix+'_PASSWORD')
    if interactive:
        username=username or getpass.getpass(prefix+' username (hidden): ')
        password=password or getpass.getpass(prefix+' password (hidden): ')
    if not username or not password:
        raise BootstrapError('Required test credentials unavailable')
    return username,password


def authenticate(transport, session, username, password, expected_marker, other_marker, cookie_name):
    page=transport.follow(session,transport.request(session,'GET',transport.login_url))
    if page.status != 200 or page.url != transport.login_url:
        raise BootstrapError('Expected local Moodle login page unavailable')
    form=LoginForm();form.feed(page.text)
    if form.count != 1 or form.method != 'post' or not form.token or urljoin(page.url,form.action or '') != transport.login_url:
        raise BootstrapError('Expected same-origin login form/token unavailable')
    posted=transport.request(session,'POST',transport.login_url,dict(username=username,password=password,logintoken=form.token))
    form.token=None
    if posted.status not in {301,302,303,307,308}:
        raise BootstrapError('Login not successful; no retry or password guessing')
    transport.follow(session,posted)
    # Explicit independent identity observation; never trust HTTP 200 alone.
    identity=transport.request(session,'GET',urljoin(transport.base,'my/'))
    if identity.status != 200 or expected_marker not in identity.text or other_marker in identity.text or 'id="login"' in identity.text:
        raise BootstrapError('Session identity verification failed (wrong role/account or login barrier)')
    cookies=[c for c in session.cookies if c.name==cookie_name and c.domain.lstrip('.')==urlsplit(transport.base).hostname
             and not c.domain_specified and urlsplit(transport.base).path.startswith(c.path) and not c.is_expired()]
    if len(cookies)!=1 or not cookies[0].value or any(x in cookies[0].value for x in ['\r','\n',';']):
        raise BootstrapError('Exactly one origin-scoped session cookie required')
    return cookie_name+'='+cookies[0].value


@contextmanager
def verified_sessions(policy, runtime, context, *, interactive=False, session_factory=requests.Session,
                      clock=time.monotonic,sleep=time.sleep):
    """Yield non-secret metadata; publish cookies only into this process's scoped env."""
    transport=LoginTransport(policy,clock=clock,sleep=sleep)
    low_user,low_password=credentials('student',interactive)
    high_user,high_password=credentials('administrator',interactive)
    if low_user==high_user: raise BootstrapError('Distinct student and administrator accounts required')
    sessions=[]; cookies=[]; original={}
    markers=context['identity_markers']
    references=[context['restricted_session'],context['privileged_session']]
    roles=['student','administrator']
    try:
        for reference,role,user,password,which in zip(references,roles,[low_user,high_user],[low_password,high_password],['restricted','privileged']):
            if runtime.sessions.get(reference,{}).get('role') != role: raise BootstrapError('Session/role reference mismatch')
            session=session_factory();sessions.append(session)
            session.trust_env=False;session.auth=None;session.headers.clear();session.cookies.clear()
            cookie=authenticate(transport,session,user,password,markers[which],markers['privileged' if which=='restricted' else 'restricted'],context.get('cookie_name','MoodleSession'))
            cookies.append(cookie)
        if cookies[0]==cookies[1]: raise BootstrapError('Test sessions must be distinct')
        for reference,cookie in zip(references,cookies):
            name=runtime.sessions[reference]['cookie_env']
            if name in original: raise BootstrapError('Distinct ephemeral cookie environment references required')
            original[name]=os.environ.get(name)
            os.environ[name]=cookie
        yield {'identity_verified':True,'roles':roles,'requests_used':transport.used,'rate_checkpoint':transport.last_request}
    finally:
        for name,value in original.items():
            if value is None: os.environ.pop(name,None)
            else: os.environ[name]=value
        for session in sessions:
            session.cookies.clear();session.close()
        cookies.clear()
        low_password=high_password=None
