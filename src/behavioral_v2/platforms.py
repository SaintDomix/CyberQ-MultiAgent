"""Versioned semantic adapters. No labels, estimators, credentials or network."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Protocol
from urllib.parse import unquote, urlsplit

VOCABULARY = ('AUTH_LOGIN','AUTH_LOGOUT','DASHBOARD','COURSE_VIEW','CONTENT_VIEW',
    'QUIZ_ACTIVITY','PROFILE','ADMIN_ACTION','SEARCH','APPLICATION_API',
    'AJAX_SERVICE','STATIC_ASSET','OTHER_NAVIGATION','UNKNOWN')


@dataclass(frozen=True)
class SemanticRequest:
    category: str
    resource_kind: str | None = None

    def __post_init__(self):
        if self.category not in VOCABULARY or self.resource_kind not in (None,'THEME'):
            raise ValueError('Unsupported canonical semantics')


class BehaviorPlatformAdapter(Protocol):
    platform_id: str
    adapter_version: str
    def map_request(self, path: str, method: str = 'GET') -> SemanticRequest: ...
    def map_application_event(self, event: dict) -> SemanticRequest: ...
    def identity(self) -> dict: ...


class GenericHTTPBehaviorAdapter:
    platform_id = 'generic_http'
    adapter_version = 'generic-http-1.0'

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        if any(not p.startswith('/') or c not in VOCABULARY for p,c in self.routes.items()):
            raise ValueError('Invalid declarative route map')

    def map_request(self,path,method='GET'):
        p=unquote(urlsplit(path).path)
        if p in self.routes:return SemanticRequest(self.routes[p])
        if re.search(r'\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$',p,re.I):
            return SemanticRequest('STATIC_ASSET')
        return SemanticRequest('OTHER_NAVIGATION' if p.startswith('/') else 'UNKNOWN')

    def map_application_event(self,event):
        # The generic contract accepts an explicit canonical exporter category,
        # never guesses authentication outcome from free-form event text.
        value=event.get('canonical_category','UNKNOWN')
        return SemanticRequest(value)

    def identity(self):
        value={'platform_id':self.platform_id,'adapter_version':self.adapter_version,
            'routes':self.routes,'vocabulary':list(VOCABULARY),
            'implementation_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        if hasattr(self,'mount'):value['mount']=self.mount
        value['sha256']=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return value


class MoodleBehaviorAdapter(GenericHTTPBehaviorAdapter):
    platform_id='moodle'
    adapter_version='moodle-canonical-3.1'

    def __init__(self,mount='/moodle/'):
        super().__init__()
        if not mount.startswith('/') or not mount.endswith('/') or '..' in mount:
            raise ValueError('Invalid application mount')
        self.mount=mount

    def map_request(self,path,method='GET'):
        raw=unquote(urlsplit(path).path)
        if raw==self.mount.rstrip('/'):return SemanticRequest('OTHER_NAVIGATION')
        if not raw.startswith(self.mount):return SemanticRequest('UNKNOWN')
        p=raw[len(self.mount):].lower()
        exact={'login/index.php':'AUTH_LOGIN','login/logout.php':'AUTH_LOGOUT',
            'my/':'DASHBOARD','my/index.php':'DASHBOARD','course/view.php':'COURSE_VIEW',
            'user/profile.php':'PROFILE','user/view.php':'PROFILE','user/preferences.php':'PROFILE',
            'search/index.php':'SEARCH'}
        if p in exact:return SemanticRequest(exact[p])
        for prefix,category in (('lib/ajax/','AJAX_SERVICE'),('webservice/','APPLICATION_API'),
            ('api/','APPLICATION_API'),('admin/','ADMIN_ACTION'),('report/','ADMIN_ACTION'),
            ('mod/quiz/','QUIZ_ACTIVITY'),('mod/resource/','CONTENT_VIEW'),
            ('mod/page/','CONTENT_VIEW'),('mod/book/','CONTENT_VIEW')):
            if p.startswith(prefix):return SemanticRequest(category)
        if p.startswith('theme/'):return SemanticRequest('STATIC_ASSET','THEME')
        if re.search(r'\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$',p) or p.startswith(('lib/javascript.php','lib/requirejs.php','lib/polyfills/')):
            return SemanticRequest('STATIC_ASSET')
        return SemanticRequest('OTHER_NAVIGATION' if p in ('','index.php') or p.endswith('.php') else 'UNKNOWN')

    def map_application_event(self,event):
        name=event.get('eventname','').lstrip('\\')
        mapping={'core\\event\\user_loggedin':'AUTH_LOGIN','core\\event\\user_login_failed':'AUTH_LOGIN',
            'core\\event\\user_loggedout':'AUTH_LOGOUT','core\\event\\dashboard_viewed':'DASHBOARD',
            'core\\event\\course_viewed':'COURSE_VIEW','core\\event\\user_profile_viewed':'PROFILE',
            'mod_quiz\\event\\course_module_viewed':'QUIZ_ACTIVITY',
            'mod_resource\\event\\course_module_viewed':'CONTENT_VIEW',
            'mod_page\\event\\course_module_viewed':'CONTENT_VIEW'}
        return SemanticRequest(mapping.get(name,'UNKNOWN'))


class MoodleAuditAdapter:
    """Import sanitized standard-store exports; no DB connector or hidden joins."""
    def __init__(self,pseudonym_key):
        if not isinstance(pseudonym_key,bytes) or len(pseudonym_key)<16:
            raise ValueError('Environment-supplied study HMAC key required')
        self._key=pseudonym_key;self.platform=MoodleBehaviorAdapter()

    def _pseudo(self,kind,value):
        if value in (None,0,'0',''):return None
        return hmac.new(self._key,(kind+':'+str(value)).encode(),hashlib.sha256).hexdigest()

    def convert(self,event):
        timestamp=event.get('timecreated')
        if type(timestamp) is not int or timestamp<0:raise ValueError('Invalid audit timestamp')
        name=event.get('eventname','').lstrip('\\')
        category=self.platform.map_application_event(event).category
        return {'version':'moodle-audit-canonical-1.0','platform_id':'moodle',
            'timestamp':datetime.fromtimestamp(timestamp,timezone.utc).isoformat(),
            'source_record_id':self._pseudo('event',event.get('id')),
            'actor_id':self._pseudo('actor',event.get('userid')),
            'related_actor_id':self._pseudo('actor',event.get('relateduserid')),
            'course_id':self._pseudo('course',event.get('courseid')),
            'context_id':self._pseudo('context',event.get('contextid')),
            'category':category,'role':event.get('role') if event.get('role') in ('student','teacher','administrator','manager') else None,
            'authentication_outcome':'FAILED' if name=='core\\event\\user_login_failed' else
                'SUCCEEDED' if name=='core\\event\\user_loggedin' else None,
            'source_semantics':'application event; no session inferred; optional role only when explicitly exported',
            'raw_sensitive_fields_retained':False,'causal':False}
