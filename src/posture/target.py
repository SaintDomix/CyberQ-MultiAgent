"""Explicit operator-authorized application scope, independent of LMS implementation."""
from dataclasses import dataclass, field, asdict
import ipaddress
import re
from urllib.parse import urlsplit, unquote, urlunsplit, parse_qsl, urlencode

SENSITIVE = re.compile(r'(?i)(password|passwd|token|sess|csrf|cookie|authorization|secret|nonce|key)')


@dataclass(frozen=True)
class AuthorizedTarget:
    target_url: str
    authorized: bool = False
    scan_profile: str = 'FULL_AUTHORIZED'
    authentication_profile: str = 'NONE'
    discovery_profile: str = 'SPIDER_CLIENT_AJAX'
    exclude_regex: tuple = ()
    api_imports: dict = field(default_factory=dict)

    def __post_init__(self):
        p=urlsplit(self.target_url)
        if (self.authorized is not True or self.scan_profile not in ('STANDARD','FULL_AUTHORIZED')
            or p.scheme not in ('http','https') or not p.hostname or p.username or p.password
            or p.query or p.fragment or len(self.target_url)>500 or any(ord(c)<33 for c in self.target_url)):
            raise ValueError('An explicit authorized HTTP(S) application URL is required')
        host=p.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        if ':' in host:raise ValueError('IPv6 target configuration is not supported by this transport profile')
        if host in ('localhost','metadata.google.internal') or host.endswith('.localhost'):
            raise ValueError('Control/metadata targets are not permitted')
        try:
            ip=ipaddress.ip_address(host)
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                raise ValueError('Control/metadata targets are not permitted')
        except ValueError:
            if re.fullmatch(r'[0-9.]+',host) or ':' in host: raise
        if p.port is not None and not 1<=p.port<=65535:raise ValueError('Invalid port')
        path=p.path or '/'
        decoded=path
        for _ in range(4):decoded=unquote(decoded)
        if '\\' in decoded or '..' in decoded.split('/') or decoded!=path or not path.endswith('/'):
            raise ValueError('Use a normalized application base path ending in /')
        port='' if p.port in (None,80 if p.scheme=='http' else 443) else ':'+str(p.port)
        object.__setattr__(self,'target_url',urlunsplit((p.scheme,host+port,path,'','')))
        if self.authentication_profile not in ('NONE','FORM','HTTP','SCRIPT','EXISTING_SESSION'):
            raise ValueError('Unsupported authentication profile')
        if self.discovery_profile not in ('SPIDER','SPIDER_CLIENT_AJAX'):raise ValueError('Unsupported discovery profile')
        if self.scan_profile=='STANDARD':object.__setattr__(self,'discovery_profile','SPIDER')
        if len(self.exclude_regex)>12:raise ValueError('Too many exclusions')
        for pattern in self.exclude_regex:
            if not isinstance(pattern,str) or len(pattern)>300:raise ValueError('Invalid exclusion')
            re.compile(pattern)
        if set(self.api_imports)-{'openapi','graphql','soap','postman'}:raise ValueError('Unknown import type')
        for url in self.api_imports.values():
            if not self.contains(url):raise ValueError('API definitions must belong to the authorized application')

    @property
    def target_origin(self):
        p=urlsplit(self.target_url);return p.scheme+'://'+p.netloc
    @property
    def target_base_path(self):return urlsplit(self.target_url).path
    @property
    def include_regex(self):return '^'+re.escape(self.target_origin)+re.escape(self.target_base_path)+'.*$'
    @property
    def exclusions(self):
        # Avoid navigation that performs account/session/content changes, not vulnerability classes.
        return (r'.*/(?:logout|delete|remove|unenrol|unenroll|signup)(?:[./?].*)?',)+tuple(self.exclude_regex)
    def contains(self,url):
        try:
            p=urlsplit(url);base=urlsplit(self.target_url)
            decoded=p.path
            for _ in range(4):decoded=unquote(decoded)
            return (p.scheme==base.scheme and p.hostname==base.hostname
                and (p.port or (443 if p.scheme=='https' else 80))==(base.port or (443 if base.scheme=='https' else 80))
                and not p.username and not p.password and not p.fragment and '\\' not in decoded
                and '..' not in decoded.split('/') and decoded.startswith(base.path)
                and not any(re.fullmatch(x,url) for x in self.exclusions))
        except (ValueError,TypeError):return False
    def export(self,aid):
        return {**asdict(self),'api_imports':{k:sanitized_url(v) for k,v in self.api_imports.items()},
            'target_origin':self.target_origin,'target_base_path':self.target_base_path,
            'context_name':aid,'include_regex':self.include_regex,'exclude_regex':list(self.exclusions),
            'authentication_status':'NOT_CONFIGURED','credentials_persisted':False}


def parameter(value):
    value=str(value or '')
    return value if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.\[\]-]{0,63}',value) and not SENSITIVE.search(value) else '[withheld]'


def sanitized_url(url):
    try:
        p=urlsplit(url)
        path='/'.join(s if len(s)<=48 and re.fullmatch(r'[A-Za-z0-9_.-]*',s)
            and not re.search(r'[A-Za-z0-9_-]{32,}',s) else '[withheld-segment]' for s in p.path.split('/'))
        query=urlencode([(parameter(k),'[withheld]') for k in sorted({k for k,v in parse_qsl(p.query,keep_blank_values=True)})])
        return urlunsplit((p.scheme,p.hostname+(':'+str(p.port) if p.port else ''),path,query,''))
    except (ValueError,TypeError):return '[withheld]'


def endpoint(url):
    p=urlsplit(sanitized_url(url));return p.scheme+'://'+p.netloc+p.path,tuple(sorted({parameter(k) for k,v in parse_qsl(p.query)}))
