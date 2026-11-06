"""Presentation/export privacy. Do not persist response bodies or log query strings."""
import hashlib
import re
from urllib.parse import urlsplit, urlunsplit
SECRET=re.compile(r'^(?:password|passwd|dbpass|dbpassword|smtp_password|secret|client_secret|token|access_token|refresh_token|logintoken|sesskey|api_key|authorization|proxy-authorization|cookie|set-cookie|username|email|credentials|session_cookie)$',re.I)
SAFE_SEGMENTS={'moodle','login','index.php','my','course','view.php','report','admin','security','user','profile.php','theme','image.php','lib','ajax','service.php','pluginfile.php','webservice','rest','server.php','mod','quiz','resource','forum','logout.php'}

def safe_path(path):
    # Unknown path segments, including identifiers/encoded payloads, are never returned verbatim.
    return '/'.join(s if not s or s.lower() in SAFE_SEGMENTS else '[redacted]' for s in path.split('/'))[:300]

def sanitize(value):
    if isinstance(value,dict):
        return {k: ('[withheld]' if SECRET.fullmatch(k) or k in ('body_sample','body','html','raw_line') else sanitize(v)) for k,v in value.items()}
    if isinstance(value,list):return [sanitize(v) for v in value]
    if isinstance(value,str):
        if value.startswith(('http://','https://')):
            u=urlsplit(value);return urlunsplit((u.scheme,u.netloc.rsplit('@',1)[-1],u.path,'',''))
        if '<input' in value.lower() or '<html' in value.lower():return '[HTML withheld]'
        value=re.sub(r'(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+',r'\1: [withheld]',value)
        return re.sub(r'''(?i)\b(password|dbpass|token|sesskey|authorization|cookie)\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)''',r'\1=[withheld]',value)
    return value

def event_view(event,prediction,span):
    return {'timestamp':event.timestamp.isoformat(),'method':event.method if event.method in ('GET','POST','HEAD','OPTIONS','TRACE','PUT','DELETE','PATCH') else 'OTHER','path':safe_path(event.path),'status':event.status,
        'client_id':hashlib.sha256(str(event.client_id).encode()).hexdigest()[:16],
        'sequence':prediction['sequence'],'record_id':prediction['record_id'],
        'window_start':prediction['window_start'],'window_end':prediction['window_end'],
        'source_bytes':{'start':span['start'],'end':span['end'],'sha256':span['sha256']},'query':'WITHHELD',
        'semantics':'Canonical observation from the live engine callback; not an exploit claim'}
