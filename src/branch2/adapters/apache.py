"""Apache combined adapter. POST bodies/session cookies/Moodle roles are absent."""
from datetime import datetime, timezone
import hashlib
import re
from urllib.parse import urlsplit
from ..events import CanonicalBehavioralEvent, identifier

PATTERN = re.compile(r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "((?:\\.|[^"\\])*)" (\d{3}) (\d+|-) "((?:\\.|[^"\\])*)" "((?:\\.|[^"\\])*)"$')


def unescape(value):
    return re.sub(r'\\x([0-9A-Fa-f]{2})',lambda m:chr(int(m[1],16)), value).replace('\\"','"').replace('\\\\','\\')


def parse_line(line, source_file, source_sha256, line_number):
    match = PATTERN.fullmatch(line.rstrip('\r\n'))
    if not match: raise ValueError('Malformed combined log')
    client, _, auth, ts, request, status, size, referrer, agent = match.groups()
    parts = request.split(' ')
    if len(parts) != 3 or not re.fullmatch(r'[A-Z]+',parts[0]) or not re.fullmatch(r'HTTP/\d(?:\.\d)?',parts[2]):
        raise ValueError('Malformed request line')
    target = urlsplit(unescape(parts[1]))
    timestamp = datetime.strptime(ts,'%d/%b/%Y:%H:%M:%S %z').astimezone(timezone.utc)
    return CanonicalBehavioralEvent(timestamp,identifier(client),parts[0],target.path, target.query,
        int(status),None if size=='-' else int(size),None if agent=='-' else unescape(agent),
        None if referrer=='-' else unescape(referrer),source_file,source_sha256,line_number,
        hashlib.sha256(line.encode()).hexdigest(),authenticated_user_id=identifier(auth),
        infrastructure_dummy=client in {'::1','127.0.0.1'} and parts[0]=='OPTIONS' and parts[1]=='*'
            and 'internal dummy connection' in agent)


def read_log(path, source_file=None):
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    events, failures = [], []
    for number,line in enumerate(raw.decode('utf-8',errors='replace').splitlines(),1):
        try: events.append(parse_line(line,source_file or str(path),digest,number))
        except (ValueError, OverflowError): failures.append({'line_number':number,'record_sha256':hashlib.sha256(line.encode()).hexdigest(),'reason':'malformed Apache combined observation'})
    return events, failures, digest
