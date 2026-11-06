"""Allowlisted evidence, not copies of raw headers/bodies or ZAP payload values."""
import hashlib
import re
from urllib.parse import urlsplit, urlunsplit


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else str(data).encode()).hexdigest()


def safe_url(value):
    try:
        p = urlsplit(str(value))
        if p.scheme not in ('http', 'https') or not p.hostname: return '[withheld]'
        path = p.path
        # Operational providers only request reviewed routes; unknown/tokenized
        # report paths are not exported as evidence.
        if not re.fullmatch(r'/moodle/(?:|login/index\.php|my/|course/|admin/)', path):
            path = '/[withheld-path]'
        return urlunsplit((p.scheme, p.hostname + (':' + str(p.port) if p.port else ''), path, '', ''))
    except (ValueError, TypeError): return '[withheld]'


def text(value):
    value = re.sub(r'<[^>]*>', '', str(value or ''))[:4000]
    value = re.sub(r'https?://[^\s<>"\']+', lambda m: safe_url(m.group()), value)
    value = re.sub(r'(?i)\bnonce-[A-Za-z0-9+/=_-]+', 'nonce-[withheld]', value)
    return re.sub(r'(?i)\b(?:password|passwd|cookie|set-cookie|authorization|token|sesskey|logintoken|secret)\s*[:=]\s*[^\s;,]+',
                  '[sensitive value withheld]', value)


def evidence_digest(value):
    data = str(value or '').encode()
    return {'source_evidence_sha256': sha(data), 'source_evidence_bytes': len(data),
            'semantics': 'Payload/parameter values withheld; digest retains linkage only'}
