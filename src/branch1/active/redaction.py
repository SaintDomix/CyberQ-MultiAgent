"""Report-copy redaction; source records and parent identities stay unchanged."""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_KEY = re.compile(r"test_identifiers|identity_markers|authenticated_marker|username|email|password|passwd|secret|token|cookie|authorization|credential|api[_-]?key|sesskey|moodlesession", re.I)
ASSIGNMENT = re.compile(r"\b([\w.-]*(?:password|passwd|secret|token|cookie|api[_-]?key|sesskey|moodlesession)[\w.-]*)\s*([=:])\s*(?:\"[^\"]*\"|'[^']*'|[^\s;,<>]+)", re.I)


def redact_text(text):
    if text.startswith(("http://", "https://")) and not any(c.isspace() for c in text):
        try:
            parts = urlsplit(text)
            netloc = parts.netloc.rsplit("@", 1)[-1]
            query = urlencode([(k, "<redacted>" if SECRET_KEY.search(k) else v)
                               for k, v in parse_qsl(parts.query, keep_blank_values=True)])
            return urlunsplit((parts.scheme, netloc, parts.path, query, ""))
        except ValueError:
            return "<redacted malformed URL>"
    text = re.sub(r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*[^\r\n]+", "Authorization: <redacted>", text)
    text = re.sub(r"(?i)\b(?:set-cookie|cookie)\s*:\s*[^\r\n]+", "Cookie: <redacted>", text)
    text = re.sub(r"https?://[^\s<>\"']+", lambda m: redact_text(m.group()), text)
    # HTML hidden fields may put name before or after value; redact the entire tag.
    text = re.sub(r"(?is)<input\b[^>]*(?:password|token|sesskey|secret)[^>]*>", "<input redacted>", text)
    return ASSIGNMENT.sub(lambda m: m.group(1)+m.group(2)+"<redacted>", text)


def redact(value):
    if isinstance(value, dict):
        return {k: "<redacted>" if SECRET_KEY.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, tuple):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
