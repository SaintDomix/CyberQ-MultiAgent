"""Canonical HTTP observations; unavailable identity/role/body evidence stays absent."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib

EVENT_VERSION = 'behavioral-http-1.0'


def identifier(value):
    return hashlib.sha256(value.encode()).hexdigest() if value and value != '-' else None


def utc(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None: raise ValueError('Explicit timezone required')
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class CanonicalBehavioralEvent:
    timestamp: datetime
    client_id: str
    method: str
    path: str
    query: str
    status: int
    response_bytes: int | None
    user_agent: str | None
    referrer: str | None
    source_file: str
    source_sha256: str
    line_number: int
    record_sha256: str
    authenticated_user_id: str | None = None
    session_id: str | None = None
    role: str | None = None
    infrastructure_dummy: bool = False
    schema_version: str = EVENT_VERSION

    def __post_init__(self):
        if self.timestamp.tzinfo is None: raise ValueError('Timezone required')
        if not 100 <= self.status <= 599: raise ValueError('Invalid HTTP status')
        if self.response_bytes is not None and self.response_bytes < 0: raise ValueError('Negative bytes')

    def safe_evidence(self):
        # Raw query/referrer/UA stay in memory only; may contain personal data or secrets.
        row = asdict(self)
        row['timestamp'] = self.timestamp.isoformat()
        for field in ('query','referrer','user_agent'):
            row[field+'_sha256'] = identifier(row.pop(field))
        return row
