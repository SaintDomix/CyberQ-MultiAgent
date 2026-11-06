"""Presence-aware canonical representation. Raw structural strings stay in memory."""
from dataclasses import dataclass, field, asdict
from datetime import datetime
import hashlib
import json
import math
import re

SCHEMA_VERSION = 'canonical-web-security-event-1.0'
FIELDS = ('timestamp', 'client_id', 'method', 'path', 'query', 'status', 'response_bytes',
          'user_agent', 'referrer', 'authenticated_user_id', 'session_id', 'role',
          'authentication_state', 'content_type', 'host', 'scheme', 'response_time')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class CanonicalWebEvent:
    timestamp: datetime | None = None
    client_id: str | None = None
    method: str | None = None
    path: str | None = None
    query: str | None = field(default=None, repr=False)
    status: int | None = None
    response_bytes: int | None = None
    user_agent: str | None = field(default=None, repr=False)
    referrer: str | None = field(default=None, repr=False)
    authenticated_user_id: str | None = None
    session_id: str | None = None
    role: str | None = None
    authentication_state: str | None = None
    content_type: str | None = None
    host: str | None = None
    scheme: str | None = None
    response_time: float | None = None
    infrastructure_dummy: bool = False
    observed_fields: tuple = ()
    source_platform: str = 'generic_web'
    source_type: str = 'structured'
    adapter_id: str = 'generic-web-1.0'
    adapter_version: str = '1.0'
    source_file: str = '<memory>'
    source_sha256: str = ''
    line_number: int = 0
    record_sha256: str = ''
    mapping_sha256: str = ''
    canonical_schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        if self.canonical_schema_version != SCHEMA_VERSION: raise ValueError('Unknown canonical schema')
        if self.timestamp is not None and (not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None):
            raise ValueError('Explicit timezone required')
        if self.method is not None and (not isinstance(self.method, str) or not re.fullmatch('[A-Z]+', self.method)):
            raise ValueError('Invalid canonical method')
        if self.status is not None and (type(self.status) is not int or not 100 <= self.status <= 599):
            raise ValueError('Invalid canonical status')
        if self.response_bytes is not None and (type(self.response_bytes) is not int or self.response_bytes < 0):
            raise ValueError('Invalid canonical bytes')
        if self.response_time is not None and (isinstance(self.response_time, bool) or not math.isfinite(self.response_time) or self.response_time < 0):
            raise ValueError('Invalid canonical response time')
        if set(self.observed_fields) - set(FIELDS): raise ValueError('Unknown presence field')

    @property
    def missing_fields(self):
        return tuple(k for k in FIELDS if k not in self.observed_fields or getattr(self, k) is None)

    def analytical(self):
        # No provenance bytes participate in format-invariance comparison.
        return {k: getattr(self, k).isoformat() if k == 'timestamp' and self.timestamp else getattr(self, k)
                for k in FIELDS} | {'infrastructure_dummy': self.infrastructure_dummy,
                                   'observed_fields': sorted(self.observed_fields)}

    def safe_evidence(self):
        # Never serialize arbitrary host/path/query/UA/referrer/identity strings.
        return {'canonical_schema_version': SCHEMA_VERSION, 'timestamp': self.timestamp.isoformat() if self.timestamp else None,
                'method': self.method, 'status': self.status, 'response_bytes': self.response_bytes,
                'observed_fields': list(self.observed_fields), 'missing_fields': list(self.missing_fields),
                'source_platform': self.source_platform, 'source_type': self.source_type,
                'adapter_id': self.adapter_id, 'adapter_version': self.adapter_version,
                'source_sha256': self.source_sha256, 'source_record_reference': self.line_number,
                'record_sha256': self.record_sha256, 'mapping_sha256': self.mapping_sha256,
                'analytical_sha256': digest(self.analytical()), 'raw_sensitive_fields_exported': False}


@dataclass
class NormalizedBatch:
    events: list
    source: dict
    detection: dict
    quality: dict
    mapping: dict = field(default_factory=dict)
    state: str = 'COMPLETE'

    def diagnostics(self, platform=None, context=None):
        from .capabilities import assess
        return {'state': self.state, 'canonical_schema_version': SCHEMA_VERSION,
                'source': self.source, 'detection': self.detection, 'quality': self.quality,
                'mapping': self.mapping, 'capabilities': assess(self, platform, context),
                'events_exported': False}
