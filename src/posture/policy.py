"""Closed laboratory profile; no frontend URLs, methods or scanner actions."""
from dataclasses import dataclass, asdict
from urllib.parse import urlsplit, unquote

TARGET = 'http://192.168.226.132/moodle/'
TARGET_ID = 'moodle-local'
PAGES = ('', 'login/index.php', 'my/', 'course/', 'admin/')


def validate_target(target_id, url=TARGET, authorized=True):
    if target_id != TARGET_ID or url != TARGET or authorized is not True:
        raise ValueError('Only the configured authorized Moodle profile is permitted')
    return TARGET


def scoped(url):
    try:
        p = urlsplit(url)
        decoded = p.path
        for _ in range(4): decoded = unquote(decoded)
        return (p.scheme == 'http' and p.hostname == '192.168.226.132'
                and p.port in (None, 80) and not p.username and not p.password
                and not p.query and not p.fragment and '\\' not in decoded
                and not any(ord(c) < 32 for c in url)
                and '..' not in decoded.split('/') and decoded.startswith('/moodle/'))
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class PassivePolicy:
    version: str = 'posture-passive-policy-1.0'
    mode: str = 'PASSIVE_BASELINE'
    active_scan: bool = False
    authorized_target_required: bool = True
    off_origin: str = 'DENY'
    state_changing_actions: str = 'DENY'
    max_requests: int = 20
    max_duration_seconds: int = 60
    max_response_bytes: int = 2_000_000
    max_depth: int = 0
    discovery: str = 'FIXED_REVIEWED_PUBLIC_PAGES; no spider or form submission'
    authenticated_coverage: str = 'NOT_VALIDATED'

    def __post_init__(self):
        if (self.mode != 'PASSIVE_BASELINE' or self.active_scan is not False
                or self.authorized_target_required is not True or self.off_origin != 'DENY'
                or self.state_changing_actions != 'DENY' or self.max_depth != 0
                or not 1 <= self.max_requests <= 20 or not 1 <= self.max_duration_seconds <= 60
                or not 1 <= self.max_response_bytes <= 2_000_000
                or self.authenticated_coverage != 'NOT_VALIDATED'):
            raise ValueError('Unsafe passive policy')

    def export(self): return asdict(self)
