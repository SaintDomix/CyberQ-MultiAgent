"""Versioned policy constants and strict canonical envelope."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json

VERSION = 'fusion-cqi-1.1'
DIMENSIONS = {
    'D1': 'TRANSPORT_HTTP_PROTECTION', 'D2': 'IDENTITY_SESSION_ACCESS',
    'D3': 'EXPOSURE_DISCLOSURE', 'D4': 'PATCH_VULNERABILITY_MANAGEMENT',
    'D5': 'SERVER_HARDENING_INTEGRITY', 'D6': 'BEHAVIORAL_THREAT_ACTIVITY',
}
CATEGORIES = {
    'Transport Security': 'D1', 'Security Headers': 'D1', 'HTTP Configuration': 'D1',
    'Authentication & Session': 'D2', 'Access Control': 'D2', 'Authentication & Access': 'D2',
    'Information Disclosure': 'D3', 'Exposure': 'D3', 'Privacy & Exposure': 'D3',
    'Patch & Vulnerability Intelligence': 'D4', 'Server-side Configuration': 'D5',
    'Runtime Hardening': 'D5', 'Network Egress / SSRF Defense': 'D5',
}
SEVERITY = {'CRITICAL': 1., 'HIGH': .75, 'MEDIUM': .5, 'LOW': .25, 'INFO': 0.}
RESULT = {'FAIL': 1., 'PARTIAL': .5, 'PASS': 0., 'DISMISSED': 0., 'NOT_APPLICABLE': 0.}
CONFIRMATION = {'CONFIRMED': 1., 'VERSION_BASED': .7, 'NOT_CONFIRMED': .35,
                'FALSE_POSITIVE': 0., 'NOT_APPLICABLE': 0.}
BEHAVIOR = {'BENIGN': 0., 'UNCERTAIN': .15, 'UNKNOWN_ANOMALY': .4,
            'ENUMERATION_RECONNAISSANCE': .5, 'ADMIN_PROBING': .5,
            'BRUTE_FORCE': .75, 'REQUEST_BURST_DOS_LIKE': .75,
            'SQLI_ATTEMPT': .75, 'XSS_ATTEMPT': .75, 'PATH_TRAVERSAL_ATTEMPT': .75}
KNOWN = frozenset(BEHAVIOR) - {'BENIGN', 'UNCERTAIN', 'UNKNOWN_ANOMALY'}
SUPPORT = {'BOTH_BENIGN_NORMAL': 0., 'ANOMALY_WITHOUT_CONFIDENT_KNOWN_ATTACK': 1.,
           'NORMAL_IF_WITH_UNCERTAIN_OR_UNAVAILABLE_CLASSIFIER': 1.,
           'KNOWN_ATTACK_WITH_ANOMALY_SUPPORT': 1., 'KNOWN_ATTACK_MODEL_DISAGREEMENT': .8}


def dumps(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def stable_id(prefix, value):
    return prefix + '-' + hashlib.sha256(dumps(value).encode()).hexdigest()


def utc(value):
    if not isinstance(value, str):
        raise ValueError('UTC timestamp required')
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None or dt.utcoffset().total_seconds() != 0:
        raise ValueError('Explicit UTC timestamp required')
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source_branch: str
    source_record_id: str
    source_path: str
    provenance: dict
    category: str
    finding_type: str
    behavior_class: str | None
    affected_asset: object
    affected_component: object
    check_result: str
    severity: object
    evidence_strength: str
    timestamps: dict
    recommendation: object
    score_eligible: bool
    semantic_scope: str
    dimension: str | None
    contribution: float | None
    coefficients: dict
    exclusions: list
    source_details: dict
    schema_version: str = VERSION
    causal: bool = False
    successful_exploitation_confirmed: bool = False

    def __post_init__(self):
        if self.source_branch not in ('BRANCH1_POSTURE', 'BRANCH2_BEHAVIOR'):
            raise ValueError('Invalid source branch')
        if not self.evidence_id or not self.source_record_id or not self.source_path:
            raise ValueError('Missing evidence identity/provenance')
        if self.dimension is not None and self.dimension not in DIMENSIONS:
            raise ValueError('Invalid dimension')
        if self.score_eligible != (self.contribution is not None):
            raise ValueError('Invalid scoring eligibility')
        if self.contribution is not None and not 0 <= self.contribution <= 1:
            raise ValueError('Invalid contribution')
        if self.causal or self.successful_exploitation_confirmed:
            raise ValueError('Unsupported causal/exploitation claim')

    def export(self):
        return asdict(self)
