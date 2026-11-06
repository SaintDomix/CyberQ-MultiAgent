"""Canonical operational posture rows compatible with the frozen Fusion adapter."""
from collections import defaultdict
from copy import deepcopy
from fusion.schema import stable_id, CATEGORIES
from fusion.adapters import posture
from .policy import TARGET

# Reviewed equivalence keys, not fuzzy titles. One deployment header control;
# all locations remain in member evidence. Cookie equivalence requires its name.
ZAP_RULES = {
    '10038': ('HDR-002', 'Security Headers', 'Content-Security-Policy'),
    '10021': ('HDR-005', 'Security Headers', 'X-Content-Type-Options'),
    '10020': ('HDR-006', 'Security Headers', 'Clickjacking protection'),
    '10035': ('HDR-001', 'Security Headers', 'Strict-Transport-Security'),
    '10036': ('DISC-001', 'Information Disclosure', 'Server version disclosure'),
    '10037': ('DISC-002', 'Information Disclosure', 'X-Powered-By disclosure'),
    '10010': ('COOKIE-MoodleSession-HTTPONLY', 'Authentication & Session', 'Cookie HttpOnly flag'),
    '10011': ('COOKIE-MoodleSession-SECURE', 'Authentication & Session', 'Cookie Secure flag'),
    '10054': ('COOKIE-MoodleSession-SAMESITE', 'Authentication & Session', 'Cookie SameSite policy'),
    '10015': ('ZAP-CACHE-CONTROL', 'Privacy & Exposure', 'Cache-control directives require review'),
    '10023': ('ZAP-DEBUG-DISCLOSURE', 'Information Disclosure', 'Debug error information disclosure'),
    '10027': ('ZAP-COMMENT-DISCLOSURE', 'Information Disclosure', 'Suspicious comments require review'),
    '90022': ('ZAP-APPLICATION-ERROR', 'Information Disclosure', 'Application error disclosure'),
}
COOKIE_IDS = {'COOKIE-001': 'COOKIE-MoodleSession-SECURE', 'COOKIE-002': 'COOKIE-MoodleSession-HTTPONLY',
              'COOKIE-003': 'COOKIE-MoodleSession-SAMESITE', 'COOKIE-004': 'COOKIE-MoodleSession-PATH',
              'COOKIE-005': 'COOKIE-MoodleSession-DOMAIN'}


def row(fid, category, title, status, severity, confirmation, source, assessment_id, at, **extra):
    identity = stable_id('operational-evidence', [assessment_id, source, fid, extra])
    return {'finding_id': fid, 'evidence_id': identity, 'category': category,
            'finding_type': title, 'check_result': 'NOT_TESTED' if status == 'NOT_REEVALUATED' else status,
            'operational_status': status, 'severity': severity, 'confirmation_status': confirmation,
            'evidence_source': source, 'assessment_id': assessment_id, 'created_at': at,
            'start_utc': at, 'end_utc': at, 'affected_asset': TARGET,
            'affected_component': 'Moodle HTTP deployment', 'semantic_scope': 'PASSIVE_FINDING; no exploit confirmation',
            'successful_exploitation_confirmed': False, 'causal': False,
            'provenance': {'assessment_id': assessment_id, 'provider': source, 'observed_at': at},
            **extra}


def not_reevaluated(catalog, executed, assessment_id, at):
    return [row(r['finding_id'], r['category'], r['finding_type'], 'NOT_REEVALUATED', None,
                'NOT_TESTED', 'NATIVE_POSTURE', assessment_id, at,
                explanation='No fresh safe operational observation for this check. Historical result is not recycled.',
                evidence={'coverage': 'NOT_REEVALUATED'}, recommendation='Arrange a separately authorized fresh internal/role/configuration check.')
            for r in catalog if r['finding_id'] not in executed]


def deduplicate(rows, target=TARGET):
    groups = defaultdict(dict)
    for r in rows:
        # Unmapped rules stay distinct and excluded; native multi-control IDs are
        # already reviewed concepts. ZAP cookie keys are assigned only on an exact name match.
        key = r.get('weakness_key') or (r['finding_id'] if r['evidence_source'] == 'NATIVE_POSTURE' else r['evidence_id'])
        groups[key][r['evidence_id']] = r
    out = []
    for key, mapping in sorted(groups.items()):
        members = sorted(mapping.values(), key=lambda r: r['evidence_id'])
        def contribution(r):
            c = posture([r], 'operational')[0].contribution
            return c if c is not None else -1
        representative = sorted(members, key=lambda r: (-contribution(r), r['evidence_source'] != 'NATIVE_POSTURE', r['evidence_id']))[0]
        result = deepcopy(representative)
        native = next((r for r in members if r['evidence_source'] == 'NATIVE_POSTURE'), None)
        if native: result['finding_id'] = native['finding_id']
        observed_sources = {r['evidence_source'] for r in members if r['operational_status'] != 'NOT_REEVALUATED'}
        cid = stable_id('canonical-posture', [target, key])
        result.update(canonical_finding_id=cid, evidence_id=stable_id('canonical-evidence', [cid, representative['assessment_id']]),
                      source_finding_ids=sorted({r.get('source_finding_id', r['finding_id']) for r in members}),
                      member_evidence_ids=sorted({r['evidence_id'] for r in members}),
                      evidence_sources=sorted(observed_sources or {r['evidence_source'] for r in members}),
                      multi_source=len(observed_sources) > 1,
                      dedup_rule='REVIEWED_CONTROL_EQUIVALENCE_MAX' if len(members) > 1 else 'INDEPENDENT_CONTROL',
                      dedup_confidence='EXPLICIT_RULE; not probability', member_count=len(members),
                      contribution_semantics='Maximum eligible source contribution, never a sum; stronger support is retained without duplicate penalty',
                      source_status_conflict=len({r['check_result'] for r in members if r['check_result'] != 'NOT_TESTED'}) > 1,
                      evidence={'members': members})
        out.append(result)
    return out
