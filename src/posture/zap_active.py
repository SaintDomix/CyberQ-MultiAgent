"""Deny-by-default fourth evidence stage; no unreviewed ZAP scan dispatch.

The installed rules do not yet have an approved pre-send scope/request bound.
An empty allowlist is an intentional unavailable result, never a successful scan.
Adding a rule requires code review and an enforcing transport, not an env flag.
"""
import re
import time
from urllib.parse import urlsplit
from .policy import TARGET, PAGES, scoped
from .providers import ZapAPI, now
from .privacy import sha

POLICY_ID = 'zap-active-lab-reviewed-1.0'
ENABLED_SCANNERS = ()
MAX_INVENTORY = 128
CONTROL_SECONDS = 8

# IDs, not names or broad scanner categories, determine the reviewed decision.
UNSAFE = frozenset('6 7 10048 20015 20018 20019 40009 40012 40014 40018 40019 40020 40021 40022 40024 40026 40027 40043 40045 40048 90019 90020 90021 90023 90024 90034 90035 90036 90037 30001 30002 40003 40008 40044 90017 10058 10104 40016 40017 50000 90026 90029'.split())
IRRELEVANT = frozenset('10045 40028 40029 40042'.split())
REVIEW_NOTES = {
    '0': 'GET directory candidate; upstream implementation delegates redirects to the core sender. Installed add-on/core binding, exact request maximum and pre-send redirect enforcement are not verified. No scan permitted.',
    '10106': 'Changes HTTP to HTTPS and handles redirects; violates the exact approved HTTP origin. No scan permitted.',
    '10047': 'HTTPS-to-HTTP cross-scheme assessment is outside this HTTP-only deployment policy.',
    '20017': 'PHP source-disclosure probe can expose source; exact installed payload/response handling is not approved.',
    '40032': 'Sensitive configuration-file read probe is not approved for this installed rule.',
    '40034': 'Environment-file read probe is not approved for this installed rule.',
    '40035': 'Hidden-file discovery exceeds the fixed current candidate set; payload list is not approved.',
}


def review_scanners(scanners):
    if not isinstance(scanners, list) or len(scanners) > MAX_INVENTORY:
        raise ValueError('Scanner inventory exceeds reviewed bound')
    reviewed, ids = [], set()
    for scanner in scanners:
        sid = str(scanner.get('id', ''))
        if not re.fullmatch(r'[0-9]{1,8}', sid) or sid in ids:
            raise ValueError('Invalid/duplicate scanner identity')
        ids.add(sid)
        decision = ('DISABLED_UNSAFE' if sid in UNSAFE else 'DISABLED_NOT_RELEVANT' if sid in IRRELEVANT
                    else 'DISABLED_UNREVIEWED')
        # Do not export arbitrary installed plugin descriptions or payload fields.
        name = str(scanner.get('name', ''))
        name = name if re.fullmatch(r'[A-Za-z0-9 ._()/+-]{1,140}', name) else '[name withheld]'
        reviewed.append({'scanner_id': sid, 'name': name, 'category_id': str(scanner.get('policyId', '')) if str(scanner.get('policyId', '')).isdigit() else None,
            'decision': decision, 'rationale': REVIEW_NOTES.get(sid,
                'Forbidden injection/execution, state-change, callback, fuzzing, resource-exhaustion or unrestricted-script behavior; not allowed.' if sid in UNSAFE else
                'Non-Moodle technology check; not relevant to the reviewed deployment.' if sid in IRRELEVANT else
                'Unseen/unreviewed installed rule; deny by default.'),
            'tests': 'Installed rule named above; detailed installed payload behavior is not approved.',
            'request_behavior': 'NOT_APPROVED; no requests permitted',
            'mutates_parameters': 'NOT_VERIFIED', 'potentially_dangerous_behavior': sid in UNSAFE,
            'server_side_state_impact': 'NOT_VERIFIED', 'external_callback_behavior': 'NOT_VERIFIED',
            'delay_or_dos_behavior': 'NOT_VERIFIED', 'authentication_assumptions': 'No authenticated scanner coverage validated',
            'enabled_by_application': False})
    return sorted(reviewed, key=lambda s: int(s['scanner_id']))


def candidates(passive, assessment_id):
    """Only this run's successfully reviewed, non-redirect GET transcript.

    No history/search/crawl, no guessed query parameters, no query values in output.
    Query-bearing URLs need a separately reviewed parameter contract; currently denied.
    """
    if passive.get('status') != 'COMPLETE' or passive.get('scope_integrity', {}).get('result') != 'PASS':
        return []
    lifecycle = passive.get('provenance', {}).get('session_lifecycle', {})
    if lifecycle.get('assessment_session_id') != assessment_id or lifecycle.get('state') != 'COLLECTED':
        return []
    urls = set()
    for request in passive.get('provenance', {}).get('requests', []):
        url = request.get('url', '')
        if (request.get('method') == 'GET' and type(request.get('status')) is int
                and 200 <= request['status'] < 300 and scoped(url)
                and urlsplit(url).path in {'/moodle/' + p for p in PAGES}):
            # Canonicalize explicit port 80 without expanding any route.
            urls.add('http://192.168.226.132' + urlsplit(url).path)
    return sorted(urls)


def unavailable(assessment_id, reason='ACTIVE_STAGE_FAILED_CLOSED'):
    return {'provider_id': 'zap_active', 'evidence_source': 'ZAP_ACTIVE', 'assessment_id': assessment_id,
        'policy_id': POLICY_ID, 'status': 'NOT_AVAILABLE', 'reason_code': reason,
        'started_at': now(), 'completed_at': now(), 'findings': [], 'scan_id': None,
        'alerts_produced': 0, 'alerts_mapped': 0, 'alerts_unmapped': 0,
        'scan_started': False, 'historical_alerts_reused': False,
        'successful_exploitation_confirmed': False, 'causal': False}


class ZapActiveStage:
    """Read-only safety gate. Deliberately has no ascan/action/scan capability.

    Do not present a no-op as scanner cancellation/timeout acceptance. An executing
    scan adapter remains blocked until a reviewed rule and pre-send guard exist.
    """
    def __init__(self, passive_provider, clock=time.monotonic):
        self.provider, self.clock = passive_provider, clock

    def run(self, assessment_id, passive):
        result = unavailable(assessment_id, 'NO_REVIEWED_SAFE_SCANNERS')
        urls = candidates(passive, assessment_id)
        result.update(target_origin='http://192.168.226.132', target_scope='/moodle/',
            zap_version=passive.get('version'),
            assessment_session_id=assessment_id, selected_urls=urls,
            selected_url_count=len(urls), selected_parameter_count=0,
            enabled_scanner_ids=[], rejected_scanner_count=None,
            plan={'candidate_url_count': len(urls), 'parameter_count': 0, 'enabled_scanner_count': 0,
                'scanner_ids': [], 'estimated_target_requests': 0, 'hard_request_ceiling': 0,
                'per_target_ceiling': 0, 'maximum_scan_duration_seconds': 0,
                'passive_completion_timeout_seconds': 0, 'concurrency': 0, 'inter_request_delay_ms': None,
                'control_deadline_seconds': CONTROL_SECONDS,
                'derivation': 'Zero reviewed rules × current candidate URLs = zero permitted target requests. Scan dispatch is absent; not a poll-and-cancel approximation.'},
            scan_duration_seconds=0, target_message_delta=0, cancellation_reason=None,
            budget_enforcement='NO_SCAN_DISPATCH_CAPABILITY', scope_integrity='NOT_RUN',
            passive_queue_completion='NOT_RUN_NO_ACTIVE_TRAFFIC', runtime_mode=None,
            scoring_effect='NONE_NO_ACTIVE_EVIDENCE', provenance={'fresh_gate_execution': True,
                'current_passive_status': passive.get('status'), 'new_session_required': True,
                'passive_alerts_reclassified_as_active': False})
        api = getattr(self.provider, 'api', None)
        if api is None or not getattr(self.provider, 'owned_ephemeral', False):
            result['reason_code'] = 'OWNED_ZAP_RUNTIME_UNAVAILABLE'
            return result
        start = self.clock(); deadline = start + CONTROL_SECONDS
        def read(component, name):
            if self.clock() >= deadline: raise ValueError('Control deadline exceeded')
            kw = {'control_deadline': deadline} if isinstance(api, ZapAPI) else {}
            value = api.call(component, 'view', name, **kw)
            if self.clock() >= deadline: raise ValueError('Control deadline exceeded')
            return value
        try:
            mode = read('core', 'mode')['mode']
            if mode != 'safe':
                result['reason_code'] = 'PASSIVE_SAFE_MODE_REQUIRED'
            else:
                before = int(read('core', 'numberOfMessages')['numberOfMessages'])
                review = review_scanners(read('ascan', 'scanners')['scanners'])
                after = int(read('core', 'numberOfMessages')['numberOfMessages'])
                result.update(runtime_mode=mode, scanner_review=review, rejected_scanner_count=len(review),
                    scanner_inventory_sha256=sha(__import__('json').dumps(review, sort_keys=True)),
                    history_count_before=before, history_count_after=after,
                    history_message_delta=after-before, scope_integrity='NO_ACTIVE_TRAFFIC_GENERATED')
                if before < 0 or after < before: raise ValueError('Unexpected history continuity')
        except Exception:
            result.update(reason_code='ZAP_ACTIVE_INVENTORY_UNAVAILABLE', scanner_review=[], rejected_scanner_count=None)
        result.update(completed_at=now(), control_duration_seconds=max(0, self.clock()-start))
        return result
