"""Existing generic Branch1 rule execution; no new checks, validators or scanner policy."""
from types import SimpleNamespace
from urllib.parse import urljoin
import time
import requests
from branch1.external_rules.generic_rules import GenericRules
from posture.providers import StrictClient, ProviderFailure, now
from posture.model import row
from posture.privacy import text

ROOT_PROBES = ('/server-status', '/phpinfo.php', '/.git/HEAD', '/.env', '/composer.lock', '/vendor/composer/installed.json')


def applicability(spec):
    fid = spec['finding_id']
    family = spec.get('family', '')
    if fid.startswith('ROLE-'): return 'ROLE_CONTEXT_REQUIRED'
    if family == 'Internal read-only configuration': return 'INTERNAL_SERVER'
    if fid.startswith(('CORE-', 'ADV-', 'PATCH-', 'PLUGIN-', 'AUTH-', 'SESSION-', 'CFG-', 'PRIV-', 'SSRF-DEF-', 'COOKIE-')) or family == 'Moodle public controls':
        return 'PLATFORM_MOODLE'
    if family == 'Core / patch / advisory': return 'PLATFORM_MOODLE'
    if fid.startswith(('EXPOSURE-', 'DISC-')): return 'GENERIC_WEB_SERVER'
    if fid.startswith(('HDR-', 'TLS-', 'HTTP-', 'CORS-', 'TRANSPORT-')): return 'GENERIC_HTTP'
    return 'PLATFORM_MOODLE'  # Unknown controls never silently acquire generic applicability.


def control_inventory(project):
    from posture.inventory import controls
    return [dict(s, applicability=applicability(s)) for s in controls(project)]


def request_plan(target):
    # Source: GenericRules.transport_and_headers + cors_methods_exposure.
    # Different Origin/header/method variants must not share responses.
    urls = [target.target_url, urljoin(target.target_url, '__security_assessment_nonexistent_7f4a9c')]
    urls += [target.target_origin + p for p in ROOT_PROBES if target.contains(target.target_origin + p)]
    plan = [('GET', u) for u in urls] + [('GET_ORIGIN', target.target_url),
        ('OPTIONS_PREFLIGHT', target.target_url), ('TRACE', target.target_url), ('OPTIONS', target.target_url)]
    return {'unique_request_variants': len(plan), 'maximum_redirect_hops': 3,
            'max_requests': len(plan) * 4, 'max_duration_seconds': 60,
            'urls': urls, 'allowed_methods': ['GET', 'OPTIONS', 'TRACE']}


class GenericScopedClient(StrictClient):
    allowed_methods = ('GET', 'OPTIONS', 'TRACE')

    def __init__(self, target, policy, **kwargs):
        super().__init__(policy, **kwargs); self.target = target
        self.reviewed = set(request_plan(target)['urls'])
        self.session.headers['User-Agent'] = 'Generic-Operational-Posture/1.0'

    def allowed_url(self, url):
        return self.target.contains(url) and url in self.reviewed

    def trace(self, url, **kw):
        self.session.cookies.clear()
        return self.request('TRACE', url, **kw)


def collect_generic(project, aid, target, *, absolute_deadline=None, client_factory=GenericScopedClient):
    plan = request_plan(target)
    policy = SimpleNamespace(max_requests=plan['max_requests'], max_duration_seconds=60, max_response_bytes=1_000_000)
    client = client_factory(target, policy)
    if absolute_deadline is not None: client.deadline = min(client.deadline, absolute_deadline)
    findings = []; error = None
    try:
        base = client.get(target.target_url)
        rules = GenericRules(client, target.target_url)
        observed = rules.transport_and_headers(base) + rules.cors_methods_exposure()
        for f in observed:
            status = 'NOT_REEVALUATED' if f.status in ('ERROR', 'NOT_TESTED') else f.status
            findings.append(row(f.finding_id, f.category, f.indicator, status, f.severity,
                'NOT_TESTED' if status == 'NOT_REEVALUATED' else f.confidence, 'NATIVE_POSTURE', aid, now(),
                weakness_key=f.finding_id, source_finding_id=f.finding_id, source_rule_id=f.finding_id,
                affected_asset=target.target_url, affected_component='Authorized generic web application',
                explanation=text(f.reason), observed_value=text(f.observed), expected_value=text(f.expected),
                recommendation=text(f.recommendation), evidence={'implementation': 'branch1.external_rules.generic_rules.GenericRules'},
                prerequisite_reason='Reviewed scope or fresh HTTP response unavailable; no historical verdict reused.' if status == 'NOT_REEVALUATED' else None,
                url=target.target_url))
    except requests.RequestException:
        error = 'GENERIC_HTTP_COLLECTION_UNAVAILABLE'
    executed = {f['finding_id'] for f in findings}
    for spec in control_inventory(project):
        if spec.get('coverage_only') or spec['finding_id'] in executed: continue
        applies = spec['applicability']
        unavailable = applies in ('GENERIC_HTTP', 'GENERIC_WEB_SERVER', 'INTERNAL_SERVER', 'ROLE_CONTEXT_REQUIRED')
        reason = ('Fresh response or reviewed endpoint prerequisite missing.' if applies.startswith('GENERIC') else
                  'A verified fresh internal collector/role context for this target is not configured.' if unavailable else
                  'Moodle-specific rule is not applicable to a generic platform; no Moodle state inferred.')
        findings.append(row(spec['finding_id'], spec['category'], spec['finding_type'],
            'NOT_REEVALUATED' if unavailable else 'NOT_APPLICABLE', None,
            'NOT_TESTED' if unavailable else 'NOT_APPLICABLE', 'NATIVE_POSTURE', aid, now(),
            affected_asset=target.target_url, affected_component='Authorized generic web application',
            weakness_key=spec['finding_id'], prerequisite_reason=reason, explanation=reason,
            applicability=applies, current_state='NOT_AVAILABLE' if unavailable else 'NOT_APPLICABLE'))
    return {'provider_id': 'native', 'status': 'COMPLETE' if executed else 'FAILED', 'findings': findings,
        'provenance': {'request_count': len(client.transcript), 'policy': plan, 'platform': 'generic_web',
            'implementation': 'branch1.external_rules.generic_rules.GenericRules', 'error_code': error,
            'moodle_collector_run': False, 'historical_result_reused': False}}
