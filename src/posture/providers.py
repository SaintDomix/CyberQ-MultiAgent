"""Native rule reuse and a closed passive-only ZAP API/proxy adapter."""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from collections import Counter
import os
import time
from urllib.parse import urljoin, urlsplit
import requests
from urllib3.util import Timeout
from urllib3.exceptions import ReadTimeoutError
from branch1.external_rules.generic_rules import GenericRules
from branch1.external_rules.cookies import cookie_findings
from branch1.external_rules.tls import run_tls
from branch1.client import redact_cookie
from .policy import TARGET, TARGET_ID, PAGES, PassivePolicy, validate_target, scoped
from .privacy import text, safe_url, sha, evidence_digest
from .model import row, COOKIE_IDS, ZAP_RULES
from .zap_history import MAX_HISTORY_MESSAGES, control_url, review_history, structural


def now(): return datetime.now(timezone.utc).isoformat()


CONNECT_TIMEOUT_SECONDS = 3.0
READ_TIMEOUT_SECONDS = 8.0
REQUEST_TIMEOUT_SECONDS = 8.0


class ProviderFailure(requests.RequestException):
    """Only fixed reason codes leave the transport boundary, never exception text."""
    def __init__(self, code, cause_code=None):
        super().__init__(code)
        self.code, self.cause_code = code, cause_code


def failure_code(error):
    if isinstance(error, ProviderFailure): return error.code
    if isinstance(error, requests.ConnectTimeout): return 'CONNECT_TIMEOUT'
    if isinstance(error, (requests.ReadTimeout, requests.Timeout, ReadTimeoutError)): return 'READ_TIMEOUT'
    if isinstance(error, requests.exceptions.ProxyError): return 'ZAP_PROXY_FAILURE'
    if isinstance(error, requests.HTTPError): return 'HTTP_ERROR'
    # Requests wraps urllib3 streaming read timeouts in ConnectionError.
    if isinstance(error, requests.ConnectionError):
        if any(isinstance(arg, ReadTimeoutError) for arg in error.args): return 'READ_TIMEOUT'
        return 'TARGET_UNREACHABLE'
    return 'PROTOCOL_ERROR'


def request_timeout(remaining):
    # Requests accepts urllib3 Timeout directly. Its total shares the initial
    # connect/read budget; unlike a tuple, connect time is subtracted from read.
    # Body streaming is additionally checked against the monotonic deadlines.
    budget = min(REQUEST_TIMEOUT_SECONDS, remaining)
    return Timeout(connect=min(CONNECT_TIMEOUT_SECONDS, budget),
                   read=min(READ_TIMEOUT_SECONDS, budget), total=budget)


def check_deadline(clock, assessment_deadline, request_deadline):
    at = clock()
    if at >= assessment_deadline: raise ProviderFailure('ASSESSMENT_DEADLINE_EXCEEDED')
    if at >= request_deadline: raise ProviderFailure('READ_TIMEOUT')


class ExternalScannerProvider(ABC):
    provider_id = ''
    provider_name = ''
    provider_version = None

    def __init__(self): self.results = {}
    def supported_modes(self): return ['PASSIVE_BASELINE']
    def target_validation(self, target_id, url=TARGET, authorized=True): return validate_target(target_id, url, authorized)
    def health(self): return self.availability()
    def assessment_status(self, assessment_id): return self.results.get(assessment_id, {'status': 'QUEUED'})['status']
    def collect_findings(self, assessment_id): return self.results[assessment_id]['findings']
    def provenance(self, assessment_id): return self.results[assessment_id]['provenance']

    @abstractmethod
    def availability(self): ...

    @abstractmethod
    def start_assessment(self, assessment_id, policy, target_id=TARGET_ID): ...


class StrictClient:
    """GET/OPTIONS only, reviewed pages only; redirects revalidated before send."""
    def __init__(self, policy, proxy=None, session=None, clock=time.monotonic):
        self.policy, self.clock = policy, clock
        self.deadline = clock() + policy.max_duration_seconds
        if session is None and os.getenv('COURSEWORK_OFFLINE')=='1':
            from coursework.lab import session as authorized_session
            session=authorized_session()
        self.session = session or requests.Session()
        self.session.trust_env = False
        self.session.headers['User-Agent'] = 'Moodle-Operational-Posture/2.0'
        if proxy: self.session.proxies.update(http=proxy)
        self.transcript = []

    allowed_methods = ('GET', 'OPTIONS')

    def allowed_url(self, url):
        return scoped(url) and urlsplit(url).path in {'/moodle/' + p for p in PAGES}

    def cached_redirect(self, method, url, headers):
        return None

    def request(self, method, url, **kwargs):
        follow = kwargs.pop('allow_redirects', True)
        headers = kwargs.pop('headers', {})
        if kwargs or method not in self.allowed_methods or any(k.lower() not in ('origin', 'access-control-request-method', 'access-control-request-headers') for k in headers):
            raise ProviderFailure('SCOPE_INTEGRITY_FAILURE')
        for _ in range(4):
            if not self.allowed_url(url):
                raise ProviderFailure('SCOPE_INTEGRITY_FAILURE')
            at = self.clock()
            remaining = self.deadline - at
            if remaining <= 0: raise ProviderFailure('ASSESSMENT_DEADLINE_EXCEEDED')
            cached = self.cached_redirect(method, url, headers) if _ else None
            if cached is not None: return cached
            if len(self.transcript) >= self.policy.max_requests: raise ProviderFailure('REQUEST_BUDGET_EXCEEDED')
            request_deadline = min(self.deadline, at + REQUEST_TIMEOUT_SECONDS)
            record = {'method': method, 'url': safe_url(url), 'status': None}
            self.transcript.append(record)  # Failed sends also consume the budget.
            try:
                r = self.session.request(method, url, headers=headers, allow_redirects=False,
                                         timeout=request_timeout(remaining), stream=True)
                with r:
                    record['status'] = r.status_code
                    check_deadline(self.clock, self.deadline, request_deadline)
                    chunks, total = [], 0
                    for chunk in r.iter_content(65536):
                        total += len(chunk)
                        if total > self.policy.max_response_bytes: raise ProviderFailure('RESPONSE_SIZE_LIMIT')
                        check_deadline(self.clock, self.deadline, request_deadline)
                        chunks.append(chunk)
                    check_deadline(self.clock, self.deadline, request_deadline)
                    r._content = b''.join(chunks); r._content_consumed = True
            except requests.RequestException as exc:
                code = failure_code(exc)
                record['error_code'] = code
                raise ProviderFailure(code) from None
            record.update(status=r.status_code, response_bytes=total, response_sha256=sha(r.content))
            if r.status_code >= 400: record['error_code'] = 'HTTP_ERROR'
            if follow and r.status_code in (301, 302, 303, 307, 308) and r.headers.get('Location'):
                url = urljoin(url, r.headers['Location'])
                # A redirect is not followed unless the next loop validates it.
                continue
            return r
        raise ProviderFailure('SCOPE_INTEGRITY_FAILURE')

    def get(self, url, **kw): return self.request('GET', url, **kw)
    def options(self, url, **kw): return self.request('OPTIONS', url, **kw)
    def trace(self, url, **kw): raise requests.RequestException('TRACE intentionally not executed')
    def close(self): self.session.close()


class NativePostureProvider(ExternalScannerProvider):
    provider_id = 'native'
    provider_name = 'Native Posture Engine'
    provider_version = 'branch1-research-rules / operational-wrapper-1.0'

    def __init__(self, client_factory=StrictClient):
        super().__init__(); self.client_factory = client_factory

    def availability(self):
        return {'provider_id': self.provider_id, 'status': 'AVAILABLE', 'version': self.provider_version,
                'supported_modes': self.supported_modes(), 'automatic_execution': False}

    def start_assessment(self, assessment_id, policy, target_id=TARGET_ID):
        self.target_validation(target_id); PassivePolicy(**policy.export())
        start = now(); client = self.client_factory(policy); findings = []; error_code = None
        try:
            base = client.get(TARGET)
            if not 200 <= base.status_code < 400: raise ProviderFailure('HTTP_ERROR')
            rules = GenericRules(client, TARGET)
            observations = run_tls(TARGET, 3) + rules.transport_and_headers(base) + cookie_findings(base)
            observations += rules.cors_methods_exposure()
            observations.append(rules.endpoint_header_finding(rules.endpoint_matrix()))
            at = now()
            for item in observations:
                d = item.to_dict(); fid = COOKIE_IDS.get(d['finding_id'], d['finding_id'])
                status = 'NOT_REEVALUATED' if d['status'] in ('ERROR', 'NOT_TESTED') else d['status']
                confirmation = 'NOT_TESTED' if status == 'NOT_REEVALUATED' else 'NOT_APPLICABLE' if status == 'NOT_APPLICABLE' else 'NOT_CONFIRMED' if d['confidence'] == 'HEURISTIC' else d['confidence']
                findings.append(row(fid, d['category'], d['indicator'], status, d['severity'], confirmation,
                    'NATIVE_POSTURE', assessment_id, at, source_rule_id=d['finding_id'], source_finding_id=d['finding_id'],
                    weakness_key=fid, observed_value=text(d['observed']), expected_value=text(d['expected']),
                    explanation=text(d['reason']), recommendation=text(d['recommendation']),
                    evidence={'observation': text(redact_cookie(d['evidence'])) if fid.startswith('COOKIE-') else text(d['evidence'])},
                    url=TARGET, source_severity=d['severity'], normalized_severity=d['severity']))
            status = 'COMPLETE'
            error = None
        except (requests.RequestException, ValueError) as exc:
            status, error = 'FAILED', 'Bounded native collection failed; no historical result substituted'
            error_code = failure_code(exc)
        finally:
            client.close()
        result = {'provider_id': self.provider_id, 'version': self.provider_version, 'status': status,
                  'started_at': start, 'completed_at': now(), 'findings': findings, 'error': error, 'error_code': error_code,
                  'provenance': {'requests': client.transcript, 'request_count': len(client.transcript),
                      'fresh_execution': True, 'native_rule_modules': ['generic_rules', 'cookies', 'tls'],
                      'failure_codes': sorted({r['error_code'] for r in client.transcript if r.get('error_code')} | ({error_code} if error_code else set())),
                      'authenticated_coverage': 'NOT_VALIDATED', 'policy': policy.export()}}
        self.results[assessment_id] = result
        return result


# No arbitrary API endpoint, active action, spider or command can be passed in.
ZAP_API = {
    ('core', 'view', 'version'), ('core', 'view', 'mode'), ('core', 'action', 'setMode'),
    ('core', 'view', 'urls'), ('core', 'view', 'numberOfMessages'), ('core', 'view', 'messages'),
    ('core', 'action', 'newSession'),
    ('pscan', 'view', 'recordsToScan'), ('pscan', 'action', 'setEnabled'),
    ('alert', 'view', 'alerts'), ('ascan', 'view', 'scans'), ('spider', 'view', 'scans'),
    ('ascan', 'view', 'scanners'),  # Read-only rule review, never scan dispatch.
}


class ZapAPI:
    def __init__(self, origin, api_key, session=None, clock=time.monotonic):
        p = urlsplit(origin)
        if (p.scheme != 'http' or p.hostname != '127.0.0.1' or not p.port or not 1024 <= p.port <= 65535
                or p.username or p.password or p.path not in ('', '/') or p.query or p.fragment):
            raise ValueError('ZAP control/proxy must be an explicit loopback port')
        self.origin = origin.rstrip('/'); self.key = api_key
        if session is None and os.getenv('COURSEWORK_OFFLINE')=='1':
            from coursework.lab import session as authorized_session
            session=authorized_session()
        self.session = session or requests.Session(); self.session.trust_env = False
        self.clock = clock

    def call(self, component, kind, name, control_deadline=None, **params):
        if (component, kind, name) not in ZAP_API: raise ValueError('ZAP endpoint outside passive allowlist')
        if component == 'ascan' and name == 'scanners' and params:
            raise ValueError('Only default installed scanner inventory inspection is permitted')
        if name == 'setMode' and params != {'mode': 'safe'}: raise ValueError('Only safe mode is permitted')
        if name == 'setEnabled' and params != {'enabled': 'true'}: raise ValueError('Passive scanning must remain enabled')
        # Unnamed volatile session only: no caller-controlled filename or overwrite.
        if name == 'newSession' and params: raise ValueError('Only a new unnamed session is permitted')
        if name == 'messages' and params != {'start': '0', 'count': str(MAX_HISTORY_MESSAGES + 1)}:
            raise ValueError('Only bounded complete history inspection is permitted')
        return self._fetch(component, kind, name, control_deadline, **params)

    def _fetch(self, component, kind, name, control_deadline=None, **params):
        """Shared bounded transport; each profile validates its own closed API surface."""
        at = self.clock()
        deadline = control_deadline if control_deadline is not None else float('inf')
        remaining = deadline - at
        if remaining <= 0: raise ProviderFailure('ASSESSMENT_DEADLINE_EXCEEDED')
        request_deadline = min(deadline, at + REQUEST_TIMEOUT_SECONDS)
        try:
            with self.session.get(f'{self.origin}/JSON/{component}/{kind}/{name}/', params=params,
                                  headers={'X-ZAP-API-Key': self.key}, timeout=request_timeout(remaining), allow_redirects=False, stream=True) as r:
                if r.status_code != 200:
                    # API error enums are useful provenance; messages/details may
                    # contain submitted URLs or secrets and are never exported.
                    import json,re
                    body=bytearray()
                    for block in r.iter_content(1024):
                        body.extend(block)
                        if len(body)>4096:break
                        check_deadline(self.clock,deadline,request_deadline)
                    try:code=json.loads(body).get('code','')
                    except (ValueError,AttributeError):code=''
                    cause='ZAP_'+code.upper() if isinstance(code,str) and re.fullmatch(r'[A-Za-z0-9_]{1,60}',code) else 'HTTP_ERROR'
                    raise ProviderFailure('HTTP_ERROR',cause)
                check_deadline(self.clock, deadline, request_deadline)
                data = bytearray()
                for block in r.iter_content(65536):
                    data.extend(block)
                    if len(data) > 5_000_000: raise ProviderFailure('RESPONSE_SIZE_LIMIT')
                    check_deadline(self.clock, deadline, request_deadline)
                check_deadline(self.clock, deadline, request_deadline)
                import json
                result = json.loads(data)
            if not isinstance(result, dict) or 'code' in result: raise ValueError('Invalid API result')
        except (requests.RequestException, ValueError) as exc:
            raise ProviderFailure('ZAP_API_UNAVAILABLE', getattr(exc,'cause_code',None) or failure_code(exc)) from None
        return result


def zap_findings(alerts, assessment_id, at):
    findings, sanitized, excluded = [], [], 0
    for a in alerts:
        url = a.get('url', '')
        if not scoped(url) or urlsplit(url).path not in {'/moodle/' + p for p in PAGES}:
            excluded += 1; continue
        plugin = str(a.get('pluginId', a.get('pluginid', '')))
        if not plugin.isdigit(): raise ValueError('Malformed ZAP rule identity')
        risk = str(a.get('riskcode', a.get('risk', '')))
        confidence = str(a.get('confidencecode', a.get('confidence', '')))
        severity = {'0': 'INFO', '1': 'LOW', '2': 'MEDIUM', '3': 'HIGH',
                    'Informational': 'INFO', 'Low': 'LOW', 'Medium': 'MEDIUM', 'High': 'HIGH'}.get(risk)
        if severity is None or confidence not in ('0', '1', '2', '3', '4', 'False Positive', 'Low', 'Medium', 'High', 'User Confirmed'):
            raise ValueError('Malformed ZAP severity/confidence')
        mapping = ZAP_RULES.get(plugin)
        param = a.get('param', '')
        if plugin in ('10010', '10011', '10054') and param != 'MoodleSession': mapping = None
        fid, category, title = mapping or ('ZAP-' + plugin, 'UNMAPPED', 'Unmapped passive rule ' + plugin)
        source_id = 'ZAP-' + plugin + '-' + sha([url, param, a.get('id')])[:16]
        false_positive = confidence in ('0', 'False Positive')
        status = 'DISMISSED' if false_positive else 'FAIL' if mapping else 'NOT_REEVALUATED'
        # Only safe structural fields leave this adapter. Arbitrary alert payload,
        # attack/otherInfo, bodies and parameter VALUES are never exported.
        safe = {'source_finding_id': source_id, 'source_rule_id': plugin, 'url': safe_url(url),
                'parameter': 'MoodleSession' if param == 'MoodleSession' else None,
                'source_severity': risk, 'source_confidence': confidence, 'normalized_severity': severity,
                'cwe': str(a.get('cweid', '')) if str(a.get('cweid', '')).isdigit() else None,
                'wasc': str(a.get('wascid', '')) if str(a.get('wascid', '')).isdigit() else None,
                'rule_reference': 'https://www.zaproxy.org/docs/alerts/' + plugin + '/',
                'sanitized_evidence': evidence_digest(a.get('evidence'))}
        sanitized.append(safe)
        findings.append(row(fid, category, title, status, severity,
            'FALSE_POSITIVE' if false_positive else 'NOT_CONFIRMED' if mapping else 'NOT_TESTED',
            'OWASP_ZAP', assessment_id, at, **safe, confidence=confidence, weakness_key=fid if mapping else source_id,
            evidence=safe['sanitized_evidence'],
            explanation='Passive scanner observation; exploitability and successful exploitation are not established.',
            recommendation='Review the passive rule evidence and validate the relevant control; ' + safe['rule_reference']))
    return findings, sanitized, excluded


class ZapPassiveProvider(ExternalScannerProvider):
    provider_id = 'zap'
    provider_name = 'OWASP ZAP Passive'

    def __init__(self, api=None, client_factory=StrictClient, clock=time.monotonic, pause=time.sleep, owned_ephemeral=None):
        super().__init__(); self.api = api; self.client_factory = client_factory
        self.configuration_error = False
        self.clock, self.pause = clock, pause
        # Only a dedicated owned daemon may have its volatile session replaced.
        # Injected non-HTTP APIs are trusted test dependencies, not frontend input.
        self.owned_ephemeral = (os.getenv('POSTURE_ZAP_OWNED_EPHEMERAL') == '1'
            if api is None or isinstance(api, ZapAPI) else True) if owned_ephemeral is None else owned_ephemeral
        if api is None and os.getenv('POSTURE_ZAP_OWNED_EPHEMERAL') == '1' and os.getenv('POSTURE_ZAP_API_KEY'):
            try:
                self.api = ZapAPI(os.getenv('POSTURE_ZAP_API_ORIGIN', 'http://127.0.0.1:8081'), os.environ['POSTURE_ZAP_API_KEY'])
            except ValueError:
                self.configuration_error = True

    def availability(self, control_deadline=None):
        if self.api is None:
            return {'provider_id': 'zap', 'status': 'UNAVAILABLE', 'runtime': 'INVALID_LOOPBACK_CONFIGURATION' if self.configuration_error else 'UNAVAILABLE_PENDING_INSTALL',
                    'version': None, 'mode': 'PASSIVE_BASELINE', 'active_scanner': 'DISABLED', 'error_code': 'ZAP_API_UNAVAILABLE'}
        try:
            kw = {'control_deadline': control_deadline} if isinstance(self.api, ZapAPI) else {}
            version = str(self.api.call('core', 'view', 'version', **kw)['version'])
            import re
            if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}', version): raise ValueError('Invalid runtime version')
            return {'provider_id': 'zap', 'status': 'AVAILABLE', 'version': version,
                    'mode': 'PASSIVE_BASELINE', 'active_scanner': 'DISABLED'}
        except (requests.RequestException, ValueError, KeyError) as exc:
            return {'provider_id': 'zap', 'status': 'UNAVAILABLE', 'version': None,
                    'runtime': 'CONFIGURED_DAEMON_UNAVAILABLE', 'active_scanner': 'DISABLED',
                    'error_code': 'ZAP_API_UNAVAILABLE', 'cause_code': getattr(exc, 'cause_code', None) or failure_code(exc)}

    def readiness(self):
        """Read-only readiness; session creation occurs only on assessment start."""
        deadline = self.clock() + 8
        available = self.availability(control_deadline=deadline)
        state = dict(available, runtime_status=available['status'], assessment_readiness='POLICY_BLOCKED')
        if available['status'] != 'AVAILABLE':
            state['reason_code'] = 'ZAP_API_UNAVAILABLE'
            return state
        if not self.owned_ephemeral:
            state['reason_code'] = 'OWNED_EPHEMERAL_RUNTIME_REQUIRED'
            return state
        issued = [control_url(self.api.origin, 'core', 'view', 'version', {})]
        def read(component, name, **params):
            issued.append(control_url(self.api.origin, component, 'view', name, params))
            kw = {'control_deadline': deadline} if isinstance(self.api, ZapAPI) else {}
            return self.api.call(component, 'view', name, **kw, **params)
        try:
            if (read('core', 'mode')['mode'] != 'safe' or read('ascan', 'scans')['scans']
                    or read('spider', 'scans')['scans']):
                state['reason_code'] = 'PASSIVE_ISOLATION_REQUIRED'
                return state
            count = int(read('core', 'numberOfMessages')['numberOfMessages'])
            if count < 0: raise ValueError('Invalid history count')
            state.update(assessment_readiness='READY', reason_code=None,
                         session_lifecycle='NEW_UNNAMED_SESSION_ON_START', history_messages_before_start=count,
                         explanation='A fresh isolated session will be created and verified before collection; existing saved posture snapshots remain immutable.')
        except (requests.RequestException, ValueError, KeyError, TypeError):
            state['reason_code'] = 'READINESS_CHECK_FAILED'
        return state

    def start_assessment(self, assessment_id, policy, target_id=TARGET_ID):
        self.target_validation(target_id); PassivePolicy(**policy.export())
        start = now(); deadline = self.clock() + policy.max_duration_seconds
        available = self.availability(control_deadline=deadline)
        result = {'provider_id': 'zap', 'status': 'UNAVAILABLE', 'version': available.get('version'),
                  'started_at': start, 'completed_at': start, 'findings': [],
                  'provenance': {'policy': policy.export(), 'authenticated_coverage': 'NOT_VALIDATED'}}
        if available['status'] != 'AVAILABLE':
            result.update(error_code=available['error_code'], cause_code=available.get('cause_code'), completed_at=now())
            self.results[assessment_id] = result; return result
        client = None
        stage = 'control'
        issued_controls = [control_url(self.api.origin, 'core', 'view', 'version', {})]
        def control(component, kind, name, **params):
            issued_controls.append(control_url(self.api.origin, component, kind, name, params))
            if isinstance(self.api, ZapAPI):
                return self.api.call(component, kind, name, control_deadline=deadline, **params)
            return self.api.call(component, kind, name, **params)

        def reject_scope(reason):
            diag = result.setdefault('scope_integrity', {'result': 'FAIL', 'failure_reasons': []})
            diag['result'] = 'FAIL'
            if reason not in diag['failure_reasons']: diag['failure_reasons'].append(reason)
            raise ProviderFailure('SCOPE_INTEGRITY_FAILURE')

        def inspect_history(urls, transcript, phase):
            count = int(control('core', 'view', 'numberOfMessages')['numberOfMessages'])
            messages = control('core', 'view', 'messages', start='0', count=str(MAX_HISTORY_MESSAGES + 1))['messages']
            diag, classes = review_history(messages, urls, transcript, issued_controls, count)
            result['scope_integrity'] = dict(diag, phase=phase)
            if diag['result'] != 'PASS': raise ProviderFailure('SCOPE_INTEGRITY_FAILURE')
            return classes
        try:
            if not self.owned_ephemeral: raise ProviderFailure('OWNED_EPHEMERAL_RUNTIME_REQUIRED')
            if control('ascan', 'view', 'scans')['scans']: reject_scope('ACTIVE_SCAN_PRESENT')
            if control('spider', 'view', 'scans')['scans']: reject_scope('SPIDER_PRESENT')
            if control('core', 'view', 'mode')['mode'] != 'safe': reject_scope('SAFE_MODE_NOT_ENFORCED')
            lifecycle = result['provenance']['session_lifecycle'] = {
                'state': 'REQUESTED', 'assessment_session_id': assessment_id,
                'zap_session_type': 'UNNAMED_VOLATILE', 'saved_snapshots_modified': False,
                'history_messages_before_creation': int(control('core', 'view', 'numberOfMessages')['numberOfMessages'])}
            stage = 'session'
            if control('core', 'action', 'newSession').get('Result') != 'OK':
                raise ProviderFailure('ZAP_SESSION_CREATION_FAILED')
            lifecycle['state'] = 'CREATED'
            stage = 'control'
            control('core', 'action', 'setMode', mode='safe')
            if control('core', 'view', 'mode')['mode'] != 'safe': reject_scope('SAFE_MODE_NOT_ENFORCED')
            # Verify the new session really is empty. Failed/no-op reset cannot leak old alerts.
            urls = control('core', 'view', 'urls')['urls']
            inspect_history(urls, [], 'NEW_SESSION_PREFLIGHT')
            lifecycle.update(state='VERIFIED_EMPTY', target_messages_before_collection=0)
            if control('alert', 'view', 'alerts', baseurl=TARGET, start='0', count='1')['alerts'] != []:
                reject_scope('PREEXISTING_ALERTS_AFTER_NEW_SESSION')
            if int(control('pscan', 'view', 'recordsToScan')['recordsToScan']) != 0:
                reject_scope('NONEMPTY_PASSIVE_QUEUE_AFTER_NEW_SESSION')
            control('pscan', 'action', 'setEnabled', enabled='true')
            client = self.client_factory(policy, proxy=self.api.origin)
            if isinstance(client, StrictClient): client.deadline = min(client.deadline, deadline)
            stage = 'proxy'
            for rel in PAGES:
                if self.clock() >= deadline: raise ProviderFailure('ASSESSMENT_DEADLINE_EXCEEDED')
                client.get(TARGET + rel, allow_redirects=False)
            stage = 'queue'
            while int(control('pscan', 'view', 'recordsToScan')['recordsToScan']) != 0:
                remaining = deadline - self.clock()
                if remaining <= 0: raise ProviderFailure('PASSIVE_QUEUE_TIMEOUT')
                self.pause(min(.25, remaining))
            stage = 'control'
            alerts = control('alert', 'view', 'alerts', baseurl=TARGET, start='0', count='501')['alerts']
            if not isinstance(alerts, list) or len(alerts) > 500: raise ValueError('Passive alert budget exceeded')
            urls = control('core', 'view', 'urls')['urls']
            if control('core', 'view', 'mode')['mode'] != 'safe': reject_scope('SAFE_MODE_NOT_ENFORCED')
            if control('ascan', 'view', 'scans')['scans']: reject_scope('ACTIVE_SCAN_PRESENT')
            if control('spider', 'view', 'scans')['scans']: reject_scope('SPIDER_PRESENT')
            classes = inspect_history(urls, client.transcript, 'POST_COLLECTION')
            target_alerts, excluded_internal = [], 0
            for alert in alerts:
                url = alert.get('url', '')
                kind = classes.get(url)
                if kind == 'TARGET': target_alerts.append(alert)
                elif kind in ('CONTROL_PLANE', 'INTERNAL_SITE_TREE_ANCESTOR'): excluded_internal += 1
                else:
                    diag = result['scope_integrity']
                    o, p = structural(url, {'/moodle/' + rel for rel in PAGES})
                    for key, value in (('unexpected_origins', o), ('unexpected_paths', p)):
                        if value not in diag[key] and len(diag[key]) < 20: diag[key].append(value)
                    reject_scope('UNOWNED_ALERT_URL')
            findings, sanitized, excluded = zap_findings(target_alerts, assessment_id, now())
            if excluded: reject_scope('UNEXPECTED_TARGET_ALERT')
            result.update(status='COMPLETE', findings=findings, sanitized_alerts=sanitized,
                          raw_alerts_sha256=sha(__import__('json').dumps(alerts, sort_keys=True)),
                          risk_distribution=dict(Counter(a['source_severity'] for a in sanitized)),
                          confidence_distribution=dict(Counter(a['source_confidence'] for a in sanitized)),
                          raw_alert_count=len(alerts), excluded_non_target_alert_count=excluded_internal,
                          urls_observed=sum(kind == 'TARGET' for kind in classes.values()),
                          messages_observed=result['scope_integrity']['total_history_messages'],
                          passive_queue_complete=True)
            lifecycle.update(state='COLLECTED', fresh_target_requests=len(client.transcript),
                passive_queue_complete=True, fresh_alert_count=len(findings),
                mapped_alert_count=sum(f['category'] != 'UNMAPPED' for f in findings),
                unmapped_alert_count=sum(f['category'] == 'UNMAPPED' for f in findings),
                scope_integrity=result['scope_integrity']['result'])
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            code, cause = failure_code(exc), getattr(exc, 'cause_code', None)
            if stage == 'session': code, cause = 'ZAP_SESSION_CREATION_FAILED', code
            if 'session_lifecycle' in result['provenance']:
                result['provenance']['session_lifecycle'].update(state='FAILED', error_code=code)
            if stage == 'proxy' and code in ('CONNECT_TIMEOUT', 'READ_TIMEOUT', 'TARGET_UNREACHABLE', 'ZAP_PROXY_FAILURE'):
                code, cause = 'ZAP_PROXY_FAILURE', code
            if stage == 'queue' and (code == 'ASSESSMENT_DEADLINE_EXCEEDED' or cause == 'ASSESSMENT_DEADLINE_EXCEEDED'):
                code = 'PASSIVE_QUEUE_TIMEOUT'
            result.update(status='FAILED', findings=[], error_code=code, cause_code=cause,
                          error='Passive runtime/scope/queue integrity failed; no scanner payload or secrets exported')
        finally:
            if client:
                result['provenance'].update(requests=client.transcript, request_count=len(client.transcript))
                client.close()
        result['completed_at'] = now(); self.results[assessment_id] = result
        return result
