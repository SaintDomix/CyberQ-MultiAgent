"""Current execution of accepted Branch1 modules; never replay historical results."""
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import time
from urllib.parse import urlsplit, urljoin

import requests
from branch1 import external, internal, intelligence, Context
from branch1.common import Document
from branch1.external_rules.moodle_rules import MoodleRules
from .model import row, COOKIE_IDS
from .policy import TARGET, PAGES
from .privacy import text, safe_url, sha
from .providers import NativePostureProvider, StrictClient, ProviderFailure, now, failure_code
from .native_plan import NativeAssessmentPolicy, budget, MAX_REDIRECT_HOPS

# Literal paths already probed by GenericRules/MoodleRules, not a crawler.
NATIVE_PATHS = {'/moodle/' + p for p in PAGES} | {
    '/server-status', '/phpinfo.php', '/.git/HEAD', '/.env', '/composer.lock',
    '/vendor/composer/installed.json', '/moodle/__security_assessment_nonexistent_7f4a9c',
    '/moodle/admin/environment.php', '/moodle/report/security/index.php', '/moodle/admin/tool/health/',
    '/moodle/README.txt', '/moodle/lib/upgrade.txt', '/moodle/composer.json', '/moodle/package.json',
    '/moodle/phpunit.xml.dist', '/moodle/Gruntfile.js', '/moodle/install.php', '/moodle/admin/index.php', '/moodledata/', '/moodle/moodledata/'}
SETTINGS = {'wwwroot', 'passwordpolicy', 'forceloginforprofiles', 'opentogoogle', 'allowobjectembed',
    'preventexecpath', 'allowframembedding', 'lockoutthreshold', 'registerauth', 'curlsecurityblockedhosts',
    'curlsecurityallowedport', 'debugdisplay', 'debug', 'cookiesecure', 'cookiehttponly', 'sslproxy', 'enablewebservices'}


def safe(value):
    if isinstance(value, dict): return {str(k): safe(v) for k,v in value.items()}
    if isinstance(value, list): return [safe(v) for v in value[:2000]]
    return text(value) if isinstance(value, str) else value


def missing_prerequisite(fid):
    if fid.startswith('ROLE-'): return 'Fresh verified student/admin identities, distinct ephemeral sessions and reviewed content/capability markers are required; historical role results are not reused.'
    if fid == 'PATCH-001': return 'An explicit branch-compatible POSTURE_PATCH_BASELINE is required; no latest-release baseline is invented.'
    if fid.startswith(('FS-', 'AUTH-INT-', 'SESSION-INT-', 'CFG-', 'PRIV-', 'SSRF-DEF-', 'PLUGIN-', 'PHP-')):
        return 'Fresh readable Moodle collector/configuration evidence is required; filesystem web-server assertions require matching collector UID and web-SAPI assertions require web-SAPI evidence.'
    return 'Fresh successful response within the calculated complete native-plan budget and reviewed endpoint scope is required.'


class NativeClient(StrictClient):
    """Bounded original native probes, isolated from the narrower ZAP profile."""
    allowed_methods = ('GET', 'OPTIONS', 'TRACE')

    def __init__(self, policy, **kw):
        super().__init__(policy, **kw)
        self.cache, self.cache_hits = {}, 0
        self.installer_allowed = False
        self.session.auth = None
        self.session.headers.pop('Cookie', None); self.session.headers.pop('Authorization', None)
        self.session.cookies.clear()

    def allowed_url(self, url):
        try:
            p = urlsplit(url)
            if p.path == '/moodle/install.php' and not self.installer_allowed: return False
            # Fixed public transitions in the installed Moodle source:
            # install.php -> lang=en; admin/index.php:800 -> cache=1 -> require_login.
            # No cache=0, upgrade key, sesskey or arbitrary query is admitted.
            query_ok = not p.query or (p.path == '/moodle/admin/index.php'
                and p.query in ('lang=en','cache=1') and self.installer_allowed)
            return (p.scheme == 'http' and p.hostname == '192.168.226.132' and p.port in (None, 80)
                    and not p.username and not p.password and query_ok and not p.fragment
                    and p.path in NATIVE_PATHS and not any(ord(c)<32 for c in url))
        except (ValueError, TypeError): return False

    def request(self, method, url, **kw):
        if set(kw)-{'headers','allow_redirects'} or method not in self.allowed_methods or not self.allowed_url(url):
            raise ProviderFailure('SCOPE_INTEGRITY_FAILURE')
        key = (method, url, tuple(sorted(kw.get('headers', {}).items())), kw.get('allow_redirects', True))
        if self.clock() >= self.deadline: raise ProviderFailure('ASSESSMENT_DEADLINE_EXCEEDED')
        if key in self.cache:
            self.cache_hits += 1
            return self.cache[key]
        # Cache each completed hop as well as the final request result. Thus an
        # early home->my->login redirect does not force a second login GET later.
        # Keep methods and CORS header variants distinct; no cross-run reuse.
        headers, follow = kw.get('headers', {}), kw.get('allow_redirects', True)
        for _ in range(MAX_REDIRECT_HOPS+1):
            if not self.allowed_url(url): raise ProviderFailure('SCOPE_INTEGRITY_FAILURE')
            if self.clock() >= self.deadline: raise ProviderFailure('ASSESSMENT_DEADLINE_EXCEEDED')
            raw_key=(method,url,tuple(sorted(headers.items())),False)
            if raw_key in self.cache:
                self.cache_hits += 1; result=self.cache[raw_key]
            else:
                result=super().request(method,url,headers=headers,allow_redirects=False)
                self.cache[raw_key]=result
            if follow and result.status_code in (301,302,303,307,308) and result.headers.get('Location'):
                url=urljoin(url,result.headers['Location'])
                continue
            self.cache[key]=result
            return result
        raise ProviderFailure('SCOPE_INTEGRITY_FAILURE')

    def cached_redirect(self, method, url, headers):
        key = (method, url, tuple(sorted(headers.items())), True)
        if key in self.cache:
            self.cache_hits += 1
            return self.cache[key]
        return None

    def trace(self, url, **kw):
        self.session.cookies.clear()  # Never echo even an anonymous session cookie.
        return self.request('TRACE', url, **kw)


def fresh_internal(project, moodle_root, deadline, clock=time.monotonic):
    """Run the existing CLI collector only with ordinary read permission, no sudo."""
    root = Path(moodle_root)
    payload = {'core': {}, 'settings': {}, 'filesystem': {}, 'runtime': {'collector_euid': os.geteuid()}}
    reason, sources = None, {}
    version = root/'version.php'
    if version.is_file() and os.access(version, os.R_OK):
        data = version.read_bytes()
        if len(data) <= 65536:
            source = data.decode('utf-8', errors='replace')
            for key, pattern in {'version': r'\$version\s*=\s*(\d+(?:\.\d+)?)\s*;',
                'branch': r'\$branch\s*=\s*[\'\"](\d+)[\'\"]\s*;',
                'release': r'\$release\s*=\s*[\'\"]([^\'\"]+)[\'\"]\s*;'}.items():
                match = re.search(pattern, source)
                if match: payload['core'][key] = match.group(1)
            sources['version.php'] = {'sha256': sha(data), 'source': str(version)}
    php = shutil.which('php')
    collector = Path(project)/'legacy/branch1/moodle_deep_v2_role_pack/server_collector_v2.php'
    if not (root/'config.php').is_file(): reason = 'MOODLE_CONFIG_NOT_FOUND'
    elif not os.access(root/'config.php', os.R_OK): reason = 'MOODLE_CONFIG_NOT_READABLE_BY_DEMO_UID'
    elif not php or not collector.is_file(): reason = 'EXISTING_PHP_COLLECTOR_UNAVAILABLE'
    elif deadline-clock() <= 0: reason = 'ASSESSMENT_DEADLINE_EXCEEDED'
    else:
        try:
            result = subprocess.run([php, str(collector), str(root)], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=min(15, deadline-clock()), check=True)
            if len(result.stdout)>2_000_000: raise ValueError('Collector response cap')
            data = json.loads(result.stdout)
            # No database connection fields, error messages or arbitrary config keys survive.
            for section, keys in {'core': {'version','release','branch'}, 'settings': SETTINGS,
                'filesystem': {'config_permissions','config_owner','config_writable_by_collector_user',
                    'dirroot_permissions','dirroot_owner','dirroot_writable_by_collector_user','dataroot_inside_dirroot'},
                'runtime': {'collector_euid','sapi','php_version','display_errors'}}.items():
                payload[section] = safe({k:v for k,v in data.get(section, {}).items() if k in keys})
            auth = data.get('enabled_auth_plugins')
            payload['enabled_auth_plugins'] = auth if isinstance(auth,list) and all(isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9_]+',v) for v in auth) else ['__collector_error__']
            if isinstance(data.get('plugins'), list):
                payload['plugins'] = safe([{k:v for k,v in p.items() if k in {'type','name','component','standard','enabled','versiondisk','versiondb','release'}}
                                          for p in data['plugins'] if isinstance(p,dict) and 'collector_error' not in p])
            sources['collector'] = {'source': str(collector.relative_to(project)), 'sha256': sha(collector.read_bytes())}
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError):
            reason = 'INTERNAL_COLLECTOR_FAILED_OR_TIMED_OUT'
    return payload, {'collector_status': 'NOT_AVAILABLE' if reason else 'COMPLETE',
                     'reason_code': reason, 'sources': sources, 'collector_euid': os.geteuid()}


def existing_active(project, prefix, records, client, enabled):
    """Reuse the accepted planner/gate/executor; linked results never replace parents."""
    from branch1.active import SafetyPolicy, run_active
    from branch1.active.runtime import RuntimeContext
    from branch1.active.safety import Executor, SafetyError
    runtime = RuntimeContext.from_env('B1_ACTIVE_CONTEXT') if os.environ.get('B1_ACTIVE_CONTEXT') else RuntimeContext()
    remaining = min(8, max(0, client.policy.max_requests-len(client.transcript)))
    active = enabled and remaining > 0 and client.deadline-client.clock() > 5
    policy = SafetyPolicy(TARGET, active, True, max(1,remaining), 5, .25)
    ctx = Context(project, output=project/Path(prefix).parent)
    class DeadlineExecutor(Executor):
        def get(self, spec):
            # Leave enough time for the accepted rate limit and bounded request.
            if client.deadline-client.clock() <= self.policy.timeout+4:
                raise SafetyError('Native assessment deadline exhausted')
            return super().get(spec)
    executor = DeadlineExecutor(policy, runtime=runtime, clock=client.clock) if active else None
    try:
        summary = run_active(ctx, records, policy, executor=executor, runtime=runtime)
        # Original active pipeline keeps child evidence separate from posture parents.
        return {'summary': summary, 'results': safe(ctx.artifacts['active_validation_results.json']),
                'transcript': safe(ctx.artifacts['active_validation_evidence.json']),
                'parent_results_overwritten':False, 'reason': None if active else
                'Execution requires POSTURE_ENABLE_EXISTING_ACTIVE=1, runtime prerequisites and remaining shared request/time budget.'}
    finally:
        if executor: executor.session.close()


class Branch1CurrentProvider(NativePostureProvider):
    provider_version = 'accepted-branch1-modules / operational-wrapper-2.0'

    def __init__(self, project, client_factory=NativeClient, collector=fresh_internal, clock=time.monotonic,
                 moodle_root='/var/www/html/moodle'):
        super().__init__(client_factory)
        self.project, self.collector, self.clock, self.moodle_root = Path(project), collector, clock, moodle_root

    def start_assessment(self, assessment_id, policy, target_id='moodle-local',absolute_deadline=None):
        self.target_validation(target_id)
        # Server-derived native budget; never increase the independent ZAP policy.
        policy = NativeAssessmentPolicy()
        client = self.client_factory(policy); start = now(); findings = []; errors = []
        if absolute_deadline is not None:client.deadline=min(client.deadline,absolute_deadline)
        client.installer_allowed = (Path(self.moodle_root)/'config.php').is_file()
        prefix = f'runtime/posture/{assessment_id}/native.json'
        result = {'provider_id':'native', 'version':self.provider_version, 'started_at':start,
            'status':'FAILED', 'findings':[], 'provenance':{'fresh_execution':True, 'policy':policy.export(),
                'assessment_budget':budget()}}
        if absolute_deadline is not None:
            result['provenance']['whole_assessment_deadline_applied']=True
        try:
            payload, local = self.collector(self.project, self.moodle_root, client.deadline, self.clock)
            document = Document.generated(prefix+'#fresh-internal', payload)
            try: web_uid = pwd.getpwnam('www-data').pw_uid
            except KeyError: web_uid = None
            records = internal.assess(document, web_uid)
            advisory = Document.load(self.project/'src/branch1/advisories.json', self.project)
            raw_baseline = os.environ.get('POSTURE_PATCH_BASELINE')
            baseline = int(raw_baseline) if raw_baseline and raw_baseline.isdigit() else None
            records += intelligence.assess(document, advisory, baseline)
            for method in ('options','trace'):
                try: getattr(client, method)(TARGET)
                except requests.RequestException: pass
            # Prioritize the Moodle module's all-or-nothing collection. The accepted
            # external wrapper then reuses only fresh cached responses, sharing one budget.
            moodle_state = {'status':'COMPLETE','implementation':'branch1.external_rules.moodle_rules.MoodleRules.run'}
            moodle_observations = []
            try: moodle_observations, _ = MoodleRules(client, TARGET).run()
            except (requests.RequestException, ValueError) as exc:
                moodle_state.update(status='NOT_REEVALUATED',reason_code=failure_code(exc))
            external_records, artifact = external.assess(TARGET, prefix+'#external', client=client)
            # A later generic/module failure must not discard a completed fresh
            # Moodle prepass. Reuse the accepted row adapter, not historical verdicts.
            existing_ids = {r.finding_id for r in external_records}
            from branch1.common import finding as branch1_finding
            for index, observation in enumerate(moodle_observations):
                raw = observation.to_dict()
                if raw['finding_id'] in existing_ids: continue
                state, tag = raw['status'], raw['confidence']
                confirmation = ('NOT_APPLICABLE' if state == 'NOT_APPLICABLE' else
                    'NOT_TESTED' if state in ('ERROR','NOT_TESTED') else 'NOT_CONFIRMED' if tag == 'HEURISTIC' else tag)
                fresh = Document.generated(prefix+'#completed-moodle', raw)
                external_records.append(branch1_finding(fresh, 'external', raw['finding_id'], raw['category'],
                    raw['indicator'], state, confirmation, raw['severity'], raw['observed'], raw['expected'],
                    raw['reason'], raw['recommendation'], evidence={'observation':raw}, asset=TARGET, index=index))
            records += external_records
            errors = artifact.get('errors', [])
            active_result = {'status':'DEFERRED', 'reason':'Current active validation runs once after Native/ZAP canonicalization; no active request is sent by this provider.'}
            for item in records:
                d = item.to_dict(); fid = COOKIE_IDS.get(d['finding_id'], d['finding_id'])
                status = 'NOT_REEVALUATED' if d['check_result'] in ('ERROR','NOT_TESTED') else d['check_result']
                reason = None
                if status == 'NOT_REEVALUATED':
                    reason = local.get('reason_code') if d['evidence_source']=='internal' else None
                    if not reason and d['evidence_source']=='external':
                        reason = ('ASSESSMENT_DEADLINE_EXCEEDED' if client.clock()>=client.deadline else
                                  'REQUEST_BUDGET_EXCEEDED' if len(client.transcript)>=policy.max_requests else 'BOUNDED_EXTERNAL_RESPONSE_UNAVAILABLE')
                    reason = reason or missing_prerequisite(fid)
                findings.append(row(fid,d['category'],d['finding_type'],status,d['severity'],
                    'NOT_TESTED' if status=='NOT_REEVALUATED' else d['confirmation_status'], 'NATIVE_POSTURE',assessment_id,now(),
                    weakness_key=fid, source_finding_id=d['finding_id'], source_rule_id=d['finding_id'],
                    explanation=text(d.get('explanation')), recommendation=text(d.get('recommendation')),
                    observed_value=safe(d.get('observed_value')), expected_value=safe(d.get('expected_value')),
                    evidence=safe(d.get('evidence')), prerequisite_reason=reason,
                    source_provenance=d.get('provenance'), affected_component=d.get('affected_component') or 'Moodle deployment',
                    url=safe_url(d.get('affected_asset') or TARGET)))
            result.update(status='COMPLETE' if any(f['operational_status']!='NOT_REEVALUATED' for f in findings) else 'FAILED',findings=findings)
            result['provenance'].update(local_collection=local, internal_evidence=payload,
                moodle_module=moodle_state,
                advisory_catalog={'path':advisory.path,'sha256':advisory.sha256},
                native_rule_modules=['branch1.external.assess','branch1.external_rules.moodle_rules.MoodleRules.run',
                    'branch1.internal.assess','branch1.intelligence.assess'],
                role_validation={'status':'NOT_REEVALUATED','reason':missing_prerequisite('ROLE-')},
                active_validation=active_result)
        except (OSError, ValueError, requests.RequestException, TypeError, KeyError) as exc:
            result.update(error_code=failure_code(exc),error='Current Branch1 collection failed closed; no historical result substituted')
        finally:
            result['provenance'].update(requests=client.transcript,request_count=len(client.transcript),
                cache_hits=getattr(client,'cache_hits',0), cache_semantics='This execution only; no historical response reuse',
                failure_codes=sorted({r['error_code'] for r in client.transcript if r.get('error_code')}),
                authenticated_coverage='NOT_VALIDATED', external_collection_errors_present=bool(errors))
            result['provenance']['total_request_count'] = len(client.transcript) + result['provenance'].get('active_validation',{}).get('summary',{}).get('requests_used',0)
            client.close()
        result['completed_at']=now();self.results[assessment_id]=result
        return result
