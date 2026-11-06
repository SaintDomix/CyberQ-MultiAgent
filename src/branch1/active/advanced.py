"""Small, read-only validation predicates; observations are not exploit claims."""
import html
from http.cookies import SimpleCookie, CookieError
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import Decision, Outcome, RequestSpec
from .validators import hint, context

PARAMETER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
DB_ERROR = re.compile(r"SQLSTATE\[[0-9A-Z]{5}\]|you have an error in your SQL syntax|unterminated quoted string|ORA-\d{5}|sqlite3?\.(?:OperationalError|DatabaseError)|unclosed quotation mark|PostgreSQL.*?ERROR", re.I)
DENIAL = re.compile(r"access denied|permission denied|not authorized|<input[^>]+name=[\"']password[\"']", re.I)


def header(response, key):
    return next((v for k, v in response.headers.items() if k.lower() == key.lower()), "")


def blocked(response):
    return response.status in {401, 403} or bool(re.search(r"login|auth", header(response, "location"), re.I)) or bool(DENIAL.search(response.text))


def outcome(name, status, reason, result="PARTIAL"):
    return Outcome(name, result, status, reason)


def set_parameter(url, parameter, value):
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != parameter]
    return urlunsplit(parts._replace(query=urlencode(pairs + [(parameter, value)])))


def normalized(response, ignored=()):
    text = response.text
    location = header(response, "location")
    for value in ignored:
        for form in (value, html.escape(value), urlencode({"v": value})[2:]):
            text = text.replace(form, "<controlled-input>")
            location = location.replace(form, "<controlled-input>")
    return response.status, location, re.sub(r"\s+", " ", text).strip()


class InputValidator:
    patterns = ()
    requirements = ("url", "parameter", "read_only=true")

    def propose(self, parent):
        ctx = context(parent)
        if not any(p in hint(parent) for p in self.patterns) and ctx.get("validator") != self.name:
            return None
        missing = []
        if not isinstance(ctx.get("url"), str): missing.append("url")
        if not isinstance(ctx.get("parameter"), str) or not PARAMETER.fullmatch(ctx["parameter"]): missing.append("parameter")
        if ctx.get("read_only") is not True: missing.append("read_only=true")
        for field in self.extra_requirements:
            if field not in ctx: missing.append(field)
        if ctx.get("session_ref") is not None and not isinstance(ctx["session_ref"], str): missing.append("string session_ref")
        if missing:
            return Decision("MISSING_CONTEXT", "Explicit runtime prerequisites missing: " + ", ".join(missing), tuple(missing), context=dict(ctx))
        return Decision("APPLICABLE", "Explicit bounded read-only input context", authentication_requirement=ctx.get("session_ref", "anonymous"), context=dict(ctx))

    extra_requirements = ()

    def spec(self, candidate, value, purpose, private=False):
        ctx = candidate.context
        return RequestSpec(set_parameter(ctx["url"], ctx["parameter"], value), purpose,
                           session_ref=ctx.get("session_ref"), private_parameters=(ctx["parameter"],) if private else ())


class SQLInjection(InputValidator):
    name = "sql_injection"
    patterns = ("sql injection", "sqli")
    extra_requirements = ("baseline_value",)

    def propose(self, parent):
        decision = super().propose(parent)
        if decision and decision.applicability == "APPLICABLE" and (not isinstance(decision.context["baseline_value"], str) or not re.fullmatch(r"[A-Za-z0-9 _.-]{0,128}", decision.context["baseline_value"])):
            return Decision("MISSING_CONTEXT", "Short string baseline_value required", ("baseline_value",))
        return decision

    def requests(self, candidate):
        value = candidate.context["baseline_value"]
        return [self.spec(candidate, v, "SQL syntax differential " + purpose) for v, purpose in
                [(value, "baseline"), (value + "'", "single inert quote"), (value, "baseline repeat"), (value + "'", "quote repeat")]]

    def evaluate(self, candidate, responses):
        base, test, base2, test2 = responses
        db = [bool(DB_ERROR.search(r.text)) for r in responses]
        if db == [False, True, False, True] and normalized(base) == normalized(base2) and normalized(test) == normalized(test2) and not any(blocked(r) for r in responses):
            return outcome("REPRODUCIBLE_DB_ERROR", "LIKELY", "Repeatable parser/database error only after quote perturbation; SQLi relevance likely, exploitability and data access unproven")
        if normalized(base) != normalized(test):
            return outcome("WEAK_DIFFERENTIAL", "NOT_CONFIRMED", "Response difference without stable database-specific differential; ordinary errors do not prove SQLi")
        return outcome("NO_SQLI_SIGNAL", "NOT_CONFIRMED", "No database-specific differential observed; does not establish safety", "PASS")


class UnsafeReflection(InputValidator):
    name = "unsafe_reflection_xss"
    patterns = ("xss", "unsafe reflection")

    def marker(self, candidate):
        return "B1" + candidate.candidate_id[-16:] + "<'\"&>"

    def requests(self, candidate):
        marker = self.marker(candidate)
        return [self.spec(candidate, v, "inert reflection " + purpose) for v, purpose in
                [("B1baseline", "baseline"), (marker, "marker"), (marker, "marker repeat")]]

    def evaluate(self, candidate, responses):
        baseline, first, second = responses
        marker = self.marker(candidate)
        token = marker.split('<')[0]
        if token in baseline.text or any(blocked(r) or r.status != 200 for r in responses):
            return outcome("INCONCLUSIVE", "NOT_CONFIRMED", "Baseline contamination, denial or non-success response prevents reflection classification")
        def classify(r):
            if token not in r.text: return "NO_REFLECTION"
            if marker not in r.text:
                return "ENCODED_REFLECTION" if html.escape(marker) in r.text else "AMBIGUOUS_REFLECTION"
            if 'html' not in header(r, 'content-type').lower(): return "RAW_REFLECTION"
            pos = r.text.index(marker)
            prefix = r.text[:pos]
            if prefix.rfind('<!--') > prefix.rfind('-->'): return 'AMBIGUOUS_REFLECTION'
            if prefix.lower().rfind('<script') > prefix.lower().rfind('</script'):
                return "UNSAFE_CONTEXT"
            if prefix.rfind('<') > prefix.rfind('>') and re.search(r"=\s*[\"'][^<>]*$", prefix):
                return "UNSAFE_CONTEXT"
            return "RAW_REFLECTION"
        kind = classify(first)
        if kind != classify(second):
            return outcome("INCONCLUSIVE", "NOT_CONFIRMED", "Reflection context did not reproduce")
        if kind == "UNSAFE_CONTEXT":
            return outcome("POTENTIALLY_UNSAFE_CONTEXT", "LIKELY", "Repeated inert delimiter reflection in HTML attribute/script context; no JavaScript executed and exploitable XSS unproven")
        if kind == "RAW_REFLECTION":
            return outcome(kind, "CONTEXTUAL", "Raw inert input reflected; context/exploitability not established")
        if kind == "AMBIGUOUS_REFLECTION":
            return outcome("INCONCLUSIVE", "NOT_CONFIRMED", "Marker partially reflected with ambiguous encoding/context")
        return outcome(kind, "NOT_CONFIRMED", "No unsafe reflection observed for this marker; not a system-wide XSS safety claim", "PASS")


class AccountEnumeration(InputValidator):
    name = "account_enumeration"
    patterns = ("enumeration", "password recovery", "account recovery")
    extra_requirements = ("test_identifiers", "lookup_only")

    def propose(self, parent):
        decision = super().propose(parent)
        if decision and decision.applicability == "APPLICABLE":
            ids = decision.context.get("test_identifiers")
            if decision.context.get("lookup_only") is not True or not isinstance(ids, list) or len(ids) != 2 or any(not isinstance(v, str) or not v or len(v) > 128 for v in ids) or ids[0] == ids[1]:
                return Decision("MISSING_CONTEXT", "Two distinct authorized test identifiers and lookup_only=true (no recovery email/state changes) required", ("test_identifiers", "lookup_only=true"))
        return decision

    def requests(self, candidate):
        a, b = candidate.context['test_identifiers']
        return [self.spec(candidate, v, "controlled account lookup comparison", private=True) for v in (a, b, a, b)]

    def evaluate(self, candidate, responses):
        a, b, a2, b2 = [normalized(r, candidate.context['test_identifiers']) for r in responses]
        if a == b == a2 == b2:
            return outcome("NO_ACCOUNT_DISTINCTION", "NOT_CONFIRMED", "No observable account distinction in four controlled lookups; timing not assessed", "PASS")
        if a == a2 and b == b2 and a != b and all(r.status < 500 for r in responses):
            return outcome("REPRODUCIBLE_ACCOUNT_DISTINCTION", "CONFIRMED", "Account-dependent status/redirect/normalized content distinction reproduced; confirms observable distinction only, no password attempts")
        return outcome("POSSIBLE_ENUMERATION_SIGNAL", "NOT_CONFIRMED", "Unstable or error responses make account distinction inconclusive; timing not assessed")


class AccessControl:
    name = "access_control"

    def propose(self, parent):
        ctx = context(parent)
        if not any(p in hint(parent) for p in ("access control", "capability checks")) and ctx.get('validator') != self.name: return None
        required = ('url', 'restricted_session', 'privileged_session', 'identity_markers', 'privileged_markers', 'restricted_role', 'privileged_role', 'expected_denied', 'read_only')
        missing = [k for k in required if k not in ctx]
        for k in ('privileged_markers',):
            if k in ctx and (not isinstance(ctx[k], list) or not ctx[k] or any(not isinstance(v, str) or not v for v in ctx[k])): missing.append(k)
        if not isinstance(ctx.get('identity_markers'), dict) or any(not isinstance(ctx.get('identity_markers', {}).get(r), str) or not ctx['identity_markers'][r] for r in ('restricted', 'privileged')): missing.append('identity_markers for both sessions')
        if isinstance(ctx.get('identity_markers'), dict) and ctx['identity_markers'].get('restricted') == ctx['identity_markers'].get('privileged'):
            missing.append('distinct identity markers')
        if not isinstance(ctx.get('url'), str): missing.append('url string')
        if any(not isinstance(ctx.get(k), str) or not ctx[k] for k in ('restricted_session', 'privileged_session', 'restricted_role', 'privileged_role')):
            missing.append('string session references and roles')
        if ctx.get('read_only') is not True or ctx.get('expected_denied') is not True: missing.append('explicit read_only=true and expected_denied=true policy')
        if ctx.get('restricted_session') == ctx.get('privileged_session') or ctx.get('restricted_role') == ctx.get('privileged_role'): missing.append('distinct sessions and roles')
        if missing: return Decision('MISSING_CONTEXT', 'Role/content prerequisites missing: ' + ', '.join(missing), tuple(missing), 'explicit authorized roles', dict(ctx))
        return Decision('APPLICABLE', 'Explicit role policy, identities and privileged content comparators', authentication_requirement='authorized restricted and privileged roles', context=dict(ctx))

    def requests(self, candidate):
        ctx = candidate.context
        return [RequestSpec(ctx['url'], 'role/content comparison ' + role, session_ref=ctx[role + '_session']) for role in ('restricted', 'privileged', 'restricted', 'privileged')]

    def evaluate(self, candidate, responses):
        low, high, low2, high2 = responses
        ctx = candidate.context
        markers = ctx['privileged_markers']
        def identity(role, response):
            other = 'privileged' if role == 'restricted' else 'restricted'
            return ctx['identity_markers'][role] in response.text and ctx['identity_markers'][other] not in response.text
        # Link-only differences remain review evidence, matching the existing role methodology.
        def content(response):
            return re.sub(r'<a\b[^>]*>.*?</a>', '', response.text, flags=re.I | re.S)
        admin_verified = all(r.status == 200 and not blocked(r) and identity('privileged', r)
                             and all(m in content(r) for m in markers) for r in (high, high2))
        denied = blocked(low) and blocked(low2)
        facts = {'privileged_comparator_verified': admin_verified, 'restricted_denied': denied,
                 'restricted_identity_verified': all(identity('restricted', r) for r in (low, low2)),
                 'statuses': [r.status for r in responses]}
        if denied:
            if not admin_verified:
                return Outcome('ROLE_DENIED', 'NOT_TESTED', 'NOT_TESTED', 'Restricted barrier observed but admin identity/privileged comparator incomplete', facts)
            return Outcome('ROLE_DENIED', 'PASS', 'NOT_CONFIRMED', 'Repeated restricted-role barrier with verified privileged-role content; no overall safety claim', facts)
        verified = admin_verified and all(identity('restricted', r) and r.status == 200 and not blocked(r) for r in (low, low2))
        if verified and all(all(m in content(r) for m in markers) for r in (low, low2)):
            return Outcome('RESTRICTED_PRIVILEGED_CONTENT', 'PARTIAL', 'LIKELY', 'Verified roles repeatedly receive explicitly restricted privileged content; capability/function execution not attempted', facts)
        return Outcome('INCONCLUSIVE', 'PARTIAL', 'NOT_CONFIRMED', 'HTTP 200, generic content or link differences alone do not establish unauthorized access', facts)


class SessionControl:
    name = 'session_control'

    @staticmethod
    def parent_predicate(parent):
        # Select from the parent's assertion, never from co-occurring attributes.
        title = (parent.finding_type or '').lower()
        fid = parent.finding_id.upper()
        if fid.endswith('-HTTPONLY') or 'httponly' in title:
            return 'httponly'
        if fid.endswith('-SAMESITE') or 'samesite' in title:
            return 'samesite'
        if fid.endswith('-SECURE') or 'secure-cookie' in title or ('cookie' in title and 'secure' in title):
            return 'secure'
        return None

    @staticmethod
    def configuration_assessment(ctx, attrs, predicate):
        # A reference is provenance, not a loaded/parsed configured expectation.
        aliases = {'cookiesecure': 'secure', 'cookiehttponly': 'httponly', 'cookiesamesite': 'samesite'}
        expected = {}
        for raw in (ctx.get('configured_settings', {}), ctx.get('configured_attributes', {})):
            for key, value in raw.items():
                key = aliases.get(key, key)
                if key in {'secure', 'httponly'}:
                    if isinstance(value, bool):
                        parsed = value
                    elif isinstance(value, int) and value in (0, 1):
                        parsed = bool(value)
                    elif isinstance(value, str) and value.strip().lower() in {'1', '0', 'true', 'false', 'on', 'off', 'yes', 'no'}:
                        parsed = value.strip().lower() in {'1', 'true', 'on', 'yes'}
                    else:
                        parsed = None
                elif key == 'samesite':
                    parsed = value.strip().lower() if isinstance(value, str) and value.strip().lower() in {'lax', 'strict', 'none'} else None
                elif key == 'transport':
                    parsed = value.lower() if isinstance(value, str) and value.lower() in {'http', 'https'} else None
                else:
                    continue
                expected[key] = parsed
        differences = {key: attrs[key] != expected[key] if expected.get(key) is not None else None for key in attrs}
        relevant = list(attrs) if predicate == 'all_attributes' else [predicate]
        comparisons = [differences[key] for key in relevant if key in expected]
        mismatch = True if True in comparisons else (False if comparisons and all(value is False for value in comparisons) else None)
        return {'configuration_mismatch': mismatch, 'configuration_comparisons': differences,
                'configured_expectations': expected,
                'configuration_assessment': 'ASSESSED' if mismatch is not None else 'NOT_ASSESSED',
                'configuration_scope': relevant}

    def propose(self, parent):
        ctx = context(parent)
        if not any(p in hint(parent) for p in ('session', 'httponly', 'samesite', 'cookie secure', 'cookie transport')) and ctx.get('validator') != self.name: return None
        ctx = dict(ctx)
        selected = self.parent_predicate(parent)
        supplied = ctx.get('session_predicate')
        if supplied is not None and (supplied not in {'secure', 'httponly', 'samesite', 'all_attributes'} or selected and supplied != selected):
            return Decision('MISSING_CONTEXT', 'Session predicate conflicts with parent or is unsupported', ('parent-consistent session_predicate',), context=ctx)
        ctx['session_predicate'] = selected or supplied or 'all_attributes'
        # Only explicit configuration observations are transferable, not prior HTTP flags.
        if 'configured_settings' not in ctx and isinstance(parent.observed_value, dict):
            settings = {k: v for k, v in parent.observed_value.items() if k in {'cookiesecure', 'cookiehttponly', 'cookiesamesite'}}
            if settings:
                ctx['configured_settings'] = settings
        missing = [k for k in ('url', 'cookie_name') if not isinstance(ctx.get(k), str) or not ctx[k]]
        if ctx.get('read_only') is not True: missing.append('read_only=true')
        if ctx.get('require_authenticated') is True:
            if not ctx.get('session_ref'): missing.append('session_ref')
            if not isinstance(ctx.get('authenticated_marker'), str) or not ctx.get('authenticated_marker'): missing.append('authenticated_marker')
        if ctx.get('invalidated_session') and (ctx.get('expected_invalidated') is not True or not ctx.get('authenticated_marker')):
            missing.append('expected_invalidated=true and authenticated_marker')
        if any(ctx.get(k) is not None and not isinstance(ctx[k], str) for k in ('session_ref', 'invalidated_session')): missing.append('string session references')
        for key in ('configured_attributes', 'configured_settings'):
            if key in ctx and not isinstance(ctx[key], dict): missing.append(key + ' object')
        if 'samesite_policy' in ctx and (not isinstance(ctx['samesite_policy'], list) or not ctx['samesite_policy'] or any(v not in {'lax', 'strict', 'none'} for v in ctx['samesite_policy'])):
            missing.append('samesite_policy list of lowercase lax/strict/none values')
        if missing: return Decision('MISSING_CONTEXT', 'Effective HTTP cookie context missing: ' + ', '.join(missing), tuple(missing), 'authorized session if required', dict(ctx))
        return Decision('APPLICABLE', 'Observe emitted session-cookie attributes on two read-only requests', authentication_requirement=ctx.get('session_ref', 'anonymous'), context=dict(ctx))

    def requests(self, candidate):
        ctx = candidate.context
        specs = [RequestSpec(ctx['url'], 'effective session-cookie observation', session_ref=ctx.get('session_ref')) for _ in range(2)]
        if ctx.get('invalidated_session'):
            specs.extend(RequestSpec(ctx['url'], 'previously invalidated authorized test session', session_ref=ctx['invalidated_session']) for _ in range(2))
        return specs

    def evaluate(self, candidate, responses):
        attributes = []
        lifecycle = 'NOT_TESTED'
        ctx = candidate.context
        if ctx.get('require_authenticated') and any(blocked(r) or ctx['authenticated_marker'] not in r.text for r in responses[:2]):
            return outcome('AUTH_CONTEXT_UNVERIFIED', 'NOT_TESTED', 'Supplied session identity not established in response', 'NOT_TESTED')
        if ctx.get('invalidated_session'):
            old = responses[2:]
            if all(blocked(r) for r in old): lifecycle = 'PREVIOUS_SESSION_DENIED'
            elif all(r.status == 200 and ctx['authenticated_marker'] in r.text for r in old): lifecycle = 'PREVIOUS_SESSION_STILL_AUTHENTICATED'
            else: lifecycle = 'INCONCLUSIVE'
        for r in responses[:2]:
            cookies = SimpleCookie()
            try: cookies.load(header(r, 'set-cookie'))
            except CookieError: return outcome('INCONCLUSIVE', 'NOT_CONFIRMED', 'Cookie header could not be parsed')
            cookie = cookies.get(candidate.context['cookie_name'])
            if not cookie or r.status >= 400:
                return outcome('COOKIE_NOT_OBSERVED', 'NOT_TESTED', 'Named session cookie not emitted consistently; configuration is not proof of effective behavior', 'NOT_TESTED')
            attributes.append({'secure': bool(cookie['secure']), 'httponly': bool(cookie['httponly']), 'samesite': cookie['samesite'].lower(), 'transport': urlsplit(r.url).scheme})
        if attributes[0] != attributes[1]: return outcome('INCONCLUSIVE', 'NOT_CONFIRMED', 'Effective cookie attributes were inconsistent')
        attrs = attributes[0]
        predicate = ctx['session_predicate']
        configuration = self.configuration_assessment(ctx, attrs, predicate)
        samesite_weakness = attrs['samesite'] not in ctx.get('samesite_policy', ['lax', 'strict', 'none']) or (attrs['samesite'] == 'none' and not attrs['secure'])
        if predicate == 'secure':
            weakness = not attrs['secure']
        elif predicate == 'httponly':
            weakness = not attrs['httponly']
        elif predicate == 'samesite':
            weakness = samesite_weakness
        else:
            # Preserve the existing explicit/general session assessment and lifecycle checks.
            weakness = not attrs['secure'] or not attrs['httponly'] or samesite_weakness or attrs['transport'] != 'https'
        lifecycle_failure = predicate == 'all_attributes' and lifecycle == 'PREVIOUS_SESSION_STILL_AUTHENTICATED'
        result = 'FAIL' if weakness or lifecycle_failure else 'PASS'
        confirmation = 'LIKELY' if lifecycle_failure else ('CONFIRMED' if weakness or predicate == 'all_attributes' else 'NOT_CONFIRMED')
        return Outcome('PRIOR_SESSION_STILL_AUTHENTICATED' if lifecycle_failure else ('EFFECTIVE_COOKIE_WEAKNESS' if weakness else 'EFFECTIVE_COOKIE_ATTRIBUTES'), result, confirmation,
                       'Repeated effective cookie predicate: ' + predicate + '. Other attributes/lifecycle observations do not change a specific parent predicate. A negative check does not establish overall system safety; no authentication state transitions performed. Configuration compares explicit supplied settings/expectations only; conditional transport behavior may explain a setting/attribute difference',
                       {'effective_attributes': attrs, 'effective_attribute_observations': attributes,
                        'session_predicate': predicate, 'samesite_policy': ctx.get('samesite_policy'),
                        **configuration, 'prior_session_observation': lifecycle, 'rotation': 'NOT_TESTED'})



class SSRFContext:
    name = 'ssrf_context'

    def propose(self, parent):
        ctx = context(parent)
        if 'ssrf' not in hint(parent) and ctx.get('validator') != self.name: return None
        missing = [k for k in ('feature_enabled', 'url_fetch_available', 'feature_evidence') if k not in ctx]
        if any(k in ctx and not isinstance(ctx[k], bool) for k in ('feature_enabled', 'url_fetch_available')): missing.append('boolean feature state')
        if not isinstance(ctx.get('feature_evidence'), str) or not ctx.get('feature_evidence'): missing.append('explicit feature evidence reference')
        if missing: return Decision('MISSING_CONTEXT', 'SSRF contextual prerequisites missing: ' + ', '.join(missing), tuple(missing), context=dict(ctx))
        ctx = dict(ctx, affected_version=parent.to_dict()['confirmation_status'] == 'VERSION_BASED')
        return Decision('APPLICABLE', 'Request-free prerequisite assessment; does not establish SSRF', context=ctx)

    def requests(self, candidate):
        return []  # Never contact a supplied fetch URL, internal network or callback.

    def evaluate(self, candidate, responses):
        ctx = candidate.context
        if not ctx['feature_enabled'] or not ctx['url_fetch_available']:
            return outcome('FEATURE_UNAVAILABLE', 'NOT_APPLICABLE', 'Supplied feature evidence excludes this runtime surface; version parent preserved', 'NOT_APPLICABLE')
        return outcome('RELEVANT_FETCH_CONTEXT', 'CONTEXTUAL', 'Feature and URL-fetch prerequisites present; affected-version=' + str(ctx['affected_version']) + '; no server-side fetch or SSRF exploitation tested')


ADVANCED_VALIDATORS = (SQLInjection(), UnsafeReflection(), AccountEnumeration(), AccessControl(), SessionControl(), SSRFContext())
