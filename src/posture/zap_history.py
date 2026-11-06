"""Typed ZAP history accounting, separate from application scope/evidence.

ZAP 2.17 SiteMap.createReference creates type-0, unsent ancestor placeholders.
Only those exact derived ancestors may be ignored, never real proxy requests.
"""
from collections import Counter
from ipaddress import ip_address
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .policy import PAGES, scoped

VERSION = 'zap-history-integrity-1.0'
MAX_HISTORY_MESSAGES = 100
USER_AGENT = 'Moodle-Operational-Posture/2.0'
REVIEWED_PATHS = {'/moodle/' + p for p in PAGES}


def origin(url):
    p = urlsplit(url)
    if p.username or p.password or p.fragment: raise ValueError('Invalid authority')
    return p.scheme, p.hostname, p.port or (80 if p.scheme == 'http' else 443)


def control_identity(url):
    p = urlsplit(url)
    if any(ord(c) < 32 for c in url): raise ValueError('Invalid control URL')
    query = tuple(sorted(parse_qsl(p.query, keep_blank_values=True, strict_parsing=True))) if p.query else ()
    return origin(url), p.path, query


def control_url(api_origin, component, kind, name, params):
    from urllib.parse import urlencode
    return api_origin + f'/JSON/{component}/{kind}/{name}/' + ('?' + urlencode(params) if params else '')


def ancestors(urls):
    result = set()
    for url in urls:
        p = urlsplit(url)
        # SiteMap ancestors have no trailing slash, including an empty host-root path.
        parts = p.path.split('/')
        for i in range(1, len(parts)):
            result.add(urlunsplit((p.scheme, p.netloc, '/'.join(parts[:i]), '', '')))
    return result


def message_request(message):
    header = message['requestHeader']
    if not isinstance(header, str) or len(header) > 65536: raise ValueError('Invalid request header')
    lines = header.splitlines()
    method, target, version = lines[0].split()
    if version not in ('HTTP/1.0', 'HTTP/1.1'): raise ValueError('Invalid HTTP version')
    hosts, agents = [], []
    for line in lines[1:]:
        if not line: continue
        name, value = line.split(':', 1)
        if name.lower() == 'host': hosts.append(value.strip())
        if name.lower() == 'user-agent': agents.append(value.strip())
    if len(hosts) != 1 or len(agents) > 1: raise ValueError('Ambiguous HTTP authority')
    url = 'http://' + hosts[0] + target if target.startswith('/') else target
    p = urlsplit(url)
    if origin(url) != origin(p.scheme + '://' + hosts[0]): raise ValueError('Host mismatch')
    status_line = message['responseHeader'].splitlines()[0].split()
    if status_line[0] not in ('HTTP/1.0', 'HTTP/1.1'): raise ValueError('Invalid response header')
    status = int(status_line[1])
    if status != 0 and not 100 <= status <= 599: raise ValueError('Invalid status')
    return method, url, status, agents[0] if agents else None


def structural(url, safe_paths):
    """Unknown paths/hostnames may themselves contain tokens: withhold them."""
    try:
        p = urlsplit(url)
        host = p.hostname
        try: ip_address(host)
        except ValueError: host = '[withheld-host]'
        scheme = p.scheme if p.scheme in ('http', 'https') else '[withheld-scheme]'
        return scheme + '://' + host + (':' + str(p.port) if p.port else ''), p.path if p.path in safe_paths else '/[withheld-path]'
    except (ValueError, TypeError):
        return '[withheld-origin]', '/[withheld-path]'


def review_history(messages, urls, expected_requests, issued_controls, reported_count):
    """Return safe diagnostics and an in-memory URL->classification map.

    Target traffic must match the provider transcript as a multiset. Preflight
    passes an empty transcript, so any pre-existing target/internal record fails.
    Full raw API payloads are never returned or persisted.
    """
    summary = {'version': VERSION, 'result': 'FAIL', 'total_history_messages': 0,
               'target_messages': 0, 'control_plane_messages': 0,
               'ignored_internal_messages': 0, 'unexpected_messages': 0,
               'unexpected_origins': [], 'unexpected_paths': [], 'failure_reasons': [],
               'history_messages': []}
    classes, seen, ids = {}, Counter(), set()
    expected = Counter((r['method'], r['url'], r['status']) for r in expected_requests)
    approved_urls = {r['url'] for r in expected_requests}
    ancestor_urls = ancestors(approved_urls)
    controls = Counter(control_identity(u) for u in issued_controls)
    seen_controls = Counter()
    safe_paths = REVIEWED_PATHS | {urlsplit(u).path for u in ancestor_urls | set(issued_controls)}

    def reject(reason, url=None):
        if reason not in summary['failure_reasons']: summary['failure_reasons'].append(reason)
        if url is not None:
            o, p = structural(url, safe_paths)
            for key, value in (('unexpected_origins', o), ('unexpected_paths', p)):
                if value not in summary[key] and len(summary[key]) < 20: summary[key].append(value)

    if (not isinstance(messages, list) or not isinstance(urls, list)
            or not isinstance(reported_count, int) or reported_count < 0):
        reject('MALFORMED_HISTORY'); return summary, classes
    summary['total_history_messages'] = len(messages)
    summary['reported_number_of_messages'] = reported_count
    if len(messages) > MAX_HISTORY_MESSAGES or reported_count > len(messages):
        reject('INCOMPLETE_OR_OVERSIZED_HISTORY'); return summary, classes
    for m in messages:
        url = None; kind = 'UNEXPECTED'; method = None; status = None; history_type = None; ident = None
        try:
            ident, history_type = int(m['id']), int(m['type'])
            if ident < 1 or ident in ids: raise ValueError('Duplicate history identity')
            ids.add(ident)
            method, url, status, agent = message_request(m)
            if not isinstance(m['requestBody'], str) or not isinstance(m['responseBody'], str): raise ValueError('Malformed body')
            if (history_type == 1 and method == 'GET' and not m['requestBody']
                    and seen_controls[control_identity(url)] < controls[control_identity(url)] and 200 <= status < 300):
                kind = 'CONTROL_PLANE'; seen_controls[control_identity(url)] += 1
            elif (history_type == 1 and scoped(url) and urlsplit(url).path in REVIEWED_PATHS
                    and method == 'GET' and not m['requestBody'] and agent == USER_AGENT
                    and seen[(method, url, status)] < expected[(method, url, status)]):
                kind = 'TARGET'; seen[(method, url, status)] += 1
            elif (history_type == 0 and url in ancestor_urls and method == 'GET' and status == 0
                    and str(m.get('timestamp')) == '0' and str(m.get('rtt')) == '0'
                    and not m['requestBody'] and not m['responseBody']):
                kind = 'INTERNAL_SITE_TREE_ANCESTOR'
            else: reject('UNEXPECTED_HISTORY_MESSAGE', url)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError):
            reject('MALFORMED_HISTORY_MESSAGE', url)
        key = {'TARGET': 'target_messages', 'CONTROL_PLANE': 'control_plane_messages',
               'INTERNAL_SITE_TREE_ANCESTOR': 'ignored_internal_messages'}.get(kind, 'unexpected_messages')
        summary[key] += 1
        if url is not None:
            # Ambiguous classifications never let an alert be accepted later.
            classes[url] = kind if url not in classes or classes[url] == kind else 'UNEXPECTED'
        o, p = structural(url, safe_paths)
        summary['history_messages'].append({'history_id': ident, 'history_type': history_type,
            'classification': kind, 'origin': o, 'path': p, 'method': method if method in ('GET', 'POST', 'OPTIONS', 'HEAD', 'PUT', 'DELETE', 'TRACE', 'CONNECT') else '[withheld]', 'status': status})
    if seen != expected: reject('TARGET_TRANSCRIPT_MISMATCH')
    for url in urls:
        try:
            if classes.get(url) in ('TARGET', 'CONTROL_PLANE', 'INTERNAL_SITE_TREE_ANCESTOR'): continue
            # Control queries can be logged by the last inspection itself.
            if control_identity(url) in controls: continue
        except (ValueError, TypeError): pass
        reject('UNEXPLAINED_SITE_TREE_URL', url)
    if not summary['failure_reasons']: summary['result'] = 'PASS'
    return summary, classes
