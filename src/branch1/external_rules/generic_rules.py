"""Ported from first_branch_v22; see docs/BRANCH1_PIPELINE.md for changes."""
from __future__ import annotations
import requests
from urllib.parse import urlparse
from .models import Finding
from .utils import join, origin, trunc, versioned_server, with_scheme
HEADER_ENDPOINTS = {'home': '', 'login': 'login/index.php', 'my': 'my/', 'course': 'course/', 'admin': 'admin/'}

class GenericRules:

    def __init__(self, client, target):
        self.c = client
        self.target = target
        self.scheme = urlparse(target).scheme
        self.origin = origin(target)

    def transport_and_headers(self, base):
        out = []
        if self.scheme == 'https':
            http_url = with_scheme(self.target, 'http')
            try:
                r = self.c.get(http_url)
                ok = r.url.startswith('https://')
                out.append(Finding('TLS-003', 'Transport Security', 'HTTP to HTTPS redirection', 'PASS' if ok else 'FAIL', 'INFO' if ok else 'MEDIUM', 'CONFIRMED', 'TRANSPORT', f'HTTP final URL={r.url}; status={r.status_code}', 'HTTP should redirect to HTTPS.', http_url, 'HTTP ends on HTTPS.' if ok else 'HTTP did not end on HTTPS.', 'Maintain redirect.' if ok else 'Configure HTTP-to-HTTPS redirection.'))
            except requests.RequestException as exc:
                out.append(Finding('TLS-003', 'Transport Security', 'HTTP to HTTPS redirection', 'ERROR', None, 'NOT_TESTED', 'TRANSPORT', str(exc), 'Redirect HTTP to HTTPS or disable HTTP.', http_url, 'HTTP endpoint could not be assessed.', 'Verify HTTP handling manually.'))
        else:
            out.append(Finding('TLS-003', 'Transport Security', 'HTTP to HTTPS redirection', 'FAIL', 'HIGH', 'CONFIRMED', 'TRANSPORT', 'Assessment target itself is HTTP.', 'Production Moodle should use HTTPS.', self.target, 'Authentication/session traffic is served over HTTP.', 'Enable HTTPS and redirect HTTP traffic.'))
        hsts = base.headers.get('Strict-Transport-Security', '')
        if self.scheme != 'https':
            out.append(Finding('HDR-001', 'Security Headers', 'Strict-Transport-Security', 'NOT_APPLICABLE', 'INFO', 'CONFIRMED', 'TRANSPORT', 'HTTP-only target; HSTS depends on HTTPS deployment', 'HSTS on HTTPS deployment.', 'Base response headers', 'HSTS is not independently scored while the target is HTTP.', 'Enable HTTPS first, then configure HSTS.'))
        else:
            out.append(Finding('HDR-001', 'Security Headers', 'Strict-Transport-Security', 'PASS' if hsts else 'FAIL', 'INFO' if hsts else 'MEDIUM', 'CONFIRMED', 'TRANSPORT', hsts or 'Header absent', 'HSTS enabled on HTTPS deployment.', 'Base response headers', 'HSTS present.' if hsts else 'HSTS not observed.', 'Maintain HSTS.' if hsts else 'Enable HSTS.'))
        csp = base.headers.get('Content-Security-Policy', '')
        out.append(Finding('HDR-002', 'Security Headers', 'Content-Security-Policy', 'PASS' if csp else 'FAIL', 'INFO' if csp else 'MEDIUM', 'CONFIRMED', 'HEADERS', trunc(csp) if csp else 'Header absent', 'Restrictive Moodle-compatible CSP.', 'Base response headers', 'CSP is present.' if csp else 'No CSP was observed.', 'Review the current CSP.' if csp else 'Define a Moodle-compatible CSP.'))
        if csp:
            for (fid, token) in [('HDR-003', "'unsafe-inline'"), ('HDR-004', "'unsafe-eval'")]:
                weak = token in csp.lower()
                out.append(Finding(fid, 'Security Headers', f'CSP use of {token}', 'PARTIAL' if weak else 'PASS', 'LOW' if weak else 'INFO', 'CONFIRMED', 'HEADERS', f"{token} {('present' if weak else 'not observed')}", f'Avoid {token} unless required.', trunc(csp), 'A weaker CSP allowance is present.' if weak else 'Selected weak token not observed.', 'Remove/narrow the directive where compatible.' if weak else 'Maintain restrictive policy.'))
        xcto = base.headers.get('X-Content-Type-Options', '')
        xcto_ok = xcto.lower() == 'nosniff'
        out.append(Finding('HDR-005', 'Security Headers', 'X-Content-Type-Options', 'PASS' if xcto_ok else 'FAIL', 'INFO' if xcto_ok else 'LOW', 'CONFIRMED', 'HEADERS', xcto or 'Header absent', 'nosniff', 'Base response headers', 'MIME-sniffing protection observed.' if xcto_ok else 'Expected nosniff directive not observed.', 'Maintain nosniff.' if xcto_ok else 'Set X-Content-Type-Options: nosniff.'))
        xfo = base.headers.get('X-Frame-Options', '')
        frame_ancestors = 'frame-ancestors' in csp.lower() if csp else False
        protected = bool(xfo) or frame_ancestors
        out.append(Finding('HDR-006', 'Security Headers', 'Clickjacking protection', 'PASS' if protected else 'FAIL', 'INFO' if protected else 'MEDIUM', 'CONFIRMED', 'HEADERS', f"X-Frame-Options={xfo or 'absent'}; CSP frame-ancestors={('present' if frame_ancestors else 'absent')}", 'X-Frame-Options and/or CSP frame-ancestors.', 'Base response headers', 'Frame embedding is constrained.' if protected else 'No standard frame restriction observed.', 'Maintain protection.' if protected else 'Add frame-ancestors or X-Frame-Options.'))
        for (fid, name) in [('HDR-007', 'Referrer-Policy'), ('HDR-008', 'Permissions-Policy')]:
            value = base.headers.get(name, '')
            out.append(Finding(fid, 'Security Headers', name, 'PASS' if value else 'PARTIAL', 'INFO' if value else 'LOW', 'CONFIRMED', 'HEADERS', trunc(value) if value else 'Header absent', f'Explicit {name} where applicable.', 'Base response headers', f'{name} is present.' if value else f'{name} not observed.', 'Review current policy.' if value else f'Consider an explicit {name}.'))
        server = base.headers.get('Server', '')
        detailed = versioned_server(server)
        out.append(Finding('DISC-001', 'Information Disclosure', 'Server version disclosure', 'FAIL' if detailed else 'PARTIAL' if server else 'PASS', 'LOW' if server else 'INFO', 'CONFIRMED', 'DISCLOSURE', server or 'Server header absent', 'Avoid detailed server product/version disclosure.', 'Server response header', 'Detailed server version is disclosed.' if detailed else 'Server product is disclosed.' if server else 'No Server header observed.', 'Reduce server tokens.' if server else 'No action required.'))
        powered = base.headers.get('X-Powered-By', '')
        out.append(Finding('DISC-002', 'Information Disclosure', 'X-Powered-By disclosure', 'FAIL' if powered else 'PASS', 'LOW' if powered else 'INFO', 'CONFIRMED', 'DISCLOSURE', powered or 'Header absent', 'Avoid unnecessary runtime/framework disclosure.', 'Response headers', 'Runtime information is exposed.' if powered else 'X-Powered-By not observed.', 'Disable X-Powered-By.' if powered else 'No action required.'))
        return out

    def cors_methods_exposure(self):
        out = []
        test_origin = 'https://scanner-test.invalid'
        try:
            r = self.c.get(self.target, headers={'Origin': test_origin})
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            reflected = acao.strip() == test_origin
            wildcard = acao.strip() == '*'
            credentials = acac.lower() == 'true'
            bad = reflected and credentials
            out.append(Finding('CORS-001', 'HTTP Configuration', 'CORS simple-origin policy', 'FAIL' if bad else 'PARTIAL' if wildcard else 'PASS', 'HIGH' if bad else 'LOW' if wildcard else 'INFO', 'CONFIRMED', 'CORS', f"ACAO={acao or 'absent'}; ACAC={acac or 'absent'}", 'Do not reflect arbitrary origins with credentials.', 'GET request with test Origin', 'Arbitrary credentialed origin reflection observed.' if bad else 'Wildcard CORS observed.' if wildcard else 'No obviously permissive simple CORS behavior observed.', 'Restrict origins/credentials.' if bad or wildcard else 'Maintain restrictive CORS behavior.'))
        except requests.RequestException as exc:
            out.append(Finding('CORS-001', 'HTTP Configuration', 'CORS simple-origin policy', 'ERROR', None, 'NOT_TESTED', 'CORS', str(exc), 'Assessable CORS behavior.', self.target, 'CORS check could not be completed.', 'Verify manually.'))
        try:
            r = self.c.options(self.target, headers={'Origin': test_origin, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'X-Scanner-Test'})
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            acam = r.headers.get('Access-Control-Allow-Methods', '')
            reflected = acao.strip() == test_origin
            credentials = acac.lower() == 'true'
            bad = reflected and credentials
            out.append(Finding('CORS-002', 'HTTP Configuration', 'CORS preflight policy', 'FAIL' if bad else 'PASS', 'HIGH' if bad else 'INFO', 'CONFIRMED', 'CORS', f"status={r.status_code}; ACAO={acao or 'absent'}; ACAC={acac or 'absent'}; ACAM={acam or 'absent'}", 'No arbitrary credentialed preflight access.', 'OPTIONS preflight with test Origin', 'Credentialed arbitrary-origin preflight allowed.' if bad else 'No credentialed arbitrary-origin preflight was observed.', 'Restrict allowed origins.' if bad else 'Maintain restrictive preflight policy.'))
        except requests.RequestException as exc:
            out.append(Finding('CORS-002', 'HTTP Configuration', 'CORS preflight policy', 'ERROR', None, 'NOT_TESTED', 'CORS', str(exc), 'Assessable preflight behavior.', self.target, 'Preflight check could not be completed.', 'Verify manually.'))
        try:
            trace = self.c.trace(self.target)
            enabled = 200 <= trace.status_code < 300
            out.append(Finding('HTTP-001', 'HTTP Configuration', 'TRACE method', 'FAIL' if enabled else 'PASS', 'MEDIUM' if enabled else 'INFO', 'CONFIRMED', 'HTTP_METHODS', f'TRACE status={trace.status_code}', 'TRACE normally disabled.', self.target, 'TRACE appears enabled.' if enabled else 'TRACE did not succeed.', 'Disable TRACE.' if enabled else 'No action required.'))
            opt = self.c.options(self.target)
            allow = opt.headers.get('Allow', '')
            if not allow:
                out.append(Finding('HTTP-002', 'HTTP Configuration', 'OPTIONS method advertisement', 'PARTIAL', 'LOW', 'CONFIRMED', 'HTTP_METHODS', f'status={opt.status_code}; Allow header absent', 'Method exposure should be explicitly reviewable.', self.target, 'OPTIONS did not provide a conclusive Allow list.', 'Verify enabled methods at the web-server configuration level.'))
            else:
                dangerous = [m for m in ('PUT', 'DELETE', 'CONNECT') if m in allow.upper()]
                out.append(Finding('HTTP-002', 'HTTP Configuration', 'OPTIONS method advertisement', 'PARTIAL' if dangerous else 'PASS', 'MEDIUM' if dangerous else 'INFO', 'CONFIRMED', 'HTTP_METHODS', f'Allow={allow}', 'Only required methods enabled.', self.target, f"Sensitive methods advertised: {', '.join(dangerous)}" if dangerous else 'No selected high-risk methods advertised.', 'Review/restrict methods.' if dangerous else 'Maintain least privilege.'))
        except requests.RequestException as exc:
            out.append(Finding('HTTP-001', 'HTTP Configuration', 'HTTP method assessment', 'ERROR', None, 'NOT_TESTED', 'HTTP_METHODS', str(exc), 'Assessable method behavior.', self.target, 'Method checks could not be completed.', 'Verify manually.'))
        exposure_checks = [('EXPOSURE-001', '/server-status', 'Apache server-status', 'apache server status', 'MEDIUM'), ('EXPOSURE-002', '/phpinfo.php', 'PHP diagnostic page', 'phpinfo()', 'MEDIUM'), ('EXPOSURE-003', '/.git/HEAD', 'Git metadata', 'ref:', 'HIGH'), ('EXPOSURE-004', '/.env', 'Environment file', 'db_', 'HIGH'), ('EXPOSURE-005', '/composer.lock', 'Composer dependency lockfile', '"packages"', 'LOW'), ('EXPOSURE-006', '/vendor/composer/installed.json', 'Composer installed-component inventory', '"packages"', 'MEDIUM')]
        for (fid, path, label, marker, severity) in exposure_checks:
            url = self.origin + path
            try:
                r = self.c.get(url)
                body = r.text[:5000].lower()
                matched = r.status_code == 200 and marker.lower() in body
                out.append(Finding(fid, 'Exposure', f'Exposed {label}', 'FAIL' if matched else 'PASS', severity if matched else 'INFO', 'CONFIRMED' if matched else 'HEURISTIC', 'EXPOSURE', f"HTTP {r.status_code}; marker={('matched' if matched else 'not matched')}", f'{label} should not be publicly exposed.', url, f'{label} is remotely accessible.' if matched else f'No confirmed remote exposure of {label}.', f'Remove/restrict {label}.' if matched else 'No action required.'))
            except requests.RequestException as exc:
                out.append(Finding(fid, 'Exposure', f'Exposed {label}', 'ERROR', None, 'NOT_TESTED', 'EXPOSURE', str(exc), f'{label} should not be public.', url, 'Check could not be completed.', 'Verify manually.'))
        url = join(self.target, '__security_assessment_nonexistent_7f4a9c')
        try:
            r = self.c.get(url)
            sample = r.text[:10000].lower()
            markers = ['stack trace', 'fatal error', 'uncaught exception', 'traceback', 'warning:', 'notice:']
            hit = [m for m in markers if m in sample]
            out.append(Finding('DISC-003', 'Information Disclosure', 'Verbose error disclosure', 'FAIL' if hit else 'PASS', 'MEDIUM' if hit else 'INFO', 'HEURISTIC', 'DISCLOSURE', f"status={r.status_code}; markers={hit or 'none'}", 'No stack traces/runtime diagnostics in public errors.', url, 'Verbose diagnostic markers observed.' if hit else 'No selected verbose-error marker observed.', 'Disable verbose public errors.' if hit else 'Maintain safe error handling.'))
        except requests.RequestException as exc:
            out.append(Finding('DISC-003', 'Information Disclosure', 'Verbose error disclosure', 'ERROR', None, 'NOT_TESTED', 'DISCLOSURE', str(exc), 'Safe public error handling.', url, 'Error-handling check failed.', 'Verify manually.'))
        return out

    def endpoint_matrix(self):
        rows = []
        header_names = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy', 'Cache-Control']
        for (name, rel) in HEADER_ENDPOINTS.items():
            url = join(self.target, rel)
            try:
                r = self.c.get(url)
                row = {'endpoint_name': name, 'requested_url': url, 'status': r.status_code, 'final_url': r.url}
                for header in header_names:
                    row[header] = r.headers.get(header, '')
                rows.append(row)
            except Exception as exc:
                row = {'endpoint_name': name, 'requested_url': url, 'status': 'ERROR', 'final_url': str(exc)}
                for header in header_names:
                    row[header] = ''
                rows.append(row)
        return rows

    def endpoint_header_finding(self, rows):
        if not rows or any((row['status'] == 'ERROR' for row in rows)):
            return Finding('HDR-009', 'Security Headers', 'Security-header consistency across key endpoints', 'ERROR', 'INFO', 'NOT_TESTED', 'HEADERS', 'Incomplete endpoint coverage', 'Successful responses for every selected endpoint', str(rows), 'Endpoint failures prevent a complete consistency assessment.', 'Repeat failed endpoint checks.')
        core = ['Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options']
        missing = []
        for row in rows:
            if row['status'] == 'ERROR':
                continue
            for header in core:
                if not row.get(header):
                    missing.append(f"{row['endpoint_name']}:{header}")
        return Finding('HDR-009', 'Security Headers', 'Security-header consistency across key endpoints', 'PARTIAL' if missing else 'PASS', 'LOW' if missing else 'INFO', 'CONFIRMED', 'HEADERS', '; '.join(missing[:20]) if missing else 'Core headers observed on assessed endpoints', 'Consistent protective-header policy across key Moodle endpoints.', 'Multi-endpoint response-header matrix', 'One or more key endpoints lack selected headers.' if missing else 'Selected headers are consistent across assessed endpoints.', 'Apply security headers consistently.' if missing else 'Maintain consistent policy.')
