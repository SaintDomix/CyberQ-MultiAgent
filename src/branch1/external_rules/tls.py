"""Ported from first_branch_v22; see docs/BRANCH1_PIPELINE.md for changes."""
from __future__ import annotations
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from .models import Finding

def run_tls(target: str, timeout: float):
    p = urlparse(target)
    out = []
    if p.scheme != 'https':
        out.append(Finding('TLS-001', 'Transport Security', 'HTTPS enabled', 'FAIL', 'HIGH', 'CONFIRMED', 'TRANSPORT', f'Target uses {p.scheme.upper()}', 'Production authentication/session traffic should use HTTPS.', target, 'The assessed target is served over unencrypted HTTP.', 'Enable HTTPS for the Moodle deployment.'))
        out.append(Finding('TLS-002', 'Transport Security', 'TLS certificate / protocol', 'NOT_APPLICABLE', 'INFO', 'CONFIRMED', 'TRANSPORT', 'Target is HTTP; TLS handshake not applicable', 'Valid certificate and modern TLS for HTTPS deployment.', target, 'TLS cannot be assessed on the supplied HTTP target.', 'Assess again after HTTPS is enabled.'))
        return out
    host = p.hostname
    port = p.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                proto = sock.version() or 'unknown'
                cipher = sock.cipher()
    except ssl.SSLCertVerificationError as exc:
        out.append(Finding('TLS-002', 'Transport Security', 'TLS certificate / protocol', 'FAIL', 'HIGH', 'CONFIRMED', 'TRANSPORT', str(exc), 'Trusted certificate for the assessed hostname.', f'{host}:{port}', 'Certificate validation failed.', 'Install a valid certificate chain for the production hostname.'))
        return out
    except Exception as exc:
        out.append(Finding('TLS-002', 'Transport Security', 'TLS certificate / protocol', 'ERROR', None, 'NOT_TESTED', 'TRANSPORT', str(exc), 'Successful modern TLS handshake.', f'{host}:{port}', 'TLS handshake could not be fully assessed.', 'Review TLS configuration and connectivity.'))
        return out
    expired = False
    expiry_text = cert.get('notAfter', 'unknown')
    if cert.get('notAfter'):
        try:
            expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            expired = expiry <= datetime.now(timezone.utc)
        except ValueError:
            pass
    old = proto in {'TLSv1', 'TLSv1.1'}
    status = 'FAIL' if expired or old else 'PASS'
    severity = 'HIGH' if expired or old else 'INFO'
    out.append(Finding('TLS-002', 'Transport Security', 'TLS certificate / protocol', status, severity, 'CONFIRMED', 'TRANSPORT', f'protocol={proto}; expires={expiry_text}; cipher={cipher}', 'Valid certificate; TLS 1.2 or TLS 1.3.', f'{host}:{port}', 'Obsolete/invalid TLS condition detected.' if status == 'FAIL' else 'Certificate validation succeeded and negotiated TLS is modern.', 'Renew/harden TLS configuration.' if status == 'FAIL' else 'Maintain certificate renewal and modern TLS.'))
    return out
