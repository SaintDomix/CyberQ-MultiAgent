"""INTENTIONALLY VULNERABLE disposable benchmark. Never deploy with production data."""
import argparse
from contextlib import closing
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sqlite3
from urllib.parse import parse_qs, urlsplit

BANNER = 'INTENTIONALLY VULNERABLE BRANCH 1 LAB BENCHMARK — FICTITIOUS DATA ONLY'


class Application:
    """Pure deterministic request handling; a fresh in-memory DB per SQL request."""
    def handle(self, path, query):
        if path == '/':
            return 200, 'text/plain', BANNER.encode()
        values = parse_qs(query, keep_blank_values=True)
        if len(query) > 2048 or set(values) != {'q'} or len(values['q']) != 1 or len(values['q'][0]) > 128:
            return 400, 'text/plain', b'Invalid bounded benchmark input'
        value = values['q'][0]
        if path in {'/sql/vulnerable', '/sql/safe'}:
            # Only the specified benign value and the validator's single-quote perturbation.
            # No general query interface, extraction, stacked queries or arbitrary payloads.
            if value not in {'lesson', "lesson'"}:
                return 400, 'text/plain', b'Only declared fixture probes are supported'
            with closing(sqlite3.connect(':memory:')) as db:
                db.execute('CREATE TABLE fixture (name TEXT)')
                db.execute('INSERT INTO fixture VALUES (?)', ('lesson',))
                db.commit()
                db.execute('PRAGMA query_only = ON')
                try:
                    if path.endswith('vulnerable'):
                        db.execute("SELECT COUNT(*) FROM fixture WHERE name = '" + value + "'").fetchone()
                    else:
                        db.execute('SELECT COUNT(*) FROM fixture WHERE name = ?', (value,)).fetchone()
                except sqlite3.OperationalError:
                    # Actual SQLite parser error, fixed safe message rather than echoed query.
                    return 500, 'text/plain', b'sqlite3.OperationalError: controlled syntax error'
            return 200, 'text/plain', b'Lookup completed'
        if path in {'/xss/unsafe', '/xss/encoded'}:
            marker = value if path.endswith('unsafe') else html.escape(value, quote=True)
            return 200, 'text/html', ('<!doctype html><title>Lab benchmark</title><input value="' + marker + '">').encode()
        if path in {'/accounts/distinct', '/accounts/normalized'}:
            if value not in {'bench-present', 'bench-absent'}:
                return 400, 'text/plain', b'Only fictitious fixture identities are supported'
            text = 'Account exists' if value == 'bench-present' else 'Account not found'
            return 200, 'text/plain', (text if path.endswith('distinct') else 'Lookup completed').encode()
        return 404, 'text/plain', b'Not found'


class Handler(BaseHTTPRequestHandler):
    application = Application()

    def log_message(self, *args):
        pass  # Never log request URLs or payloads.

    def do_GET(self):
        parts = urlsplit(self.path)
        status, content_type, body = self.application.handle(parts.path, parts.query)
        self.send_response(status)
        self.send_header('Content-Type', content_type + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.send_error(405, 'Read-only benchmark')


def main():
    parser = argparse.ArgumentParser(description=BANNER)
    parser.add_argument('--bind', required=True, help='Explicit listening interface/address')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--authorized', action='store_true')
    args = parser.parse_args()
    if not args.authorized or not 1 <= args.port <= 65535:
        parser.error('Explicit lab authorization and port in [1,65535] required')
    print(BANNER, flush=True)
    print(f'Listening on {args.bind}:{args.port}; Ctrl-C stops and discards fixture state.', flush=True)
    with ThreadingHTTPServer((args.bind, args.port), Handler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
