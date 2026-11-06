"""Bounded, same-host posture requests, with an evidence transcript."""
import hashlib
import re
from urllib.parse import urljoin, urlsplit

import requests


def validate_target(target):
    url = urlsplit(target)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("Target must be an explicit HTTP(S) base URL without credentials/query/fragment")
    return target.rstrip("/")+"/"


def redact_cookie(value):
    return re.sub(r"(^|,\s*)([^=;,\s]+)=([^;\r\n,]*)", r"\1\2=<redacted>", value)


class Client:
    def __init__(self, target, timeout=8, max_requests=80):
        self.target = validate_target(target)
        self.timeout, self.max_requests = timeout, max_requests
        if timeout <= 0 or max_requests <= 0:
            raise ValueError("Request bounds must be positive")
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers["User-Agent"] = "Moodle-Branch1-Posture/1.0"
        self.transcript, self.cache = [], {}

    def scoped(self, url):
        base, candidate = urlsplit(self.target), urlsplit(url)
        allowed_ports = {base.port} if base.port else {None, 80, 443}
        return candidate.scheme in {"http", "https"} and candidate.hostname == base.hostname and candidate.port in allowed_ports and not candidate.username and not candidate.password

    def request(self, method, url, **kwargs):
        if method not in {"GET", "OPTIONS", "TRACE"}:
            raise requests.RequestException("Method outside passive posture scope")
        if not self.scoped(url):
            raise requests.RequestException("URL outside authorized host/port scope")
        headers = kwargs.pop("headers", {})
        follow = kwargs.pop("allow_redirects", method == "GET")
        key = (method, url, tuple(sorted(headers.items())))
        if key in self.cache:
            return self.cache[key]
        initial_url = url
        for _ in range(6):
            if len(self.transcript) >= self.max_requests:
                raise requests.RequestException("Assessment request budget exhausted")
            record = {"method": method, "requested_url": url, "request_headers": headers}
            self.transcript.append(record)
            try:
                response = self.session.request(method, url, headers=headers, timeout=self.timeout,
                                                allow_redirects=False, stream=True)
                with response:
                    chunks, total = [], 0
                    for chunk in response.iter_content(65536):
                        total += len(chunk)
                        if total > 2_000_000:
                            raise requests.RequestException("Response exceeds 2 MB evidence limit")
                        chunks.append(chunk)
                    response._content = b"".join(chunks)
                    response._content_consumed = True
                record.update(status=response.status_code, final_url=response.url,
                              response_headers={k: redact_cookie(v) if k.lower()=="set-cookie" else v for k,v in response.headers.items()},
                              body_sha256=hashlib.sha256(response.content).hexdigest(),
                              body_sample=response.text[:10000])
                if follow and response.status_code in {301,302,303,307,308} and response.headers.get("Location"):
                    next_url = urljoin(url, response.headers["Location"])
                    if not self.scoped(next_url):
                        raise requests.RequestException("Redirect outside authorized scope")
                    url = next_url
                    continue
                self.cache[key] = response
                return response
            except requests.RequestException as exc:
                record["error"] = str(exc)
                raise
        raise requests.RequestException(f"Redirect limit exceeded for {initial_url}")

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def trace(self, url, **kwargs):
        return self.request("TRACE", url, **kwargs)
