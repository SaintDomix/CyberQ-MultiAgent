"""A separate authorized, read-only, rate-limited HTTP executor; no redirects."""
from dataclasses import dataclass
import hashlib
import math
import re
import time
from urllib.parse import parse_qsl, urlsplit, urlencode, urlunsplit

import requests

from ..client import validate_target
from .redaction import redact
CREDENTIAL_KEY = re.compile(r"password|passwd|secret|token|cookie|authorization|credential|api[_-]?key|sesskey|moodlesession", re.I)


class SafetyError(ValueError):
    pass


def origin(url):
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)


@dataclass(frozen=True)
class SafetyPolicy:
    target: str | None = None
    active: bool = False
    authorized: bool = False
    request_budget: int = 20
    timeout: float = 5.0
    requests_per_second: float = 0.25
    max_response_bytes: int = 65536

    def __post_init__(self):
        if isinstance(self.request_budget, bool) or not isinstance(self.request_budget, int) or not 1 <= self.request_budget <= 40:
            raise SafetyError("Active request budget must be an integer in [1, 40]")
        for value, maximum, name in [(self.timeout, 10, "timeout"), (self.requests_per_second, 0.5, "request rate")]:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= maximum:
                raise SafetyError(f"Active {name} must be finite, positive and <= {maximum}")
        if isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int) or not 1 <= self.max_response_bytes <= 262144:
            raise SafetyError("Active response cap must be an integer in [1, 262144]")
        if self.target:
            validate_target(self.target)
        if self.active and (not self.authorized or not self.target):
            raise SafetyError("Active execution requires --active --authorized and an explicit target")

    def require_execution(self):
        if not self.active or not self.authorized or not self.target:
            raise SafetyError("Active requests are disabled without --active --authorized --target")

    def check(self, spec):
        self.require_execution()
        parts = urlsplit(spec.url)
        if origin(spec.url) != origin(self.target) or parts.username or parts.password or parts.fragment:
            raise SafetyError("Request outside exact authorized origin or includes credentials/fragment")
        if spec.method != "GET":
            raise SafetyError("Only read-only GET requests are permitted")
        if re.search(r"(?:logout|delete|remove|install|upgrade|enrol|submit|regrade|reset|edit)\b", parts.path, re.I):
            raise SafetyError("Potentially state-changing endpoint is prohibited")
        if re.search(r"%(?:2f|5c|2e)|\\|(?:^|/)\.\.(?:/|$)", parts.path, re.I):
            raise SafetyError("Encoded/traversal paths are prohibited")
        if any(k.lower() in {"action", "sesskey", "delete", "confirm", "logout"} for k, _ in parse_qsl(parts.query)):
            raise SafetyError("State-changing query context is prohibited")
        if any(CREDENTIAL_KEY.search(k) for k, _ in parse_qsl(parts.query)):
            raise SafetyError("Credential/token-bearing request context is prohibited")


@dataclass
class Response:
    status: int
    url: str
    headers: dict
    body: bytes

    @property
    def text(self):
        return self.body.decode("utf-8", errors="replace")

    def evidence(self):
        return {"status": self.status, "url": redact(self.url),
                "headers": redact({k:v for k,v in self.headers.items()
                                   if k.lower() in {"location", "content-type", "set-cookie"}}),
                "body_length": len(self.body), "body_sha256": hashlib.sha256(self.body).hexdigest()}


class Executor:
    def __init__(self, policy, *, session=None, clock=time.monotonic, sleep=time.sleep, runtime=None):
        policy.require_execution()  # Even constructing an executor requires authorization.
        from .runtime import RuntimeContext
        self.runtime = runtime or RuntimeContext()
        self.policy, self.clock, self.sleep = policy, clock, sleep
        self.session = session or requests.Session()
        self.session.trust_env = False
        self.session.auth = None
        self.session.headers.clear()
        self.session.headers["User-Agent"] = "Moodle-Branch1-Active-Validation/1.0"
        self.used, self.last_request, self.transcript = 0, None, []

    @property
    def remaining(self):
        return self.policy.request_budget-self.used

    def get(self, spec):
        self.policy.check(spec)
        if self.remaining <= 0:
            raise SafetyError("Active request budget exhausted")
        if self.last_request is not None:
            delay = 1/self.policy.requests_per_second-(self.clock()-self.last_request)
            if delay > 0:
                self.sleep(delay)
        self.last_request = self.clock()
        self.used += 1  # Attempts, including failures, consume the global budget.
        parts = urlsplit(spec.url)
        safe_url = urlunsplit(parts._replace(query=urlencode([(k, "<redacted>" if k in spec.private_parameters else v) for k,v in parse_qsl(parts.query, keep_blank_values=True)])))
        entry = {"request_index": self.used-1, "method": "GET", "url": redact(safe_url), "purpose": spec.purpose, "session_ref": spec.session_ref}
        self.transcript.append(entry)
        self.session.cookies.clear()  # No automatic cookie replay between roles/requests.
        try:
            options = {}
            if spec.session_ref:
                options["headers"] = {"Cookie": self.runtime.cookie(spec.session_ref)}
            with self.session.get(spec.url, timeout=self.policy.timeout, allow_redirects=False, stream=True, **options) as response:
                chunks, length = [], 0
                for chunk in response.iter_content(16384):
                    length += len(chunk)
                    if length > self.policy.max_response_bytes or self.clock()-self.last_request > self.policy.timeout:
                        raise requests.RequestException("Active response exceeded size/time limit")
                    chunks.append(chunk)
                result = Response(response.status_code, spec.url, dict(response.headers), b"".join(chunks))
            entry["response"] = result.evidence()
            entry["response"]["url"] = redact(safe_url)
            if spec.private_parameters or spec.session_ref:
                # Location can echo arbitrary account identifiers under unrelated keys.
                entry["response"]["headers"] = {k: "<redacted>" if k.lower() == "location" else v for k, v in entry["response"]["headers"].items()}
            return result
        except (requests.RequestException, ValueError) as exc:
            # Exception text can contain URLs/tokens or server content; retain only type.
            entry["error"] = type(exc).__name__
            raise
        finally:
            self.session.cookies.clear()
