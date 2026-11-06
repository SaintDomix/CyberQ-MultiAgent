"""Two bounded anonymous checks. Status codes alone never establish exposure."""
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .models import Decision, Outcome, RequestSpec


def hint(parent):
    return f"{parent.category or ''} {parent.finding_type or ''}".lower()


def context(parent):
    value = parent.evidence.get("active_context", {}) if isinstance(parent.evidence, dict) else {}
    return value if isinstance(value, dict) else {}


class SensitivePath:
    name = "sensitive_path"

    def propose(self, parent):
        if "expos" not in hint(parent):
            return None
        url = context(parent).get("url") or parent.affected_asset
        profile = None
        if isinstance(url, str):
            path = urlsplit(url).path.lower()
            profile = {"/.git/head": "git", "/.env": "environment", "/phpinfo.php": "phpinfo",
                       "/server-status": "apache_status"}.get(next((suffix for suffix in
                           ["/.git/head", "/.env", "/phpinfo.php", "/server-status"] if path.endswith(suffix)), ""))
            if "directory listing" in hint(parent):
                profile = "directory_index"
        if not profile or urlsplit(url).query:
            return Decision("NOT_APPLICABLE", "No supported explicit path/content profile", ("explicit URL", "recognized content profile"))
        return Decision("APPLICABLE", "Explicit path with a recognizable content signature", context={"url": url, "profile": profile})

    def requests(self, candidate):
        url = candidate.context["url"]
        control = urljoin(url, ".__branch1_control_" + candidate.candidate_id[-16:])
        return [RequestSpec(url, "read candidate path"), RequestSpec(control, "compare inert nonexistent path")]

    def evaluate(self, candidate, responses):
        response, control = responses
        text = response.text
        location = next((v for k,v in response.headers.items() if k.lower() == "location"), "")
        if response.status in (404, 410):
            return Outcome("NOT_FOUND", "PASS", "NOT_CONFIRMED", "Path not found on this request; no system-wide safety claim")
        if response.status in (401, 403) or (300 <= response.status < 400 and re.search(r"login|auth", location, re.I)) or re.search(r'name=[\"\'](?:password|username)[\"\']|permission denied|access denied', text, re.I):
            return Outcome("AUTH_DENIED", "PASS", "NOT_CONFIRMED", "Anonymous request denied or redirected to authentication")
        profile = candidate.context["profile"]
        signatures = {
            "git": bool(re.fullmatch(r"(?:ref: refs/[^\s]+|[0-9a-f]{40})\s*", text, re.I)),
            "environment": not re.search(r"<(?:html|body|form)\b", text, re.I) and bool(re.search(r"(?m)^(?:DB_|DATABASE_|APP_|SECRET_|API_)[A-Z_]*\s*=\s*\S+", text)),
            "phpinfo": bool(re.search(r"<title>\s*phpinfo\(\)\s*</title>", text, re.I)) and "php version" in text.lower(),
            "apache_status": "apache server status" in text.lower() and bool(re.search(r"server uptime|server version", text, re.I)),
            "directory_index": bool(re.search(r"<title>\s*Index of ", text, re.I)) and bool(re.search(r"href=", text, re.I)),
        }
        if response.status == 200 and signatures.get(profile) and response.body != control.body:
            return Outcome("EXPOSED_CONTENT", "FAIL", "CONFIRMED", "Recognizable content publicly readable and different from control; confirms exposure only")
        return Outcome("INCONCLUSIVE", "PARTIAL", "NOT_CONFIRMED", "No distinctive readable content; HTTP status alone is insufficient (generic/error/soft-404 responses included)")


class OpenRedirect:
    name = "open_redirect"

    def propose(self, parent):
        if "open redirect" not in hint(parent):
            return None
        ctx = context(parent)
        if not isinstance(ctx.get("url"), str) or not isinstance(ctx.get("redirect_parameter"), str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", ctx["redirect_parameter"]) or ctx.get("read_only") is not True:
            return Decision("NOT_APPLICABLE", "Explicit read-only endpoint and redirect parameter required", ("url", "redirect_parameter", "read_only=true"))
        if ctx.get("authentication", "anonymous") != "anonymous":
            return Decision("NOT_APPLICABLE", "Authenticated execution is not implemented", authentication_requirement=str(ctx["authentication"]))
        return Decision("APPLICABLE", "Explicit anonymous read-only redirect context", context=dict(ctx))

    def requests(self, candidate):
        ctx = candidate.context
        url = ctx["url"]
        destination = "https://branch1-validation.invalid/return/" + candidate.candidate_id
        parts = urlsplit(url)
        query = [(k,v) for k,v in parse_qsl(parts.query, keep_blank_values=True) if k != ctx["redirect_parameter"]]
        test = urlunsplit(parts._replace(query=urlencode(query + [(ctx["redirect_parameter"], destination)])))
        return [RequestSpec(url, "baseline redirect without supplied destination"), RequestSpec(test, "inert off-origin redirect destination; never followed")]

    def evaluate(self, candidate, responses):
        baseline, tested = responses
        expected = "https://branch1-validation.invalid/return/" + candidate.candidate_id
        def destination(response):
            location = next((v for k,v in response.headers.items() if k.lower() == "location"), "")
            return urljoin(response.url, location) if location else None
        dest = destination(tested)
        if tested.status in {301,302,303,307,308} and dest == expected and destination(baseline) != expected:
            return Outcome("EXTERNAL_REDIRECT", "FAIL", "CONFIRMED", "Server Location reflects controlled off-origin destination; redirect was not followed")
        if dest and urlsplit(dest).netloc != urlsplit(candidate.context["url"]).netloc:
            return Outcome("INCONCLUSIVE", "PARTIAL", "NOT_CONFIRMED", "Unrelated external redirect does not prove parameter-controlled redirect")
        return Outcome("INTERNAL_OR_NO_REDIRECT", "PASS", "NOT_CONFIRMED", "No controlled external redirect observed; negative check does not establish system safety")


from .advanced import ADVANCED_VALIDATORS

DEFAULT_VALIDATORS = (SensitivePath(), OpenRedirect(), *ADVANCED_VALIDATORS)
