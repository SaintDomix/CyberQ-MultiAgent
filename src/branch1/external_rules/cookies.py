"""Ported from first_branch_v22; see docs/BRANCH1_PIPELINE.md for changes."""
from __future__ import annotations

from http.cookies import SimpleCookie

from .models import Finding
from .utils import trunc


def _set_cookie_lines(response):
    try:
        values = response.raw.headers.getlist("Set-Cookie")
        if values:
            return values
    except Exception:
        pass

    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def _parse(response):
    rows = []

    for line in _set_cookie_lines(response):
        cookie = SimpleCookie()
        try:
            cookie.load(line)
        except Exception:
            continue

        for name, morsel in cookie.items():
            rows.append({
                "name": name,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or "",
                "path": morsel["path"] or "",
                "domain": morsel["domain"] or "",
                "raw": line,
            })
    return rows


def cookie_findings(response):
    rows = _parse(response)
    session_rows = [r for r in rows if r["name"].lower() == "moodlesession"]

    if not session_rows:
        return [Finding(
            "COOKIE-000", "Authentication & Session",
            "MoodleSession cookie observation",
            "PARTIAL", "INFO", "CONFIRMED", "SESSION",
            "MoodleSession was not set by the assessed response",
            "Observe MoodleSession during login/session workflow.",
            "Set-Cookie response headers",
            "Session-cookie attributes could not be assessed from this response.",
            "Re-check the login response or authenticated workflow."
        )]

    c = session_rows[0]
    out = []

    out.append(Finding(
        "COOKIE-001", "Authentication & Session",
        "MoodleSession Secure flag",
        "PASS" if c["secure"] else "FAIL",
        "INFO" if c["secure"] else "MEDIUM",
        "CONFIRMED", "TRANSPORT",
        f"Secure={c['secure']}",
        "Secure=True when HTTPS is used.",
        trunc(c["raw"]),
        "The session cookie is restricted to HTTPS."
        if c["secure"]
        else "The session cookie is not restricted to HTTPS.",
        "Maintain Secure."
        if c["secure"]
        else "Enable HTTPS and set Secure for MoodleSession."
    ))

    out.append(Finding(
        "COOKIE-002", "Authentication & Session",
        "MoodleSession HttpOnly flag",
        "PASS" if c["httponly"] else "FAIL",
        "INFO" if c["httponly"] else "MEDIUM",
        "CONFIRMED", "SESSION",
        f"HttpOnly={c['httponly']}",
        "HttpOnly=True for MoodleSession.",
        trunc(c["raw"]),
        "HttpOnly is present."
        if c["httponly"]
        else "HttpOnly is absent.",
        "Maintain HttpOnly."
        if c["httponly"]
        else "Set HttpOnly for MoodleSession."
    ))

    out.append(Finding(
        "COOKIE-003", "Authentication & Session",
        "MoodleSession SameSite policy",
        "PASS" if c["samesite"] else "PARTIAL",
        "INFO" if c["samesite"] else "LOW",
        "CONFIRMED", "SESSION",
        f"SameSite={c['samesite'] or 'absent'}",
        "Explicit SameSite policy appropriate for Moodle.",
        trunc(c["raw"]),
        "Explicit SameSite is present."
        if c["samesite"]
        else "No explicit SameSite attribute was observed.",
        "Review/maintain the SameSite policy."
    ))

    out.append(Finding(
        "COOKIE-004", "Authentication & Session",
        "MoodleSession Path scope",
        "PASS" if c["path"] else "PARTIAL",
        "INFO" if c["path"] else "LOW",
        "CONFIRMED", "SESSION",
        f"Path={c['path'] or 'absent'}",
        "Session cookie should be scoped appropriately.",
        trunc(c["raw"]),
        "Explicit cookie path is configured."
        if c["path"]
        else "No explicit cookie path was observed.",
        "Keep the cookie path no broader than required."
    ))

    if c["domain"]:
        broad = c["domain"].startswith(".")
        out.append(Finding(
            "COOKIE-005", "Authentication & Session",
            "MoodleSession Domain scope",
            "PARTIAL" if broad else "PASS",
            "LOW" if broad else "INFO",
            "CONFIRMED", "SESSION",
            f"Domain={c['domain']}",
            "Cookie domain should not be broader than required.",
            trunc(c["raw"]),
            "Cookie is scoped to a parent domain."
            if broad
            else "Cookie domain is explicitly scoped.",
            "Review whether the domain scope is broader than necessary."
        ))
    else:
        out.append(Finding(
            "COOKIE-005", "Authentication & Session",
            "MoodleSession Domain scope",
            "PASS", "INFO", "CONFIRMED", "SESSION",
            "No Domain attribute (host-only cookie)",
            "Host-only cookie unless a broader domain is required.",
            trunc(c["raw"]),
            "The cookie is host-only.",
            "No action required."
        ))

    return out
