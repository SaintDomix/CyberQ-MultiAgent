"""Ported from first_branch_v22; see docs/BRANCH1_PIPELINE.md for changes."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, urlunparse


def normalize(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not url.endswith("/"):
        url += "/"
    return url


def origin(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def with_scheme(url: str, scheme: str) -> str:
    p = urlparse(url)
    return urlunparse((scheme, p.netloc, p.path or "/", "", "", ""))


def join(base: str, path: str) -> str:
    return urljoin(base, path)


def trunc(value: str, limit: int = 500) -> str:
    value = (value or "").replace("\n", " ").replace("\r", " ").strip()
    return value if len(value) <= limit else value[:limit] + "..."


def versioned_server(value: str) -> bool:
    return bool(
        re.search(r"\b[A-Za-z][A-Za-z0-9._-]*/\d+(?:\.\d+)+", value or "")
    )
