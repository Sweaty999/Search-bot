from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import tldextract


MAX_QUERY_LENGTH = 500


def clean_query(value: str) -> str:
    return " ".join(value.strip().split())[:MAX_QUERY_LENGTH]


def is_public_http_url(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    host = (parsed.hostname or "").strip("[]").lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return True


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    extracted = tldextract.extract(value)
    if not extracted.domain or not extracted.suffix:
        return value
    return f"{extracted.domain}.{extracted.suffix}"
