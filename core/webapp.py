from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class WebAppUrlCheck:
    valid: bool
    reason: str | None = None


def validate_webapp_url(url: str | None) -> WebAppUrlCheck:
    if not url:
        return WebAppUrlCheck(False, "WEBAPP_URL is not configured.")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return WebAppUrlCheck(False, "WebApp requires HTTPS URL. Use ngrok/cloudflared/render/railway domain.")
    host = (parsed.hostname or "").lower()
    if not host:
        return WebAppUrlCheck(False, "WEBAPP_URL host is missing.")
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return WebAppUrlCheck(False, "WEBAPP_URL cannot use localhost or 127.0.0.1 in Telegram.")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return WebAppUrlCheck(False, "WEBAPP_URL cannot point to a private/local IP.")
    except ValueError:
        pass
    return WebAppUrlCheck(True)
