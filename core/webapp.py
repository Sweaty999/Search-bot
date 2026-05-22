from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from core.localization import t


@dataclass(frozen=True)
class WebAppUrlCheck:
    valid: bool
    reason: str | None = None


def validate_webapp_url(url: str | None) -> WebAppUrlCheck:
    if not url:
        return WebAppUrlCheck(False, t("errors.webapp_not_configured"))
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return WebAppUrlCheck(False, t("errors.webapp_https_required"))
    host = (parsed.hostname or "").lower()
    if not host:
        return WebAppUrlCheck(False, t("errors.webapp_host_missing"))
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return WebAppUrlCheck(False, t("errors.webapp_localhost_forbidden"))
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return WebAppUrlCheck(False, t("errors.webapp_private_ip_forbidden"))
    except ValueError:
        pass
    return WebAppUrlCheck(True)
