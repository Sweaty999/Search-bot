from __future__ import annotations

import ipaddress
import socket
from typing import Any

from osint.collectors.base import BaseCollector, CollectorContext, compact_dict
from osint.models import Finding


class IpCollector(BaseCollector):
    name = "ip"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        ip = ipaddress.ip_address(context.entity.normalized)
        findings = [
            Finding(
                category="ip",
                title="IP address classification and reverse DNS",
                source=self.name,
                confidence=0.9,
                data={
                    "ip": str(ip),
                    "version": ip.version,
                    "is_global": ip.is_global,
                    "is_private": ip.is_private,
                    "is_reserved": ip.is_reserved,
                    "reverse_dns": _reverse_dns(str(ip)),
                    "local_asn_lookup": "not_configured",
                },
            )
        ]

        if context.api.enabled("ipinfo"):
            findings.append(
                Finding(
                    category="geo_asn",
                    title="IPInfo geolocation and ASN",
                    source="ipinfo",
                    confidence=0.82,
                    data=await _ipinfo(context, str(ip)),
                )
            )

        if context.api.enabled("shodan"):
            findings.append(
                Finding(
                    category="host_intelligence",
                    title="Shodan host intelligence",
                    source="shodan",
                    confidence=0.78,
                    data=await _shodan_host(context, str(ip)),
                )
            )

        if context.api.enabled("virustotal"):
            findings.append(
                Finding(
                    category="threat_reputation",
                    title="VirusTotal IP reputation",
                    source="virustotal",
                    confidence=0.78,
                    data=await _virustotal_ip(context, str(ip)),
                )
            )
        return findings


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


async def _ipinfo(context: CollectorContext, ip: str) -> dict[str, Any]:
    payload = await context.api.get_json(
        "ipinfo",
        context.http,
        f"https://ipinfo.io/{ip}/json",
        params={"token": context.settings.ipinfo_token},
    )
    if not payload:
        return {}
    return compact_dict(
        {
            "ip": payload.get("ip"),
            "hostname": payload.get("hostname"),
            "city": payload.get("city"),
            "region": payload.get("region"),
            "country": payload.get("country"),
            "loc": payload.get("loc"),
            "org": payload.get("org"),
            "postal": payload.get("postal"),
            "timezone": payload.get("timezone"),
            "asn": payload.get("asn"),
            "company": payload.get("company"),
            "privacy": payload.get("privacy"),
        }
    )


async def _shodan_host(context: CollectorContext, ip: str) -> dict[str, Any]:
    payload = await context.api.get_json(
        "shodan",
        context.http,
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": context.settings.shodan_api_key},
    )
    if not payload:
        return {}
    services = []
    for item in payload.get("data", [])[:20]:
        services.append(
            compact_dict(
                {
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "hostnames": item.get("hostnames"),
                    "domains": item.get("domains"),
                    "ssl": bool(item.get("ssl")),
                    "timestamp": item.get("timestamp"),
                    "banner": str(item.get("data", ""))[:800],
                }
            )
        )
    return compact_dict(
        {
            "ip": payload.get("ip_str"),
            "ports": payload.get("ports"),
            "hostnames": payload.get("hostnames"),
            "domains": payload.get("domains"),
            "organization": payload.get("org"),
            "isp": payload.get("isp"),
            "asn": payload.get("asn"),
            "country": payload.get("country_name"),
            "city": payload.get("city"),
            "services": services,
        }
    )


async def _virustotal_ip(context: CollectorContext, ip: str) -> dict[str, Any]:
    payload = await context.api.get_json(
        "virustotal",
        context.http,
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": context.settings.vt_api_key or ""},
    )
    attributes = (payload or {}).get("data", {}).get("attributes", {})
    return compact_dict(
        {
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "reputation": attributes.get("reputation"),
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "country": attributes.get("country"),
            "network": attributes.get("network"),
        }
    )
