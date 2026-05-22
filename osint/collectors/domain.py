from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import date, datetime
from typing import Any

import dns.asyncresolver
import whois
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from core.localization import t
from osint.collectors.base import BaseCollector, CollectorContext, compact_dict, fetch_text
from osint.models import Entity, EntityKind, Finding
from osint.parsers.html import extract_page_metadata


class DomainCollector(BaseCollector):
    name = "domain"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        domain = context.entity.normalized
        dns_task = asyncio.create_task(_dns_records(domain))
        whois_task = asyncio.create_task(asyncio.to_thread(_whois_lookup, domain))
        ssl_task = asyncio.create_task(asyncio.to_thread(_ssl_certificate, domain))

        findings: list[Finding] = []
        if context.api.enabled("virustotal"):
            findings.append(
                Finding(
                    category="threat_reputation",
                    title=t("findings.domain_vt_title"),
                    source="virustotal",
                    confidence=0.78,
                    data=await _virustotal_domain(context, domain),
                )
            )

        if context.api.enabled("shodan"):
            findings.append(
                Finding(
                    category="host_intelligence",
                    title=t("findings.domain_shodan_title"),
                    source="shodan",
                    confidence=0.72,
                    data=await _shodan_domain(context, domain),
                )
            )

        findings.extend([
            Finding(
                category="dns",
                title=t("findings.domain_dns_title"),
                source="dns",
                confidence=0.88,
                data=await dns_task,
            ),
            Finding(
                category="whois",
                title=t("findings.domain_whois_title"),
                source="whois",
                confidence=0.7,
                data=await whois_task,
            ),
            Finding(
                category="ssl",
                title=t("findings.domain_tls_title"),
                source="ssl",
                confidence=0.75,
                data=await ssl_task,
            ),
        ])

        homepage = await _homepage_metadata(context, domain)
        if homepage:
            findings.append(homepage)

        robots = await fetch_text(context, f"https://{domain}/robots.txt", max_chars=20_000)
        sitemap = await fetch_text(context, f"https://{domain}/sitemap.xml", max_chars=50_000)
        findings.append(
            Finding(
                category="web_files",
                title=t("findings.domain_web_files_title"),
                source="http",
                confidence=0.6 if robots or sitemap else 0.25,
                data=compact_dict(
                    {
                        "robots_status": robots.status if robots else None,
                        "robots_url": robots.url if robots else None,
                        "robots_preview": (robots.text or "")[:1200] if robots else None,
                        "sitemap_status": sitemap.status if sitemap else None,
                        "sitemap_url": sitemap.url if sitemap else None,
                        "sitemap_preview": (sitemap.text or "")[:1200] if sitemap else None,
                    }
                ),
            )
        )

        if context.deep or context.premium:
            subdomains = await _crtsh_subdomains(context, domain)
            findings.append(
                Finding(
                    category="subdomains",
                    title=t("findings.domain_ct_title"),
                    source="crt.sh",
                    source_url=f"https://crt.sh/?q=%.{domain}",
                    confidence=0.75 if subdomains else 0.25,
                    data={"subdomains": subdomains[:100], "count": len(subdomains)},
                    entities=[
                        Entity(kind=EntityKind.domain, value=item, normalized=item, confidence=0.74)
                        for item in subdomains[:50]
                    ],
                )
            )
        return findings


async def _dns_records(domain: str) -> dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    output: dict[str, Any] = {}
    for record_type in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA"):
        try:
            answers = await resolver.resolve(domain, record_type, lifetime=5)
            output[record_type.lower()] = [str(answer).strip('"') for answer in answers]
        except Exception as exc:
            output[f"{record_type.lower()}_error"] = str(exc)
    return compact_dict(output)


def _whois_lookup(domain: str) -> dict[str, Any]:
    try:
        raw = whois.whois(domain)
    except Exception as exc:
        return {"error": str(exc)}
    return {key: _serialize(value) for key, value in dict(raw).items() if value not in (None, "", [], {})}


def _ssl_certificate(domain: str) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert_der = tls.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_der)
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return compact_dict(
            {
                "subject_common_name": common_names[0].value if common_names else None,
                "issuer_common_name": issuer_names[0].value if issuer_names else None,
                "serial_number": str(cert.serial_number),
                "not_valid_before": cert.not_valid_before_utc.isoformat(),
                "not_valid_after": cert.not_valid_after_utc.isoformat(),
                "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            }
        )
    except Exception as exc:
        return {"error": str(exc)}


async def _homepage_metadata(context: CollectorContext, domain: str) -> Finding | None:
    for scheme in ("https", "http"):
        fetched = await fetch_text(context, f"{scheme}://{domain}", max_chars=250_000)
        if not fetched:
            continue
        metadata = extract_page_metadata(fetched.text or "", fetched.url)
        return Finding(
            category="website",
            title=t("findings.domain_homepage_title"),
            source="http",
            source_url=fetched.url,
            confidence=0.82,
            data={"status_code": fetched.status, "metadata": metadata},
        )
    return None


async def _crtsh_subdomains(context: CollectorContext, domain: str) -> list[str]:
    try:
        async with context.http.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
        ) as response:
            if response.status >= 400:
                return []
            rows = await response.json(content_type=None)
    except Exception:
        return []
    subdomains: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        name = str(row.get("name_value", ""))
        for item in name.splitlines():
            item = item.lower().strip("*. ")
            if item.endswith(domain):
                subdomains.add(item)
    return sorted(subdomains)


def _serialize(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    return value if isinstance(value, (str, int, float, bool)) else str(value)


async def _virustotal_domain(context: CollectorContext, domain: str) -> dict[str, Any]:
    payload = await context.api.get_json(
        "virustotal",
        context.http,
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": context.settings.vt_api_key or ""},
    )
    attributes = (payload or {}).get("data", {}).get("attributes", {})
    return compact_dict(
        {
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories"),
            "registrar": attributes.get("registrar"),
            "creation_date": attributes.get("creation_date"),
            "last_dns_records": attributes.get("last_dns_records"),
        }
    )


async def _shodan_domain(context: CollectorContext, domain: str) -> dict[str, Any]:
    dns_payload = await context.api.get_json(
        "shodan",
        context.http,
        f"https://api.shodan.io/dns/domain/{domain}",
        params={"key": context.settings.shodan_api_key},
    )
    search_payload = await context.api.get_json(
        "shodan",
        context.http,
        "https://api.shodan.io/shodan/host/search",
        params={"key": context.settings.shodan_api_key, "query": f"hostname:{domain}", "limit": 20},
    )
    matches = []
    for item in (search_payload or {}).get("matches", [])[:20]:
        matches.append(
            compact_dict(
                {
                    "ip": item.get("ip_str"),
                    "port": item.get("port"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "hostnames": item.get("hostnames"),
                    "domains": item.get("domains"),
                    "organization": item.get("org"),
                    "timestamp": item.get("timestamp"),
                }
            )
        )
    return compact_dict(
        {
            "subdomains": (dns_payload or {}).get("subdomains"),
            "records": (dns_payload or {}).get("data"),
            "matches": matches,
            "total": (search_payload or {}).get("total"),
        }
    )
