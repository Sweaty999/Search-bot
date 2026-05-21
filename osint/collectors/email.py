from __future__ import annotations

import hashlib

import dns.asyncresolver
from email_validator import validate_email

from osint.collectors.base import BaseCollector, CollectorContext, compact_dict
from osint.models import Entity, EntityKind, Finding


class EmailCollector(BaseCollector):
    name = "email"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        email = validate_email(context.entity.normalized, check_deliverability=False)
        domain = email.domain
        findings = [
            Finding(
                category="email",
                title="Email format and domain",
                source=self.name,
                confidence=0.95,
                data={"normalized": email.normalized, "local_part": email.local_part, "domain": domain},
                entities=[Entity(kind=EntityKind.domain, value=domain, normalized=domain, confidence=0.9)],
            )
        ]

        abstract_data = await _abstract_email_validation(context, email.normalized)
        if abstract_data:
            findings.append(
                Finding(
                    category="email_validation",
                    title="Abstract API email validation",
                    source="abstract",
                    confidence=0.88,
                    data=abstract_data,
                )
            )

        dns_data = await _email_dns(domain)
        findings.append(
            Finding(
                category="dns",
                title="Email DNS records",
                source="dns",
                confidence=0.85 if dns_data.get("mx") else 0.45,
                data=dns_data,
            )
        )

        if context.api.enabled("virustotal"):
            findings.append(
                Finding(
                    category="threat_reputation",
                    title="Email domain VirusTotal reputation",
                    source="virustotal",
                    confidence=0.74,
                    data=await _virustotal_domain(context, domain),
                )
            )

        gravatar_hash = hashlib.md5(email.normalized.strip().lower().encode("utf-8"), usedforsecurity=False).hexdigest()
        findings.append(
            Finding(
                category="profile",
                title="Gravatar public avatar endpoint",
                source="gravatar",
                source_url=f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404",
                confidence=0.35,
                data={"md5": gravatar_hash, "note": "URL is a public profile check endpoint; a 200 response can indicate a public avatar."},
            )
        )

        if context.deep or context.premium:
            hits = await context.search.search(context.http, f'"{email.normalized}" OR "{email.local_part}" "{domain}"', limit=10)
            github_hits = await context.search.search(context.http, f'"{email.normalized}" site:github.com', limit=5)
            findings.append(
                Finding(
                    category="public_mentions",
                    title="Public email mentions",
                    source="multi_engine_search",
                    confidence=0.7 if hits else 0.2,
                    data={
                        "hits": [hit.model_dump() for hit in hits],
                        "github_public_references": [hit.model_dump() for hit in github_hits],
                    },
                )
            )
        return findings


async def _abstract_email_validation(context: CollectorContext, email: str) -> dict[str, object] | None:
    if not context.api.enabled("abstract"):
        return None
    payload = await context.api.get_json(
        "abstract",
        context.http,
        "https://emailvalidation.abstractapi.com/v1/",
        params={"api_key": context.settings.abstract_api_key, "email": email},
    )
    if not payload:
        return None
    return compact_dict(
        {
            "email": payload.get("email"),
            "deliverability": payload.get("deliverability"),
            "quality_score": payload.get("quality_score"),
            "is_valid_format": _abstract_flag(payload, "is_valid_format"),
            "is_free_email": _abstract_flag(payload, "is_free_email"),
            "is_disposable_email": _abstract_flag(payload, "is_disposable_email"),
            "is_role_email": _abstract_flag(payload, "is_role_email"),
            "is_catchall_email": _abstract_flag(payload, "is_catchall_email"),
            "is_mx_found": _abstract_flag(payload, "is_mx_found"),
            "is_smtp_valid": _abstract_flag(payload, "is_smtp_valid"),
            "domain": payload.get("domain"),
        }
    )


def _abstract_flag(payload: dict[str, object], key: str) -> object:
    value = payload.get(key)
    if isinstance(value, dict):
        return value.get("value")
    return value


async def _virustotal_domain(context: CollectorContext, domain: str) -> dict[str, object]:
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
        }
    )


async def _email_dns(domain: str) -> dict[str, object]:
    resolver = dns.asyncresolver.Resolver()
    data: dict[str, object] = {}
    for record_type in ("MX", "TXT", "SPF", "DMARC"):
        query_name = domain if record_type != "DMARC" else f"_dmarc.{domain}"
        actual_type = "TXT" if record_type in {"SPF", "DMARC"} else record_type
        try:
            answers = await resolver.resolve(query_name, actual_type, lifetime=5)
            data[record_type.lower()] = [str(answer).strip('"') for answer in answers]
        except Exception as exc:
            data[record_type.lower()] = []
            data[f"{record_type.lower()}_error"] = str(exc)
    return compact_dict(data)
