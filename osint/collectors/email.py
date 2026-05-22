from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

import dns.asyncresolver
from email_validator import EmailNotValidError, validate_email

from core.localization import t
from osint.collectors.base import BaseCollector, CollectorContext, compact_dict
from osint.models import Entity, EntityKind, Finding, SearchHit


DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "10minutemail.com",
    "guerrillamail.com",
    "tempmail.com",
    "yopmail.com",
    "throwawaymail.com",
}


class EmailCollector(BaseCollector):
    name = "email"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        try:
            email = validate_email(context.entity.normalized, check_deliverability=False)
        except EmailNotValidError as exc:
            return [
                Finding(
                    category="email",
                    title=t("findings.email_format_title"),
                    source=self.name,
                    confidence=0.25,
                    description=str(exc),
                    data={"email": context.entity.normalized, "syntax_valid": False},
                )
            ]
        domain = email.domain
        findings = [
            Finding(
                category="email",
                title=t("findings.email_format_title"),
                source=self.name,
                confidence=0.95,
                data={
                    "normalized": email.normalized,
                    "local_part": email.local_part,
                    "domain": domain,
                    "syntax_valid": True,
                    "disposable_risk": domain.lower() in DISPOSABLE_DOMAINS,
                },
                entities=[Entity(kind=EntityKind.domain, value=domain, normalized=domain, confidence=0.9)],
            )
        ]

        abstract_data = await _abstract_email_validation(context, email.normalized)
        if abstract_data:
            findings.append(
                Finding(
                    category="email_validation",
                    title=t("findings.abstract_email_title"),
                    source="abstract",
                    confidence=0.88,
                    data=abstract_data,
                )
            )

        dns_data = await _email_dns(domain)
        findings.append(
            Finding(
                category="dns",
                title=t("findings.email_dns_title"),
                source="dns",
                confidence=0.85 if dns_data.get("mx") else 0.45,
                data=dns_data,
                entities=[Entity(kind=EntityKind.domain, value=domain, normalized=domain, confidence=0.85)],
            )
        )

        if context.api.enabled("virustotal"):
            findings.append(
                Finding(
                    category="threat_reputation",
                    title=t("findings.email_reputation_title"),
                    source="virustotal",
                    confidence=0.74,
                    data=await _virustotal_domain(context, domain),
                )
            )

        gravatar_hash = hashlib.md5(email.normalized.strip().lower().encode("utf-8"), usedforsecurity=False).hexdigest()
        findings.append(
            Finding(
                category="profile",
                title=t("findings.gravatar_title"),
                source="gravatar",
                source_url=f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404",
                confidence=0.35,
                data={
                    "md5": gravatar_hash,
                    "status_code": await _gravatar_status(context, gravatar_hash),
                    "note": t("findings.gravatar_note"),
                },
            )
        )

        if context.deep or context.premium:
            queries = _email_queries(email.normalized, email.local_part, domain)
            search_results = await _search_many(context, queries, limit=5)
            hits = _dedupe_hits(search_results)
            github_hits = [hit for hit in hits if "github.com" in (hit.domain or urlsplit(hit.url).netloc)]
            findings.append(
                Finding(
                    category="public_mentions",
                    title=t("findings.email_mentions_title"),
                    source="multi_engine_search",
                    confidence=0.7 if hits else 0.2,
                    data={
                        "queries": queries,
                        "hits": [hit.model_dump() for hit in hits],
                        "github_public_references": [hit.model_dump() for hit in github_hits],
                        "public_websites": [hit.model_dump() for hit in hits if "github.com" not in (hit.domain or "")][:30],
                        "policy": t("findings.policy_public_only"),
                    },
                    entities=_entities_from_hits(hits),
                )
            )
            findings.append(
                Finding(
                    category="email_domain_intelligence",
                    title=t("findings.email_domain_intel_title"),
                    source=self.name,
                    confidence=0.72 if dns_data.get("mx") else 0.42,
                    data={
                        "email_domain": domain,
                        "mx_provider": _mx_provider(dns_data.get("mx", [])),
                        "spf": dns_data.get("spf", []),
                        "dmarc": dns_data.get("dmarc", []),
                        "dkim": dns_data.get("dkim", {}),
                        "website_metadata": await _domain_website_metadata(context, domain),
                        "domain_reputation": await _virustotal_domain(context, domain) if context.api.enabled("virustotal") else {},
                        "deliverability": _deliverability(abstract_data, dns_data),
                        "disposable_risk": domain.lower() in DISPOSABLE_DOMAINS,
                    },
                    entities=[Entity(kind=EntityKind.domain, value=domain, normalized=domain, confidence=0.9), *_entities_from_hits(hits)[:30]],
                )
            )
        return findings


async def _search_many(context: CollectorContext, queries: list[str], limit: int) -> list[SearchHit]:
    import asyncio

    results = await asyncio.gather(*[context.search.search(context.http, query, limit=limit) for query in queries])
    return [hit for group in results for hit in group]


def _email_queries(email: str, local: str, domain: str) -> list[str]:
    return _unique(
        [
            f'"{email}"',
            f'"{email}" site:github.com',
            f'"{email}" site:gitlab.com',
            f'"{email}" filetype:pdf',
            f'"{email}" "contact"',
            f'"{local}" "{domain}"',
            f'"{domain}" "email"',
            f'"{domain}" "MX"',
            f'"{domain}" "SPF" "DMARC"',
        ]
    )


async def _gravatar_status(context: CollectorContext, gravatar_hash: str) -> int | None:
    try:
        async with context.http.get(f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404", allow_redirects=False) as response:
            return response.status
    except Exception:
        return None


async def _domain_website_metadata(context: CollectorContext, domain: str) -> dict[str, object]:
    from osint.parsers.html import extract_page_metadata

    for url in (f"https://{domain}", f"http://{domain}"):
        try:
            async with context.http.get(url, allow_redirects=True) as response:
                text = await response.text(errors="ignore")
                metadata = extract_page_metadata(text[:180_000], str(response.url))
                return compact_dict({"url": str(response.url), "status_code": response.status, **metadata})
        except Exception:
            continue
    return {}


def _entities_from_hits(hits: list[SearchHit]) -> list[Entity]:
    entities: list[Entity] = []
    email_re = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}")
    phone_re = re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)")
    for hit in hits[:50]:
        entities.append(Entity(kind=EntityKind.url, value=hit.url, normalized=hit.url, confidence=hit.confidence, metadata={"platform": hit.domain}))
        if hit.domain:
            entities.append(Entity(kind=EntityKind.domain, value=hit.domain, normalized=hit.domain, confidence=0.58))
        haystack = f"{hit.title} {hit.snippet} {hit.url}"
        for found in email_re.findall(haystack)[:6]:
            entities.append(Entity(kind=EntityKind.email, value=found, normalized=found.lower(), confidence=0.62))
        for found in phone_re.findall(haystack)[:4]:
            entities.append(Entity(kind=EntityKind.phone, value=found, normalized=found, confidence=0.45))
    return _dedupe_entities(entities)


def _dedupe_hits(hits: list[SearchHit]) -> list[SearchHit]:
    seen: set[str] = set()
    output: list[SearchHit] = []
    for hit in hits:
        key = hit.url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        output.append(hit)
    return output[:70]


def _dedupe_entities(entities: list[Entity]) -> list[Entity]:
    seen: set[tuple[str, str]] = set()
    output: list[Entity] = []
    for entity in entities:
        key = (entity.kind.value, entity.normalized.casefold())
        if key in seen:
            continue
        seen.add(key)
        output.append(entity)
    return output


def _mx_provider(records: object) -> str:
    if not isinstance(records, list) or not records:
        return ""
    host = str(records[0]).lower()
    if "google" in host or "aspmx" in host:
        return "Google Workspace"
    if "outlook" in host or "protection.outlook" in host:
        return "Microsoft 365"
    if "yandex" in host:
        return "Yandex"
    if "zoho" in host:
        return "Zoho"
    return host


def _deliverability(abstract_data: dict[str, object] | None, dns_data: dict[str, object]) -> dict[str, object]:
    if abstract_data:
        return compact_dict(
            {
                "deliverability": abstract_data.get("deliverability"),
                "quality_score": abstract_data.get("quality_score"),
                "is_mx_found": abstract_data.get("is_mx_found"),
                "is_smtp_valid": abstract_data.get("is_smtp_valid"),
            }
        )
    return {"is_mx_found": bool(dns_data.get("mx")), "source": "dns"}


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = " ".join(str(value).split())
        if normalized and normalized.casefold() not in seen:
            seen.add(normalized.casefold())
            output.append(normalized)
    return output


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
    dkim: dict[str, list[str]] = {}
    for selector in ("default", "google", "selector1", "selector2", "mail", "smtp", "k1"):
        try:
            answers = await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=4)
            dkim[selector] = [str(answer).strip('"') for answer in answers]
        except Exception:
            continue
    data["dkim"] = dkim
    return compact_dict(data)
