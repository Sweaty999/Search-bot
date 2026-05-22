from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from core.localization import t
from osint.collectors.base import BaseCollector, CollectorContext, compact_dict
from osint.models import Entity, EntityKind, Finding, SearchHit


class PhoneCollector(BaseCollector):
    name = "phone"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        phone = phonenumbers.parse(context.entity.normalized, context.settings.default_phone_region)
        region_code = phonenumbers.region_code_for_number(phone)
        variants = _phone_variants(phone, context.entity.value)
        data = compact_dict(
            {
                "e164": phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164),
                "international": phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "national": phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.NATIONAL),
                "rfc3966": phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.RFC3966),
                "country": geocoder.description_for_number(phone, "ru") or geocoder.description_for_number(phone, "en"),
                "country_flag": _country_flag(region_code),
                "carrier": carrier.name_for_number(phone, "ru") or carrier.name_for_number(phone, "en"),
                "timezones": list(timezone.time_zones_for_number(phone)),
                "region_code": region_code,
                "possible_region": region_code,
                "valid": phonenumbers.is_valid_number(phone),
                "possible": phonenumbers.is_possible_number(phone),
                "format_variants": variants,
            }
        )
        findings = [
            Finding(
                category="phone",
                title=t("findings.phone_metadata_title"),
                source=self.name,
                confidence=0.92,
                data=data,
                entities=[Entity(kind=EntityKind.phone, value=data["e164"], normalized=data["e164"], confidence=0.92)],
            )
        ]

        if context.deep or context.premium:
            queries = _phone_queries(phone, variants)
            search_results = await _search_many(context, queries, limit=5)
            hits = _dedupe_hits(search_results)
            classified = [_classify_phone_mention(hit.model_dump()) for hit in hits]
            reputation = _phone_reputation(classified)
            findings.append(
                Finding(
                    category="public_mentions",
                    title=t("findings.phone_mentions_title"),
                    source="multi_engine_search",
                    confidence=0.65 if hits else 0.2,
                    data={
                        "queries": queries,
                        "hits": classified,
                        "ads": [hit for hit in classified if "marketplace_or_ads" in hit.get("mention_labels", [])],
                        "public_profiles": [hit for hit in classified if "social_or_messenger" in hit.get("mention_labels", [])],
                        "domains": sorted({str(hit.get("domain") or "") for hit in classified if hit.get("domain")}),
                        "policy": t("findings.policy_public_only"),
                    },
                    entities=_entities_from_hits(hits),
                )
            )
            findings.append(
                Finding(
                    category="phone_reputation",
                    title=t("findings.phone_reputation_title"),
                    source="multi_engine_search",
                    confidence=reputation["confidence"],
                    data=reputation,
                    entities=_entities_from_hits(hits),
                )
            )
        return findings


async def _search_many(context: CollectorContext, queries: list[str], limit: int) -> list[SearchHit]:
    import asyncio

    results = await asyncio.gather(*[context.search.search(context.http, query, limit=limit) for query in queries])
    return [hit for group in results for hit in group]


def _phone_queries(phone, variants: list[str]) -> list[str]:
    e164 = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164)
    national = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.NATIONAL)
    international = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    compact = e164.replace("+", "")
    local = "".join(char for char in national if char.isdigit())
    queries = [
        f'"{e164}"',
        f'"{international}"',
        f'"{national}"',
        f'"{compact}"',
        f'"{local}"',
        f'"{e164}" contact',
        f'"{e164}" ads',
        f'"{e164}" marketplace',
        f'"{e164}" scam OR spam',
    ]
    queries.extend(f'"{variant}"' for variant in variants[:8])
    return _unique(queries)


def _phone_variants(phone, raw_value: str) -> list[str]:
    variants = [
        raw_value,
        phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164),
        phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.NATIONAL),
        phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.RFC3966),
    ]
    digits = "".join(char for char in variants[1] if char.isdigit())
    if digits:
        variants.extend([digits, f"+{digits}", " ".join([digits[:3], digits[3:6], digits[6:]])])
    return _unique([item.strip() for item in variants if item])


def _country_flag(region_code: str | None) -> str:
    if not region_code or len(region_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(char.upper()) - ord("A")) for char in region_code)


def _dedupe_hits(hits: list[SearchHit]) -> list[SearchHit]:
    seen: set[str] = set()
    output: list[SearchHit] = []
    for hit in hits:
        key = hit.url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        output.append(hit)
    return output[:60]


def _entities_from_hits(hits: list[SearchHit]) -> list[Entity]:
    entities: list[Entity] = []
    for hit in hits[:40]:
        entities.append(Entity(kind=EntityKind.url, value=hit.url, normalized=hit.url, confidence=hit.confidence, metadata={"platform": hit.domain}))
        if hit.domain:
            entities.append(Entity(kind=EntityKind.domain, value=hit.domain, normalized=hit.domain, confidence=0.58))
    return entities


def _phone_reputation(rows: list[dict[str, object]]) -> dict[str, object]:
    risk_terms = ("scam", "spam", "fraud", "phishing", "мошен", "скам", "спам")
    risk_hits = []
    for row in rows:
        haystack = f"{row.get('title', '')} {row.get('url', '')} {row.get('snippet', '')}".casefold()
        if any(term in haystack for term in risk_terms):
            risk_hits.append(row)
    confidence = 0.72 if risk_hits else 0.35 if rows else 0.2
    return {
        "spam_indicators": risk_hits,
        "scam_indicators": risk_hits,
        "confidence": confidence,
        "risk_score": min(1.0, len(risk_hits) * 0.18),
        "policy": t("findings.policy_public_only"),
    }


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = " ".join(str(value).split())
        if normalized and normalized.casefold() not in seen:
            seen.add(normalized.casefold())
            output.append(normalized)
    return output


def _classify_phone_mention(hit: dict[str, object]) -> dict[str, object]:
    haystack = f"{hit.get('title', '')} {hit.get('url', '')} {hit.get('snippet', '')}".casefold()
    labels = []
    if any(term in haystack for term in ("marketplace", "olx", "craigslist", "classified", "ads", "advert")):
        labels.append("marketplace_or_ads")
    if any(term in haystack for term in ("facebook", "instagram", "t.me", "telegram", "whatsapp", "viber")):
        labels.append("social_or_messenger")
    if any(term in haystack for term in ("company", "contact", "support", "business")):
        labels.append("business_contact")
    if any(term in haystack for term in ("scam", "spam", "fraud", "phishing", "мошен", "скам", "спам")):
        labels.append("risk_reputation")
    hit["mention_labels"] = labels or ["unclassified_public_mention"]
    return hit
