from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from osint.collectors.base import BaseCollector, CollectorContext, compact_dict
from osint.models import Finding


class PhoneCollector(BaseCollector):
    name = "phone"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        phone = phonenumbers.parse(context.entity.normalized, None)
        data = compact_dict(
            {
                "e164": phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164),
                "international": phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "national": phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.NATIONAL),
                "rfc3966": phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.RFC3966),
                "country": geocoder.description_for_number(phone, "en"),
                "carrier": carrier.name_for_number(phone, "en"),
                "timezones": list(timezone.time_zones_for_number(phone)),
                "region_code": phonenumbers.region_code_for_number(phone),
                "valid": phonenumbers.is_valid_number(phone),
                "possible": phonenumbers.is_possible_number(phone),
            }
        )
        findings = [
            Finding(
                category="phone",
                title="Phone number metadata",
                source=self.name,
                confidence=0.92,
                data=data,
            )
        ]

        if context.deep or context.premium:
            hits = await context.search.search(context.http, f'"{context.entity.normalized}"', limit=8)
            classified = [_classify_phone_mention(hit.model_dump()) for hit in hits]
            findings.append(
                Finding(
                    category="public_mentions",
                    title="Public mentions from search engines",
                    source="multi_engine_search",
                    confidence=0.65 if hits else 0.2,
                    data={
                        "hits": classified,
                        "policy": "Public mentions only. No private databases, leaks or bypass sources are queried.",
                    },
                )
            )
        return findings


def _classify_phone_mention(hit: dict[str, object]) -> dict[str, object]:
    haystack = f"{hit.get('title', '')} {hit.get('url', '')} {hit.get('snippet', '')}".casefold()
    labels = []
    if any(term in haystack for term in ("marketplace", "olx", "craigslist", "classified", "ads", "advert")):
        labels.append("marketplace_or_ads")
    if any(term in haystack for term in ("facebook", "instagram", "t.me", "telegram", "whatsapp", "viber")):
        labels.append("social_or_messenger")
    if any(term in haystack for term in ("company", "contact", "support", "business")):
        labels.append("business_contact")
    hit["mention_labels"] = labels or ["unclassified_public_mention"]
    return hit
