from __future__ import annotations

import asyncio
import re
from collections import Counter
from urllib.parse import urljoin, urlsplit

import phonenumbers
from bs4 import BeautifulSoup

from core.localization import t
from core.validators import is_public_http_url
from osint.collectors.base import BaseCollector, CollectorContext, compact_dict, fetch_text
from osint.collectors.username import SOCIAL_PLATFORMS
from osint.models import Entity, EntityKind, Finding, SearchHit
from osint.parsers.html import extract_page_metadata


EMAIL_RE = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)")
USERNAME_RE = re.compile(r"(?<![\w@])@([a-zA-Z0-9_]{3,64})")
TELEGRAM_LINK_RE = re.compile(r"https?://(?:t\.me|telegram\.me)/[a-zA-Z0-9_/?=&.-]+|(?:t\.me|telegram\.me)/[a-zA-Z0-9_/?=&.-]+")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
SOCIAL_HOSTS = {
    "github.com",
    "reddit.com",
    "youtube.com",
    "youtu.be",
    "tiktok.com",
    "instagram.com",
    "twitch.tv",
    "steamcommunity.com",
    "gitlab.com",
    "medium.com",
    "pinterest.com",
    "soundcloud.com",
    "vimeo.com",
    "behance.net",
    "telegram.me",
    "t.me",
}


class TelegramCollector(BaseCollector):
    name = "telegram"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        target = context.entity.normalized.strip().strip("@")
        if not target:
            return [_policy_finding(context.entity.normalized)]

        if target.isdigit():
            return await self._collect_public_id(context, target)

        profile_url = f"https://t.me/{target}"
        messages_url = f"https://t.me/s/{target}"
        profile_page, messages_page = await asyncio.gather(
            fetch_text(context, profile_url),
            fetch_text(context, messages_url),
        )

        profile = _parse_profile(profile_page.text if profile_page else "", profile_url, profile_page.status if profile_page else 0)
        messages = _parse_public_messages(messages_page.text if messages_page else "", messages_url, messages_page.status if messages_page else 0)
        links = sorted(set(profile.get("links", []) + [link for message in messages for link in message.get("links", [])]))
        text_corpus = " ".join(
            [
                str(profile.get("title") or ""),
                str(profile.get("description") or ""),
                str(profile.get("about") or ""),
                *[str(message.get("text") or "") for message in messages],
                " ".join(links),
            ]
        )
        extracted = _extract_public_entities(text_corpus, links)
        relation_entities = _relation_entities(links, extracted)
        entity_type = _infer_entity_type(profile, messages, target)
        score = _telegram_score(profile, messages, extracted)

        findings = [
            Finding(
                category="telegram_profile",
                title=t("findings.telegram_profile_title"),
                source=self.name,
                source_url=profile_url,
                confidence=score["confidence"],
                data=compact_dict(
                    {
                        "username": target,
                        "display_name": profile.get("title"),
                        "bio_about": profile.get("description") or profile.get("about"),
                        "avatar": profile.get("avatar"),
                        "public_url": profile_url,
                        "status_code": profile.get("status_code"),
                        "public_links": links[:80],
                        "public_mentions": extracted["telegram_mentions"][:80],
                        "linked_websites": extracted["websites"][:80],
                        "linked_socials": extracted["socials"][:80],
                        "policy": t("findings.policy_public_only"),
                        "privacy_note": t("telegram.no_hidden_phone"),
                    }
                ),
                entities=relation_entities,
            ),
            Finding(
                category="telegram_entity",
                title=t("findings.telegram_entity_title"),
                source=self.name,
                source_url=messages_url,
                confidence=score["public_evidence_score"],
                data=compact_dict(
                    {
                        "type": entity_type,
                        "title": profile.get("title"),
                        "description": profile.get("description") or profile.get("about"),
                        "subscribers": profile.get("subscribers"),
                        "extra": profile.get("extra"),
                        "channel_group_username": target,
                        "public_messages_available": bool(messages),
                        "public_messages_count": len(messages),
                        "pinned_links": _pinned_links(messages),
                        "linked_discussion_group": _linked_discussion(links),
                        "source_reliability": score["source_reliability"],
                        "public_evidence_score": score["public_evidence_score"],
                        "risk_indicators": score["risk_indicators"],
                        "noise_filtering": score["noise_filtering"],
                    }
                ),
                entities=relation_entities,
            ),
        ]

        findings.append(
            Finding(
                category="telegram_public_messages",
                title=t("findings.telegram_messages_title"),
                source=self.name,
                source_url=messages_url,
                confidence=0.78 if messages else 0.25,
                description=t("findings.no_public_messages") if not messages else "",
                data={
                    "messages": messages[:30],
                    "policy": t("findings.policy_public_only"),
                },
                entities=_entities_from_messages(messages),
            )
        )

        if context.deep or context.premium:
            mentions = await _telegram_mentions(context, target)
            reuse = await _platform_reuse(context, target)
            variants = _username_variants(target)
            variant_hits = await _variant_hits(context, variants[:12])

            findings.extend(
                [
                    Finding(
                        category="telegram_mentions",
                        title=t("findings.telegram_mentions_title"),
                        source="multi_engine_search",
                        confidence=_hits_confidence(mentions),
                        data={
                            "queries": _telegram_dorks(target),
                            "hits": [_classify_telegram_hit(hit).model_dump() for hit in mentions],
                            "policy": t("findings.policy_public_only"),
                        },
                        entities=_entities_from_hits(mentions),
                    ),
                    Finding(
                        category="username_reuse",
                        title=t("findings.telegram_reuse_title"),
                        source=self.name,
                        confidence=max([float(item.get("confidence") or 0.0) for item in reuse], default=0.35),
                        data={"profiles": reuse},
                        entities=[
                            Entity(
                                kind=EntityKind.url,
                                value=str(item["url"]),
                                normalized=str(item["url"]),
                                confidence=float(item.get("confidence") or 0.35),
                                metadata={"platform": item.get("platform")},
                            )
                            for item in reuse
                        ],
                    ),
                    Finding(
                        category="username_variants",
                        title=t("findings.telegram_variants_title"),
                        source=self.name,
                        confidence=0.55 if variant_hits else 0.35,
                        data={
                            "variants": variants,
                            "similar_public_hits": [hit.model_dump() for hit in variant_hits],
                        },
                        entities=_entities_from_hits(variant_hits),
                    ),
                    Finding(
                        category="telegram_relation_graph",
                        title=t("findings.telegram_graph_title"),
                        source=self.name,
                        confidence=score["confidence"],
                        data={
                            "relations": _relation_rows(target, links, extracted, messages),
                            "public_evidence_score": score["public_evidence_score"],
                            "source_reliability": score["source_reliability"],
                            "confidence_score": score["confidence"],
                        },
                        entities=relation_entities + _entities_from_hits(mentions)[:40],
                    ),
                ]
            )

        return findings

    async def _collect_public_id(self, context: CollectorContext, target: str) -> list[Finding]:
        queries = [f'"{target}" "telegram"', f'"Telegram ID" "{target}"', f'"user id" "{target}" "telegram"']
        hits = []
        if context.deep or context.premium:
            search_results = await asyncio.gather(*[context.search.search(context.http, query, limit=5) for query in queries])
            hits = [hit for result in search_results for hit in result]
        return [
            Finding(
                category="telegram_public_id",
                title=t("findings.telegram_profile_title"),
                source=self.name,
                confidence=0.45 if hits else 0.25,
                data={
                    "telegram_id": target,
                    "note": t("telegram.public_id_note"),
                    "queries": queries,
                    "hits": [hit.model_dump() for hit in hits],
                    "policy": t("findings.policy_public_only"),
                },
                entities=_entities_from_hits(hits),
            )
        ]


def _parse_profile(html: str, url: str, status: int) -> dict[str, object]:
    soup = BeautifulSoup(html or "", "lxml")
    metadata = extract_page_metadata(html[:250_000], url)
    title = _text(soup.select_one(".tgme_page_title")) or metadata.get("title")
    description = _text(soup.select_one(".tgme_page_description")) or metadata.get("description") or metadata.get("og_description")
    extra = _text(soup.select_one(".tgme_page_extra"))
    avatar = ""
    image = soup.select_one(".tgme_page_photo_image")
    if image and image.get("src"):
        avatar = urljoin(url, str(image["src"]))
    avatar = avatar or str(metadata.get("og_image") or "")
    return compact_dict(
        {
            "status_code": status,
            "title": _clean_tg_title(str(title or "")),
            "description": description,
            "about": _text(soup.select_one(".tgme_page_additional")),
            "extra": extra,
            "subscribers": _extract_count(extra),
            "avatar": avatar,
            "links": _public_links(soup, url),
            "metadata": metadata,
        }
    )


def _parse_public_messages(html: str, url: str, status: int) -> list[dict[str, object]]:
    if not html or status >= 400:
        return []
    soup = BeautifulSoup(html, "lxml")
    messages: list[dict[str, object]] = []
    for index, node in enumerate(soup.select(".tgme_widget_message")[:40]):
        text_node = node.select_one(".tgme_widget_message_text")
        text = text_node.get_text(" ", strip=True) if text_node else ""
        links = _public_links(node, url)
        date_node = node.select_one("time")
        message_url = ""
        link_node = node.select_one(".tgme_widget_message_date a[href]")
        if link_node and link_node.get("href"):
            message_url = urljoin(url, str(link_node["href"]))
        views = _text(node.select_one(".tgme_widget_message_views"))
        service = _text(node.select_one(".tgme_widget_message_service_message"))
        messages.append(
            compact_dict(
                {
                    "index": index + 1,
                    "url": message_url,
                    "datetime": date_node.get("datetime") if date_node else "",
                    "text": text[:1200],
                    "links": links[:30],
                    "views": views,
                    "service": service,
                    "pinned": "pinned" in f"{node.get('class', '')} {service}".casefold(),
                    "emails": sorted(set(EMAIL_RE.findall(text)))[:20],
                    "phones": _normalize_phones(PHONE_RE.findall(text)),
                    "mentions": sorted(set(USERNAME_RE.findall(text)))[:30],
                }
            )
        )
    return messages


async def _telegram_mentions(context: CollectorContext, username: str) -> list[SearchHit]:
    queries = _telegram_dorks(username)
    results = await asyncio.gather(*[context.search.search(context.http, query, limit=6) for query in queries])
    return _dedupe_hits([hit for group in results for hit in group])[:60]


async def _platform_reuse(context: CollectorContext, username: str) -> list[dict[str, object]]:
    templates = {
        platform: template
        for platform, template in SOCIAL_PLATFORMS.items()
        if platform not in {"Telegram", "Facebook", "DeviantArt"}
    }
    templates["Telegram channel/bot"] = "https://t.me/{username}"
    profiles = [{"platform": platform, "url": template.format(username=username)} for platform, template in templates.items()]
    semaphore = asyncio.Semaphore(6)
    await asyncio.gather(*[_check_public_profile(context, profile, username, semaphore) for profile in profiles])
    return profiles


async def _variant_hits(context: CollectorContext, variants: list[str]) -> list[SearchHit]:
    queries = [f'"{variant}" telegram' for variant in variants if variant]
    if not queries:
        return []
    results = await asyncio.gather(*[context.search.search(context.http, query, limit=3) for query in queries[:10]])
    return _dedupe_hits([hit for group in results for hit in group])[:25]


async def _check_public_profile(
    context: CollectorContext,
    profile: dict[str, object],
    username: str,
    semaphore: asyncio.Semaphore,
) -> None:
    url = str(profile["url"])
    async with semaphore:
        try:
            async with context.http.get(url, allow_redirects=True) as response:
                profile["status"] = response.status
                profile["final_url"] = str(response.url)
                body = await response.text(errors="ignore")
        except Exception as exc:
            profile["error"] = str(exc)
            profile["confidence"] = 0.12
            return
    metadata = extract_page_metadata(body[:180_000], str(profile.get("final_url") or url))
    title = str(metadata.get("title") or "")
    description = str(metadata.get("description") or metadata.get("og_description") or "")
    profile["title"] = title[:180]
    profile["description"] = description[:300]
    profile["avatar"] = metadata.get("og_image")
    profile["confidence"] = _reuse_confidence(profile, username)


def _telegram_dorks(username: str) -> list[str]:
    return [
        f'"@{username}"',
        f'"t.me/{username}"',
        f'"telegram.me/{username}"',
        f'"{username}" telegram',
        f'"{username}" site:t.me',
        f'"{username}" site:telegra.ph',
        f'"{username}" site:github.com',
        f'"{username}" site:reddit.com',
        f'"{username}" site:youtube.com',
        f'"{username}" site:tiktok.com',
        f'"{username}" site:instagram.com',
    ]


def _username_variants(username: str) -> list[str]:
    base = username.strip("@")
    lower = base.lower()
    upper = base.upper()
    compact = re.sub(r"[._-]+", "", base)
    parts = [part for part in re.split(r"[._-]+", base) if part]
    variants = {
        base,
        lower,
        upper,
        base.replace("_", "."),
        base.replace("_", "-"),
        base.replace(".", "_"),
        base.replace("-", "_"),
        compact,
        f"{lower}1",
        f"{lower}01",
        f"{lower}123",
        f"the{lower}",
        f"{lower}official",
        "_".join(parts),
        ".".join(parts),
        _transliterate(lower),
    }
    return [item for item in sorted(variants, key=lambda item: (item.lower() != lower, len(item), item)) if item]


def _transliterate(value: str) -> str:
    mapping = {
        "а": "a",
        "б": "b",
        "в": "v",
        "г": "g",
        "д": "d",
        "е": "e",
        "ё": "e",
        "ж": "zh",
        "з": "z",
        "и": "i",
        "й": "y",
        "к": "k",
        "л": "l",
        "м": "m",
        "н": "n",
        "о": "o",
        "п": "p",
        "р": "r",
        "с": "s",
        "т": "t",
        "у": "u",
        "ф": "f",
        "х": "h",
        "ц": "c",
        "ч": "ch",
        "ш": "sh",
        "щ": "sch",
        "ы": "y",
        "э": "e",
        "ю": "yu",
        "я": "ya",
        "і": "i",
        "ї": "yi",
        "є": "ye",
        "ґ": "g",
    }
    return "".join(mapping.get(char, char) for char in value)


def _extract_public_entities(text: str, links: list[str]) -> dict[str, list[str]]:
    emails = sorted(set(EMAIL_RE.findall(text)))[:80]
    phones = _normalize_phones(PHONE_RE.findall(text))[:50]
    mentions = sorted(set(USERNAME_RE.findall(text)))[:80]
    telegram_mentions = sorted(set(_normalize_telegram_link(match) for match in TELEGRAM_LINK_RE.findall(text)))[:80]
    domains = sorted(set(match.lower() for match in DOMAIN_RE.findall(" ".join([text, " ".join(links)]))))[:120]
    socials = sorted(set(link for link in links if _is_social_link(link)))[:80]
    websites = sorted(set(link for link in links if is_public_http_url(link) and not _is_social_link(link)))[:80]
    return {
        "emails": emails,
        "phones": phones,
        "mentions": mentions,
        "telegram_mentions": telegram_mentions,
        "domains": domains,
        "socials": socials,
        "websites": websites,
    }


def _relation_entities(links: list[str], extracted: dict[str, list[str]]) -> list[Entity]:
    entities: list[Entity] = []
    for link in links[:80]:
        entities.append(Entity(kind=EntityKind.url, value=link, normalized=link, confidence=0.68, metadata={"platform": _platform_from_url(link)}))
    for email in extracted["emails"][:40]:
        entities.append(Entity(kind=EntityKind.email, value=email, normalized=email.lower(), confidence=0.72))
    for phone in extracted["phones"][:30]:
        entities.append(Entity(kind=EntityKind.phone, value=phone, normalized=phone, confidence=0.58))
    for mention in extracted["mentions"][:50]:
        entities.append(Entity(kind=EntityKind.username, value=mention, normalized=mention.lstrip("@"), confidence=0.56))
    for domain in extracted["domains"][:60]:
        entities.append(Entity(kind=EntityKind.domain, value=domain, normalized=domain, confidence=0.62))
    return _dedupe_entities(entities)


def _entities_from_messages(messages: list[dict[str, object]]) -> list[Entity]:
    entities: list[Entity] = []
    for message in messages[:30]:
        for link in (message.get("links", [])[:20] if isinstance(message.get("links"), list) else []):
            entities.append(Entity(kind=EntityKind.url, value=str(link), normalized=str(link), confidence=0.62, metadata={"platform": _platform_from_url(str(link))}))
        for email in (message.get("emails", [])[:10] if isinstance(message.get("emails"), list) else []):
            entities.append(Entity(kind=EntityKind.email, value=str(email), normalized=str(email).lower(), confidence=0.68))
        for phone in (message.get("phones", [])[:10] if isinstance(message.get("phones"), list) else []):
            entities.append(Entity(kind=EntityKind.phone, value=str(phone), normalized=str(phone), confidence=0.55))
        for mention in (message.get("mentions", [])[:10] if isinstance(message.get("mentions"), list) else []):
            entities.append(Entity(kind=EntityKind.username, value=str(mention), normalized=str(mention).lstrip("@"), confidence=0.55))
    return _dedupe_entities(entities)


def _entities_from_hits(hits: list[SearchHit]) -> list[Entity]:
    entities: list[Entity] = []
    for hit in hits:
        entities.append(Entity(kind=EntityKind.url, value=hit.url, normalized=hit.url, confidence=hit.confidence, metadata={"platform": hit.domain}))
        text = f"{hit.title} {hit.snippet} {hit.url}"
        for email in EMAIL_RE.findall(text)[:8]:
            entities.append(Entity(kind=EntityKind.email, value=email, normalized=email.lower(), confidence=0.6))
        for username in USERNAME_RE.findall(text)[:8]:
            entities.append(Entity(kind=EntityKind.username, value=username, normalized=username.lstrip("@"), confidence=0.55))
        for link in TELEGRAM_LINK_RE.findall(text)[:8]:
            clean = _normalize_telegram_link(link)
            entities.append(Entity(kind=EntityKind.telegram, value=clean, normalized=clean.rsplit("/", 1)[-1], confidence=0.62))
    return _dedupe_entities(entities)


def _relation_rows(target: str, links: list[str], extracted: dict[str, list[str]], messages: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for link in links[:60]:
        rows.append({"from": f"telegram:{target}", "to": link, "type": "public_link", "confidence": 0.68})
    for key in ("emails", "phones", "mentions", "domains", "socials", "websites", "telegram_mentions"):
        for value in extracted.get(key, [])[:30]:
            rows.append({"from": f"telegram:{target}", "to": value, "type": key, "confidence": 0.58})
    for message in messages[:20]:
        if message.get("url"):
            rows.append({"from": f"telegram:{target}", "to": message["url"], "type": "public_message", "confidence": 0.72})
    return rows[:180]


def _telegram_score(profile: dict[str, object], messages: list[dict[str, object]], extracted: dict[str, list[str]]) -> dict[str, object]:
    evidence = 0.25
    if profile.get("status_code") == 200:
        evidence += 0.2
    if profile.get("title"):
        evidence += 0.12
    if profile.get("description") or profile.get("about"):
        evidence += 0.1
    if profile.get("avatar"):
        evidence += 0.06
    if profile.get("subscribers"):
        evidence += 0.08
    if messages:
        evidence += min(0.18, len(messages) * 0.01)
    if extracted["websites"] or extracted["socials"]:
        evidence += 0.08
    if extracted["emails"] or extracted["phones"]:
        evidence += 0.04
    risk_terms = _risk_terms(" ".join([str(profile.get("description") or ""), *(str(item.get("text") or "") for item in messages[:20])]))
    source_reliability = round(0.82 if profile.get("status_code") == 200 else 0.45, 2)
    public_evidence_score = round(min(evidence, 0.98), 2)
    risk = round(min(1.0, len(risk_terms) * 0.12), 2)
    return {
        "confidence": public_evidence_score,
        "source_reliability": source_reliability,
        "public_evidence_score": public_evidence_score,
        "risk_indicators": risk_terms,
        "noise_filtering": {
            "messages_seen": len(messages),
            "unique_domains": len(extracted["domains"]),
            "risk_score": risk,
        },
    }


def _infer_entity_type(profile: dict[str, object], messages: list[dict[str, object]], username: str) -> str:
    haystack = f"{username} {profile.get('title', '')} {profile.get('description', '')} {profile.get('extra', '')}".casefold()
    if username.casefold().endswith("bot") or " bot" in haystack or "бот" in haystack:
        return t("telegram.type_bot")
    if "members" in haystack or "участник" in haystack or "группа" in haystack or "group" in haystack:
        return t("telegram.type_group")
    if messages or "subscribers" in haystack or "подписчик" in haystack or "channel" in haystack or "канал" in haystack:
        return t("telegram.type_channel")
    return t("telegram.type_user")


def _risk_terms(text: str) -> list[str]:
    terms = ("scam", "fraud", "phishing", "spam", "malware", "скам", "мошен", "фишинг", "спам")
    haystack = text.casefold()
    return [term for term in terms if term in haystack]


def _pinned_links(messages: list[dict[str, object]]) -> list[str]:
    links: list[str] = []
    for message in messages:
        if message.get("pinned"):
            links.extend([str(link) for link in message.get("links", []) if link])
    return sorted(set(links))[:30]


def _linked_discussion(links: list[str]) -> str:
    for link in links:
        host = urlsplit(link).netloc.lower()
        if host in {"t.me", "telegram.me"} and ("comment=" in link or "/c/" in link):
            return link
    return ""


def _public_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    links: list[str] = []
    for tag in soup.find_all("a", href=True)[:260]:
        href = urljoin(base_url, str(tag["href"]))
        if href.startswith(("http://", "https://")) and is_public_http_url(href):
            links.append(href)
    return sorted(set(links))[:120]


def _normalize_phones(values: list[str]) -> list[str]:
    phones: list[str] = []
    for value in values:
        try:
            parsed = phonenumbers.parse(value, None)
            if phonenumbers.is_possible_number(parsed):
                phones.append(phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
        except phonenumbers.NumberParseException:
            phones.append(re.sub(r"\s+", " ", value).strip())
    return sorted(set(phones))[:50]


def _extract_count(value: object) -> int | None:
    text = str(value or "").replace(",", " ").replace("\u00a0", " ")
    match = re.search(r"(\d+(?:[ .]\d+)*)", text)
    if not match:
        return None
    try:
        return int(re.sub(r"\D", "", match.group(1)))
    except ValueError:
        return None


def _reuse_confidence(profile: dict[str, object], username: str) -> float:
    status = int(profile.get("status") or 0)
    final_url = str(profile.get("final_url") or profile.get("url") or "").casefold()
    title = str(profile.get("title") or "").casefold()
    description = str(profile.get("description") or "").casefold()
    score = 0.16
    if status in {200, 301, 302}:
        score += 0.32
    if username.casefold() in final_url:
        score += 0.18
    if username.casefold() in title:
        score += 0.16
    if username.casefold() in description:
        score += 0.08
    if profile.get("avatar"):
        score += 0.06
    return round(min(score, 0.96), 2)


def _hits_confidence(hits: list[SearchHit]) -> float:
    if not hits:
        return 0.2
    engines = len({hit.engine for hit in hits})
    domains = len({hit.domain for hit in hits})
    return round(min(0.95, 0.45 + min(0.25, len(hits) * 0.015) + min(0.15, engines * 0.05) + min(0.1, domains * 0.01)), 2)


def _classify_telegram_hit(hit: SearchHit) -> SearchHit:
    haystack = f"{hit.title} {hit.url} {hit.snippet}".casefold()
    labels = []
    if "t.me" in haystack or "telegram.me" in haystack:
        labels.append("telegram_public")
    if any(host in haystack for host in ("github.com", "reddit.com", "youtube.com", "tiktok.com", "instagram.com")):
        labels.append("cross_platform")
    if any(term in haystack for term in ("scam", "fraud", "spam", "phishing", "скам", "мошен")):
        labels.append("risk_reputation")
    hit.metadata["mention_labels"] = labels or ["public_mention"]
    return hit


def _dedupe_hits(hits: list[SearchHit]) -> list[SearchHit]:
    seen: set[str] = set()
    unique: list[SearchHit] = []
    for hit in hits:
        key = hit.url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        unique.append(hit)
    return unique


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


def _is_social_link(link: str) -> bool:
    host = urlsplit(link).netloc.lower().removeprefix("www.")
    return any(host == social or host.endswith(f".{social}") for social in SOCIAL_HOSTS)


def _platform_from_url(link: str) -> str:
    return urlsplit(link).netloc.lower().removeprefix("www.")


def _normalize_telegram_link(value: str) -> str:
    value = value.strip()
    if value.startswith("t.me/") or value.startswith("telegram.me/"):
        return f"https://{value}"
    return value


def _clean_tg_title(value: str) -> str:
    return re.sub(r"\s+-\s+Telegram.*$", "", value).strip()


def _text(node) -> str:
    return node.get_text(" ", strip=True) if node else ""


def _policy_finding(target: str) -> Finding:
    return Finding(
        category="telegram_policy",
        title=t("findings.telegram_profile_title"),
        source="telegram",
        confidence=0.2,
        data={"target": target, "policy": t("findings.policy_public_only")},
    )
