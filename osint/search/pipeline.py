from __future__ import annotations

import asyncio
import re
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp
import phonenumbers
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

from core.config import Settings
from core.localization import t
from core.validators import is_public_http_url
from osint.models import Entity, EntityKind, Finding, SearchHit
from osint.parsers.html import extract_page_metadata
from osint.screenshots.service import capture_screenshot
from osint.search.client import MultiEngineSearch


EXPANSION_SITES = (
    "github.com",
    "reddit.com",
    "t.me",
    "telegram.me",
    "telegra.ph",
    "pastebin.com",
    "medium.com",
    "youtube.com",
    "tiktok.com",
    "instagram.com",
    "twitch.tv",
    "steamcommunity.com",
    "gitlab.com",
    "pinterest.com",
    "soundcloud.com",
    "vimeo.com",
    "behance.net",
)

SOCIAL_HOSTS = (
    "github.com",
    "reddit.com",
    "t.me",
    "telegram.me",
    "youtube.com",
    "youtu.be",
    "tiktok.com",
    "instagram.com",
    "facebook.com",
    "medium.com",
    "gitlab.com",
    "twitch.tv",
    "steamcommunity.com",
    "pinterest.com",
    "soundcloud.com",
    "vimeo.com",
    "behance.net",
)

EMAIL_RE = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
USERNAME_RE = re.compile(r"(?<![\w@])@([a-zA-Z0-9_.-]{3,64})")
RISK_TERMS = ("malware", "phishing", "scam", "fraud", "leak", "dump", "paste", "breach", "credential")
NOISE_TERMS = ("login", "signup", "captcha", "tag/", "category/", "/search", "search?")


@dataclass(slots=True)
class PipelineOutput:
    hits: list[SearchHit]
    finding: Finding
    timeline: list[dict[str, object]]


async def run_deep_search_pipeline(
    *,
    entity: Entity,
    query: str,
    http: aiohttp.ClientSession,
    search: MultiEngineSearch,
    settings: Settings,
    deep: bool,
    premium: bool,
) -> PipelineOutput:
    stage_limit = 12 if (deep or premium) else 5
    result_limit = 8 if (deep or premium) else 4
    enrich_limit = 32 if (deep or premium) else 8

    queries = expand_queries(entity, query)[:stage_limit]
    timeline: list[dict[str, object]] = [
        {"stage": t("pipeline.stage_detect_entity"), "entity_type": entity.kind.value, "value": entity.normalized},
        {"stage": t("pipeline.stage_query_expansion"), "queries": queries},
    ]

    search_results = await asyncio.gather(*[search.search(http, item, limit=result_limit) for item in queries])
    raw_hits = [hit for hits in search_results for hit in hits]
    deduped = _dedupe_hits(raw_hits)
    timeline.append({"stage": t("pipeline.stage_parallel_search"), "raw_hits": len(raw_hits), "deduped_hits": len(deduped)})

    enriched = await _enrich_hits(deduped[:enrich_limit], entity, http, settings, deep or premium)
    ranked = _rank_enriched(enriched, entity)
    timeline.append({"stage": t("pipeline.stage_enrichment"), "enriched_hits": len(enriched)})
    timeline.append({"stage": t("pipeline.stage_ranking"), "top_domains": _top_domains(ranked, limit=8)})

    entities = _entities_from_hits(ranked)
    source_table = [_source_row(hit) for hit in ranked[:50]]
    domain_groups = _domain_groups(ranked)
    counters = Counter(entity.kind.value for entity in entities)
    risk_score = round(max([hit.risk_score for hit in ranked], default=0.0), 2)
    confidence = round(max([hit.confidence for hit in ranked], default=0.35), 2)

    finding = Finding(
        category="deep_search",
        title=t("findings.deep_search_title"),
        source="deep_search_pipeline",
        confidence=confidence,
        data={
            "queries": queries,
            "source_table": source_table,
            "domain_groups": domain_groups,
            "entity_counters": dict(counters),
            "risk_score": risk_score,
            "ranking_notes": [
                t("findings.ranking_notes_dedupe"),
                t("findings.ranking_notes_exact"),
                t("findings.ranking_notes_noise"),
            ],
        },
        entities=entities[:120],
    )
    return PipelineOutput(hits=ranked[:50], finding=finding, timeline=timeline)


def expand_queries(entity: Entity, query: str) -> list[str]:
    base = entity.normalized or query.strip()
    expansions = [
        base,
        f'"{base}"',
        f"{base} social media",
        f"{base} соцсети",
    ]
    if entity.kind == EntityKind.email:
        local, _, domain = base.partition("@")
        expansions.extend(
            [
                f'"{base}"',
                f'"{local}" "{domain}"',
                f'"{base}" site:github.com',
                f'"{base}" site:docs.google.com',
                f'"{domain}" mx spf dmarc',
                f'"{domain}" contact email',
            ]
        )
    elif entity.kind == EntityKind.phone:
        expansions.extend(_phone_query_variants(base))
    elif entity.kind == EntityKind.domain:
        expansions.extend([f"site:{base}", f'"{base}" security', f'"{base}" contact'])
    elif entity.kind == EntityKind.telegram:
        username = base.strip("@")
        expansions.extend(
            [
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
        )
    elif entity.kind == EntityKind.username:
        expansions.extend([f'"{base}" username', f'"@{base}"'])

    expansions.extend([f"{base} site:{site}" for site in EXPANSION_SITES])
    seen: set[str] = set()
    output: list[str] = []
    for item in expansions:
        item = " ".join(item.split())
        if item and item.casefold() not in seen:
            seen.add(item.casefold())
            output.append(item)
    return output


def _phone_query_variants(value: str) -> list[str]:
    variants = [f'"{value}"']
    try:
        parsed = phonenumbers.parse(value, None)
        variants.extend(
            [
                f'"{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}"',
                f'"{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)}"',
            ]
        )
    except phonenumbers.NumberParseException:
        pass
    variants.extend([f'"{value}" marketplace', f'"{value}" ads', f'"{value}" social'])
    return variants


def _dedupe_hits(hits: list[SearchHit]) -> list[SearchHit]:
    seen: set[str] = set()
    unique: list[SearchHit] = []
    for hit in hits:
        normalized = _normalize_url(hit.url)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        hit.url = normalized
        hit.domain = urlsplit(normalized).netloc.lower().removeprefix("www.")
        unique.append(hit)
    return unique


def _normalize_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return ""
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower().removeprefix("www."), path, "", ""))


async def _enrich_hits(
    hits: list[SearchHit],
    entity: Entity,
    http: aiohttp.ClientSession,
    settings: Settings,
    screenshots: bool,
) -> list[SearchHit]:
    semaphore = asyncio.Semaphore(6)

    async def enrich(hit: SearchHit, index: int) -> SearchHit:
        if not is_public_http_url(hit.url):
            hit.is_noisy = True
            return hit
        async with semaphore:
            try:
                async with http.get(hit.url, allow_redirects=True, timeout=settings.http_timeout_seconds) as response:
                    text = await response.text(errors="ignore")
                    hit.status_code = response.status
                    hit.final_url = str(response.url)
            except Exception as exc:
                hit.metadata["fetch_error"] = str(exc)
                hit.is_noisy = True
                return hit

        html = text[:400_000]
        metadata = extract_page_metadata(html, hit.final_url or hit.url)
        extracted = _extract_entities_from_html(html, hit.final_url or hit.url)
        hit.title = metadata.get("title") or hit.title
        hit.metadata.update(metadata)
        hit.metadata.update(extracted)
        hit.risk_score = _risk_score(hit, html)
        hit.is_noisy = hit.is_noisy or _is_noisy(hit, html)
        hit.is_official_profile = _is_official_profile(hit, entity)
        if screenshots and index < 3:
            screenshot = await capture_screenshot(hit.final_url or hit.url, settings)
            if screenshot:
                hit.metadata["screenshot"] = screenshot
        return hit

    return await asyncio.gather(*[enrich(hit, index) for index, hit in enumerate(hits)])


def _extract_entities_from_html(html: str, base_url: str) -> dict[str, object]:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        soup = BeautifulSoup(html or "", "lxml")
    text = soup.get_text(" ", strip=True)[:80_000]
    links = [urljoin(base_url, str(tag["href"])) for tag in soup.find_all("a", href=True)[:300]]
    social_links = sorted({link for link in links if any(host in urlsplit(link).netloc.lower() for host in SOCIAL_HOSTS)})
    usernames = sorted(set(USERNAME_RE.findall(text)))[:50]
    domains = sorted({match.lower() for match in DOMAIN_RE.findall(" ".join([text, " ".join(links)]))})[:80]
    ips = sorted(set(IP_RE.findall(text)))[:50]
    emails = sorted(set(EMAIL_RE.findall(text)))[:50]
    phones = sorted(set(PHONE_RE.findall(text)))[:50]
    canonical = ""
    canonical_tag = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical_tag and canonical_tag.get("href"):
        canonical = urljoin(base_url, str(canonical_tag["href"]))
    return {
        "canonical": canonical,
        "emails": emails,
        "phones": phones,
        "usernames": usernames,
        "social_links": social_links[:80],
        "domains": domains,
        "ips": ips,
    }


def _rank_enriched(hits: list[SearchHit], entity: Entity) -> list[SearchHit]:
    needle = entity.normalized.casefold()
    for hit in hits:
        haystack = " ".join(
            [
                hit.title,
                hit.snippet,
                hit.url,
                str(hit.metadata.get("description", "")),
                str(hit.metadata.get("emails", "")),
                str(hit.metadata.get("usernames", "")),
            ]
        ).casefold()
        exact = 1.0 if needle and needle in haystack else 0.0
        official = 0.6 if hit.is_official_profile else 0.0
        metadata_bonus = 0.2 if hit.metadata.get("emails") or hit.metadata.get("social_links") else 0.0
        noise_penalty = 0.7 if hit.is_noisy else 0.0
        status_penalty = 0.4 if hit.status_code and hit.status_code >= 400 else 0.0
        hit.relevance_score = round(max(0.0, hit.relevance_score + exact + official + metadata_bonus - noise_penalty - status_penalty), 3)
        hit.score = hit.relevance_score
        hit.confidence = min(0.98, round(max(hit.confidence, 0.35 + exact + official + metadata_bonus - noise_penalty), 2))
    return sorted(hits, key=lambda item: (item.is_noisy, -item.score))


def _risk_score(hit: SearchHit, html: str) -> float:
    haystack = f"{hit.url} {hit.title} {hit.snippet} {html[:20000]}".casefold()
    hits = sum(1 for term in RISK_TERMS if term in haystack)
    vt_stats = ((hit.metadata.get("virustotal") or {}) if isinstance(hit.metadata.get("virustotal"), dict) else {}).get("last_analysis_stats", {})
    malicious = vt_stats.get("malicious", 0) if isinstance(vt_stats, dict) else 0
    suspicious = vt_stats.get("suspicious", 0) if isinstance(vt_stats, dict) else 0
    return round(min(1.0, hits * 0.12 + malicious * 0.08 + suspicious * 0.05), 2)


def _is_noisy(hit: SearchHit, html: str) -> bool:
    haystack = f"{hit.url} {hit.title}".casefold()
    if any(term in haystack for term in NOISE_TERMS):
        return True
    if hit.status_code and hit.status_code >= 400:
        return True
    return len(html or "") < 120


def _is_official_profile(hit: SearchHit, entity: Entity) -> bool:
    if entity.kind != EntityKind.username:
        return False
    username = entity.normalized.strip("@").casefold()
    path_parts = [part for part in urlsplit(hit.final_url or hit.url).path.split("/") if part]
    if not path_parts:
        return False
    return path_parts[-1].casefold().strip("@") == username or path_parts[0].casefold().strip("@") == username


def _entities_from_hits(hits: list[SearchHit]) -> list[Entity]:
    entities: list[Entity] = []
    for hit in hits:
        for email in hit.metadata.get("emails", [])[:10]:
            entities.append(Entity(kind=EntityKind.email, value=email, normalized=str(email).lower(), confidence=0.72))
        for phone in hit.metadata.get("phones", [])[:8]:
            entities.append(Entity(kind=EntityKind.phone, value=phone, normalized=str(phone), confidence=0.55))
        for username in hit.metadata.get("usernames", [])[:10]:
            entities.append(Entity(kind=EntityKind.username, value=username, normalized=str(username).lstrip("@"), confidence=0.55))
        for domain in hit.metadata.get("domains", [])[:12]:
            entities.append(Entity(kind=EntityKind.domain, value=domain, normalized=str(domain).lower(), confidence=0.6))
        for ip in hit.metadata.get("ips", [])[:8]:
            entities.append(Entity(kind=EntityKind.ip, value=ip, normalized=str(ip), confidence=0.58))
        for link in hit.metadata.get("social_links", [])[:10]:
            entities.append(Entity(kind=EntityKind.url, value=link, normalized=str(link), confidence=0.65, metadata={"platform": urlsplit(str(link)).netloc}))
        entities.append(Entity(kind=EntityKind.url, value=hit.url, normalized=hit.url, confidence=hit.confidence))
    return _dedupe_entities(entities)


def _dedupe_entities(entities: list[Entity]) -> list[Entity]:
    seen: set[tuple[str, str]] = set()
    unique: list[Entity] = []
    for entity in entities:
        key = (entity.kind.value, entity.normalized.casefold())
        if key in seen:
            continue
        seen.add(key)
        unique.append(entity)
    return unique


def _source_row(hit: SearchHit) -> dict[str, object]:
    return {
        "title": hit.title,
        "url": hit.url,
        "domain": hit.domain,
        "engine": hit.engine,
        "query": hit.query,
        "status_code": hit.status_code,
        "confidence": hit.confidence,
        "relevance_score": hit.relevance_score,
        "risk_score": hit.risk_score,
        "noisy": hit.is_noisy,
        "official_profile": hit.is_official_profile,
        "favicon": hit.metadata.get("favicon"),
        "screenshot": hit.metadata.get("screenshot"),
    }


def _domain_groups(hits: list[SearchHit]) -> dict[str, list[dict[str, object]]]:
    groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    for hit in hits:
        groups[hit.domain or "unknown"].append(_source_row(hit))
    return {domain: rows[:12] for domain, rows in sorted(groups.items(), key=lambda item: len(item[1]), reverse=True)}


def _top_domains(hits: list[SearchHit], limit: int) -> list[dict[str, object]]:
    counter = Counter(hit.domain or "unknown" for hit in hits)
    return [{"domain": domain, "count": count} for domain, count in counter.most_common(limit)]
