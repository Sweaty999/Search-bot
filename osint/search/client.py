from __future__ import annotations

import logging
import asyncio
import random
import re
from urllib.parse import urlsplit, urlunsplit

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from core.config import Settings, get_settings
from osint.models import SearchHit
from osint.search.engines import SearchEngine, default_engines

logger = logging.getLogger(__name__)


class MultiEngineSearch:
    def __init__(self, settings: Settings | None = None, engines: list[SearchEngine] | None = None) -> None:
        self.settings = settings or get_settings()
        self.engines = engines if engines is not None else default_engines(self.settings)

    async def search(self, http: aiohttp.ClientSession, query: str, limit: int = 10) -> list[SearchHit]:
        if not self.engines:
            return []

        ordered = sorted(self.engines, key=lambda item: item.priority, reverse=True)
        results = await asyncio.gather(
            *[self._safe_engine_search(engine, http, query, limit) for engine in ordered],
        )
        all_hits = [hit for hits in results for hit in hits]

        ranked = _rank(_deduplicate(all_hits), query)
        return ranked[:limit]

    async def _safe_engine_search(
        self,
        engine: SearchEngine,
        http: aiohttp.ClientSession,
        query: str,
        limit: int,
    ) -> list[SearchHit]:
        try:
            hits = await self._engine_search(engine, http, query, limit)
            for hit in hits:
                hit.query = query
            return hits
        except Exception as exc:
            logger.warning("Search engine %s failed: %s", engine.name, exc)
            return []

    @retry(wait=wait_exponential(multiplier=0.5, min=0.5, max=3), stop=stop_after_attempt(2), reraise=True)
    async def _engine_search(
        self,
        engine: SearchEngine,
        http: aiohttp.ClientSession,
        query: str,
        limit: int,
    ) -> list[SearchHit]:
        return await engine.search(http, query, limit)


def make_http_session(settings: Settings | None = None) -> aiohttp.ClientSession:
    settings = settings or get_settings()
    headers = {"User-Agent": random.choice(settings.user_agents), "Accept-Language": "en-US,en;q=0.9"}
    timeout = aiohttp.ClientTimeout(total=settings.http_timeout_seconds)
    return aiohttp.ClientSession(headers=headers, timeout=timeout)


def _deduplicate(hits: list[SearchHit]) -> list[SearchHit]:
    seen: set[str] = set()
    unique: list[SearchHit] = []
    for hit in hits:
        normalized = _normalize_url(hit.url)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique.append(hit)
    return unique


def _normalize_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower().removeprefix("www."), path, "", ""))


def _rank(hits: list[SearchHit], query: str) -> list[SearchHit]:
    terms = {term for term in re.split(r"\W+", query.casefold()) if len(term) > 2}
    for hit in hits:
        haystack = f"{hit.title} {hit.snippet} {hit.url}".casefold()
        overlap = sum(1 for term in terms if term in haystack)
        engine_bonus = {"serpapi": 0.25, "duckduckgo": 0.18, "google_cse": 0.12, "public_scraping": 0.05}.get(
            hit.engine,
            0,
        )
        exact_bonus = 0.8 if query.casefold() in haystack else 0.0
        official_bonus = 0.4 if _looks_official_profile(hit.url) else 0.0
        noise_penalty = 0.5 if _looks_noisy(hit.url, hit.title) else 0.0
        hit.domain = urlsplit(hit.url).netloc.lower().removeprefix("www.")
        hit.is_official_profile = official_bonus > 0
        hit.is_noisy = noise_penalty > 0
        hit.relevance_score = round(max(0.0, overlap + exact_bonus + official_bonus + engine_bonus - noise_penalty), 3)
        hit.score = hit.relevance_score
        hit.confidence = min(0.98, round(0.35 + (overlap * 0.1) + exact_bonus + official_bonus + engine_bonus - noise_penalty, 2))
    return sorted(hits, key=lambda item: item.score, reverse=True)


def _looks_official_profile(url: str) -> bool:
    host = urlsplit(url).netloc.lower()
    return any(
        domain in host
        for domain in (
            "github.com",
            "reddit.com",
            "t.me",
            "youtube.com",
            "tiktok.com",
            "instagram.com",
            "facebook.com",
            "medium.com",
            "gitlab.com",
            "twitch.tv",
            "steamcommunity.com",
            "pinterest.com",
        )
    )


def _looks_noisy(url: str, title: str) -> bool:
    haystack = f"{url} {title}".casefold()
    return any(token in haystack for token in ("login", "signup", "tag/", "search?", "/search", "captcha", "category/"))
